# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import datetime
import json
import subprocess
import textwrap
from typing import IO, Any, Optional

from mkosi.config import ManifestFormat, OutputFormat
from mkosi.context import Context
from mkosi.distributions import PackageType
from mkosi.installer.apt import Apt
from mkosi.installer.pacman import Pacman
from mkosi.log import complete_step
from mkosi.run import run
from mkosi.util import read_env_file


@dataclasses.dataclass
class PackageManifest:
    """A description of a package

    The fields used here must match
    https://systemd.io/COREDUMP_PACKAGE_METADATA/#well-known-keys.
    """

    type: str
    name: str
    version: str
    architecture: str
    size: int

    def as_dict(self) -> dict[str, str]:
        return {
            "type": self.type,
            "name": self.name,
            "version": self.version,
            "architecture": self.architecture,
        }


@dataclasses.dataclass
class SourcePackageManifest:
    name: str
    changelog: Optional[str]
    packages: list[PackageManifest] = dataclasses.field(default_factory=list)

    def add(self, package: PackageManifest) -> None:
        self.packages.append(package)

    def report(self) -> str:
        size = sum(p.size for p in self.packages)

        t = textwrap.dedent(
            f"""\
            SourcePackage: {self.name}
            Packages:      {" ".join(p.name for p in self.packages)}
            Size:          {size}
            """
        )
        if self.changelog:
            t += f"""\nChangelog:\n{self.changelog}\n"""
        return t


@dataclasses.dataclass
class Manifest:
    context: Context
    packages: list[PackageManifest] = dataclasses.field(default_factory=list)
    source_packages: dict[str, SourcePackageManifest] = dataclasses.field(default_factory=dict)
    extension: dict[str, str] = dataclasses.field(default_factory=dict)

    _init_timestamp: datetime.datetime = dataclasses.field(
        init=False, default_factory=lambda: datetime.datetime.now().replace(microsecond=0)
    )

    def need_source_info(self) -> bool:
        return ManifestFormat.changelog in self.context.config.manifest_format

    def record_packages(self) -> None:
        with complete_step("Recording packages in manifest…"):
            if self.context.config.distribution.package_type() == PackageType.rpm:
                self.record_rpm_packages()
            if self.context.config.distribution.package_type() == PackageType.deb:
                self.record_deb_packages()
            if self.context.config.distribution.package_type() == PackageType.pkg:
                self.record_pkg_packages()

    def record_rpm_packages(self) -> None:
        c = run(
            [
                "rpm",
                "--root=/buildroot",
                "--query",
                "--all",
                "--queryformat", r"%{NEVRA}\t%{SOURCERPM}\t%{NAME}\t%{ARCH}\t%{LONGSIZE}\t%{INSTALLTIME}\n",
            ],
            stdout=subprocess.PIPE,
            sandbox=(
                self.context.sandbox(options=["--ro-bind", self.context.root, "/buildroot"])
            ),
        )  # fmt: skip

        packages = sorted(c.stdout.splitlines())

        for package in packages:
            nevra, srpm, name, arch, size, installtime = package.split("\t")

            assert nevra.startswith(f"{name}-")
            evra = nevra.removeprefix(f"{name}-")
            # Some packages have architecture '(none)', and it's not part of NEVRA, e.g.:
            # gpg-pubkey-45719a39-5f2c0192 gpg-pubkey (none) 0 1635985199
            if arch != "(none)":
                assert nevra.endswith(f".{arch}")
                evr = evra.removesuffix(f".{arch}")
            else:
                evr = evra
                arch = ""

            # If we are creating a layer based on a BaseImage=, e.g. a sysext, filter by
            # packages that were installed in this execution of mkosi. We assume that the
            # upper layer is put together in one go, which currently is always true.
            if (
                self.context.config.base_trees
                and datetime.datetime.fromtimestamp(int(installtime)) < self._init_timestamp
            ):
                continue

            manifest = PackageManifest("rpm", name, evr, arch, int(size))
            self.packages.append(manifest)

            if not self.need_source_info():
                continue

            source = self.source_packages.get(srpm)
            if source is None:
                c = run(
                    [
                        "rpm",
                        "--root=/buildroot",
                        "--query",
                        "--changelog",
                        nevra,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    sandbox=self.context.sandbox(options=["--ro-bind", self.context.root, "/buildroot"]),
                )
                changelog = c.stdout.strip()
                source = SourcePackageManifest(srpm, changelog)
                self.source_packages[srpm] = source

            source.add(manifest)

    def record_deb_packages(self) -> None:
        c = run(
            [
                "dpkg-query",
                "--admindir=/buildroot/var/lib/dpkg",
                "--show",
                "--showformat", r"${Package}\t${source:Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${db-fsys:Last-Modified}\n",  # noqa: E501
            ],
            stdout=subprocess.PIPE,
            sandbox=self.context.sandbox(options=["--ro-bind", self.context.root, "/buildroot"]),
        )  # fmt: skip

        packages = sorted(c.stdout.splitlines())

        for package in packages:
            name, source, version, arch, size, installtime = package.split("\t")

            # dpkg records the size in KBs, the field is optional db-fsys:Last-Modified is not available in
            # very old dpkg, so just skip creating the manifest for sysext when building on very old
            # distributions by setting the timestamp to epoch. This only affects Ubuntu Bionic which is
            # nearing EOL.  If we are creating a layer based on a BaseImage=, e.g. a sysext, filter by
            # packages that were installed in this execution of mkosi. We assume that the upper layer is put
            # together in one go, which currently is always true.
            install_timestamp = datetime.datetime.fromtimestamp(int(installtime) if installtime else 0)
            if self.context.config.base_trees and install_timestamp < self._init_timestamp:
                continue

            manifest = PackageManifest("deb", name, version, arch, int(size or 0) * 1024)
            self.packages.append(manifest)

            if not self.need_source_info():
                continue

            source_package = self.source_packages.get(source)
            if source_package is None:
                # Yes, --quiet is specified twice, to avoid output about download stats. Note that the
                # argument of the 'changelog' verb is the binary package name, not the source package
                # name. We also have to set "Dir" explicitly because apt has no separate option to configure
                # the changelog directory. Apt.invoke() sets all options that are interpreted relative to Dir
                # to absolute paths by default so this is safe.
                result = Apt.invoke(
                    self.context,
                    "changelog",
                    ["--quiet", "--quiet", "-o", "Dir=/buildroot", name],
                    stdout=subprocess.PIPE,
                )
                source_package = SourcePackageManifest(source, result.stdout.strip())
                self.source_packages[source] = source_package

            source_package.add(manifest)

    def record_pkg_packages(self) -> None:
        packages = sorted((self.context.root / "var/lib/pacman/local").glob("*/desc"))

        for desc in packages:
            name, version, source, arch = Pacman.parse_pkg_desc(desc)
            package = PackageManifest("pkg", name, version, arch, 0)
            self.packages.append(package)

            source_package = self.source_packages.get(source)
            if source_package is None:
                source_package = SourcePackageManifest(source, None)
                self.source_packages[source] = source_package
            source_package.add(package)

    def record_extension_release(self) -> None:
        if self.context.config.output_format not in (OutputFormat.sysext, OutputFormat.confext):
            return

        with complete_step(f"Recording {type} information in manifest…"):
            d = "usr/lib" if self.context.config.output_format == OutputFormat.sysext else "etc"
            p = self.context.root / d / f"extension-release.d/extension-release.{self.context.config.output}"

            self.extension = read_env_file(p)

    def has_data(self) -> bool:
        # We might add more data in the future
        return len(self.packages) > 0 or len(self.extension) > 0

    def as_dict(self) -> dict[str, Any]:
        config = {
            "name": self.context.config.image_id or "image",
            "distribution": str(self.context.config.distribution),
            "architecture": str(self.context.config.architecture),
            "output_format": str(self.context.config.output_format),
        }
        if self.context.config.image_version is not None:
            config["version"] = self.context.config.image_version
        if self.context.config.release is not None:
            config["release"] = str(self.context.config.release)

        return {
            # Bump this when incompatible changes are made to the manifest format.
            "manifest_version": 1,
            # Describe the image itself.
            "config": config,
            # Describe the image content in terms of packages.
            "packages": [package.as_dict() for package in self.packages],
            # Describe the SYSEXT / CONFEXT metadata.
            "extension": self.extension,
        }

    def write_json(self, out: IO[str]) -> None:
        json.dump(self.as_dict(), out, indent=2)

    def write_package_report(self, out: IO[str]) -> None:
        """Create a human-readable report about packages

        This is modelled after "Fedora compose reports" that are sent
        to fedora-devel. The format describes added and removed
        packages, and includes the changelogs. A diff between two such
        reports shows what changed *in* the packages quite nicely.
        """
        out.write(f"Packages: {len(self.packages)}\n")
        out.write(f"Size:     {sum(p.size for p in self.packages)}")

        for package in self.source_packages.values():
            out.write(f"\n{80 * '-'}\n")
            out.write(package.report())
