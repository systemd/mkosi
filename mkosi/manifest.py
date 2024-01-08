# SPDX-License-Identifier: LGPL-2.1+

import dataclasses
import datetime
import json
import logging
import subprocess
import textwrap
from pathlib import Path
from typing import IO, Any, Optional

from mkosi.config import Config, ManifestFormat
from mkosi.distributions import Distribution, PackageType
from mkosi.run import run


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


def parse_pkg_desc(f: Path) -> tuple[str, str, str, str]:
    name = version = base = arch = ""
    with f.open() as desc:
        for line in desc:
            line = line.strip()
            if line == "%NAME%":
                name = next(desc).strip()
            elif line == "%VERSION%":
                version = next(desc).strip()
            elif line == "%BASE%":
                base = next(desc).strip()
            elif line == "%ARCH%":
                arch = next(desc).strip()
                break
    return name, version, base, arch


@dataclasses.dataclass
class Manifest:
    config: Config
    packages: list[PackageManifest] = dataclasses.field(default_factory=list)
    source_packages: dict[str, SourcePackageManifest] = dataclasses.field(default_factory=dict)

    _init_timestamp: datetime.datetime = dataclasses.field(init=False, default_factory=datetime.datetime.now)

    def need_source_info(self) -> bool:
        return ManifestFormat.changelog in self.config.manifest_format

    def record_packages(self, root: Path) -> None:
        if self.config.distribution.package_type() == PackageType.rpm:
            self.record_rpm_packages(root)
        if self.config.distribution.package_type() == PackageType.deb:
            self.record_deb_packages(root)
        if self.config.distribution.package_type() == PackageType.pkg:
            self.record_pkg_packages(root)

    def record_rpm_packages(self, root: Path) -> None:
        # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/ so rpm
        # has to be told to use the location the rpmdb was moved to.
        # Otherwise the rpmdb will appear empty. See: https://bugs.debian.org/1004863
        dbpath = "/usr/lib/sysimage/rpm"
        if not (root / dbpath).exists():
            dbpath = "/var/lib/rpm"

        c = run(
            [
                "rpm",
                f"--root={root}",
                f"--dbpath={dbpath}",
                "-qa",
                "--qf", r"%{NEVRA}\t%{SOURCERPM}\t%{NAME}\t%{ARCH}\t%{LONGSIZE}\t%{INSTALLTIME}\n",
            ],
            stdout=subprocess.PIPE,
            sandbox=self.config.sandbox(),
        )

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

            size = int(size)
            installtime = datetime.datetime.fromtimestamp(int(installtime))

            # If we are creating a layer based on a BaseImage=, e.g. a sysext, filter by
            # packages that were installed in this execution of mkosi. We assume that the
            # upper layer is put together in one go, which currently is always true.
            if self.config.base_trees and installtime < self._init_timestamp:
                continue

            manifest = PackageManifest("rpm", name, evr, arch, size)
            self.packages.append(manifest)

            if not self.need_source_info():
                continue

            source = self.source_packages.get(srpm)
            if source is None:
                c = run(
                    [
                        "rpm",
                        f"--root={root}",
                        f"--dbpath={dbpath}",
                        "-q",
                        "--changelog",
                        nevra,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    sandbox=self.config.sandbox(),
                )
                changelog = c.stdout.strip()
                source = SourcePackageManifest(srpm, changelog)
                self.source_packages[srpm] = source

            source.add(manifest)

    def record_deb_packages(self, root: Path) -> None:
        c = run(
            [
                "dpkg-query",
                f"--admindir={root}/var/lib/dpkg",
                "--show",
                "--showformat",
                    r'${Package}\t${source:Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${db-fsys:Last-Modified}\n',
            ],
            stdout=subprocess.PIPE,
            sandbox=self.config.sandbox(),
        )

        packages = sorted(c.stdout.splitlines())

        for package in packages:
            name, source, version, arch, size, installtime = package.split("\t")

            # dpkg records the size in KBs, the field is optional
            # db-fsys:Last-Modified is not available in very old dpkg, so just skip creating
            # the manifest for sysext when building on very old distributions by setting the
            # timestamp to epoch. This only affects Ubuntu Bionic which is nearing EOL.
            size = int(size) * 1024 if size else 0
            installtime = datetime.datetime.fromtimestamp(int(installtime) if installtime else 0)

            # If we are creating a layer based on a BaseImage=, e.g. a sysext, filter by
            # packages that were installed in this execution of mkosi. We assume that the
            # upper layer is put together in one go, which currently is always true.
            if self.config.base_trees and installtime < self._init_timestamp:
                continue

            manifest = PackageManifest("deb", name, version, arch, size)
            self.packages.append(manifest)

            if not self.need_source_info():
                continue

            source_package = self.source_packages.get(source)
            if source_package is None:
                # Yes, --quiet is specified twice, to avoid output about download stats.
                # Note that the argument of the 'changelog' verb is the binary package name,
                # not the source package name.
                cmd = [
                    "apt-get",
                    "--quiet",
                    "--quiet",
                    "-o", f"Dir={root}",
                    "-o", f"DPkg::Chroot-Directory={root}",
                    "changelog",
                    name,
                ]

                # If we are building with docs then it's easy, as the changelogs are saved
                # in the image, just fetch them. Otherwise they will be downloaded from the network.
                if self.config.with_docs:
                    # By default apt drops privileges and runs as the 'apt' user, but that means it
                    # loses access to the build directory, which is 700.
                    cmd += ["--option", "Acquire::Changelogs::AlwaysOnline=false",
                            "--option", "Debug::NoDropPrivs=true"]
                else:
                    # Override the URL to avoid HTTPS, so that we don't need to install
                    # ca-certificates to make it work.
                    if self.config.distribution == Distribution.ubuntu:
                        cmd += ["--option", "Acquire::Changelogs::URI::Override::Origin::Ubuntu=http://changelogs.ubuntu.com/changelogs/pool/@CHANGEPATH@/changelog"]
                    else:
                        cmd += ["--option", "Acquire::Changelogs::URI::Override::Origin::Debian=http://metadata.ftp-master.debian.org/changelogs/@CHANGEPATH@_changelog"]

                # We have to run from the root, because if we use the RootDir option to make
                # apt from the host look at the repositories in the image, it will also pick
                # the 'methods' executables from there, but the ABI might not be compatible.
                result = run(cmd, stdout=subprocess.PIPE, sandbox=self.config.sandbox())
                source_package = SourcePackageManifest(source, result.stdout.strip())
                self.source_packages[source] = source_package

            source_package.add(manifest)

    def record_pkg_packages(self, root: Path) -> None:
        packages = sorted((root / "var/lib/pacman/local").glob("*/desc"))

        for desc in packages:
            name, version, source, arch = parse_pkg_desc(desc)
            package = PackageManifest("pkg", name, version, arch, 0)
            self.packages.append(package)

            source_package = self.source_packages.get(source)
            if source_package is None:
                source_package = SourcePackageManifest(source, None)
                self.source_packages[source] = source_package
            source_package.add(package)

    def has_data(self) -> bool:
        # We might add more data in the future
        return len(self.packages) > 0

    def as_dict(self) -> dict[str, Any]:
        config = {
            "name": self.config.image_id or "image",
            "distribution": str(self.config.distribution),
            "architecture": str(self.config.architecture),
        }
        if self.config.image_version is not None:
            config["version"] = self.config.image_version
        if self.config.release is not None:
            config["release"] = self.config.release

        return {
            # Bump this when incompatible changes are made to the manifest format.
            "manifest_version": 1,
            # Describe the image itself.
            "config": config,
            # Describe the image content in terms of packages.
            "packages": [package.as_dict() for package in self.packages],
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
        logging.info(f"Packages: {len(self.packages)}")
        logging.info(f"Size:     {sum(p.size for p in self.packages)}")

        for package in self.source_packages.values():
            logging.info(f"\n{80*'-'}\n")
            out.write(package.report())
