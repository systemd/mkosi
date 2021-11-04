# SPDX-License-Identifier: LGPL-2.1+

import dataclasses
import json
from datetime import datetime
from pathlib import Path
from subprocess import DEVNULL, PIPE
from textwrap import dedent
from typing import IO, Any, Dict, List, Optional, cast

from .backend import (
    CommandLineArguments,
    Distribution,
    ManifestFormat,
    PackageType,
    run,
    run_workspace_command,
)


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

    def as_dict(self) -> Dict[str, str]:
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
    packages: List[PackageManifest] = dataclasses.field(default_factory=list)

    def add(self, package: PackageManifest) -> None:
        self.packages.append(package)

    def report(self) -> str:
        size = sum(p.size for p in self.packages)

        t = dedent(
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
    args: CommandLineArguments
    packages: List[PackageManifest] = dataclasses.field(default_factory=list)
    source_packages: Dict[str, SourcePackageManifest] = dataclasses.field(default_factory=dict)

    _init_timestamp: datetime = dataclasses.field(init=False, default_factory=datetime.now)

    def need_source_info(self) -> bool:
        return ManifestFormat.changelog in self.args.manifest_format

    def record_packages(self, root: Path) -> None:
        if cast(Any, self.args.distribution).package_type == PackageType.rpm:
            self.record_rpm_packages(root)
        if cast(Any, self.args.distribution).package_type == PackageType.deb:
            self.record_deb_packages(root)
        # TODO: add implementations for other package managers

    def record_rpm_packages(self, root: Path) -> None:
        c = run(
            ["rpm", f"--root={root}", "-qa", "--qf",
             r"%{NEVRA}\t%{SOURCERPM}\t%{NAME}\t%{ARCH}\t%{SIZE}\t%{INSTALLTIME}\n"],
            stdout=PIPE,
            stderr=DEVNULL,
            text=True,
        )

        packages = sorted(c.stdout.splitlines())

        for package in packages:
            nevra, srpm, name, arch, size, installtime = package.split("\t")

            assert nevra.startswith(f"{name}-")
            evra = nevra[len(name) + 1 :]
            # Some packages have architecture '(none)', and it's not part of NEVRA, e.g.:
            # gpg-pubkey-45719a39-5f2c0192 gpg-pubkey (none) 0 1635985199
            if arch != "(none)":
                assert nevra.endswith(f".{arch}")
                evr = evra[: len(arch) + 1]
            else:
                evr = evra
                arch = ""

            size = int(size)
            installtime = datetime.fromtimestamp(int(installtime))

            # If we are creating a layer based on a BaseImage=, e.g. a sysext, filter by
            # packages that were installed in this execution of mkosi. We assume that the
            # upper layer is put together in one go, which currently is always true.
            if self.args.base_image and installtime < self._init_timestamp:
                continue

            package = PackageManifest("rpm", name, evr, arch, size)
            self.packages.append(package)

            if not self.need_source_info():
                continue

            source = self.source_packages.get(srpm)
            if source is None:
                c = run(["rpm", f"--root={root}", "-q", "--changelog", nevra],
                        stdout=PIPE,
                        stderr=DEVNULL,
                        text=True)
                changelog = c.stdout.strip()
                source = SourcePackageManifest(srpm, changelog)
                self.source_packages[srpm] = source

            source.add(package)

    def record_deb_packages(self, root: Path) -> None:
        c = run(
            ["dpkg-query", f"--admindir={root}/var/lib/dpkg", "--show", "--showformat",
             r'${Package}\t${source:Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${db-fsys:Last-Modified}\n'],
            stdout=PIPE,
            stderr=DEVNULL,
            text=True,
        )

        packages = sorted(c.stdout.splitlines())

        for package in packages:
            name, source, version, arch, size, installtime = package.split("\t")

            # dpkg records the size in KBs
            size = int(size) * 1024
            installtime = datetime.fromtimestamp(int(installtime))

            # If we are creating a layer based on a BaseImage=, e.g. a sysext, filter by
            # packages that were installed in this execution of mkosi. We assume that the
            # upper layer is put together in one go, which currently is always true.
            if self.args.base_image and installtime < self._init_timestamp:
                continue

            package = PackageManifest("deb", name, version, arch, size)
            self.packages.append(package)

            if not self.need_source_info():
                continue

            source_package = self.source_packages.get(source)
            if source_package is None:
                # Yes, --quiet is specified twice, to avoid output about download stats.
                # Note that the argument of the 'changelog' verb is the binary package name,
                # not the source package name.
                cmd = ["apt-get", "--quiet", "--quiet", "changelog", name]

                # If we are building with docs then it's easy, as the changelogs are saved
                # in the image, just fetch them. Otherwise they will be downloaded from the network.
                if self.args.with_docs:
                    # By default apt drops privileges and runs as the 'apt' user, but that means it
                    # loses access to the build directory, which is 700.
                    cmd += ["--option", "Acquire::Changelogs::AlwaysOnline=false",
                            "--option", "Debug::NoDropPrivs=true"]
                else:
                    # Override the URL to avoid HTTPS, so that we don't need to install
                    # ca-certificates to make it work.
                    if self.args.distribution == Distribution.ubuntu:
                        cmd += ["--option", "Acquire::Changelogs::URI::Override::Origin::Ubuntu=http://changelogs.ubuntu.com/changelogs/pool/@CHANGEPATH@/changelog"]
                    else:
                        cmd += ["--option", "Acquire::Changelogs::URI::Override::Origin::Debian=http://metadata.ftp-master.debian.org/changelogs/@CHANGEPATH@_changelog"]

                # We have to run from the root, because if we use the RootDir option to make
                # apt from the host look at the repositories in the image, it will also pick
                # the 'methods' executables from there, but the ABI might not be compatible.
                changelog = run_workspace_command(self.args, root, cmd, network=not self.args.with_docs, capture_stdout=True)
                source_package = SourcePackageManifest(source, changelog)
                self.source_packages[source] = source_package

            source_package.add(package)

    def has_data(self) -> bool:
        # We might add more data in the future
        return len(self.packages) > 0

    def as_dict(self) -> Dict[str, Any]:
        return {
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
        print(f"Packages: {len(self.packages)}", file=out)
        print(f"Size:     {sum(p.size for p in self.packages)}", file=out)

        for package in self.source_packages.values():
            print(f"\n{80*'-'}\n", file=out)
            out.write(package.report())
