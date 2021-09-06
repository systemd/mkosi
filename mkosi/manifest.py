# SPDX-License-Identifier: LGPL-2.1+

import dataclasses
import json
from pathlib import Path
from subprocess import DEVNULL, PIPE
from textwrap import dedent
from typing import IO, Any, Dict, List, Optional, cast

from .backend import CommandLineArguments, PackageType, run


@dataclasses.dataclass
class PackageManifest:
    """A description of a package

    The fields used here must match
    https://systemd.io/COREDUMP_PACKAGE_METADATA/#well-known-keys.
    """

    type: str
    name: str
    version: str
    size: int

    def as_dict(self) -> Dict[str, str]:
        return {
            "type": self.type,
            "name": self.name,
            "version": self.version,
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

    def record_packages(self, root: Path) -> None:
        if cast(Any, self.args.distribution).package_type == PackageType.rpm:
            self.record_rpm_packages(root)
        # TODO: add implementations for other package managers

    def record_rpm_packages(self, root: Path) -> None:
        c = run(
            ["rpm", f"--root={root}", "-qa", "--qf", r"%{NEVRA}\t%{SOURCERPM}\t%{NAME}\t%{SIZE}\n"],
            stdout=PIPE,
            stderr=DEVNULL,
            universal_newlines=True,
        )

        packages = sorted(c.stdout.splitlines())

        for package in packages:
            nevra, srpm, name, size = package.split("\t")

            assert nevra.startswith(f"{name}-")
            evra = nevra[len(name) + 1 :]

            size = int(size)

            source = self.source_packages.get(srpm)
            if source is None:
                c = run(
                    ["rpm", f"--root={root}", "-q", "--changelog", nevra],
                    stdout=PIPE,
                    stderr=DEVNULL,
                    universal_newlines=True,
                )
                changelog = c.stdout.strip()
                source = SourcePackageManifest(srpm, changelog)
                self.source_packages[srpm] = source

            package = PackageManifest("rpm", name, evra, size)
            self.packages.append(package)
            source.add(package)

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
