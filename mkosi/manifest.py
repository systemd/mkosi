# SPDX-License-Identifier: LGPL-2.1+

import dataclasses
import json
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
class Manifest:
    args: CommandLineArguments
    packages: List[PackageManifest] = dataclasses.field(default_factory=list)

    def record_packages(self, root: str) -> None:
        if cast(Any, self.args.distribution).package_type == PackageType.rpm:
            self.record_rpm_packages(root)
        # TODO: add implementations for other package managers

    def record_rpm_packages(self, root: str) -> None:
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

            package = PackageManifest("rpm", name, evra, size)
            self.packages.append(package)

    def has_data(self) -> bool:
        # We might add more data in the future
        return len(self.packages) > 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "packages": [package.as_dict() for package in self.packages],
        }

    def write_json(self, out: IO[str]) -> None:
        json.dump(self.as_dict(), out, indent=2)
