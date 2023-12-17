# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.distributions import DistributionInstaller
from mkosi.log import die
from mkosi.state import MkosiState


class Installer(DistributionInstaller):
    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        return str(arch)

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        pass

    @classmethod
    def install(cls, state: MkosiState) -> None:
        pass

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        if packages:
            die("Installing packages is not supported for custom distributions'")

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        if packages:
            die("Removing packages is not supported for custom distributions")
