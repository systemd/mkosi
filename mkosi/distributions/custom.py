# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import DistributionInstaller
from mkosi.log import die


class Installer(DistributionInstaller):
    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        return str(arch)

    @classmethod
    def setup(cls, context: Context) -> None:
        pass

    @classmethod
    def install(cls, context: Context) -> None:
        pass

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str]) -> None:
        if packages:
            die("Installing packages is not supported for custom distributions'")

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        if packages:
            die("Removing packages is not supported for custom distributions")
