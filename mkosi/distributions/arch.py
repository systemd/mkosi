# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller, PackageType
from mkosi.installer.pacman import invoke_pacman, setup_pacman
from mkosi.log import die
from mkosi.state import MkosiState


class ArchInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.pkg

    @classmethod
    def default_release(cls) -> str:
        return "rolling"

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        setup_pacman(state)

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_pacman(state, packages, apivfs=apivfs)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Arch Linux")

        return a

