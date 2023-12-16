# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer.pacman import PacmanRepository, invoke_pacman, setup_pacman
from mkosi.log import die
from mkosi.state import MkosiState


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Arch Linux"

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
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.arch

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        if state.config.local_mirror:
            repos = [PacmanRepository("core", state.config.local_mirror)]
        else:
            repos = []

            if state.config.architecture == Architecture.arm64:
                url = f"{state.config.mirror or 'http://mirror.archlinuxarm.org'}/$arch/$repo"
            else:
                url = f"{state.config.mirror or 'https://geo.mirror.pkgbuild.com'}/$repo/os/$arch"

            # Testing repositories have to go before regular ones to to take precedence.
            for id in (
                "core-testing",
                "core-testing-debug",
                "extra-testing",
                "extra-testing-debug",
                "core-debug",
                "extra-debug",
            ):
                if id in state.config.repositories:
                    repos += [PacmanRepository(id, url)]

            for id in ("core", "extra"):
                repos += [PacmanRepository(id, url)]

        setup_pacman(state, repos)

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_pacman(
            state,
            "--sync",
            ["--refresh", "--needed", "--assume-installed", "initramfs"],
            packages,
            apivfs=apivfs,
        )

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_pacman(state, "--remove", ["--nosave", "--recursive"], packages)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Arch Linux")

        return a

