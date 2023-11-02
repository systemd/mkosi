# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.architecture import Architecture
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import Repo, find_rpm_gpgkey, invoke_dnf, setup_dnf
from mkosi.installer.nix import setup_nix, invoke_nix
from mkosi.log import die
from mkosi.state import MkosiState


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "NixOS"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.nix

    @classmethod
    def default_release(cls) -> str:
        return "nixos-unstable"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.nixos

    @classmethod
    def tools_tree_packages(cls) -> list[str]:
        return []

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        setup_nix(state)

    @classmethod
    def install(cls, state: MkosiState) -> None:
        invoke_nix(state)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        pass

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64    : "x86_64-linux",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Fedora")

        return a
