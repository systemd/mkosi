# SPDX-License-Identifier: LGPL-2.1-or-later

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distribution import (
    Distribution,
    DistributionInstaller,
    PackageType,
)
from mkosi.installer.bst import BST
from mkosi.log import die


class Installer(DistributionInstaller, distribution=Distribution.buildstream):
    @classmethod
    def pretty_name(cls) -> str:
        return "BuildStream"

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.none

    @classmethod
    def default_release(cls) -> str:
        return "snapshot"

    @classmethod
    def package_manager(cls, config: "Config") -> type[BST]:
        return BST

    @classmethod
    def setup(cls, context: Context) -> None:
        BST.setup(context)

    @classmethod
    def install(cls, context: Context) -> None:
        pass

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm: "arm-a32",
            Architecture.arm64: "arm-a64",
            Architecture.loongarch64: "la64v100",
            Architecture.ppc64: "power-isa-be",
            Architecture.ppc64_le: "power-isa-le",
            Architecture.riscv32: "rv32g",
            Architecture.riscv64: "rv64g",
            Architecture.x86: "x86-32",
            Architecture.x86_64: "x86-64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {arch} is not supported by {cls.pretty_name()}")

        return a
