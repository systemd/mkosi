# SPDX-License-Identifier: LGPL-2.1-or-later

from mkosi.config import Config
from mkosi.context import Context

from mkosi.log import die
from mkosi.config import Architecture
from mkosi.installer.bst import BST
from mkosi.distribution import (
    Distribution,
    DistributionInstaller,
    PackageType,
)

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
        pass

    @classmethod
    def install(cls, context: Context) -> None:
        pass

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "x86_64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a

    @classmethod
    def latest_snapshot(cls, config: Config) -> str:
        die(f"Latest snapshot not supported by {cls.pretty_name()}")

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        return False
