# SPDX-License-Identifier: LGPL-2.1-or-later


from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import DistributionInstaller
from mkosi.installer import PackageManager


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Custom"

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        return str(arch)

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        return PackageManager

    @classmethod
    def setup(cls, context: Context) -> None:
        pass

    @classmethod
    def install(cls, context: Context) -> None:
        pass
