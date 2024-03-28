# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable, Sequence

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.moss import Moss
from mkosi.log import die


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "iSerpent OS"

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.moss

    @classmethod
    def default_release(cls) -> str:
        return "rolling"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.serpentos

    @classmethod
    def package_manager(cls, config: "Config") -> type[PackageManager]:
        return Moss

    @classmethod
    def createrepo(cls, context: Context) -> None:
        pass

    @classmethod
    def setup(cls, context: Context) -> None:
        Moss.setup(context, cls.repositories(context))

    @classmethod
    def sync(cls, context: Context) -> None:
        pass

    @classmethod
    def install(cls, context: Context) -> None:
        # needed for moss to copy the kernel later
        (context.root / "boot").mkdir(exist_ok=True)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        Moss.invoke(
            context,
            "install",
            [],
            packages,
            apivfs=apivfs,
        )

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        Moss.invoke(context, "remove", [], packages)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[Moss.Repository]:
        url = "https://dev.serpentos.com/volatile/x86_64/stone.index"
        if context.config.local_mirror:
            url = context.config.local_mirror

        yield Moss.Repository("volatile", "Default repository", url, 1000)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a

