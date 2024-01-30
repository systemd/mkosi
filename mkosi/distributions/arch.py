# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable, Sequence

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.pacman import Pacman
from mkosi.log import die


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
    def package_manager(cls, config: "Config") -> type[PackageManager]:
        return Pacman

    @classmethod
    def createrepo(cls, context: Context) -> None:
        Pacman.createrepo(context)

    @classmethod
    def setup(cls, context: Context) -> None:
        Pacman.setup(context, cls.repositories(context))

    @classmethod
    def sync(cls, context: Context) -> None:
        Pacman.sync(context)

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        Pacman.invoke(
            context,
            "--sync",
            ["--needed", "--assume-installed", "initramfs"],
            packages,
            apivfs=apivfs,
        )

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        Pacman.invoke(context, "--remove", ["--nosave", "--recursive"], packages)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[Pacman.Repository]:
        if context.config.local_mirror:
            yield Pacman.Repository("core", context.config.local_mirror)
        else:
            if context.config.architecture == Architecture.arm64:
                url = f"{context.config.mirror or 'http://mirror.archlinuxarm.org'}/$arch/$repo"
            else:
                url = f"{context.config.mirror or 'https://geo.mirror.pkgbuild.com'}/$repo/os/$arch"

            # Testing repositories have to go before regular ones to to take precedence.
            repos = [
                repo for repo in (
                    "core-testing",
                    "core-testing-debug",
                    "extra-testing",
                    "extra-testing-debug",
                    "core-debug",
                    "extra-debug",
                ) if repo in context.config.repositories
            ] + ["core", "extra"]

            for repo in repos:
                yield Pacman.Repository(repo, url)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Arch Linux")

        return a

