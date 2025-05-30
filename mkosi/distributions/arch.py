# SPDX-License-Identifier: LGPL-2.1-or-later

import tempfile
from collections.abc import Iterable
from pathlib import Path

from mkosi.archive import extract_tar
from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distributions import DistributionInstaller, PackageType
from mkosi.installer.pacman import Pacman, PacmanRepository
from mkosi.log import complete_step, die


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
    def package_manager(cls, config: "Config") -> type[Pacman]:
        return Pacman

    @classmethod
    def keyring(cls, context: Context) -> None:
        if context.config.repository_key_fetch:
            with (
                complete_step(f"Downloading {cls.pretty_name()} keyring"),
                tempfile.TemporaryDirectory() as d,
            ):
                curl(
                    context.config,
                    "https://archlinux.org/packages/core/any/archlinux-keyring/download",
                    Path(d),
                )
                extract_tar(
                    next(Path(d).iterdir()),
                    context.sandbox_tree,
                    dirs=["usr/share/pacman/keyrings"],
                    sandbox=context.sandbox,
                )

        Pacman.keyring(context)

    @classmethod
    def setup(cls, context: Context) -> None:
        Pacman.setup(context, list(cls.repositories(context)))

    @classmethod
    def install(cls, context: Context) -> None:
        Pacman.install(context, ["filesystem"], apivfs=False)

    @classmethod
    def finalize(cls, context: Context) -> None:
        pass

    @classmethod
    def repositories(cls, context: Context) -> Iterable[PacmanRepository]:
        if context.config.local_mirror:
            yield PacmanRepository("core", context.config.local_mirror)
        else:
            if context.config.architecture.is_arm_variant():
                url = f"{context.config.mirror or 'http://mirror.archlinuxarm.org'}/$arch/$repo"
            else:
                url = f"{context.config.mirror or 'https://geo.mirror.pkgbuild.com'}/$repo/os/$arch"

            # Testing repositories have to go before regular ones to to take precedence.
            repos = [
                repo
                for repo in (
                    "core-testing",
                    "core-testing-debug",
                    "extra-testing",
                    "extra-testing-debug",
                    "core-debug",
                    "extra-debug",
                    "multilib-testing",
                    "multilib",
                )
                if repo in context.config.repositories
            ] + ["core", "extra"]

            if context.config.architecture.is_arm_variant():
                repos += ["alarm"]

            for repo in repos:
                yield PacmanRepository(repo, url)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "x86_64",
            Architecture.arm64:  "aarch64",
            Architecture.arm:    "armv7h",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by Arch Linux")

        return a
