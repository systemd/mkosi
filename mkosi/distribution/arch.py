# SPDX-License-Identifier: LGPL-2.1-or-later

import datetime
import tempfile
from collections.abc import Iterable
from pathlib import Path

from mkosi.archive import extract_tar
from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distribution import Distribution, DistributionInstaller, PackageType, join_mirror
from mkosi.installer.pacman import Pacman, PacmanRepository
from mkosi.log import complete_step, die


class Installer(DistributionInstaller, distribution=Distribution.arch):
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
                    output_dir=Path(d),
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
    def repositories(cls, context: Context) -> Iterable[PacmanRepository]:
        if context.config.local_mirror:
            yield PacmanRepository("core", context.config.local_mirror)
        else:
            if context.config.architecture.is_arm_variant():
                if context.config.snapshot and not context.config.mirror:
                    die("There is no known public mirror for snapshots of Arch Linux ARM")

                mirror = context.config.mirror or "http://mirror.archlinuxarm.org"
            else:
                if context.config.mirror:
                    mirror = context.config.mirror
                elif context.config.snapshot:
                    mirror = "https://archive.archlinux.org"
                else:
                    mirror = "https://geo.mirror.pkgbuild.com"

            if context.config.snapshot:
                url = join_mirror(mirror, f"repos/{context.config.snapshot}/$repo/os/$arch")
            elif context.config.architecture.is_arm_variant():
                url = join_mirror(mirror, "$arch/$repo")
            else:
                url = join_mirror(mirror, "$repo/os/$arch")

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

    @classmethod
    def latest_snapshot(cls, config: Config) -> str:
        url = join_mirror(config.mirror or "https://archive.archlinux.org", "repos/last/lastsync")
        return datetime.datetime.fromtimestamp(int(curl(config, url)), datetime.timezone.utc).strftime(
            "%Y/%m/%d"
        )

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        return package in ("linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt", "linux-rt-lts")
