# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.apk import Apk
from mkosi.log import die


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Alpine Linux"

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.apk

    @classmethod
    def default_release(cls) -> str:
        return "edge"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.arch

    @classmethod
    def grub_prefix(cls) -> str:
        return "grub"

    @classmethod
    def package_manager(cls, config: Config) -> type[Apk]:
        return Apk

    @classmethod
    def setup(cls, context: Context) -> None:
        Apk.setup(
            context,
            list(cls.repositories(context)),
        )

    @classmethod
    def install(cls, context: Context) -> None:
        if context.config.repository_key_check and context.config.repository_key_fetch:
            # First install keys, then we can verify other packages installed later.
            Apk.install(context, ["--allow-untrusted", "alpine-keys"])
        Apk.install(context, ["alpine-baselayout", "alpine-release"])

    @classmethod
    def repositories(cls, context: Context) -> Iterable[str]:
        if context.config.snapshot:
            die(f"Snapshot= is currently not supported by {cls.pretty_name()}")

        mirror = context.config.local_mirror
        if not mirror:
            mirror = context.config.mirror
        if not mirror:
            mirror = "https://dl-cdn.alpinelinux.org/alpine"

        url = join_mirror(mirror, context.config.release)

        repos = ["main", "community"]
        if "testing" in context.config.repositories:
            repos += ["testing"]

        for repo in repos:
            yield f"{url}/{repo}"

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm:         "armhf",
            Architecture.arm64:       "aarch64",
            Architecture.loongarch64: "loongarch64",
            Architecture.ppc64_le:    "ppc64le",
            Architecture.riscv64:     "riscv64",
            Architecture.s390x:       "s390x",
            Architecture.x86:         "x86",
            Architecture.x86_64:      "x86_64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is currently not supported by {cls.pretty_name()}")

        return a
