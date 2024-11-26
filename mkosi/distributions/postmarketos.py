# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable, Sequence

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.apk import Apk
from mkosi.log import die
from mkosi.util import sort_packages


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "postmarketOS"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.apk

    @classmethod
    def default_release(cls) -> str:
        return "rolling"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.postmarketos

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        return Apk

    @classmethod
    def setup(cls, context: Context) -> None:
        Apk.setup(context, list(cls.repositories(context)))

    @classmethod
    def install(cls, context: Context) -> None:
        import logging
        (context.root / "lib").symlink_to("usr/lib")
        (context.root / "bin").symlink_to("usr/bin")
        (context.root / "usr/lib").mkdir(parents=True, exist_ok=True)
        (context.root / "usr/bin").mkdir(parents=True, exist_ok=True)
        for p in context.root.rglob("*"):
            logging.warning(str(p))
        cls.install_packages(context, [
            "--initdb",
            "alpine-base",
            "postmarketos-base",
            # "device-qemu-amd64",
            # "device-qemu-amd64-kernel-edge",
        ], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        Apk.invoke(
            context,
            "add",
            [*sort_packages(packages)],
            apivfs=apivfs,
        )

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        Apk.invoke(context, "del", [*packages], apivfs=True)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[str]:
        print("fetch repos")
        return iter([
            "https://mirror.postmarketos.org/postmarketos/staging/systemd/master/",
            "http://mirror.postmarketos.org/postmarketos/master",
            "http://dl-cdn.alpinelinux.org/alpine/edge/main",
            "http://dl-cdn.alpinelinux.org/alpine/edge/community",
            "http://dl-cdn.alpinelinux.org/alpine/edge/testing",
        ])

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "x86_64",
            Architecture.arm64:  "aarch64",
            Architecture.arm:    "armv7h",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by Alpine Linux")

        return a
