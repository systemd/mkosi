# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable, Sequence
import os
from sys import stdout

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.apk import Apk
from mkosi.log import die
from mkosi.mounts import finalize_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.util import listify, sort_packages


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
    def package_manager(cls, config: "Config") -> type[PackageManager]:
        return Apk

    @classmethod
    def createrepo(cls, context: Context) -> None:
        Apk.createrepo(context)

    @classmethod
    def setup(cls, context: Context) -> None:
        Apk.setup(context, cls.repositories(context))

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["--initdb",
                                       "alpine-base",
                                       "postmarketos-base",
                                       "device-qemu-amd64",
                                       "device-qemu-amd64-kernel-edge",
                                       ], apivfs=False)
        root = context.root
        with finalize_source_mounts(
            context.config,
            ephemeral=os.getuid() == 0 and context.config.build_sources_ephemeral,
        ) as sources:
            run(
                ["mv", (root / "etc/os-release"), (root / "usr/lib/os-release")],
                sandbox=(
                    context.sandbox(
                        network=True,
                        options=[
                            "--bind", context.root, context.root,
                            *sources,
                            "--chdir", "/work/src",
                            # pacman will fail unless invoked as root so make sure we're uid/gid 0 in the sandbox.
                            "--uid", "0",
                            "--gid", "0",
                        ],
                    ) + (apivfs_cmd(context.root))
                ),
                env=context.config.environment,
                stdout=None,
            )

        cls.install_packages(context, ["--initdb",
                                       "device-qemu-amd64",
                                       "device-qemu-amd64-kernel-edge",
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
    @listify
    def repositories(cls, context: Context) -> Iterable[str]:
        print("fetch repos")
        return iter([
            "/home/cas/.local/var/pmbootstrap/packages/edge/",
            "http://mirror.postmarketos.org/postmarketos/master",
            "http://dl-cdn.alpinelinux.org/alpine/edge/main",
            "http://dl-cdn.alpinelinux.org/alpine/edge/community",
            "http://dl-cdn.alpinelinux.org/alpine/edge/testing",
        ])

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
            Architecture.arm    : "armv7h",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Alpine Linux")

        return a
