# SPDX-License-Identifier: LGPL-2.1+

import shutil
from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import invoke_dnf, setup_dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Mageia"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def default_release(cls) -> str:
        return "cauldron"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.mageia

    @classmethod
    def setup(cls, context: Context) -> None:
        gpgurls = (
            find_rpm_gpgkey(
                context,
                "RPM-GPG-KEY-Mageia",
                "https://mirrors.kernel.org/mageia/distrib/$releasever/$basearch/media/core/release/media_info/pubkey",
            ),
        )

        repos = []

        if context.config.local_mirror:
            repos += [RpmRepository("core-release", f"baseurl={context.config.local_mirror}", gpgurls)]
        elif context.config.mirror:
            url = f"baseurl={join_mirror(context.config.mirror, 'distrib/$releasever/$basearch/media/core/')}"
            repos += [
                RpmRepository("core-release", f"{url}/release", gpgurls),
                RpmRepository("core-updates", f"{url}/updates/", gpgurls)
            ]
        else:
            url = "mirrorlist=https://www.mageia.org/mirrorlist/?release=$releasever&arch=$basearch&section=core"
            repos += [
                RpmRepository("core-release", f"{url}&repo=release", gpgurls),
                RpmRepository("core-updates", f"{url}&repo=updates", gpgurls)
            ]

        setup_dnf(context, repos)

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(context, "install", packages, apivfs=apivfs)

        for d in context.root.glob("boot/vmlinuz-*"):
            kver = d.name.removeprefix("vmlinuz-")
            vmlinuz = context.root / "usr/lib/modules" / kver / "vmlinuz"
            if not vmlinuz.exists():
                shutil.copy2(d, vmlinuz)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        invoke_dnf(context, "remove", packages)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Mageia")

        return a
