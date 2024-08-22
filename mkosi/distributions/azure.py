# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import (
    fedora,
    join_mirror,
)
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.log import die
from mkosi.util import listify


class Installer(fedora.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Azure Linux"

    @classmethod
    def default_release(cls) -> str:
        return "3.0-prod"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def setup(cls, context: Context) -> None:
        Dnf.setup(context, cls.repositories(context), filelists=False)
        setup_rpm(context, dbpath="/var/lib/rpm")

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem", "azurelinux-release"], apivfs=False)

    @classmethod
    @listify
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        gpgurls = (
            find_rpm_gpgkey(
                context,
                "MICROSOFT-RPM-GPG-KEY",
                "https://raw.githubusercontent.com/rpm-software-management/distribution-gpg-keys/main/keys/azure-linux/MICROSOFT-RPM-GPG-KEY",
            ),
        )

        if context.config.local_mirror:
            yield RpmRepository("base", f"baseurl={context.config.local_mirror}", gpgurls)
            return

        mirror = context.config.mirror or "https://packages.microsoft.com/azurelinux"

        if any(context.config.release.endswith(f"-{suffix}") for suffix in ("prod", "preview")):
            rel = context.config.release
        else:
            rel = f"{context.config.release}-prod"

        url = join_mirror(mirror, rel.replace("-", "/"))

        nvidia = "nvidia" if rel.endswith("-prod") else "NVIDIA"
        for repo in ("base", "extended", "ms-oss", "ms-non-oss", "cloud-native", nvidia):
            yield RpmRepository(
                repo,
                f"baseurl={url}/{repo}/$basearch",
                gpgurls,
            )

        for repo in ("base", "cloud-native", "extended"):
            yield RpmRepository(
                f"{repo}-debuginfo",
                f"baseurl={url}/{repo}/debuginfo/$basearch",
                gpgurls,
                enabled=False,
            )

        for repo in ("base", "cloud-native", "extended", "ms-oss"):
            yield RpmRepository(
                f"{repo}-source",
                f"baseurl={url}/{repo}/srpms",
                gpgurls,
                enabled=False,
            )

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm64  : "aarch64",
            Architecture.x86_64 : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a
