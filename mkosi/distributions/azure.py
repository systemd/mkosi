# SPDX-License-Identifier: LGPL-2.1-or-later

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


class Installer(fedora.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Azure Linux"

    @classmethod
    def default_release(cls) -> str:
        return "3.0"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def setup(cls, context: Context) -> None:
        Dnf.setup(context, list(cls.repositories(context)), filelists=False)
        setup_rpm(context, dbpath="/var/lib/rpm")

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem", "azurelinux-release"], apivfs=False)

    @classmethod
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
        url = join_mirror(mirror, context.config.release)

        for repo in ("base", "extended", "ms-oss", "ms-non-oss", "cloud-native", "nvidia"):
            yield RpmRepository(
                repo,
                f"baseurl={url}/prod/{repo}/$basearch",
                gpgurls,
            )

            repo = "NVIDIA" if repo == "nvidia" else repo
            yield RpmRepository(
                f"{repo}-preview",
                f"baseurl={url}/preview/{repo}/$basearch",
                gpgurls,
                enabled=False,
            )

        for repo in ("base", "cloud-native", "extended"):
            yield RpmRepository(
                f"{repo}-debuginfo",
                f"baseurl={url}/prod/{repo}/debuginfo/$basearch",
                gpgurls,
                enabled=False,
            )
            yield RpmRepository(
                f"{repo}-preview-debuginfo",
                f"baseurl={url}/preview/{repo}/debuginfo/$basearch",
                gpgurls,
                enabled=False,
            )

        for repo in ("base", "cloud-native", "extended", "ms-oss"):
            yield RpmRepository(
                f"{repo}-source",
                f"baseurl={url}/prod/{repo}/srpms",
                gpgurls,
                enabled=False,
            )
            yield RpmRepository(
                f"{repo}-source",
                f"baseurl={url}/preview/{repo}/srpms",
                gpgurls,
                enabled=False,
            )

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm64:  "aarch64",
            Architecture.x86_64: "x86_64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a
