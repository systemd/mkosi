# SPDX-License-Identifier: LGPL-2.1+

from mkosi.config import MkosiConfig
from mkosi.distributions.centos import CentosInstaller
from mkosi.installer.dnf import Repo


class AlmaInstaller(CentosInstaller):
    @staticmethod
    def gpgurls() -> tuple[str, ...]:
        return ("https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-$releasever",)

    @classmethod
    def repository_url(cls, config: MkosiConfig, repo: str) -> str:
        if config.mirror:
            return f"baseurl={config.mirror}/almalinux/$releasever/{repo}/$basearch/os"
        else:
            return f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/{repo.lower()}"

    @classmethod
    def sig_repositories(cls, config: MkosiConfig) -> list[Repo]:
        return []
