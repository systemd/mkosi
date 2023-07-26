# SPDX-License-Identifier: LGPL-2.1+

from mkosi.config import MkosiConfig
from mkosi.distributions.centos import CentosInstaller
from mkosi.installer.dnf import Repo


class RockyInstaller(CentosInstaller):
    @staticmethod
    def gpgurls() -> tuple[str, ...]:
        return ("https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-$releasever",)

    @classmethod
    def repository_url(cls, config: MkosiConfig, repo: str) -> str:
        if config.mirror:
            return f"baseurl={config.mirror}/rocky/$releasever/{repo}/$basearch/os"
        else:
            return f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo={repo}-$releasever"

    @classmethod
    def sig_repositories(cls, config: MkosiConfig) -> list[Repo]:
        return []
