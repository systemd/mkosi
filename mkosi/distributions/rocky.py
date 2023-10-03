# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.config import MkosiConfig
from mkosi.distributions import centos
from mkosi.installer.dnf import Repo


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Rocky Linux"

    @staticmethod
    def gpgurls(config: MkosiConfig) -> tuple[str, ...]:
        gpgpath = Path(f"/usr/share/distribution-gpg-keys/rocky/RPM-GPG-KEY-Rocky-{config.release}")
        if gpgpath.exists():
            return (f"file://{gpgpath}",)
        else:
            return ("https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-$releasever",)

    @classmethod
    def repository_variants(cls, config: MkosiConfig, repo: str) -> list[Repo]:
        if config.mirror:
            url = f"baseurl={config.mirror}/rocky/$releasever/{repo}/$basearch/os"
        else:
            url = f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo={repo}-$releasever"

        return [Repo(repo, url, cls.gpgurls(config))]

    @classmethod
    def sig_repositories(cls, config: MkosiConfig) -> list[Repo]:
        return []
