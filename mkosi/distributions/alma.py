# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.config import MkosiConfig
from mkosi.distributions import centos
from mkosi.installer.dnf import Repo


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "AlmaLinux"

    @staticmethod
    def gpgurls(config: MkosiConfig) -> tuple[str, ...]:
        gpgpath = Path(f"/usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-{config.release}")
        if gpgpath.exists():
            return (f"file://{gpgpath}",)
        else:
            return ("https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-$releasever",)

    @classmethod
    def repository_variants(cls, config: MkosiConfig, repo: str) -> list[Repo]:
        if config.mirror:
            url = f"baseurl={config.mirror}/almalinux/$releasever/{repo}/$basearch/os"
        else:
            url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/{repo.lower()}"

        return [Repo(repo, url, cls.gpgurls(config))]

    @classmethod
    def sig_repositories(cls, config: MkosiConfig) -> list[Repo]:
        return []
