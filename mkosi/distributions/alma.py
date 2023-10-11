# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.distributions import centos
from mkosi.installer.dnf import Repo
from mkosi.state import MkosiState


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "AlmaLinux"

    @staticmethod
    def gpgurls(state: MkosiState) -> tuple[str, ...]:
        gpgpath = Path(f"/usr/share/distribution-gpg-keys/alma/RPM-GPG-KEY-AlmaLinux-{state.config.release}")
        if gpgpath.exists():
            return (f"file://{gpgpath}",)
        else:
            return ("https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-$releasever",)

    @classmethod
    def repository_variants(cls, state: MkosiState, repo: str) -> list[Repo]:
        if state.config.mirror:
            url = f"baseurl={state.config.mirror}/almalinux/$releasever/{repo}/$basearch/os"
        else:
            url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/{repo.lower()}"

        return [Repo(repo, url, cls.gpgurls(state))]

    @classmethod
    def sig_repositories(cls, state: MkosiState) -> list[Repo]:
        return []
