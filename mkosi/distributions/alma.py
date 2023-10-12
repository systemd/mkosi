# SPDX-License-Identifier: LGPL-2.1+

from mkosi.distributions import centos
from mkosi.installer.dnf import Repo, find_rpm_gpgkey
from mkosi.state import MkosiState


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "AlmaLinux"

    @staticmethod
    def gpgurls(state: MkosiState) -> tuple[str, ...]:
        return (
            find_rpm_gpgkey(
                state,
                f"RPM-GPG-KEY-AlmaLinux-{state.config.release}",
                f"https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-{state.config.release}",
            ),
        )

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
