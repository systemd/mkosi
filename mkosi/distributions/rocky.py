# SPDX-License-Identifier: LGPL-2.1+

from mkosi.distributions import centos, join_mirror
from mkosi.installer.dnf import Repo, find_rpm_gpgkey
from mkosi.state import MkosiState


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Rocky Linux"

    @staticmethod
    def gpgurls(state: MkosiState) -> tuple[str, ...]:
        return (
            find_rpm_gpgkey(
                state,
                f"RPM-GPG-KEY-Rocky-{state.config.release}",
                f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-{state.config.release}",
            ),
        )

    @classmethod
    def repository_variants(cls, state: MkosiState, repo: str) -> list[Repo]:
        if state.config.mirror:
            url = f"baseurl={join_mirror(state.config.mirror, f'rocky/$releasever/{repo}/$basearch/os')}"
        else:
            url = f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo={repo}-$releasever"

        return [Repo(repo, url, cls.gpgurls(state))]

    @classmethod
    def sig_repositories(cls, state: MkosiState) -> list[Repo]:
        return []
