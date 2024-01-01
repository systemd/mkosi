# SPDX-License-Identifier: LGPL-2.1+

from mkosi.context import Context
from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Rocky Linux"

    @staticmethod
    def gpgurls(context: Context) -> tuple[str, ...]:
        return (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-Rocky-{context.config.release}",
                f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-{context.config.release}",
            ),
        )

    @classmethod
    def repository_variants(cls, context: Context, repo: str) -> list[RpmRepository]:
        if context.config.mirror:
            url = f"baseurl={join_mirror(context.config.mirror, f'rocky/$releasever/{repo}/$basearch/os')}"
        else:
            url = f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo={repo}-$releasever"

        return [RpmRepository(repo, url, cls.gpgurls(context))]

    @classmethod
    def sig_repositories(cls, context: Context) -> list[RpmRepository]:
        return []
