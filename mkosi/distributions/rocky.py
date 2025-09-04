# SPDX-License-Identifier: LGPL-2.1-or-later

from mkosi.context import Context
from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Rocky Linux"

    @classmethod
    def gpgurls(cls, context: Context) -> tuple[str, ...]:
        return (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-Rocky-{context.config.release.major}",
                f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-{context.config.release.major}",
            ),
        )

    @classmethod
    def repository_variants(
        cls,
        context: Context,
        gpgurls: tuple[str, ...],
        repo: str,
    ) -> list[RpmRepository]:
        if context.config.mirror:
            url = f"baseurl={join_mirror(context.config.mirror, f'$releasever/{repo}/$basearch/os')}"
        else:
            url = f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo={repo}-$releasever"

        return [RpmRepository(repo, url, gpgurls)]

    @classmethod
    def sig_repositories(cls, context: Context) -> list[RpmRepository]:
        return []
