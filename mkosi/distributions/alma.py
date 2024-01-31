# SPDX-License-Identifier: LGPL-2.1+

from mkosi.context import Context
from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "AlmaLinux"

    @staticmethod
    def gpgurls(context: Context) -> tuple[str, ...]:
        return (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-AlmaLinux-{context.config.release}",
            ) or f"https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-{context.config.release}",
        )

    @classmethod
    def repository_variants(cls, context: Context, repo: str) -> list[RpmRepository]:
        if context.config.mirror:
            url = f"baseurl={join_mirror(context.config.mirror, f'almalinux/$releasever/{repo}/$basearch/os')}"
        else:
            url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/{repo.lower()}"

        return [RpmRepository(repo, url, cls.gpgurls(context))]

    @classmethod
    def sig_repositories(cls, context: Context) -> list[RpmRepository]:
        return []
