# SPDX-License-Identifier: LGPL-2.1-or-later

from mkosi.context import Context
from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "AlmaLinux"

    @classmethod
    def gpgurls(cls, context: Context) -> tuple[str, ...]:
        major = cls.major_release(context.config)
        return (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-AlmaLinux-{major}",
                f"https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-{major}",
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
            url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/{repo.lower()}"

        return [RpmRepository(repo, url, gpgurls)]

    @classmethod
    def sig_repositories(cls, context: Context) -> list[RpmRepository]:
        return []
