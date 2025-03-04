# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.context import Context
from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "RHEL UBI"

    @classmethod
    def gpgurls(cls, context: Context) -> tuple[str, ...]:
        return (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-redhat{cls.major_release(context.config)}-release",
                "https://access.redhat.com/security/data/fd431d51.txt",
            ),
        )

    @classmethod
    def repository_variants(cls, context: Context, repo: str) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(repo, f"baseurl={context.config.local_mirror}", cls.gpgurls(context))
        else:
            mirror = context.config.mirror or "https://cdn-ubi.redhat.com/content/public/ubi/dist/"

            v = context.config.release
            yield RpmRepository(
                f"ubi-{v}-{repo}-rpms",
                f"baseurl={join_mirror(mirror, f'ubi{v}/{v}/$basearch/{repo}/os')}",
                cls.gpgurls(context),
            )
            yield RpmRepository(
                f"ubi-{v}-{repo}-debug-rpms",
                f"baseurl={join_mirror(mirror, f'ubi{v}/{v}/$basearch/{repo}/debug')}",
                cls.gpgurls(context),
                enabled=False,
            )
            yield RpmRepository(
                f"ubi-{v}-{repo}-source",
                f"baseurl={join_mirror(mirror, f'ubi{v}/{v}/$basearch/{repo}/source')}",
                cls.gpgurls(context),
                enabled=False,
            )

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        yield from cls.repository_variants(context, "baseos")
        yield from cls.repository_variants(context, "appstream")
        yield from cls.repository_variants(context, "codeready-builder")
        yield from cls.epel_repositories(context)
