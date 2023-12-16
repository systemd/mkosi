# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable

from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.state import MkosiState


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "RHEL UBI"

    @staticmethod
    def gpgurls(state: MkosiState) -> tuple[str, ...]:
        major = int(float(state.config.release))

        return (
            find_rpm_gpgkey(
                state,
                f"RPM-GPG-KEY-redhat{major}-release",
                "https://access.redhat.com/security/data/fd431d51.txt",
            ),
        )

    @classmethod
    def repository_variants(cls, state: MkosiState, repo: str) -> Iterable[RpmRepository]:
        if state.config.local_mirror:
            yield RpmRepository(repo, f"baseurl={state.config.local_mirror}", cls.gpgurls(state))
        else:
            mirror = state.config.mirror or "https://cdn-ubi.redhat.com/content/public/ubi/dist/"

            v = state.config.release
            yield RpmRepository(
                f"ubi-{v}-{repo}-rpms",
                f"baseurl={join_mirror(mirror, f'ubi{v}/{v}/$basearch/{repo}/os')}",
                cls.gpgurls(state),
            )
            yield RpmRepository(
                f"ubi-{v}-{repo}-debug-rpms",
                f"baseurl={join_mirror(mirror, f'ubi{v}/{v}/$basearch/{repo}/debug')}",
                cls.gpgurls(state),
                enabled=False,
            )
            yield RpmRepository(
                f"ubi-{v}-{repo}-source",
                f"baseurl={join_mirror(mirror, f'ubi{v}/{v}/$basearch/{repo}/source')}",
                cls.gpgurls(state),
                enabled=False,
            )

    @classmethod
    def repositories(cls, state: MkosiState) -> Iterable[RpmRepository]:
        yield from cls.repository_variants(state, "baseos")
        yield from cls.repository_variants(state, "appstream")
        yield from cls.repository_variants(state, "codeready-builder")
        yield from cls.epel_repositories(state)
