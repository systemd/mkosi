# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Optional

from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die
from mkosi.state import MkosiState


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "RHEL"

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

    @staticmethod
    def sslcacert(state: MkosiState) -> Optional[Path]:
        if state.config.mirror:
            return None

        p = Path("etc/rhsm/ca/redhat-uep.pem")
        if (state.pkgmngr / p).exists():
            p = state.pkgmngr / p
        elif (Path("/") / p).exists():
            p = Path("/") / p
        else:
            die("redhat-uep.pem certificate not found in host system or package manager tree")

        return p

    @staticmethod
    def sslclientkey(state: MkosiState) -> Optional[Path]:
        if state.config.mirror:
            return None

        pattern = "etc/pki/entitlement/*-key.pem"

        p = next((p for p in sorted(state.pkgmngr.glob(pattern))), None)
        if not p:
            p = next((p for p in Path("/").glob(pattern)), None)
        if not p:
            die("Entitlement key not found in host system or package manager tree")

        return p

    @staticmethod
    def sslclientcert(state: MkosiState) -> Optional[Path]:
        if state.config.mirror:
            return None

        pattern = "etc/pki/entitlement/*.pem"

        p = next((p for p in sorted(state.pkgmngr.glob(pattern)) if "key" not in p.name), None)
        if not p:
            p = next((p for p in sorted(Path("/").glob(pattern)) if "key" not in p.name), None)
        if not p:
            die("Entitlement certificate not found in host system or package manager tree")

        return p

    @classmethod
    def repository_variants(cls, state: MkosiState, repo: str) -> Iterable[RpmRepository]:
        if state.config.local_mirror:
            yield RpmRepository(repo, f"baseurl={state.config.local_mirror}", cls.gpgurls(state))
        else:
            mirror = state.config.mirror or "https://cdn.redhat.com/content/dist/"

            common: dict[str, Any] = dict(
                gpgurls=cls.gpgurls(state),
                sslcacert=cls.sslcacert(state),
                sslclientcert=cls.sslclientcert(state),
                sslclientkey=cls.sslclientkey(state),
            )

            v = state.config.release
            major = int(float(v))
            yield RpmRepository(
                f"rhel-{v}-{repo}-rpms",
                f"baseurl={join_mirror(mirror, f'rhel{major}/{v}/$basearch/{repo}/os')}",
                enabled=True,
                **common,
            )
            yield RpmRepository(
                f"rhel-{v}-{repo}-debug-rpms",
                f"baseurl={join_mirror(mirror, f'rhel{major}/{v}/$basearch/{repo}/debug')}",
                enabled=False,
                **common,
            )
            yield RpmRepository(
                f"rhel-{v}-{repo}-source",
                f"baseurl={join_mirror(mirror, f'rhel{major}/{v}/$basearch/{repo}/source')}",
                enabled=False,
                **common,
            )

    @classmethod
    def repositories(cls, state: MkosiState) -> Iterable[RpmRepository]:
        yield from cls.repository_variants(state, "baseos")
        yield from cls.repository_variants(state, "appstream")
        yield from cls.repository_variants(state, "codeready-builder")
        yield from cls.epel_repositories(state)
