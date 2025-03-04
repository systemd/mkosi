# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Optional

from mkosi.context import Context
from mkosi.distributions import centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "RHEL"

    @classmethod
    def gpgurls(cls, context: Context) -> tuple[str, ...]:
        return (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-redhat{cls.major_release(context.config)}-release",
                "https://access.redhat.com/security/data/fd431d51.txt",
            ),
        )

    @staticmethod
    def sslcacert(context: Context) -> Optional[Path]:
        if context.config.mirror:
            return None

        p = Path("etc/rhsm/ca/redhat-uep.pem")
        if (context.sandbox_tree / p).exists():
            p = context.sandbox_tree / p
        elif (Path("/") / p).exists():
            p = Path("/") / p
        else:
            die("redhat-uep.pem certificate not found in host system or sandbox tree")

        return p

    @staticmethod
    def sslclientkey(context: Context) -> Optional[Path]:
        if context.config.mirror:
            return None

        pattern = "etc/pki/entitlement/*-key.pem"

        p = next((p for p in sorted(context.sandbox_tree.glob(pattern))), None)
        if not p:
            p = next((p for p in Path("/").glob(pattern)), None)
        if not p:
            die("Entitlement key not found in host system or sandbox tree")

        return p

    @staticmethod
    def sslclientcert(context: Context) -> Optional[Path]:
        if context.config.mirror:
            return None

        pattern = "etc/pki/entitlement/*.pem"

        p = next((p for p in sorted(context.sandbox_tree.glob(pattern)) if "key" not in p.name), None)
        if not p:
            p = next((p for p in sorted(Path("/").glob(pattern)) if "key" not in p.name), None)
        if not p:
            die("Entitlement certificate not found in host system or sandbox tree")

        return p

    @classmethod
    def repository_variants(cls, context: Context, repo: str) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(repo, f"baseurl={context.config.local_mirror}", cls.gpgurls(context))
        else:
            mirror = context.config.mirror or "https://cdn.redhat.com/content/dist/"

            common: dict[str, Any] = dict(
                gpgurls=cls.gpgurls(context),
                sslcacert=cls.sslcacert(context),
                sslclientcert=cls.sslclientcert(context),
                sslclientkey=cls.sslclientkey(context),
            )

            v = context.config.release
            major = cls.major_release(context.config)
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
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        yield from cls.repository_variants(context, "baseos")
        yield from cls.repository_variants(context, "appstream")
        yield from cls.repository_variants(context, "codeready-builder")
        yield from cls.epel_repositories(context)
