# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from mkosi.context import Context
from mkosi.distribution import Distribution, centos, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die
from mkosi.run import exists_in_sandbox, glob_in_sandbox


class Installer(centos.Installer, distribution=Distribution.rhel):
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
    def sslcacert(context: Context) -> Path | None:
        if context.config.mirror:
            return None

        path = Path("etc/rhsm/ca/redhat-uep.pem")
        if not exists_in_sandbox(path, sandbox=context.sandbox()):
            die(
                f"redhat-uep.pem certificate not found in sandbox at {path}",
                hint="Add the certificate to the sandbox with SandboxTrees= or mkosi.sandbox/",
            )

        return path

    @staticmethod
    def sslclientkey(context: Context) -> Path | None:
        if context.config.mirror:
            return None

        glob = "etc/pki/entitlement/*-key.pem"
        paths = glob_in_sandbox(glob, sandbox=context.sandbox())
        if not paths:
            die(
                f"No entitlement keys found at {glob} in sandbox",
                hint="Add an entitlement key to the sandbox with SandboxTrees= or mkosi.sandbox/",
            )

        return paths[0]

    @staticmethod
    def sslclientcert(context: Context) -> Path | None:
        if context.config.mirror:
            return None

        glob = "etc/pki/entitlement/*.pem"
        paths = [p for p in glob_in_sandbox(glob, sandbox=context.sandbox()) if "-key.pem" not in p.name]
        if not paths:
            die(
                f"No entitlement certificates found at {glob} in sandbox",
                hint="Add an entitlement certificate to the sandbox with SandboxTrees= or mkosi.sandbox/",
            )

        return paths[0]

    @classmethod
    def repository_variants(
        cls,
        context: Context,
        gpgurls: tuple[str, ...],
        repo: str,
    ) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(repo, f"baseurl={context.config.local_mirror}", gpgurls)
        else:
            mirror = context.config.mirror or "https://cdn.redhat.com/content/dist/"

            common: dict[str, Any] = dict(
                gpgurls=gpgurls,
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
        if context.config.snapshot:
            die(f"Snapshot= is not supported for {cls.pretty_name()}")

        gpgurls = cls.gpgurls(context)
        yield from cls.repository_variants(context, gpgurls, "baseos")
        yield from cls.repository_variants(context, gpgurls, "appstream")
        yield from cls.repository_variants(context, gpgurls, "codeready-builder")
        yield from cls.epel_repositories(context)
