# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable

from mkosi.config import MkosiConfig
from mkosi.distributions import centos
from mkosi.installer.dnf import Repo


class Installer(centos.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "RHEL UBI"

    @staticmethod
    def gpgurls(config: MkosiConfig) -> tuple[str, ...]:
        return ("https://access.redhat.com/security/data/fd431d51.txt",)

    @classmethod
    def repository_variants(cls, config: MkosiConfig, repo: str) -> Iterable[Repo]:
        if config.local_mirror:
            yield Repo(repo, f"baseurl={config.local_mirror}", cls.gpgurls(config))
        else:
            v = config.release
            yield Repo(
                f"ubi-{v}-{repo}-rpms",
                f"baseurl={centos.join_mirror(config, f'ubi{v}/{v}/$basearch/{repo}/os')}",
                cls.gpgurls(config),
            )
            yield Repo(
                f"ubi-{v}-{repo}-debug-rpms",
                f"baseurl={centos.join_mirror(config, f'ubi{v}/{v}/$basearch/{repo}/debug')}",
                cls.gpgurls(config),
                enabled=False,
            )
            yield Repo(
                f"ubi-{v}-{repo}-source",
                f"baseurl={centos.join_mirror(config, f'ubi{v}/{v}/$basearch/{repo}/source')}",
                cls.gpgurls(config),
                enabled=False,
            )
            if repo == "codeready-builder":
                yield Repo(
                    f"ubi-{v}-{repo}",
                    f"baseurl={centos.join_mirror(config, f'ubi{v}/{v}/$basearch/{repo}/os')}",
                    cls.gpgurls(config),
                    enabled=False,
                )

    @classmethod
    def repositories(cls, config: MkosiConfig, release: int) -> Iterable[Repo]:
        yield from cls.repository_variants(config, "baseos")
        yield from cls.repository_variants(config, "appstream")
        yield from cls.repository_variants(config, "codeready-builder")
