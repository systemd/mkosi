# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import invoke_dnf, setup_dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import complete_step, die
from mkosi.tree import rmtree
from mkosi.versioncomp import GenericVersion


def move_rpm_db(root: Path) -> None:
    """Link /var/lib/rpm to /usr/lib/sysimage/rpm for compat with old rpm"""
    olddb = root / "var/lib/rpm"
    newdb = root / "usr/lib/sysimage/rpm"

    if newdb.exists() and not newdb.is_symlink():
        with complete_step("Moving rpm database /usr/lib/sysimage/rpm → /var/lib/rpm"):
            rmtree(olddb)
            shutil.move(newdb, olddb)

            newdb.symlink_to(os.path.relpath(olddb, start=newdb.parent))



class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "CentOS"

    @classmethod
    def filesystem(cls) -> str:
        return "xfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def default_release(cls) -> str:
        return "9"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.fedora

    @classmethod
    def setup(cls, context: Context) -> None:
        if GenericVersion(context.config.release) <= 7:
            die(f"{cls.pretty_name()} 7 or earlier variants are not supported")

        setup_dnf(context, cls.repositories(context))
        (context.pkgmngr / "etc/dnf/vars/stream").write_text(f"{context.config.release}-stream\n")

    @classmethod
    def install(cls, context: Context) -> None:
        # Make sure glibc-minimal-langpack is installed instead of glibc-all-langpacks.
        cls.install_packages(context, ["filesystem", "glibc-minimal-langpack"], apivfs=False)

        # On Fedora, the default rpmdb has moved to /usr/lib/sysimage/rpm so if that's the case we
        # need to move it back to /var/lib/rpm on CentOS.
        move_rpm_db(context.root)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(context, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        invoke_dnf(context, "remove", packages)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64   : "x86_64",
            Architecture.ppc64_le : "ppc64le",
            Architecture.s390x    : "s390x",
            Architecture.arm64    : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a

    @staticmethod
    def gpgurls(context: Context) -> tuple[str, ...]:
        keys = ("RPM-GPG-KEY-CentOS-Official", "RPM-GPG-KEY-CentOS-SIG-Extras")
        return tuple(find_rpm_gpgkey(context, key, f"https://www.centos.org/keys/{key}") for key in keys)

    @classmethod
    def repository_variants(cls, context: Context, repo: str) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(repo, f"baseurl={context.config.local_mirror}", cls.gpgurls(context))

        elif mirror := context.config.mirror:
            if GenericVersion(context.config.release) <= 8:
                yield RpmRepository(
                    repo.lower(),
                    f"baseurl={join_mirror(mirror, f'centos/$stream/{repo}/$basearch/os')}",
                    cls.gpgurls(context),
                )
                yield RpmRepository(
                    f"{repo.lower()}-debuginfo",
                    f"baseurl={join_mirror(mirror, 'centos-debuginfo/$stream/$basearch')}",
                    cls.gpgurls(context),
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo.lower()}-source",
                    f"baseurl={join_mirror(mirror, f'centos/$stream/{repo}/Source')}",
                    cls.gpgurls(context),
                    enabled=False,
                )
            else:
                if repo == "extras":
                    yield RpmRepository(
                        repo.lower(),
                        f"baseurl={join_mirror(mirror, f'SIGs/$stream/{repo}/$basearch/extras-common')}",
                        cls.gpgurls(context),
                    )
                    yield RpmRepository(
                        f"{repo.lower()}-source",
                        f"baseurl={join_mirror(mirror, f'SIGs/$stream/{repo}/source/extras-common')}",
                        cls.gpgurls(context),
                        enabled=False,
                    )

                else:
                    yield RpmRepository(
                        repo.lower(),
                        f"baseurl={join_mirror(mirror, f'$stream/{repo}/$basearch/os')}",
                        cls.gpgurls(context),
                    )
                    yield RpmRepository(
                        f"{repo.lower()}-debuginfo",
                        f"baseurl={join_mirror(mirror, f'$stream/{repo}/$basearch/debug/tree')}",
                        cls.gpgurls(context),
                        enabled=False,
                    )
                    yield RpmRepository(
                        f"{repo.lower()}-source",
                        f"baseurl={join_mirror(mirror, f'$stream/{repo}/source/tree')}",
                        cls.gpgurls(context),
                        enabled=False,
                    )

        else:
            if GenericVersion(context.config.release) <= 8:
                yield RpmRepository(
                    repo.lower(),
                    f"mirrorlist=http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={repo}",
                    cls.gpgurls(context),
                )
                # These can't be retrieved from the mirrorlist.
                yield RpmRepository(
                    f"{repo.lower()}-debuginfo",
                    "baseurl=http://debuginfo.centos.org/$stream/$basearch",
                    cls.gpgurls(context),
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo.lower()}-source",
                    f"baseurl=https://vault.centos.org/centos/$stream/{repo}/Source",
                    cls.gpgurls(context),
                    enabled=False,
                )
            else:
                url = "metalink=https://mirrors.centos.org/metalink"

                if repo == "extras":
                    yield RpmRepository(
                        repo.lower(),
                        f"{url}?arch=$basearch&repo=centos-extras-sig-extras-common-$stream",
                        cls.gpgurls(context),
                    )
                    yield RpmRepository(
                        f"{repo.lower()}-source",
                        f"{url}?arch=source&repo=centos-extras-sig-extras-common-source-$stream",
                        cls.gpgurls(context),
                        enabled=False,
                    )
                else:
                    yield RpmRepository(
                        repo.lower(),
                        f"{url}?arch=$basearch&repo=centos-{repo.lower()}-$stream",
                        cls.gpgurls(context),
                    )
                    yield RpmRepository(
                        f"{repo.lower()}-debuginfo",
                        f"{url}?arch=$basearch&repo=centos-{repo.lower()}-debug-$stream",
                        cls.gpgurls(context),
                        enabled=False,
                    )
                    yield RpmRepository(
                        f"{repo.lower()}-source",
                        f"{url}?arch=source&repo=centos-{repo.lower()}-source-$stream",
                        cls.gpgurls(context),
                        enabled=False,
                    )

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield from cls.repository_variants(context, "AppStream")
        else:
            yield from cls.repository_variants(context, "BaseOS")
            yield from cls.repository_variants(context, "AppStream")
            yield from cls.repository_variants(context, "extras")

        if GenericVersion(context.config.release) >= 9:
            yield from cls.repository_variants(context, "CRB")
        else:
            yield from cls.repository_variants(context, "PowerTools")

        yield from cls.epel_repositories(context)
        yield from cls.sig_repositories(context)

    @classmethod
    def epel_repositories(cls, context: Context) -> Iterable[RpmRepository]:
        gpgurls = (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-EPEL-{context.config.release}",
                f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{context.config.release}",
            ),
        )

        if context.config.local_mirror:
            return

        if mirror := context.config.mirror:
            for repo, dir in (
                ("epel", "epel"),
                ("epel-next", "epel/next"),
                ("epel-testing", "epel/testing"),
                ("epel-next-testing", "epel/testing/next")
            ):
                yield RpmRepository(
                    repo,
                    f"baseurl={join_mirror(mirror, f'{dir}/$releasever/Everything/$basearch')}",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo}-debuginfo",
                    f"baseurl={join_mirror(mirror, f'{dir}/$releasever/Everything/$basearch/debug')}",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo}-source",
                    f"baseurl={join_mirror(mirror, f'{dir}/$releasever/Everything/source/tree')}",
                    gpgurls,
                    enabled=False,
                )
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"
            for repo in ("epel", "epel-next"):
                yield RpmRepository(repo, f"{url}&repo={repo}-$releasever", gpgurls, enabled=False)
                yield RpmRepository(
                    f"{repo}-debuginfo",
                    f"{url}&repo={repo}-debug-$releasever",
                    gpgurls,
                    enabled=False
                )
                yield RpmRepository(
                    f"{repo}-source",
                    f"{url}&repo={repo}-source-$releasever",
                    gpgurls,
                    enabled=False
                )

            yield RpmRepository(
                "epel-testing",
                f"{url}&repo=testing-epel$releasever",
                gpgurls,
                enabled=False
            )
            yield RpmRepository(
                "epel-testing-debuginfo",
                f"{url}&repo=testing-debug-epel$releasever",
                gpgurls,
                enabled=False
            )
            yield RpmRepository(
                "epel-testing-source",
                f"{url}&repo=testing-source-epel$releasever",
                gpgurls,
                enabled=False
            )
            yield RpmRepository(
                "epel-next-testing",
                f"{url}&repo=epel-testing-next-$releasever",
                gpgurls,
                enabled=False
            )
            yield RpmRepository(
                "epel-next-testing-debuginfo",
                f"{url}&repo=epel-testing-next-debug-$releasever",
                gpgurls,
                enabled=False,
            )
            yield RpmRepository(
                "epel-next-testing-source",
                f"{url}&repo=epel-testing-next-source-$releasever",
                gpgurls,
                enabled=False,
            )

    @classmethod
    def sig_repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            return

        sigs = (
            (
                "hyperscale",
                (f"packages-{c}" for c in ("main", "experimental", "facebook", "hotfixes", "spin", "intel")),
                ("RPM-GPG-KEY-CentOS-SIG-HyperScale",),
            ),
        )

        for sig, components, keys in sigs:
            gpgurls = tuple(find_rpm_gpgkey(context, key, f"https://www.centos.org/keys/{key}") for key in keys)

            for c in components:
                if mirror := context.config.mirror:
                    if GenericVersion(context.config.release) <= 8:
                        yield RpmRepository(
                            f"{sig}-{c}",
                            f"baseurl={join_mirror(mirror, f'centos/$stream/{sig}/$basearch/{c}')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield RpmRepository(
                            f"{sig}-{c}-debuginfo",
                            f"baseurl={join_mirror(mirror, f'$stream/{sig}/$basearch')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield RpmRepository(
                            f"{sig}-{c}-source",
                            f"baseurl={join_mirror(mirror, f'centos/$stream/{sig}/Source')}",
                            gpgurls,
                            enabled=False,
                        )
                    else:
                        yield RpmRepository(
                            f"{sig}-{c}",
                            f"baseurl={join_mirror(mirror, f'SIGs/$stream/{sig}/$basearch/{c}')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield RpmRepository(
                            f"{sig}-{c}-debuginfo",
                            f"baseurl={join_mirror(mirror, f'SIGs/$stream/{sig}/$basearch/{c}/debug')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield RpmRepository(
                            f"{sig}-{c}-source",
                            f"baseurl={join_mirror(mirror, f'SIGs/$stream/{sig}/source/{c}')}",
                            gpgurls,
                            enabled=False,
                        )
                else:
                    if GenericVersion(context.config.release) <= 8:
                        yield RpmRepository(
                            f"{sig}-{c}",
                            f"mirrorlist=http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={sig}-{c}",
                            gpgurls,
                            enabled=False,
                        )
                        # These can't be retrieved from the mirrorlist.
                        yield RpmRepository(
                            f"{sig}-{c}-debuginfo",
                            f"baseurl=http://debuginfo.centos.org/centos/$stream/{sig}/$basearch",
                            gpgurls,
                            enabled=False,
                        )
                        yield RpmRepository(
                            f"{sig}-{c}-source",
                            f"baseurl=https://vault.centos.org/$stream/{sig}/Source/{c}",
                            gpgurls,
                            enabled=False,
                        )
                    else:
                        url = "metalink=https://mirrors.centos.org/metalink"
                        yield RpmRepository(
                            f"{sig}-{c}",
                            f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-$stream",
                            gpgurls,
                            enabled=False,
                        )
                        yield RpmRepository(
                            f"{sig}-{c}-debuginfo",
                            f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-debug-$stream",
                            gpgurls,
                            enabled=False,
                        )
                        yield RpmRepository(
                            f"{sig}-{c}-source",
                            f"{url}?arch=source&repo=centos-{sig}-sig-{c}-source-$stream",
                            gpgurls,
                            enabled=False,
                        )

                    yield RpmRepository(
                        f"{sig}-{c}-testing",
                        f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                        gpgurls,
                        enabled=False,
                    )

                    if GenericVersion(context.config.release) >= 9:
                        yield RpmRepository(
                            f"{sig}-{c}-testing-debuginfo",
                            f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                            gpgurls,
                            enabled=False,
                        )
