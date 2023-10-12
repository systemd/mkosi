# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
import urllib.parse
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer.dnf import Repo, find_rpm_gpgkey, invoke_dnf, setup_dnf
from mkosi.log import complete_step, die
from mkosi.state import MkosiState
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


def join_mirror(mirror: str, link: str) -> str:
    return urllib.parse.urljoin(mirror, link)


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
    def tools_tree_repositories(cls) -> list[str]:
        return ["epel", "epel-next"]

    @classmethod
    def tools_tree_packages(cls) -> list[str]:
        return [
            "apt",
            "bash",
            "bubblewrap",
            "ca-certificates",
            "coreutils",
            "cpio",
            "curl",
            "debian-keyring",
            "distribution-gpg-keys",
            "dnf",
            "dosfstools",
            "e2fsprogs",
            "edk2-ovmf",
            "mtools",
            "openssh-clients",
            "openssl",
            "pesign",
            "python3-cryptography",
            "qemu-kvm-core",
            "socat",
            "squashfs-tools",
            "strace",
            "swtpm",
            "systemd-container",
            "systemd-udev",
            "systemd",
            "tar",
            "util-linux",
            "virtiofsd",
            "xfsprogs",
            "xz",
            "zstd",
        ]

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        if GenericVersion(state.config.release) <= 7:
            die(f"{cls.pretty_name()} 7 or earlier variants are not supported")

        setup_dnf(state, cls.repositories(state))
        (state.pkgmngr / "etc/dnf/vars/stream").write_text(f"{state.config.release}-stream\n")

    @classmethod
    def install(cls, state: MkosiState) -> None:
        # Make sure glibc-minimal-langpack is installed instead of glibc-all-langpacks.
        cls.install_packages(state, ["filesystem", "glibc-minimal-langpack"], apivfs=False)

        # On Fedora, the default rpmdb has moved to /usr/lib/sysimage/rpm so if that's the case we
        # need to move it back to /var/lib/rpm on CentOS.
        move_rpm_db(state.root)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)

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
    def gpgurls(state: MkosiState) -> tuple[str, ...]:
        keys = ("RPM-GPG-KEY-CentOS-Official", "RPM-GPG-KEY-CentOS-SIG-Extras")
        return tuple(find_rpm_gpgkey(state, key, f"https://www.centos.org/keys/{key}") for key in keys)

    @classmethod
    def repository_variants(cls, state: MkosiState, repo: str) -> Iterable[Repo]:
        if state.config.local_mirror:
            yield Repo(repo, f"baseurl={state.config.local_mirror}", cls.gpgurls(state))

        elif state.config.mirror:
            if GenericVersion(state.config.release) <= 8:
                yield Repo(
                    repo.lower(),
                    f"baseurl={join_mirror(state.config.mirror, f'centos/$stream/{repo}/$basearch/os')}",
                    cls.gpgurls(state),
                )
                yield Repo(
                    f"{repo.lower()}-debuginfo",
                    f"baseurl={join_mirror(state.config.mirror, 'centos-debuginfo/$stream/$basearch')}",
                    cls.gpgurls(state),
                    enabled=False,
                )
                yield Repo(
                    f"{repo.lower()}-source",
                    f"baseurl={join_mirror(state.config.mirror, f'centos/$stream/{repo}/Source')}",
                    cls.gpgurls(state),
                    enabled=False,
                )
            else:
                if repo == "extras":
                    yield Repo(
                        repo.lower(),
                        f"baseurl={join_mirror(state.config.mirror, f'SIGs/$stream/{repo}/$basearch/extras-common')}",
                        cls.gpgurls(state),
                    )
                    yield Repo(
                        f"{repo.lower()}-source",
                        f"baseurl={join_mirror(state.config.mirror, f'SIGs/$stream/{repo}/source/extras-common')}",
                        cls.gpgurls(state),
                        enabled=False,
                    )

                else:
                    yield Repo(
                        repo.lower(),
                        f"baseurl={join_mirror(state.config.mirror, f'$stream/{repo}/$basearch/os')}",
                        cls.gpgurls(state),
                    )
                    yield Repo(
                        f"{repo.lower()}-debuginfo",
                        f"baseurl={join_mirror(state.config.mirror, f'$stream/{repo}/$basearch/debug/tree')}",
                        cls.gpgurls(state),
                        enabled=False,
                    )
                    yield Repo(
                        f"{repo.lower()}-source",
                        f"baseurl={join_mirror(state.config.mirror, f'$stream/{repo}/source/tree')}",
                        cls.gpgurls(state),
                        enabled=False,
                    )

        else:
            if GenericVersion(state.config.release) <= 8:
                yield Repo(
                    repo.lower(),
                    f"mirrorlist=http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={repo}",
                    cls.gpgurls(state),
                )
                # These can't be retrieved from the mirrorlist.
                yield Repo(
                    f"{repo.lower()}-debuginfo",
                    "baseurl=http://debuginfo.centos.org/$stream/$basearch",
                    cls.gpgurls(state),
                    enabled=False,
                )
                yield Repo(
                    f"{repo.lower()}-source",
                    f"baseurl=https://vault.centos.org/centos/$stream/{repo}/Source",
                    cls.gpgurls(state),
                    enabled=False,
                )
            else:
                url = "metalink=https://mirrors.centos.org/metalink"

                if repo == "extras":
                    yield Repo(
                        repo.lower(),
                        f"{url}?arch=$basearch&repo=centos-extras-sig-extras-common-$stream",
                        cls.gpgurls(state),
                    )
                    yield Repo(
                        f"{repo.lower()}-source",
                        f"{url}?arch=source&repo=centos-extras-sig-extras-common-source-$stream",
                        cls.gpgurls(state),
                        enabled=False,
                    )
                else:
                    yield Repo(
                        repo.lower(),
                        f"{url}?arch=$basearch&repo=centos-{repo.lower()}-$stream",
                        cls.gpgurls(state),
                    )
                    yield Repo(
                        f"{repo.lower()}-debuginfo",
                        f"{url}?arch=$basearch&repo=centos-{repo.lower()}-debug-$stream",
                        cls.gpgurls(state),
                        enabled=False,
                    )
                    yield Repo(
                        f"{repo.lower()}-source",
                        f"{url}?arch=source&repo=centos-{repo.lower()}-source-$stream",
                        cls.gpgurls(state),
                        enabled=False,
                    )

    @classmethod
    def repositories(cls, state: MkosiState) -> Iterable[Repo]:
        if state.config.local_mirror:
            yield from cls.repository_variants(state, "AppStream")
        else:
            yield from cls.repository_variants(state, "BaseOS")
            yield from cls.repository_variants(state, "AppStream")
            yield from cls.repository_variants(state, "extras")

        if GenericVersion(state.config.release) >= 9:
            yield from cls.repository_variants(state, "CRB")
        else:
            yield from cls.repository_variants(state, "PowerTools")

        yield from cls.epel_repositories(state)
        yield from cls.sig_repositories(state)

    @classmethod
    def epel_repositories(cls, state: MkosiState) -> Iterable[Repo]:
        gpgurls = (
            find_rpm_gpgkey(
                state,
                f"RPM-GPG-KEY-EPEL-{state.config.release}",
                f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{state.config.release}",
            ),
        )

        if state.config.local_mirror:
            return

        if state.config.mirror:
            for repo, dir in (
                ("epel", "epel"),
                ("epel-next", "epel/next"),
                ("epel-testing", "epel/testing"),
                ("epel-next-testing", "epel/testing/next")
            ):
                yield Repo(
                    repo,
                    f"baseurl={join_mirror(state.config.mirror, f'{dir}/$releasever/Everything/$basearch')}",
                    gpgurls,
                    enabled=False,
                )
                yield Repo(
                    f"{repo}-debuginfo",
                    f"baseurl={join_mirror(state.config.mirror, f'{dir}/$releasever/Everything/$basearch/debug')}",
                    gpgurls,
                    enabled=False,
                )
                yield Repo(
                    f"{repo}-source",
                    f"baseurl={join_mirror(state.config.mirror, f'{dir}/$releasever/Everything/source/tree')}",
                    gpgurls,
                    enabled=False,
                )
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"
            for repo in ("epel", "epel-next"):
                yield Repo(repo, f"{url}&repo={repo}-$releasever", gpgurls, enabled=False)
                yield Repo(f"{repo}-debuginfo", f"{url}&repo={repo}-debug-$releasever", gpgurls, enabled=False)
                yield Repo(f"{repo}-source", f"{url}&repo={repo}-source-$releasever", gpgurls, enabled=False)

            yield Repo("epel-testing", f"{url}&repo=testing-epel$releasever", gpgurls, enabled=False)
            yield Repo("epel-testing-debuginfo", f"{url}&repo=testing-debug-epel$releasever", gpgurls, enabled=False)
            yield Repo("epel-testing-source", f"{url}&repo=testing-source-epel$releasever", gpgurls, enabled=False)
            yield Repo("epel-next-testing", f"{url}&repo=epel-testing-next-$releasever", gpgurls, enabled=False)
            yield Repo(
                "epel-next-testing-debuginfo",
                f"{url}&repo=epel-testing-next-debug-$releasever",
                gpgurls,
                enabled=False,
            )
            yield Repo(
                "epel-next-testing-source",
                f"{url}&repo=epel-testing-next-source-$releasever",
                gpgurls,
                enabled=False,
            )

    @classmethod
    def sig_repositories(cls, state: MkosiState) -> Iterable[Repo]:
        if state.config.local_mirror:
            return

        sigs = (
            (
                "hyperscale",
                (f"packages-{c}" for c in ("main", "experimental", "facebook", "hotfixes", "spin", "intel")),
                ("RPM-GPG-KEY-CentOS-SIG-HyperScale",),
            ),
        )

        for sig, components, keys in sigs:
            gpgurls = tuple(find_rpm_gpgkey(state, key, f"https://www.centos.org/keys/{key}") for key in keys)

            for c in components:
                if state.config.mirror:
                    if GenericVersion(state.config.release) <= 8:
                        yield Repo(
                            f"{sig}-{c}",
                            f"baseurl={join_mirror(state.config.mirror, f'centos/$stream/{sig}/$basearch/{c}')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield Repo(
                            f"{sig}-{c}-debuginfo",
                            f"baseurl={join_mirror(state.config.mirror, f'$stream/{sig}/$basearch')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield Repo(
                            f"{sig}-{c}-source",
                            f"baseurl={join_mirror(state.config.mirror, f'centos/$stream/{sig}/Source')}",
                            gpgurls,
                            enabled=False,
                        )
                    else:
                        yield Repo(
                            f"{sig}-{c}",
                            f"baseurl={join_mirror(state.config.mirror, f'SIGs/$stream/{sig}/$basearch/{c}')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield Repo(
                            f"{sig}-{c}-debuginfo",
                            f"baseurl={join_mirror(state.config.mirror, f'SIGs/$stream/{sig}/$basearch/{c}/debug')}",
                            gpgurls,
                            enabled=False,
                        )
                        yield Repo(
                            f"{sig}-{c}-source",
                            f"baseurl={join_mirror(state.config.mirror, f'SIGs/$stream/{sig}/source/{c}')}",
                            gpgurls,
                            enabled=False,
                        )
                else:
                    if GenericVersion(state.config.release) <= 8:
                        yield Repo(
                            f"{sig}-{c}",
                            f"mirrorlist=http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={sig}-{c}",
                            gpgurls,
                            enabled=False,
                        )
                        # These can't be retrieved from the mirrorlist.
                        yield Repo(
                            f"{sig}-{c}-debuginfo",
                            f"baseurl=http://debuginfo.centos.org/centos/$stream/{sig}/$basearch",
                            gpgurls,
                            enabled=False,
                        )
                        yield Repo(
                            f"{sig}-{c}-source",
                            f"baseurl=https://vault.centos.org/$stream/{sig}/Source/{c}",
                            gpgurls,
                            enabled=False,
                        )
                    else:
                        url = "metalink=https://mirrors.centos.org/metalink"
                        yield Repo(
                            f"{sig}-{c}",
                            f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-$stream",
                            gpgurls,
                            enabled=False,
                        )
                        yield Repo(
                            f"{sig}-{c}-debuginfo",
                            f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-debug-$stream",
                            gpgurls,
                            enabled=False,
                        )
                        yield Repo(
                            f"{sig}-{c}-source",
                            f"{url}?arch=source&repo=centos-{sig}-sig-{c}-source-$stream",
                            gpgurls,
                            enabled=False,
                        )

                    yield Repo(
                        f"{sig}-{c}-testing",
                        f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                        gpgurls,
                        enabled=False,
                    )

                    if GenericVersion(state.config.release) >= 9:
                        yield Repo(
                            f"{sig}-{c}-testing-debuginfo",
                            f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                            gpgurls,
                            enabled=False,
                        )
