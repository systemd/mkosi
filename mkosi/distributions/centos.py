# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
import urllib.parse
from collections.abc import Sequence
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.config import MkosiConfig
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer.dnf import Repo, invoke_dnf, setup_dnf
from mkosi.log import complete_step, die
from mkosi.state import MkosiState
from mkosi.tree import rmtree


def move_rpm_db(root: Path) -> None:
    """Link /var/lib/rpm to /usr/lib/sysimage/rpm for compat with old rpm"""
    olddb = root / "var/lib/rpm"
    newdb = root / "usr/lib/sysimage/rpm"

    if newdb.exists() and not newdb.is_symlink():
        with complete_step("Moving rpm database /usr/lib/sysimage/rpm → /var/lib/rpm"):
            rmtree(olddb)
            shutil.move(newdb, olddb)

            newdb.symlink_to(os.path.relpath(olddb, start=newdb.parent))


def join_mirror(config: MkosiConfig, link: str) -> str:
    assert config.mirror is not None
    return urllib.parse.urljoin(config.mirror, link)


class Installer(DistributionInstaller):
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
    def tools_tree_packages(cls) -> list[str]:
        return [
            "bash",
            "bubblewrap",
            "ca-certificates",
            "coreutils",
            "cpio",
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
        release = int(state.config.release)

        if release <= 7:
            die("CentOS 7 or earlier variants are not supported")

        setup_dnf(state, cls.repositories(state.config, release))
        (state.pkgmngr / "etc/dnf/vars/stream").write_text(f"{state.config.release}-stream\n")

    @classmethod
    def install(cls, state: MkosiState) -> None:
        # Make sure glibc-minimal-langpack is installed instead of glibc-all-langpacks.
        cls.install_packages(state, ["filesystem", "glibc-minimal-langpack"], apivfs=False)

        # On Fedora, the default rpmdb has moved to /usr/lib/sysimage/rpm so if that's the case we need to
        # move it back to /var/lib/rpm on CentOS.
        move_rpm_db(state.root)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64   : "x86_64",
            Architecture.ppc64_le : "ppc64le",
            Architecture.s390x    : "s390x",
            Architecture.arm64    : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by CentOS")

        return a

    @staticmethod
    def gpgurls() -> tuple[str, ...]:
        return (
            "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official",
            "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-SIG-Extras",
        )

    @classmethod
    def repository_variants(cls, config: MkosiConfig, repo: str) -> list[Repo]:
        if config.local_mirror:
            return [Repo(repo, f"baseurl={config.local_mirror}", cls.gpgurls())]

        if config.mirror:
            if int(config.release) <= 8:
                return [
                    Repo(
                        repo.lower(),
                        f"baseurl={join_mirror(config, f'centos/$stream/{repo}/$basearch/os')}",
                        cls.gpgurls()
                    ),
                    Repo(
                        f"{repo.lower()}-debuginfo",
                        f"baseurl={join_mirror(config, 'centos-debuginfo/$stream/$basearch')}",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                    Repo(
                        f"{repo.lower()}-source",
                        f"baseurl={join_mirror(config, f'centos/$stream/{repo}/Source')}",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                ]
            else:
                if repo == "extras":
                    return [
                        Repo(
                            repo.lower(),
                            f"baseurl={join_mirror(config, f'SIGs/$stream/{repo}/$basearch/extras-common')}",
                            cls.gpgurls(),
                        ),
                        Repo(
                            f"{repo.lower()}-source",
                            f"baseurl={join_mirror(config, f'SIGs/$stream/{repo}/source/extras-common')}",
                            cls.gpgurls(),
                            enabled=False,
                        ),
                    ]

                return [
                    Repo(
                        repo.lower(),
                        f"baseurl={join_mirror(config, f'$stream/{repo}/$basearch/os')}",
                        cls.gpgurls(),
                    ),
                    Repo(
                        f"{repo.lower()}-debuginfo",
                        f"baseurl={join_mirror(config, f'$stream/{repo}/$basearch/debug/tree')}",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                    Repo(
                        f"{repo.lower()}-source",
                        f"baseurl={join_mirror(config, f'$stream/{repo}/source/tree')}",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                ]
        else:
            if int(config.release) <= 8:
                return [
                    Repo(
                        repo.lower(),
                        f"mirrorlist=http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={repo}",
                        cls.gpgurls(),
                    ),
                    # These can't be retrieved from the mirrorlist.
                    Repo(
                        f"{repo.lower()}-debuginfo",
                        "baseurl=http://debuginfo.centos.org/$stream/$basearch",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                    Repo(
                        f"{repo.lower()}-source",
                        f"baseurl=https://vault.centos.org/centos/$stream/{repo}/Source",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                ]
            else:
                url = "metalink=https://mirrors.centos.org/metalink"

                if repo == "extras":
                    return [
                        Repo(
                            repo.lower(),
                            f"{url}?arch=$basearch&repo=centos-extras-sig-extras-common-$stream",
                            cls.gpgurls(),
                        ),
                        Repo(
                            f"{repo.lower()}-source",
                            f"{url}?arch=source&repo=centos-extras-sig-extras-common-source-$stream",
                            cls.gpgurls(),
                            enabled=False,
                        ),
                    ]

                return [
                    Repo(repo.lower(), f"{url}?arch=$basearch&repo=centos-{repo.lower()}-$stream", cls.gpgurls()),
                    Repo(
                        f"{repo.lower()}-debuginfo",
                        f"{url}?arch=$basearch&repo=centos-{repo.lower()}-debug-$stream",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                    Repo(
                        f"{repo.lower()}-source",
                        f"{url}?arch=source&repo=centos-{repo.lower()}-source-$stream",
                        cls.gpgurls(),
                        enabled=False,
                    ),
                ]

    @classmethod
    def repositories(cls, config: MkosiConfig, release: int) -> list[Repo]:
        if config.local_mirror:
            return cls.repository_variants(config, "AppStream")

        repos = [
            *cls.repository_variants(config, "BaseOS"),
            *cls.repository_variants(config, "AppStream"),
            *cls.repository_variants(config, "extras"),
        ]

        if release >= 9:
            repos += cls.repository_variants(config, "CRB")
        else:
            repos += cls.repository_variants(config, "PowerTools")

        return repos + cls.epel_repositories(config) + cls.sig_repositories(config)

    @classmethod
    def epel_repositories(cls, config: MkosiConfig) -> list[Repo]:
        gpgurls = ("https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-$releasever",)

        if config.local_mirror:
            return []

        repos = []

        if config.mirror:
            for repo, dir in (
                ("epel", "epel"),
                ("epel-next", "epel/next"),
                ("epel-testing", "epel/testing"),
                ("epel-next-testing", "epel/testing/next")
            ):
                repos += [
                    Repo(
                        repo,
                        f"baseurl={join_mirror(config, f'{dir}/$releasever/Everything/$basearch')}",
                        gpgurls,
                        enabled=False,
                    ),
                    Repo(
                        f"{repo}-debuginfo",
                        f"baseurl={join_mirror(config, f'{dir}/$releasever/Everything/$basearch/debug')}",
                        gpgurls,
                        enabled=False,
                    ),
                    Repo(
                        f"{repo}-source",
                        f"baseurl={join_mirror(config, f'{dir}/$releasever/Everything/source/tree')}",
                        gpgurls,
                        enabled=False,
                    ),
                ]
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"
            for repo in ("epel", "epel-next"):
                repos += [
                    Repo(repo, f"{url}&repo={repo}-$releasever", gpgurls, enabled=False),
                    Repo(f"{repo}-debuginfo", f"{url}&repo={repo}-debug-$releasever", gpgurls, enabled=False),
                    Repo(f"{repo}-source", f"{url}&repo={repo}-source-$releasever", gpgurls, enabled=False),
                ]

            repos += [
                Repo("epel-testing", f"{url}&repo=testing-epel$releasever", gpgurls, enabled=False),
                Repo("epel-testing-debuginfo", f"{url}&repo=testing-debug-epel$releasever", gpgurls, enabled=False),
                Repo("epel-testing-source", f"{url}&repo=testing-source-epel$releasever", gpgurls, enabled=False),
                Repo("epel-next-testing", f"{url}&repo=epel-testing-next-$releasever", gpgurls, enabled=False),
                Repo(
                    "epel-next-testing-debuginfo",
                    f"{url}&repo=epel-testing-next-debug-$releasever",
                    gpgurls,
                    enabled=False,
                ),
                Repo(
                    "epel-next-testing-source",
                    f"{url}&repo=epel-testing-next-source-$releasever",
                    gpgurls,
                    enabled=False,
                ),
            ]

        return repos

    @classmethod
    def sig_repositories(cls, config: MkosiConfig) -> list[Repo]:
        if config.local_mirror:
            return []

        sigs = (
            (
                "hyperscale",
                (f"packages-{c}" for c in ("main", "experimental", "facebook", "hotfixes", "spin", "intel")),
                ("https://www.centos.org/keys/RPM-GPG-KEY-CentOS-SIG-HyperScale",),
            ),
        )

        repos = []

        for sig, components, gpgurls in sigs:
            for c in components:
                if config.mirror:
                    if int(config.release) <= 8:
                        repos += [
                            Repo(
                                f"{sig}-{c}",
                                f"baseurl={join_mirror(config, f'centos/$stream/{sig}/$basearch/{c}')}",
                                gpgurls,
                                enabled=False,
                            ),
                            Repo(
                                f"{sig}-{c}-debuginfo",
                                f"baseurl={join_mirror(config, f'$stream/{sig}/$basearch')}",
                                gpgurls,
                                enabled=False,
                            ),
                            Repo(
                                f"{sig}-{c}-source",
                                f"baseurl={join_mirror(config, f'centos/$stream/{sig}/Source')}",
                                gpgurls,
                                enabled=False,
                            ),
                        ]
                    else:
                        repos += [
                            Repo(
                                f"{sig}-{c}",
                                f"baseurl={join_mirror(config, f'SIGs/$stream/{sig}/$basearch/{c}')}",
                                gpgurls,
                                enabled=False,
                            ),
                            Repo(
                                f"{sig}-{c}-debuginfo",
                                f"baseurl={join_mirror(config, f'SIGs/$stream/{sig}/$basearch/{c}/debug')}",
                                gpgurls,
                                enabled=False,
                            ),
                            Repo(
                                f"{sig}-{c}-source",
                                f"baseurl={join_mirror(config, f'SIGs/$stream/{sig}/source/{c}')}",
                                gpgurls,
                                enabled=False,
                            ),
                        ]
                else:
                    if int(config.release) <= 8:
                        repos += [
                            Repo(
                                f"{sig}-{c}",
                                f"mirrorlist=http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={sig}-{c}",
                                gpgurls,
                                enabled=False,
                            ),
                            # These can't be retrieved from the mirrorlist.
                            Repo(
                                f"{sig}-{c}-debuginfo",
                                f"baseurl=http://debuginfo.centos.org/centos/$stream/{sig}/$basearch",
                                gpgurls,
                                enabled=False,
                            ),
                            Repo(
                                f"{sig}-{c}-source",
                                f"baseurl=https://vault.centos.org/$stream/{sig}/Source/{c}",
                                gpgurls,
                                enabled=False,
                            ),
                        ]
                    else:
                        url = "metalink=https://mirrors.centos.org/metalink"
                        repos += [
                            Repo(
                                f"{sig}-{c}",
                                f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-$stream",
                                gpgurls,
                                enabled=False,
                            ),
                            Repo(
                                f"{sig}-{c}-debuginfo",
                                f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-debug-$stream",
                                gpgurls,
                                enabled=False,
                            ),
                            Repo(
                                f"{sig}-{c}-source",
                                f"{url}?arch=source&repo=centos-{sig}-sig-{c}-source-$stream",
                                gpgurls,
                                enabled=False,
                            ),
                        ]

                    repos += [
                        Repo(
                            f"{sig}-{c}-testing",
                            f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                            gpgurls,
                            enabled=False,
                        ),
                    ]

                    if int(config.release) >= 9:
                        repos += [
                            Repo(
                                f"{sig}-{c}-testing-debuginfo",
                                f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                                gpgurls,
                                enabled=False,
                            ),
                        ]

        return repos
