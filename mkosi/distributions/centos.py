# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
from collections.abc import Sequence
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.config import MkosiConfig
from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, invoke_dnf, setup_dnf
from mkosi.log import complete_step, die
from mkosi.remove import unlink_try_hard
from mkosi.state import MkosiState


def move_rpm_db(root: Path) -> None:
    """Link /var/lib/rpm to /usr/lib/sysimage/rpm for compat with old rpm"""
    olddb = root / "var/lib/rpm"
    newdb = root / "usr/lib/sysimage/rpm"

    if newdb.exists() and not newdb.is_symlink():
        with complete_step("Moving rpm database /usr/lib/sysimage/rpm → /var/lib/rpm"):
            unlink_try_hard(olddb)
            shutil.move(newdb, olddb)

            newdb.symlink_to(os.path.relpath(olddb, start=newdb.parent))


class CentosInstaller(DistributionInstaller):

    @classmethod
    def filesystem(cls) -> str:
        # This should really be "xfs" but unprivileged population of XFS filesystems with files containing
        # spaces in their path is broken and needs fixing in xfsprogs, see
        # https://marc.info/?l=linux-xfs&m=167450838316386&w=2.
        return "ext4"

    @classmethod
    def filesystem_options(cls, state: MkosiState) -> dict[str, list[str]]:
        # Hard code the features from /etc/mke2fs.conf from CentOS 8 Stream to ensure that filesystems
        # created on distros with newer versions of e2fsprogs are compatible with e2fsprogs from CentOS
        # Stream 8.

        return {
            "8": {
                "ext4": ["-O", ",".join([
                    "none",
                    "sparse_super",
                    "large_file",
                    "filetype",
                    "resize_inode",
                    "dir_index",
                    "ext_attr",
                    "has_journal",
                    "extent",
                    "huge_file",
                    "flex_bg",
                    "metadata_csum",
                    "64bit",
                    "dir_nlink",
                    "extra_isize"
                ])],
            },
        }.get(state.config.release, {})

    @classmethod
    def install(cls, state: MkosiState) -> None:
        # Make sure glibc-minimal-langpack is installed instead of glibc-all-langpacks.
        cls.install_packages(state, ["filesystem", "glibc-minimal-langpack"], apivfs=False)

        # On Fedora, the default rpmdb has moved to /usr/lib/sysimage/rpm so if that's the case we need to
        # move it back to /var/lib/rpm on CentOS.
        move_rpm_db(state.root)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        release = int(state.config.release)

        if release <= 7:
            die("CentOS 7 or earlier variants are not supported")

        setup_dnf(state, cls.repositories(state.config, release))
        invoke_dnf(state, "install", packages, apivfs=apivfs,
                   env=dict(DNF_VAR_stream=f"{state.config.release}-stream"))

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
    def repository_url(cls, config: MkosiConfig, repo: str) -> str:
        if config.mirror:
            if int(config.release) <= 8:
                return f"baseurl={config.mirror}/centos/$stream/{repo}/$basearch/os"
            else:
                if repo == "extras":
                    return f"baseurl={config.mirror}/SIGS/$stream/{repo}/$basearch/os"

                return f"baseurl={config.mirror}/$stream/{repo}/$basearch/os"
        else:
            if int(config.release) <= 8:
                return f"mirrorlist=http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={repo}"
            else:
                if repo == "extras":
                    repo = "extras-sig-extras-common"

                return f"metalink=https://mirrors.centos.org/metalink?arch=$basearch&repo=centos-{repo.lower()}-$stream"

    @classmethod
    def repositories(cls, config: MkosiConfig, release: int) -> list[Repo]:
        if config.local_mirror:
            appstream_url = f"baseurl={config.local_mirror}"
            baseos_url = extras_url = powertools_url = crb_url = None
        else:
            appstream_url = cls.repository_url(config, "AppStream")
            baseos_url = cls.repository_url(config, "BaseOS")
            extras_url = cls.repository_url(config, "extras")
            if release >= 9:
                crb_url = cls.repository_url(config, "CRB")
                powertools_url = None
            else:
                crb_url = None
                powertools_url = cls.repository_url(config, "PowerTools")

        repos = []
        for name, url in (("appstream",  appstream_url),
                               ("baseos",     baseos_url),
                               ("extras",     extras_url),
                               ("crb",        crb_url),
                               ("powertools", powertools_url)):
            if url:
                repos += [Repo(name, url, cls.gpgurls())]

        return repos + cls.epel_repositories(config) + cls.sig_repositories(config)

    @classmethod
    def epel_repositories(cls, config: MkosiConfig) -> list[Repo]:
        epel_gpgurl = "https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-$releasever"

        if config.local_mirror:
            return []

        if config.mirror:
            epel_url = f"baseurl={config.mirror}/epel/$releasever/Everything/$basearch"
            epel_next_url = f"baseurl={config.mirror}/epel/next/$releasever/Everything/$basearch"
            epel_testing_url = f"baseurl={config.mirror}/epel/testing/$releasever/Everything/$basearch"
        else:
            epel_url = "metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-$releasever&arch=$basearch"
            epel_next_url = "metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-next-$releasever&arch=$basearch"
            epel_testing_url = "metalink=https://mirrors.fedoraproject.org/metalink?repo=testing-epel$releasever&arch=$basearch"

        return [
            Repo("epel", epel_url, (epel_gpgurl,), enabled=False),
            Repo("epel-next", epel_next_url, (epel_next_url,), enabled=False),
            Repo("epel-testing", epel_testing_url, (epel_gpgurl,), enabled=False),
        ]

    @classmethod
    def sig_repositories(cls, config: MkosiConfig) -> list[Repo]:
        if config.local_mirror:
            return []

        sigs = (
            (
                "hyperscale",
                (f"packages-{c}" for c in ("main", "experimental", "facebook", "hotfixes", "spin", "intel")),
                "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-SIG-HyperScale",
            ),
        )

        repos = []

        for sig, components, gpgurl in sigs:
            for c in components:
                if config.mirror:
                    if int(config.release) <= 8:
                        url = f"baseurl={config.mirror}/centos/$stream/{sig}/$basearch/{c}"
                    else:
                        url = f"baseurl={config.mirror}/SIGs/$stream/{sig}/$basearch/{c}"
                else:
                    repo = f"{sig}-{c}" if int(config.release) <= 8 else f"{sig}-sig-{c}"
                    url = cls.repository_url(config, repo)

                repos += [
                    Repo(
                        id=f"{sig}-{c}",
                        url=url,
                        gpgurls=(gpgurl,),
                        enabled=False
                    ),
                    Repo(
                        id=f"{sig}-{c}-testing",
                        url=f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                        gpgurls=(gpgurl,),
                        enabled=False,
                    ),
                ]

        return repos
