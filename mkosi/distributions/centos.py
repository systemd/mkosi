# SPDX-License-Identifier: LGPL-2.1+

import shutil
from pathlib import Path

from mkosi.backend import (
    Distribution,
    MkosiConfig,
    MkosiState,
    add_packages,
    complete_step,
    die,
    run_workspace_command,
)
from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, install_packages_dnf, invoke_dnf, setup_dnf
from mkosi.remove import unlink_try_hard


def move_rpm_db(root: Path) -> None:
    """Link /var/lib/rpm to /usr/lib/sysimage/rpm for compat with old rpm"""
    olddb = root / "var/lib/rpm"
    newdb = root / "usr/lib/sysimage/rpm"

    if newdb.exists():
        with complete_step("Moving rpm database /usr/lib/sysimage/rpm → /var/lib/rpm"):
            unlink_try_hard(olddb)
            shutil.move(newdb, olddb)

            if not any(newdb.parent.iterdir()):
                newdb.parent.rmdir()


class CentosInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> list[str]:
        return ["var/cache/yum", "var/cache/dnf"]

    @classmethod
    def filesystem(cls) -> str:
        return "xfs"

    @classmethod
    @complete_step("Installing CentOS…")
    def install(cls, state: "MkosiState") -> None:
        release = int(state.config.release)

        if release <= 7:
            die("CentOS 7 or earlier variants are not supported")
        elif release == 8 or state.config.distribution != Distribution.centos:
            repos = cls._variant_repos(state.config, release)
        else:
            repos = cls._stream_repos(state.config, release)

        setup_dnf(state, repos)

        if state.config.distribution == Distribution.centos:
            state.workspace.joinpath("vars/stream").write_text(f"{state.config.release}-stream")

        packages = {*state.config.packages}
        add_packages(state.config, packages, "systemd", "dnf")
        if not state.do_run_build_script and state.config.bootable:
            add_packages(state.config, packages, "kernel", "dracut", "dracut-config-generic")
            add_packages(state.config, packages, "systemd-udev", conditional="systemd")

        if state.do_run_build_script:
            packages.update(state.config.build_packages)

        if not state.do_run_build_script and "epel" in state.config.repositories:
            add_packages(state.config, packages, "epel-release")
            if state.config.netdev:
                add_packages(state.config, packages, "systemd-networkd", conditional="systemd")
            if state.config.distribution != Distribution.centos and release >= 9:
                add_packages(state.config, packages, "systemd-boot", conditional="systemd")

        install_packages_dnf(state, packages)

        # On Fedora, the default rpmdb has moved to /usr/lib/sysimage/rpm so if that's the case we need to
        # move it back to /var/lib/rpm on CentOS.
        move_rpm_db(state.root)

        # Centos Stream 8 and below can't write to the sqlite db backend used by
        # default in newer RPM releases so let's rebuild the DB to use the old bdb
        # backend instead. Because newer RPM releases have dropped support for the
        # bdb backend completely, we check if rpm is installed and use
        # run_workspace_command() to rebuild the rpm db.
        if release <= 8 and state.root.joinpath("usr/bin/rpm").exists():
            cmdline = ["rpm", "--rebuilddb", "--define", "_db_backend bdb"]
            run_workspace_command(state, cmdline)

    @classmethod
    def remove_packages(cls, state: MkosiState, remove: list[str]) -> None:
        invoke_dnf(state, 'remove', remove)

    @staticmethod
    def _gpg_locations(release: int) -> tuple[Path, str]:
        return (
            Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial"),
            "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official"
        )

    @staticmethod
    def _epel_gpg_locations() -> tuple[Path, str]:
        return (
            Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-$releasever"),
            "https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-$releasever",
        )

    @staticmethod
    def _extras_gpg_locations(release: int) -> tuple[Path, str]:
        return (
            Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-Extras-SHA512"),
            "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-SIG-Extras"
        )

    @classmethod
    def _mirror_directory(cls) -> str:
        return "centos"

    @classmethod
    def _mirror_repo_url(cls, repo: str) -> str:
        return f"http://mirrorlist.centos.org/?release=$stream&arch=$basearch&repo={repo}"

    @classmethod
    def _variant_repos(cls, config: MkosiConfig, release: int) -> list[Repo]:
        # Repos for CentOS Linux 8, CentOS Stream 8 and CentOS variants

        directory = cls._mirror_directory()
        gpgpath, gpgurl = cls._gpg_locations(release)
        epel_gpgpath, epel_gpgurl = cls._epel_gpg_locations()

        if config.local_mirror:
            appstream_url = f"baseurl={config.local_mirror}"
            baseos_url = extras_url = powertools_url = crb_url = epel_url = None
        elif config.mirror:
            appstream_url = f"baseurl={config.mirror}/{directory}/$stream/AppStream/$basearch/os"
            baseos_url = f"baseurl={config.mirror}/{directory}/$stream/BaseOS/$basearch/os"
            extras_url = f"baseurl={config.mirror}/{directory}/$stream/extras/$basearch/os"
            if release >= 9:
                crb_url = f"baseurl={config.mirror}/{directory}/$stream/CRB/$basearch/os"
                powertools_url = None
            else:
                crb_url = None
                powertools_url = f"baseurl={config.mirror}/{directory}/$stream/PowerTools/$basearch/os"
            epel_url = f"baseurl={config.mirror}/epel/$releasever/Everything/$basearch"
        else:
            appstream_url = f"mirrorlist={cls._mirror_repo_url('AppStream')}"
            baseos_url = f"mirrorlist={cls._mirror_repo_url('BaseOS')}"
            extras_url = f"mirrorlist={cls._mirror_repo_url('extras')}"
            if release >= 9:
                crb_url = f"mirrorlist={cls._mirror_repo_url('CRB')}"
                powertools_url = None
            else:
                crb_url = None
                powertools_url = f"mirrorlist={cls._mirror_repo_url('PowerTools')}"
            epel_url = "mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-$releasever&arch=$basearch"

        repos = [Repo("appstream", appstream_url, gpgpath, gpgurl)]
        if baseos_url is not None:
            repos += [Repo("baseos", baseos_url, gpgpath, gpgurl)]
        if extras_url is not None:
            repos += [Repo("extras", extras_url, gpgpath, gpgurl)]
        if crb_url is not None:
            repos += [Repo("crb", crb_url, gpgpath, gpgurl)]
        if powertools_url is not None:
            repos += [Repo("powertools", powertools_url, gpgpath, gpgurl)]
        if epel_url is not None:
            repos += [Repo("epel", epel_url, epel_gpgpath, epel_gpgurl, enabled=False)]

        return repos

    @classmethod
    def _stream_repos(cls, config: MkosiConfig, release: int) -> list[Repo]:
        # Repos for CentOS Stream 9 and later

        gpgpath, gpgurl = cls._gpg_locations(release)
        epel_gpgpath, epel_gpgurl = cls._epel_gpg_locations()
        extras_gpgpath, extras_gpgurl = cls._extras_gpg_locations(release)

        if config.local_mirror:
            appstream_url = f"baseurl={config.local_mirror}"
            baseos_url = extras_url = crb_url = epel_url = None
        elif config.mirror:
            appstream_url = f"baseurl={config.mirror}/centos-stream/$stream/AppStream/$basearch/os"
            baseos_url = f"baseurl={config.mirror}/centos-stream/$stream/BaseOS/$basearch/os"
            extras_url = f"baseurl={config.mirror}/centos-stream/SIGS/$stream/extras/$basearch/extras-common"
            crb_url = f"baseurl={config.mirror}/centos-stream/$stream/CRB/$basearch/os"
            epel_url = f"baseurl={config.mirror}/epel/$stream/Everything/$basearch"
        else:
            appstream_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-appstream-$stream&arch=$basearch&protocol=https,http"
            baseos_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-baseos-$stream&arch=$basearch&protocol=https,http"
            extras_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-extras-sig-extras-common-$stream&arch=$basearch&protocol=https,http"
            crb_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-crb-$stream&arch=$basearch&protocol=https,http"
            epel_url = "mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-$releasever&arch=$basearch&protocol=https,http"

        repos = [Repo("appstream", appstream_url, gpgpath, gpgurl)]
        if baseos_url is not None:
            repos += [Repo("baseos", baseos_url, gpgpath, gpgurl)]
        if extras_url is not None:
            repos += [Repo("extras", extras_url, extras_gpgpath, extras_gpgurl)]
        if crb_url is not None:
            repos += [Repo("crb", crb_url, gpgpath, gpgurl)]
        if epel_url is not None:
            repos += [Repo("epel", epel_url, epel_gpgpath, epel_gpgurl, enabled=False)]

        return repos
