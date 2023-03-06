# SPDX-License-Identifier: LGPL-2.1+

import shutil
from collections.abc import Sequence
from pathlib import Path

from mkosi.backend import Distribution, MkosiConfig, MkosiState, add_packages
from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, invoke_dnf, setup_dnf
from mkosi.log import complete_step, die
from mkosi.remove import unlink_try_hard
from mkosi.run import run_workspace_command


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
        # This should really be "xfs" but unprivileged population of XFS filesystems with files containing
        # spaces in their path is broken and needs fixing in xfsprogs, see
        # https://marc.info/?l=linux-xfs&m=167450838316386&w=2.
        return "ext4"

    @staticmethod
    def kernel_command_line(state: MkosiState) -> list[str]:
        kcl = []

        # systemd-gpt-auto-generator only started applying the GPT partition read-only flag to gpt-auto
        # mounts from v240 onwards, while CentOS Stream 8 ships systemd v239, so we have to nudge gpt-auto to
        # mount the root partition rw by default.
        if state.config.bootable and int(state.config.release) <= 8:
            kcl += ["rw"]

        return kcl + DistributionInstaller.kernel_command_line(state)

    @classmethod
    @complete_step("Installing CentOS…")
    def install(cls, state: MkosiState) -> None:
        release = int(state.config.release)

        if release <= 7:
            die("CentOS 7 or earlier variants are not supported")
        elif release == 8 or state.config.distribution != Distribution.centos:
            repos = cls._variant_repos(state.config, release)
        else:
            repos = cls._stream_repos(state.config, release)

        setup_dnf(state, repos)

        if state.config.distribution == Distribution.centos:
            env = dict(DNF_VAR_stream=f"{state.config.release}-stream")
        else:
            env = {}

        packages = state.config.packages.copy()
        add_packages(state.config, packages, "systemd", "rpm")
        if not state.do_run_build_script:
            if state.config.bootable:
                add_packages(state.config, packages, "kernel", "dracut", "dracut-config-generic")
                add_packages(state.config, packages, "systemd-udev", conditional="systemd")
            if state.config.ssh:
                add_packages(state.config, packages, "openssh-server")

        if state.do_run_build_script:
            packages += state.config.build_packages

        if "epel" in state.config.repositories:
            add_packages(state.config, packages, "epel-release")
            if not state.do_run_build_script:
                if state.config.netdev:
                    add_packages(state.config, packages, "systemd-networkd", conditional="systemd")
                if state.config.distribution != Distribution.centos and release >= 9:
                    add_packages(state.config, packages, "systemd-boot", conditional="systemd")

        # Make sure we only install the minimal language files by default on CentOS Stream 8 which still
        # defaults to all langpacks.
        if release <= 8:
            add_packages(state.config, packages, "glibc-minimal-langpack")

        invoke_dnf(state, "install", packages, env)

        syslog = state.root.joinpath("etc/systemd/system/syslog.service")
        if release <= 8 and syslog.is_symlink():
            syslog.unlink()

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
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        if state.config.distribution == Distribution.centos:
            env = dict(DNF_VAR_stream=f"{state.config.release}-stream")
        else:
            env = {}

        invoke_dnf(state, "install", packages, env)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)

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
    def _epel_repos(cls, config: MkosiConfig) -> list[Repo]:
        epel_gpgpath, epel_gpgurl = cls._epel_gpg_locations()

        if config.local_mirror:
            return []

        if config.mirror:
            epel_url = f"baseurl={config.mirror}/epel/$releasever/Everything/$basearch"
            epel_testing_url = f"baseurl={config.mirror}/epel/testing/$releasever/Everything/$basearch"
        else:
            epel_url = "metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-$releasever&arch=$basearch"
            epel_testing_url = "metalink=https://mirrors.fedoraproject.org/metalink?repo=testing-epel$releasever&arch=$basearch"

        return [
            Repo("epel", epel_url, epel_gpgpath, epel_gpgurl, enabled=False),
            Repo("epel-testing", epel_testing_url, epel_gpgpath, epel_gpgurl, enabled=False),
        ]

    @classmethod
    def _variant_repos(cls, config: MkosiConfig, release: int) -> list[Repo]:
        # Repos for CentOS Linux 8, CentOS Stream 8 and CentOS variants

        directory = cls._mirror_directory()
        gpgpath, gpgurl = cls._gpg_locations(release)

        if config.local_mirror:
            appstream_url = f"baseurl={config.local_mirror}"
            baseos_url = extras_url = powertools_url = crb_url = None
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

        repos = [Repo("appstream", appstream_url, gpgpath, gpgurl)]
        if baseos_url is not None:
            repos += [Repo("baseos", baseos_url, gpgpath, gpgurl)]
        if extras_url is not None:
            repos += [Repo("extras", extras_url, gpgpath, gpgurl)]
        if crb_url is not None:
            repos += [Repo("crb", crb_url, gpgpath, gpgurl)]
        if powertools_url is not None:
            repos += [Repo("powertools", powertools_url, gpgpath, gpgurl)]
        repos += cls._epel_repos(config)

        return repos

    @classmethod
    def _stream_repos(cls, config: MkosiConfig, release: int) -> list[Repo]:
        # Repos for CentOS Stream 9 and later

        gpgpath, gpgurl = cls._gpg_locations(release)
        extras_gpgpath, extras_gpgurl = cls._extras_gpg_locations(release)

        if config.local_mirror:
            appstream_url = f"baseurl={config.local_mirror}"
            baseos_url = extras_url = crb_url = None
        elif config.mirror:
            appstream_url = f"baseurl={config.mirror}/centos-stream/$stream/AppStream/$basearch/os"
            baseos_url = f"baseurl={config.mirror}/centos-stream/$stream/BaseOS/$basearch/os"
            extras_url = f"baseurl={config.mirror}/centos-stream/SIGS/$stream/extras/$basearch/extras-common"
            crb_url = f"baseurl={config.mirror}/centos-stream/$stream/CRB/$basearch/os"
        else:
            appstream_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-appstream-$stream&arch=$basearch&protocol=https,http"
            baseos_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-baseos-$stream&arch=$basearch&protocol=https,http"
            extras_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-extras-sig-extras-common-$stream&arch=$basearch&protocol=https,http"
            crb_url = "metalink=https://mirrors.centos.org/metalink?repo=centos-crb-$stream&arch=$basearch&protocol=https,http"

        repos = [Repo("appstream", appstream_url, gpgpath, gpgurl)]
        if baseos_url is not None:
            repos += [Repo("baseos", baseos_url, gpgpath, gpgurl)]
        if extras_url is not None:
            repos += [Repo("extras", extras_url, extras_gpgpath, extras_gpgurl)]
        if crb_url is not None:
            repos += [Repo("crb", crb_url, gpgpath, gpgurl)]
        repos += cls._epel_repos(config)

        return repos
