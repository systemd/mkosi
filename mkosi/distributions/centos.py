# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path
from typing import List, Tuple

from mkosi.backend import (
    MkosiConfig,
    MkosiState,
    add_packages,
    complete_step,
    die,
    is_epel_variant,
    run_workspace_command,
)
from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, install_packages_dnf, invoke_dnf, setup_dnf


class CentosInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> List[str]:
        return ["var/cache/yum", "var/cache/dnf"]

    @classmethod
    @complete_step("Installing CentOS…")
    def install(cls, state: "MkosiState") -> None:
        epel_release = cls._parse_epel_release(state.config.release)

        if epel_release <= 7:
            die("CentOS 7 or earlier variants are not supported")
        elif epel_release <= 8 or not "-stream" in state.config.release:
            repos = cls._variant_repos(state.config, epel_release)
        else:
            repos = cls._stream_repos(state.config, epel_release)

        setup_dnf(state, repos)

        if "-stream" in state.config.release:
            state.workspace.joinpath("vars/stream").write_text(state.config.release)

        packages = {*state.config.packages}
        add_packages(state.config, packages, "systemd", "dnf")
        if not state.do_run_build_script and state.config.bootable:
            add_packages(state.config, packages, "kernel", "dracut")
            add_packages(state.config, packages, "systemd-udev", conditional="systemd")

        if state.do_run_build_script:
            packages.update(state.config.build_packages)

        if state.do_run_build_script:
            packages.update(state.config.build_packages)

        if not state.do_run_build_script and is_epel_variant(state.config.distribution):
            if state.config.netdev:
                add_packages(state.config, packages, "systemd-networkd", conditional="systemd")
            if epel_release >= 9:
                add_packages(state.config, packages, "systemd-boot", conditional="systemd")

        install_packages_dnf(state, packages)

        # Centos Stream 8 and below can't write to the sqlite db backend used by
        # default in newer RPM releases so let's rebuild the DB to use the old bdb
        # backend instead. Because newer RPM releases have dropped support for the
        # bdb backend completely, we check if rpm is installed and use
        # run_workspace_command() to rebuild the rpm db.
        if epel_release <= 8 and state.root.joinpath("usr/bin/rpm").exists():
            cmdline = ["rpm", "--rebuilddb", "--define", "_db_backend bdb"]
            run_workspace_command(state, cmdline)

    @classmethod
    def remove_packages(cls, state: MkosiState, remove: List[str]) -> None:
        invoke_dnf(state, 'remove', remove)

    @classmethod
    def _is_epel(cls) -> bool:
        name = cls.__name__
        if name.endswith("Installer"):
            name = name[:-9]
        return name.endswith("Epel")

    @staticmethod
    def _parse_epel_release(release: str) -> int:
        fields = release.split(".")
        if fields[0].endswith("-stream"):
            epel_release = fields[0].split("-")[0]
        else:
            epel_release = fields[0]
        return int(epel_release)

    @staticmethod
    def _gpg_locations(epel_release: int) -> Tuple[Path, str]:
        return (
            Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial"),
            "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official"
        )

    @staticmethod
    def _epel_gpg_locations(epel_release: int) -> Tuple[Path, str]:
        return (
            Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}"),
            f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}",
        )

    @classmethod
    def _mirror_directory(cls) -> str:
        return "centos"

    @classmethod
    def _mirror_repo_url(cls, config: MkosiConfig, repo: str) -> str:
        return f"http://mirrorlist.centos.org/?release={config.release}&arch=$basearch&repo={repo}"

    @classmethod
    def _variant_repos(cls, config: MkosiConfig, epel_release: int) -> List[Repo]:
        # Repos for CentOS Linux 8, CentOS Stream 8 and CentOS variants

        directory = cls._mirror_directory()
        gpgpath, gpgurl = cls._gpg_locations(epel_release)
        epel_gpgpath, epel_gpgurl = cls._epel_gpg_locations(epel_release)

        if config.local_mirror:
            appstream_url = f"baseurl={config.local_mirror}"
            baseos_url = extras_url = powertools_url = epel_url = None
        elif config.mirror:
            appstream_url = f"baseurl={config.mirror}/{directory}/{config.release}/AppStream/$basearch/os"
            baseos_url = f"baseurl={config.mirror}/{directory}/{config.release}/BaseOS/$basearch/os"
            extras_url = f"baseurl={config.mirror}/{directory}/{config.release}/extras/$basearch/os"
            powertools_url = f"baseurl={config.mirror}/{directory}/{config.release}/PowerTools/$basearch/os"
            epel_url = f"baseurl={config.mirror}/epel/{epel_release}/Everything/$basearch"
        else:
            appstream_url = f"mirrorlist={cls._mirror_repo_url(config, 'AppStream')}"
            baseos_url = f"mirrorlist={cls._mirror_repo_url(config, 'BaseOS')}"
            extras_url = f"mirrorlist={cls._mirror_repo_url(config, 'extras')}"
            powertools_url = f"mirrorlist={cls._mirror_repo_url(config, 'PowerTools')}"
            epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=$basearch"

        repos = [Repo("AppStream", appstream_url, gpgpath, gpgurl)]
        if baseos_url is not None:
            repos += [Repo("BaseOS", baseos_url, gpgpath, gpgurl)]
        if extras_url is not None:
            repos += [Repo("extras", extras_url, gpgpath, gpgurl)]
        if powertools_url is not None:
            repos += [Repo("PowerTools", powertools_url, gpgpath, gpgurl)]
        if epel_url is not None and cls._is_epel():
            repos += [Repo("epel", epel_url, epel_gpgpath, epel_gpgurl)]

        return repos

    @classmethod
    def _stream_repos(cls, config: MkosiConfig, epel_release: int) -> List[Repo]:
        # Repos for CentOS Stream 9 and later

        gpgpath, gpgurl = cls._gpg_locations(epel_release)
        epel_gpgpath, epel_gpgurl = cls._epel_gpg_locations(epel_release)

        release = f"{epel_release}-stream"

        if config.local_mirror:
            appstream_url = f"baseurl={config.local_mirror}"
            baseos_url = crb_url = epel_url = None
        elif config.mirror:
            appstream_url = f"baseurl={config.mirror}/centos-stream/{release}/AppStream/$basearch/os"
            baseos_url = f"baseurl={config.mirror}/centos-stream/{release}/BaseOS/$basearch/os"
            crb_url = f"baseurl={config.mirror}/centos-stream/{release}/CRB/$basearch/os"
            epel_url = f"baseurl={config.mirror}/epel/{epel_release}/Everything/$basearch"
        else:
            appstream_url = f"metalink=https://mirrors.centos.org/metalink?repo=centos-appstream-{release}&arch=$basearch"
            baseos_url = f"metalink=https://mirrors.centos.org/metalink?repo=centos-baseos-{release}&arch=$basearch"
            crb_url = f"metalink=https://mirrors.centos.org/metalink?repo=centos-crb-{release}&arch=$basearch"
            epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=$basearch"

        repos = [Repo("AppStream", appstream_url, gpgpath, gpgurl)]
        if baseos_url is not None:
            repos += [Repo("BaseOS", baseos_url, gpgpath, gpgurl)]
        if crb_url is not None:
            repos += [Repo("CRB", crb_url, gpgpath, gpgurl)]
        if epel_url is not None and cls._is_epel():
            repos += [Repo("epel", epel_url, epel_gpgpath, epel_gpgurl)]

        return repos
