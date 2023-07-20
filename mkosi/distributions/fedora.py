# SPDX-License-Identifier: LGPL-2.1+

import logging
import os
import shutil
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from textwrap import dedent
from typing import Any, NamedTuple

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller
from mkosi.log import die
from mkosi.remove import unlink_try_hard
from mkosi.run import bwrap
from mkosi.state import MkosiState
from mkosi.util import Distribution, detect_distribution, sort_packages


class FedoraInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        release = parse_fedora_release(state.config.release)
        release_url = updates_url = appstream_url = baseos_url = extras_url = crb_url = None

        if state.config.local_mirror:
            release_url = f"baseurl={state.config.local_mirror}"
        elif release == "eln":
            assert state.config.mirror
            appstream_url = f"baseurl={state.config.mirror}/AppStream/$basearch/os"
            baseos_url = f"baseurl={state.config.mirror}/BaseOS/$basearch/os"
            extras_url = f"baseurl={state.config.mirror}/Extras/$basearch/os"
            crb_url = f"baseurl={state.config.mirror}/CRB/$basearch/os"
        elif state.config.mirror:
            directory = "development" if release == "rawhide" else "releases"
            release_url = f"baseurl={state.config.mirror}/{directory}/$releasever/Everything/$basearch/os/"
            updates_url = f"baseurl={state.config.mirror}/updates/$releasever/Everything/$basearch/"
        else:
            release_url = f"metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-{release}&arch=$basearch"
            updates_url = (
                "metalink=https://mirrors.fedoraproject.org/metalink?"
                f"repo=updates-released-f{release}&arch=$basearch"
            )

        if release == "rawhide":
            # On rawhide, the "updates" repo is the same as the "fedora" repo.
            # In other versions, the "fedora" repo is frozen at release, and "updates" provides any new packages.
            updates_url = None

        # See: https://fedoraproject.org/security/
        gpgurl = "https://fedoraproject.org/fedora.gpg"

        repos = []
        for name, url in (("fedora",    release_url),
                          ("updates",   updates_url),
                          ("appstream", appstream_url),
                          ("baseos",    baseos_url),
                          ("extras",    extras_url),
                          ("crb",       crb_url)):
            if url:
                repos += [Repo(name, url, [gpgurl])]

        setup_dnf(state, repos)
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.arm64     : "aarch64",
            Architecture.ia64      : "ia64",
            Architecture.mips64_le : "mips64el",
            Architecture.mips_le   : "mipsel",
            Architecture.parisc    : "parisc64",
            Architecture.ppc64_le  : "ppc64le",
            Architecture.riscv64   : "riscv64",
            Architecture.s390x     : "s390x",
            Architecture.x86_64    : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Fedora")

        return a


def parse_fedora_release(release: str) -> str:
    # The release can be specified as 'rawhide-<version>'. We don't make use
    # of the second part right now, but we allow it for compatibility.
    if release.startswith("rawhide-"):
        release, releasever = release.split("-")
        logging.info(f"Fedora rawhide — release version: {releasever}")
    return release


def fedora_release_at_least(release: str, threshold: str) -> bool:
    if release in ("rawhide", "eln"):
        return True
    if threshold in ("rawhide", "eln"):
        return False
    # If neither is 'rawhide', both must be integers
    return int(release) >= int(threshold)


class Repo(NamedTuple):
    id: str
    url: str
    gpgurls: list[str]
    enabled: bool = True


def setup_dnf(state: MkosiState, repos: Sequence[Repo]) -> None:
    config = state.pkgmngr / "etc/dnf/dnf.conf"

    if not config.exists():
        config.parent.mkdir(exist_ok=True, parents=True)
        config.write_text(
            dedent(
                """\
                [main]
                install_weak_deps=0
                """
            )
        )

    repofile = state.pkgmngr / "etc/yum.repos.d/mkosi.repo"
    if not repofile.exists():
        repofile.parent.mkdir(exist_ok=True, parents=True)
        with repofile.open("w") as f:
            for repo in repos:
                f.write(
                    dedent(
                        f"""\
                        [{repo.id}]
                        name={repo.id}
                        {repo.url}
                        gpgcheck=1
                        enabled={int(repo.enabled)}
                        """
                    )
                )

                for i, url in enumerate(repo.gpgurls):
                    f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                    f.write(f"{url}\n")


def invoke_dnf(
    state: MkosiState,
    command: str,
    packages: Iterable[str],
    env: Mapping[str, Any] = {},
    apivfs: bool = True
) -> None:
    if state.config.distribution == Distribution.fedora:
        release = parse_fedora_release(state.config.release)
    else:
        release = state.config.release

    state.pkgmngr.joinpath("etc/dnf/vars").mkdir(exist_ok=True, parents=True)
    state.pkgmngr.joinpath("etc/yum.repos.d").mkdir(exist_ok=True, parents=True)
    state.pkgmngr.joinpath("var/lib/dnf").mkdir(exist_ok=True, parents=True)

    # dnf5 does not support building for foreign architectures yet (missing --forcearch)
    dnf = shutil.which("dnf5") if state.config.architecture.is_native() else None
    dnf = dnf or shutil.which("dnf") or "yum"

    cmdline = [
        dnf,
        "--assumeyes",
        f"--config={state.pkgmngr / 'etc/dnf/dnf.conf'}",
        "--best",
        f"--releasever={release}",
        f"--installroot={state.root}",
        "--setopt=keepcache=1",
        f"--setopt=cachedir={state.cache_dir}",
        f"--setopt=reposdir={state.pkgmngr / 'etc/yum.repos.d'}",
        f"--setopt=varsdir={state.pkgmngr / 'etc/dnf/vars'}",
        f"--setopt=persistdir={state.pkgmngr / 'var/lib/dnf'}",
        "--setopt=check_config_file_age=0",
        "--no-plugins" if dnf.endswith("dnf5") else "--noplugins",
    ]

    # Make sure we download filelists so all dependencies can be resolved.
    # See https://bugzilla.redhat.com/show_bug.cgi?id=2180842
    if (dnf.endswith("dnf5") and
        not (state.config.distribution == Distribution.fedora
             and fedora_release_at_least(release, '38'))):
        cmdline += ["--setopt=optional_metadata_types=filelists"]

    if not state.config.repository_key_check:
        cmdline += ["--nogpgcheck"]

    if state.config.repositories:
        opt = "--enable-repo" if dnf.endswith("dnf5") else "--enablerepo"
        cmdline += [f"{opt}={repo}" for repo in state.config.repositories]

    # TODO: this breaks with a local, offline repository created with 'createrepo'
    if state.config.cache_only and not state.config.local_mirror:
        cmdline += ["--cacheonly"]

    if not state.config.architecture.is_native():
        cmdline += [f"--forcearch={state.installer.architecture(state.config.architecture)}"]

    if not state.config.with_docs:
        cmdline += ["--no-docs" if dnf.endswith("dnf5") else "--nodocs"]

    cmdline += [command, *sort_packages(packages)]

    bwrap(cmdline,
          apivfs=state.root if apivfs else None,
          env=dict(KERNEL_INSTALL_BYPASS="1") | env | state.config.environment)

    fixup_rpmdb_location(state.root)

    # The log directory is always interpreted relative to the install root so there's nothing we can do but
    # to remove the log files from the install root afterwards.
    for p in (state.root / "var/log").iterdir():
        if p.name.startswith("dnf"):
            p.unlink()


def fixup_rpmdb_location(root: Path) -> None:
    distribution, _ = detect_distribution()
    if distribution not in (Distribution.debian, Distribution.ubuntu):
        return

    # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/ so it needs to be copied back in the
    # right location, otherwise the rpmdb will be broken. See: https://bugs.debian.org/1004863. We also
    # replace it with a symlink so that any further rpm operations immediately use the correct location.

    rpmdb_home = root / "root/.rpmdb"
    if rpmdb_home.exists() and not rpmdb_home.is_symlink():
        # Take into account the new location in F36
        rpmdb = root / "usr/lib/sysimage/rpm"
        if not rpmdb.exists():
            rpmdb = root / "var/lib/rpm"
        unlink_try_hard(rpmdb)
        shutil.move(rpmdb_home, rpmdb)
        rpmdb_home.symlink_to(os.path.relpath(rpmdb, start=rpmdb_home.parent))
