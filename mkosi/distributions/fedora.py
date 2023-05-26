# SPDX-License-Identifier: LGPL-2.1+

import logging
import os
import shutil
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from textwrap import dedent
from typing import Any, NamedTuple

from mkosi.distributions import DistributionInstaller
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

        if state.config.local_mirror:
            release_url = f"baseurl={state.config.local_mirror}"
            updates_url = None
        elif state.config.mirror:
            baseurl = urllib.parse.urljoin(state.config.mirror, f"releases/{release}/Everything/$basearch/os/")
            media = urllib.parse.urljoin(baseurl.replace("$basearch", state.config.architecture), "media.repo")
            if not url_exists(media):
                baseurl = urllib.parse.urljoin(state.config.mirror, f"development/{release}/Everything/$basearch/os/")

            release_url = f"baseurl={baseurl}"
            updates_url = f"baseurl={state.config.mirror}/updates/{release}/Everything/$basearch/"
        else:
            release_url = f"metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-{release}&arch=$basearch"
            updates_url = (
                "metalink=https://mirrors.fedoraproject.org/metalink?"
                f"repo=updates-released-f{release}&arch=$basearch"
            )
        if release == 'rawhide':
            # On rawhide, the "updates" repo is the same as the "fedora" repo.
            # In other versions, the "fedora" repo is frozen at release, and "updates" provides any new packages.
            updates_url = None

        # See: https://fedoraproject.org/security/
        gpgurl = "https://fedoraproject.org/fedora.gpg"

        repos = [Repo("fedora", release_url, [gpgurl])]
        if updates_url is not None:
            repos += [Repo("updates", updates_url, [gpgurl])]

        setup_dnf(state, repos)
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)


def parse_fedora_release(release: str) -> str:
    # The release can be specified as 'rawhide-<version>'. We don't make use
    # of the second part right now, but we allow it for compatibility.
    if release.startswith("rawhide-"):
        release, releasever = release.split("-")
        logging.info(f"Fedora rawhide — release version: {releasever}")
    return release


def fedora_release_at_least(release: str, threshold: str) -> bool:
    if release == 'rawhide':
        return True
    if threshold == 'rawhide':
        return False
    # If neither is 'rawhide', both must be integers
    return int(release) >= int(threshold)


def url_exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD")
    try:
        if urllib.request.urlopen(req):
            return True
    except Exception:
        pass
    return False


class Repo(NamedTuple):
    id: str
    url: str
    gpgurls: list[str]
    enabled: bool = True


def setup_dnf(state: MkosiState, repos: Sequence[Repo]) -> None:
    with state.workspace.joinpath("dnf.conf").open("w") as f:
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

    state.workspace.joinpath("vars").mkdir(exist_ok=True)
    state.workspace.joinpath("log").mkdir(exist_ok=True)
    state.workspace.joinpath("persist").mkdir(exist_ok=True)

    dnf = shutil.which("dnf5") or shutil.which("dnf") or "yum"

    cmdline = [
        dnf,
        "-y",
        f"--config={state.workspace.joinpath('dnf.conf')}",
        command,
        "--best",
        "--allowerasing",
        f"--releasever={release}",
        f"--installroot={state.root}",
        "--setopt=keepcache=1",
        "--setopt=install_weak_deps=0",
        f"--setopt=cachedir={state.cache_dir}",
        f"--setopt=reposdir={' '.join(str(p) for p in state.config.repo_dirs)}",
        f"--setopt=varsdir={state.workspace / 'vars'}",
        f"--setopt=logdir={state.workspace / 'log'}",
        f"--setopt=persistdir={state.workspace / 'persist'}",
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
        cmdline += ["-C"]

    if not state.config.architecture_is_native():
        cmdline += [f"--forcearch={state.config.architecture}"]

    if not state.config.with_docs:
        cmdline += ["--no-docs" if dnf.endswith("dnf5") else "--nodocs"]

    cmdline += sort_packages(packages)

    bwrap(cmdline, apivfs=state.root if apivfs else None,
          env=dict(KERNEL_INSTALL_BYPASS="1") | env | state.environment)

    fixup_rpmdb_location(state.root)


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
