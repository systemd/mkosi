# SPDX-License-Identifier: LGPL-2.1+

import logging
import shutil
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from textwrap import dedent
from typing import Any, NamedTuple, Optional

from mkosi.distributions import DistributionInstaller
from mkosi.remove import unlink_try_hard
from mkosi.run import run_with_apivfs
from mkosi.util import Distribution, MkosiState, detect_distribution, sort_packages


class FedoraInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["setup"])

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        release, releasever = parse_fedora_release(state.config.release)

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

        gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-{releasever}-{state.config.architecture}")
        # See: https://fedoraproject.org/security/
        gpgurl = "https://fedoraproject.org/fedora.gpg"

        repos = [Repo("fedora", release_url, gpgpath, gpgurl)]
        if updates_url is not None:
            repos += [Repo("updates", updates_url, gpgpath, gpgurl)]

        setup_dnf(state, repos)
        invoke_dnf(state, "install", packages)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)


def parse_fedora_release(release: str) -> tuple[str, str]:
    if release.startswith("rawhide-"):
        release, releasever = release.split("-")
        logging.info(f"Fedora rawhide — release version: {releasever}")
        return ("rawhide", releasever)
    else:
        return (release, release)


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
    gpgpath: Path
    gpgurl: Optional[str] = None
    enabled: bool = True


def setup_dnf(state: MkosiState, repos: Sequence[Repo] = ()) -> None:
    with state.workspace.joinpath("dnf.conf").open("w") as f:
        gpgcheck = True

        for repo in repos:
            gpgkey: Optional[str] = None

            if repo.gpgpath.exists():
                gpgkey = f"file://{repo.gpgpath}"
            elif repo.gpgurl:
                gpgkey = repo.gpgurl
            else:
                logging.warning(f"GPG key not found at {repo.gpgpath}. Not checking GPG signatures.")
                gpgcheck = False

            f.write(
                dedent(
                    f"""\
                    [{repo.id}]
                    name={repo.id}
                    {repo.url}
                    gpgkey={gpgkey or ''}
                    gpgcheck={int(gpgcheck)}
                    enabled={int(repo.enabled)}
                    """
                )
            )


def invoke_dnf(state: MkosiState, command: str, packages: Iterable[str], env: Mapping[str, Any] = {}) -> None:
    if state.config.distribution == Distribution.fedora:
        release, _ = parse_fedora_release(state.config.release)
    else:
        release = state.config.release

    state.workspace.joinpath("vars").mkdir(exist_ok=True)

    cmdline = [
        shutil.which('dnf5') or shutil.which('dnf') or 'yum',
        "-y",
        f"--config={state.workspace.joinpath('dnf.conf')}",
        command,
        "--best",
        "--allowerasing",
        f"--releasever={release}",
        f"--installroot={state.root}",
        "--setopt=keepcache=1",
        "--setopt=install_weak_deps=0",
        f"--setopt=cachedir={state.cache}",
        f"--setopt=reposdir={' '.join(str(p) for p in state.config.repo_dirs)}",
        f"--setopt=varsdir={state.workspace / 'vars'}",
        "--setopt=check_config_file_age=0",
        "--noplugins",
    ]

    if not state.config.repository_key_check:
        cmdline += ["--nogpgcheck"]

    if state.config.repositories:
        cmdline += [f"--enablerepo={repo}" for repo in state.config.repositories]

    # TODO: this breaks with a local, offline repository created with 'createrepo'
    if state.config.cache_only and not state.config.local_mirror:
        cmdline += ["-C"]

    if not state.config.architecture_is_native():
        cmdline += [f"--forcearch={state.config.architecture}"]

    if not state.config.with_docs:
        cmdline += ["--nodocs"]

    cmdline += sort_packages(packages)

    run_with_apivfs(state, cmdline, env=dict(KERNEL_INSTALL_BYPASS="1") | env)

    distribution, _ = detect_distribution()
    if distribution not in (Distribution.debian, Distribution.ubuntu):
        return

    # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/
    # so it needs to be copied back in the right location, otherwise
    # the rpmdb will be broken. See: https://bugs.debian.org/1004863
    rpmdb_home = state.root / "root/.rpmdb"
    if rpmdb_home.exists():
        # Take into account the new location in F36
        rpmdb = state.root / "usr/lib/sysimage/rpm"
        if not rpmdb.exists():
            rpmdb = state.root / "var/lib/rpm"
        unlink_try_hard(rpmdb)
        shutil.move(rpmdb_home, rpmdb)
