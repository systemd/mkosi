# SPDX-License-Identifier: LGPL-2.1+

import shutil
import subprocess
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from textwrap import dedent
from typing import Any, NamedTuple, Optional

from mkosi.backend import Distribution, MkosiState, detect_distribution, sort_packages
from mkosi.distributions import DistributionInstaller
from mkosi.log import MkosiPrinter, complete_step, warn
from mkosi.remove import unlink_try_hard
from mkosi.run import run_with_apivfs, run_workspace_command

FEDORA_KEYS_MAP = {
    "36": "53DED2CB922D8B8D9E63FD18999F7CBF38AB71F4",
    "37": "ACB5EE4E831C74BB7C168D27F55AD3FB5323552A",
    "38": "6A51BBABBA3D5467B6171221809A8D7CEB10B464",
    "39": "E8F23996F23218640CB44CBE75CF5AC418B8E74C",
}


class FedoraInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        return install_fedora(state)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "install", packages)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)


def parse_fedora_release(release: str) -> tuple[str, str]:
    if release.startswith("rawhide-"):
        release, releasever = release.split("-")
        MkosiPrinter.info(f"Fedora rawhide — release version: {releasever}")
        return ("rawhide", releasever)
    else:
        return (release, release)


@complete_step("Installing Fedora Linux…")
def install_fedora(state: MkosiState) -> None:
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

    if releasever in FEDORA_KEYS_MAP:
        gpgid = f"keys/{FEDORA_KEYS_MAP[releasever]}.txt"
    else:
        gpgid = "fedora.gpg"

    gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-{releasever}-{state.config.architecture}")
    gpgurl = urllib.parse.urljoin("https://getfedora.org/static/", gpgid)

    repos = [Repo("fedora", release_url, gpgpath, gpgurl)]
    if updates_url is not None:
        repos += [Repo("updates", updates_url, gpgpath, gpgurl)]

    setup_dnf(state, repos)

    invoke_dnf(state, "install", ["filesystem", *state.config.packages])

    # Fedora defaults to sssd authselect profile, let's override it with the minimal profile if it exists and
    # extend it with the with-homed feature if we can find it.
    if state.root.joinpath("usr/share/authselect/default/minimal").exists():
        run_workspace_command(state, ["authselect", "select", "minimal"])

        features = run_workspace_command(state, ["authselect", "list-features", "minimal"],
                                         stdout=subprocess.PIPE).stdout.split()
        if "with-homed" in features:
            run_workspace_command(state, ["authselect", "enable-feature", "with-homed"])


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
                warn(f"GPG key not found at {repo.gpgpath}. Not checking GPG signatures.")
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
        'dnf' if shutil.which('dnf') else 'yum',
        "-y",
        f"--config={state.workspace.joinpath('dnf.conf')}",
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

    cmdline += [command, *sort_packages(packages)]

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
