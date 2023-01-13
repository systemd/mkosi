# SPDX-License-Identifier: LGPL-2.1+

import shutil
import urllib.parse
import urllib.request
from collections.abc import Iterable, Sequence
from pathlib import Path
from textwrap import dedent
from typing import NamedTuple, Optional

from mkosi.backend import (
    Distribution,
    MkosiPrinter,
    MkosiState,
    add_packages,
    complete_step,
    detect_distribution,
    run,
    sort_packages,
    warn,
)
from mkosi.distributions import DistributionInstaller
from mkosi.mounts import mount_api_vfs
from mkosi.remove import unlink_try_hard

FEDORA_KEYS_MAP = {
    "36": "53DED2CB922D8B8D9E63FD18999F7CBF38AB71F4",
    "37": "ACB5EE4E831C74BB7C168D27F55AD3FB5323552A",
    "38": "6A51BBABBA3D5467B6171221809A8D7CEB10B464",
    "39": "E8F23996F23218640CB44CBE75CF5AC418B8E74C",
}


class FedoraInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> list[str]:
        return ["var/cache/dnf"]

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        return install_fedora(state)

    @classmethod
    def remove_packages(cls, state: MkosiState, remove: list[str]) -> None:
        invoke_dnf(state, 'remove', remove)


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

    packages = {*state.config.packages}
    add_packages(state.config, packages, "systemd", "util-linux", "dnf")

    if not state.do_run_build_script and state.config.bootable:
        add_packages(state.config, packages, "kernel-core", "kernel-modules", "dracut", "dracut-config-generic")
        add_packages(state.config, packages, "systemd-udev", conditional="systemd")
    if state.do_run_build_script:
        packages.update(state.config.build_packages)
    if not state.do_run_build_script and state.config.netdev:
        add_packages(state.config, packages, "systemd-networkd", conditional="systemd")
    install_packages_dnf(state, packages)

    # FIXME: should this be conditionalized on config.with_docs like in install_debian_or_ubuntu()?
    #        But we set LANG=C.UTF-8 anyway.
    shutil.rmtree(state.root / "usr/share/locale", ignore_errors=True)


def url_exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD")
    try:
        if urllib.request.urlopen(req):
            return True
    except Exception:
        pass
    return False


def make_rpm_list(state: MkosiState, packages: set[str]) -> set[str]:
    packages = packages.copy()

    if not state.do_run_build_script and state.config.ssh:
        add_packages(state.config, packages, "openssh-server")

    return packages


def install_packages_dnf(state: MkosiState, packages: set[str],) -> None:
    packages = make_rpm_list(state, packages)
    invoke_dnf(state, 'install', packages)


class Repo(NamedTuple):
    id: str
    url: str
    gpgpath: Path
    gpgurl: Optional[str] = None


def setup_dnf(state: MkosiState, repos: Sequence[Repo] = ()) -> None:
    gpgcheck = True

    repo_file = state.workspace / "mkosi.repo"
    with repo_file.open("w") as f:
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
                    enabled=1
                    """
                )
            )

    default_repos  = f"reposdir={state.workspace} {state.config.repos_dir if state.config.repos_dir else ''}"

    vars_dir = state.workspace / "vars"
    vars_dir.mkdir(exist_ok=True)

    config_file = state.workspace / "dnf.conf"
    config_file.write_text(
        dedent(
            f"""\
            [main]
            gpgcheck={'1' if gpgcheck else '0'}
            {default_repos }
            varsdir={vars_dir}
            """
        )
    )


def invoke_dnf(state: MkosiState, command: str, packages: Iterable[str]) -> None:
    if state.config.distribution == Distribution.fedora:
        release, _ = parse_fedora_release(state.config.release)
    else:
        release = state.config.release

    config_file = state.workspace / "dnf.conf"

    cmd = 'dnf' if shutil.which('dnf') else 'yum'

    cmdline = [
        cmd,
        "-y",
        f"--config={config_file}",
        "--best",
        "--allowerasing",
        f"--releasever={release}",
        f"--installroot={state.root}",
        "--setopt=keepcache=1",
        "--setopt=install_weak_deps=0",
        "--noplugins",
    ]

    if not state.config.repository_key_check:
        cmdline += ["--nogpgcheck"]

    if state.config.repositories:
        cmdline += ["--disablerepo=*"] + [f"--enablerepo={repo}" for repo in state.config.repositories]

    # TODO: this breaks with a local, offline repository created with 'createrepo'
    if state.config.with_network == "never" and not state.config.local_mirror:
        cmdline += ["-C"]

    if not state.config.architecture_is_native():
        cmdline += [f"--forcearch={state.config.architecture}"]

    if not state.config.with_docs:
        cmdline += ["--nodocs"]

    cmdline += [command, *sort_packages(packages)]

    with mount_api_vfs(state.root):
        run(cmdline, env={"KERNEL_INSTALL_BYPASS": state.environment.get("KERNEL_INSTALL_BYPASS", "1")})

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
