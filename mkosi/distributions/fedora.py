# SPDX-License-Identifier: LGPL-2.1+

import shutil
import urllib.parse
import urllib.request
from pathlib import Path
from textwrap import dedent
from typing import Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple, cast

from mkosi.backend import (
    Distribution,
    MkosiPrinter,
    MkosiState,
    OutputFormat,
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
    "7":  "CAB44B996F27744E86127CDFB44269D04F2A6FD2",
    "8":  "4FFF1F04010DEDCAE203591D62AEC3DC6DF2196F",
    "9":  "4FFF1F04010DEDCAE203591D62AEC3DC6DF2196F",
    "10": "61A8ABE091FF9FBBF4B07709BF226FCC4EBFC273",
    "11": "AEE40C04E34560A71F043D7C1DC5C758D22E77F2",
    "12": "6BF178D28A789C74AC0DC63B9D1CC34857BBCCBA",
    "13": "8E5F73FF2A1817654D358FCA7EDC6AD6E8E40FDE",
    "14": "235C2936B4B70E61B373A020421CADDB97A1071F",
    "15": "25DBB54BDED70987F4C10042B4EBF579069C8460",
    "16": "05A912AC70457C3DBC82D352067F00B6A82BA4B7",
    "17": "CAC43FB774A4A673D81C5DE750E94C991ACA3465",
    "18": "7EFB8811DD11E380B679FCEDFF01125CDE7F38BD",
    "19": "CA81B2C85E4F4D4A1A3F723407477E65FB4B18E6",
    "20": "C7C9A9C89153F20183CE7CBA2EB161FA246110C1",
    "21": "6596B8FBABDA5227A9C5B59E89AD4E8795A43F54",
    "22": "C527EA07A9349B589C35E1BF11ADC0948E1431D5",
    "23": "EF45510680FB02326B045AFB32474CF834EC9CBA",
    "24": "5048BDBBA5E776E547B09CCC73BDE98381B46521",
    "25": "C437DCCD558A66A37D6F43724089D8F2FDB19C98",
    "26": "E641850B77DF435378D1D7E2812A6B4B64DAB85D",
    "27": "860E19B0AFA800A1751881A6F55E7430F5282EE4",
    "28": "128CF232A9371991C8A65695E08E7E629DB62FB1",
    "29": "5A03B4DD8254ECA02FDA1637A20AA56B429476B4",
    "30": "F1D8EC98F241AAF20DF69420EF3C111FCFC659B9",
    "31": "7D22D5867F2A4236474BF7B850CB390B3C3359C4",
    "32": "97A1AE57C3A2372CCA3A4ABA6C13026D12C944D0",
    "33": "963A2BEB02009608FE67EA4249FD77499570FF31",
    "34": "8C5BA6990BDB26E19F2A1A801161AE6945719A39",
    "35": "787EA6AE1147EEE56C40B30CDB4639719867C58F",
    "36": "53DED2CB922D8B8D9E63FD18999F7CBF38AB71F4",
    "37": "ACB5EE4E831C74BB7C168D27F55AD3FB5323552A",
    "38": "6A51BBABBA3D5467B6171221809A8D7CEB10B464",
    "39": "E8F23996F23218640CB44CBE75CF5AC418B8E74C",
}


class FedoraInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> List[str]:
        return ["var/cache/dnf"]

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        return install_fedora(state)

    @classmethod
    def remove_packages(cls, state: MkosiState, remove: List[str]) -> None:
        invoke_dnf(state, 'remove', remove)


def fedora_release_cmp(a: str, b: str) -> int:
    """Return negative if a<b, 0 if a==b, positive otherwise"""

    # This will throw ValueError on non-integer strings
    anum = 1000 if a == "rawhide" else int(a)
    bnum = 1000 if b == "rawhide" else int(b)
    return anum - bnum


def parse_fedora_release(release: str) -> Tuple[str, str]:
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
        key = FEDORA_KEYS_MAP[releasever]

        # The website uses short identifiers for Fedora < 35: https://pagure.io/fedora-web/websites/issue/196
        if int(releasever) < 35:
            key = FEDORA_KEYS_MAP[releasever][-8:]

        gpgid = f"keys/{key}.txt"
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
        add_packages(state.config, packages, "kernel-core", "kernel-modules", "dracut")
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


def make_rpm_list(state: MkosiState, packages: Set[str]) -> Set[str]:
    packages = packages.copy()

    if state.config.bootable:
        # Temporary hack: dracut only adds crypto support to the initrd, if the cryptsetup binary is installed
        if state.config.encrypt or state.config.verity:
            add_packages(state.config, packages, "cryptsetup", conditional="dracut")

        if state.config.output_format == OutputFormat.gpt_ext4:
            add_packages(state.config, packages, "e2fsprogs")

        if state.config.output_format == OutputFormat.gpt_xfs:
            add_packages(state.config, packages, "xfsprogs")

        if state.config.output_format == OutputFormat.gpt_btrfs:
            add_packages(state.config, packages, "btrfs-progs")

    if not state.do_run_build_script and state.config.ssh:
        add_packages(state.config, packages, "openssh-server")

    return packages


def install_packages_dnf(state: MkosiState, packages: Set[str],) -> None:
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

    if state.config.use_host_repositories:
        default_repos  = ""
    else:
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
        shutil.move(cast(str, rpmdb_home), rpmdb)
