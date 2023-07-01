# SPDX-License-Identifier: LGPL-2.1+

import shutil
import urllib.request
import xml.etree.ElementTree as ElementTree
from collections.abc import Sequence
from textwrap import dedent

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, fixup_rpmdb_location, invoke_dnf, setup_dnf
from mkosi.log import die
from mkosi.run import bwrap
from mkosi.state import MkosiState
from mkosi.types import PathString


class OpensuseInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        release = state.config.release
        if release == "leap":
            release = "stable"

        # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy
        # (14.x won't ever appear). For anything else, let's default to Leap.
        if state.config.local_mirror:
            release_url = f"{state.config.local_mirror}"
            updates_url = None
        if release.isdigit() or release == "tumbleweed":
            release_url = f"{state.config.mirror}/tumbleweed/repo/oss/"
            updates_url = f"{state.config.mirror}/update/tumbleweed/"
        elif release in ("current", "stable"):
            release_url = f"{state.config.mirror}/distribution/openSUSE-stable/repo/oss/"
            updates_url = f"{state.config.mirror}/update/openSUSE-{release}/"
        else:
            release_url = f"{state.config.mirror}/distribution/leap/{release}/repo/oss/"
            updates_url = f"{state.config.mirror}/update/leap/{release}/oss/"

        if shutil.which("zypper") is not None:
            repo_list = [("repo-oss", release_url)]
            if updates_url is not None:
                repo_list += [("repo-update", updates_url)]

            setup_zypper(state, repo_list)
            invoke_zypper(state, "install", ["-y", "--download-in-advance", "--no-recommends"], packages, apivfs=apivfs)
        else:
            repos = [Repo("repo-oss", f"baseurl={release_url}", fetch_gpgurls(release_url))]
            if updates_url is not None:
                repos += [Repo("repo-update", f"baseurl={updates_url}", fetch_gpgurls(updates_url))]

            setup_dnf(state, repos)
            invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        if shutil.which("zypper") is not None:
            invoke_zypper(state, "remove", ["-y", "--clean-deps"], packages)
        else:
            invoke_dnf(state, "remove", packages)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by OpenSUSE")

        return a


def fetch_gpgurls(repourl: str) -> list[str]:
    gpgurls = [f"{repourl}/repodata/repomd.xml.key"]

    with urllib.request.urlopen(f"{repourl}/repodata/repomd.xml") as f:
        xml = f.read().decode()
        root = ElementTree.fromstring(xml)

        tags = root.find("{http://linux.duke.edu/metadata/repo}tags")
        if not tags:
            die("repomd.xml missing <tags> element")

        for child in tags.iter("{http://linux.duke.edu/metadata/repo}content"):
            if child.text and child.text.startswith("gpg-pubkey"):
                gpgkey = child.text.partition("?")[0]
                gpgurls += [f"{repourl}{gpgkey}"]

    return gpgurls


def setup_zypper(state: MkosiState, repos: Sequence[tuple[str, str]] = ()) -> None:
    with state.workspace.joinpath("zypp.conf").open("w") as f:
        f.write(
            dedent(
                f"""\
                [main]
                rpm.install.excludedocs = {"no" if state.config.with_docs else "yes"}
                """
            )
        )

    state.workspace.joinpath("zypp.repos.d").mkdir(exist_ok=True)

    with state.workspace.joinpath("zypp.repos.d/mkosi.repo").open("w") as f:
        for id, url in repos:
            f.write(
                dedent(
                    f"""\
                    [{id}]
                    name={id}
                    baseurl={url}
                    autorefresh=0
                    enabled=1
                    keeppackages=1
                    """
                )
            )


def invoke_zypper(
    state: MkosiState,
    verb: str,
    options: Sequence[str],
    packages: Sequence[str],
    apivfs: bool = True
) -> None:
    cmdline: list[PathString] = [
        "zypper",
        "--root", state.root,
        f"--cache-dir={state.cache_dir}",
        f"--reposd-dir={state.workspace / 'zypp.repos.d'}",
        "--gpg-auto-import-keys" if state.config.repository_key_check else "--no-gpg-checks",
        "--non-interactive",
        verb,
        *options,
        *packages,
    ]

    env = dict(ZYPP_CONF=str(state.workspace / "zypp.conf"), KERNEL_INSTALL_BYPASS="1") | state.environment

    bwrap(cmdline, apivfs=state.root if apivfs else None, env=env)

    fixup_rpmdb_location(state.root)
