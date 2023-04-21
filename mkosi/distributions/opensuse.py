# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

from mkosi.distributions import DistributionInstaller
from mkosi.run import bwrap
from mkosi.types import PathString
from mkosi.util import MkosiState


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

        repos = [("repo-oss", release_url)]
        if updates_url is not None:
            repos += [("repo-update", updates_url)]

        setup_zypper(state, repos)
        invoke_zypper(state, "install", ["-y", "--download-in-advance", "--no-recommends"], packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_zypper(state, "remove", ["-y", "--clean-deps"], packages)

    @staticmethod
    def initrd_path(kver: str) -> Path:
        return Path("boot") / f"initrd-{kver}"


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
        f"--cache-dir={state.cache}",
        f"--reposd-dir={state.workspace / 'zypp.repos.d'}",
        "--gpg-auto-import-keys" if state.config.repository_key_check else "--no-gpg-checks",
        "--non-interactive",
        verb,
        *options,
        *packages,
    ]

    env = dict(ZYPP_CONF=str(state.workspace / "zypp.conf"), KERNEL_INSTALL_BYPASS="1") | state.environment

    bwrap(cmdline, apivfs=state.root if apivfs else None, env=env)

