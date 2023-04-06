# SPDX-License-Identifier: LGPL-2.1+

import shutil
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

from mkosi.backend import MkosiState, patch_file
from mkosi.distributions import DistributionInstaller
from mkosi.log import complete_step
from mkosi.run import run, run_with_apivfs
from mkosi.types import PathString


class OpensuseInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        return install_opensuse(state)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        zypper_install(state, packages)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        zypper_remove(state, packages)

    @staticmethod
    def initrd_path(kver: str) -> Path:
        return Path("boot") / f"initrd-{kver}"

    @staticmethod
    def repositories(state: MkosiState) -> Sequence[tuple[str, str]]:
        release = state.config.release
        if release == "leap":
            release = "stable"

        # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy
        # (14.x won't ever appear). For anything else, let's default to Leap.
        if release.isdigit() or release == "tumbleweed":
            release_url = f"{state.config.mirror}/tumbleweed/repo/oss/"
            updates_url = f"{state.config.mirror}/update/tumbleweed/"
        elif release in ("current", "stable"):
            release_url = f"{state.config.mirror}/distribution/openSUSE-stable/repo/oss/"
            updates_url = f"{state.config.mirror}/update/openSUSE-{release}/"
        else:
            release_url = f"{state.config.mirror}/distribution/leap/{release}/repo/oss/"
            updates_url = f"{state.config.mirror}/update/leap/{release}/oss/"

        return (("repo-oss", release_url), ("repo-update", updates_url))


def invoke_zypper(state: MkosiState,
                  global_opts: list[str],
                  verb: str,
                  verb_opts: list[str],
                  *args: PathString,
                  with_apivfs: bool = False) -> None:

    cmdline: list[PathString] = ["zypper", "--root", state.root, *global_opts, verb, *verb_opts, *args]
    env = dict(ZYPP_CONF=str(state.root / "etc/zypp/zypp.conf"), KERNEL_INSTALL_BYPASS="1")

    if with_apivfs:
        run_with_apivfs(state, cmdline, env=env)
    else:
        run(cmdline, env=env)


def zypper_init(state: MkosiState) -> None:
    if state.config.base_image is not None:
        return

    state.root.joinpath("etc/zypp").mkdir(mode=0o755, parents=True, exist_ok=True)

    # No matter if --root is used or not, zypper always considers its config
    # files from the host environment. If we want to use our custom versions for
    # the rootfs, we're left with two ways to specify them, depending on whether
    # we need to customize a setting defined in zypp.conf or in zypper.conf. If
    # it's in zypp.conf then the environment variable 'ZYPP_CONF' must be used
    # (!) otherwise a custom zypper.conf can be specified with the global option
    # '--config'.

    zypp_conf = state.root.joinpath("etc/zypp/zypp.conf")

    # For some reason zypper has no command line option to exclude the docs,
    # this can only be configured via zypp.conf.
    zypp_conf.write_text(
        dedent(
             f"""\
             [main]
             solver.onlyRequires = yes
             rpm.install.excludedocs = {"no" if state.config.with_docs else "yes"}
             """
        )
    )


def zypper_addrepo(state: MkosiState, url: str, name: str, caching: bool = False) -> None:
    invoke_zypper(state, [], "addrepo", ["--check", "--keep-packages" if caching else "--no-keep-packages"], url, name)


def zypper_removerepo(state: MkosiState, repo: str) -> None:
    invoke_zypper(state, [], "removerepo", [], repo)


def zypper_modifyrepo(state: MkosiState, repo: str, caching: bool) -> None:
    invoke_zypper(state, [], "modifyrepo", ["--keep-packages" if caching else "--no-keep-packages"], repo)


def zypper_init_repositories(state: MkosiState) -> None:
    # If we need to use a local mirror, create a temporary repository
    # definition, which is valid only at image build time. It will be removed
    # from the image and replaced with the final repositories at the end of the
    # installation process.
    #
    # We need to enable packages caching in any cases to make sure that the
    # package cache stays populated after "zypper install".

    if state.config.local_mirror:
        zypper_addrepo(state, state.config.local_mirror, "local-mirror", caching=True)
    else:
        for name, url in OpensuseInstaller.repositories(state):
            if state.config.base_image is None:
                zypper_addrepo(state, url, name, caching=True)
            else:
                zypper_modifyrepo(state, name, caching=True)


def zypper_finalize_repositories(state: MkosiState) -> None:
    if state.config.local_mirror:
        zypper_removerepo(state, "local-mirror")

    # Disable package caching in the image that was enabled previously to
    # populate mkosi package cache.
    for name, url in OpensuseInstaller.repositories(state):
        if state.config.local_mirror and state.config.base_image is None:
            zypper_addrepo(state, url, name)
        elif state.config.base_image is None:
            zypper_modifyrepo(state, name, caching=False)
        else:
            zypper_removerepo(state, name)


def zypper_install(state: MkosiState, packages: Sequence[str]) -> None:
    global_opts = [
        f"--cache-dir={state.cache}",
        "--gpg-auto-import-keys" if state.config.repository_key_check else "--no-gpg-checks",
    ]

    verb_opts = ["-y", "--download-in-advance"]

    invoke_zypper(state, global_opts, "install", verb_opts, *packages, with_apivfs=True)


def zypper_remove(state: MkosiState, packages: Sequence[str]) -> None:
    invoke_zypper(state, [], "remove", ["-y", "--clean-deps"], *packages, with_apivfs=True)


@complete_step("Installing openSUSE…")
def install_opensuse(state: MkosiState) -> None:

    zypper_init(state)
    zypper_init_repositories(state)

    zypper_install(state, ["filesystem", *state.config.packages])
    zypper_finalize_repositories(state)

    if state.config.base_image is not None:
        return

    if state.config.password == "":
        if not state.root.joinpath("etc/pam.d/common-auth").exists():
            for prefix in ("lib", "etc"):
                if state.root.joinpath(f"usr/{prefix}/pam.d/common-auth").exists():
                    shutil.copy2(state.root / f"usr/{prefix}/pam.d/common-auth", state.root / "etc/pam.d/common-auth")
                    break

        def jj(line: str) -> str:
            if "pam_unix.so" in line:
                return f"{line.strip()} nullok"
            return line

        patch_file(state.root / "etc/pam.d/common-auth", jj)
