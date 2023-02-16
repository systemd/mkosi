# SPDX-License-Identifier: LGPL-2.1+

import shutil
from collections.abc import Iterable
from pathlib import Path
from textwrap import dedent

from mkosi.backend import MkosiState, add_packages, patch_file
from mkosi.distributions import DistributionInstaller
from mkosi.log import complete_step
from mkosi.run import run, run_with_apivfs
from mkosi.types import PathString


class OpensuseInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> list[str]:
        return ["var/cache/zypp/packages"]

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        if state.config.base_image:
            # We assume that the base image has been properly initialized and it
            # contains all the metadata we need to install the additional
            # packages.
            return zypper_install(state, {*state.config.packages})

        return install_opensuse(state)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: list[str]) -> None:
        zypper_remove(state, packages)

    @staticmethod
    def initrd_path(kver: str) -> Path:
        return Path("boot") / f"initrd-{kver}"


def invoke_zypper(state: MkosiState,
                  global_opts: list[str],
                  verb: str,
                  verb_opts: list[str],
                  *args: PathString,
                  with_apivfs: bool = False) -> None:

    cmdline: list[PathString] = ["zypper", "--root", state.root, *global_opts, verb, *verb_opts, *args]
    env={"ZYPP_CONF": state.root.joinpath("etc/zypp/zypp.conf")}

    if with_apivfs:
        run_with_apivfs(state, cmdline, env=env)
    else:
        run(cmdline, env=env)


def zypper_init(state: MkosiState) -> None:
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


def zypper_install(state: MkosiState, packages: Iterable[str]) -> None:
    global_opts = [
        f"--cache-dir={state.cache}",
        "--gpg-auto-import-keys" if state.config.repository_key_check else "--no-gpg-checks",
    ]

    verb_opts = ["-y", "--download-in-advance"]

    invoke_zypper(state, global_opts, "install", verb_opts, *packages, with_apivfs=True)


def zypper_remove(state: MkosiState, packages: Iterable[str]) -> None:
    invoke_zypper(state, [], "remove", ["-y", "--clean-deps"], *packages, with_apivfs=True)


@complete_step("Installing openSUSE…")
def install_opensuse(state: MkosiState) -> None:
    release = state.config.release.strip('"')

    # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy (14.x won't ever appear). For
    # anything else, let's default to Leap.
    if release.isdigit() or release == "tumbleweed":
        release_url = f"{state.config.mirror}/tumbleweed/repo/oss/"
        updates_url = f"{state.config.mirror}/update/tumbleweed/"
    elif release == "leap":
        release_url = f"{state.config.mirror}/distribution/leap/15.1/repo/oss/"
        updates_url = f"{state.config.mirror}/update/leap/15.1/oss/"
    elif release == "current":
        release_url = f"{state.config.mirror}/distribution/openSUSE-stable/repo/oss/"
        updates_url = f"{state.config.mirror}/update/openSUSE-current/"
    elif release == "stable":
        release_url = f"{state.config.mirror}/distribution/openSUSE-stable/repo/oss/"
        updates_url = f"{state.config.mirror}/update/openSUSE-stable/"
    else:
        release_url = f"{state.config.mirror}/distribution/leap/{release}/repo/oss/"
        updates_url = f"{state.config.mirror}/update/leap/{release}/oss/"

    zypper_init(state)

    # If we need to use a local mirror, create a temporary repository
    # definition, which is valid only at image build time. It will be removed
    # from the image and replaced with the final repositories at the end of the
    # installation process.
    #
    # We need to enable packages caching in any cases to make sure that the package
    # cache stays populated after "zypper install".

    if state.config.local_mirror:
        zypper_addrepo(state, state.config.local_mirror, "local-mirror", caching=True)
    else:
        zypper_addrepo(state, release_url, "repo-oss", caching=True)
        zypper_addrepo(state, updates_url, "repo-update", caching=True)

    packages = {*state.config.packages}
    add_packages(state.config, packages, "systemd", "glibc-locale-base", "zypper")

    if release.startswith("42."):
        add_packages(state.config, packages, "patterns-openSUSE-minimal_base")
    else:
        add_packages(state.config, packages, "patterns-base-minimal_base")

    if not state.do_run_build_script and state.config.bootable:
        add_packages(state.config, packages, "kernel-default", "dracut")

    if state.config.netdev:
        add_packages(state.config, packages, "systemd-network")

    if state.do_run_build_script:
        packages.update(state.config.build_packages)

    if not state.do_run_build_script and state.config.ssh:
        add_packages(state.config, packages, "openssh-server")

    zypper_install(state, packages)

    if state.config.local_mirror:
        zypper_removerepo(state, "local-mirror")
        zypper_addrepo(state, release_url, "repo-oss")
        zypper_addrepo(state, updates_url, "repo-update")
    else:
        # Disable package caching in the image that was enabled previously to
        # populate mkosi package cache.
        zypper_modifyrepo(state, "repo-oss", caching=False)
        zypper_modifyrepo(state, "repo-update", caching=False)

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

    if state.config.autologin:
        # copy now, patch later (in configure_autologin())
        if not state.root.joinpath("etc/pam.d/login").exists():
            for prefix in ("lib", "etc"):
                if state.root.joinpath(f"usr/{prefix}/pam.d/login").exists():
                    shutil.copy2(state.root / f"usr/{prefix}/pam.d/login", state.root / "etc/pam.d/login")
                    break

    if state.config.bootable and not state.do_run_build_script:
        dracut_dir = state.root / "etc/dracut.conf.d"
        dracut_dir.mkdir(mode=0o755, exist_ok=True)

        dracut_dir.joinpath("30-mkosi-opensuse.conf").write_text('hostonly=no\n')
