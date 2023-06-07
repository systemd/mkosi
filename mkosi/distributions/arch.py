# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from textwrap import dedent

from mkosi.architecture import Architecture
from mkosi.config import ConfigFeature
from mkosi.distributions import DistributionInstaller
from mkosi.log import die
from mkosi.run import bwrap
from mkosi.state import MkosiState
from mkosi.types import PathString
from mkosi.util import sort_packages


class ArchInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        assert state.config.mirror

        if state.config.local_mirror:
            server = f"Server = {state.config.local_mirror}"
        else:
            if state.config.architecture == Architecture.arm64:
                server = f"Server = {state.config.mirror}/$arch/$repo"
            else:
                server = f"Server = {state.config.mirror}/$repo/os/$arch"

        # Create base layout for pacman and pacman-key
        state.root.joinpath("var/lib/pacman").mkdir(mode=0o755, exist_ok=True, parents=True)

        pacman_conf = state.workspace / "pkgmngr/etc/pacman.conf"
        pacman_conf.parent.mkdir(mode=0o755, exist_ok=True, parents=True)

        if state.config.repository_key_check:
            sig_level = "Required DatabaseOptional"
        else:
            # If we are using a single local mirror built on the fly there
            # will be no signatures
            sig_level = "Never"

        with pacman_conf.open("w") as f:
            f.write(
                dedent(
                    f"""\
                    [options]
                    RootDir = {state.root}
                    LogFile = /dev/null
                    CacheDir = {state.cache_dir}
                    GPGDir = /etc/pacman.d/gnupg/
                    HookDir = {state.root}/etc/pacman.d/hooks/
                    HoldPkg = pacman glibc
                    Architecture = {state.installer.architecture(state.config.architecture)}
                    Color
                    CheckSpace
                    SigLevel = {sig_level}
                    ParallelDownloads = 5

                    [core]
                    {server}
                    """
                )
            )

            if not state.config.local_mirror:
                f.write(
                    dedent(
                        f"""\

                        [extra]
                        {server}

                        [community]
                        {server}
                        """
                    )
                )

            if state.workspace.joinpath("pkgmngr/etc/pacman.d/conf/").glob("*"):
                f.write(
                    dedent(
                        f"""\

                        Include = {state.workspace}/pkgmngr/etc/pacman.d/conf/*
                        """
                    )
                )

        return invoke_pacman(state, packages, apivfs=apivfs)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Arch Linux")

        return a


def invoke_pacman(state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
    cmdline: list[PathString] = [
        "pacman",
        "--config", state.workspace / "pkgmngr/etc/pacman.conf",
        "--noconfirm",
        "--needed",
        "-Sy", *sort_packages(packages),
    ]

    # If we're generating a bootable image, we'll do so with a prebuilt initramfs, so no need for an
    # initramfs generator.
    if state.config.bootable != ConfigFeature.disabled:
        cmdline += ["--assume-installed", "initramfs"]

    bwrap(cmdline, apivfs=state.root if apivfs else None, env=dict(KERNEL_INSTALL_BYPASS="1") | state.environment)
