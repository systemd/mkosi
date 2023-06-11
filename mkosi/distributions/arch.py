# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from pathlib import Path
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
        setup_pacman(state)
        invoke_pacman(state, packages, apivfs=apivfs)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Arch Linux")

        return a


def setup_pacman(state: MkosiState) -> None:
    assert state.config.mirror

    if state.config.local_mirror:
        server = f"Server = {state.config.local_mirror}"
    else:
        if state.config.architecture == Architecture.arm64:
            server = f"Server = {state.config.mirror}/$arch/$repo"
        else:
            server = f"Server = {state.config.mirror}/$repo/os/$arch"

    if state.config.repository_key_check:
        sig_level = "Required DatabaseOptional"
    else:
        # If we are using a single local mirror built on the fly there
        # will be no signatures
        sig_level = "Never"

    # Create base layout for pacman and pacman-key
    state.root.joinpath("var/lib/pacman").mkdir(mode=0o755, exist_ok=True, parents=True)

    config = state.pkgmngr / "etc/pacman.conf"
    config.parent.mkdir(mode=0o755, exist_ok=True, parents=True)

    with config.open("w") as f:
        f.write(
            dedent(
                f"""\
                [options]
                HoldPkg = pacman glibc
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
                    """
                )
            )

        if any(state.pkgmngr.joinpath("etc/pacman.d/").glob("*.conf")):
            f.write(
                dedent(
                    f"""\

                    Include = {state.pkgmngr}/etc/pacman.d/*.conf
                    """
                )
            )


def invoke_pacman(state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
    gpgdir = state.pkgmngr / "etc/pacman.d/gnupg/"
    gpgdir = gpgdir if gpgdir.exists() else Path("/etc/pacman.d/gnupg/")

    cmdline: list[PathString] = [
        "pacman",
        "--config", state.pkgmngr / "etc/pacman.conf",
        "--root", state.root,
        "--logfile", "/dev/null",
        "--cachedir", state.cache_dir,
        "--gpgdir", gpgdir,
        "--hookdir", state.root / "etc/pacman.d/hooks",
        "--arch",  state.installer.architecture(state.config.architecture),
        "--color", "auto",
        "--noconfirm",
        "--needed",
        "-Sy", *sort_packages(packages),
    ]

    # If we're generating a bootable image, we'll do so with a prebuilt initramfs, so no need for an
    # initramfs generator.
    if state.config.bootable != ConfigFeature.disabled:
        cmdline += ["--assume-installed", "initramfs"]

    bwrap(cmdline, apivfs=state.root if apivfs else None, env=dict(KERNEL_INSTALL_BYPASS="1") | state.environment)
