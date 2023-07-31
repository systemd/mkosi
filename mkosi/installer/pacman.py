# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Sequence
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.config import ConfigFeature
from mkosi.run import bwrap
from mkosi.state import MkosiState
from mkosi.util import sort_packages


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
    if config.exists():
        return

    config.parent.mkdir(mode=0o755, exist_ok=True, parents=True)

    repos = []

    # Testing repositories have to go before regular ones to to take precedence.
    if not state.config.local_mirror:
        for repo in ("core-testing", "extra-testing"):
            if repo in state.config.repositories:
                repos += [repo]

    repos += ["core"]
    if not state.config.local_mirror:
        repos += ["extra"]

    with config.open("w") as f:
        f.write(
            textwrap.dedent(
                f"""\
                [options]
                SigLevel = {sig_level}
                ParallelDownloads = 5
                """
            )
        )

        for repo in repos:
            f.write(
                textwrap.dedent(
                    f"""\

                    [{repo}]
                    {server}
                    """
                )
            )

        if any(state.pkgmngr.joinpath("etc/pacman.d/").glob("*.conf")):
            f.write(
                textwrap.dedent(
                    f"""\

                    Include = {state.pkgmngr}/etc/pacman.d/*.conf
                    """
                )
            )


def pacman_cmd(state: MkosiState) -> list[str]:
    gpgdir = state.pkgmngr / "etc/pacman.d/gnupg/"
    gpgdir = gpgdir if gpgdir.exists() else Path("/etc/pacman.d/gnupg/")

    cmdline = [
        "pacman",
        f"--config={state.pkgmngr / 'etc/pacman.conf'}",
        f"--root={state.root}",
        "--logfile=/dev/null",
        f"--cachedir={state.cache_dir}",
        f"--gpgdir={gpgdir}",
        f"--hookdir={state.root / 'etc/pacman.d/hooks'}",
        f"--arch={state.installer.architecture(state.config.architecture)}",
        "--color", "auto",
        "--noconfirm",
        "--needed",
    ]

    # If we're generating a bootable image, we'll do so with a prebuilt initramfs, so no need for an
    # initramfs generator.
    if state.config.bootable != ConfigFeature.disabled:
        cmdline += ["--assume-installed", "initramfs"]

    return cmdline


def invoke_pacman(state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
    bwrap(pacman_cmd(state) + ["-Sy"] + sort_packages(packages),
          apivfs=state.root if apivfs else None,
          env=state.config.environment)
