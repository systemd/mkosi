# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Iterable, Sequence
from typing import NamedTuple

from mkosi.bubblewrap import apivfs_cmd, bwrap
from mkosi.state import MkosiState
from mkosi.types import PathString
from mkosi.util import sort_packages, umask


class PacmanRepository(NamedTuple):
    id: str
    url: str


def setup_pacman(state: MkosiState, repositories: Iterable[PacmanRepository]) -> None:
    if state.config.repository_key_check:
        sig_level = "Required DatabaseOptional"
    else:
        # If we are using a single local mirror built on the fly there
        # will be no signatures
        sig_level = "Never"

    # Create base layout for pacman and pacman-key
    with umask(~0o755):
        (state.root / "var/lib/pacman").mkdir(exist_ok=True, parents=True)

    (state.cache_dir / "cache/pacman/pkg").mkdir(parents=True, exist_ok=True)

    config = state.pkgmngr / "etc/pacman.conf"
    if config.exists():
        return

    config.parent.mkdir(exist_ok=True, parents=True)

    with config.open("w") as f:
        f.write(
            textwrap.dedent(
                f"""\
                [options]
                SigLevel = {sig_level}
                LocalFileSigLevel = Optional
                ParallelDownloads = 5
                """
            )
        )

        for repo in repositories:
            f.write(
                textwrap.dedent(
                    f"""\

                    [{repo.id}]
                    Server = {repo.url}
                    """
                )
            )

        if any((state.pkgmngr / "etc/pacman.d/").glob("*.conf")):
            f.write(
                textwrap.dedent(
                    """\

                    Include = /etc/pacman.d/*.conf
                    """
                )
            )


def pacman_cmd(state: MkosiState) -> list[PathString]:
    return [
        "pacman",
        "--root", state.root,
        "--logfile=/dev/null",
        "--cachedir", state.cache_dir / "cache/pacman/pkg",
        "--hookdir", state.root / "etc/pacman.d/hooks",
        "--arch", state.config.distribution.architecture(state.config.architecture),
        "--color", "auto",
        "--noconfirm",
    ]


def invoke_pacman(
    state: MkosiState,
    operation: str,
    options: Sequence[str] = (),
    packages: Sequence[str] = (),
    apivfs: bool = True,
) -> None:
    cmd = apivfs_cmd(state.root) if apivfs else []
    bwrap(state, cmd + pacman_cmd(state) + [operation, *options, *sort_packages(packages)],
          network=True, env=state.config.environment)
