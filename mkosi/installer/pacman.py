# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Iterable, Sequence
from typing import NamedTuple

from mkosi.context import Context
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd, finalize_crypto_mounts
from mkosi.types import PathString
from mkosi.util import sort_packages, umask


class PacmanRepository(NamedTuple):
    id: str
    url: str


def setup_pacman(context: Context, repositories: Iterable[PacmanRepository]) -> None:
    if context.config.repository_key_check:
        sig_level = "Required DatabaseOptional"
    else:
        # If we are using a single local mirror built on the fly there
        # will be no signatures
        sig_level = "Never"

    # Create base layout for pacman and pacman-key
    with umask(~0o755):
        (context.root / "var/lib/pacman").mkdir(exist_ok=True, parents=True)

    (context.cache_dir / "cache/pacman/pkg").mkdir(parents=True, exist_ok=True)

    config = context.pkgmngr / "etc/pacman.conf"
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

        if any((context.pkgmngr / "etc/pacman.d/").glob("*.conf")):
            f.write(
                textwrap.dedent(
                    """\

                    Include = /etc/pacman.d/*.conf
                    """
                )
            )


def pacman_cmd(context: Context) -> list[PathString]:
    return [
        "pacman",
        "--root", context.root,
        "--logfile=/dev/null",
        "--cachedir", context.cache_dir / "cache/pacman/pkg",
        "--hookdir", context.root / "etc/pacman.d/hooks",
        "--arch", context.config.distribution.architecture(context.config.architecture),
        "--color", "auto",
        "--noconfirm",
    ]


def invoke_pacman(
    context: Context,
    operation: str,
    options: Sequence[str] = (),
    packages: Sequence[str] = (),
    apivfs: bool = True,
) -> None:
    with finalize_ephemeral_source_mounts(context.config) as sources:
        run(
            pacman_cmd(context) + [operation, *options, *sort_packages(packages)],
            sandbox=(
                context.sandbox(
                    network=True,
                    options=[
                        "--bind", context.root, context.root,
                        "--bind", context.cache_dir / "cache/pacman/pkg", context.cache_dir / "cache/pacman/pkg",
                        *(["--ro-bind", m, m] if (m := context.config.local_mirror) else []),
                        *finalize_crypto_mounts(tools=context.config.tools()),
                        *sources,
                        "--chdir", "/work/src",
                    ],
                ) + (apivfs_cmd(context.root) if apivfs else [])
            ),
            env=context.config.environment,
        )
