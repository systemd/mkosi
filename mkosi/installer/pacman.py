# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NamedTuple

from mkosi.context import Context
from mkosi.installer import finalize_package_manager_mounts
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import PathString
from mkosi.user import INVOKING_USER
from mkosi.util import sort_packages, umask
from mkosi.versioncomp import GenericVersion


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

    INVOKING_USER.mkdir(context.config.package_cache_dir_or_default() / "pacman/pkg")

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
        "--cachedir=/var/cache/pacman/pkg",
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
                        *finalize_package_manager_mounts(context),
                        *sources,
                        "--chdir", "/work/src",
                    ],
                ) + (apivfs_cmd(context.root) if apivfs else [])
            ),
            env=context.config.environment,
        )


def createrepo_pacman(context: Context, *, force: bool = False) -> None:
    run(
        [
            "repo-add",
            context.packages / "mkosi-packages.db.tar",
            *sorted(context.packages.glob("*.pkg.tar*"), key=lambda p: GenericVersion(Path(p).name)),
        ]
    )


def localrepo_pacman() -> PacmanRepository:
    return PacmanRepository(id="mkosi-packages", url="file:///work/packages")
