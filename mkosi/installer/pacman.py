# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NamedTuple

from mkosi.context import Context
from mkosi.installer import PackageManager, finalize_package_manager_mounts
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import PathString
from mkosi.util import sort_packages, umask
from mkosi.versioncomp import GenericVersion


class Pacman(PackageManager):
    class Repository(NamedTuple):
        id: str
        url: str

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {"pacman": apivfs_cmd(context.root) + cls.cmd(context)}

    @classmethod
    def setup(cls, context: Context, repositories: Iterable[Repository]) -> None:
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

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
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

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        options: Sequence[str] = (),
        packages: Sequence[str] = (),
        apivfs: bool = True,
    ) -> None:
        with finalize_ephemeral_source_mounts(context.config) as sources:
            run(
                cls.cmd(context) + [operation, *options, *sort_packages(packages)],
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

    @classmethod
    def createrepo(cls, context: Context, *, force: bool = False) -> None:
        run(
            [
                "repo-add",
                context.packages / "mkosi-packages.db.tar",
                *sorted(context.packages.glob("*.pkg.tar*"), key=lambda p: GenericVersion(Path(p).name)),
            ]
        )

    @classmethod
    def localrepo(cls) -> Repository:
        return cls.Repository(id="mkosi-packages", url="file:///work/packages")
