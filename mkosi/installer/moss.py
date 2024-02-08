# SPDX-License-Identifier: LGPL-2.1+

import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NamedTuple

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.mounts import finalize_source_mounts
from mkosi.run import find_binary, run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import PathString
from mkosi.util import sort_packages


def _moss_cache_dir(context: Context) -> Path:
    moss_cache_dir = context.config.package_cache_dir_or_default() / "moss"
    return moss_cache_dir


class Moss(PackageManager):
    class Repository(NamedTuple):
        id: str
        description: str
        uri: str
        priority: int

    @classmethod
    def executable(cls, config: Config) -> str:
        # Allow the user to override autodetection with an environment variable
        moss = config.environment.get("MKOSI_MOSS")
        root = config.tools()

        return Path(moss or find_binary("moss", root=root) or "moss").name

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("moss")

    @classmethod
    def cache_subdirs(cls, cache: Path) -> list[Path]:
        return [
            p / "moss"
            for p in cache.iterdir()
            if p.is_dir() and "-" in p.name and "mkosi" not in p.name
        ]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "moss": apivfs_cmd(context.root) + cls.cmd(context),
            "mkosi-install": ["moss", "install"],
            "mkosi-upgrade": ["moss", "sync"],
            "mkosi-remove": ["moss", "remove"],
        }

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        return [
            *super().mounts(context),
            # Moss has all its cache in `,moss/cache`, mount that from the outside
            "--bind",
            _moss_cache_dir(context),
            Path("/.moss/cache"),
        ]

    @classmethod
    def setup(cls, context: Context, repositories: Iterable[Repository]) -> None:
        # Create custom cache dir for moss
        moss_cache_dir = _moss_cache_dir(context)
        moss_cache_dir.mkdir(exist_ok=True)
        (context.root / ".moss").mkdir(exist_ok=True)
        (context.root / ".moss" / "cache").mkdir(exist_ok=True)

        for repo in repositories:
            cls.invoke(
                context,
                "repo",
                [
                    "add",
                    "-c",
                    repo.description,
                    "-p",
                    f"{repo.priority}",
                    repo.id,
                    repo.uri,
                ],
            )

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        moss = cls.executable(context.config)
        return [
            moss,
            "--directory",
            context.root,
            "--yes-all",
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
        with finalize_source_mounts(
            context.config,
            ephemeral=os.getuid() == 0 and context.config.build_sources_ephemeral,
        ) as sources:
            run(
                cls.cmd(context) + [operation, *options, *sort_packages(packages)],
                sandbox=(
                    context.sandbox(
                        network=True,
                        options=[
                            "--bind",
                            context.root,
                            context.root,
                            *cls.mounts(context),
                            *sources,
                            "--chdir",
                            "/work/src",
                        ],
                    )
                    + (apivfs_cmd(context.root) if apivfs else [])
                ),
                env=context.config.environment,
            )
