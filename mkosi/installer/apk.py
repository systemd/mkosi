# SPDX-License-Identifier: LGPL-2.1+
import os
import shutil
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NamedTuple

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.mounts import finalize_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import _FILE, CompletedProcess, PathString
from mkosi.util import umask
from mkosi.versioncomp import GenericVersion


class Apk(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "apk"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("apk")

    @classmethod
    def cache_subdirs(cls, cache: Path) -> list[Path]:
        return [cache / "apk"]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "apk": apivfs_cmd(context.root) + cls.cmd(context),
            "mkosi-install"  : ["apk", "--update-cache", "add"],
            "mkosi-upgrade"  : ["apk", "--update-cache", "upgrade"],
            "mkosi-remove"   : ["apk", "--remove", "del"],
            "mkosi-reinstall": ["apk", "--update-cache", "fix"],
        }

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        mounts: list[PathString] = [
            *super().mounts(context),
            # pacman writes downloaded packages to the first writable cache directory. We don't want it to write to our
            # local repository directory so we expose it as a read-only directory to pacman.
            "--ro-bind", context.packages, "/var/cache/apk",
        ]

        return mounts

    @classmethod
    def setup(cls, context: Context, repositories: Iterable[str]) -> None:
        config = context.root / "etc/apk/repositories"
        if config.exists():
            print("apk setup() repo file exists!")
            return

        config.parent.mkdir(exist_ok=True, parents=True)

        with config.open("w") as f:
            for repo in repositories:
                f.write(f"{repo}\n")

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        _cmd = [
            "apk",
            "--root", context.root,
            # Make sure pacman looks at our local repository first by putting it as the first cache directory. We mount
            # it read-only so the second directory will still be used for writing new cache entries.
            #"--cache-dir=" + str(context.root / "var/cache/apk/mkosi"),
            "--arch", context.config.distribution.architecture(context.config.architecture),
            "--no-interactive",
            "--update-cache",
        ]
        #if not context.config.repository_key_check:
        _cmd += ["--allow-untrusted"]
        return _cmd

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        arguments: Sequence[str] = (),
        *,
        apivfs: bool = False,
        stdout: _FILE = None,
    ) -> CompletedProcess:
        with finalize_source_mounts(
            context.config,
            ephemeral=os.getuid() == 0 and context.config.build_sources_ephemeral,
        ) as sources:
            return run(
                cls.cmd(context) + [operation, *arguments],
                sandbox=(
                    context.sandbox(
                        network=True,
                        options=[
                            "--bind", context.root, context.root,
                            *cls.mounts(context),
                            *sources,
                            "--chdir", "/work/src",
                            # pacman will fail unless invoked as root so make sure we're uid/gid 0 in the sandbox.
                            "--uid", "0",
                            "--gid", "0",
                        ],
                    ) + (apivfs_cmd(context.root) if apivfs else [])
                ),
                env=context.config.environment,
                stdout=stdout,
            )

    @classmethod
    def sync(cls, context: Context) -> None:
        if (context.root / "etc/apk/world").exists():
            cls.invoke(context, "update", [])

    @classmethod
    def createrepo(cls, context: Context) -> None:
        print("apk createrepo() called!")
        # run(
        #     [
        #         "repo-add",
        #         "--quiet",
        #         context.packages / "mkosi.db.tar",
        #         *sorted(context.packages.glob("*.pkg.tar*"), key=lambda p: GenericVersion(Path(p).name))
        #     ],
        #     sandbox=context.sandbox(options=["--bind", context.packages, context.packages]),
        # )

        # # pacman can't sync a single repository, so we go behind its back and do it ourselves.
        # shutil.move(
        #     context.packages / "mkosi.db.tar",
        #     context.package_cache_dir / "lib/pacman/sync/mkosi.db"
        # )
