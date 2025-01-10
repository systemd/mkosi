# SPDX-License-Identifier: LGPL-2.1+
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.run import run
from mkosi.types import _FILE, CompletedProcess, PathString


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
            "apk": cls.apivfs_script_cmd(context) + cls.cmd(context),
            "mkosi-install":   ["apk", "--update-cache", "add"],
            "mkosi-upgrade":   ["apk", "--update-cache", "upgrade"],
            "mkosi-remove":    ["apk", "--remove", "del"],
            "mkosi-reinstall": ["apk", "--update-cache", "fix"],
        }  # fmt: skip

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        mounts: list[PathString] = [
            *super().mounts(context),
            # pacman writes downloaded packages to the first writable cache directory.
            # We don't want it to write to our local repository directory so we expose it
            # as a read-only directory to pacman.
            # "--ro-bind", context.packages, "/var/cache/apk",
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
        return [
            "apk",
            "--root", "/buildroot",
            # Make sure pacman looks at our local repository first by putting it as the first cache dir.
            # We mount it read-only so the second directory will still be used for writing new cache entries.
            #"--cache-dir=" + str(context.root / "var/cache/apk/mkosi"),
            "--cache-dir", "/var/cache/apk",
            "--arch", context.config.distribution.architecture(context.config.architecture),
            "--no-interactive",
            "--update-cache",
            *(["--allow-untrusted"] if not context.config.repository_key_check else []),
        ]  # fmt: skip

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
        return run(
            cls.cmd(context) + [operation, *arguments],
            sandbox=cls.sandbox(context, apivfs=apivfs),
            env=cls.finalize_environment(context),
            stdout=stdout,
        )

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        # TODO implement force
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
