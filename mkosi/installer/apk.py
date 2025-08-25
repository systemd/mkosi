# SPDX-License-Identifier: LGPL-2.1-or-later
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.run import run, CompletedProcess
from mkosi.util import _FILE, PathString


class Apk(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "apk"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("apk")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[Path]:
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
        ]

        mounts += ["--ro-bind", "/etc/apk/keys", "/etc/apk/keys"]

        cache_dir = context.config.package_cache_dir_or_default() / "apk"
        cache_dir.mkdir(parents=True, exist_ok=True)
        mounts += ["--bind", cache_dir, "/var/cache/apk"]

        return mounts

    @classmethod
    def setup(cls, context: Context, repositories: Iterable[str]) -> None:
        # Create cache symlink to enable automatic caching
        cache_link = context.root / "etc/apk/cache"
        if not cache_link.exists():
            cache_link.parent.mkdir(exist_ok=True, parents=True)
            cache_link.symlink_to("/var/cache/apk")

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
            "--keys-dir", "/etc/apk/keys",
            "--root", "/buildroot",
            # Make sure apk looks at our local repository first by putting it as the first cache dir.
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
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
    ) -> None:
        cls.invoke(context, "add", packages, apivfs=apivfs)

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "del", packages, apivfs=True)

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        # TODO implement force
        if (context.root / "etc/apk/world").exists():
            cls.invoke(context, "update", [])

    @classmethod
    def createrepo(cls, context: Context) -> None:
        # TODO: implement createrepo
        print("apk createrepo() called!")
