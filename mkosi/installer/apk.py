# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.log import die
from mkosi.run import CompletedProcess, run, workdir
from mkosi.util import _FILE, PathString


@dataclasses.dataclass(frozen=True)
class ApkRepository:
    id: str
    base_url: str
    repo_type: str  # "alpine" or "postmarketos"
    release: str
    repo_name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.release != "edge":
            die(f"Only 'edge' release is currently supported, got '{self.release}'")

    @property
    def url(self) -> str:
        if self.repo_type == "alpine":
            return f"{self.base_url}/{self.release}/{self.repo_name}"
        elif self.repo_type == "postmarketos":
            release_path = f"v{self.release}"
            if self.release == "edge":
                release_path = "master"
            if self.repo_name is None:
                return f"{self.base_url}/{release_path}"
            else:
                return f"{self.base_url}/{self.repo_name}/{release_path}"
        else:
            raise ValueError(f"Unknown repo_type: {self.repo_type}")


class Apk(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "apk"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("apk")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        return [(Path("apk"), Path("apk"))]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "apk": cls.apivfs_script_cmd(context) + cls.cmd(context),
            "mkosi-install":   ["apk", "add"],
            "mkosi-upgrade":   ["apk", "upgrade"],
            "mkosi-remove":    ["apk", "--remove", "del"],
            "mkosi-reinstall": ["apk", "fix", "--reinstall"],
        }  # fmt: skip

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        mounts: list[PathString] = [
            *super().mounts(context),
        ]

        cache_dir = context.config.package_cache_dir_or_default() / "apk"
        cache_dir.mkdir(parents=True, exist_ok=True)
        mounts += ["--bind", cache_dir, "/var/cache/apk"]

        return mounts

    @classmethod
    def setup(cls, context: Context, repositories: Sequence[ApkRepository]) -> None:
        config = context.root / "etc/apk/repositories"
        if config.exists():
            return

        config.parent.mkdir(exist_ok=True, parents=True)

        with config.open("w") as f:
            for repo in repositories:
                f.write(f"{repo.url}\n")

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        return [
            "apk",
            "--root", "/buildroot",
            "--cache-dir", "/var/cache/apk",
            "--arch", context.config.distribution.architecture(context.config.architecture),
            "--no-interactive",
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
        allow_downgrade: bool = False,
    ) -> None:
        arguments = list(packages)
        # Initialize database if it doesn't exist
        db_dir = context.root / "usr/lib/apk/db"
        if not (db_dir / "installed").exists():
            arguments = ["--initdb"] + arguments
        cls.invoke(context, "add", arguments, apivfs=apivfs)

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "del", packages, apivfs=True)

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        # APK requires database initialization before update, skip if not initialized. Sync will happen
        # during initdb
        db_dir = context.root / "usr/lib/apk/db"
        if not (db_dir / "installed").exists():
            return
        arguments = ["--update-cache"] if force else []
        cls.invoke(context, "update", arguments)

    @classmethod
    def createrepo(cls, context: Context) -> None:
        apk_files = [p.name for p in context.repository.glob("*.apk")]
        if not apk_files:
            return

        # Move apk files to arch-specific directory
        arch = context.config.distribution.architecture(context.config.architecture)
        arch_dir = context.repository / arch
        arch_dir.mkdir(exist_ok=True)
        for apk_file in apk_files:
            (context.repository / apk_file).rename(arch_dir / apk_file)

        run(
            [
                "apk",
                "index",
                "-o",
                "APKINDEX.tar.gz",
                # rewrite-arch is needed to make sure noarch pkgs have the arch set so apk can find them in
                # the repo
                "--rewrite-arch",
                context.config.distribution.architecture(context.config.architecture),
                *(["--allow-untrusted"] if not context.config.repository_key_check else []),
                *apk_files,
            ],
            sandbox=context.sandbox(
                options=[
                    "--bind",
                    context.repository,
                    workdir(context.repository),
                    "--chdir",
                    workdir(context.repository / arch),
                ]
            ),
        )

        with (context.root / "etc/apk/repositories").open("a") as f:
            f.write("file:///repository/\n")

        cls.sync(context, force=True)

    @classmethod
    def keyring(cls, context: Context) -> None:
        pass
