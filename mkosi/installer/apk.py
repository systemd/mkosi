# SPDX-License-Identifier: LGPL-2.1-or-later
import shutil
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.log import ARG_DEBUG
from mkosi.run import (
    CompletedProcess,
    exists_in_sandbox,
    run,
)
from mkosi.util import _FILE, PathString


class Apk(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "apk"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("apk")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        return []

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "apk": cls.apivfs_script_cmd(context) + cls.env_cmd(context) + cls.cmd(context),
            "mkosi-install":   ["apk", "add"],
            "mkosi-upgrade":   ["apk", "upgrade"],
            "mkosi-remove":    ["apk", "del"],
            "mkosi-reinstall": ["apk", "fix"],
        }  # fmt: skip

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        return [
            *super().mounts(context),
            "--bind",
            context.config.package_cache_dir_or_default() / "cache/apk",
            "/buildroot/etc/apk/cache",
        ]

    @classmethod
    def setup(
        cls,
        context: Context,
        repositories: Sequence[str],
        filelists: bool = True,
        metadata_expire: Optional[str] = None,
    ) -> None:
        (context.sandbox_tree / "etc/resolv.conf").touch()

        (context.sandbox_tree / "etc/apk/repositories.d").mkdir(parents=True, exist_ok=True)

        path = context.sandbox_tree / "etc/apk/repositories"
        if not path.exists():
            with path.open("w") as f:
                for repo in repositories:
                    f.write(f"{repo}\n")

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        return super().finalize_environment(context)

    @classmethod
    def cmd(
        cls,
        context: Context,
    ) -> list[PathString]:
        apk = cls.executable(context.config)

        cmdline: list[PathString] = [
            apk,
            "--root=/buildroot",
            "--no-interactive",
            f"--arch={context.config.distribution.architecture(context.config.architecture)}",
            "--repositories-file=/etc/apk/repositories",
        ]

        # When --root= is specified, repositories file in the specified root will be read by default, but we
        # would like to avoid copying the file into the root directory. However, when --repositories-file= is
        # specified, repositories.d directories will not be read. Hence, we need to pass the additional
        # repositories through the command line.
        for p in (context.sandbox_tree / "etc/apk/repositories.d").glob("*.list"):
            with p.open("r") as f:
                for line in f:
                    cmdline += [f"--repository={line.strip()}"]

        if ARG_DEBUG.get() or True:
            cmdline += ["--verbose"]

        if not context.config.repository_key_check:
            cmdline += ["--allow-untrusted"]

        return cmdline

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        arguments: Sequence[str] = (),
        *,
        options: Sequence[str] = (),
        apivfs: bool = False,
        stdout: _FILE = None,
        cached_metadata: bool = True,
    ) -> CompletedProcess:
        return run(
            cls.cmd(context) + [*options, operation, *arguments],
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
        arguments = ["--upgrade"]
        if not exists_in_sandbox(
            "/buildroot/lib/apk/db/installed",
            sandbox=cls.sandbox(context, apivfs=True),
        ):
            arguments += ["--initdb"]

        arguments += [*packages]
        cls.invoke(context, "add", arguments, apivfs=apivfs)

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "del", packages, apivfs=True)

    @classmethod
    def sync(cls, context: Context, force: bool, arguments: Sequence[str] = ()) -> None:
        if exists_in_sandbox(
            "/buildroot/lib/apk/db/installed",
            sandbox=cls.sandbox(context, apivfs=True),
        ):
            cls.invoke(context, "update", apivfs=True)

    @classmethod
    def createrepo(cls, context: Context) -> None:
        # Assume context.repository / name / arch / APKINDEX.tar.gz, and each repository has
        # name-keys.apk that contains public key for the repository.
        packages = []
        arch = context.config.distribution.architecture(context.config.architecture)
        for repo in context.repository.iterdir():
            if not (repo / arch / "APKINDEX.tar.gz").exists():
                continue

            name = repo.name

            # Create repository file.
            path = context.sandbox_tree / f"etc/apk/repositories.d/{name}.list"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w") as f:
                f.write(f"file:///repository/{name}\n")

            packages += [f"{name}-keys"]

        # Install key files if necessary.
        if context.config.repository_key_check:
            cls.install(context, ["--allow-untrusted"] + packages)

    @classmethod
    def package_globs(cls) -> list[str]:
        return ["**/*.apk"]

    @classmethod
    def install_package_directories(cls, context: Context, directories: Sequence[Path]) -> None:
        # Assume d / name / arch / APKINDEX.tar.gz
        arch = context.config.distribution.architecture(context.config.architecture)
        for d in directories:
            for repo in d.iterdir():
                if not (repo / arch / "APKINDEX.tar.gz").exists():
                    continue

                name = repo.name
                shutil.rmtree(context.repository / name, ignore_errors=True)
                shutil.copytree(
                    repo, context.repository / name, copy_function=shutil.copy, dirs_exist_ok=True
                )
