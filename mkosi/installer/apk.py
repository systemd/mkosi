# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
from collections.abc import Sequence
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.run import CompletedProcess, run, workdir
from mkosi.util import _FILE, PathString


@dataclasses.dataclass(frozen=True)
class ApkRepository:
    url: str


class Apk(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "apk"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("apk")

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "apk": cls.apivfs_script_cmd(context) + cls.env_cmd(context) + cls.cmd(context),
            "mkosi-install":   ["apk", "add"],
            "mkosi-upgrade":   ["apk", "upgrade"],
            "mkosi-remove":    ["apk", "--remove", "del"],
            "mkosi-reinstall": ["apk", "fix", "--reinstall"],
        }  # fmt: skip

    @classmethod
    def setup(cls, context: Context, repositories: Sequence[ApkRepository]) -> None:
        config = context.sandbox_tree / "etc/apk/repositories"
        if config.exists():
            return

        config.parent.mkdir(exist_ok=True, parents=True)

        config.write_text("\n".join(repo.url for repo in repositories) + "\n")

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        return super().finalize_environment(context) | {
            # Some package managers (e.g. apk) require SHA1 support for signature verification, and this is
            # disabled in the default crypto-policies for Fedora/RH/SuSE. This variable is set to re-enable
            # SHA1 support on this distributions so that mkosi can use these package managers.
            # Also see: https://gitlab.alpinelinux.org/alpine/apk-tools/-/issues/11139#note_542183
            "OPENSSL_ENABLE_SHA1_SIGNATURES": "1",
        }

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        return [
            "apk",
            "--root", "/buildroot",
            "--cache-dir", "/var/cache/apk",
            "--arch", context.config.distribution.architecture(context.config.architecture),
            "--no-interactive",
            "--preserve-env",
            "--cache-packages",
            "--keys-dir", "/etc/apk/keys",
            "--repositories-file", "/etc/apk/repositories",
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
        arguments = [
            "--initdb",
            "--upgrade",
            "--latest",
            # effectively disable refreshing the cache in this situation
            "--cache-max-age", "999999999",
            *packages,
        ]  # fmt: skip
        cls.invoke(context, "add", arguments, apivfs=apivfs)

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "del", packages, apivfs=True)

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        # Initialize database if it doesn't exist
        if not (context.root / "usr/lib/apk/db/installed").exists():
            cls.invoke(context, "add", ["--initdb"])

        arguments = ["--update-cache"] if force else []
        cls.invoke(context, "update", arguments)

    @classmethod
    def createrepo(cls, context: Context) -> None:
        packages = [p.name for p in context.repository.glob("*.apk")]
        if not packages:
            return

        # Move apk files to arch-specific directory
        arch = context.config.distribution.architecture(context.config.architecture)
        arch_dir = context.repository / arch
        arch_dir.mkdir(exist_ok=True)
        for package in packages:
            (context.repository / package).rename(arch_dir / package)

        run(
            [
                "apk",
                "index",
                "-o", "APKINDEX.tar.gz",
                # rewrite-arch is needed to make sure noarch pkgs have the arch set so apk can find them in
                # the repo
                "--rewrite-arch", context.config.distribution.architecture(context.config.architecture),
                *(["--allow-untrusted"] if not context.config.repository_key_check else []),
                *packages,
            ],
            sandbox=context.sandbox(
                options=[
                    "--bind", context.repository, workdir(context.repository),
                    "--chdir", workdir(context.repository / arch),
                ]
            ),
        )  # fmt: skip

        with (context.sandbox_tree / "etc/apk/repositories").open("a") as f:
            f.write("file:///repository/\n")

        cls.sync(context, force=True)

    @classmethod
    def keyring(cls, context: Context) -> None:
        pass
