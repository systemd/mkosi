# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import shutil
from collections.abc import Sequence
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.run import CompletedProcess, run, workdir
from mkosi.tree import rmtree
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
            "mkosi-install":   ["apk", "add", "--upgrade", "--cache-max-age", "999999999"],
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
            # apk requires SHA1 support for signature verification, and this is disabled in the default
            # crypto-policies for Fedora/RH/SuSE. This variable is set to re-enable SHA1 support on these
            # distributions.
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
        cls.invoke(
            context,
            "add",
            [
                "--initdb",
                "--upgrade",
                # effectively disable refreshing the cache in this situation
                "--cache-max-age", "999999999",
                *packages,
            ],
            apivfs=apivfs,
        )  # fmt: skip

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "del", packages, apivfs=True)

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        # Updating the cache requires an initialized apk database but we don't want to touch the image root
        # directory so temporarily replace it with an empty directory to make apk happy.
        saved = context.root.rename(context.workspace / "saved-root")
        context.root.mkdir()
        cls.invoke(context, "add", ["--initdb"])
        cls.invoke(context, "update", ["--update-cache"] if force else [])
        rmtree(context.root)
        saved.rename(context.root)

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

        # Generate temporary signing key using openssl
        # This uses the same method as abuild-keygen, because this tool is not available on all distros
        key_name = "mkosi@local-temp"
        priv_key = context.workspace / f"{key_name}.rsa"
        pub_key = context.workspace / f"{key_name}.rsa.pub"

        if not priv_key.exists():
            run(["openssl", "genrsa", "-out", str(priv_key), "2048"], env=cls.finalize_environment(context))
            run(
                ["openssl", "rsa", "-in", str(priv_key), "-pubout", "-out", str(pub_key)],
                env=cls.finalize_environment(context),
            )
            keys_dir = context.sandbox_tree / "etc/apk/keys"
            keys_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pub_key, keys_dir / pub_key.name)

        # Create index archive
        run(
            [
                "apk",
                "index",
                "-o", "APKINDEX.tar.gz",
                "--rewrite-arch", arch,
                # Note: "allow-untrusted" because pkgs may be signed by another key that might not be
                # available
                "--allow-untrusted",
                *packages,
            ],
            sandbox=context.sandbox(
                options=[
                    "--bind", context.repository, workdir(context.repository),
                    "--chdir", workdir(arch_dir),
                ]
            ),
        )  # fmt: skip

        # Create and sign index signature file
        # Note: The index signing stuff below was largely inspired by what abuild-sign and abuild-tar tools
        # do on Alpine Linux. These tools are not always packages for other distros.
        sig_file = arch_dir / f".SIGN.RSA.{pub_key.name}"
        run(
            [
                "openssl",
                "dgst",
                "-sha1",
                "-sign", str(priv_key),
                "-out", str(sig_file),
                str(arch_dir / "APKINDEX.tar.gz"),
            ],
            env=cls.finalize_environment(context),
        )  # fmt: skip

        # Create tar of signature, and strip EOF markers to allow concatenation with compressed index
        temp_tar = context.workspace / "sig.tar"
        with temp_tar.open("wb") as f:
            run(
                [
                    "tar", "-cf", "-",
                    "--format=posix",
                    "--owner=0",
                    "--group=0",
                    "--numeric-owner",
                    "-C", str(arch_dir),
                    sig_file.name,
                ],
                stdout=f,
            )  # fmt: skip

        tar_data = temp_tar.read_bytes()
        while tar_data.endswith(b"\x00" * 512):
            tar_data = tar_data[:-512]
        temp_tar.write_bytes(tar_data)

        # Prepend gzipped signature to original index
        index_file = arch_dir / "APKINDEX.tar.gz"
        temp_signed = context.workspace / "signed.tar.gz"
        with temp_signed.open("wb") as out:
            run(["gzip", "-n", "-9", "-c", str(temp_tar)], stdout=out)
            out.write(index_file.read_bytes())

        # Finally, overwrite the original index archive with the signed index archive
        temp_signed.replace(index_file)

        repos = context.sandbox_tree / "etc/apk/repositories"
        local_repo = "file:///repository/"
        if repos.exists():
            content = repos.read_text()
            if local_repo not in content:
                with repos.open("a") as f:
                    f.write(f"{local_repo}\n")
        else:
            repos.write_text(f"{local_repo}\n")

        cls.sync(context, force=True)

    @classmethod
    def keyring(cls, context: Context) -> None:
        pass
