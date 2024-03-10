# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable
from pathlib import Path

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.apk import Apk, ApkRepository
from mkosi.log import complete_step, die
from mkosi.run import exists_in_sandbox
from mkosi.tree import copy_tree


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "postmarketOS"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.apk

    @classmethod
    def default_release(cls) -> str:
        return "edge"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.postmarketos

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        return Apk

    @classmethod
    def setup(cls, context: Context) -> None:
        Apk.setup(context, list(cls.repositories(context)))
        cls.keyring(context)

    @classmethod
    def install(cls, context: Context) -> None:
        # Create merged /usr manually for now until our upstream (Alpine Linux) supports it:
        # https://gitlab.alpinelinux.org/alpine/aports/-/merge_requests/85504
        for dir in ["lib", "bin", "sbin"]:
            (context.root / "usr" / dir).mkdir(parents=True, exist_ok=True)
            (context.root / dir).symlink_to(f"usr/{dir}")
        Apk.install(
            context,
            [
                "postmarketos-baselayout",
                "postmarketos-release",
            ],
            apivfs=False,
        )

    @classmethod
    def repositories(cls, context: Context) -> Iterable[ApkRepository]:
        if context.config.local_mirror:
            yield ApkRepository(
                id="local-mirror",
                base_url=context.config.local_mirror,
                repo_type="postmarketos",
                release=context.config.release,
            )
            return

        # Alpine repos
        alpine_mirror = "https://dl-cdn.alpinelinux.org/alpine"
        for repo_name in ["main", "community", "testing"]:
            yield ApkRepository(
                id=f"alpine-{repo_name}",
                base_url=alpine_mirror,
                repo_type="alpine",
                release=context.config.release,
                repo_name=repo_name,
            )

        # postmarketOS repos
        mirror = context.config.mirror or "https://mirror.postmarketos.org/postmarketos"
        yield ApkRepository(
            id="postmarketos-systemd",
            base_url=mirror,
            repo_type="postmarketos",
            release=context.config.release,
            repo_name="extra-repos/systemd",
        )
        yield ApkRepository(
            id="postmarketos-main", base_url=mirror, repo_type="postmarketos", release=context.config.release
        )

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "x86_64",
            Architecture.arm64:  "aarch64",
            Architecture.arm:    "armv7h",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by postmarketOS")

        return a

    @classmethod
    def keyring(cls, context: Context) -> None:
        if not context.config.repository_key_check:
            return

        with complete_step("Setting up postmarketOS keyring"):
            # Check if distribution-gpg-keys directories exist
            alpine_keys_dir = Path("/usr/share/distribution-gpg-keys/alpine-linux")
            pmos_keys_dir = Path("/usr/share/distribution-gpg-keys/postmarketos")

            if not exists_in_sandbox(alpine_keys_dir, sandbox=context.sandbox()):
                die(
                    f"Alpine Linux GPG keys not found in sandbox at {alpine_keys_dir}",
                    hint="Make sure the distribution-gpg-keys package is installed",
                )

            if not exists_in_sandbox(pmos_keys_dir, sandbox=context.sandbox()):
                die(
                    f"postmarketOS GPG keys not found in sandbox at {pmos_keys_dir}",
                    hint="Make sure the distribution-gpg-keys package is installed",
                )

            (context.root / "usr/lib/apk/keys").mkdir(parents=True, exist_ok=True)
            copy_tree(
                alpine_keys_dir,
                context.root / "usr/lib/apk/keys",
                sandbox=context.sandbox,
            )
            copy_tree(
                pmos_keys_dir,
                context.root / "usr/lib/apk/keys",
                sandbox=context.sandbox,
            )
