# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.apk import Apk, ApkRepository
from mkosi.log import complete_step, die
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

        # TODO: Create merged /usr manually for now until our upstream (Alpine Linux) supports it:
        # https://gitlab.alpinelinux.org/alpine/aports/-/merge_requests/85504
        for dir in ["lib", "bin", "sbin"]:
            (context.root / "usr" / dir).mkdir(parents=True, exist_ok=True)
            (context.root / dir).symlink_to(f"usr/{dir}")

        with complete_step("Setting up postmarketOS keyring"):
            # Create keys directory in sandbox
            keys_dir = context.sandbox_tree / "etc/apk/keys"
            keys_dir.mkdir(parents=True, exist_ok=True)

            # Copy keys from various sources (if they exist)
            for d in [
                context.config.tools() / "usr/lib/apk/keys",
                context.config.tools() / "usr/share/distribution-gpg-keys/alpine-linux",
                context.config.tools() / "usr/share/distribution-gpg-keys/postmarketos",
            ]:
                if d.exists():
                    copy_tree(d, keys_dir, sandbox=context.sandbox)

    @classmethod
    def install(cls, context: Context) -> None:
        Apk.install(context, ["postmarketos-baselayout", "postmarketos-release"], apivfs=False)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[ApkRepository]:
        if context.config.release != "edge":
            die(f"Only 'edge' release is currently supported, got '{context.config.release}'")

        if context.config.local_mirror:
            yield ApkRepository(url=context.config.local_mirror)
            return

        # Alpine repos
        for repo_name in ["main", "community", "testing"]:
            yield ApkRepository(
                url=f"https://dl-cdn.alpinelinux.org/alpine/{context.config.release}/{repo_name}"
            )

        # postmarketOS repos
        mirror = context.config.mirror or "https://mirror.postmarketos.org/postmarketos"
        subdir = "master" if context.config.release == "edge" else f"v{context.config.release}"

        # systemd repo
        url = f"{mirror}/extra-repos/systemd/{subdir}"
        yield ApkRepository(url=url)

        # main repo
        url = f"{mirror}/{subdir}"
        yield ApkRepository(url=url)

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
