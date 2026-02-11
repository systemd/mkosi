# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distribution import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.apk import Apk, ApkRepository
from mkosi.log import complete_step, die
from mkosi.util import copyfile


class Installer(DistributionInstaller, distribution=Distribution.postmarketos):
    _default_release = "edge"
    _releasemap = {"edge": ("9999", "edge")}

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
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.postmarketos

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        return Apk

    @classmethod
    def setup(cls, context: Context) -> None:
        with complete_step("Setting up postmarketOS keyring"):
            keys = context.sandbox_tree / "etc/apk/keys"
            keys.mkdir(parents=True, exist_ok=True)

            for d in [
                context.config.tools() / "usr/lib/apk/keys",
                context.config.tools() / "usr/share/distribution-gpg-keys/alpine-linux",
                context.config.tools() / "usr/share/distribution-gpg-keys/postmarketos",
            ]:
                if not d.exists():
                    continue

                # Do not overwrite keys in /etc/apk/keys to make sure that user provided keys take priority.
                for key in d.iterdir():
                    if key.is_dir():
                        continue

                    dest = keys / key.name
                    if dest.exists():
                        continue

                    copyfile(key, dest)

        Apk.setup(context, list(cls.repositories(context)))

    @classmethod
    def install(cls, context: Context) -> None:
        # TODO: Create merged /usr manually for now until our upstream (Alpine Linux) supports it:
        # https://gitlab.alpinelinux.org/alpine/aports/-/merge_requests/85504
        for dir in ["lib", "bin", "sbin"]:
            (context.root / "usr" / dir).mkdir(parents=True, exist_ok=True)
            (context.root / dir).symlink_to(f"usr/{dir}")

        cls.install_packages(context, ["postmarketos-baselayout", "postmarketos-release"], apivfs=False)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[ApkRepository]:
        if context.config.release != "edge":
            die(f"Only 'edge' release is currently supported, got '{context.config.release}'")

        if context.config.local_mirror:
            yield ApkRepository(url=context.config.local_mirror)
            return

        # Alpine repos
        # Note: "testing" is enabled here because it's also enabled by default when pmbootstrap builds pmOS
        # images, sometimes pmOS pkgs temporarily depend on things in testing.
        for repo_name in ["main", "community", "testing"]:
            yield ApkRepository(
                url=f"https://dl-cdn.alpinelinux.org/alpine/{context.config.release}/{repo_name}"
            )

        # postmarketOS repos
        mirror = context.config.mirror or "https://mirror.postmarketos.org/postmarketos"
        subdir = "master" if context.config.release == "edge" else f"v{context.config.release}"

        yield ApkRepository(url=f"{mirror}/extra-repos/systemd/{subdir}")
        yield ApkRepository(url=f"{mirror}/{subdir}")

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "x86_64",
            Architecture.arm64:  "aarch64",
            Architecture.arm:    "armv7",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by postmarketOS")

        return a

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        if not package.startswith("linux-"):
            return False

        if package.endswith(("-doc", "-dev", "-manual")):
            return False

        # These pkgs end with many different things
        if package.startswith(("linux-tools-", "linux-firmware-")):
            return False

        if package in {
            "linux-timemachine",
            "linux-headers",
            "linux-apfs-rw-src",
        }:
            return False

        return True
