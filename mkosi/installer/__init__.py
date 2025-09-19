# SPDX-License-Identifier: LGPL-2.1-or-later

import itertools
import shutil
from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path

from mkosi.config import Config, ConfigFeature, OutputFormat
from mkosi.context import Context
from mkosi.mounts import finalize_certificate_mounts
from mkosi.run import apivfs_options, finalize_interpreter, finalize_passwd_symlinks, find_binary
from mkosi.tree import rmtree
from mkosi.util import PathString, flatten, startswith


class PackageManager:
    @classmethod
    def executable(cls, config: Config) -> str:
        return "custom"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("custom")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        return []

    @classmethod
    def state_subdirs(cls, state: Path) -> list[Path]:
        return []

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {}

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        env = {
            "HOME": "/",  # Make sure rpm doesn't pick up ~/.rpmmacros and ~/.rpmrc.
            # systemd's chroot detection doesn't work when unprivileged so tell it explicitly.
            "SYSTEMD_IN_CHROOT": "1",
        }

        if "SYSTEMD_HWDB_UPDATE_BYPASS" not in context.config.finalize_environment():
            env["SYSTEMD_HWDB_UPDATE_BYPASS"] = "1"

        if (
            "KERNEL_INSTALL_BYPASS" not in context.config.finalize_environment()
            and context.config.bootable != ConfigFeature.disabled
        ):
            env["KERNEL_INSTALL_BYPASS"] = "1"
        else:
            env |= {
                "BOOT_ROOT": "/boot",
                # Required to make 90-loaderentry.install put the right paths into the bootloader entry.
                "BOOT_MNT": "/boot",
                # Hack to tell dracut to not create a hostonly initrd when it's invoked by kernel-install.
                "hostonly_l": "no",
            }

        return context.config.finalize_environment() | env

    @classmethod
    def env_cmd(cls, context: Context) -> list[PathString]:
        return ["env", *([f"{k}={v}" for k, v in cls.finalize_environment(context).items()])]

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        mounts = [
            *finalize_certificate_mounts(context.config),
            "--bind", context.repository, "/repository",
        ]  # fmt: skip

        if context.config.local_mirror and (mirror := startswith(context.config.local_mirror, "file://")):
            mounts += ["--ro-bind", mirror, mirror]

        subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

        for d in ("cache", "lib"):
            src = context.metadata_dir / d / subdir
            mounts += ["--bind", src, Path("/var") / d / subdir]

            # If we're not operating on the configured package cache directory, we're operating on a snapshot
            # of the repository metadata. To make sure any downloaded packages are still cached in the
            # configured package cache directory in this scenario, we mount in the relevant directories from
            # the configured package cache directory.
            if d == "cache" and context.metadata_dir != context.config.package_cache_dir_or_default():
                caches = context.config.distribution.package_manager(context.config).package_subdirs(src)
                mounts += flatten(
                    (
                        "--bind",
                        context.config.package_cache_dir_or_default() / d / subdir / srcsubdir,
                        Path("/var") / d / subdir / dstsubdir,
                    )
                    for srcsubdir, dstsubdir in caches
                    if (context.config.package_cache_dir_or_default() / d / subdir / srcsubdir).exists()
                )

        return mounts

    @classmethod
    def options(cls, *, root: PathString, apivfs: bool = True) -> list[PathString]:
        return [
            *(apivfs_options() if apivfs else []),
            "--become-root",
            "--suppress-chown",
            "--suppress-sync",
            # Make sure /etc/machine-id is not overwritten by any package manager post install scripts.
            "--ro-bind-try", Path(root) / "etc/machine-id", "/buildroot/etc/machine-id",
            # Nudge gpg to create its sockets in /run by making sure /run/user/0 exists.
            "--dir", "/run/user/0",
            # Some package managers (e.g. dpkg) read from the host's /etc/passwd instead of the buildroot's
            # /etc/passwd so we symlink /etc/passwd from the buildroot to make sure it gets used.
            *(finalize_passwd_symlinks("/buildroot") if apivfs else []),
        ]  # fmt: skip

    @classmethod
    def apivfs_script_cmd(cls, context: Context) -> list[PathString]:
        return [
            finalize_interpreter(bool(context.config.tools_tree)), "-SI", "/sandbox.py",
            "--bind", "/", "/",
            "--same-dir",
            "--bind", "/var/tmp", "/buildroot/var/tmp",
            *apivfs_options(),
            *cls.options(root="/buildroot"),
        ]  # fmt: skip

    @classmethod
    def sandbox(
        cls,
        context: Context,
        *,
        apivfs: bool,
        options: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]:
        return context.sandbox(
            network=True,
            options=[
                *context.rootoptions(),
                *cls.mounts(context),
                *cls.options(root=context.root, apivfs=apivfs),
                *options,
            ],
        )  # fmt: skip

    @classmethod
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        pass

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        pass

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        pass

    @classmethod
    def createrepo(cls, context: Context) -> None:
        pass

    @classmethod
    def package_globs(cls) -> list[str]:
        return []

    @classmethod
    def install_package_directories(cls, context: Context, directories: Sequence[Path]) -> None:
        for d in directories:
            for p in itertools.chain(*(d.glob(glob) for glob in cls.package_globs())):
                shutil.copy(p, context.repository, follow_symlinks=True)


def clean_package_manager_metadata(context: Context) -> None:
    """
    Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if
    the package manager is not present in the image.
    """
    subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

    if context.config.clean_package_metadata == ConfigFeature.disabled:
        return

    if context.config.clean_package_metadata == ConfigFeature.auto and context.config.output_format in (
        OutputFormat.directory,
        OutputFormat.tar,
    ):
        return

    # If cleaning is not explicitly requested, keep the repository metadata if we're building a directory or
    # tar image (which are often used as a base tree for extension images and thus should retain package
    # manager metadata) or if the corresponding package manager is installed in the image.

    executable = context.config.distribution.package_manager(context.config).executable(context.config)
    remove = []

    for tool, paths in (
        ("rpm",      ["var/lib/rpm", "usr/lib/sysimage/rpm"]),
        ("dnf5",     ["usr/lib/sysimage/libdnf5"]),
        ("dpkg",     ["var/lib/dpkg"]),
        (executable, [f"var/lib/{subdir}", f"var/cache/{subdir}"]),
    ):  # fmt: skip
        if context.config.clean_package_metadata == ConfigFeature.enabled or not find_binary(
            tool, root=context.root
        ):
            remove += [context.root / p for p in paths if (context.root / p).exists()]

    rmtree(*remove, sandbox=context.sandbox)
