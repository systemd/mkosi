# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

from mkosi.config import Config, ConfigFeature, OutputFormat
from mkosi.context import Context
from mkosi.mounts import finalize_crypto_mounts
from mkosi.run import find_binary
from mkosi.sandbox import Mount
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import startswith


class PackageManager:
    @classmethod
    def executable(cls, config: Config) -> str:
        return "custom"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("custom")

    @classmethod
    def cache_subdirs(cls, cache: Path) -> list[Path]:
        return []

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {}

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        env = {
            "HOME": "/", # Make sure rpm doesn't pick up ~/.rpmmacros and ~/.rpmrc.
        }

        if "SYSTEMD_HWDB_UPDATE_BYPASS" not in context.config.environment:
            env["SYSTEMD_HWDB_UPDATE_BYPASS"] = "1"

        if (
            "KERNEL_INSTALL_BYPASS" not in context.config.environment and
            context.config.bootable != ConfigFeature.disabled
        ):
            env["KERNEL_INSTALL_BYPASS"] = "1"

        return env

    @classmethod
    def env_cmd(cls, context: Context) -> list[PathString]:
        return ["env", *([f"{k}={v}" for k, v in cls.finalize_environment(context).items()])]

    @classmethod
    def mounts(cls, context: Context) -> list[Mount]:
        mounts = [
            *finalize_crypto_mounts(context.config),
            Mount(context.repository, "/repository"),
        ]

        if context.config.local_mirror and (mirror := startswith(context.config.local_mirror, "file://")):
            mounts += [Mount(mirror, mirror, ro=True)]

        subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

        for d in ("cache", "lib"):
            src = context.package_cache_dir / d / subdir
            mounts += [Mount(src, Path("/var") / d / subdir)]

            # If we're not operating on the configured package cache directory, we're operating on a snapshot of the
            # repository metadata in the image root directory. To make sure any downloaded packages are still cached in
            # the configured package cache directory in this scenario, we mount in the relevant directories from the
            # configured package cache directory.
            if d == "cache" and context.package_cache_dir != context.config.package_cache_dir_or_default():
                caches = context.config.distribution.package_manager(context.config).cache_subdirs(src)
                mounts += [
                    Mount(
                        context.config.package_cache_dir_or_default() / d / subdir / p.relative_to(src),
                        Path("/var") / d / subdir / p.relative_to(src),
                    )
                    for p in caches
                    if (context.config.package_cache_dir_or_default() / d / subdir / p.relative_to(src)).exists()
                ]

        return mounts

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        pass

    @classmethod
    def createrepo(cls, context: Context) -> None:
        pass


def clean_package_manager_metadata(context: Context) -> None:
    """
    Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if
    the package manager is not present in the image.
    """
    subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

    if context.package_cache_dir.is_relative_to(context.root):
        # Copy the package manager repository metadata to the workspace so it stays available for later steps even if
        # it is removed from the image by a later step.
        for d in ("cache", "lib"):
            src = context.package_cache_dir / d / subdir
            if not src.exists():
                continue

            dst = context.workspace / "package-cache-dir" / d / subdir
            dst.mkdir(parents=True, exist_ok=True)

            copy_tree(src, dst, sandbox=context.sandbox)

        context.package_cache_dir = context.workspace / "package-cache-dir"

    if context.config.overlay:
        return

    if context.config.clean_package_metadata == ConfigFeature.disabled:
        return

    if (
        context.config.clean_package_metadata == ConfigFeature.auto and
        context.config.output_format in (OutputFormat.directory, OutputFormat.tar)
    ):
        return

    # If cleaning is not explicitly requested, keep the repository metadata if we're building a directory or tar image
    # (which are often used as a base tree for extension images and thus should retain package manager metadata) or if
    # the corresponding package manager is installed in the image.

    executable = context.config.distribution.package_manager(context.config).executable(context.config)

    for tool, paths in (("rpm",      ["var/lib/rpm", "usr/lib/sysimage/rpm"]),
                        ("dnf5",     ["usr/lib/sysimage/libdnf5"]),
                        ("dpkg",     ["var/lib/dpkg"]),
                        (executable, [f"var/lib/{subdir}", f"var/cache/{subdir}"])):
        if context.config.clean_package_metadata == ConfigFeature.enabled or not find_binary(tool, root=context.root):
            rmtree(*(context.root / p for p in paths if (context.root / p).exists()), sandbox=context.sandbox)
