# SPDX-License-Identifier: LGPL-2.1+

import os
from pathlib import Path

from mkosi.config import Config, ConfigFeature, OutputFormat
from mkosi.context import Context
from mkosi.run import find_binary
from mkosi.sandbox import finalize_crypto_mounts
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import flatten


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
    def mounts(cls, context: Context) -> list[PathString]:
        mounts: list[PathString] = [
            *(["--ro-bind", m, m] if (m := context.config.local_mirror) else []),
            *finalize_crypto_mounts(tools=context.config.tools()),
            "--bind", context.packages, "/work/packages",
        ]

        subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

        for d in ("cache", "lib"):
            src = context.package_cache_dir / d / subdir
            mounts += ["--bind", src, Path("/var") / d / subdir]

            # If we're not operating on the configured package cache directory, we're operating on a snapshot of the
            # repository metadata in the image root directory. To make sure any downloaded packages are still cached in
            # the configured package cache directory in this scenario, we mount in the relevant directories from the
            # configured package cache directory.
            if d == "cache" and context.package_cache_dir != context.config.package_cache_dir_or_default():
                caches = context.config.distribution.package_manager(context.config).cache_subdirs(src)
                mounts += flatten(
                    [
                        "--bind",
                        os.fspath(context.config.package_cache_dir_or_default() / d / subdir / p.relative_to(src)),
                        Path("/var") / d / subdir / p.relative_to(src),
                    ]
                    for p in caches
                )

        return mounts


def clean_package_manager_metadata(context: Context) -> None:
    """
    Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if
    the package manager is not present in the image.
    """
    if (
        context.package_cache_dir.is_relative_to(context.root) and
        not context.config.overlay and (
            context.config.clean_package_metadata != ConfigFeature.disabled or
            context.config.output_format not in (OutputFormat.directory, OutputFormat.tar)
        )
    ):
        # Instead of removing the package cache directory from the image, we move it to the workspace so it stays
        # available for later steps and is automatically removed along with the workspace when the build finishes.
        subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

        for d in ("cache", "lib"):
            src = context.package_cache_dir / d / subdir
            if not src.exists():
                continue

            dst = context.workspace / "package-cache-dir" / d / subdir
            dst.mkdir(parents=True, exist_ok=True)

            copy_tree(src, dst, sandbox=context.sandbox)

        context.package_cache_dir = context.workspace / "package-cache-dir"

    if context.config.clean_package_metadata == ConfigFeature.disabled:
        return

    always = context.config.clean_package_metadata == ConfigFeature.enabled
    executable = context.config.distribution.package_manager(context.config).executable(context.config)
    subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

    for tool, paths in (("rpm",      ["var/lib/rpm", "usr/lib/sysimage/rpm"]),
                        ("dnf5",     ["usr/lib/sysimage/libdnf5"]),
                        ("dpkg",     ["var/lib/dpkg"]),
                        (executable, [f"var/lib/{subdir}", f"var/cache/{subdir}"])):
        if always or not find_binary(tool, root=context.root):
            rmtree(*(context.root / p for p in paths), sandbox=context.sandbox)
