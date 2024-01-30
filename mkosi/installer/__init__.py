# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.config import ConfigFeature
from mkosi.context import Context
from mkosi.run import find_binary
from mkosi.sandbox import finalize_crypto_mounts
from mkosi.tree import rmtree
from mkosi.types import PathString
from mkosi.util import flatten


class PackageManager:
    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        raise NotImplementedError


def clean_package_manager_metadata(context: Context) -> None:
    """
    Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if
    the package manager is not present in the image.
    """

    if context.config.clean_package_metadata == ConfigFeature.disabled:
        return

    always = context.config.clean_package_metadata == ConfigFeature.enabled

    for tool, paths in (("rpm",    ["var/lib/rpm", "usr/lib/sysimage/rpm"]),
                        ("dnf5",   ["usr/lib/sysimage/libdnf5"]),
                        ("dpkg",   ["var/lib/dpkg"]),
                        ("pacman", ["var/lib/pacman"])):
        if always or not find_binary(tool, root=context.root):
            rmtree(*(context.root / p for p in paths),
                   sandbox=context.sandbox(options=["--bind", context.root, context.root]))


def finalize_package_manager_mounts(context: Context) -> list[PathString]:
    from mkosi.installer.dnf import Dnf

    mounts: list[PathString] = [
        *(["--ro-bind", m, m] if (m := context.config.local_mirror) else []),
        *finalize_crypto_mounts(tools=context.config.tools()),
        "--bind", context.packages, "/work/packages",
    ]

    mounts += flatten(
        ["--bind", context.cache_dir / d, Path("/var") / d]
        for d in (
            "lib/apt",
            "cache/apt",
            f"cache/{Dnf.subdir(context.config)}",
            f"lib/{Dnf.subdir(context.config)}",
            "cache/pacman/pkg",
            "cache/zypp",
        )
        if (context.cache_dir / d).exists()
    )

    return mounts
