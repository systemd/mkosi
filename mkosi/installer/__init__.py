# SPDX-License-Identifier: LGPL-2.1+

import os
from pathlib import Path

from mkosi.config import ConfigFeature
from mkosi.context import Context
from mkosi.run import find_binary
from mkosi.sandbox import apivfs_cmd, finalize_crypto_mounts
from mkosi.tree import rmtree
from mkosi.types import PathString
from mkosi.util import flatten


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


def package_manager_scripts(context: Context) -> dict[str, list[PathString]]:
    from mkosi.installer.apt import apt_cmd
    from mkosi.installer.dnf import dnf_cmd
    from mkosi.installer.pacman import pacman_cmd
    from mkosi.installer.rpm import rpm_cmd
    from mkosi.installer.zypper import zypper_cmd

    return {
        "pacman": apivfs_cmd(context.root) + pacman_cmd(context),
        "zypper": apivfs_cmd(context.root) + zypper_cmd(context),
        "dnf"   : apivfs_cmd(context.root) + dnf_cmd(context),
        "rpm"   : apivfs_cmd(context.root) + rpm_cmd(context),
    } | {
        command: apivfs_cmd(context.root) + apt_cmd(context, command) for command in (
            "apt",
            "apt-cache",
            "apt-cdrom",
            "apt-config",
            "apt-extracttemplates",
            "apt-get",
            "apt-key",
            "apt-mark",
            "apt-sortpkgs",
        )
    }


def finalize_package_manager_mounts(context: Context) -> list[PathString]:
    from mkosi.installer.dnf import dnf_subdir

    mounts: list[PathString] = [
        *(["--ro-bind", m, m] if (m := context.config.local_mirror) else []),
        *(["--ro-bind", os.fspath(p), os.fspath(p)] if (p := context.workspace / "apt.conf").exists() else []),
        *finalize_crypto_mounts(tools=context.config.tools()),
        "--bind", context.packages, "/work/packages",
    ]

    mounts += flatten(
        ["--bind", context.cache_dir / d, Path("/var") / d]
        for d in (
            "lib/apt",
            "cache/apt",
            f"cache/{dnf_subdir(context)}",
            f"lib/{dnf_subdir(context)}",
            "cache/pacman/pkg",
            "cache/zypp",
        )
        if (context.cache_dir / d).exists()
    )

    return mounts
