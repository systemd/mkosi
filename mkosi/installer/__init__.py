# SPDX-License-Identifier: LGPL-2.1+

import os

from mkosi.bubblewrap import apivfs_cmd
from mkosi.config import ConfigFeature
from mkosi.context import Context
from mkosi.installer.apt import apt_cmd
from mkosi.installer.dnf import dnf_cmd
from mkosi.installer.pacman import pacman_cmd
from mkosi.installer.rpm import rpm_cmd
from mkosi.installer.zypper import zypper_cmd
from mkosi.tree import rmtree
from mkosi.types import PathString


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
        for bin in ("bin", "sbin"):
            if not always and os.access(context.root / "usr" / bin / tool, mode=os.F_OK, follow_symlinks=False):
                break
        else:
            for p in paths:
                rmtree(context.root / p)


def package_manager_scripts(context: Context) -> dict[str, list[PathString]]:
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
