# SPDX-License-Identifier: LGPL-2.1+

import os

from mkosi.bubblewrap import apivfs_cmd
from mkosi.config import ConfigFeature
from mkosi.installer.apt import apt_cmd
from mkosi.installer.dnf import dnf_cmd
from mkosi.installer.pacman import pacman_cmd
from mkosi.installer.rpm import rpm_cmd
from mkosi.installer.zypper import zypper_cmd
from mkosi.state import MkosiState
from mkosi.tree import rmtree
from mkosi.types import PathString


def clean_package_manager_metadata(state: MkosiState) -> None:
    """
    Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if
    the package manager is not present in the image.
    """

    if state.config.clean_package_metadata == ConfigFeature.disabled:
        return

    always = state.config.clean_package_metadata == ConfigFeature.enabled

    for tool, paths in (("rpm",    ["var/lib/rpm", "usr/lib/sysimage/rpm"]),
                        ("dnf5",   ["usr/lib/sysimage/libdnf5"]),
                        ("dpkg",   ["var/lib/dpkg"]),
                        ("pacman", ["var/lib/pacman"])):
        for bin in ("bin", "sbin"):
            if not always and os.access(state.root / "usr" / bin / tool, mode=os.F_OK, follow_symlinks=False):
                break
        else:
            for p in paths:
                rmtree(state.root / p)


def package_manager_scripts(state: MkosiState) -> dict[str, list[PathString]]:
    return {
        "pacman": apivfs_cmd(state.root) + pacman_cmd(state),
        "zypper": apivfs_cmd(state.root) + zypper_cmd(state),
        "dnf"   : apivfs_cmd(state.root) + dnf_cmd(state),
        "rpm"   : apivfs_cmd(state.root) + rpm_cmd(state),
    } | {
        command: apivfs_cmd(state.root) + apt_cmd(state, command) for command in (
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
