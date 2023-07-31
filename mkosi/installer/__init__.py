# SPDX-License-Identifier: LGPL-2.1+

import os

from mkosi.config import ConfigFeature
from mkosi.state import MkosiState
from mkosi.tree import rmtree


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
                        ("dpkg",   ["var/lib/dpkg"]),
                        ("pacman", ["var/lib/pacman"])):
        for bin in ("bin", "sbin"):
            if not always and os.access(state.root / "usr" / bin / tool, mode=os.F_OK, follow_symlinks=False):
                break
        else:
            for p in paths:
                rmtree(state.root / p)
