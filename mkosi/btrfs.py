# SPDX-License-Identifier: LGPL-2.1+

import shutil
from pathlib import Path

from mkosi.config import ConfigFeature, MkosiConfig
from mkosi.install import copy_path
from mkosi.log import die
from mkosi.run import run


def btrfs_maybe_make_subvolume(config: MkosiConfig, path: Path, mode: int) -> None:
    if config.use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    if config.use_subvolumes != ConfigFeature.disabled and shutil.which("btrfs") is not None:
        result = run(["btrfs", "subvolume", "create", path],
                     check=config.use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result == 0:
        path.chmod(mode)
    else:
        path.mkdir(mode)


def btrfs_maybe_snapshot_subvolume(config: MkosiConfig, src: Path, dst: Path) -> None:
    subvolume = (config.use_subvolumes == ConfigFeature.enabled or
                 config.use_subvolumes == ConfigFeature.auto and shutil.which("btrfs") is not None)

    if config.use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    # Subvolumes always have inode 256 so we can use that to check if a directory is a subvolume.
    if not subvolume or src.stat().st_ino != 256 or (dst.exists() and any(dst.iterdir())):
        return copy_path(src, dst)

    # btrfs can't snapshot to an existing directory so make sure the destination does not exist.
    if dst.exists():
        dst.rmdir()

    if shutil.which("btrfs"):
        result = run(["btrfs", "subvolume", "snapshot", src, dst],
                    check=config.use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result != 0:
        copy_path(src, dst)
