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


def btrfs_maybe_snapshot_subvolume(config: MkosiConfig, src: Path, dst: Path, move: bool = False) -> None:
    if config.use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    subvolume = (config.use_subvolumes == ConfigFeature.enabled or
                 config.use_subvolumes == ConfigFeature.auto and shutil.which("btrfs") is not None)

    # Subvolumes always have inode 256
    if subvolume and src.stat().st_ino == 256:
        if dst.exists():
            dst.rmdir()
        if run(["btrfs", "subvolume", "snapshot", src, dst],
               check=config.use_subvolumes == ConfigFeature.enabled).returncode == 0:
            return

    if move:
        shutil.move(src, dst)
    else:
        copy_path(src, dst)
