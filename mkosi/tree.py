# SPDX-License-Identifier: LGPL-2.1+

import errno
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from mkosi.archive import extract_tar
from mkosi.config import ConfigFeature, MkosiConfig
from mkosi.log import die
from mkosi.run import run
from mkosi.types import PathString
from mkosi.util import umask


def statfs(path: Path) -> str:
    return run(["stat", "--file-system", "--format", "%T", path], stdout=subprocess.PIPE).stdout.strip()


def is_subvolume(path: Path) -> bool:
    return path.is_dir() and statfs(path) == "btrfs" and path.stat().st_ino == 256


def make_tree(config: MkosiConfig, path: Path) -> None:
    if config.use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    if statfs(path.parent) != "btrfs":
        if config.use_subvolumes == ConfigFeature.enabled:
            die(f"Subvolumes requested but {path} is not located on a btrfs filesystem")

        path.mkdir()
        return

    if config.use_subvolumes != ConfigFeature.disabled and shutil.which("btrfs") is not None:
        result = run(["btrfs", "subvolume", "create", path],
                     check=config.use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result != 0:
        path.mkdir()


def copy_tree(config: MkosiConfig, src: Path, dst: Path, *, preserve_owner: bool = True) -> None:
    subvolume = (config.use_subvolumes == ConfigFeature.enabled or
                 config.use_subvolumes == ConfigFeature.auto and shutil.which("btrfs") is not None)

    if config.use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    copy: list[PathString] = [
        "cp",
        "--recursive",
        f"--preserve=mode,timestamps,links,xattr{',ownership' if preserve_owner else ''}",
        "--reflink=auto",
        src, dst,
    ]

    # If the source and destination are both directories, we want to merge the source directory with the
    # destination directory. If the source if a file and the destination is a directory, we want to copy
    # the source inside the directory.
    if src.is_dir():
        copy += ["--no-target-directory"]

    # Subvolumes always have inode 256 so we can use that to check if a directory is a subvolume.
    if not subvolume or not preserve_owner or not is_subvolume(src) or (dst.exists() and any(dst.iterdir())):
        run(copy)
        return

    # btrfs can't snapshot to an existing directory so make sure the destination does not exist.
    if dst.exists():
        dst.rmdir()

    if shutil.which("btrfs"):
        result = run(["btrfs", "subvolume", "snapshot", src, dst],
                     check=config.use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result != 0:
        run(copy)


def rmtree(*paths: Path) -> None:
    run(["rm", "-rf", "--", *paths])


def move_tree(config: MkosiConfig, src: Path, dst: Path) -> None:
    if src == dst:
        return

    if dst.is_dir():
        dst = dst / src.name

    try:
        src.rename(dst)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise e

        copy_tree(config, src, dst)
        rmtree(src)


def install_tree(config: MkosiConfig, src: Path, dst: Path, target: Optional[Path] = None) -> None:
    t = dst
    if target:
        t = dst / target.relative_to("/")

    with umask(~0o755):
        t.parent.mkdir(parents=True, exist_ok=True)

    if src.is_dir() or (src.is_file() and target):
        copy_tree(config, src, t, preserve_owner=False)
    elif src.suffix == ".tar":
        extract_tar(src, t)
    elif src.suffix == ".raw":
        run(["systemd-dissect", "--copy-from", src, "/", t])
    else:
        die(f"Source tree {src} has unsupported source tree type \"{src.suffix}\"")
