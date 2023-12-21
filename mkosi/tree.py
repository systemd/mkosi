# SPDX-License-Identifier: LGPL-2.1+

import errno
import shutil
import subprocess
from pathlib import Path

from mkosi.config import ConfigFeature
from mkosi.log import die
from mkosi.run import run
from mkosi.types import PathString
from mkosi.versioncomp import GenericVersion


def statfs(path: Path) -> str:
    return run(["stat", "--file-system", "--format", "%T", path], stdout=subprocess.PIPE).stdout.strip()


def is_subvolume(path: Path) -> bool:
    return path.is_dir() and statfs(path) == "btrfs" and path.stat().st_ino == 256


def make_tree(path: Path, use_subvolumes: ConfigFeature = ConfigFeature.disabled) -> None:
    if use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    if statfs(path.parent) != "btrfs":
        if use_subvolumes == ConfigFeature.enabled:
            die(f"Subvolumes requested but {path} is not located on a btrfs filesystem")

        path.mkdir()
        return

    if use_subvolumes != ConfigFeature.disabled and shutil.which("btrfs") is not None:
        result = run(["btrfs", "subvolume", "create", path],
                     check=use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result != 0:
        path.mkdir()


def cp_version() -> GenericVersion:
    return GenericVersion(run(["cp", "--version"], stdout=subprocess.PIPE).stdout.strip().splitlines()[0].split()[3])


def copy_tree(
    src: Path,
    dst: Path,
    *,
    preserve_owner: bool = True,
    clobber: bool = True,
    dereference: bool = False,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
) -> None:
    subvolume = (use_subvolumes == ConfigFeature.enabled or
                 use_subvolumes == ConfigFeature.auto and shutil.which("btrfs") is not None)

    if use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    copy: list[PathString] = [
        "cp",
        "--recursive",
        "--dereference" if dereference else "--no-dereference",
        f"--preserve=mode,timestamps,links,xattr{',ownership' if preserve_owner else ''}",
        "--reflink=auto",
        src, dst,
    ]

    # --no-clobber will make cp fail if a file already exists since coreutils v9.2. In coreutils v9.3, --update=none
    # was introduced to support the previous behavior of --no-clobber again. On coreutils v9.2, --no-clobber will fail
    # and --update=none is not available so in that case we're out of luck. There don't seem to be any distros
    # packaging coreutils v9.2 though so let's hope we don't trigger this edge case.
    if not clobber:
        copy += ["--update=none"] if cp_version() >= "9.3" else ["--no-clobber"]

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
                     check=use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result != 0:
        run(copy)


def rmtree(*paths: Path) -> None:
    run(["rm", "-rf", "--", *paths])


def move_tree(src: Path, dst: Path, use_subvolumes: ConfigFeature = ConfigFeature.disabled) -> None:
    if src == dst:
        return

    if dst.is_dir():
        dst = dst / src.name

    try:
        src.rename(dst)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise e

        copy_tree(src, dst, use_subvolumes=use_subvolumes)
        rmtree(src)
