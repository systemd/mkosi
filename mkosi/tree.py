# SPDX-License-Identifier: LGPL-2.1+

import errno
import shutil
import subprocess
from pathlib import Path
from typing import Sequence, cast

from mkosi.config import ConfigFeature, MkosiConfig
from mkosi.log import die
from mkosi.run import bwrap, finalize_passwd_mounts, run
from mkosi.types import PathString
from mkosi.util import tar_binary


def statfs(path: Path) -> str:
    return cast(str, run(["stat", "--file-system", "--format", "%T", path],
                         stdout=subprocess.PIPE).stdout.strip())


def is_subvolume(path: Path) -> bool:
    return path.is_dir() and statfs(path) == "btrfs" and path.stat().st_ino == 256


def make_tree(config: MkosiConfig, path: Path, mode: int) -> None:
    if config.use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    if statfs(path.parent) != "btrfs":
        if config.use_subvolumes == ConfigFeature.enabled:
            die(f"Subvolumes requested but {path} is not located on a btrfs filesystem")

        path.mkdir(mode)
        return

    if config.use_subvolumes != ConfigFeature.disabled and shutil.which("btrfs") is not None:
        result = run(["btrfs", "subvolume", "create", path],
                     check=config.use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result == 0:
        path.chmod(mode)
    else:
        path.mkdir(mode)


def copy_tree(config: MkosiConfig, src: Path, dst: Path, *, preserve_owner: bool = True) -> None:
    subvolume = (config.use_subvolumes == ConfigFeature.enabled or
                 config.use_subvolumes == ConfigFeature.auto and shutil.which("btrfs") is not None)

    if config.use_subvolumes == ConfigFeature.enabled and not shutil.which("btrfs"):
        die("Subvolumes requested but the btrfs command was not found")

    copy: Sequence[PathString] = [
        "cp",
        "--recursive",
        f"--preserve=mode,timestamps,links,xattr{',ownership' if preserve_owner else ''}",
        "--no-target-directory",
        "--reflink=auto",
        src, dst,
    ]

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


def rmtree(path: Path) -> None:
    run(["rm", "-rf", "--", path])


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


def tar_exclude_apivfs_tmp() -> list[str]:
    return [
        "--exclude", "./dev/*",
        "--exclude", "./proc/*",
        "--exclude", "./sys/*",
        "--exclude", "./tmp/*",
        "--exclude", "./run/*",
        "--exclude", "./var/tmp/*",
    ]


def archive_tree(src: Path, dst: Path) -> None:
    bwrap(
        [
            tar_binary(),
            "--create",
            "--file", dst,
            "--directory", src,
            "--acls",
            "--selinux",
            "--xattrs",
            "--sparse",
            "--force-local",
            *tar_exclude_apivfs_tmp(),
            ".",
        ],
        # Make sure tar uses user/group information from the root directory instead of the host.
        options=finalize_passwd_mounts(src) if (src / "etc/passwd").exists() else [],
    )


def extract_tree(src: Path, dst: Path) -> None:
    bwrap(
        [
            tar_binary(),
            "--extract",
            "--file", src,
            "--directory", dst,
            "--keep-directory-symlink",
            "--no-overwrite-dir",
            "--same-permissions",
            "--same-owner" if (dst / "etc/passwd").exists() else "--numeric-owner",
            "--same-order",
            "--acls",
            "--selinux",
            "--xattrs",
            "--force-local",
            *tar_exclude_apivfs_tmp(),
        ],
        # Make sure tar uses user/group information from the root directory instead of the host.
        options=finalize_passwd_mounts(dst) if (dst / "etc/passwd").exists() else [],
    )
