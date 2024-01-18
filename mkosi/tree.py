# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import errno
import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

from mkosi.config import ConfigFeature
from mkosi.log import die
from mkosi.run import find_binary, run
from mkosi.types import PathString


def statfs(path: Path, *, sandbox: Sequence[PathString] = ()) -> str:
    return run(["stat", "--file-system", "--format", "%T", path],
               sandbox=sandbox, stdout=subprocess.PIPE).stdout.strip()


def is_subvolume(path: Path, *, sandbox: Sequence[PathString] = ()) -> bool:
    return path.is_dir() and statfs(path, sandbox=sandbox) == "btrfs" and path.stat().st_ino == 256


def make_tree(
    path: Path,
    *,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    tools: Path = Path("/"),
    sandbox: Sequence[PathString] = (),
) -> None:
    if use_subvolumes == ConfigFeature.enabled and not find_binary("btrfs", root=tools):
        die("Subvolumes requested but the btrfs command was not found")

    if statfs(path.parent, sandbox=sandbox) != "btrfs":
        if use_subvolumes == ConfigFeature.enabled:
            die(f"Subvolumes requested but {path} is not located on a btrfs filesystem")

        path.mkdir()
        return

    if use_subvolumes != ConfigFeature.disabled and find_binary("btrfs", root=tools) is not None:
        result = run(["btrfs", "subvolume", "create", path],
                     sandbox=sandbox, check=use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result != 0:
        path.mkdir()


@contextlib.contextmanager
def preserve_target_directories_stat(src: Path, dst: Path) -> Iterator[None]:
    dirs = [p for d in src.glob("**/") if (dst / (p := d.relative_to(src))).exists()]

    with tempfile.TemporaryDirectory() as tmp:
        for d in dirs:
            (tmp / d).mkdir(exist_ok=True)
            shutil.copystat(dst / d, tmp / d)

        yield

        for d in dirs:
            shutil.copystat(tmp / d, dst / d)


def copy_tree(
    src: Path,
    dst: Path,
    *,
    preserve: bool = True,
    dereference: bool = False,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    tools: Path = Path("/"),
    sandbox: Sequence[PathString] = (),
) -> None:
    subvolume = (use_subvolumes == ConfigFeature.enabled or
                 use_subvolumes == ConfigFeature.auto and find_binary("btrfs", root=tools) is not None)

    if use_subvolumes == ConfigFeature.enabled and not find_binary("btrfs", root=tools):
        die("Subvolumes requested but the btrfs command was not found")

    copy: list[PathString] = [
        "cp",
        "--recursive",
        "--dereference" if dereference else "--no-dereference",
        f"--preserve=mode,links{',timestamps,ownership,xattr' if preserve else ''}",
        "--reflink=auto",
        src, dst,
    ]

    # If the source and destination are both directories, we want to merge the source directory with the
    # destination directory. If the source if a file and the destination is a directory, we want to copy
    # the source inside the directory.
    if src.is_dir():
        copy += ["--no-target-directory"]

    # Subvolumes always have inode 256 so we can use that to check if a directory is a subvolume.
    if (
        not subvolume or
        not preserve or
        not is_subvolume(src, sandbox=sandbox) or
        not find_binary("btrfs", root=tools) or
        (dst.exists() and any(dst.iterdir()))
    ):
        with (
            preserve_target_directories_stat(src, dst)
            if not preserve
            else contextlib.nullcontext()
        ):
            run(copy, sandbox=sandbox)
        return

    # btrfs can't snapshot to an existing directory so make sure the destination does not exist.
    if dst.exists():
        dst.rmdir()

    result = run(["btrfs", "subvolume", "snapshot", src, dst],
                 check=use_subvolumes == ConfigFeature.enabled, sandbox=sandbox).returncode
    if result != 0:
        with (
            preserve_target_directories_stat(src, dst)
            if not preserve
            else contextlib.nullcontext()
        ):
            run(copy, sandbox=sandbox)


def rmtree(*paths: Path, sandbox: Sequence[PathString] = ()) -> None:
    if paths:
        run(["rm", "-rf", "--", *paths], sandbox=sandbox)


def move_tree(
    src: Path,
    dst: Path,
    *,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    tools: Path = Path("/"),
    sandbox: Sequence[PathString] = (),
) -> None:
    if src == dst:
        return

    if dst.is_dir():
        dst = dst / src.name

    try:
        src.rename(dst)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise e

        copy_tree(src, dst, use_subvolumes=use_subvolumes, tools=tools, sandbox=sandbox)
        rmtree(src, sandbox=sandbox)
