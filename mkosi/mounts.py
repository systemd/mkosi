# SPDX-License-Identifier: LGPL-2.1+

import collections
import contextlib
import os
import platform
import stat
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Callable, Deque, Optional, TypeVar, Union, cast

from mkosi.log import complete_step
from mkosi.manifest import GenericVersion
from mkosi.run import run
from mkosi.types import PathString

T = TypeVar("T")


def scandir_recursive(
    root: Path,
    filter: Optional[Callable[[os.DirEntry[str]], T]] = None,
) -> Iterator[T]:
    """Recursively walk the tree starting at @root, optionally apply filter, yield non-none values"""
    queue: Deque[Union[str, Path]] = collections.deque([root])

    while queue:
        for entry in os.scandir(queue.pop()):
            pred = filter(entry) if filter is not None else entry
            if pred is not None:
                yield cast(T, pred)
            if entry.is_dir(follow_symlinks=False):
                queue.append(entry.path)


def stat_is_whiteout(st: os.stat_result) -> bool:
    return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0


def delete_whiteout_files(path: Path) -> None:
    """Delete any char(0,0) device nodes underneath @path

    Overlayfs uses such files to mark "whiteouts" (files present in
    the lower layers, but removed in the upper one).
    """

    with complete_step("Removing overlay whiteout files…"):
        for entry in cast(Iterator[os.DirEntry[str]], scandir_recursive(path)):
            if stat_is_whiteout(entry.stat(follow_symlinks=False)):
                os.unlink(entry.path)


@contextlib.contextmanager
def mount(
    what: PathString,
    where: Path,
    operation: Optional[str] = None,
    options: Sequence[str] = (),
    type: Optional[str] = None,
    read_only: bool = False,
) -> Iterator[Path]:
    os.makedirs(where, 0o755, True)

    if read_only:
        options = ["ro", *options]

    cmd: list[PathString] = ["mount", "--no-mtab"]

    if operation:
        cmd += [operation]

    cmd += [what, where]

    if type:
        cmd += ["--types", type]

    if options:
        cmd += ["--options", ",".join(options)]

    try:
        run(cmd)
        yield where
    finally:
        run(["umount", "--no-mtab", "--recursive", where])


@contextlib.contextmanager
def mount_overlay(
    lower: Path,
    upper: Path,
    workdir: Path,
    where: Path
) -> Iterator[Path]:
    options = [f"lowerdir={lower}", f"upperdir={upper}", f"workdir={workdir}"]

    # userxattr is only supported on overlayfs since kernel 5.11
    if GenericVersion(platform.release()) >= GenericVersion("5.11"):
        options.append("userxattr")

    try:
        with mount("overlay", where, options=options, type="overlay"):
            yield where
    finally:
        with complete_step("Cleaning up overlayfs"):
            delete_whiteout_files(upper)


@contextlib.contextmanager
def dissect_and_mount(image: Path, where: Path) -> Iterator[Path]:
    run(["systemd-dissect", "-M", image, where])
    try:
        yield where
    finally:
        run(["umount", "--recursive", where])
