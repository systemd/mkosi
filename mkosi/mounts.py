# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import stat
from pathlib import Path
from typing import ContextManager, Iterator, List, Optional, Sequence, Union, cast

from mkosi.backend import complete_step, run, scandir_recursive

PathString = Union[Path, str]


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

    cmd: List[PathString] = ["mount", "--no-mtab"]

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


def mount_bind(what: Path, where: Optional[Path] = None) -> ContextManager[Path]:
    if where is None:
        where = what

    os.makedirs(what, 0o755, True)
    os.makedirs(where, 0o755, True)
    return mount(what, where, operation="--bind")


def mount_tmpfs(where: Path) -> ContextManager[Path]:
    return mount("tmpfs", where, type="tmpfs")


@contextlib.contextmanager
def mount_overlay(
    lower: Path,
    upper: Path,
    workdir: Path,
    where: Path
) -> Iterator[Path]:
    options = [f'lowerdir={lower}', f'upperdir={upper}', f'workdir={workdir}']

    try:
        with mount("overlay", where, options=options, type="overlay"):
            yield where
    finally:
        with complete_step("Cleaning up overlayfs"):
            delete_whiteout_files(upper)


@contextlib.contextmanager
def mount_api_vfs(root: Path) -> Iterator[None]:
    subdirs = ("proc", "dev", "sys")

    with complete_step("Mounting API VFS…", "Unmounting API VFS…"), contextlib.ExitStack() as stack:
        for subdir in subdirs:
            stack.enter_context(mount_bind(Path("/") / subdir, root / subdir))

        yield


@contextlib.contextmanager
def dissect_and_mount(image: Path, where: Path) -> Iterator[Path]:
    run(["systemd-dissect", "-M", image, where])
    try:
        yield where
    finally:
        run(["umount", "--recursive", where])
