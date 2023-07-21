# SPDX-License-Identifier: LGPL-2.1+

import collections
import contextlib
import os
import platform
import stat
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Callable, Deque, Optional, TypeVar, Union, cast

from mkosi.config import GenericVersion, MkosiConfig
from mkosi.log import complete_step
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
    umount: bool = True,
) -> Iterator[Path]:
    if not where.exists():
        where.mkdir(mode=0o755, parents=True)

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
        if umount:
            # If we mounted over /usr, trying to use umount will fail with "target is busy", because umount
            # is being called from /usr, which we're trying to unmount. To work around this issue, we do a
            # lazy unmount.
            run(["umount", "--no-mtab", "--lazy", where])


@contextlib.contextmanager
def mount_overlay(
    lowerdirs: Sequence[Path],
    upperdir: Path,
    where: Path,
    read_only: bool = True,
) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(dir=upperdir.parent, prefix=f"{upperdir.name}-workdir") as workdir:
        options = [f"lowerdir={lower}" for lower in lowerdirs] + [f"upperdir={upperdir}", f"workdir={workdir}"]

        # userxattr is only supported on overlayfs since kernel 5.11
        if GenericVersion(platform.release()) >= GenericVersion("5.11"):
            options.append("userxattr")

        try:
            with mount("overlay", where, options=options, type="overlay", read_only=read_only):
                yield where
        finally:
            with complete_step("Cleaning up overlayfs"):
                delete_whiteout_files(upperdir)


@contextlib.contextmanager
def mount_tools(config: MkosiConfig, umount: bool = True) -> Iterator[None]:
    if not config.tools_tree:
        yield
        return

    # If a tools tree is specified, we should ignore any local modifications made to PATH as any of those
    # binaries might not work anymore when /usr is replaced wholesale. We also make sure that both /usr/bin
    # and /usr/sbin/ are searched so that e.g. if the host is Arch and the root is Debian we don't ignore the
    # binaries from /usr/sbin in the Debian root.
    old = os.environ["PATH"]
    os.environ["PATH"] = "/usr/bin:/usr/sbin"

    try:
        with mount(what=config.tools_tree / "usr", where=Path("/usr"), operation="--bind", read_only=True, umount=umount):
            yield
    finally:
        os.environ["PATH"] = old


@contextlib.contextmanager
def mount_passwd(name: str, uid: int, gid: int, umount: bool = True) -> Iterator[None]:
    """
    ssh looks up the running user in /etc/passwd and fails if it can't find the running user. To trick it, we
    mount over /etc/passwd with our own file containing our user in the user namespace.
    """
    with tempfile.NamedTemporaryFile(prefix="mkosi.passwd", mode="w") as passwd:
        passwd.write(f"{name}:x:{uid}:{gid}:{name}:/bin/sh\n")
        os.fchown(passwd.file.fileno(), uid, gid)

        with mount(passwd.name, Path("/etc/passwd"), operation="--bind", umount=umount):
            passwd.close() # Don't need the file anymore after it's mounted.
            yield
