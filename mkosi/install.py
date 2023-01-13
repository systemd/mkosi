# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import errno
import fcntl
import importlib.resources
import os
import shutil
import stat
from pathlib import Path
from textwrap import dedent
from typing import Any, BinaryIO, Iterator, Optional, cast

from mkosi.backend import MkosiState, PathString, complete_step


def reflink(oldfd: int, newfd: int) -> None:
    # FIXME: Replace with fcntl.FICLONE when we move to Python 3.12
    FICLONE = 1074041865
    fcntl.ioctl(newfd, FICLONE, oldfd)


def make_executable(path: Path) -> None:
    st = path.stat()
    os.chmod(path, st.st_mode | stat.S_IEXEC)


def write_resource(
    where: Path, resource: str, key: str, *, executable: bool = False, mode: Optional[int] = None
) -> None:
    text = importlib.resources.read_text(resource, key)
    where.write_text(text)
    if mode is not None:
        where.chmod(mode)
    elif executable:
        make_executable(where)


def add_dropin_config(root: Path, unit: str, name: str, content: str) -> None:
    """Add a dropin config `name.conf` in /etc/systemd/system for `unit`."""
    dropin = root / f"etc/systemd/system/{unit}.d/{name}.conf"
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    dropin.write_text(dedent(content))
    dropin.chmod(0o644)


def add_dropin_config_from_resource(
    root: Path, unit: str, name: str, resource: str, key: str
) -> None:
    dropin = root / f"etc/systemd/system/{unit}.d/{name}.conf"
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    write_resource(dropin, resource, key, mode=0o644)


@contextlib.contextmanager
def open_close(path: PathString, flags: int, mode: int = 0o664) -> Iterator[int]:
    fd = os.open(path, flags | os.O_CLOEXEC, mode)
    try:
        yield fd
    finally:
        os.close(fd)


def copy_fd(oldfd: int, newfd: int) -> None:
    try:
        reflink(oldfd, newfd)
    except OSError as e:
        if e.errno not in {errno.EXDEV, errno.EOPNOTSUPP, errno.ENOTTY}:
            raise
        # While mypy handles this correctly, Pyright doesn't yet.
        shutil.copyfileobj(open(oldfd, "rb", closefd=False), cast(Any, open(newfd, "wb", closefd=False)))


def copy_file_object(oldobject: BinaryIO, newobject: BinaryIO) -> None:
    try:
        reflink(oldobject.fileno(), newobject.fileno())
    except OSError as e:
        if e.errno not in {errno.EXDEV, errno.EOPNOTSUPP, errno.ENOTTY}:
            raise
        shutil.copyfileobj(oldobject, newobject)
        newobject.flush()


def copy_file(oldpath: PathString, newpath: PathString) -> None:
    oldpath = Path(oldpath)
    newpath = Path(newpath)

    if oldpath.is_symlink():
        src = oldpath.readlink()
        newpath.symlink_to(src)
        return

    with open_close(oldpath, os.O_RDONLY) as oldfd:
        st = os.stat(oldfd)

        try:
            with open_close(newpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, st.st_mode) as newfd:
                copy_fd(oldfd, newfd)
        except FileExistsError:
            newpath.unlink()
            with open_close(newpath, os.O_WRONLY | os.O_CREAT, st.st_mode) as newfd:
                copy_fd(oldfd, newfd)
    shutil.copystat(oldpath, newpath, follow_symlinks=False)


def symlink_f(target: str, path: Path) -> None:
    try:
        path.symlink_to(target)
    except FileExistsError:
        os.unlink(path)
        path.symlink_to(target)


def copy_path(oldpath: PathString, newpath: Path, *, copystat: bool = True) -> None:
    try:
        newpath.mkdir(exist_ok=True)
    except FileExistsError:
        # something that is not a directory already exists
        newpath.unlink()
        newpath.mkdir()

    for entry in os.scandir(oldpath):
        newentry = newpath / entry.name
        if entry.is_dir(follow_symlinks=False):
            copy_path(entry.path, newentry)
        elif entry.is_symlink():
            target = os.readlink(entry.path)
            symlink_f(target, newentry)
            shutil.copystat(entry.path, newentry, follow_symlinks=False)
        else:
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(st.st_mode):
                copy_file(entry.path, newentry)
            else:
                print("Ignoring", entry.path)
                continue

    if copystat:
        shutil.copystat(oldpath, newpath, follow_symlinks=True)


def install_skeleton_trees(state: MkosiState, cached: bool, *, late: bool=False) -> None:
    if not state.config.skeleton_trees:
        return

    if cached:
        return

    if not late and state.installer.needs_skeletons_after_bootstrap:
        return

    with complete_step("Copying in skeleton file trees…"):
        for tree in state.config.skeleton_trees:
            if tree.is_dir():
                copy_path(tree, state.root, copystat=False)
            else:
                # unpack_archive() groks Paths, but mypy doesn't know this.
                # Pretend that tree is a str.
                shutil.unpack_archive(tree, state.root)
