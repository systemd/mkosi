# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import fcntl
import importlib.resources
import os
import shutil
import stat
from collections.abc import Iterator
from pathlib import Path
from textwrap import dedent
from typing import Optional

from mkosi.backend import MkosiState
from mkosi.log import complete_step
from mkosi.run import run


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
def flock(path: Path) -> Iterator[Path]:
    fd = os.open(path, os.O_CLOEXEC|os.O_DIRECTORY|os.O_RDONLY)
    try:
        fcntl.fcntl(fd, fcntl.FD_CLOEXEC)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield Path(path)
    finally:
        os.close(fd)


def copy_path(src: Path, dst: Path, preserve_owner: bool = True) -> None:
    run([
        "cp",
        "--recursive",
        "--no-dereference",
        f"--preserve=mode,timestamps,links,xattr{',ownership' if preserve_owner else ''}",
        "--no-target-directory",
        "--reflink=auto",
        src, dst,
    ])


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
                copy_path(tree, state.root, preserve_owner=False)
            else:
                # unpack_archive() groks Paths, but mypy doesn't know this.
                # Pretend that tree is a str.
                shutil.unpack_archive(tree, state.root)
