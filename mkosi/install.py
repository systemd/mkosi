# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import fcntl
import importlib.resources
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

from mkosi.run import bwrap


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


def add_dropin_config_from_resource(
    root: Path, unit: str, name: str, resource: str, key: str
) -> None:
    dropin = root / f"usr/lib/systemd/system/{unit}.d/{name}.conf"
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


def copy_path(
    src: Path,
    dst: Path,
    *,
    dereference: bool = False,
    preserve_owner: bool = True,
    root: Optional[Path] = None,
) -> None:
    bwrap([
        "cp",
        "--recursive",
        f"--{'' if dereference else 'no-'}dereference",
        f"--preserve=mode,timestamps,links,xattr{',ownership' if preserve_owner else ''}",
        "--no-target-directory",
        "--reflink=auto",
        src, dst,
    ], root=root)
