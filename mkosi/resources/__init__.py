# SPDX-License-Identifier: PSF-2.0
# Based on code from https://github.com/python/cpython/blob/main/Lib/importlib/resources/_common.py

import contextlib
import functools
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import AbstractContextManager
from pathlib import Path

if sys.version_info >= (3, 11):
    from importlib.resources.abc import Traversable
else:
    from importlib.abc import Traversable


@contextlib.contextmanager
def temporary_file(path: Traversable, suffix: str = "") -> Iterator[Path]:
    fd, raw_path = tempfile.mkstemp(suffix=suffix)
    try:
        try:
            os.write(fd, path.read_bytes())
        finally:
            os.close(fd)
        yield Path(raw_path)
    finally:
        try:
            os.remove(raw_path)
        except FileNotFoundError:
            pass


def dir_is_present(path: Traversable) -> bool:
    """
    Some Traversables implement ``is_dir()`` to raise an
    exception (i.e. ``FileNotFoundError``) when the
    directory doesn't exist. This function wraps that call
    to always return a boolean and only return True
    if there's a dir and it exists.
    """
    with contextlib.suppress(FileNotFoundError):
        return path.is_dir()
    return False


@functools.singledispatch
def as_file(path: Traversable) -> AbstractContextManager[Path]:
    """
    Given a Traversable object, return that object as a
    path on the local file system in a context manager.
    """
    return temporary_dir(path) if dir_is_present(path) else temporary_file(path, suffix=path.name)


@contextlib.contextmanager
def temporary_dir(path: Traversable) -> Iterator[Path]:
    """
    Given a traversable dir, recursively replicate the whole tree
    to the file system in a context manager.
    """
    assert path.is_dir()
    with tempfile.TemporaryDirectory() as temp_dir:
        yield write_contents(Path(temp_dir), path)


def write_contents(target: Path, source: Traversable) -> Path:
    child = target.joinpath(source.name)
    if source.is_dir():
        child.mkdir()
        for item in source.iterdir():
            write_contents(child, item)
    else:
        child.write_bytes(source.read_bytes())
    return child
