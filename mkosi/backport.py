# SPDX-License-Identifier: PSF-2.0
# Copied from https://github.com/python/cpython/blob/main/Lib/importlib/resources/_common.py

# We backport as_file() from python 3.12 here temporarily since it added directory support.
# TODO: Remove once minimum python version is 3.12.

import contextlib
import functools
import os
import tempfile
from pathlib import Path
from typing import no_type_check


@no_type_check
@contextlib.contextmanager
def _tempfile(
    reader,
    suffix='',
    # gh-93353: Keep a reference to call os.remove() in late Python
    # finalization.
    *,
    _os_remove=os.remove,
):
    # Not using tempfile.NamedTemporaryFile as it leads to deeper 'try'
    # blocks due to the need to close the temporary file to work on Windows
    # properly.
    fd, raw_path = tempfile.mkstemp(suffix=suffix)
    try:
        try:
            os.write(fd, reader())
        finally:
            os.close(fd)
        del reader
        yield Path(raw_path)
    finally:
        try:
            _os_remove(raw_path)
        except FileNotFoundError:
            pass

@no_type_check
def _temp_file(path):
    return _tempfile(path.read_bytes, suffix=path.name)

@no_type_check
def _is_present_dir(path) -> bool:
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

@no_type_check
@functools.singledispatch
def as_file(path):
    """
    Given a Traversable object, return that object as a
    path on the local file system in a context manager.
    """
    return _temp_dir(path) if _is_present_dir(path) else _temp_file(path)

@no_type_check
@contextlib.contextmanager
def _temp_path(dir: tempfile.TemporaryDirectory):
    """
    Wrap tempfile.TemporyDirectory to return a pathlib object.
    """
    with dir as result:
        yield Path(result)

@no_type_check
@contextlib.contextmanager
def _temp_dir(path):
    """
    Given a traversable dir, recursively replicate the whole tree
    to the file system in a context manager.
    """
    assert path.is_dir()
    with _temp_path(tempfile.TemporaryDirectory()) as temp_dir:
        yield _write_contents(temp_dir, path)

@no_type_check
def _write_contents(target, source):
    child = target.joinpath(source.name)
    if source.is_dir():
        child.mkdir()
        for item in source.iterdir():
            _write_contents(child, item)
    else:
        child.write_bytes(source.read_bytes())
    return child
