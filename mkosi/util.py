# SPDX-License-Identifier: LGPL-2.1+

import ast
import contextlib
import copy
import enum
import errno
import fcntl
import functools
import hashlib
import importlib
import importlib.resources
import itertools
import logging
import os
import re
import resource
import stat
import tempfile
from collections.abc import Hashable, Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional, TypeVar, no_type_check

from mkosi.log import die
from mkosi.types import PathString

T = TypeVar("T")
V = TypeVar("V")
S = TypeVar("S", bound=Hashable)


def dictify(f: Callable[..., Iterator[tuple[T, V]]]) -> Callable[..., dict[T, V]]:
    def wrapper(*args: Any, **kwargs: Any) -> dict[T, V]:
        return dict(f(*args, **kwargs))

    return functools.update_wrapper(wrapper, f)


def listify(f: Callable[..., Iterable[T]]) -> Callable[..., list[T]]:
    def wrapper(*args: Any, **kwargs: Any) -> list[T]:
        return list(f(*args, **kwargs))

    return functools.update_wrapper(wrapper, f)


def tuplify(f: Callable[..., Iterable[T]]) -> Callable[..., tuple[T, ...]]:
    def wrapper(*args: Any, **kwargs: Any) -> tuple[T, ...]:
        return tuple(f(*args, **kwargs))

    return functools.update_wrapper(wrapper, f)


def one_zero(b: bool) -> str:
    return "1" if b else "0"


def is_power_of_2(x: int) -> bool:
    return x > 0 and (x & x - 1 == 0)


def round_up(x: int, blocksize: int = 4096) -> int:
    return (x + blocksize - 1) // blocksize * blocksize


def startswith(s: str, prefix: str) -> Optional[str]:
    if s.startswith(prefix):
        return s.removeprefix(prefix)
    return None


@dictify
def read_env_file(path: PathString) -> Iterator[tuple[str, str]]:
    with Path(path).open() as f:
        for line_number, line in enumerate(f, start=1):
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            if m := re.match(r"([A-Z][A-Z_0-9]+)=(.*)", line):
                name, val = m.groups()
                if val and val[0] in "\"'":
                    val = ast.literal_eval(val)
                yield name, val
            else:
                logging.info(f"{path}:{line_number}: bad line {line!r}")


def format_rlimit(rlimit: int) -> str:
    limits = resource.getrlimit(rlimit)
    soft = "infinity" if limits[0] == resource.RLIM_INFINITY else str(limits[0])
    hard = "infinity" if limits[1] == resource.RLIM_INFINITY else str(limits[1])
    return f"{soft}:{hard}"


def sort_packages(packages: Iterable[str]) -> list[str]:
    """Sorts packages: normal first, paths second, conditional third"""

    m = {"(": 2, "/": 1}
    return sorted(packages, key=lambda name: (m.get(name[0], 0), name))


def flatten(lists: Iterable[Iterable[T]]) -> list[T]:
    """Flatten a sequence of sequences into a single list."""
    return list(itertools.chain.from_iterable(lists))


@contextlib.contextmanager
def chdir(directory: PathString) -> Iterator[None]:
    old = Path.cwd()

    if old == directory:
        yield
        return

    try:
        os.chdir(directory)
        yield
    finally:
        os.chdir(old)


def make_executable(*paths: Path) -> None:
    for path in paths:
        st = path.stat()
        os.chmod(path, st.st_mode | stat.S_IEXEC)


@contextlib.contextmanager
def flock(path: Path, flags: int = fcntl.LOCK_EX) -> Iterator[int]:
    fd = os.open(path, os.O_CLOEXEC|os.O_RDONLY)
    try:
        fcntl.fcntl(fd, fcntl.FD_CLOEXEC)
        logging.debug(f"Acquiring lock on {path}")
        fcntl.flock(fd, flags)
        logging.debug(f"Acquired lock on {path}")
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def flock_or_die(path: Path) -> Iterator[Path]:
    try:
        with flock(path, fcntl.LOCK_EX|fcntl.LOCK_NB):
            yield path
    except OSError as e:
        if e.errno != errno.EWOULDBLOCK:
            raise e

        die(f"Cannot lock {path} as it is locked by another process",
            hint="Maybe another mkosi process is still using it? Use Ephemeral=yes to enable booting multiple "
                 "instances of the same image")


@contextlib.contextmanager
def scopedenv(env: Mapping[str, Any]) -> Iterator[None]:
    old = copy.deepcopy(os.environ)
    os.environ |= env

    # python caches the default temporary directory so when we might modify TMPDIR we have to make sure it
    # gets recalculated (see https://docs.python.org/3/library/tempfile.html#tempfile.tempdir).
    tempfile.tempdir = None

    try:
        yield
    finally:
        os.environ = old
        tempfile.tempdir = None


class StrEnum(enum.Enum):
    def __str__(self) -> str:
        assert isinstance(self.value, str)
        return self.value

    # Used by enum.auto() to get the next value.
    @staticmethod
    def _generate_next_value_(name: str, start: int, count: int, last_values: Sequence[str]) -> str:
        return name.replace("_", "-")

    @classmethod
    def values(cls) -> list[str]:
        return list(s.replace("_", "-") for s in map(str, cls.__members__))


@contextlib.contextmanager
def umask(mask: int) -> Iterator[None]:
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)


def parents_below(path: Path, below: Path) -> list[Path]:
    parents = list(path.parents)
    return parents[:parents.index(below)]


@contextlib.contextmanager
def resource_path(mod: ModuleType) -> Iterator[Path]:

    # We backport as_file() from python 3.12 here temporarily since it added directory support.
    # TODO: Remove once minimum python version is 3.12.

    # SPDX-License-Identifier: PSF-2.0
    # Copied from https://github.com/python/cpython/blob/main/Lib/importlib/resources/_common.py

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

    t = importlib.resources.files(mod)
    with as_file(t) as p:
        # Make sure any temporary directory that the resources are unpacked in is accessible to the invoking user so
        # that any commands executed as the invoking user can access files within it.
        if (
            p.parent.parent == Path(os.getenv("TMPDIR", "/tmp")) and
            stat.S_IMODE(p.parent.stat().st_mode) == 0o700
        ):
            p.parent.chmod(0o755)

        yield p


def hash_file(path: Path) -> str:
    # TODO Replace with hashlib.file_digest after dropping support for Python 3.10.
    bs = 16 * 1024**2
    h = hashlib.sha256()

    with path.open("rb") as sf:
        while (buf := sf.read(bs)):
            h.update(buf)

    return h.hexdigest()


def try_or(fn: Callable[..., T], exception: type[Exception], default: T) -> T:
    try:
        return fn()
    except exception:
        return default


def groupby(seq: Sequence[T], key: Callable[[T], S]) -> list[tuple[S, list[T]]]:
    grouped: dict[S, list[T]] = {}

    for i in seq:
        k = key(i)

        if k not in grouped:
            grouped[k] = []

        grouped[k].append(i)

    return [(key, group) for key, group in grouped.items()]
