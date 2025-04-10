# SPDX-License-Identifier: LGPL-2.1-or-later

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
from typing import IO, Any, Callable, Optional, Protocol, TypeVar, Union

from mkosi.backport import as_file
from mkosi.log import die

T = TypeVar("T")
V = TypeVar("V")
S = TypeVar("S", bound=Hashable)

# Borrowed from https://github.com/python/typeshed/blob/3d14016085aed8bcf0cf67e9e5a70790ce1ad8ea/stdlib/3/subprocess.pyi#L24
_FILE = Union[None, int, IO[Any]]
PathString = Union[Path, str]

# Borrowed from
# https://github.com/python/typeshed/blob/ec52bf1adde1d3183d0595d2ba982589df48dff1/stdlib/_typeshed/__init__.pyi#L19
# and
# https://github.com/python/typeshed/blob/ec52bf1adde1d3183d0595d2ba982589df48dff1/stdlib/_typeshed/__init__.pyi#L224
_T_co = TypeVar("_T_co", covariant=True)


class SupportsRead(Protocol[_T_co]):
    def read(self, __length: int = ...) -> _T_co: ...


def dictify(f: Callable[..., Iterator[tuple[T, V]]]) -> Callable[..., dict[T, V]]:
    def wrapper(*args: Any, **kwargs: Any) -> dict[T, V]:
        return dict(f(*args, **kwargs))

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
    fd = os.open(path, os.O_CLOEXEC | os.O_RDONLY)
    try:
        fcntl.fcntl(fd, fcntl.FD_CLOEXEC)
        logging.debug(f"Acquiring lock on {path}")
        fcntl.flock(fd, flags)
        logging.debug(f"Acquired lock on {path}")
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def flock_or_die(path: Path, flags: int = fcntl.LOCK_EX) -> Iterator[Path]:
    try:
        with flock(path, flags | fcntl.LOCK_NB):
            yield path
    except OSError as e:
        if e.errno != errno.EWOULDBLOCK:
            raise e

        die(
            f"Cannot lock {path} as it is locked by another process",
            hint="Maybe another mkosi process is still using it? Use Ephemeral=yes to enable booting "
            "multiple instances of the same image",
        )


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

    @classmethod
    def choices(cls) -> list[str]:
        return [*cls.values(), ""]


def parents_below(path: Path, below: Path) -> list[Path]:
    parents = list(path.parents)
    return parents[: parents.index(below)]


@contextlib.contextmanager
def resource_path(mod: ModuleType) -> Iterator[Path]:
    t = importlib.resources.files(mod)
    with as_file(t) as p:
        # Make sure any temporary directory that the resources are unpacked in is accessible to the invoking
        # user so that any commands executed as the invoking user can access files within it.
        if (
            p.parent.parent == Path(os.getenv("TMPDIR", "/tmp"))
            and stat.S_IMODE(p.parent.stat().st_mode) == 0o700
        ):
            p.parent.chmod(0o755)

        yield p


def hash_file(path: Path) -> str:
    # TODO Replace with hashlib.file_digest after dropping support for Python 3.10.
    h = hashlib.sha256()
    b = bytearray(16 * 1024**2)
    mv = memoryview(b)

    with path.open("rb", buffering=0) as f:
        while n := f.readinto(mv):
            h.update(mv[:n])

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


def current_home_dir() -> Optional[Path]:
    home = Path(h) if (h := os.getenv("HOME")) else None

    if Path.cwd() in (Path("/"), Path("/home")):
        return home

    if Path.cwd().is_relative_to("/root"):
        return Path("/root")

    if Path.cwd().is_relative_to("/home"):
        # `Path.parents` only supports slices and negative indexing from Python 3.10 onwards.
        # TODO: Remove list() when we depend on Python 3.10 or newer.
        return list(Path.cwd().parents)[-3]

    return home


def unique(seq: Sequence[T]) -> list[T]:
    return list(dict.fromkeys(seq))


def mandatory_variable(name: str) -> str:
    try:
        return os.environ[name]
    except KeyError:
        die(f"${name} must be set in the environment")
