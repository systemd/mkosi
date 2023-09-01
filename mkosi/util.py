# SPDX-License-Identifier: LGPL-2.1+

import ast
import contextlib
import copy
import enum
import errno
import fcntl
import functools
import importlib
import itertools
import logging
import os
import pwd
import re
import resource
import stat
import sys
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

from mkosi.types import PathString

T = TypeVar("T")
V = TypeVar("V")


def dictify(f: Callable[..., Iterator[tuple[T, V]]]) -> Callable[..., dict[T, V]]:
    def wrapper(*args: Any, **kwargs: Any) -> dict[T, V]:
        return dict(f(*args, **kwargs))

    return functools.update_wrapper(wrapper, f)


@dictify
def read_os_release() -> Iterator[tuple[str, str]]:
    try:
        filename = "/etc/os-release"
        f = open(filename)
    except FileNotFoundError:
        filename = "/usr/lib/os-release"
        f = open(filename)

    with f:
        for line_number, line in enumerate(f, start=1):
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            if (m := re.match(r"([A-Z][A-Z_0-9]+)=(.*)", line)):
                name, val = m.groups()
                if val and val[0] in "\"'":
                    val = ast.literal_eval(val)
                yield name, val
            else:
                print(f"{filename}:{line_number}: bad line {line!r}", file=sys.stderr)


def format_rlimit(rlimit: int) -> str:
    limits = resource.getrlimit(rlimit)
    soft = "infinity" if limits[0] == resource.RLIM_INFINITY else str(limits[0])
    hard = "infinity" if limits[1] == resource.RLIM_INFINITY else str(limits[1])
    return f"{soft}:{hard}"


def sort_packages(packages: Iterable[str]) -> list[str]:
    """Sorts packages: normal first, paths second, conditional third"""

    m = {"(": 2, "/": 1}
    sort = lambda name: (m.get(name[0], 0), name)
    return sorted(packages, key=sort)


def flatten(lists: Iterable[Iterable[T]]) -> list[T]:
    """Flatten a sequence of sequences into a single list."""
    return list(itertools.chain.from_iterable(lists))


class InvokingUser:
    @staticmethod
    def _uid_from_env() -> Optional[int]:
        uid = os.getenv("SUDO_UID") or os.getenv("PKEXEC_UID")
        return int(uid) if uid is not None else None

    @classmethod
    def uid(cls) -> int:
        return cls._uid_from_env() or os.getuid()

    @classmethod
    def uid_gid(cls) -> tuple[int, int]:
        if (uid := cls._uid_from_env()) is not None:
            gid = int(os.getenv("SUDO_GID", pwd.getpwuid(uid).pw_gid))
            return uid, gid
        return os.getuid(), os.getgid()

    @classmethod
    def name(cls) -> str:
        return pwd.getpwuid(cls.uid()).pw_name

    @classmethod
    def home(cls) -> Path:
        return Path(f"~{cls.name()}").expanduser()

    @classmethod
    def is_running_user(cls) -> bool:
        return cls.uid() == os.getuid()


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


def qemu_check_kvm_support(log: bool) -> bool:
    # some CI runners may present a non-working KVM device
    try:
        os.close(os.open("/dev/kvm", os.O_RDWR|os.O_CLOEXEC))
    except OSError as e:
        if e.errno == errno.ENOENT:
            if log:
                logging.warning("/dev/kvm not found. Not using KVM acceleration.")
            return False
        elif e.errno in (errno.EPERM, errno.EACCES):
            if log:
                logging.warning("Permission denied to access /dev/kvm. Not using KVM acceleration")
            return False

        raise e

    return True


def qemu_check_vsock_support(log: bool) -> bool:
    try:
        os.close(os.open("/dev/vhost-vsock", os.O_RDWR|os.O_CLOEXEC))
    except OSError as e:
        if e.errno == errno.ENOENT:
            if log:
                logging.warning("/dev/vhost-vsock not found. Not adding a vsock device to the virtual machine.")
            return False
        elif e.errno in (errno.EPERM, errno.EACCES):
            if log:
                logging.warning("Permission denied to access /dev/vhost-vsock. Not adding a vsock device to the virtual machine.")
            return False

        raise e

    return True


def format_bytes(num_bytes: int) -> str:
    if num_bytes >= 1024**3:
        return f"{num_bytes/1024**3 :0.1f}G"
    if num_bytes >= 1024**2:
        return f"{num_bytes/1024**2 :0.1f}M"
    if num_bytes >= 1024:
        return f"{num_bytes/1024 :0.1f}K"

    return f"{num_bytes}B"


def make_executable(path: Path) -> None:
    st = path.stat()
    os.chmod(path, st.st_mode | stat.S_IEXEC)


def try_import(module: str) -> None:
    try:
        importlib.import_module(module)
    except ModuleNotFoundError:
        pass


@contextlib.contextmanager
def flock(path: Path) -> Iterator[int]:
    fd = os.open(path, os.O_CLOEXEC|os.O_RDONLY)
    try:
        fcntl.fcntl(fd, fcntl.FD_CLOEXEC)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        os.close(fd)


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
        return list(map(str, cls))


def one_zero(b: bool) -> str:
    return "1" if b else "0"


@contextlib.contextmanager
def umask(mask: int) -> Iterator[None]:
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)
