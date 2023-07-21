# SPDX-License-Identifier: LGPL-2.1+

import ast
import contextlib
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
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")
V = TypeVar("V")


class PackageType(enum.Enum):
    rpm = 1
    deb = 2
    pkg = 3
    ebuild = 5


class Verb(enum.Enum):
    build   = "build"
    clean   = "clean"
    summary = "summary"
    shell   = "shell"
    boot    = "boot"
    qemu    = "qemu"
    ssh     = "ssh"
    serve   = "serve"
    bump    = "bump"
    help    = "help"
    genkey  = "genkey"

    # Defining __str__ is required to get "print_help()" output to include the human readable (values) of Verb.
    def __str__(self) -> str:
        return self.value


class Distribution(enum.Enum):
    package_type: PackageType

    fedora       = "fedora", PackageType.rpm
    debian       = "debian", PackageType.deb
    ubuntu       = "ubuntu", PackageType.deb
    arch         = "arch", PackageType.pkg
    opensuse     = "opensuse", PackageType.rpm
    mageia       = "mageia", PackageType.rpm
    centos       = "centos", PackageType.rpm
    openmandriva = "openmandriva", PackageType.rpm
    rocky        = "rocky", PackageType.rpm
    alma         = "alma", PackageType.rpm
    gentoo       = "gentoo", PackageType.ebuild

    def __new__(cls, name: str, package_type: PackageType) -> "Distribution":
        # This turns the list above into enum entries with .package_type attributes.
        # See https://docs.python.org/3.9/library/enum.html#when-to-use-new-vs-init
        # for an explanation.
        entry = object.__new__(cls)
        entry._value_ = name
        entry.package_type = package_type
        return entry

    def __str__(self) -> str:
        return self.name

    def is_centos_variant(self) -> bool:
        return self in (Distribution.centos, Distribution.alma, Distribution.rocky)


class Compression(enum.Enum):
    none = None
    zst = "zst"
    xz = "xz"
    bz2 = "bz2"
    gz = "gz"
    lz4 = "lz4"
    lzma = "lzma"

    def __str__(self) -> str:
        return str(self.value).lower()

    def __bool__(self) -> bool:
        return bool(self.value)


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


def detect_distribution() -> tuple[Optional[Distribution], Optional[str]]:
    try:
        os_release = read_os_release()
    except FileNotFoundError:
        return None, None

    dist_id = os_release.get("ID", "linux")
    dist_id_like = os_release.get("ID_LIKE", "").split()
    version = os_release.get("VERSION", None)
    version_id = os_release.get("VERSION_ID", None)
    version_codename = os_release.get("VERSION_CODENAME", None)
    extracted_codename = None

    if version:
        # extract Debian release codename
        m = re.search(r"\((.*?)\)", version)
        if m:
            extracted_codename = m.group(1)

    d: Optional[Distribution] = None
    for the_id in [dist_id, *dist_id_like]:
        d = Distribution.__members__.get(the_id, None)
        if d is not None:
            break

    if d in {Distribution.debian, Distribution.ubuntu} and (version_codename or extracted_codename):
        version_id = version_codename or extracted_codename

    return d, version_id


def is_dnf_distribution(d: Distribution) -> bool:
    return d in (
        Distribution.fedora,
        Distribution.mageia,
        Distribution.centos,
        Distribution.openmandriva,
        Distribution.rocky,
        Distribution.alma,
    )


def is_apt_distribution(d: Distribution) -> bool:
    return d in (Distribution.debian, Distribution.ubuntu)


def is_portage_distribution(d: Distribution) -> bool:
    return d in (Distribution.gentoo,)


class OutputFormat(str, enum.Enum):
    directory = "directory"
    tar = "tar"
    cpio = "cpio"
    disk = "disk"
    none = "none"


class ManifestFormat(str, enum.Enum):
    json      = "json"       # the standard manifest in json format
    changelog = "changelog"  # human-readable text file with package changelogs



def format_rlimit(rlimit: int) -> str:
    limits = resource.getrlimit(rlimit)
    soft = "infinity" if limits[0] == resource.RLIM_INFINITY else str(limits[0])
    hard = "infinity" if limits[1] == resource.RLIM_INFINITY else str(limits[1])
    return f"{soft}:{hard}"


def tmp_dir() -> Path:
    path = os.environ.get("TMPDIR") or "/var/tmp"
    return Path(path)


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
def chdir(directory: Path) -> Iterator[None]:
    old = Path.cwd()

    if old == directory:
        yield
        return

    try:
        os.chdir(directory)
        yield
    finally:
        os.chdir(old)


def qemu_check_kvm_support() -> bool:
    kvm = Path("/dev/kvm")
    if not kvm.is_char_device():
        return False
    # some CI runners may present a non-working KVM device
    try:
        with kvm.open("r+b"):
            return True
    except OSError:
        return False


def qemu_check_vsock_support(log: bool) -> bool:
    try:
        os.open("/dev/vhost-vsock", os.O_RDWR|os.O_CLOEXEC)
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
