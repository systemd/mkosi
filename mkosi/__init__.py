# SPDX-License-Identifier: LGPL-2.1+

import argparse
import collections
import configparser
import contextlib
import copy
import crypt
import ctypes
import ctypes.util
import datetime
import enum
import errno
import fcntl
import getpass
import glob
import time
import hashlib
import os
import platform
import shlex
import shutil
import signal
import stat
import string
import subprocess
import sys
import tempfile
import json
import urllib.request
import re
import urllib.parse
import uuid
from subprocess import DEVNULL, PIPE
from textwrap import dedent
from typing import (
    IO,
    Any,
    BinaryIO,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    NamedTuple,
    NoReturn,
    Optional,
    Sequence,
    Set,
    TextIO,
    Tuple,
    TypeVar,
    Union,
    cast,
    TYPE_CHECKING,
    ContextManager,
)
from types import FrameType

from .printer import MkosiPrinter


__version__ = "9"


# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[Any]
    TempDir = tempfile.TemporaryDirectory[str]
else:
    CompletedProcess = subprocess.CompletedProcess
    TempDir = tempfile.TemporaryDirectory


MKOSI_COMMANDS_CMDLINE = ("build", "shell", "boot", "qemu", "ssh")
MKOSI_COMMANDS_NEED_BUILD = ("shell", "boot", "qemu")
MKOSI_COMMANDS_SUDO = ("build", "clean", "shell", "boot", "qemu")
MKOSI_COMMANDS = ("build", "clean", "help", "summary", "genkey") + MKOSI_COMMANDS_CMDLINE

DRACUT_SYSTEMD_EXTRAS = [
    "/usr/lib/systemd/systemd-veritysetup",
    "/usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "/usr/bin/systemd-repart",
    "/usr/lib/systemd/system/systemd-repart.service",
    "/usr/lib/systemd/system/initrd-root-fs.target.wants/systemd-repart.service",
]

DRACUT_UNIFIED_KERNEL_INSTALL = """\
#!/bin/bash -e

COMMAND="$1"
KERNEL_VERSION="$2"
BOOT_DIR_ABS="$3"
KERNEL_IMAGE="$4"
ROOTHASH="${5:-}"

# If KERNEL_INSTALL_MACHINE_ID is defined but empty, BOOT_DIR_ABS is a fake directory so let's skip creating
# the unified kernel image.
if [[ -z "${KERNEL_INSTALL_MACHINE_ID-unset}" ]]; then
    exit 0
fi

# Strip machine ID and kernel version to get the boot directory.
PREFIX=$(dirname $(dirname "$BOOT_DIR_ABS"))

if [[ -n "$ROOTHASH" ]]; then
    BOOT_BINARY="${PREFIX}/EFI/Linux/linux-${KERNEL_VERSION}-${ROOTHASH}.efi"
else
    BOOT_BINARY="${PREFIX}/EFI/Linux/linux-${KERNEL_VERSION}.efi"
fi

case "$COMMAND" in
    add)
        if [[ -f /etc/kernel/cmdline ]]; then
            read -r -d '' BOOT_OPTIONS < /etc/kernel/cmdline || true
        elif [[ -f /usr/lib/kernel/cmdline ]]; then
            read -r -d '' BOOT_OPTIONS < /usr/lib/kernel/cmdline || true
        else
            read -r -d '' BOOT_OPTIONS < /proc/cmdline || true
        fi

        if [[ -n "$ROOTHASH" ]]; then
            BOOT_OPTIONS="${BOOT_OPTIONS} roothash=${ROOTHASH}"
        fi

        if [[ -n "$KERNEL_IMAGE" ]]; then
            DRACUT_KERNEL_IMAGE_OPTION="--kernel-image ${KERNEL_IMAGE}"
        else
            DRACUT_KERNEL_IMAGE_OPTION=""
        fi

        dracut \\
            --uefi \\
            --kver "$KERNEL_VERSION" \\
            $DRACUT_KERNEL_IMAGE_OPTION \\
            --kernel-cmdline "$BOOT_OPTIONS" \\
            --force \\
            "$BOOT_BINARY"
        ;;
    remove)
        rm -f -- "$BOOT_BINARY"
        ;;
esac
"""


# This global should be initialized after parsing arguments
arg_debug = ()


class MkosiException(Exception):
    """Leads to sys.exit"""


def print_running_cmd(cmdline: Iterable[str]) -> None:
    MkosiPrinter.print_step("Running command:")
    MkosiPrinter.print_step(" ".join(shlex.quote(x) for x in cmdline) + "\n")


@contextlib.contextmanager
def delay_interrupt() -> Generator[None, None, None]:
    # CTRL+C is sent to the entire process group. We delay its handling in mkosi itself so the subprocess can
    # exit cleanly before doing mkosi's cleanup. If we don't do this, we get device or resource is busy
    # errors when unmounting stuff later on during cleanup. We only delay a single CTRL+C interrupt so that a
    # user can always exit mkosi even if a subprocess hangs by pressing CTRL+C twice.
    interrupted = False

    def handler(signal: int, frame: FrameType) -> None:
        nonlocal interrupted
        if interrupted:
            raise KeyboardInterrupt()
        else:
            interrupted = True

    s = signal.signal(signal.SIGINT, handler)

    try:
        yield
    finally:
        signal.signal(signal.SIGINT, s)

        if interrupted:
            die("Interrupted")


# Borrowed from https://github.com/python/typeshed/blob/3d14016085aed8bcf0cf67e9e5a70790ce1ad8ea/stdlib/3/subprocess.pyi#L24
_FILE = Union[None, int, IO[Any]]


def run(
    cmdline: List[str],
    check: bool = True,
    stdout: _FILE = None,
    stderr: _FILE = None,
    **kwargs: Any,
) -> CompletedProcess:
    if "run" in arg_debug:
        MkosiPrinter.info("+ " + " ".join(shlex.quote(x) for x in cmdline))

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess output on stderr since we do so as well
        # for mkosi's own output.
        stdout = sys.stderr

    try:
        with delay_interrupt():
            return subprocess.run(cmdline, check=check, stdout=stdout, stderr=stderr, **kwargs)
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")


def die(message: str) -> NoReturn:
    MkosiPrinter.warn(f"Error: {message}")
    raise MkosiException(message)


def warn(message: str) -> None:
    MkosiPrinter.warn(f"Warning: {message}")


def tmp_dir() -> str:
    return os.environ.get("TMPDIR") or "/var/tmp"


class CommandLineArguments(argparse.Namespace):
    """Type-hinted storage for command line arguments."""

    swap_partno: Optional[int] = None
    esp_partno: Optional[int] = None
    xbootldr_partno: Optional[int] = None
    minimize: bool = False

    def generated_root(self) -> bool:
        """Returns whether this configuration means we need to generate a file system from a prepared tree

        This is needed for anything squashfs and when root minimization is required."""
        return self.minimize or self.output_format.is_squashfs()


class SourceFileTransfer(enum.Enum):
    copy_all = "copy-all"
    copy_git_cached = "copy-git-cached"
    copy_git_others = "copy-git-others"
    copy_git_more = "copy-git-more"
    mount = "mount"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def doc(cls) -> Dict["SourceFileTransfer", str]:
        return {
            cls.copy_all: "normal file copy",
            cls.copy_git_cached: "use git-ls-files --cached, ignoring any file that git itself ignores",
            cls.copy_git_others: "use git-ls-files --others, ignoring any file that git itself ignores",
            cls.copy_git_more: "use git-ls-files --cached, ignoring any file that git itself ignores, but include the .git/ directory",
            cls.mount: "bind mount source files into the build image",
        }


class OutputFormat(enum.Enum):
    directory = enum.auto()
    subvolume = enum.auto()
    tar = enum.auto()

    gpt_ext4 = enum.auto()
    gpt_xfs = enum.auto()
    gpt_btrfs = enum.auto()
    gpt_squashfs = enum.auto()

    plain_squashfs = enum.auto()

    # Kept for backwards compatibility
    raw_ext4 = raw_gpt = gpt_ext4
    raw_xfs = gpt_xfs
    raw_btrfs = gpt_btrfs
    raw_squashfs = gpt_squashfs

    def __repr__(self) -> str:
        """Return the member name without the class name"""
        return self.name

    def __str__(self) -> str:
        """Return the member name without the class name"""
        return self.name

    @classmethod
    def from_string(cls, name: str) -> "OutputFormat":
        """A convenience method to be used with argparse"""
        try:
            return cls[name]
        except KeyError:
            # this let's argparse generate a proper error message
            return name  # type: ignore

    def is_disk_rw(self) -> bool:
        "Output format is a disk image with a parition table and a writable filesystem"
        return self in (OutputFormat.gpt_ext4, OutputFormat.gpt_xfs, OutputFormat.gpt_btrfs)

    def is_disk(self) -> bool:
        "Output format is a disk image with a partition table"
        return self.is_disk_rw() or self == OutputFormat.gpt_squashfs

    def is_squashfs(self) -> bool:
        "The output format contains a squashfs partition"
        return self in {OutputFormat.gpt_squashfs, OutputFormat.plain_squashfs}

    def can_minimize(self) -> bool:
        "The output format can be 'minimized'"
        return self in (OutputFormat.gpt_ext4, OutputFormat.gpt_btrfs)

    def needed_kernel_module(self) -> str:
        if self == OutputFormat.gpt_btrfs:
            return "btrfs"
        elif self == OutputFormat.gpt_squashfs or self == OutputFormat.plain_squashfs:
            return "squashfs"
        elif self == OutputFormat.gpt_xfs:
            return "xfs"
        else:
            return "ext4"


class Distribution(enum.Enum):
    fedora = 1
    debian = 2
    ubuntu = 3
    arch = 4
    opensuse = 5
    mageia = 6
    centos = 7
    centos_epel = 8
    clear = 9
    photon = 10
    openmandriva = 11

    def __str__(self) -> str:
        return self.name


# fmt: off
GPT_ROOT_X86           = uuid.UUID("44479540f29741b29af7d131d5f0458a")  # NOQA: E221
GPT_ROOT_X86_64        = uuid.UUID("4f68bce3e8cd4db196e7fbcaf984b709")  # NOQA: E221
GPT_ROOT_ARM           = uuid.UUID("69dad7102ce44e3cb16c21a1d49abed3")  # NOQA: E221
GPT_ROOT_ARM_64        = uuid.UUID("b921b0451df041c3af444c6f280d3fae")  # NOQA: E221
GPT_ROOT_IA64          = uuid.UUID("993d8d3df80e4225855a9daf8ed7ea97")  # NOQA: E221
GPT_ESP                = uuid.UUID("c12a7328f81f11d2ba4b00a0c93ec93b")  # NOQA: E221
GPT_BIOS               = uuid.UUID("2168614864496e6f744e656564454649")  # NOQA: E221
GPT_SWAP               = uuid.UUID("0657fd6da4ab43c484e50933c84b4f4f")  # NOQA: E221
GPT_HOME               = uuid.UUID("933ac7e12eb44f13b8440e14e2aef915")  # NOQA: E221
GPT_SRV                = uuid.UUID("3b8f842520e04f3b907f1a25a76f98e8")  # NOQA: E221
GPT_XBOOTLDR           = uuid.UUID("bc13c2ff59e64262a352b275fd6f7172")  # NOQA: E221
GPT_ROOT_X86_VERITY    = uuid.UUID("d13c5d3bb5d1422ab29f9454fdc89d76")  # NOQA: E221
GPT_ROOT_X86_64_VERITY = uuid.UUID("2c7357edebd246d9aec123d437ec2bf5")  # NOQA: E221
GPT_ROOT_ARM_VERITY    = uuid.UUID("7386cdf2203c47a9a498f2ecce45a2d6")  # NOQA: E221
GPT_ROOT_ARM_64_VERITY = uuid.UUID("df3300ced69f4c92978c9bfb0f38d820")  # NOQA: E221
GPT_ROOT_IA64_VERITY   = uuid.UUID("86ed10d5b60745bb8957d350f23d0571")  # NOQA: E221
GPT_TMP                = uuid.UUID("7ec6f5573bc54acab29316ef5df639d1")  # NOQA: E221
GPT_VAR                = uuid.UUID("4d21b016b53445c2a9fb5c16e091fd2d")  # NOQA: E221
# fmt: on


# This is a non-formatted partition used to store the second stage
# part of the bootloader because it doesn't necessarily fits the MBR
# available space. 1MiB is more than enough for our usages and there's
# little reason for customization since it only stores the bootloader and
# not user-owned configuration files or kernels. See
# https://en.wikipedia.org/wiki/BIOS_boot_partition
# and https://www.gnu.org/software/grub/manual/grub/html_node/BIOS-installation.html
BIOS_PARTITION_SIZE = 1024 * 1024

CLONE_NEWNS = 0x00020000

FEDORA_KEYS_MAP = {
    "23": "34EC9CBA",
    "24": "81B46521",
    "25": "FDB19C98",
    "26": "64DAB85D",
    "27": "F5282EE4",
    "28": "9DB62FB1",
    "29": "429476B4",
    "30": "CFC659B9",
    "31": "3C3359C4",
    "32": "12C944D0",
}

# 1 MB at the beginning of the disk for the GPT disk label, and
# another MB at the end (this is actually more than needed.)
GPT_HEADER_SIZE = 1024 * 1024
GPT_FOOTER_SIZE = 1024 * 1024


# Debian calls their architectures differently, so when calling debootstrap we
# will have to map to their names
DEBIAN_ARCHITECTURES = {
    "x86_64": "amd64",
    "x86": "i386",
    "aarch64": "arm64",
    "armhfp": "armhf",
}


class GPTRootTypePair(NamedTuple):
    root: uuid.UUID
    verity: uuid.UUID


def gpt_root_native(arch: Optional[str]) -> GPTRootTypePair:
    """The tag for the native GPT root partition for the given architecture

    Returns a tuple of two tags: for the root partition and for the
    matching verity partition.
    """
    if arch is None:
        arch = platform.machine()
    if arch == "x86_64":
        return GPTRootTypePair(GPT_ROOT_X86_64, GPT_ROOT_X86_64_VERITY)
    elif arch == "aarch64":
        return GPTRootTypePair(GPT_ROOT_ARM_64, GPT_ROOT_ARM_64_VERITY)
    elif arch == "armv7l":
        return GPTRootTypePair(GPT_ROOT_ARM, GPT_ROOT_ARM_VERITY)
    else:
        die(f"Unknown architecture {arch}.")


def unshare(flags: int) -> None:
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        die("Could not find libc")
    libc = ctypes.CDLL(libc_name, use_errno=True)

    if libc.unshare(ctypes.c_int(flags)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def format_bytes(num_bytes: int) -> str:
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes/1024**3 :0.1f}G"
    if num_bytes >= 1024 * 1024:
        return f"{num_bytes/1024**2 :0.1f}M"
    if num_bytes >= 1024:
        return f"{num_bytes/1024 :0.1f}K"

    return f"{num_bytes}B"


def roundup512(x: int) -> int:
    return (x + 511) & ~511


def mkdir_last(path: str, mode: int = 0o777) -> str:
    """Create directory path

    Only the final component will be created, so this is different than mkdirs().
    """
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        if not os.path.isdir(path):
            raise
    return path


# fmt: off
_IOC_NRBITS   =  8  # NOQA: E221,E222
_IOC_TYPEBITS =  8  # NOQA: E221,E222
_IOC_SIZEBITS = 14  # NOQA: E221,E222
_IOC_DIRBITS  =  2  # NOQA: E221,E222

_IOC_NRSHIFT   = 0  # NOQA: E221
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS  # NOQA: E221
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS  # NOQA: E221
_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS  # NOQA: E221

_IOC_NONE  = 0  # NOQA: E221
_IOC_WRITE = 1  # NOQA: E221
_IOC_READ  = 2  # NOQA: E221
# fmt: on


def _IOC(dir_rw: int, type_drv: int, nr: int, argtype: str) -> int:
    size = {"int": 4, "size_t": 8}[argtype]
    return dir_rw << _IOC_DIRSHIFT | type_drv << _IOC_TYPESHIFT | nr << _IOC_NRSHIFT | size << _IOC_SIZESHIFT


def _IOW(type_drv: int, nr: int, size: str) -> int:
    return _IOC(_IOC_WRITE, type_drv, nr, size)


FICLONE = _IOW(0x94, 9, "int")


@contextlib.contextmanager
def open_close(path: str, flags: int, mode: int = 0o664) -> Generator[int, None, None]:
    fd = os.open(path, flags | os.O_CLOEXEC, mode)
    try:
        yield fd
    finally:
        os.close(fd)


def _reflink(oldfd: int, newfd: int) -> None:
    fcntl.ioctl(newfd, FICLONE, oldfd)


def copy_fd(oldfd: int, newfd: int) -> None:
    try:
        _reflink(oldfd, newfd)
    except OSError as e:
        if e.errno not in {errno.EXDEV, errno.EOPNOTSUPP}:
            raise
        shutil.copyfileobj(open(oldfd, "rb", closefd=False), open(newfd, "wb", closefd=False))


def copy_file_object(oldobject: BinaryIO, newobject: BinaryIO) -> None:
    try:
        _reflink(oldobject.fileno(), newobject.fileno())
    except OSError as e:
        if e.errno not in {errno.EXDEV, errno.EOPNOTSUPP}:
            raise
        shutil.copyfileobj(oldobject, newobject)


def copy_symlink(oldpath: str, newpath: str) -> None:
    src = os.readlink(oldpath)
    os.symlink(src, newpath)


def copy_file(oldpath: str, newpath: str) -> None:
    if os.path.islink(oldpath):
        copy_symlink(oldpath, newpath)
        return

    with open_close(oldpath, os.O_RDONLY) as oldfd:
        st = os.stat(oldfd)

        try:
            with open_close(newpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, st.st_mode) as newfd:
                copy_fd(oldfd, newfd)
        except FileExistsError:
            os.unlink(newpath)
            with open_close(newpath, os.O_WRONLY | os.O_CREAT, st.st_mode) as newfd:
                copy_fd(oldfd, newfd)
    shutil.copystat(oldpath, newpath, follow_symlinks=False)


def symlink_f(target: str, path: str) -> None:
    try:
        os.symlink(target, path)
    except FileExistsError:
        os.unlink(path)
        os.symlink(target, path)


def copy_path(oldpath: str, newpath: str) -> None:
    try:
        mkdir_last(newpath)
    except FileExistsError:
        # something that is not a directory already exists
        os.unlink(newpath)
        mkdir_last(newpath)

    for entry in os.scandir(oldpath):
        newentry = os.path.join(newpath, entry.name)
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
    shutil.copystat(oldpath, newpath, follow_symlinks=True)


@contextlib.contextmanager
def complete_step(text: str, text2: Optional[str] = None) -> Generator[List[Any], None, None]:
    MkosiPrinter.print_step(text + "...")
    args: List[Any] = []
    yield args
    if text2 is not None:
        MkosiPrinter.print_step(text2.format(*args) + ".")


@complete_step("Detaching namespace")
def init_namespace(args: CommandLineArguments) -> None:
    args.original_umask = os.umask(0o000)
    unshare(CLONE_NEWNS)
    run(["mount", "--make-rslave", "/"])


def setup_workspace(args: CommandLineArguments) -> TempDir:
    MkosiPrinter.print_step("Setting up temporary workspace.")
    if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        d = tempfile.TemporaryDirectory(dir=os.path.dirname(args.output), prefix=".mkosi-")
    else:
        d = tempfile.TemporaryDirectory(dir=tmp_dir(), prefix="mkosi-")

    MkosiPrinter.print_step("Temporary workspace in " + d.name + " is now set up.")
    return d


def btrfs_subvol_create(path: str, mode: int = 0o755) -> None:
    m = os.umask(~mode & 0o7777)
    run(["btrfs", "subvol", "create", path])
    os.umask(m)


def btrfs_subvol_delete(path: str) -> None:
    # Extract the path of the subvolume relative to the filesystem
    c = run(["btrfs", "subvol", "show", path], stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    subvol_path = c.stdout.splitlines()[0]
    # Make the subvolume RW again if it was set RO by btrfs_subvol_delete
    run(["btrfs", "property", "set", path, "ro", "false"])
    # Recursively delete the direct children of the subvolume
    c = run(["btrfs", "subvol", "list", "-o", path], stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
    for line in c.stdout.splitlines():
        if not line:
            continue
        child_subvol_path = line.split(" ", 8)[-1]
        child_path = os.path.normpath(os.path.join(path, os.path.relpath(child_subvol_path, subvol_path)))
        btrfs_subvol_delete(child_path)
    # Delete the subvolume now that all its descendants have been deleted
    run(["btrfs", "subvol", "delete", path], stdout=DEVNULL, stderr=DEVNULL)


def btrfs_subvol_make_ro(path: str, b: bool = True) -> None:
    run(["btrfs", "property", "set", path, "ro", "true" if b else "false"])


@contextlib.contextmanager
def btrfs_forget_stale_devices() -> Generator[None, None, None]:
    # When using cached images (-i), mounting btrfs images would sometimes fail
    # with EEXIST. This is likely because a stale device is leftover somewhere
    # from the previous run. To fix this, we make sure to always clean up stale
    # btrfs devices after unmounting the image.
    try:
        yield
    finally:
        if shutil.which("btrfs"):
            run(["btrfs", "device", "scan", "-u"])


def image_size(args: CommandLineArguments) -> int:
    size = GPT_HEADER_SIZE + GPT_FOOTER_SIZE

    if args.root_size is not None:
        size += args.root_size
    if args.home_size is not None:
        size += args.home_size
    if args.srv_size is not None:
        size += args.srv_size
    if args.var_size is not None:
        size += args.var_size
    if args.tmp_size is not None:
        size += args.tmp_size
    if args.bootable:
        if "uefi" in args.boot_protocols:
            size += args.esp_size
        if "bios" in args.boot_protocols:
            size += BIOS_PARTITION_SIZE
    if args.xbootldr_size is not None:
        size += args.xbootldr_size
    if args.swap_size is not None:
        size += args.swap_size
    if args.verity_size is not None:
        size += args.verity_size

    return size


def disable_cow(path: str) -> None:
    """Disable copy-on-write if applicable on filesystem"""

    run(["chattr", "+C", path], stdout=DEVNULL, stderr=DEVNULL, check=False)


def determine_partition_table(args: CommandLineArguments) -> Tuple[str, bool]:
    pn = 1
    table = "label: gpt\n"
    if args.gpt_first_lba is not None:
        table += f"first-lba: {args.gpt_first_lba:d}\n"
    run_sfdisk = False
    args.esp_partno = None
    args.bios_partno = None

    if args.bootable:
        if "uefi" in args.boot_protocols:
            table += f'size={args.esp_size // 512}, type={GPT_ESP}, name="ESP System Partition"\n'
            args.esp_partno = pn
            pn += 1

        if "bios" in args.boot_protocols:
            table += f'size={BIOS_PARTITION_SIZE // 512}, type={GPT_BIOS}, name="BIOS Boot Partition"\n'
            args.bios_partno = pn
            pn += 1

        run_sfdisk = True

    if args.xbootldr_size is not None:
        table += f'size={args.xbootldr_size // 512}, type={GPT_XBOOTLDR}, name="Boot Loader Partition"\n'
        args.xbootldr_partno = pn
        pn += 1
    else:
        args.xbootldr_partno = None

    if args.swap_size is not None:
        table += f'size={args.swap_size // 512}, type={GPT_SWAP}, name="Swap Partition"\n'
        args.swap_partno = pn
        pn += 1
        run_sfdisk = True
    else:
        args.swap_partno = None

    args.home_partno = None
    args.srv_partno = None
    args.var_partno = None
    args.tmp_partno = None

    if args.output_format != OutputFormat.gpt_btrfs:
        if args.home_size is not None:
            table += f'size={args.home_size // 512}, type={GPT_HOME}, name="Home Partition"\n'
            args.home_partno = pn
            pn += 1
            run_sfdisk = True

        if args.srv_size is not None:
            table += f'size={args.srv_size // 512}, type={GPT_SRV}, name="Server Data Partition"\n'
            args.srv_partno = pn
            pn += 1
            run_sfdisk = True

        if args.var_size is not None:
            table += f'size={args.var_size // 512}, type={GPT_VAR}, name="Variable Data Partition"\n'
            args.var_partno = pn
            pn += 1
            run_sfdisk = True

        if args.tmp_size is not None:
            table += f'size={args.tmp_size // 512}, type={GPT_TMP}, name="Temporary Data Partition"\n'
            args.tmp_partno = pn
            pn += 1
            run_sfdisk = True

    if not args.generated_root():
        table += 'type={}, attrs={}, name="Root Partition"\n'.format(
            gpt_root_native(args.architecture).root,
            "GUID:60" if args.read_only and args.output_format != OutputFormat.gpt_btrfs else "",
        )
        run_sfdisk = True

    args.root_partno = pn
    pn += 1

    if args.verity:
        args.verity_partno = pn
        pn += 1
    else:
        args.verity_partno = None

    return table, run_sfdisk


def create_image(args: CommandLineArguments, root: str, for_cache: bool) -> Optional[BinaryIO]:
    if not args.output_format.is_disk():
        return None

    with complete_step("Creating partition table", "Created partition table as {.name}") as output:

        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(prefix=".mkosi-", delete=not for_cache, dir=os.path.dirname(args.output)),
        )
        output.append(f)
        disable_cow(f.name)
        f.truncate(image_size(args))

        table, run_sfdisk = determine_partition_table(args)

        if run_sfdisk:
            run(["sfdisk", "--color=never", f.name], input=table.encode("utf-8"))
            run(["sync"])

        args.ran_sfdisk = run_sfdisk

    return f


def copy_image_temporary(src: str, dir: str) -> BinaryIO:
    with open(src, "rb") as source:
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=dir))

        # So on one hand we want CoW off, since this stuff will
        # have a lot of random write accesses. On the other we
        # want the copy to be snappy, hence we do want CoW. Let's
        # ask for both, and let the kernel figure things out:
        # let's turn off CoW on the file, but start with a CoW
        # copy. On btrfs that works: the initial copy is made as
        # CoW but later changes do not result in CoW anymore.

        disable_cow(f.name)
        copy_file_object(source, f)

        return f


def copy_file_temporary(src: str, dir: str) -> BinaryIO:
    with open(src, "rb") as source:
        f = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=dir))
        copy_file_object(source, f)
        return f


def reuse_cache_image(
    args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool
) -> Tuple[Optional[BinaryIO], bool]:
    if not args.incremental:
        return None, False
    if not args.output_format.is_disk_rw():
        return None, False

    fname = args.cache_pre_dev if do_run_build_script else args.cache_pre_inst
    if for_cache:
        if fname and os.path.exists(fname):
            # Cache already generated, skip generation, note that manually removing the exising cache images is
            # necessary if Packages or BuildPackages change
            return None, True
        else:
            return None, False

    if fname is None:
        return None, False

    with complete_step("Basing off cached image " + fname, "Copied cached image as {.name}") as output:

        try:
            f = copy_image_temporary(src=fname, dir=os.path.dirname(args.output))
        except FileNotFoundError:
            return None, False

        output.append(f)
        _, run_sfdisk = determine_partition_table(args)
        args.ran_sfdisk = run_sfdisk

    return f, True


@contextlib.contextmanager
def attach_image_loopback(args: CommandLineArguments, raw: Optional[BinaryIO]) -> Generator[Optional[str], None, None]:
    if raw is None:
        yield None
        return

    with complete_step("Attaching image file", "Attached image file as {}") as output:
        c = run(["losetup", "--find", "--show", "--partscan", raw.name], stdout=PIPE)
        loopdev = c.stdout.decode("utf-8").strip()
        output.append(loopdev)

    try:
        yield loopdev
    finally:
        with complete_step("Detaching image file"):
            run(["losetup", "--detach", loopdev])


def optional_partition(loopdev: str, partno: Optional[int]) -> Optional[str]:
    if partno is None:
        return None

    return partition(loopdev, partno)


def partition(loopdev: str, partno: int) -> str:
    return loopdev + "p" + str(partno)


def prepare_swap(args: CommandLineArguments, loopdev: Optional[str], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return
    if args.swap_partno is None:
        return

    with complete_step("Formatting swap partition"):
        run(["mkswap", "-Lswap", partition(loopdev, args.swap_partno)])


def prepare_esp(args: CommandLineArguments, loopdev: Optional[str], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return
    if args.esp_partno is None:
        return

    with complete_step("Formatting ESP partition"):
        run(["mkfs.fat", "-nEFI", "-F32", partition(loopdev, args.esp_partno)])


def prepare_xbootldr(args: CommandLineArguments, loopdev: Optional[str], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return
    if args.xbootldr_partno is None:
        return

    with complete_step("Formatting XBOOTLDR partition"):
        run(["mkfs.fat", "-nXBOOTLDR", "-F32", partition(loopdev, args.xbootldr_partno)])


def mkfs_ext4_cmd(label: str, mount: str) -> List[str]:
    return ["mkfs.ext4", "-I", "256", "-L", label, "-M", mount]


def mkfs_xfs_cmd(label: str) -> List[str]:
    return ["mkfs.xfs", "-n", "ftype=1", "-L", label]


def mkfs_btrfs_cmd(label: str) -> List[str]:
    return ["mkfs.btrfs", "-L", label, "-d", "single", "-m", "single"]


def mkfs_generic(args: CommandLineArguments, label: str, mount: str, dev: str) -> None:
    cmdline = []

    if args.output_format == OutputFormat.gpt_btrfs:
        cmdline = mkfs_btrfs_cmd(label)
    elif args.output_format == OutputFormat.gpt_xfs:
        cmdline = mkfs_xfs_cmd(label)
    else:
        cmdline = mkfs_ext4_cmd(label, mount)

    if args.output_format == OutputFormat.gpt_ext4:
        if args.distribution in (Distribution.centos, Distribution.centos_epel) and is_older_than_centos8(
            args.release
        ):
            # e2fsprogs in centos7 is too old and doesn't support this feature
            cmdline += ["-O", "^metadata_csum"]

        if args.architecture in ("x86_64", "aarch64"):
            # enable 64bit filesystem feature on supported architectures
            cmdline += ["-O", "64bit"]

    run(cmdline + [dev])


def luks_format(dev: str, passphrase: Dict[str, str]) -> None:
    if passphrase["type"] == "stdin":
        passphrase_content = (passphrase["content"] + "\n").encode("utf-8")
        run(
            [
                "cryptsetup",
                "luksFormat",
                "--force-password",
                "--pbkdf-memory=64",
                "--pbkdf-parallel=1",
                "--pbkdf-force-iterations=1000",
                "--batch-mode",
                dev,
            ],
            input=passphrase_content,
        )
    else:
        assert passphrase["type"] == "file"
        run(
            [
                "cryptsetup",
                "luksFormat",
                "--force-password",
                "--pbkdf-memory=64",
                "--pbkdf-parallel=1",
                "--pbkdf-force-iterations=1000",
                "--batch-mode",
                dev,
                passphrase["content"],
            ]
        )


def luks_open(dev: str, passphrase: Dict[str, str]) -> str:
    name = str(uuid.uuid4())

    if passphrase["type"] == "stdin":
        passphrase_content = (passphrase["content"] + "\n").encode("utf-8")
        run(["cryptsetup", "open", "--type", "luks", dev, name], input=passphrase_content)
    else:
        assert passphrase["type"] == "file"
        run(["cryptsetup", "--key-file", passphrase["content"], "open", "--type", "luks", dev, name])

    return os.path.join("/dev/mapper", name)


def luks_close(dev: Optional[str], text: str) -> None:
    if dev is None:
        return

    with complete_step(text):
        run(["cryptsetup", "close", dev])


def luks_format_root(
    args: CommandLineArguments,
    loopdev: str,
    do_run_build_script: bool,
    cached: bool,
    inserting_generated_root: bool = False,
) -> None:
    if args.encrypt != "all":
        return
    if args.root_partno is None:
        return
    if args.generated_root() and not inserting_generated_root:
        return
    if do_run_build_script:
        return
    if cached:
        return

    with complete_step("LUKS formatting root partition"):
        luks_format(partition(loopdev, args.root_partno), args.passphrase)


def luks_format_home(args: CommandLineArguments, loopdev: str, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    if args.home_partno is None:
        return
    if do_run_build_script:
        return
    if cached:
        return

    with complete_step("LUKS formatting home partition"):
        luks_format(partition(loopdev, args.home_partno), args.passphrase)


def luks_format_srv(args: CommandLineArguments, loopdev: str, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    if args.srv_partno is None:
        return
    if do_run_build_script:
        return
    if cached:
        return

    with complete_step("LUKS formatting server data partition"):
        luks_format(partition(loopdev, args.srv_partno), args.passphrase)


def luks_format_var(args: CommandLineArguments, loopdev: str, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    if args.var_partno is None:
        return
    if do_run_build_script:
        return
    if cached:
        return

    with complete_step("LUKS formatting variable data partition"):
        luks_format(partition(loopdev, args.var_partno), args.passphrase)


def luks_format_tmp(args: CommandLineArguments, loopdev: str, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    if args.tmp_partno is None:
        return
    if do_run_build_script:
        return
    if cached:
        return

    with complete_step("LUKS formatting temporary data partition"):
        luks_format(partition(loopdev, args.tmp_partno), args.passphrase)


def luks_setup_root(
    args: CommandLineArguments, loopdev: str, do_run_build_script: bool, inserting_generated_root: bool = False
) -> Optional[str]:
    if args.encrypt != "all":
        return None
    if args.root_partno is None:
        return None
    if args.generated_root() and not inserting_generated_root:
        return None
    if do_run_build_script:
        return None

    with complete_step("Opening LUKS root partition"):
        return luks_open(partition(loopdev, args.root_partno), args.passphrase)


def luks_setup_home(args: CommandLineArguments, loopdev: str, do_run_build_script: bool) -> Optional[str]:
    if args.encrypt is None:
        return None
    if args.home_partno is None:
        return None
    if do_run_build_script:
        return None

    with complete_step("Opening LUKS home partition"):
        return luks_open(partition(loopdev, args.home_partno), args.passphrase)


def luks_setup_srv(args: CommandLineArguments, loopdev: str, do_run_build_script: bool) -> Optional[str]:
    if args.encrypt is None:
        return None
    if args.srv_partno is None:
        return None
    if do_run_build_script:
        return None

    with complete_step("Opening LUKS server data partition"):
        return luks_open(partition(loopdev, args.srv_partno), args.passphrase)


def luks_setup_var(args: CommandLineArguments, loopdev: str, do_run_build_script: bool) -> Optional[str]:
    if args.encrypt is None:
        return None
    if args.var_partno is None:
        return None
    if do_run_build_script:
        return None

    with complete_step("Opening LUKS variable data partition"):
        return luks_open(partition(loopdev, args.var_partno), args.passphrase)


def luks_setup_tmp(args: CommandLineArguments, loopdev: str, do_run_build_script: bool) -> Optional[str]:
    if args.encrypt is None:
        return None
    if args.tmp_partno is None:
        return None
    if do_run_build_script:
        return None

    with complete_step("Opening LUKS temporary data partition"):
        return luks_open(partition(loopdev, args.tmp_partno), args.passphrase)


@contextlib.contextmanager
def luks_setup_all(
    args: CommandLineArguments, loopdev: Optional[str], do_run_build_script: bool
) -> Generator[Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]], None, None]:
    if not args.output_format.is_disk():
        yield (None, None, None, None, None)
        return
    assert loopdev is not None

    try:
        root = luks_setup_root(args, loopdev, do_run_build_script)
        try:
            home = luks_setup_home(args, loopdev, do_run_build_script)
            try:
                srv = luks_setup_srv(args, loopdev, do_run_build_script)
                try:
                    var = luks_setup_var(args, loopdev, do_run_build_script)
                    try:
                        tmp = luks_setup_tmp(args, loopdev, do_run_build_script)

                        yield (
                            optional_partition(loopdev, args.root_partno) if root is None else root,
                            optional_partition(loopdev, args.home_partno) if home is None else home,
                            optional_partition(loopdev, args.srv_partno) if srv is None else srv,
                            optional_partition(loopdev, args.var_partno) if var is None else var,
                            optional_partition(loopdev, args.tmp_partno) if tmp is None else tmp,
                        )
                    finally:
                        luks_close(tmp, "Closing LUKS temporary data partition")
                finally:
                    luks_close(var, "Closing LUKS variable data partition")
            finally:
                luks_close(srv, "Closing LUKS server data partition")
        finally:
            luks_close(home, "Closing LUKS home partition")
    finally:
        luks_close(root, "Closing LUKS root partition")


def prepare_root(args: CommandLineArguments, dev: Optional[str], cached: bool) -> None:
    if dev is None:
        return
    if args.generated_root():
        return
    if cached:
        return

    with complete_step("Formatting root partition"):
        mkfs_generic(args, "root", "/", dev)


def prepare_home(args: CommandLineArguments, dev: Optional[str], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting home partition"):
        mkfs_generic(args, "home", "/home", dev)


def prepare_srv(args: CommandLineArguments, dev: Optional[str], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting server data partition"):
        mkfs_generic(args, "srv", "/srv", dev)


def prepare_var(args: CommandLineArguments, dev: Optional[str], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting variable data partition"):
        mkfs_generic(args, "var", "/var", dev)


def prepare_tmp(args: CommandLineArguments, dev: Optional[str], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting temporary data partition"):
        mkfs_generic(args, "tmp", "/var/tmp", dev)


def mount_loop(args: CommandLineArguments, dev: str, where: str, read_only: bool = False) -> None:
    os.makedirs(where, 0o755, True)

    options = []
    if not args.output_format.is_squashfs():
        options.append("discard")

    if (
        args.compress
        and args.output_format == OutputFormat.gpt_btrfs
        and not (where.endswith("/efi") or where.endswith("/boot"))
    ):
        if isinstance(args.compress, bool):
            options.append("compress")
        else:
            options.append(f"compress={args.compress}")

    if read_only:
        options.append("ro")

    cmd = ["mount", "-n", dev, where]
    if options:
        cmd += ["-o", ",".join(options)]

    run(cmd)


def mount_bind(what: str, where: str) -> str:
    os.makedirs(what, 0o755, True)
    os.makedirs(where, 0o755, True)
    run(["mount", "--bind", what, where])
    return where


def mount_tmpfs(where: str) -> None:
    os.makedirs(where, 0o755, True)
    run(["mount", "tmpfs", "-t", "tmpfs", where])


@contextlib.contextmanager
def mount_image(
    args: CommandLineArguments,
    root: str,
    loopdev: Optional[str],
    root_dev: Optional[str],
    home_dev: Optional[str],
    srv_dev: Optional[str],
    var_dev: Optional[str],
    tmp_dev: Optional[str],
    root_read_only: bool = False,
) -> Generator[None, None, None]:
    with complete_step("Mounting image"):

        if root_dev is not None:
            mount_loop(args, root_dev, root, root_read_only)
        else:
            # always have a root of the tree as a mount point so we can
            # recursively unmount anything that ends up mounted there
            mount_bind(root, root)

        if home_dev is not None:
            mount_loop(args, home_dev, os.path.join(root, "home"))

        if srv_dev is not None:
            mount_loop(args, srv_dev, os.path.join(root, "srv"))

        if var_dev is not None:
            mount_loop(args, var_dev, os.path.join(root, "var"))

        if tmp_dev is not None:
            mount_loop(args, tmp_dev, os.path.join(root, "var/tmp"))

        if args.esp_partno is not None and loopdev is not None:
            mount_loop(args, partition(loopdev, args.esp_partno), os.path.join(root, "efi"))

        if args.xbootldr_partno is not None and loopdev is not None:
            mount_loop(args, partition(loopdev, args.xbootldr_partno), os.path.join(root, "boot"))

        # Make sure /tmp and /run are not part of the image
        mount_tmpfs(os.path.join(root, "run"))
        mount_tmpfs(os.path.join(root, "tmp"))

    try:
        yield
    finally:
        with complete_step("Unmounting image"):
            umount(root)


def install_etc_hostname(args: CommandLineArguments, root: str, cached: bool) -> None:
    if cached:
        return

    etc_hostname = os.path.join(root, "etc/hostname")

    # Always unlink first, so that we don't get in trouble due to a
    # symlink or suchlike. Also if no hostname is configured we really
    # don't want the file to exist, so that systemd's implicit
    # hostname logic can take effect.
    try:
        os.unlink(etc_hostname)
    except FileNotFoundError:
        pass

    if args.hostname:
        with complete_step("Assigning hostname"):
            open(etc_hostname, "w").write(args.hostname + "\n")


@contextlib.contextmanager
def mount_api_vfs(args: CommandLineArguments, root: str) -> Generator[None, None, None]:
    paths = ("/proc", "/dev", "/sys")

    with complete_step("Mounting API VFS"):
        for d in paths:
            mount_bind(d, root + d)
    try:
        yield
    finally:
        with complete_step("Unmounting API VFS"):
            for d in paths:
                umount(root + d)


@contextlib.contextmanager
def mount_cache(args: CommandLineArguments, root: str) -> Generator[None, None, None]:
    if args.cache_path is None:
        yield
        return

    caches = []

    # We can't do this in mount_image() yet, as /var itself might have to be created as a subvolume first
    with complete_step("Mounting Package Cache"):
        if args.distribution in (Distribution.fedora, Distribution.mageia, Distribution.openmandriva):
            caches = [mount_bind(args.cache_path, os.path.join(root, "var/cache/dnf"))]
        elif args.distribution in (Distribution.centos, Distribution.centos_epel):
            # We mount both the YUM and the DNF cache in this case, as
            # YUM might just be redirected to DNF even if we invoke
            # the former
            caches = [
                mount_bind(os.path.join(args.cache_path, "yum"), os.path.join(root, "var/cache/yum")),
                mount_bind(os.path.join(args.cache_path, "dnf"), os.path.join(root, "var/cache/dnf")),
            ]
        elif args.distribution in (Distribution.debian, Distribution.ubuntu):
            caches = [mount_bind(args.cache_path, os.path.join(root, "var/cache/apt/archives"))]
        elif args.distribution == Distribution.arch:
            caches = [mount_bind(args.cache_path, os.path.join(root, "var/cache/pacman/pkg"))]
        elif args.distribution == Distribution.opensuse:
            caches = [mount_bind(args.cache_path, os.path.join(root, "var/cache/zypp/packages"))]
        elif args.distribution == Distribution.photon:
            caches = [mount_bind(os.path.join(args.cache_path, "tdnf"), os.path.join(root, "var/cache/tdnf"))]
    try:
        yield
    finally:
        with complete_step("Unmounting Package Cache"):
            for d in caches:  # NOQA: E501
                umount(d)


def umount(where: str) -> None:
    run(["umount", "--recursive", "-n", where])


def configure_dracut(args: CommandLineArguments, root: str) -> None:
    dracut_dir = os.path.join(root, "etc/dracut.conf.d")
    os.mkdir(dracut_dir, 0o755)

    with open(os.path.join(dracut_dir, "30-mkosi-hostonly.conf"), "w") as f:
        f.write(f"hostonly={'yes' if args.hostonly_initrd else 'no'}\n")

    with open(os.path.join(dracut_dir, "30-mkosi-systemd-extras.conf"), "w") as f:
        for extra in DRACUT_SYSTEMD_EXTRAS:
            f.write(f'install_optional_items+=" {extra} "\n')

    with open(os.path.join(dracut_dir, "30-mkosi-qemu.conf"), "w") as f:
        f.write('add_dracutmodules+=" qemu "\n')

    if args.hostonly_initrd:
        with open(os.path.join(dracut_dir, "30-mkosi-filesystem.conf"), "w") as f:
            f.write(f'filesystems+=" {(args.output_format.needed_kernel_module())} "\n')

    # These distros need uefi_stub configured explicitly for dracut to find the systemd-boot uefi stub.
    if args.esp_partno is not None and args.distribution in (
        Distribution.ubuntu,
        Distribution.debian,
        Distribution.mageia,
        Distribution.openmandriva,
    ):
        with open(os.path.join(dracut_dir, "30-mkosi-uefi-stub.conf"), "w") as f:
            f.write("uefi_stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub\n")

    # efivarfs must be present in order to GPT root discovery work
    if args.esp_partno is not None:
        with open(os.path.join(dracut_dir, "30-mkosi-efivarfs.conf"), "w") as f:
            f.write('add_drivers+=" efivarfs "\n')


def prepare_tree_root(args: CommandLineArguments, root: str) -> None:
    if args.output_format == OutputFormat.subvolume:
        with complete_step("Setting up OS tree root"):
            btrfs_subvol_create(root)


def prepare_tree(args: CommandLineArguments, root: str, do_run_build_script: bool, cached: bool) -> None:
    if cached:
        return

    with complete_step("Setting up basic OS tree"):
        if args.output_format is OutputFormat.subvolume or (
            args.output_format is OutputFormat.gpt_btrfs and not args.minimize
        ):
            btrfs_subvol_create(os.path.join(root, "home"))
            btrfs_subvol_create(os.path.join(root, "srv"))
            btrfs_subvol_create(os.path.join(root, "var"))
            btrfs_subvol_create(os.path.join(root, "var/tmp"), 0o1777)
            os.mkdir(os.path.join(root, "var/lib"))
            btrfs_subvol_create(os.path.join(root, "var/lib/machines"), 0o700)

        # We need an initialized machine ID for the build & boot logic to work
        os.mkdir(os.path.join(root, "etc"), 0o755)
        with open(os.path.join(root, "etc/machine-id"), "w") as f:
            f.write(args.machine_id)
            f.write("\n")

        if not do_run_build_script and args.bootable:
            if args.xbootldr_partno is not None:
                # Create directories for kernels and entries if this is enabled
                os.mkdir(os.path.join(root, "boot/EFI"), 0o700)
                os.mkdir(os.path.join(root, "boot/EFI/Linux"), 0o700)
                os.mkdir(os.path.join(root, "boot/loader"), 0o700)
                os.mkdir(os.path.join(root, "boot/loader/entries"), 0o700)
                os.mkdir(os.path.join(root, "boot", args.machine_id), 0o700)
            else:
                # If this is not enabled, let's create an empty directory on /boot
                os.mkdir(os.path.join(root, "boot"), 0o700)

            if args.esp_partno is not None:
                os.mkdir(os.path.join(root, "efi/EFI"), 0o700)
                os.mkdir(os.path.join(root, "efi/EFI/BOOT"), 0o700)
                os.mkdir(os.path.join(root, "efi/EFI/systemd"), 0o700)
                os.mkdir(os.path.join(root, "efi/loader"), 0o700)

                if args.xbootldr_partno is None:
                    # Create directories for kernels and entries, unless the XBOOTLDR partition is turned on
                    os.mkdir(os.path.join(root, "efi/EFI/Linux"), 0o700)
                    os.mkdir(os.path.join(root, "efi/loader/entries"), 0o700)
                    os.mkdir(os.path.join(root, "efi", args.machine_id), 0o700)

                    # Create some compatibility symlinks in /boot in case that is not set up otherwise
                    os.symlink("../efi", os.path.join(root, "boot/efi"))
                    os.symlink("../efi/loader", os.path.join(root, "boot/loader"))
                    os.symlink("../efi/" + args.machine_id, os.path.join(root, "boot", args.machine_id))

            os.mkdir(os.path.join(root, "etc/kernel"), 0o755)

            with open(os.path.join(root, "etc/kernel/cmdline"), "w") as cmdline:
                cmdline.write(" ".join(args.kernel_command_line))
                cmdline.write("\n")

        if do_run_build_script or args.ssh:
            os.mkdir(os.path.join(root, "root"), 0o750)

        if args.ssh and not do_run_build_script:
            os.mkdir(os.path.join(root, "root/.ssh"), 0o700)

        if do_run_build_script:
            os.mkdir(os.path.join(root, "root/dest"), 0o755)

            if args.include_dir is not None:
                os.mkdir(os.path.join(root, "usr"), 0o755)
                os.mkdir(os.path.join(root, "usr/include"), 0o755)

            if args.build_dir is not None:
                os.mkdir(os.path.join(root, "root/build"), 0o755)

        if args.network_veth and not do_run_build_script:
            os.mkdir(os.path.join(root, "etc/systemd"), 0o755)
            os.mkdir(os.path.join(root, "etc/systemd/network"), 0o755)


def patch_file(filepath: str, line_rewriter: Callable[[str], str]) -> None:
    temp_new_filepath = filepath + ".tmp.new"

    with open(filepath, "r") as old:
        with open(temp_new_filepath, "w") as new:
            for line in old:
                new.write(line_rewriter(line))

    shutil.copystat(filepath, temp_new_filepath)
    os.remove(filepath)
    shutil.move(temp_new_filepath, filepath)


def disable_pam_securetty(root: str) -> None:
    def _rm_securetty(line: str) -> str:
        if "pam_securetty.so" in line:
            return ""
        return line

    patch_file(os.path.join(root, "etc/pam.d/login"), _rm_securetty)


def run_workspace_command(
    args: CommandLineArguments,
    root: str,
    cmd: List[str],
    network: bool = False,
    env: Dict[str, str] = {},
    nspawn_params: List[str] = [],
) -> None:
    cmdline = [
        "systemd-nspawn",
        "--quiet",
        "--directory=" + root,
        "--uuid=" + args.machine_id,
        "--machine=mkosi-" + uuid.uuid4().hex,
        "--as-pid2",
        "--register=no",
        "--bind=" + var_tmp(root) + ":/var/tmp",
        "--setenv=SYSTEMD_OFFLINE=1",
    ]

    if network:
        # If we're using the host network namespace, use the same resolver
        cmdline += ["--bind-ro=/etc/resolv.conf"]
    else:
        cmdline += ["--private-network"]

    cmdline += [f"--setenv={k}={v}" for k, v in env.items()]

    if nspawn_params:
        cmdline += nspawn_params

    result = run(cmdline + ["--"] + cmd, check=False)
    if result.returncode != 0:
        if "workspace-command" in arg_debug:
            run(cmdline, check=False)
        die(f"Workspace command `{' '.join(cmd)}` returned non-zero exit code {result.returncode}.")


def check_if_url_exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD")
    try:
        if urllib.request.urlopen(req):
            return True
        return False
    except:  # NOQA: E722
        return False


def make_executable(path: str) -> None:
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IEXEC)


def disable_kernel_install(args: CommandLineArguments, root: str) -> None:
    # Let's disable the automatic kernel installation done by the kernel RPMs. After all, we want to built
    # our own unified kernels that include the root hash in the kernel command line and can be signed as a
    # single EFI executable. Since the root hash is only known when the root file system is finalized we turn
    # off any kernel installation beforehand.
    #
    # For BIOS mode, we don't have that option, so do not mask the units.
    if not args.bootable or args.bios_partno is not None or not args.with_unified_kernel_images:
        return

    for d in ("etc", "etc/kernel", "etc/kernel/install.d"):
        mkdir_last(os.path.join(root, d), 0o755)

    for f in ("50-dracut.install", "51-dracut-rescue.install", "90-loaderentry.install"):
        path = os.path.join(root, "etc/kernel/install.d", f)
        os.symlink("/dev/null", path)


def reenable_kernel_install(args: CommandLineArguments, root: str) -> None:
    if not args.bootable or args.bios_partno is not None or not args.with_unified_kernel_images:
        return

    hook_path = os.path.join(root, "etc/kernel/install.d/50-mkosi-dracut-unified-kernel.install")
    with open(hook_path, "w") as f:
        f.write(DRACUT_UNIFIED_KERNEL_INSTALL)

    make_executable(hook_path)


def make_rpm_list(args: argparse.Namespace, packages: Set[str], do_run_build_script: bool) -> Set[str]:
    packages = packages.copy()

    if args.bootable:
        # Temporary hack: dracut only adds crypto support to the initrd, if the cryptsetup binary is installed
        if args.encrypt or args.verity:
            packages.add("cryptsetup")

        if args.output_format == OutputFormat.gpt_ext4:
            packages.add("e2fsprogs")

        if args.output_format == OutputFormat.gpt_xfs:
            packages.add("xfsprogs")

        if args.output_format == OutputFormat.gpt_btrfs:
            packages.add("btrfs-progs")

        if args.bios_partno:
            if args.distribution in (Distribution.mageia, Distribution.openmandriva):
                packages.add("grub2")
            else:
                packages.add("grub2-pc")

    if not do_run_build_script and args.ssh:
        packages.add("openssh-server")

    return packages


def clean_dnf_metadata(root: str) -> None:
    """Removes dnf metadata iff /bin/dnf is not present in the image

    If dnf is not installed, there doesn't seem to be much use in
    keeping the dnf metadata, since it's not usable from within the
    image anyway.
    """
    dnf_metadata_paths = [
        os.path.join(root, "var/lib/dnf"),
        *glob.glob(f"{os.path.join(root, 'var/log/dnf')}.*"),
        *glob.glob(f"{os.path.join(root, 'var/log/hawkey')}.*"),
        os.path.join(root, "var/cache/dnf"),
    ]
    dnf_path = os.path.join(root, "bin/dnf")
    keep_dnf_data = os.access(dnf_path, os.F_OK, follow_symlinks=False)

    if not keep_dnf_data or all(not os.path.exists(path) for path in dnf_metadata_paths):
        return

    with complete_step("Cleaning dnf metadata..."):
        remove_glob(*dnf_metadata_paths)


def clean_yum_metadata(root: str) -> None:
    """Removes yum metadata iff /bin/yum is not present in the image"""
    yum_metadata_paths = [
        os.path.join(root, "var/lib/yum"),
        *glob.glob(f"{os.path.join(root, 'var/log/yum')}.*"),
        os.path.join(root, "var/cache/yum"),
    ]
    yum_path = os.path.join(root, "bin/yum")
    keep_yum_data = os.access(yum_path, os.F_OK, follow_symlinks=False)

    if not keep_yum_data or all(not os.path.exists(path) for path in yum_metadata_paths):
        return

    with complete_step("Cleaning yum metadata..."):
        remove_glob(*yum_metadata_paths)


def clean_rpm_metadata(root: str) -> None:
    """Removes rpm metadata iff /bin/rpm is not present in the image"""
    rpm_metadata_path = os.path.join(root, "var/lib/rpm")
    rpm_path = os.path.join(root, "bin/rpm")
    keep_rpm_data = os.access(rpm_path, os.F_OK, follow_symlinks=False)

    if not keep_rpm_data or not os.path.exists(rpm_metadata_path):
        return

    with complete_step("Cleaning rpm metadata..."):
        remove_glob(rpm_metadata_path)


def clean_tdnf_metadata(root: str) -> None:
    """Removes tdnf metadata iff /bin/tdnf is not present in the image"""
    tdnf_metadata_paths = [*glob.glob(f"{os.path.join(root, 'var/log/tdnf')}.*"), os.path.join(root, "var/cache/tdnf")]
    tdnf_path = os.path.join(root, "usr/bin/tdnf")
    keep_tdnf_data = os.access(tdnf_path, os.F_OK, follow_symlinks=False)

    if not keep_tdnf_data or all(not os.path.exists(path) for path in tdnf_metadata_paths):
        return

    with complete_step("Cleaning tdnf metadata..."):
        remove_glob(*tdnf_metadata_paths)


def clean_package_manager_metadata(root: str) -> None:
    """Clean up package manager metadata

    Try them all regardless of the distro: metadata is only removed if the
    package manager is present in the image.
    """

    # we try then all: metadata will only be touched if any of them are in the
    # final image
    clean_dnf_metadata(root)
    clean_yum_metadata(root)
    clean_rpm_metadata(root)
    clean_tdnf_metadata(root)
    # FIXME: implement cleanup for other package managers


def invoke_dnf(
    args: CommandLineArguments, root: str, repositories: List[str], packages: Set[str], do_run_build_script: bool
) -> None:
    repos = ["--enablerepo=" + repo for repo in repositories]
    config_file = os.path.join(workspace(root), "dnf.conf")
    packages = make_rpm_list(args, packages, do_run_build_script)

    cmdline = [
        "dnf",
        "-y",
        "--config=" + config_file,
        "--best",
        "--allowerasing",
        "--releasever=" + args.release,
        "--installroot=" + root,
        "--disablerepo=*",
        *repos,
        "--setopt=keepcache=1",
        "--setopt=install_weak_deps=0",
    ]

    if args.architecture is not None:
        cmdline += [f"--forcearch={args.architecture}"]

    if args.with_network == "never":
        cmdline += ["--cacheonly"]

    if not args.with_docs:
        cmdline += ["--nodocs"]

    cmdline += ["install", *packages]

    with mount_api_vfs(args, root):
        run(cmdline)


def invoke_tdnf(
    args: CommandLineArguments,
    root: str,
    repositories: List[str],
    packages: Set[str],
    gpgcheck: bool,
    do_run_build_script: bool,
) -> None:
    repos = ["--enablerepo=" + repo for repo in repositories]
    config_file = os.path.join(workspace(root), "dnf.conf")
    packages = make_rpm_list(args, packages, do_run_build_script)

    cmdline = [
        "tdnf",
        "-y",
        "--config=" + config_file,
        "--releasever=" + args.release,
        "--installroot=" + root,
        "--disablerepo=*",
        *repos,
    ]

    if not gpgcheck:
        cmdline.append("--nogpgcheck")

    cmdline += ["install", *packages]

    with mount_api_vfs(args, root):
        run(cmdline)


class Repo(NamedTuple):
    id: str
    name: str
    url: str
    gpgpath: str
    gpgurl: Optional[str] = None


def setup_dnf(args: CommandLineArguments, root: str, repos: List[Repo] = []) -> None:
    gpgcheck = True

    repo_file = os.path.join(workspace(root), "temp.repo")
    with open(repo_file, "w") as f:
        for repo in repos:
            gpgkey: Optional[str] = None

            if os.path.exists(repo.gpgpath):
                gpgkey = f"file://{repo.gpgpath}"
            elif repo.gpgurl:
                gpgkey = repo.gpgurl
            else:
                warn(f"GPG key not found at {repo.gpgpath}. Not checking GPG signatures.")
                gpgcheck = False

            f.write(
                dedent(
                    f"""\
                    [{repo.id}]
                    name={repo.name}
                    {repo.url}
                    gpgkey={gpgkey or ''}
                    """
                )
            )

    config_file = os.path.join(workspace(root), "dnf.conf")
    with open(config_file, "w") as f:
        f.write(
            dedent(
                f"""\
                [main]
                gpgcheck={'1' if gpgcheck else '0'}
                {"repodir" if args.distribution == Distribution.photon else "reposdir"}={workspace(root)}
                """
            )
        )


@complete_step("Installing Photon")
def install_photon(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    release_url = "baseurl=https://dl.bintray.com/vmware/photon_release_$releasever_$basearch"
    updates_url = "baseurl=https://dl.bintray.com/vmware/photon_updates_$releasever_$basearch"
    gpgpath = "/etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY"

    setup_dnf(
        args,
        root,
        repos=[
            Repo("photon", f"VMware Photon OS {args.release} Release", release_url, gpgpath),
            Repo("photon-updates", f"VMware Photon OS {args.release} Updates", updates_url, gpgpath),
        ],
    )

    packages = {"minimal"}
    if not do_run_build_script and args.bootable:
        packages |= {"linux", "initramfs"}

    invoke_tdnf(
        args,
        root,
        args.repositories or ["photon", "photon-updates"],
        packages,
        os.path.exists(gpgpath),
        do_run_build_script,
    )


@complete_step("Installing Clear Linux")
def install_clear(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    if args.release == "latest":
        release = "clear"
    else:
        release = "clear/" + args.release

    packages = {"os-core-plus", *args.packages}
    if do_run_build_script:
        packages.update(args.build_packages)
    if not do_run_build_script and args.bootable:
        packages.add("kernel-native")
    if not do_run_build_script and args.ssh:
        packages.add("openssh-server")

    swupd_extract = shutil.which("swupd-extract")

    if swupd_extract is None:
        die(
            dedent(
                """
                Couldn't find swupd-extract program, download (or update it) it using:

                  go get -u github.com/clearlinux/mixer-tools/swupd-extract

                and it will be installed by default in ~/go/bin/swupd-extract. Also
                ensure that you have openssl program in your system.
                """
            )
        )

    print(f"Using {swupd_extract}")

    run([swupd_extract, "-output", root, "-state", args.cache_path, release, *packages], check=True)

    os.symlink("../run/systemd/resolve/resolv.conf", os.path.join(root, "etc/resolv.conf"))

    # Clear Linux doesn't have a /etc/shadow at install time, it gets
    # created when the root first login. To set the password via
    # mkosi, create one.
    if not do_run_build_script and args.password is not None:
        shadow_file = os.path.join(root, "etc/shadow")
        with open(shadow_file, "w") as f:
            f.write("root::::::::")
        os.chmod(shadow_file, 0o400)
        # Password is already empty for root, so no need to reset it later.
        if args.password == "":
            args.password = None


@complete_step("Installing Fedora")
def install_fedora(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    if args.release == "rawhide":
        last = sorted(FEDORA_KEYS_MAP)[-1]
        warn(f"Assuming rawhide is version {last} — " + "You may specify otherwise with --release=rawhide-<version>")
        args.releasever = last
    elif args.release.startswith("rawhide-"):
        args.release, args.releasever = args.release.split("-")
        MkosiPrinter.info(f"Fedora rawhide — release version: {args.releasever}")
    else:
        args.releasever = args.release

    arch = args.architecture or platform.machine()

    if args.mirror:
        baseurl = urllib.parse.urljoin(args.mirror, f"releases/{args.release}/Everything/$basearch/os/")
        media = urllib.parse.urljoin(baseurl.replace("$basearch", arch), "media.repo")
        if not check_if_url_exists(media):
            baseurl = urllib.parse.urljoin(args.mirror, f"development/{args.release}/Everything/$basearch/os/")

        release_url = f"baseurl={baseurl}"
        updates_url = f"baseurl={args.mirror}/updates/{args.release}/Everything/$basearch/"
    else:
        release_url = (
            f"metalink=https://mirrors.fedoraproject.org/metalink?" + f"repo=fedora-{args.release}&arch=$basearch"
        )
        updates_url = (
            f"metalink=https://mirrors.fedoraproject.org/metalink?"
            + f"repo=updates-released-f{args.release}&arch=$basearch"
        )

    if args.releasever in FEDORA_KEYS_MAP:
        gpgid = f"keys/{FEDORA_KEYS_MAP[args.releasever]}.txt"
    else:
        gpgid = "fedora.gpg"

    gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-{args.releasever}-{arch}"
    gpgurl = urllib.parse.urljoin("https://getfedora.org/static/", gpgid)

    setup_dnf(
        args,
        root,
        repos=[
            Repo("fedora", f"Fedora {args.release.capitalize()} - base", release_url, gpgpath, gpgurl),
            Repo("updates", f"Fedora {args.release.capitalize()} - updates", updates_url, gpgpath, gpgurl),
        ],
    )

    packages = {"fedora-release", "glibc-minimal-langpack", "systemd", *args.packages}
    if not do_run_build_script and args.bootable:
        packages |= {"kernel-core", "kernel-modules", "systemd-udev", "binutils", "dracut"}
        configure_dracut(args, root)
    if do_run_build_script:
        packages.update(args.build_packages)
    if not do_run_build_script and args.network_veth:
        packages.add("systemd-networkd")
    invoke_dnf(args, root, args.repositories or ["fedora", "updates"], packages, do_run_build_script)

    with open(os.path.join(root, "etc/locale.conf"), "w") as f:
        f.write("LANG=C.UTF-8\n")


@complete_step("Installing Mageia")
def install_mageia(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    if args.mirror:
        baseurl = f"{args.mirror}/distrib/{args.release}/x86_64/media/core/"
        release_url = f"baseurl={baseurl}/release/"
        updates_url = f"baseurl={baseurl}/updates/"
    else:
        baseurl = f"https://www.mageia.org/mirrorlist/?release={args.release}&arch=x86_64&section=core"
        release_url = f"mirrorlist={baseurl}&repo=release"
        updates_url = f"mirrorlist={baseurl}&repo=updates"

    gpgpath = "/etc/pki/rpm-gpg/RPM-GPG-KEY-Mageia"

    setup_dnf(
        args,
        root,
        repos=[
            Repo("mageia", f"Mageia {args.release} Core Release", release_url, gpgpath),
            Repo("updates", f"Mageia {args.release} Core Updates", updates_url, gpgpath),
        ],
    )

    packages = {"basesystem-minimal", *args.packages}
    if not do_run_build_script and args.bootable:
        packages |= {"kernel-server-latest", "binutils", "dracut"}

        configure_dracut(args, root)
        # Mageia ships /etc/50-mageia.conf that omits systemd from the initramfs and disables hostonly.
        # We override that again so our defaults get applied correctly on Mageia as well.
        with open(os.path.join(root, "etc/dracut.conf.d/51-mkosi-override-mageia.conf"), "w") as f:
            f.write("hostonly=no\n")
            f.write('omit_dracutmodules=""\n')
    if do_run_build_script:
        packages.update(args.build_packages)
    invoke_dnf(args, root, args.repositories or ["mageia", "updates"], packages, do_run_build_script)

    disable_pam_securetty(root)


@complete_step("Installing OpenMandriva")
def install_openmandriva(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    release = args.release.strip("'")

    if release[0].isdigit():
        release_model = "rock"
    elif release == "cooker":
        release_model = "cooker"
    else:
        release_model = release

    if args.mirror:
        baseurl = f"{args.mirror}/{release_model}/repository/x86_64/main"
        release_url = f"baseurl={baseurl}/release/"
        updates_url = f"baseurl={baseurl}/updates/"
    else:
        baseurl = f"http://mirrors.openmandriva.org/mirrors.php?platform={release_model}&arch=x86_64&repo=main"
        release_url = f"mirrorlist={baseurl}&release=release"
        updates_url = f"mirrorlist={baseurl}&release=updates"

    gpgpath = "/etc/pki/rpm-gpg/RPM-GPG-KEY-OpenMandriva"

    setup_dnf(
        args,
        root,
        repos=[
            Repo("openmandriva", f"OpenMandriva {release_model} Main", release_url, gpgpath),
            Repo("updates", f"OpenMandriva {release_model} Main Updates", updates_url, gpgpath),
        ],
    )

    # well we may use basesystem here, but that pulls lot of stuff
    packages = {"basesystem-minimal", "systemd", *args.packages}
    if not do_run_build_script and args.bootable:
        packages |= {"kernel-release-server", "binutils", "systemd-boot", "dracut", "timezone", "systemd-cryptsetup"}
        configure_dracut(args, root)
    if do_run_build_script:
        packages.update(args.build_packages)
    invoke_dnf(args, root, args.repositories or ["openmandriva", "updates"], packages, do_run_build_script)

    disable_pam_securetty(root)


def invoke_yum(
    args: CommandLineArguments, root: str, repositories: List[str], packages: Set[str], do_run_build_script: bool
) -> None:
    repos = ["--enablerepo=" + repo for repo in repositories]
    config_file = os.path.join(workspace(root), "dnf.conf")
    packages = make_rpm_list(args, packages, do_run_build_script)

    cmdline = [
        "yum",
        "-y",
        "--config=" + config_file,
        "--releasever=" + args.release,
        "--installroot=" + root,
        "--disablerepo=*",
        *repos,
        "--setopt=keepcache=1",
    ]

    if args.architecture is not None:
        cmdline += [f"--forcearch={args.architecture}"]

    if not args.with_docs:
        cmdline.append("--setopt=tsflags=nodocs")

    cmdline += ["install", *packages]

    with mount_api_vfs(args, root):
        run(cmdline)


def invoke_dnf_or_yum(
    args: CommandLineArguments, root: str, repositories: List[str], packages: Set[str], do_run_build_script: bool
) -> None:
    if shutil.which("dnf") is None:
        invoke_yum(args, root, repositories, packages, do_run_build_script)
    else:
        invoke_dnf(args, root, repositories, packages, do_run_build_script)


def install_centos_old(args: CommandLineArguments, root: str, epel_release: int) -> List[str]:
    # Repos for CentOS 7 and earlier

    gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-{args.release}"
    gpgurl = f"https://www.centos.org/keys/RPM-GPG-KEY-CentOS-{args.release}"
    epel_gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}"
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        release_url = f"baseurl={args.mirror}/centos/{args.release}/os/x86_64"
        updates_url = f"baseurl={args.mirror}/centos/{args.release}/updates/x86_64/"
        extras_url = f"baseurl={args.mirror}/centos/{args.release}/extras/x86_64/"
        centosplus_url = f"baseurl={args.mirror}/centos/{args.release}/centosplus/x86_64/"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/x86_64/"
    else:
        release_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=os"
        updates_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=updates"
        extras_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=extras"
        centosplus_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=centosplus"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=x86_64"

    setup_dnf(
        args,
        root,
        repos=[
            Repo("base", f"CentOS-{args.release} - Base", release_url, gpgpath, gpgurl),
            Repo("updates", f"CentOS-{args.release} - Updates", updates_url, gpgpath, gpgurl),
            Repo("extras", f"CentOS-{args.release} - Extras", extras_url, gpgpath, gpgurl),
            Repo("centosplus", f"CentOS-{args.release} - Plus", centosplus_url, gpgpath, gpgurl),
            Repo(
                "epel",
                f"name=Extra Packages for Enterprise Linux {epel_release} - $basearch",
                epel_url,
                epel_gpgpath,
                epel_gpgurl,
            ),
        ],
    )

    return ["base", "updates", "extras", "centosplus"]


def install_centos_new(args: CommandLineArguments, root: str, epel_release: int) -> List[str]:
    # Repos for CentOS 8 and later

    gpgpath = "/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial"
    gpgurl = "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official"
    epel_gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}"
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        appstream_url = f"baseurl={args.mirror}/centos/{args.release}/AppStream/x86_64/os"
        baseos_url = f"baseurl={args.mirror}/centos/{args.release}/BaseOS/x86_64/os"
        extras_url = f"baseurl={args.mirror}/centos/{args.release}/extras/x86_64/os"
        centosplus_url = f"baseurl={args.mirror}/centos/{args.release}/centosplus/x86_64/os"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/Everything/x86_64"
    else:
        appstream_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=AppStream"
        baseos_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=BaseOS"
        extras_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=extras"
        centosplus_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=centosplus"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=x86_64"

    setup_dnf(
        args,
        root,
        repos=[
            Repo("AppStream", f"CentOS-{args.release} - AppStream", appstream_url, gpgpath, gpgurl),
            Repo("BaseOS", f"CentOS-{args.release} - Base", baseos_url, gpgpath, gpgurl),
            Repo("extras", f"CentOS-{args.release} - Extras", extras_url, gpgpath, gpgurl),
            Repo("centosplus", f"CentOS-{args.release} - Plus", centosplus_url, gpgpath, gpgurl),
            Repo(
                "epel",
                f"name=Extra Packages for Enterprise Linux {epel_release} - $basearch",
                epel_url,
                epel_gpgpath,
                epel_gpgurl,
            ),
        ],
    )

    return ["AppStream", "BaseOS", "extras", "centosplus"]


def is_older_than_centos8(release: str) -> bool:
    # CentOS 7 contains some very old versions of certain libraries
    # which require workarounds in different places.
    # Additionally the repositories have been changed between 7 and 8
    epel_release = release.split(".")[0]
    try:
        return int(epel_release) <= 7
    except ValueError:
        return False


@complete_step("Installing CentOS")
def install_centos(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    old = is_older_than_centos8(args.release)
    epel_release = int(args.release.split(".")[0])

    if old:
        default_repos = install_centos_old(args, root, epel_release)
    else:
        default_repos = install_centos_new(args, root, epel_release)

    packages = {"centos-release", "systemd", *args.packages}
    if not do_run_build_script and args.bootable:
        packages |= {"kernel", "dracut", "binutils"}
        configure_dracut(args, root)
        if old:
            packages |= {"grub2-efi", "grub2-tools", "grub2-efi-x64-modules", "shim-x64", "efibootmgr", "efivar-libs"}
        else:
            # this does not exist on CentOS 7
            packages.add("systemd-udev")

    if do_run_build_script:
        packages.update(args.build_packages)

    repos = args.repositories or default_repos

    if args.distribution == Distribution.centos_epel:
        repos += ["epel"]
        packages.add("epel-release")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.distribution == Distribution.centos_epel and args.network_veth:
        packages.add("systemd-networkd")

    invoke_dnf_or_yum(args, root, repos, packages, do_run_build_script)


def debootstrap_knows_arg(arg: str) -> bool:
    return bytes("invalid option", "UTF-8") not in run(["debootstrap", arg], stdout=PIPE, check=False).stdout


def install_debian_or_ubuntu(args: CommandLineArguments, root: str, *, do_run_build_script: bool, mirror: str) -> None:
    repos = set(args.repositories) or {"main"}
    # Ubuntu needs the 'universe' repo to install 'dracut'
    if args.distribution == Distribution.ubuntu and args.bootable:
        repos.add("universe")

    cmdline = ["debootstrap", "--variant=minbase", "--merged-usr", f"--components={','.join(repos)}"]

    if args.architecture is not None:
        debarch = DEBIAN_ARCHITECTURES.get(args.architecture)
        cmdline += [f"--arch={debarch}"]

    # Let's use --no-check-valid-until only if debootstrap knows it
    if debootstrap_knows_arg("--no-check-valid-until"):
        cmdline.append("--no-check-valid-until")

    # Either the image builds or it fails and we restart, we don't need safety fsyncs when bootstrapping
    # Add it before debootstrap, as the second stage already uses dpkg from the chroot
    dpkg_io_conf = os.path.join(root, "etc/dpkg/dpkg.cfg.d/unsafe_io")
    os.makedirs(os.path.dirname(dpkg_io_conf), mode=0o755, exist_ok=True)
    with open(dpkg_io_conf, "w") as f:
        f.write("force-unsafe-io\n")

    cmdline += [args.release, root, mirror]
    run(cmdline)

    # Install extra packages via the secondary APT run, because it is smarter and can deal better with any
    # conflicts. dbus and libpam-systemd are optional dependencies for systemd in debian so we include them
    # explicitly.
    extra_packages = {"systemd", "systemd-sysv", "dbus", "libpam-systemd"}
    extra_packages.update(args.packages)

    if do_run_build_script:
        extra_packages.update(args.build_packages)

    if not do_run_build_script and args.bootable:
        extra_packages.add("dracut")
        extra_packages.add("binutils")

        configure_dracut(args, root)

        if args.distribution == Distribution.ubuntu:
            extra_packages.add("linux-generic")
        else:
            extra_packages.add("linux-image-amd64")

        if args.bios_partno:
            extra_packages.add("grub-pc")

        if args.output_format == OutputFormat.gpt_btrfs:
            extra_packages.add("btrfs-progs")

    if not do_run_build_script and args.ssh:
        extra_packages.add("openssh-server")

    # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
    # start. Let's install one that denies all daemon startups.
    # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
    # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
    # the admin.
    policyrcd = os.path.join(root, "usr/sbin/policy-rc.d")
    with open(policyrcd, "w") as f:
        f.write("#!/bin/sh\nexit 101\n")
    os.chmod(policyrcd, 0o755)

    doc_paths = [
        "/usr/share/locale",
        "/usr/share/doc",
        "/usr/share/man",
        "/usr/share/groff",
        "/usr/share/info",
        "/usr/share/lintian",
        "/usr/share/linda",
    ]
    if not args.with_docs:
        # Remove documentation installed by debootstrap
        cmdline = ["/bin/rm", "-rf"] + doc_paths
        run_workspace_command(args, root, cmdline)
        # Create dpkg.cfg to ignore documentation on new packages
        dpkg_conf = os.path.join(root, "etc/dpkg/dpkg.cfg.d/01_nodoc")
        with open(dpkg_conf, "w") as f:
            f.writelines(f"path-exclude {d}/*\n" for d in doc_paths)

    cmdline = ["/usr/bin/apt-get", "--assume-yes", "--no-install-recommends", "install", *extra_packages]
    env = {
        "DEBIAN_FRONTEND": "noninteractive",
        "DEBCONF_NONINTERACTIVE_SEEN": "true",
    }

    if not do_run_build_script and args.bootable and args.with_unified_kernel_images:
        # Disable dracut postinstall script for this apt-get run.
        env["INITRD"] = "No"

        if args.distribution == Distribution.debian and args.release == "unstable":
            # systemd-boot won't boot unified kernel images generated without a BUILD_ID or VERSION_ID in
            # /etc/os-release.
            with open(os.path.join(root, "etc/os-release"), "a") as f:
                f.write("BUILD_ID=unstable\n")

    run_workspace_command(args, root, cmdline, network=True, env=env)
    os.unlink(policyrcd)
    os.unlink(dpkg_io_conf)
    # Debian still has pam_securetty module enabled
    disable_pam_securetty(root)


@complete_step("Installing Debian")
def install_debian(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    install_debian_or_ubuntu(args, root, do_run_build_script=do_run_build_script, mirror=args.mirror)


@complete_step("Installing Ubuntu")
def install_ubuntu(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    install_debian_or_ubuntu(args, root, do_run_build_script=do_run_build_script, mirror=args.mirror)


@complete_step("Installing Arch Linux")
def install_arch(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    if args.release is not None:
        MkosiPrinter.info("Distribution release specification is not supported for Arch Linux, ignoring.")

    if args.mirror:
        if platform.machine() == "aarch64":
            server = f"Server = {args.mirror}/$arch/$repo"
        else:
            server = f"Server = {args.mirror}/$repo/os/$arch"
    else:
        # Instead of harcoding a single mirror, we retrieve a list of mirrors from Arch's mirrorlist
        # generator ordered by mirror score. This usually results in a solid mirror and also ensures that we
        # have fallback mirrors available if necessary. Finally, the mirrors will be more likely to be up to
        # date and we won't end up with a stable release that hardcodes a broken mirror.
        mirrorlist = os.path.join(workspace(root), "mirrorlist")
        with urllib.request.urlopen(
            "https://www.archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4&use_mirror_status=on"
        ) as r:
            with open(mirrorlist, "w") as f:
                mirrors = r.readlines()
                uncommented = [line.decode("utf-8")[1:] for line in mirrors]
                f.writelines(uncommented)
                server = f"Include = {mirrorlist}"

    # Create base layout for pacman and pacman-key
    os.makedirs(os.path.join(root, "var/lib/pacman"), 0o755, exist_ok=True)
    os.makedirs(os.path.join(root, "etc/pacman.d/gnupg"), 0o755, exist_ok=True)

    # Permissions on these directories are all 0o777 because of `mount --bind`
    # limitations but pacman expects them to be 0o755 so we fix them before
    # calling pacstrap (except /var/tmp which is 0o1777).
    fix_permissions_dirs = {
        "boot": 0o755,
        "etc": 0o755,
        "etc/pacman.d": 0o755,
        "var": 0o755,
        "var/lib": 0o755,
        "var/cache": 0o755,
        "var/cache/pacman": 0o755,
        "var/tmp": 0o1777,
        "run": 0o755,
    }

    for dir, permissions in fix_permissions_dirs.items():
        path = os.path.join(root, dir)
        if os.path.exists(path):
            os.chmod(path, permissions)

    pacman_conf = os.path.join(workspace(root), "pacman.conf")
    with open(pacman_conf, "w") as f:
        f.write(
            dedent(
                f"""\
                [options]
                RootDir     = {root}
                LogFile     = /dev/null
                CacheDir    = {root}/var/cache/pacman/pkg/
                GPGDir      = {root}/etc/pacman.d/gnupg/
                HookDir     = {root}/etc/pacman.d/hooks/
                HoldPkg     = pacman glibc
                Architecture = auto
                Color
                CheckSpace
                SigLevel    = Required DatabaseOptional TrustAll

                [core]
                {server}

                [extra]
                {server}

                [community]
                {server}
                """
            )
        )

        if args.repositories:
            for repository in args.repositories:
                # repositories must be passed in the form <repo name>::<repo url>
                repository_name, repository_server = repository.split("::", 1)

                # note: for additional repositories, signature checking options are set to pacman's default values
                f.write(
                    dedent(
                        f"""\

                        [{repository_name}]
                        SigLevel = Optional TrustedOnly
                        Server = {repository_server}
                        """
                    )
                )

    if not do_run_build_script and args.bootable:
        hooks_dir = os.path.join(root, "etc/pacman.d/hooks")
        scripts_dir = os.path.join(root, "etc/pacman.d/scripts")

        os.makedirs(hooks_dir, 0o755, exist_ok=True)
        os.makedirs(scripts_dir, 0o755, exist_ok=True)

        # Disable depmod pacman hook as depmod is handled by kernel-install as well.
        os.symlink("/dev/null", os.path.join(hooks_dir, "60-depmod.hook"))

        kernel_add_hook = os.path.join(hooks_dir, "90-mkosi-kernel-add.hook")
        with open(kernel_add_hook, "w") as f:
            f.write(
                dedent(
                    """\
                    [Trigger]
                    Operation = Install
                    Operation = Upgrade
                    Type = Path
                    Target = usr/lib/modules/*/vmlinuz
                    Target = usr/lib/kernel/install.d/*
                    Target = boot/*-ucode.img

                    [Trigger]
                    Operation = Install
                    Operation = Upgrade
                    Type = Package
                    Target = systemd

                    [Action]
                    Description = Adding kernel and initramfs images to /boot...
                    When = PostTransaction
                    Exec = /etc/pacman.d/scripts/mkosi-kernel-add
                    NeedsTargets
                    """
                )
            )

        kernel_add_script = os.path.join(scripts_dir, "mkosi-kernel-add")
        with open(kernel_add_script, "w") as f:
            f.write(
                dedent(
                    """\
                    #!/bin/bash -e
                    shopt -s nullglob

                    declare -a kernel_version

                    # Check the targets passed by the pacman hook.
                    while read -r line
                    do
                        if [[ "$line" =~ usr/lib/modules/([^/]+)/vmlinuz ]]
                        then
                            kernel_version+=( "${BASH_REMATCH[1]}" )
                        else
                            # If a non-matching line is passed, just rebuild all kernels.
                            kernel_version=()
                            for f in /usr/lib/modules/*/vmlinuz
                            do
                                kernel_version+=( "$(basename "$(dirname "$f")")" )
                            done
                            break
                        fi
                    done

                    # (re)build the kernel images.
                    for kv in "${kernel_version[@]}"
                    do
                        kernel-install add "$kv" "/usr/lib/modules/${kv}/vmlinuz"
                    done
                    """
                )
            )

        make_executable(kernel_add_script)

        kernel_remove_hook = os.path.join(hooks_dir, "60-mkosi-kernel-remove.hook")
        with open(kernel_remove_hook, "w") as f:
            f.write(
                dedent(
                    """\
                    [Trigger]
                    Operation = Upgrade
                    Operation = Remove
                    Type = Path
                    Target = usr/lib/modules/*/vmlinuz

                    [Action]
                    Description = Removing kernel and initramfs images from /boot...
                    When = PreTransaction
                    Exec = /etc/pacman.d/mkosi-kernel-remove
                    NeedsTargets
                    """
                )
            )

        kernel_remove_script = os.path.join(scripts_dir, "mkosi-kernel-remove")
        with open(kernel_remove_script, "w") as f:
            f.write(
                dedent(
                    """\
                    #!/bin/bash -e

                    while read -r f; do
                        kernel-install remove "$(basename "$(dirname "$f")")"
                    done
                    """
                )
            )

        make_executable(kernel_remove_script)

        if args.esp_partno is not None:
            bootctl_update_hook = os.path.join(hooks_dir, "91-mkosi-bootctl-update-hook")
            with open(bootctl_update_hook, "w") as f:
                f.write(
                    dedent(
                        """\
                        [Trigger]
                        Operation = Upgrade
                        Type = Package
                        Target = systemd

                        [Action]
                        Description = Updating systemd-boot...
                        When = PostTransaction
                        Exec = /usr/bin/bootctl update
                        """
                    )
                )

        if args.bios_partno is not None:
            vmlinuz_add_hook = os.path.join(hooks_dir, "90-mkosi-vmlinuz-add.hook")
            with open(vmlinuz_add_hook, "w") as f:
                f.write(
                    """\
                    [Trigger]
                    Operation = Install
                    Operation = Upgrade
                    Type = Path
                    Target = usr/lib/modules/*/vmlinuz

                    [Action]
                    Description = Adding vmlinuz to /boot...
                    When = PostTransaction
                    Exec = /bin/bash -c 'while read -r f; do install -Dm644 "$f" "/boot/vmlinuz-$(basename "$(dirname "$f")")"; done'
                    NeedsTargets
                    """
                )

            make_executable(vmlinuz_add_hook)

            vmlinuz_remove_hook = os.path.join(hooks_dir, "60-mkosi-vmlinuz-remove.hook")
            with open(vmlinuz_remove_hook, "w") as f:
                f.write(
                    """\
                    [Trigger]
                    Operation = Upgrade
                    Operation = Remove
                    Type = Path
                    Target = usr/lib/modules/*/vmlinuz

                    [Action]
                    Description = Removing vmlinuz from /boot...
                    When = PreTransaction
                    Exec = /bin/bash -c 'while read -r f; do rm -f "/boot/vmlinuz-$(basename "$(dirname "$f")")"; done'
                    NeedsTargets
                    """
                )

            make_executable(vmlinuz_remove_hook)

    keyring = "archlinux"
    if platform.machine() == "aarch64":
        keyring += "arm"

    packages = {"base"}

    if not do_run_build_script and args.bootable:
        if args.output_format == OutputFormat.gpt_btrfs:
            packages.add("btrfs-progs")
        elif args.output_format == OutputFormat.gpt_xfs:
            packages.add("xfsprogs")
        if args.encrypt:
            packages.add("cryptsetup")
            packages.add("device-mapper")
        if args.bios_partno:
            packages.add("grub")

        packages.add("dracut")
        packages.add("binutils")

        configure_dracut(args, root)

    packages.update(args.packages)

    official_kernel_packages = {
        "linux",
        "linux-lts",
        "linux-hardened",
        "linux-zen",
    }

    has_kernel_package = official_kernel_packages.intersection(args.packages)
    if not do_run_build_script and args.bootable and not has_kernel_package:
        # No user-specified kernel
        packages.add("linux")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.ssh:
        packages.add("openssh")

    def run_pacman(packages: Set[str]) -> None:
        conf = ["--config", pacman_conf]

        try:
            run(["pacman-key", *conf, "--init"])
            run(["pacman-key", *conf, "--populate"])
            run(["pacman", *conf, "--noconfirm", "-Sy", *packages])
        finally:
            # Kill the gpg-agent started by pacman and pacman-key.
            run(["gpgconf", "--homedir", os.path.join(root, "etc/pacman.d/gnupg"), "--kill", "all"])

    with mount_api_vfs(args, root):
        run_pacman(packages)

    # If /etc/locale.gen exists, uncomment the desired locale and leave the rest of the file untouched.
    # If it doesn’t exist, just write the desired locale in it.
    try:

        def _enable_locale(line: str) -> str:
            if line.startswith("#en_US.UTF-8"):
                return line.replace("#", "")
            return line

        patch_file(os.path.join(root, "etc/locale.gen"), _enable_locale)

    except FileNotFoundError:
        with open(os.path.join(root, "etc/locale.gen"), "x") as f:
            f.write("en_US.UTF-8 UTF-8\n")

    run_workspace_command(args, root, ["/usr/bin/locale-gen"])

    with open(os.path.join(root, "etc/locale.conf"), "w") as f:
        f.write("LANG=en_US.UTF-8\n")

    # Arch still uses pam_securetty which prevents root login into
    # systemd-nspawn containers. See https://bugs.archlinux.org/task/45903.
    disable_pam_securetty(root)


@complete_step("Installing openSUSE")
def install_opensuse(args: CommandLineArguments, root: str, do_run_build_script: bool) -> None:
    release = args.release.strip('"')

    # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy (14.x won't ever appear). For
    # anything else, let's default to Leap.
    if release.isdigit() or release == "tumbleweed":
        release_url = f"{args.mirror}/tumbleweed/repo/oss/"
        updates_url = f"{args.mirror}/update/tumbleweed/"
    elif release == "leap":
        release_url = f"{args.mirror}/distribution/leap/15.1/repo/oss/"
        updates_url = f"{args.mirror}/update/leap/15.1/oss/"
    elif release == "current":
        release_url = f"{args.mirror}/distribution/openSUSE-stable/repo/oss/"
        updates_url = f"{args.mirror}/update/openSUSE-current/"
    elif release == "stable":
        release_url = f"{args.mirror}/distribution/openSUSE-stable/repo/oss/"
        updates_url = f"{args.mirror}/update/openSUSE-stable/"
    else:
        release_url = f"{args.mirror}/distribution/leap/{release}/repo/oss/"
        updates_url = f"{args.mirror}/update/leap/{release}/oss/"

    # Configure the repositories: we need to enable packages caching here to make sure that the package cache
    # stays populated after "zypper install".
    run(["zypper", "--root", root, "addrepo", "-ck", release_url, "repo-oss"])
    run(["zypper", "--root", root, "addrepo", "-ck", updates_url, "repo-update"])

    if not args.with_docs:
        with open(os.path.join(root, "etc/zypp/zypp.conf"), "w") as f:
            f.write("rpm.install.excludedocs = yes\n")

    packages = {"systemd", *args.packages}

    if release.startswith("42."):
        packages.add("patterns-openSUSE-minimal_base")
    else:
        packages.add("patterns-base-minimal_base")

    if not do_run_build_script and args.bootable:
        packages.add("kernel-default")
        packages.add("dracut")
        packages.add("binutils")

        configure_dracut(args, root)

        if args.bios_partno is not None:
            packages.add("grub2")

    if not do_run_build_script and args.encrypt:
        packages.add("device-mapper")

    if args.output_format in (OutputFormat.subvolume, OutputFormat.gpt_btrfs):
        packages.add("btrfsprogs")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.ssh:
        packages.update("openssh-server")

    cmdline = [
        "zypper",
        "--root",
        root,
        "--gpg-auto-import-keys",
        "install",
        "-y",
        "--no-recommends",
        "--download-in-advance",
        *packages,
    ]

    with mount_api_vfs(args, root):
        run(cmdline)

    # Disable packages caching in the image that was enabled previously to populate the package cache.
    run(["zypper", "--root", root, "modifyrepo", "-K", "repo-oss"])
    run(["zypper", "--root", root, "modifyrepo", "-K", "repo-update"])

    if args.password == "":
        shutil.copy2(os.path.join(root, "usr/etc/pam.d/common-auth"), os.path.join(root, "etc/pam.d/common-auth"))

        def jj(line: str) -> str:
            if "pam_unix.so" in line:
                return f"{line.strip()} nullok"
            return line

        patch_file(os.path.join(root, "etc/pam.d/common-auth"), jj)


def install_distribution(args: CommandLineArguments, root: str, do_run_build_script: bool, cached: bool) -> None:
    if cached:
        return

    install: Dict[Distribution, Callable[[CommandLineArguments, str, bool], None]] = {
        Distribution.fedora: install_fedora,
        Distribution.centos: install_centos,
        Distribution.centos_epel: install_centos,
        Distribution.mageia: install_mageia,
        Distribution.debian: install_debian,
        Distribution.ubuntu: install_ubuntu,
        Distribution.arch: install_arch,
        Distribution.opensuse: install_opensuse,
        Distribution.clear: install_clear,
        Distribution.photon: install_photon,
        Distribution.openmandriva: install_openmandriva,
    }

    disable_kernel_install(args, root)

    with mount_cache(args, root):
        install[args.distribution](args, root, do_run_build_script)

    reenable_kernel_install(args, root)


def reset_machine_id(args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool) -> None:
    """Make /etc/machine-id an empty file.

    This way, on the next boot is either initialized and committed (if /etc is
    writable) or the image runs with a transient machine ID, that changes on
    each boot (if the image is read-only).
    """

    if do_run_build_script:
        return
    if for_cache:
        return

    with complete_step("Resetting machine ID"):
        machine_id = os.path.join(root, "etc/machine-id")
        try:
            os.unlink(machine_id)
        except FileNotFoundError:
            pass
        open(machine_id, "w+b").close()
        dbus_machine_id = os.path.join(root, "var/lib/dbus/machine-id")
        try:
            os.unlink(dbus_machine_id)
        except FileNotFoundError:
            pass
        else:
            os.symlink("../../../etc/machine-id", dbus_machine_id)


def reset_random_seed(args: CommandLineArguments, root: str) -> None:
    """Remove random seed file, so that it is initialized on first boot"""
    random_seed = os.path.join(root, "var/lib/systemd/random-seed")
    if not os.path.exists(random_seed):
        return

    with complete_step("Removing random seed"):
        os.unlink(random_seed)


def set_root_password(args: CommandLineArguments, root: str, do_run_build_script: bool, cached: bool) -> None:
    "Set the root account password, or just delete it so it's easy to log in"

    if do_run_build_script:
        return
    if cached:
        return

    if args.password == "":
        with complete_step("Deleting root password"):

            def jj(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", ""] + line.split(":")[2:])
                return line

            patch_file(os.path.join(root, "etc/passwd"), jj)
    elif args.password:
        with complete_step("Setting root password"):
            if args.password_is_hashed:
                password = args.password
            else:
                password = crypt.crypt(args.password, crypt.mksalt(crypt.METHOD_SHA512))

            def jj(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", password] + line.split(":")[2:])
                return line

            patch_file(os.path.join(root, "etc/shadow"), jj)


def pam_add_autologin(root: str, tty: str) -> None:
    with open(os.path.join(root, "etc/pam.d/login"), "r+") as f:
        original = f.read()
        f.seek(0)
        f.write(f"auth sufficient pam_succeed_if.so tty = {tty}\n")
        f.write(original)


def set_autologin(args: CommandLineArguments, root: str, do_run_build_script: bool, cached: bool) -> None:
    if do_run_build_script or cached or not args.autologin:
        return

    with complete_step("Setting up autologin"):
        # On Debian, PAM wants the full path to the console device or it will refuse access
        device_prefix = "/dev/" if args.distribution is Distribution.debian else ""

        override_dir = os.path.join(root, "etc/systemd/system/console-getty.service.d")
        os.makedirs(override_dir, mode=0o755, exist_ok=True)

        override_file = os.path.join(override_dir, "autologin.conf")
        with open(override_file, "w") as f:
            f.write(
                dedent(
                    r"""
                    [Service]
                    ExecStart=
                    ExecStart=-/sbin/agetty -o '-p -- \\u' --noclear --autologin root --keep-baud console 115200,38400,9600 $TERM
                    """
                )
            )

        os.chmod(override_file, 0o644)

        pam_add_autologin(root, f"{device_prefix}pts/0")

        override_dir = os.path.join(root, "etc/systemd/system/serial-getty@ttyS0.service.d")
        os.makedirs(override_dir, mode=0o755, exist_ok=True)

        override_file = os.path.join(override_dir, "autologin.conf")
        with open(override_file, "w") as f:
            f.write(
                dedent(
                    r"""
                    [Service]
                    ExecStart=
                    ExecStart=-/sbin/agetty -o '-p -- \\u' --autologin root --keep-baud 115200,57600,38400,9600 %I $TERM
                    """
                )
            )

        os.chmod(override_file, 0o644)

        pam_add_autologin(root, f"{device_prefix}ttyS0")

        override_dir = os.path.join(root, "etc/systemd/system/getty@tty1.service.d")
        os.makedirs(override_dir, mode=0o755, exist_ok=True)

        override_file = os.path.join(override_dir, "autologin.conf")
        with open(override_file, "w") as f:
            f.write(
                dedent(
                    r"""
                    [Service]
                    ExecStart=
                    ExecStart=-/sbin/agetty -o '-p -- \\u' --autologin root --noclear %I $TERM
                    """
                )
            )

        os.chmod(override_file, 0o644)

        pam_add_autologin(root, f"{device_prefix}tty1")
        pam_add_autologin(root, f"{device_prefix}console")


def set_serial_terminal(args: CommandLineArguments, root: str, do_run_build_script: bool, cached: bool) -> None:
    """Override TERM for the serial console with the terminal type from the host."""

    if do_run_build_script or cached or not args.qemu_headless:
        return

    with complete_step("Configuring serial tty (ttyS0)"):
        override_dir = os.path.join(root, "etc/systemd/system/serial-getty@ttyS0.service.d")
        os.makedirs(override_dir, mode=0o755, exist_ok=True)

        columns, lines = shutil.get_terminal_size(fallback=(80, 24))
        override_file = os.path.join(override_dir, "term.conf")
        with open(override_file, "w") as f:
            f.write(
                dedent(
                    f"""
                    [Service]
                    Environment=TERM={os.getenv('TERM', 'vt220')}
                    Environment=COLUMNS={columns}
                    Environment=LINES={lines}
                    """
                )
            )

        os.chmod(override_file, 0o644)


def nspawn_params_for_build_sources(args: CommandLineArguments, sft: SourceFileTransfer) -> List[str]:
    params = []

    if args.build_sources is not None:
        params.append("--setenv=SRCDIR=/root/src")
        params.append("--chdir=/root/src")
        if sft == SourceFileTransfer.mount:
            params.append("--bind=" + args.build_sources + ":/root/src")

        if args.read_only:
            params.append("--overlay=+/root/src::/root/src")
    else:
        params.append("--chdir=/root")

    return params


def run_prepare_script(args: CommandLineArguments, root: str, do_run_build_script: bool, cached: bool) -> None:
    if args.prepare_script is None:
        return
    if cached:
        return

    verb = "build" if do_run_build_script else "final"

    with mount_cache(args, root), complete_step("Running prepare script"):

        # We copy the prepare script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(args.prepare_script, os.path.join(root, "root/prepare"))

        nspawn_params = nspawn_params_for_build_sources(args, SourceFileTransfer.mount)
        run_workspace_command(args, root, ["/root/prepare", verb], network=True, nspawn_params=nspawn_params)

        if os.path.exists(os.path.join(root, "root/src")):
            os.rmdir(os.path.join(root, "root/src"))
        os.unlink(os.path.join(root, "root/prepare"))


def run_postinst_script(
    args: CommandLineArguments, root: str, loopdev: Optional[str], do_run_build_script: bool, for_cache: bool
) -> None:
    if args.postinst_script is None:
        return
    if for_cache:
        return

    verb = "build" if do_run_build_script else "final"

    with mount_cache(args, root), complete_step("Running postinstall script"):

        # We copy the postinst script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(args.postinst_script, os.path.join(root, "root/postinst"))

        nspawn_params = []
        # in order to have full blockdev access, i.e. for making grub2 bootloader changes
        # we need to have these bind mounts for a proper chroot setup
        if args.bootable:
            if loopdev is None:
                raise ValueError("Parameter 'loopdev' required for bootable images.")
            nspawn_params += nspawn_params_for_blockdev_access(args, loopdev)

        run_workspace_command(
            args, root, ["/root/postinst", verb], network=args.with_network, nspawn_params=nspawn_params
        )
        os.unlink(os.path.join(root, "root/postinst"))


def output_dir(args: CommandLineArguments) -> str:
    return args.output_dir or os.getcwd()


def run_finalize_script(args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool) -> None:
    if args.finalize_script is None:
        return
    if for_cache:
        return

    verb = "build" if do_run_build_script else "final"

    with complete_step("Running finalize script"):
        env = collections.ChainMap({"BUILDROOT": root, "OUTPUTDIR": output_dir(args)}, os.environ)
        run([args.finalize_script, verb], env=env)


def nspawn_params_for_blockdev_access(args: CommandLineArguments, loopdev: str) -> List[str]:
    params = [
        f"--bind-ro={loopdev}",
        f"--bind-ro=/dev/block",
        f"--bind-ro=/dev/disk",
        f"--property=DeviceAllow={loopdev}",
    ]
    for partno in (args.esp_partno, args.bios_partno, args.root_partno, args.xbootldr_partno):
        if partno is not None:
            p = partition(loopdev, partno)
            if os.path.exists(p):
                params += [f"--bind-ro={p}", f"--property=DeviceAllow={p}"]
    return params


def write_grub_config(args: CommandLineArguments, root: str) -> None:
    kernel_cmd_line = " ".join(args.kernel_command_line)
    grub_cmdline = f'GRUB_CMDLINE_LINUX="{kernel_cmd_line}"\n'
    os.makedirs(os.path.join(root, "etc/default"), exist_ok=True, mode=0o755)
    grub_config = os.path.join(root, "etc/default/grub")
    if not os.path.exists(grub_config):
        with open(grub_config, "w+") as f:
            f.write(grub_cmdline)
    else:

        def jj(line: str) -> str:
            if line.startswith("GRUB_CMDLINE_LINUX="):
                return grub_cmdline
            if args.qemu_headless:
                if "GRUB_TERMINAL_INPUT" in line:
                    return 'GRUB_TERMINAL_INPUT="console serial"'
                if "GRUB_TERMINAL_OUTPUT" in line:
                    return 'GRUB_TERMINAL_OUTPUT="console serial"'
            return line

        patch_file(grub_config, jj)

        if args.qemu_headless:
            with open(grub_config, "a") as f:
                f.write('GRUB_SERIAL_COMMAND="serial --unit=0 --speed 115200"\n')


def install_grub(args: CommandLineArguments, root: str, loopdev: str, grub: str) -> None:
    if args.bios_partno is None:
        return

    write_grub_config(args, root)

    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    cmdline = [f"{grub}-install", "--modules=ext2 part_gpt", "--target=i386-pc", loopdev]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)

    # TODO: Remove os.path.basename once https://github.com/systemd/systemd/pull/16645 is widely available.
    cmdline = [f"{grub}-mkconfig", f"--output=/boot/{os.path.basename(grub)}/grub.cfg"]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)


def install_boot_loader_clear(args: CommandLineArguments, root: str, loopdev: str) -> None:
    # clr-boot-manager uses blkid in the device backing "/" to
    # figure out uuid and related parameters.
    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    cmdline = ["/usr/bin/clr-boot-manager", "update", "-i"]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)


def install_boot_loader_centos_old_efi(args: CommandLineArguments, root: str, loopdev: str) -> None:
    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    # prepare EFI directory on ESP
    os.makedirs(os.path.join(root, "efi/EFI/centos"), exist_ok=True)

    # patch existing or create minimal GRUB_CMDLINE config
    write_grub_config(args, root)

    # generate grub2 efi boot config
    cmdline = ["/sbin/grub2-mkconfig", "-o", "/efi/EFI/centos/grub.cfg"]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)

    # if /sys/firmware/efi is not present within systemd-nspawn the grub2-mkconfig makes false assumptions, let's fix this
    def _fix_grub(line: str) -> str:
        if "linux16" in line:
            return line.replace("linux16", "linuxefi")
        elif "initrd16" in line:
            return line.replace("initrd16", "initrdefi")
        return line

    patch_file(os.path.join(root, "efi/EFI/centos/grub.cfg"), _fix_grub)


def install_boot_loader(
    args: CommandLineArguments, root: str, loopdev: Optional[str], do_run_build_script: bool, cached: bool
) -> None:
    if not args.bootable or do_run_build_script:
        return
    assert loopdev is not None

    if cached:
        return

    with complete_step("Installing boot loader"):
        if args.esp_partno:
            if args.distribution == Distribution.clear:
                pass
            elif args.distribution in (Distribution.centos, Distribution.centos_epel) and is_older_than_centos8(
                args.release
            ):
                install_boot_loader_centos_old_efi(args, root, loopdev)
            else:
                run_workspace_command(args, root, ["bootctl", "install"])

        if args.bios_partno and args.distribution != Distribution.clear:
            grub = (
                "grub"
                if args.distribution in (Distribution.ubuntu, Distribution.debian, Distribution.arch)
                else "grub2"
            )
            # TODO: Just use "grub" once https://github.com/systemd/systemd/pull/16645 is widely available.
            if args.distribution in (Distribution.ubuntu, Distribution.debian, Distribution.opensuse):
                grub = f"/usr/sbin/{grub}"

            install_grub(args, root, loopdev, grub)

        if args.distribution == Distribution.clear:
            install_boot_loader_clear(args, root, loopdev)


def install_extra_trees(args: CommandLineArguments, root: str, for_cache: bool) -> None:
    if not args.extra_trees:
        return

    if for_cache:
        return

    with complete_step("Copying in extra file trees"):
        for d in args.extra_trees:
            if os.path.isdir(d):
                copy_path(d, root)
            else:
                shutil.unpack_archive(d, root)


def install_skeleton_trees(args: CommandLineArguments, root: str, for_cache: bool) -> None:
    if not args.skeleton_trees:
        return

    with complete_step("Copying in skeleton file trees"):
        for d in args.skeleton_trees:
            if os.path.isdir(d):
                copy_path(d, root)
            else:
                shutil.unpack_archive(d, root)


def copy_git_files(src: str, dest: str, *, source_file_transfer: SourceFileTransfer) -> None:
    what_files = ["--exclude-standard", "--cached"]
    if source_file_transfer == SourceFileTransfer.copy_git_others:
        what_files += ["--others", "--exclude=.mkosi-*"]

    c = run(["git", "-C", src, "ls-files", "-z"] + what_files, stdout=PIPE, universal_newlines=False, check=True)
    files = {x.decode("utf-8") for x in c.stdout.rstrip(b"\0").split(b"\0")}

    # Add the .git/ directory in as well.
    if source_file_transfer == SourceFileTransfer.copy_git_more:
        # r=root, d=directories, f=files
        top = os.path.join(src, ".git/")
        for r, d, f in os.walk(top):
            for fh in f:
                fp = os.path.join(r, fh)  # full path
                fr = os.path.join(".git/", fp[len(top) :])  # relative to top
                files.add(fr)

    # Get submodule files
    c = run(["git", "-C", src, "submodule", "status", "--recursive"], stdout=PIPE, universal_newlines=True, check=True)
    submodules = {x.split()[1] for x in c.stdout.splitlines()}

    # workaround for git-ls-files returning the path of submodules that we will
    # still parse
    files -= submodules

    for sm in submodules:
        c = run(
            ["git", "-C", os.path.join(src, sm), "ls-files", "-z"] + what_files,
            stdout=PIPE,
            universal_newlines=False,
            check=True,
        )
        files |= {os.path.join(sm, x.decode("utf-8")) for x in c.stdout.rstrip(b"\0").split(b"\0")}
        files -= submodules

    del c

    for path in files:
        src_path = os.path.join(src, path)
        dest_path = os.path.join(dest, path)

        directory = os.path.dirname(dest_path)
        os.makedirs(directory, exist_ok=True)

        copy_file(src_path, dest_path)


def install_build_src(args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool) -> None:
    if for_cache:
        return

    if args.build_script is None:
        return

    if do_run_build_script:
        with complete_step("Copying in build script"):
            copy_file(args.build_script, os.path.join(root, "root", os.path.basename(args.build_script)))

    if do_run_build_script:
        sft = args.source_file_transfer
    else:
        sft = args.source_file_transfer_final

    if args.build_sources is None or sft is None:
        return

    with complete_step("Copying in sources"):
        target = os.path.join(root, "root/src")

        if sft in (
            SourceFileTransfer.copy_git_others,
            SourceFileTransfer.copy_git_cached,
            SourceFileTransfer.copy_git_more,
        ):
            copy_git_files(args.build_sources, target, source_file_transfer=sft)
        elif sft == SourceFileTransfer.copy_all:
            ignore = shutil.ignore_patterns(
                ".git",
                ".mkosi-*",
                "*.cache-pre-dev",
                "*.cache-pre-inst",
                os.path.basename(args.output_dir) + "/" if args.output_dir else "mkosi.output/",
                os.path.basename(args.cache_path) + "/" if args.cache_path else "mkosi.cache/",
                os.path.basename(args.build_dir) + "/" if args.build_dir else "mkosi.builddir/",
                os.path.basename(args.include_dir) + "/" if args.include_dir else "mkosi.includedir/",
                os.path.basename(args.install_dir) + "/" if args.install_dir else "mkosi.installdir/",
            )
            shutil.copytree(args.build_sources, target, symlinks=True, ignore=ignore)


def install_build_dest(args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool) -> None:
    if do_run_build_script:
        return
    if for_cache:
        return

    if args.build_script is None:
        return

    with complete_step("Copying in build tree"):
        copy_path(install_dir(args, root), root)


def make_read_only(args: CommandLineArguments, root: str, for_cache: bool, b: bool = True) -> None:
    if not args.read_only:
        return
    if for_cache:
        return

    if args.output_format not in (OutputFormat.gpt_btrfs, OutputFormat.subvolume):
        return

    with complete_step("Marking root subvolume read-only"):
        btrfs_subvol_make_ro(root, b)


def make_tar(args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool) -> Optional[BinaryIO]:
    if do_run_build_script:
        return None
    if args.output_format != OutputFormat.tar:
        return None
    if for_cache:
        return None

    with complete_step("Creating archive"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(args.output), prefix=".mkosi-"))
        # OpenMandriva defaults to bsdtar(libarchive) which uses POSIX argument list so let's keep a separate list
        if shutil.which("bsdtar") and args.distribution == Distribution.openmandriva:
            _tar_cmd = ["bsdtar", "-C", root, "-c", "-J", "--xattrs", "-f", "-", "."]
        else:
            _tar_cmd = ["tar", "-C", root, "-c", "-J", "--xattrs", "--xattrs-include=*"]
            if args.tar_strip_selinux_context:
                _tar_cmd.append("--xattrs-exclude=security.selinux")
            _tar_cmd.append(".")

        run(_tar_cmd, env={"XZ_OPT": "-T0"}, stdout=f)

    return f


def make_squashfs(args: CommandLineArguments, root: str, for_cache: bool) -> Optional[BinaryIO]:
    if not args.output_format.is_squashfs():
        return None
    if for_cache:
        return None

    command = args.mksquashfs_tool[0] if args.mksquashfs_tool else "mksquashfs"
    comp_args = args.mksquashfs_tool[1:] if args.mksquashfs_tool and args.mksquashfs_tool[1:] else ["-noappend"]

    if args.compress is not True:
        assert args.compress is not False
        comp_args += ["-comp", args.compress]

    with complete_step("Creating squashfs file system"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-squashfs", dir=os.path.dirname(args.output))
        )
        run([command, root, f.name, *comp_args])

    return f


def make_minimal_ext4(args: CommandLineArguments, root: str, for_cache: bool) -> Optional[BinaryIO]:
    if args.output_format != OutputFormat.gpt_ext4:
        return None
    if not args.minimize:
        return None
    if for_cache:
        return None

    with complete_step("Creating ext4 root file system"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-mkfs-ext4", dir=os.path.dirname(args.output))
        )
        f.truncate(args.root_size)
        run(["mkfs.ext4", "-I", "256", "-L", "root", "-M", "/", "-d", root, f.name])

    with complete_step("Minimizing ext4 root file system"):
        run(["resize2fs", "-M", f.name])

    return f


def make_minimal_btrfs(args: CommandLineArguments, root: str, for_cache: bool) -> Optional[BinaryIO]:
    if args.output_format != OutputFormat.gpt_btrfs:
        return None
    if not args.minimize:
        return None
    if for_cache:
        return None

    with complete_step("Creating minimal btrfs root file system"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-mkfs-btrfs", dir=os.path.dirname(args.output))
        )
        f.truncate(args.root_size)

        command = ["mkfs.btrfs", "-L", "root", "-d", "single", "-m", "single", "--shrink", "--rootdir", root, f.name]
        try:
            run(command)
        except subprocess.CalledProcessError:
            # The --shrink option was added in btrfs-tools 4.14.1, before that it was the default behaviour.
            # If the above fails, let's see if things work if we drop it
            command.remove("--shrink")
            run(command)

    return f


def make_generated_root(args: CommandLineArguments, root: str, for_cache: bool) -> Optional[BinaryIO]:

    if args.output_format == OutputFormat.gpt_ext4:
        return make_minimal_ext4(args, root, for_cache)
    if args.output_format == OutputFormat.gpt_btrfs:
        return make_minimal_btrfs(args, root, for_cache)
    if args.output_format.is_squashfs():
        return make_squashfs(args, root, for_cache)

    return None


def read_partition_table(loopdev: str) -> Tuple[List[str], int]:
    table = []
    last_sector = 0

    c = run(["sfdisk", "--dump", loopdev], stdout=PIPE)

    in_body = False
    for line in c.stdout.decode("utf-8").split("\n"):
        stripped = line.strip()

        if stripped == "":  # empty line is where the body begins
            in_body = True
            continue
        if not in_body:
            continue

        table.append(stripped)

        _, rest = stripped.split(":", 1)
        fields = rest.split(",")

        start = None
        size = None

        for field in fields:
            f = field.strip()

            if f.startswith("start="):
                start = int(f[6:])
            if f.startswith("size="):
                size = int(f[5:])

        if start is not None and size is not None:
            end = start + size
            if end > last_sector:
                last_sector = end

    return table, last_sector * 512


def insert_partition(
    args: CommandLineArguments,
    root: str,
    raw: BinaryIO,
    loopdev: str,
    partno: int,
    blob: BinaryIO,
    name: str,
    type_uuid: uuid.UUID,
    read_only: bool,
    uuid_opt: Optional[uuid.UUID] = None,
) -> int:
    if args.ran_sfdisk:
        old_table, last_partition_sector = read_partition_table(loopdev)
    else:
        # No partition table yet? Then let's fake one...
        old_table = []
        last_partition_sector = GPT_HEADER_SIZE

    blob_size = roundup512(os.stat(blob.name).st_size)
    luks_extra = 2 * 1024 * 1024 if args.encrypt == "all" else 0
    new_size = last_partition_sector + blob_size + luks_extra + GPT_FOOTER_SIZE

    MkosiPrinter.print_step(f"Resizing disk image to {format_bytes(new_size)}...")

    os.truncate(raw.name, new_size)
    run(["losetup", "--set-capacity", loopdev])

    MkosiPrinter.print_step(f"Inserting partition of {format_bytes(blob_size)}...")

    table = "label: gpt\n"
    if args.gpt_first_lba is not None:
        table += f"first-lba: {args.gpt_first_lba:d}\n"

    for t in old_table:
        table += t + "\n"

    if uuid_opt is not None:
        table += "uuid=" + str(uuid_opt) + ", "

    n_sectors = (blob_size + luks_extra) // 512
    table += 'size={}, type={}, attrs={}, name="{}"\n'.format(
        n_sectors, type_uuid, "GUID:60" if read_only else "", name
    )

    print(table)

    run(["sfdisk", "--color=never", loopdev], input=table.encode("utf-8"))
    run(["sync"])

    MkosiPrinter.print_step("Writing partition...")

    if args.root_partno == partno:
        luks_format_root(args, loopdev, False, True)
        dev = luks_setup_root(args, loopdev, False, True)
    else:
        dev = None

    path = dev if dev is not None else partition(loopdev, partno)
    try:
        run(["dd", f"if={blob.name}", f"of={path}", "conv=nocreat"])
    finally:
        luks_close(dev, "Closing LUKS root partition")

    args.ran_sfdisk = True

    return blob_size


def insert_generated_root(
    args: CommandLineArguments,
    root: str,
    raw: Optional[BinaryIO],
    loopdev: Optional[str],
    image: Optional[BinaryIO],
    for_cache: bool,
) -> None:
    if not args.generated_root():
        return
    if not args.output_format.is_disk():
        return
    if for_cache:
        return
    assert raw is not None
    assert loopdev is not None
    assert image is not None

    with complete_step("Inserting generated root partition"):
        args.root_size = insert_partition(
            args,
            root,
            raw,
            loopdev,
            args.root_partno,
            image,
            "Root Partition",
            gpt_root_native(args.architecture).root,
            args.output_format.is_squashfs(),
        )


def make_verity(
    args: CommandLineArguments, root: str, dev: Optional[str], do_run_build_script: bool, for_cache: bool
) -> Tuple[Optional[BinaryIO], Optional[str]]:
    if do_run_build_script or not args.verity:
        return None, None
    if for_cache:
        return None, None
    assert dev is not None

    with complete_step("Generating verity hashes"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(args.output), prefix=".mkosi-"))
        c = run(["veritysetup", "format", dev, f.name], stdout=PIPE)

        for line in c.stdout.decode("utf-8").split("\n"):
            if line.startswith("Root hash:"):
                root_hash = line[10:].strip()
                return f, root_hash

        raise ValueError("Root hash not found")


def insert_verity(
    args: CommandLineArguments,
    root: str,
    raw: Optional[BinaryIO],
    loopdev: Optional[str],
    verity: Optional[BinaryIO],
    root_hash: Optional[str],
    for_cache: bool,
) -> None:
    if verity is None:
        return
    if for_cache:
        return
    assert loopdev is not None
    assert raw is not None
    assert root_hash is not None

    # Use the final 128 bit of the root hash as partition UUID of the verity partition
    u = uuid.UUID(root_hash[-32:])

    with complete_step("Inserting verity partition"):
        insert_partition(
            args,
            root,
            raw,
            loopdev,
            args.verity_partno,
            verity,
            "Verity Partition",
            gpt_root_native(args.architecture).verity,
            True,
            u,
        )


def patch_root_uuid(
    args: CommandLineArguments, loopdev: Optional[str], root_hash: Optional[str], for_cache: bool
) -> None:
    if root_hash is None:
        return
    assert loopdev is not None

    if for_cache:
        return

    # Use the first 128bit of the root hash as partition UUID of the root partition
    u = uuid.UUID(root_hash[:32])

    with complete_step("Patching root partition UUID"):
        run(["sfdisk", "--part-uuid", loopdev, str(args.root_partno), str(u)], check=True)


def install_unified_kernel(
    args: CommandLineArguments,
    root: str,
    root_hash: Optional[str],
    do_run_build_script: bool,
    for_cache: bool,
    cached: bool,
    mount: Callable[[], ContextManager[None]],
) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if not args.bootable or args.esp_partno is None or not args.with_unified_kernel_images:
        return
    if for_cache and args.verity:
        return
    if cached and not args.verity:
        return

    # Don't bother running dracut if this is a development build. Strictly speaking it would probably be a
    # good idea to run it, so that the development environment differs as little as possible from the final
    # build, but then again the initrd should not be relevant for building, and dracut is simply very slow,
    # hence let's avoid it invoking it needlessly, given that we never actually invoke the boot loader on the
    # development image.
    if do_run_build_script:
        return

    with mount(), complete_step("Generating combined kernel + initrd boot file"):
        # Apparently openmandriva hasn't yet completed its usrmerge so we use lib here instead of usr/lib.
        with os.scandir(os.path.join(root, "lib/modules")) as d:
            for kver in d:
                if not kver.is_dir():
                    continue

                prefix = "/boot" if args.xbootldr_partno is not None else "/efi"
                # While the kernel version can generally be found as a directory under /usr/lib/modules, the
                # kernel image files can be found either in /usr/lib/modules/<kernel-version>/vmlinuz or in
                # /boot depending on the distro. By invoking the kernel-install script directly, we can pass
                # the empty string as the kernel image which causes the script to not pass the --kernel-image
                # option to dracut so it searches the image for us.
                cmdline = [
                    "/etc/kernel/install.d/50-mkosi-dracut-unified-kernel.install",
                    "add",
                    kver.name,
                    f"{prefix}/{args.machine_id}/{kver.name}",
                    "",
                ]
                if root_hash is not None:
                    cmdline.append(root_hash)

                run_workspace_command(args, root, cmdline)


def secure_boot_sign(
    args: CommandLineArguments,
    root: str,
    do_run_build_script: bool,
    for_cache: bool,
    cached: bool,
    mount: Callable[[], ContextManager[None]],
) -> None:
    if do_run_build_script:
        return
    if not args.bootable:
        return
    if not args.secure_boot:
        return
    if for_cache and args.verity:
        return
    if cached and not args.verity:
        return

    with mount():
        for path, _, filenames in os.walk(os.path.join(root, "efi")):
            for i in filenames:
                if not i.endswith(".efi") and not i.endswith(".EFI"):
                    continue

                with complete_step(f"Signing EFI binary {i} in ESP"):
                    p = os.path.join(path, i)

                    run(
                        [
                            "sbsign",
                            "--key",
                            args.secure_boot_key,
                            "--cert",
                            args.secure_boot_certificate,
                            "--output",
                            p + ".signed",
                            p,
                        ],
                        check=True,
                    )

                    os.rename(p + ".signed", p)


def xz_output(args: CommandLineArguments, raw: Optional[BinaryIO]) -> Optional[BinaryIO]:
    if not args.output_format.is_disk():
        return raw
    assert raw is not None

    if not args.xz:
        return raw

    xz_binary = "pxz" if shutil.which("pxz") else "xz"

    with complete_step("Compressing image file"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=os.path.dirname(args.output)))
        run([xz_binary, "-c", raw.name], stdout=f)

    return f


def qcow2_output(args: CommandLineArguments, raw: Optional[BinaryIO]) -> Optional[BinaryIO]:
    if not args.output_format.is_disk():
        return raw
    assert raw is not None

    if not args.qcow2:
        return raw

    with complete_step("Converting image file to qcow2"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=os.path.dirname(args.output)))
        run(["qemu-img", "convert", "-onocow=on", "-fraw", "-Oqcow2", raw.name, f.name])

    return f


def write_root_hash_file(args: CommandLineArguments, root_hash: Optional[str]) -> Optional[BinaryIO]:
    if root_hash is None:
        return None

    with complete_step("Writing .roothash file"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(mode="w+b", prefix=".mkosi", dir=os.path.dirname(args.output_root_hash_file)),
        )
        f.write((root_hash + "\n").encode())

    return f


def copy_nspawn_settings(args: CommandLineArguments) -> Optional[BinaryIO]:
    if args.nspawn_settings is None:
        return None

    with complete_step("Copying nspawn settings file"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(
                mode="w+b", prefix=".mkosi-", dir=os.path.dirname(args.output_nspawn_settings)
            ),
        )

        with open(args.nspawn_settings, "rb") as c:
            f.write(c.read())

    return f


def hash_file(of: TextIO, sf: BinaryIO, fname: str) -> None:
    bs = 16 * 1024 ** 2
    h = hashlib.sha256()

    sf.seek(0)
    buf = sf.read(bs)
    while len(buf) > 0:
        h.update(buf)
        buf = sf.read(bs)

    of.write(h.hexdigest() + " *" + fname + "\n")


def calculate_sha256sum(
    args: CommandLineArguments,
    raw: Optional[BinaryIO],
    tar: Optional[BinaryIO],
    root_hash_file: Optional[BinaryIO],
    nspawn_settings: Optional[BinaryIO],
) -> Optional[TextIO]:
    if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        return None

    if not args.checksum:
        return None

    with complete_step("Calculating SHA256SUMS"):
        f: TextIO = cast(
            TextIO,
            tempfile.NamedTemporaryFile(
                mode="w+", prefix=".mkosi-", encoding="utf-8", dir=os.path.dirname(args.output_checksum)
            ),
        )

        if raw is not None:
            hash_file(f, raw, os.path.basename(args.output))
        if tar is not None:
            hash_file(f, tar, os.path.basename(args.output))
        if root_hash_file is not None:
            hash_file(f, root_hash_file, os.path.basename(args.output_root_hash_file))
        if nspawn_settings is not None:
            hash_file(f, nspawn_settings, os.path.basename(args.output_nspawn_settings))

    return f


def calculate_signature(args: CommandLineArguments, checksum: Optional[IO[Any]]) -> Optional[BinaryIO]:
    if not args.sign:
        return None

    if checksum is None:
        return None

    with complete_step("Signing SHA256SUMS"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(mode="wb", prefix=".mkosi-", dir=os.path.dirname(args.output_signature)),
        )

        cmdline = ["gpg", "--detach-sign"]

        if args.key is not None:
            cmdline += ["--default-key", args.key]

        checksum.seek(0)
        run(cmdline, stdin=checksum, stdout=f)

    return f


def calculate_bmap(args: CommandLineArguments, raw: Optional[BinaryIO]) -> Optional[TextIO]:
    if not args.bmap:
        return None

    if not args.output_format.is_disk_rw():
        return None
    assert raw is not None

    with complete_step("Creating BMAP file"):
        f: TextIO = cast(
            TextIO,
            tempfile.NamedTemporaryFile(
                mode="w+", prefix=".mkosi-", encoding="utf-8", dir=os.path.dirname(args.output_bmap)
            ),
        )

        cmdline = ["bmaptool", "create", raw.name]
        run(cmdline, stdout=f)

    return f


def save_cache(args: CommandLineArguments, root: str, raw: Optional[str], cache_path: Optional[str]) -> None:
    if cache_path is None or raw is None:
        return

    with complete_step("Installing cache copy ", "Successfully installed cache copy " + cache_path):

        if args.output_format.is_disk_rw():
            os.chmod(raw, 0o666 & ~args.original_umask)
            shutil.move(raw, cache_path)
        else:
            shutil.move(root, cache_path)


def _link_output(args: CommandLineArguments, oldpath: str, newpath: str) -> None:
    os.chmod(oldpath, 0o666 & ~args.original_umask)
    os.link(oldpath, newpath)
    if args.no_chown:
        return

    sudo_uid = os.getenv("SUDO_UID")
    sudo_gid = os.getenv("SUDO_GID")
    if not (sudo_uid and sudo_gid):
        return

    sudo_user = os.getenv("SUDO_USER", default=sudo_uid)
    with complete_step(
        f"Changing ownership of output file {newpath} to user {sudo_user} (acquired from sudo)",
        f"Successfully changed ownership of {newpath}",
    ):
        os.chown(newpath, int(sudo_uid), int(sudo_gid))


def link_output(args: CommandLineArguments, root: str, artifact: Optional[BinaryIO]) -> None:
    with complete_step("Linking image file", "Successfully linked " + args.output):
        if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
            assert artifact is None

            make_read_only(args, root, for_cache=False, b=False)
            os.rename(root, args.output)
            make_read_only(args, args.output, for_cache=False, b=True)

        elif args.output_format.is_disk() or args.output_format in (OutputFormat.plain_squashfs, OutputFormat.tar):
            assert artifact is not None
            _link_output(args, artifact.name, args.output)


def link_output_nspawn_settings(args: CommandLineArguments, path: Optional[str]) -> None:
    if path is None:
        return

    with complete_step("Linking nspawn settings file", "Successfully linked " + args.output_nspawn_settings):
        _link_output(args, path, args.output_nspawn_settings)


def link_output_checksum(args: CommandLineArguments, checksum: Optional[str]) -> None:
    if checksum is None:
        return

    with complete_step("Linking SHA256SUMS file", "Successfully linked " + args.output_checksum):
        _link_output(args, checksum, args.output_checksum)


def link_output_root_hash_file(args: CommandLineArguments, root_hash_file: Optional[str]) -> None:
    if root_hash_file is None:
        return

    with complete_step("Linking .roothash file", "Successfully linked " + args.output_root_hash_file):
        _link_output(args, root_hash_file, args.output_root_hash_file)


def link_output_signature(args: CommandLineArguments, signature: Optional[str]) -> None:
    if signature is None:
        return

    with complete_step("Linking SHA256SUMS.gpg file", "Successfully linked " + args.output_signature):
        _link_output(args, signature, args.output_signature)


def link_output_bmap(args: CommandLineArguments, bmap: Optional[str]) -> None:
    if bmap is None:
        return

    with complete_step("Linking .bmap file", "Successfully linked " + args.output_bmap):
        _link_output(args, bmap, args.output_bmap)


def link_output_sshkey(args: CommandLineArguments, sshkey: Optional[str]) -> None:
    if sshkey is None:
        return

    with complete_step("Linking private ssh key file", f"Successfully linked {args.output_sshkey}"):
        _link_output(args, sshkey, args.output_sshkey)
        os.chmod(args.output_sshkey, 0o600)


def dir_size(path: str) -> int:
    dir_sum = 0
    for entry in os.scandir(path):
        if entry.is_symlink():
            # We can ignore symlinks because they either point into our tree,
            # in which case we'll include the size of target directory anyway,
            # or outside, in which case we don't need to.
            continue
        elif entry.is_file():
            dir_sum += entry.stat().st_blocks * 512
        elif entry.is_dir():
            dir_sum += dir_size(entry.path)
    return dir_sum


def print_output_size(args: CommandLineArguments) -> None:
    if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        MkosiPrinter.print_step("Resulting image size is " + format_bytes(dir_size(args.output)) + ".")
    else:
        st = os.stat(args.output)
        MkosiPrinter.print_step(
            "Resulting image size is "
            + format_bytes(st.st_size)
            + ", consumes "
            + format_bytes(st.st_blocks * 512)
            + "."
        )  # NOQA: E501


def setup_package_cache(args: CommandLineArguments) -> Optional[TempDir]:
    if args.cache_path and os.path.exists(args.cache_path):
        return None

    d = None
    with complete_step("Setting up package cache", "Setting up package cache {} complete") as output:
        if args.cache_path is None:
            d = tempfile.TemporaryDirectory(dir=os.path.dirname(args.output), prefix=".mkosi-")
            args.cache_path = d.name
        else:
            os.makedirs(args.cache_path, 0o755, exist_ok=True)
        output.append(args.cache_path)

    return d


class ListAction(argparse.Action):
    delimiter: str

    def __init__(self, *args: Any, choices: Optional[Iterable[Any]] = None, **kwargs: Any) -> None:
        self.list_choices = choices
        super().__init__(*args, **kwargs)

    def __call__(
        self,  # These type-hints are copied from argparse.pyi
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        assert isinstance(values, str)
        ary = getattr(namespace, self.dest)
        if ary is None:
            ary = []

        # Support list syntax for comma separated lists as well
        if self.delimiter == "," and values.startswith("[") and values.endswith("]"):
            values = values[1:-1]

        # Make sure delimiters between quotes are ignored by using the csv module.
        # Inspired by https://stackoverflow.com/a/2787979.
        new = re.split(f"""{self.delimiter}(?=(?:[^'"]|'[^']*'|"[^"]*")*$)""", values)

        for x in new:
            x = x.strip()
            if not x:  # ignore empty entries
                continue
            if self.list_choices is not None and x not in self.list_choices:
                raise ValueError(f"Unknown value {x!r}")

            # Remove ! prefixed list entries from list. !* removes all entries. This works for strings only now.
            if x.startswith("!*"):
                ary = []
            elif x.startswith("!"):
                if x[1:] in ary:
                    ary.remove(x[1:])
            else:
                ary.append(x)
        setattr(namespace, self.dest, ary)


class CommaDelimitedListAction(ListAction):
    delimiter = ","


class ColonDelimitedListAction(ListAction):
    delimiter = ":"


class SpaceDelimitedListAction(ListAction):
    delimiter = " "


class BooleanAction(argparse.Action):
    """Parse boolean command line arguments

    The argument may be added more than once. The argument may be set explicitly (--foo yes)
    or implicitly --foo. If the parameter name starts with "not-" or "without-" the value gets
    inverted.
    """

    def __init__(
        self,  # These type-hints are copied from argparse.pyi
        option_strings: Sequence[str],
        dest: str,
        nargs: Optional[Union[int, str]] = None,
        const: Any = True,
        default: Any = False,
        **kwargs: Any,
    ) -> None:
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(BooleanAction, self).__init__(option_strings, dest, nargs="?", const=const, default=default, **kwargs)

    def __call__(
        self,  # These type-hints are copied from argparse.pyi
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:
        new_value = self.default
        if isinstance(values, str):
            try:
                new_value = parse_boolean(values)
            except ValueError as exp:
                raise argparse.ArgumentError(self, str(exp))
        elif isinstance(values, bool):  # Assign const
            new_value = values
        else:
            raise argparse.ArgumentError(self, "Invalid argument for %s %s" % (str(option_string), str(values)))

        # invert the value if the argument name starts with "not" or "without"
        for option in self.option_strings:
            if option[2:].startswith("not-") or option[2:].startswith("without-"):
                new_value = not new_value
                break

        setattr(namespace, self.dest, new_value)


class WithNetworkAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:

        if isinstance(values, str):
            if values == "never":
                setattr(namespace, self.dest, "never")
                return

        super().__call__(parser, namespace, values, option_string)


class ArgumentParserMkosi(argparse.ArgumentParser):
    """ArgumentParser with support for mkosi.defaults file(s)

    This derived class adds a simple ini file parser to python's ArgumentParser features.
    Each line of the ini file is converted to a command line argument. Example:
    "FooBar=Hello_World"  in the ini file appends "--foo-bar Hello_World" to sys.argv.

    Command line arguments starting with - or --are considered as regular arguments. Arguments
    starting with @ are considered as files which are fed to the ini file parser implemented
    in this class.
    """

    # Mapping of parameters supported in config files but not as command line arguments.
    SPECIAL_MKOSI_DEFAULT_PARAMS = {
        "QCow2": "--qcow2",
        "OutputDirectory": "--output-dir",
        "XZ": "--xz",
        "NSpawnSettings": "--settings",
        "ESPSize": "--esp-size",
        "CheckSum": "--checksum",
        "BMap": "--bmap",
        "Packages": "--package",
        "ExtraTrees": "--extra-tree",
        "SkeletonTrees": "--skeleton-tree",
        "BuildPackages": "--build-package",
        "PostInstallationScript": "--postinst-script",
        "GPTFirstLBA": "--gpt-first-lba",
        "TarStripSELinuxContext": "--tar-strip-selinux-context",
    }

    fromfile_prefix_chars = "@"

    def __init__(self, *kargs: Any, **kwargs: Any) -> None:
        self._ini_file_section = ""
        self._ini_file_key = ""  # multi line list processing
        self._ini_file_list_mode = False

        # Add config files to be parsed
        kwargs["fromfile_prefix_chars"] = ArgumentParserMkosi.fromfile_prefix_chars
        super().__init__(*kargs, **kwargs)

    def _read_args_from_files(self, arg_strings: List[str]) -> List[str]:
        """Convert @ prefixed command line arguments with corresponding file content

        Regular arguments are just returned. Arguments prefixed with @ are considered as
        configuration file paths. The settings of each file are parsed and returned as
        command line arguments.
        Example:
          The following mkosi.default is loaded.
          [Distribution]
          Distribution=fedora

          mkosi is called like: mkosi -p httpd

          arg_strings: ['@mkosi.default', '-p', 'httpd']
          return value: ['--distribution', 'fedora', '-p', 'httpd']
        """

        def camel_to_arg(camel: str) -> str:
            s1 = re.sub("(.)([A-Z][a-z]+)", r"\1-\2", camel)
            return re.sub("([a-z0-9])([A-Z])", r"\1-\2", s1).lower()

        def ini_key_to_cli_arg(key: str) -> str:
            try:
                return ArgumentParserMkosi.SPECIAL_MKOSI_DEFAULT_PARAMS[key]
            except KeyError:
                return "--" + camel_to_arg(key)

        # expand arguments referencing files
        new_arg_strings = []
        for arg_string in arg_strings:
            # for regular arguments, just add them back into the list
            if not arg_string or arg_string[0] not in self.fromfile_prefix_chars:
                new_arg_strings.append(arg_string)
                continue
            # replace arguments referencing files with the file content
            try:
                # This used to use configparser.ConfigParser before, but
                # ConfigParser's interpolation clashes with systemd style
                # specifier, e.g. %u for user, since both use % as a sigil.
                config = configparser.RawConfigParser(delimiters="=")
                config.optionxform = str  # type: ignore
                with open(arg_string[1:]) as args_file:
                    config.read_file(args_file)
                for section in config.sections():
                    for key, value in config.items(section):
                        cli_arg = ini_key_to_cli_arg(key)

                        # \n in value strings is forwarded. Depending on the action type, \n is considered as a delimiter or needs to be replaced by a ' '
                        for action in self._actions:
                            if cli_arg in action.option_strings:
                                if isinstance(action, ListAction):
                                    value = value.replace(os.linesep, action.delimiter)
                        new_arg_strings.extend([cli_arg, value])
            except OSError as e:
                self.error(str(e))
        # return the modified argument list
        return new_arg_strings


COMPRESSION_ALGORITHMS = "zlib", "lzo", "zstd", "lz4", "xz"


def parse_compression(value: str) -> Union[str, bool]:
    if value in COMPRESSION_ALGORITHMS:
        return value
    return parse_boolean(value)


def parse_source_file_transfer(value: str) -> Optional[SourceFileTransfer]:
    if value == "":
        return None
    try:
        return SourceFileTransfer(value)
    except Exception as exp:
        raise argparse.ArgumentTypeError(str(exp))


def create_parser() -> ArgumentParserMkosi:
    parser = ArgumentParserMkosi(prog="mkosi", description="Build Legacy-Free OS Images", add_help=False)

    group = parser.add_argument_group("Commands")
    group.add_argument("verb", choices=MKOSI_COMMANDS, default="build", help="Operation to execute")
    group.add_argument(
        "cmdline", nargs=argparse.REMAINDER, help="The command line to use for " + str(MKOSI_COMMANDS_CMDLINE)[1:-1]
    )
    group.add_argument("-h", "--help", action="help", help="Show this help")
    group.add_argument("--version", action="version", version="%(prog)s " + __version__)

    group = parser.add_argument_group("Distribution")
    group.add_argument("-d", "--distribution", choices=Distribution.__members__, help="Distribution to install")
    group.add_argument("-r", "--release", help="Distribution release to install")
    group.add_argument("-m", "--mirror", help="Distribution mirror to use")
    group.add_argument(
        "--repositories",
        action=CommaDelimitedListAction,
        dest="repositories",
        default=[],
        help="Repositories to use",
        metavar="REPOS",
    )
    group.add_argument("--architecture", help="Override the architecture of installation")

    group = parser.add_argument_group("Output")
    group.add_argument(
        "-t",
        "--format",
        dest="output_format",
        choices=OutputFormat,
        type=OutputFormat.from_string,
        help="Output Format",
    )
    group.add_argument("-o", "--output", help="Output image path", metavar="PATH")
    group.add_argument("-O", "--output-dir", help="Output root directory", metavar="DIR")
    group.add_argument(
        "-f",
        "--force",
        action="count",
        dest="force_count",
        default=0,
        help="Remove existing image file before operation",
    )
    group.add_argument(
        "-b",
        "--bootable",
        action=BooleanAction,
        help="Make image bootable on EFI (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    group.add_argument(
        "--boot-protocols",
        action=CommaDelimitedListAction,
        help="Boot protocols to use on a bootable image",
        metavar="PROTOCOLS",
        default=[],
    )
    group.add_argument(
        "--kernel-command-line",
        action=SpaceDelimitedListAction,
        default=["rhgb", "selinux=0", "audit=0"],
        help="Set the kernel command line (only bootable images)",
    )
    group.add_argument(
        "--kernel-commandline", action=SpaceDelimitedListAction, dest="kernel_command_line", help=argparse.SUPPRESS
    )  # Compatibility option
    group.add_argument(
        "--secure-boot", action=BooleanAction, help="Sign the resulting kernel/initrd image for UEFI SecureBoot"
    )
    group.add_argument("--secure-boot-key", help="UEFI SecureBoot private key in PEM format", metavar="PATH")
    group.add_argument("--secure-boot-certificate", help="UEFI SecureBoot certificate in X509 format", metavar="PATH")
    group.add_argument(
        "--secure-boot-valid-days",
        help="Number of days UEFI SecureBoot keys should be valid when generating keys",
        metavar="DAYS",
        default="730",
    )
    group.add_argument(
        "--secure-boot-common-name",
        help="Template for the UEFI SecureBoot CN when generating keys",
        metavar="CN",
        default="mkosi of %u",
    )
    group.add_argument(
        "--read-only",
        action=BooleanAction,
        help="Make root volume read-only (only gpt_ext4, gpt_xfs, gpt_btrfs, subvolume, implied with gpt_squashfs and plain_squashfs)",
    )
    group.add_argument(
        "--encrypt", choices=("all", "data"), help='Encrypt everything except: ESP ("all") or ESP and root ("data")'
    )
    group.add_argument("--verity", action=BooleanAction, help="Add integrity partition (implies --read-only)")
    group.add_argument(
        "--compress",
        type=parse_compression,
        help="Enable compression in file system (only gpt_btrfs, subvolume, gpt_squashfs, plain_squashfs)",
    )
    group.add_argument(
        "--mksquashfs", dest="mksquashfs_tool", type=str.split, help="Script to call instead of mksquashfs"
    )
    group.add_argument(
        "--xz",
        action=BooleanAction,
        help="Compress resulting image with xz (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs, implied on tar)",
    )  # NOQA: E501
    group.add_argument(
        "--qcow2",
        action=BooleanAction,
        help="Convert resulting image to qcow2 (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    group.add_argument("--hostname", help="Set hostname")
    group.add_argument(
        "--no-chown",
        action=BooleanAction,
        help="When running with sudo, disable reassignment of ownership of the generated files to the original user",
    )  # NOQA: E501
    group.add_argument(
        "--tar-strip-selinux-context",
        action=BooleanAction,
        help="Do not include SELinux file context information in tar. Not compatible with bsdtar.",
    )
    group.add_argument(
        "-i", "--incremental", action=BooleanAction, help="Make use of and generate intermediary cache images"
    )
    group.add_argument("-M", "--minimize", action=BooleanAction, help="Minimize root file system size")
    group.add_argument(
        "--without-unified-kernel-images",
        action=BooleanAction,
        dest="with_unified_kernel_images",
        default=True,
        help="Do not install unified kernel images",
    )
    group.add_argument("--with-unified-kernel-images", action=BooleanAction, default=True, help=argparse.SUPPRESS)
    group.add_argument("--gpt-first-lba", type=int, help="Set the first LBA within GPT Header", metavar="FIRSTLBA")
    group.add_argument("--hostonly-initrd", action=BooleanAction, help="Enable dracut hostonly option")

    group = parser.add_argument_group("Packages")
    group.add_argument(
        "-p",
        "--package",
        action=CommaDelimitedListAction,
        dest="packages",
        default=[],
        help="Add an additional package to the OS image",
        metavar="PACKAGE",
    )
    group.add_argument("--with-docs", action=BooleanAction, help="Install documentation")
    group.add_argument(
        "-T",
        "--without-tests",
        action=BooleanAction,
        dest="with_tests",
        default=True,
        help="Do not run tests as part of build script, if supported",
    )
    group.add_argument(
        "--with-tests", action=BooleanAction, default=True, help=argparse.SUPPRESS
    )  # Compatibility option
    group.add_argument("--cache", dest="cache_path", help="Package cache path", metavar="PATH")
    group.add_argument(
        "--extra-tree",
        action=CommaDelimitedListAction,
        dest="extra_trees",
        default=[],
        help="Copy an extra tree on top of image",
        metavar="PATH",
    )
    group.add_argument(
        "--skeleton-tree",
        action="append",
        dest="skeleton_trees",
        default=[],
        help="Use a skeleton tree to bootstrap the image before installing anything",
        metavar="PATH",
    )
    group.add_argument("--build-script", help="Build script to run inside image", metavar="PATH")
    group.add_argument(
        "--build-environment",
        action=SpaceDelimitedListAction,
        dest="build_env",
        default=[],
        help="Set an environment variable when running the build script",
        metavar="NAME=VALUE",
    )
    group.add_argument("--build-sources", help="Path for sources to build", metavar="PATH")
    group.add_argument("--build-dir", help=argparse.SUPPRESS, metavar="PATH")  # Compatibility option
    group.add_argument(
        "--build-directory", dest="build_dir", help="Path to use as persistent build directory", metavar="PATH"
    )
    group.add_argument(
        "--include-directory", dest="include_dir", help="Path to use as persistent include directory", metavar="PATH"
    )
    group.add_argument(
        "--install-directory", dest="install_dir", help="Path to use as persistent install directory", metavar="PATH"
    )
    group.add_argument(
        "--build-package",
        action=CommaDelimitedListAction,
        dest="build_packages",
        default=[],
        help="Additional packages needed for build script",
        metavar="PACKAGE",
    )
    group.add_argument(
        "--skip-final-phase", action=BooleanAction, help="Skip the (second) final image building phase.", default=False
    )
    group.add_argument("--postinst-script", help="Postinstall script to run inside image", metavar="PATH")
    group.add_argument(
        "--prepare-script", help="Prepare script to run inside the image before it is cached", metavar="PATH"
    )
    group.add_argument("--finalize-script", help="Postinstall script to run outside image", metavar="PATH")
    group.add_argument(
        "--source-file-transfer",
        type=parse_source_file_transfer,
        choices=[*list(SourceFileTransfer), None],
        default=None,
        help="Method used to copy build sources to the build image."
        + "; ".join([f"'{k}': {v}" for k, v in SourceFileTransfer.doc().items()])
        + " (default: copy-git-others if in a git repository, otherwise copy-all)",
    )
    group.add_argument(
        "--source-file-transfer-final",
        type=parse_source_file_transfer,
        choices=[*list(SourceFileTransfer), None],
        default=None,
        help="Method used to copy build sources to the final image."
        + "; ".join([f"'{k}': {v}" for k, v in SourceFileTransfer.doc().items() if k != SourceFileTransfer.mount])
        + " (default: None)",
    )
    group.add_argument(
        "--with-network",
        action=WithNetworkAction,
        help="Run build and postinst scripts with network access (instead of private network)",
    )
    group.add_argument("--settings", dest="nspawn_settings", help="Add in .nspawn settings file", metavar="PATH")

    group = parser.add_argument_group("Partitions")
    group.add_argument(
        "--root-size", help="Set size of root partition (only gpt_ext4, gpt_xfs, gpt_btrfs)", metavar="BYTES"
    )
    group.add_argument(
        "--esp-size",
        help="Set size of EFI system partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
        metavar="BYTES",
    )  # NOQA: E501
    group.add_argument(
        "--xbootldr-size",
        help="Set size of the XBOOTLDR partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
        metavar="BYTES",
    )  # NOQA: E501
    group.add_argument(
        "--swap-size",
        help="Set size of swap partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
        metavar="BYTES",
    )  # NOQA: E501
    group.add_argument(
        "--home-size", help="Set size of /home partition (only gpt_ext4, gpt_xfs, gpt_squashfs)", metavar="BYTES"
    )
    group.add_argument(
        "--srv-size", help="Set size of /srv partition (only gpt_ext4, gpt_xfs, gpt_squashfs)", metavar="BYTES"
    )
    group.add_argument(
        "--var-size", help="Set size of /var partition (only gpt_ext4, gpt_xfs, gpt_squashfs)", metavar="BYTES"
    )
    group.add_argument(
        "--tmp-size", help="Set size of /var/tmp partition (only gpt_ext4, gpt_xfs, gpt_squashfs)", metavar="BYTES"
    )

    group = parser.add_argument_group("Validation (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs, tar)")
    group.add_argument("--checksum", action=BooleanAction, help="Write SHA256SUMS file")
    group.add_argument("--sign", action=BooleanAction, help="Write and sign SHA256SUMS file")
    group.add_argument("--key", help="GPG key to use for signing")
    group.add_argument(
        "--bmap",
        action=BooleanAction,
        help="Write block map file (.bmap) for bmaptool usage (only gpt_ext4, gpt_btrfs)",
    )
    group.add_argument("--password", help="Set the root password")
    group.add_argument(
        "--password-is-hashed", action=BooleanAction, help="Indicate that the root password has already been hashed"
    )
    group.add_argument("--autologin", action=BooleanAction, help="Enable root autologin")

    group = parser.add_argument_group("Host configuration")
    group.add_argument(
        "--extra-search-path",
        dest="extra_search_paths",
        action=ColonDelimitedListAction,
        default=[],
        help="List of colon-separated paths to look for programs before looking in PATH",
    )
    group.add_argument(
        "--extra-search-paths", dest="extra_search_paths", action=ColonDelimitedListAction, help=argparse.SUPPRESS
    )  # Compatibility option
    group.add_argument("--qemu-headless", action=BooleanAction, help="Configure image for qemu's -nographic mode")
    group.add_argument(
        "--network-veth",
        action=BooleanAction,
        help="Create a virtual Ethernet link between the host and the container/VM",
    )
    group.add_argument(
        "--ephemeral",
        action=BooleanAction,
        help="If specified, the container/VM is run with a temporary snapshot of the output image that is "
        "removed immediately when the container/VM terminates",
    )
    group.add_argument(
        "--ssh", action=BooleanAction, help="Set up SSH access from the host to the final image via `mkosi ssh`"
    )

    group = parser.add_argument_group("Additional Configuration")
    group.add_argument("-C", "--directory", help="Change to specified directory before doing anything", metavar="PATH")
    group.add_argument("--default", dest="default_path", help="Read configuration data from file", metavar="PATH")
    group.add_argument(
        "-a", "--all", action="store_true", dest="all", default=False, help="Build all settings files in mkosi.files/"
    )
    group.add_argument(
        "--all-directory",
        dest="all_directory",
        help="Specify path to directory to read settings files from",
        metavar="PATH",
    )

    group.add_argument(
        "--debug",
        action=CommaDelimitedListAction,
        default=[],
        help="Turn on debugging output",
        metavar="SELECTOR",
        choices=("run", "build-script", "workspace-command"),
    )
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    return parser


def load_distribution(args: CommandLineArguments) -> CommandLineArguments:
    if args.distribution is not None:
        args.distribution = Distribution[args.distribution]

    if args.distribution is None or args.release is None:
        d, r = detect_distribution()

        if args.distribution is None:
            args.distribution = d

        if args.distribution == d and d != Distribution.clear and args.release is None:
            args.release = r

    if args.distribution is None:
        die("Couldn't detect distribution.")

    return args


def parse_args(argv: Optional[List[str]] = None) -> Dict[str, CommandLineArguments]:
    """Load default values from files and parse command line arguments

    Do all about default files and command line arguments parsing. If --all argument is passed
    more than one job needs to be processed. The returned tuple contains CommandLineArguments
    valid for all jobs as well as a dict containing the arguments per job.
    """
    parser = create_parser()

    # always work on a copy, argv will be altered which might has some side effects e.g. in unit tests.
    if argv is None:
        argv = copy.deepcopy(sys.argv[1:])
    else:
        argv = copy.deepcopy(argv)

    # If ArgumentParserMkosi loads settings from mkosi.default files, the settings from files
    # are converted to command line arguments. This breaks ArgumentParser's support for default
    # values of positional arguments. Make sure the verb command gets explicitly passed.
    # Insert a -- before the positional verb argument otherwise it might be considered as an argument of
    # a parameter with nargs='?'. For example mkosi -i summary would be treated as -i=summary.
    found_verb = False
    for verb in MKOSI_COMMANDS:
        try:
            v_i = argv.index(verb)
            if v_i > 0:
                if argv[v_i - 1] != "--":
                    argv.insert(v_i, "--")
            found_verb = True
            break
        except ValueError:
            pass
    if found_verb is False:
        argv.extend(["--", "build"])

    # First run of command line arguments parsing to get the directory of mkosi.default file and the verb argument.
    args_pre_parsed, _ = parser.parse_known_args(copy.deepcopy(argv))

    if args_pre_parsed.verb == "help":
        parser.print_help()
        sys.exit(0)

    # Make sure all paths are absolute and valid.
    # Relative paths are not valid yet since we are not in the final working directory yet.
    if args_pre_parsed.directory is not None:
        args_pre_parsed.directory = os.path.abspath(args_pre_parsed.directory)
        directory = args_pre_parsed.directory
    else:
        directory = os.path.abspath(".")

    if args_pre_parsed.all_directory:
        if os.path.isabs(args_pre_parsed.all_directory):
            all_directory = args_pre_parsed.all_directory
        else:
            all_directory = os.path.join(directory, args_pre_parsed.all_directory)
    else:
        all_directory = os.path.join(directory, "mkosi.files/")

    if args_pre_parsed.default_path:
        if os.path.isabs(args_pre_parsed.default_path):
            default_path = args_pre_parsed.default_path
        else:
            default_path = os.path.join(directory, args_pre_parsed.default_path)

        if not os.path.exists(default_path):
            die(f"No config file found at {default_path}")
    else:
        default_path = os.path.join(directory, "mkosi.default")

    if args_pre_parsed.all and args_pre_parsed.default_path:
        die("--all and --default= may not be combined.")

    # Parse everything in --all mode
    args_all = {}
    if args_pre_parsed.all:
        if not os.path.isdir(all_directory):
            die("all-directory %s does not exist." % all_directory)
        for f in os.scandir(all_directory):
            if not f.name.startswith("mkosi."):
                continue
            args = parse_args_file(copy.deepcopy(argv), f.path)
            args_all[f.name] = args
    # Parse everything in normal mode
    else:
        args = parse_args_file_group(argv, default_path)

        args = load_distribution(args)

        # Parse again with any extra distribution files included.
        args = parse_args_distribution_group(argv, str(args.distribution))

        args_all["default"] = args

    return args_all


def parse_args_file(argv_post_parsed: List[str], default_path: str) -> CommandLineArguments:
    """Parse just one mkosi.* file (--all mode)"""
    argv_post_parsed.insert(1, ArgumentParserMkosi.fromfile_prefix_chars + default_path)
    parser = create_parser()
    # parse all parameters handled by mkosi. Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    return parser.parse_args(argv_post_parsed, CommandLineArguments())


def parse_args_file_group(argv_post_parsed: List[str], default_path: str) -> CommandLineArguments:
    """Parse a set of mkosi.default and mkosi.default.d/* files."""
    # Add the @ prefixed filenames to current argument list in inverse priority order.
    all_defaults_files = []
    defaults_dir = "mkosi.default.d"
    if os.path.isdir(defaults_dir):
        for defaults_file in sorted(os.listdir(defaults_dir)):
            defaults_path = os.path.join(defaults_dir, defaults_file)
            if os.path.isfile(defaults_path):
                all_defaults_files.append(ArgumentParserMkosi.fromfile_prefix_chars + defaults_path)
    if os.path.isfile(default_path):
        all_defaults_files.insert(0, ArgumentParserMkosi.fromfile_prefix_chars + default_path)
    argv_post_parsed[0:0] = all_defaults_files

    parser = create_parser()

    # parse all parameters handled by mkosi. Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    return parser.parse_args(argv_post_parsed, CommandLineArguments())


def parse_args_distribution_group(argv_post_parsed: List[str], distribution: str) -> CommandLineArguments:
    all_defaults_files = []
    distribution_dir = f"mkosi.default.d/{distribution}"
    if os.path.isdir(distribution_dir):
        for distribution_file in sorted(os.listdir(distribution_dir)):
            distribution_path = os.path.join(distribution_dir, distribution_file)
            if os.path.isfile(distribution_path):
                all_defaults_files.append(ArgumentParserMkosi.fromfile_prefix_chars + distribution_path)

    # Insert the distro specific config files after the rest of the config files so they override these.
    for i, v in enumerate(argv_post_parsed):
        if not v.startswith(ArgumentParserMkosi.fromfile_prefix_chars):
            argv_post_parsed[i:i] = all_defaults_files
            break
    else:
        # Append to the end if the args only contain files and no regular args.
        argv_post_parsed += all_defaults_files

    return create_parser().parse_args(argv_post_parsed, CommandLineArguments())


def parse_bytes(num_bytes: Optional[str]) -> Optional[int]:
    if num_bytes is None:
        return num_bytes

    if num_bytes.endswith("G"):
        factor = 1024 ** 3
    elif num_bytes.endswith("M"):
        factor = 1024 ** 2
    elif num_bytes.endswith("K"):
        factor = 1024
    else:
        factor = 1

    if factor > 1:
        num_bytes = num_bytes[:-1]

    result = int(num_bytes) * factor
    if result <= 0:
        raise ValueError("Size out of range")

    if result % 512 != 0:
        raise ValueError("Size not a multiple of 512")

    return result


def detect_distribution() -> Tuple[Optional[Distribution], Optional[str]]:
    try:
        f = open("/etc/os-release")
    except IOError:
        try:
            f = open("/usr/lib/os-release")
        except IOError:
            return None, None

    dist_id = None
    version_id = None
    version_codename = None
    extracted_codename = None

    for ln in f:
        if ln.startswith("ID="):
            dist_id = ln[3:].strip(" \t\n\"'")
        if ln.startswith("ID_LIKE="):
            dist_id_like = ln[8:].strip(" \t\n\"'").split()
        if ln.startswith("VERSION_ID="):
            version_id = ln[11:].strip(" \t\n\"'")
        if ln.startswith("VERSION_CODENAME="):
            version_codename = ln[17:].strip(" \t\n\"'")
        if ln.startswith("VERSION="):
            # extract Debian release codename
            version_str = ln[8:].strip(" \t\n\"'")
            debian_codename_re = r"\((.*?)\)"

            codename_list = re.findall(debian_codename_re, version_str)
            if len(codename_list) == 1:
                extracted_codename = codename_list[0]

    if dist_id == "clear-linux-os":
        dist_id = "clear"

    d: Optional[Distribution] = None
    if dist_id is not None:
        d = Distribution.__members__.get(dist_id, None)
        if d is None:
            for dist_id in dist_id_like:
                d = Distribution.__members__.get(dist_id, None)
                if d is not None:
                    break

    if (d == Distribution.debian or d == Distribution.ubuntu) and (version_codename or extracted_codename):
        # debootstrap needs release codenames, not version numbers
        if version_codename:
            version_id = version_codename
        else:
            version_id = extracted_codename

    return d, version_id


def unlink_try_hard(path: str) -> None:
    try:
        os.unlink(path)
    except:  # NOQA: E722
        pass

    try:
        btrfs_subvol_delete(path)
    except:  # NOQA: E722
        pass

    try:
        shutil.rmtree(path)
    except:  # NOQA: E722
        pass


def remove_glob(*patterns: str) -> None:
    pathgen = (glob.glob(pattern) for pattern in patterns)
    paths: Set[str] = set(sum(pathgen, []))  # uniquify
    for path in paths:
        unlink_try_hard(path)


def empty_directory(path: str) -> None:
    try:
        for f in os.listdir(path):
            unlink_try_hard(os.path.join(path, f))
    except FileNotFoundError:
        pass


def unlink_output(args: CommandLineArguments) -> None:
    if not args.force and args.verb != "clean":
        return

    if not args.skip_final_phase:
        with complete_step("Removing output files"):
            unlink_try_hard(args.output)

            if args.checksum:
                unlink_try_hard(args.output_checksum)

            if args.verity:
                unlink_try_hard(args.output_root_hash_file)

            if args.sign:
                unlink_try_hard(args.output_signature)

            if args.bmap:
                unlink_try_hard(args.output_bmap)

            if args.nspawn_settings is not None:
                unlink_try_hard(args.output_nspawn_settings)

        if args.ssh:
            unlink_try_hard(args.output_sshkey)

    # We remove any cached images if either the user used --force
    # twice, or he/she called "clean" with it passed once. Let's also
    # remove the downloaded package cache if the user specified one
    # additional "--force".

    if args.verb == "clean":
        remove_build_cache = args.force_count > 0
        remove_package_cache = args.force_count > 1
    else:
        remove_build_cache = args.force_count > 1
        remove_package_cache = args.force_count > 2

    if remove_build_cache:
        if args.cache_pre_dev is not None or args.cache_pre_inst is not None:
            with complete_step("Removing incremental cache files"):
                if args.cache_pre_dev is not None:
                    unlink_try_hard(args.cache_pre_dev)

                if args.cache_pre_inst is not None:
                    unlink_try_hard(args.cache_pre_inst)

        if args.build_dir is not None:
            with complete_step("Clearing out build directory"):
                empty_directory(args.build_dir)

        if args.include_dir is not None:
            with complete_step("Clearing out include directory"):
                empty_directory(args.include_dir)

        if args.install_dir is not None:
            with complete_step("Clearing out install directory"):
                empty_directory(args.install_dir)

    if remove_package_cache:
        if args.cache_path is not None:
            with complete_step("Clearing out package cache"):
                empty_directory(args.cache_path)


def parse_boolean(s: str) -> bool:
    "Parse 1/true/yes as true and 0/false/no as false"
    s_l = s.lower()
    if s_l in {"1", "true", "yes"}:
        return True

    if s_l in {"0", "false", "no"}:
        return False

    raise ValueError(f"Invalid literal for bool(): {s!r}")


def find_nspawn_settings(args: CommandLineArguments) -> None:
    if args.nspawn_settings is not None:
        return

    if os.path.exists("mkosi.nspawn"):
        args.nspawn_settings = "mkosi.nspawn"


def find_extra(args: CommandLineArguments) -> None:

    if len(args.extra_trees) > 0:
        return

    if os.path.isdir("mkosi.extra"):
        args.extra_trees.append("mkosi.extra")
    if os.path.isfile("mkosi.extra.tar"):
        args.extra_trees.append("mkosi.extra.tar")


def find_skeleton(args: CommandLineArguments) -> None:

    if len(args.skeleton_trees) > 0:
        return

    if os.path.isdir("mkosi.skeleton"):
        args.skeleton_trees.append("mkosi.skeleton")
    if os.path.isfile("mkosi.skeleton.tar"):
        args.skeleton_trees.append("mkosi.skeleton.tar")


def args_find_path(
    args: CommandLineArguments, name: str, path: str, *, type_call: Callable[[str], Any] = lambda x: x
) -> None:
    if getattr(args, name) is not None:
        return
    if os.path.exists(path):
        path = os.path.abspath(path)
        path = type_call(path)
        setattr(args, name, path)


def find_cache(args: CommandLineArguments) -> None:
    if args.cache_path is not None:
        return

    if os.path.exists("mkosi.cache/"):
        args.cache_path = "mkosi.cache/" + args.distribution.name

        # Clear has a release number that can be used, however the
        # cache is valid (and more efficient) across releases.
        if args.distribution != Distribution.clear and args.release is not None:
            args.cache_path += "~" + args.release


def require_private_file(name: str, description: str) -> None:
    mode = os.stat(name).st_mode & 0o777
    if mode & 0o007:
        warn(
            dedent(
                f"""
                Permissions of '{name}' of '{mode:04o}' are too open.
                When creating {description} files use an access mode that restricts access to the owner only.\
                """
            )
        )


def find_passphrase(args: CommandLineArguments) -> None:
    if args.encrypt is None:
        args.passphrase = None
        return

    try:
        require_private_file("mkosi.passphrase", "passphrase")

        args.passphrase = {"type": "file", "content": "mkosi.passphrase"}

    except FileNotFoundError:
        while True:
            passphrase = getpass.getpass("Please enter passphrase: ")
            passphrase_confirmation = getpass.getpass("Passphrase confirmation: ")
            if passphrase == passphrase_confirmation:
                args.passphrase = {"type": "stdin", "content": passphrase}
                break

            MkosiPrinter.info("Passphrase doesn't match confirmation. Please try again.")


def find_password(args: CommandLineArguments) -> None:
    if args.password is not None:
        return

    try:
        require_private_file("mkosi.rootpw", "root password")

        with open("mkosi.rootpw") as f:
            args.password = f.read().strip()

    except FileNotFoundError:
        pass


def find_secure_boot(args: CommandLineArguments) -> None:
    if not args.secure_boot:
        return

    if args.secure_boot_key is None:
        if os.path.exists("mkosi.secure-boot.key"):
            args.secure_boot_key = "mkosi.secure-boot.key"

    if args.secure_boot_certificate is None:
        if os.path.exists("mkosi.secure-boot.crt"):
            args.secure_boot_certificate = "mkosi.secure-boot.crt"


def strip_suffixes(path: str) -> str:
    t = path
    while True:
        if t.endswith(".xz"):
            t = t[:-3]
        elif t.endswith(".raw"):
            t = t[:-4]
        elif t.endswith(".tar"):
            t = t[:-4]
        elif t.endswith(".qcow2"):
            t = t[:-6]
        else:
            break

    return t


def build_nspawn_settings_path(path: str) -> str:
    return strip_suffixes(path) + ".nspawn"


def build_root_hash_file_path(path: str) -> str:
    return strip_suffixes(path) + ".roothash"


def check_valid_script(path: str) -> None:
    if not os.path.exists(path):
        die(f"{path} does not exist")
    if not os.path.isfile(path):
        die(f"{path} is not a file")
    if not os.access(path, os.X_OK):
        die(f"{path} is not executable")


def load_args(args: CommandLineArguments) -> CommandLineArguments:
    global arg_debug
    arg_debug = args.debug

    args_find_path(args, "nspawn_settings", "mkosi.nspawn")
    args_find_path(args, "build_script", "mkosi.build")
    args_find_path(args, "build_sources", ".")
    args_find_path(args, "build_dir", "mkosi.builddir/")
    args_find_path(args, "include_dir", "mkosi.includedir/")
    args_find_path(args, "install_dir", "mkosi.installdir/")
    args_find_path(args, "postinst_script", "mkosi.postinst")
    args_find_path(args, "prepare_script", "mkosi.prepare")
    args_find_path(args, "finalize_script", "mkosi.finalize")
    args_find_path(args, "output_dir", "mkosi.output/")
    args_find_path(args, "mksquashfs_tool", "mkosi.mksquashfs-tool", type_call=lambda x: [x])

    find_extra(args)
    find_skeleton(args)
    find_password(args)
    find_passphrase(args)
    find_secure_boot(args)

    args.extra_search_paths = expand_paths(args.extra_search_paths)

    if args.cmdline and args.verb not in MKOSI_COMMANDS_CMDLINE:
        die("Additional parameters only accepted for " + str(MKOSI_COMMANDS_CMDLINE)[1:-1] + " invocations.")

    args.force = args.force_count > 0

    if args.output_format is None:
        args.output_format = OutputFormat.gpt_ext4

    args = load_distribution(args)

    if args.release is None:
        if args.distribution == Distribution.fedora:
            args.release = "33"
        elif args.distribution in (Distribution.centos, Distribution.centos_epel):
            args.release = "8"
        elif args.distribution == Distribution.mageia:
            args.release = "7"
        elif args.distribution == Distribution.debian:
            args.release = "unstable"
        elif args.distribution == Distribution.ubuntu:
            args.release = "focal"
        elif args.distribution == Distribution.opensuse:
            args.release = "tumbleweed"
        elif args.distribution == Distribution.clear:
            args.release = "latest"
        elif args.distribution == Distribution.photon:
            args.release = "3.0"
        elif args.distribution == Distribution.openmandriva:
            args.release = "cooker"

    if args.distribution in (Distribution.centos, Distribution.centos_epel):
        epel_release = int(args.release.split(".")[0])
        if epel_release <= 8 and args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, CentOS {epel_release} does not support btrfs")
        if epel_release <= 7 and args.bootable and "uefi" in args.boot_protocols and args.with_unified_kernel_images:
            die(
                f"Sorry, CentOS {epel_release} does not support unified kernel images. "
                "You must use --without-unified-kernel-images."
            )

    # Remove once https://github.com/clearlinux/clr-boot-manager/pull/238 is merged and available.
    if args.distribution == Distribution.clear and args.output_format == OutputFormat.gpt_btrfs:
        die("Sorry, Clear Linux does not support btrfs")

    if args.distribution == Distribution.clear and "," in args.boot_protocols:
        die("Sorry, Clear Linux does not support hybrid BIOS/UEFI images")

    if shutil.which("bsdtar") and args.distribution == Distribution.openmandriva and args.tar_strip_selinux_context:
        die("Sorry, bsdtar on OpenMandriva is incompatible with --tar-strip-selinux-context")

    find_cache(args)

    if args.mirror is None:
        if args.distribution in (Distribution.fedora, Distribution.centos):
            args.mirror = None
        elif args.distribution == Distribution.debian:
            args.mirror = "http://deb.debian.org/debian"
        elif args.distribution == Distribution.ubuntu:
            args.mirror = "http://archive.ubuntu.com/ubuntu"
            if platform.machine() == "aarch64":
                args.mirror = "http://ports.ubuntu.com/"
        elif args.distribution == Distribution.arch and platform.machine() == "aarch64":
            args.mirror = "http://mirror.archlinuxarm.org"
        elif args.distribution == Distribution.opensuse:
            args.mirror = "http://download.opensuse.org"

    if args.minimize and not args.output_format.can_minimize():
        die("Minimal file systems only supported for ext4 and btrfs.")

    if args.generated_root() and args.incremental:
        die("Sorry, incremental mode is currently not supported for squashfs or minimized file systems.")

    if args.bootable:
        if args.output_format in (
            OutputFormat.directory,
            OutputFormat.subvolume,
            OutputFormat.tar,
            OutputFormat.plain_squashfs,
        ):
            die("Directory, subvolume, tar and plain squashfs images cannot be booted.")

        if not args.boot_protocols:
            args.boot_protocols = ["uefi"]

            if args.distribution == Distribution.photon:
                args.boot_protocols = ["bios"]

        if not {"uefi", "bios"}.issuperset(args.boot_protocols):
            die("Not a valid boot protocol")

        if "uefi" in args.boot_protocols and args.distribution == Distribution.photon:
            die(f"uefi boot not supported for {args.distribution}")

    if args.encrypt is not None:
        if not args.output_format.is_disk():
            die("Encryption is only supported for disk images.")

        if args.encrypt == "data" and args.output_format == OutputFormat.gpt_btrfs:
            die("'data' encryption mode not supported on btrfs, use 'all' instead.")

        if args.encrypt == "all" and args.verity:
            die("'all' encryption mode may not be combined with Verity.")

    if args.sign:
        args.checksum = True

    if args.output is None:
        if args.output_format.is_disk():
            args.output = "image" + (".qcow2" if args.qcow2 else ".raw") + (".xz" if args.xz else "")
        elif args.output_format == OutputFormat.tar:
            args.output = "image.tar.xz"
        else:
            args.output = "image"

    if args.output_dir is not None:
        args.output_dir = os.path.abspath(args.output_dir)

        if "/" not in args.output:
            args.output = os.path.join(args.output_dir, args.output)
        else:
            warn("Ignoring configured output directory as output file is a qualified path.")

    if args.incremental or args.verb == "clean":
        args.cache_pre_dev = args.output + ".cache-pre-dev"
        args.cache_pre_inst = args.output + ".cache-pre-inst"
    else:
        args.cache_pre_dev = None
        args.cache_pre_inst = None

    args.output = os.path.abspath(args.output)

    if args.output_format == OutputFormat.tar:
        args.xz = True

    if args.output_format.is_squashfs():
        args.read_only = True
        args.root_size = None
        if args.compress is False:
            die("Cannot disable compression with squashfs")
        if args.compress is None:
            args.compress = True

    if args.verity:
        args.read_only = True
        args.output_root_hash_file = build_root_hash_file_path(args.output)

    if args.checksum:
        args.output_checksum = os.path.join(os.path.dirname(args.output), "SHA256SUMS")

    if args.sign:
        args.output_signature = os.path.join(os.path.dirname(args.output), "SHA256SUMS.gpg")

    if args.bmap:
        args.output_bmap = args.output + ".bmap"

    if args.nspawn_settings is not None:
        args.nspawn_settings = os.path.abspath(args.nspawn_settings)
        args.output_nspawn_settings = build_nspawn_settings_path(args.output)

    # We want this set even if --ssh is not specified so we can find the SSH key when verb == "ssh".
    args.output_sshkey = os.path.join(os.path.dirname(args.output), "id_rsa")

    if args.build_script is not None:
        check_valid_script(args.build_script)
        args.build_script = os.path.abspath(args.build_script)

    if args.build_sources is not None:
        args.build_sources = os.path.abspath(args.build_sources)

    if args.build_dir is not None:
        args.build_dir = os.path.abspath(args.build_dir)

    if args.include_dir is not None:
        args.include_dir = os.path.abspath(args.include_dir)

    if args.install_dir is not None:
        args.install_dir = os.path.abspath(args.install_dir)

    if args.postinst_script is not None:
        check_valid_script(args.postinst_script)
        args.postinst_script = os.path.abspath(args.postinst_script)

    if args.prepare_script is not None:
        check_valid_script(args.prepare_script)
        args.prepare_script = os.path.abspath(args.prepare_script)

    if args.finalize_script is not None:
        check_valid_script(args.finalize_script)
        args.finalize_script = os.path.abspath(args.finalize_script)

    if args.cache_path is not None:
        args.cache_path = os.path.abspath(args.cache_path)

    if args.extra_trees:
        for i in range(len(args.extra_trees)):
            args.extra_trees[i] = os.path.abspath(args.extra_trees[i])

    if args.skeleton_trees is not None:
        for i in range(len(args.skeleton_trees)):
            args.skeleton_trees[i] = os.path.abspath(args.skeleton_trees[i])

    args.root_size = parse_bytes(args.root_size)
    args.home_size = parse_bytes(args.home_size)
    args.srv_size = parse_bytes(args.srv_size)
    args.var_size = parse_bytes(args.var_size)
    args.tmp_size = parse_bytes(args.tmp_size)
    args.esp_size = parse_bytes(args.esp_size)
    args.xbootldr_size = parse_bytes(args.xbootldr_size)
    args.swap_size = parse_bytes(args.swap_size)

    if args.root_size is None:
        args.root_size = 3 * 1024 * 1024 * 1024

    if args.bootable and args.esp_size is None:
        args.esp_size = 256 * 1024 * 1024

    args.verity_size = None

    if args.secure_boot_key is not None:
        args.secure_boot_key = os.path.abspath(args.secure_boot_key)

    if args.secure_boot_certificate is not None:
        args.secure_boot_certificate = os.path.abspath(args.secure_boot_certificate)

    if args.secure_boot:
        if args.secure_boot_key is None:
            die(
                "UEFI SecureBoot enabled, but couldn't find private key. (Consider placing it in mkosi.secure-boot.key?)"
            )  # NOQA: E501

        if args.secure_boot_certificate is None:
            die(
                "UEFI SecureBoot enabled, but couldn't find certificate. (Consider placing it in mkosi.secure-boot.crt?)"
            )  # NOQA: E501

    if args.verb in ("shell", "boot"):
        if args.output_format == OutputFormat.tar:
            die("Sorry, can't acquire shell in or boot a tar archive.")
        if args.xz:
            die("Sorry, can't acquire shell in or boot an XZ compressed image.")
        if args.qcow2:
            die("Sorry, can't acquire shell in or boot a qcow2 image.")

    if args.verb == "qemu":
        if not args.output_format.is_disk():
            die("Sorry, can't boot non-disk images with qemu.")

    if needs_build(args) and args.qemu_headless and not args.bootable:
        die("--qemu-headless requires --bootable")

    if args.qemu_headless and "console=ttyS0" not in args.kernel_command_line:
        args.kernel_command_line.append("console=ttyS0")

    if args.bootable and args.distribution == Distribution.mageia:
        # TODO: Remove once dracut 045 is available in mageia.
        args.kernel_command_line.append("root=/dev/gpt-auto-root")

    if not args.read_only:
        args.kernel_command_line.append("rw")

    if args.generated_root() and "bios" in args.boot_protocols:
        die("Sorry, BIOS cannot be combined with --minimize or squashfs filesystems")

    if args.bootable and args.distribution in (Distribution.clear, Distribution.photon):
        die("Sorry, --bootable is not supported on this distro")

    if not args.with_unified_kernel_images and "uefi" in args.boot_protocols:
        if args.distribution in (Distribution.debian, Distribution.ubuntu, Distribution.mageia, Distribution.opensuse):
            die("Sorry, --without-unified-kernel-images is not supported in UEFI mode on this distro.")

    if args.verity and not args.with_unified_kernel_images:
        die("Sorry, --verity can only be used with unified kernel images")

    if args.source_file_transfer is None:
        if os.path.exists(".git") or os.path.exists(os.path.join(args.build_sources, ".git")):
            args.source_file_transfer = SourceFileTransfer.copy_git_others
        else:
            args.source_file_transfer = SourceFileTransfer.copy_all

    if args.source_file_transfer_final == SourceFileTransfer.mount:
        die("Sorry, --source-file-transfer-final=mount is not supported")

    if args.skip_final_phase and args.verb != "build":
        die("--skip-final-phase can only be used when building an image using `mkosi build`")

    if args.ssh and not args.network_veth:
        die("--ssh cannot be used without --network-veth")

    return args


def check_output(args: CommandLineArguments) -> None:
    if args.skip_final_phase:
        return

    for f in (
        args.output,
        args.output_checksum if args.checksum else None,
        args.output_signature if args.sign else None,
        args.output_bmap if args.bmap else None,
        args.output_nspawn_settings if args.nspawn_settings is not None else None,
        args.output_root_hash_file if args.verity else None,
        args.output_sshkey if args.ssh else None,
    ):

        if f is None:
            continue

        if os.path.exists(f):
            die("Output file " + f + " exists already. (Consider invocation with --force.)")


def yes_no(b: bool) -> str:
    return "yes" if b else "no"


def format_bytes_or_disabled(sz: Optional[int]) -> str:
    if sz is None:
        return "(disabled)"

    return format_bytes(sz)


def format_bytes_or_auto(sz: Optional[int]) -> str:
    if sz is None:
        return "(automatic)"

    return format_bytes(sz)


def none_to_na(s: Optional[str]) -> str:
    return "n/a" if s is None else s


def none_to_no(s: Optional[str]) -> str:
    return "no" if s is None else s


def none_to_none(o: Optional[object]) -> str:
    return "none" if o is None else str(o)


def line_join_list(ary: List[str]) -> str:

    if not ary:
        return "none"

    return "\n                        ".join(ary)


def print_summary(args: CommandLineArguments) -> None:
    # FIXME: normal print
    MkosiPrinter.info("COMMANDS:")
    MkosiPrinter.info("                      verb: " + args.verb)
    try:
        MkosiPrinter.info("                   cmdline: " + " ".join(args.cmdline))
    except AttributeError:
        pass
    MkosiPrinter.info("\nDISTRIBUTION:")
    MkosiPrinter.info("              Distribution: " + args.distribution.name)
    MkosiPrinter.info("                   Release: " + none_to_na(args.release))
    if args.architecture:
        MkosiPrinter.info("              Architecture: " + args.architecture)
    if args.mirror is not None:
        MkosiPrinter.info("                    Mirror: " + args.mirror)
    if args.repositories is not None and len(args.repositories) > 0:
        MkosiPrinter.info("              Repositories: " + ",".join(args.repositories))
    MkosiPrinter.info("\nOUTPUT:")
    if args.hostname:
        MkosiPrinter.info("                  Hostname: " + args.hostname)
    MkosiPrinter.info("             Output Format: " + args.output_format.name)
    if args.output_format.can_minimize():
        MkosiPrinter.info("                  Minimize: " + yes_no(args.minimize))
    if args.output_dir:
        MkosiPrinter.info("          Output Directory: " + args.output_dir)
    MkosiPrinter.info("                    Output: " + args.output)
    MkosiPrinter.info("           Output Checksum: " + none_to_na(args.output_checksum if args.checksum else None))
    MkosiPrinter.info("          Output Signature: " + none_to_na(args.output_signature if args.sign else None))
    MkosiPrinter.info("               Output Bmap: " + none_to_na(args.output_bmap if args.bmap else None))
    MkosiPrinter.info(
        "    Output nspawn Settings: "
        + none_to_na(args.output_nspawn_settings if args.nspawn_settings is not None else None)
    )  # NOQA: E501
    MkosiPrinter.info("            Output SSH key: " + none_to_na(args.output_sshkey if args.ssh else None))
    MkosiPrinter.info("               Incremental: " + yes_no(args.incremental))

    MkosiPrinter.info("                 Read-only: " + yes_no(args.read_only))
    detail = " ({})".format(args.compress) if args.compress and not isinstance(args.compress, bool) else ""
    MkosiPrinter.info("            FS Compression: " + yes_no(args.compress) + detail)

    MkosiPrinter.info("            XZ Compression: " + yes_no(args.xz))
    if args.mksquashfs_tool:
        MkosiPrinter.info("           Mksquashfs tool: " + " ".join(args.mksquashfs_tool))

    if args.output_format.is_disk():
        MkosiPrinter.info("                     QCow2: " + yes_no(args.qcow2))

    MkosiPrinter.info("                Encryption: " + none_to_no(args.encrypt))
    MkosiPrinter.info("                    Verity: " + yes_no(args.verity))

    if args.output_format.is_disk():
        MkosiPrinter.info("                  Bootable: " + yes_no(args.bootable))

        if args.bootable:
            MkosiPrinter.info("       Kernel Command Line: " + " ".join(args.kernel_command_line))
            MkosiPrinter.info("           UEFI SecureBoot: " + yes_no(args.secure_boot))

            if args.secure_boot:
                MkosiPrinter.info("       UEFI SecureBoot Key: " + args.secure_boot_key)
                MkosiPrinter.info("     UEFI SecureBoot Cert.: " + args.secure_boot_certificate)

            MkosiPrinter.info("            Boot Protocols: " + line_join_list(args.boot_protocols))
            MkosiPrinter.info("     Unified Kernel Images: " + yes_no(args.with_unified_kernel_images))
            MkosiPrinter.info("             GPT First LBA: " + str(args.gpt_first_lba))
            MkosiPrinter.info("           Hostonly Initrd: " + yes_no(args.hostonly_initrd))

    MkosiPrinter.info("\nPACKAGES:")
    MkosiPrinter.info("                  Packages: " + line_join_list(args.packages))

    if args.distribution in (Distribution.fedora, Distribution.centos, Distribution.centos_epel, Distribution.mageia):
        MkosiPrinter.info("    With Documentation: " + yes_no(args.with_docs))

    MkosiPrinter.info("             Package Cache: " + none_to_none(args.cache_path))
    MkosiPrinter.info("               Extra Trees: " + line_join_list(args.extra_trees))
    MkosiPrinter.info("            Skeleton Trees: " + line_join_list(args.skeleton_trees))
    MkosiPrinter.info("              Build Script: " + none_to_none(args.build_script))
    MkosiPrinter.info("         Build Environment: " + line_join_list(args.build_env))

    if args.build_script:
        MkosiPrinter.info("             Run tests: " + yes_no(args.with_tests))

    MkosiPrinter.info("             Build Sources: " + none_to_none(args.build_sources))
    MkosiPrinter.info("      Source File Transfer: " + none_to_none(args.source_file_transfer))
    MkosiPrinter.info("Source File Transfer Final: " + none_to_none(args.source_file_transfer_final))
    MkosiPrinter.info("           Build Directory: " + none_to_none(args.build_dir))
    MkosiPrinter.info("         Include Directory: " + none_to_none(args.include_dir))
    MkosiPrinter.info("         Install Directory: " + none_to_none(args.install_dir))
    MkosiPrinter.info("            Build Packages: " + line_join_list(args.build_packages))
    MkosiPrinter.info("          Skip final phase: " + yes_no(args.skip_final_phase))
    MkosiPrinter.info("        Postinstall Script: " + none_to_none(args.postinst_script))
    MkosiPrinter.info("            Prepare Script: " + none_to_none(args.prepare_script))
    MkosiPrinter.info("           Finalize Script: " + none_to_none(args.finalize_script))
    MkosiPrinter.info("      Scripts with network: " + yes_no(args.with_network))
    MkosiPrinter.info("           nspawn Settings: " + none_to_none(args.nspawn_settings))

    if args.output_format.is_disk():
        MkosiPrinter.info("\nPARTITIONS:")
        MkosiPrinter.info("            Root Partition: " + format_bytes_or_auto(args.root_size))
        MkosiPrinter.info("            Swap Partition: " + format_bytes_or_disabled(args.swap_size))
        if "uefi" in args.boot_protocols:
            MkosiPrinter.info("                       ESP: " + format_bytes_or_disabled(args.esp_size))
        if "bios" in args.boot_protocols:
            MkosiPrinter.info("                      BIOS: " + format_bytes_or_disabled(BIOS_PARTITION_SIZE))
        MkosiPrinter.info("        XBOOTLDR Partition: " + format_bytes_or_disabled(args.xbootldr_size))
        MkosiPrinter.info("           /home Partition: " + format_bytes_or_disabled(args.home_size))
        MkosiPrinter.info("            /srv Partition: " + format_bytes_or_disabled(args.srv_size))
        MkosiPrinter.info("            /var Partition: " + format_bytes_or_disabled(args.var_size))
        MkosiPrinter.info("        /var/tmp Partition: " + format_bytes_or_disabled(args.tmp_size))

        MkosiPrinter.info("\nVALIDATION:")
        MkosiPrinter.info("                  Checksum: " + yes_no(args.checksum))
        MkosiPrinter.info("                      Sign: " + yes_no(args.sign))
        MkosiPrinter.info("                   GPG Key: " + ("default" if args.key is None else args.key))
        MkosiPrinter.info("                  Password: " + ("default" if args.password is None else "set"))
        MkosiPrinter.info("                 Autologin: " + yes_no(args.autologin))

    MkosiPrinter.info("\nHOST CONFIGURATION:")
    MkosiPrinter.info("        Extra search paths: " + line_join_list(args.extra_search_paths))
    MkosiPrinter.info("             QEMU Headless: " + yes_no(args.qemu_headless))
    MkosiPrinter.info("              Network Veth: " + yes_no(args.network_veth))


def reuse_cache_tree(
    args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool, cached: bool
) -> bool:
    """If there's a cached version of this tree around, use it and
    initialize our new root directly from it. Returns a boolean indicating
    whether we are now operating on a cached version or not."""

    if cached:
        return True

    if not args.incremental:
        return False
    if for_cache:
        return False
    if args.output_format.is_disk_rw():
        return False

    fname = args.cache_pre_dev if do_run_build_script else args.cache_pre_inst
    if fname is None:
        return False

    with complete_step("Copying in cached tree " + fname):
        try:
            copy_path(fname, root)
        except FileNotFoundError:
            return False

    return True


def make_output_dir(args: CommandLineArguments) -> None:
    """Create the output directory if set and not existing yet"""
    if args.output_dir is None:
        return

    mkdir_last(args.output_dir, 0o755)


def make_build_dir(args: CommandLineArguments) -> None:
    """Create the build directory if set and not existing yet"""
    if args.build_dir is None:
        return

    mkdir_last(args.build_dir, 0o755)


def setup_ssh(
    args: CommandLineArguments, root: str, do_run_build_script: bool, for_cache: bool, cached: bool
) -> Optional[TextIO]:
    if do_run_build_script or not args.ssh:
        return None

    if args.distribution in (Distribution.debian, Distribution.ubuntu):
        unit = "ssh"
    else:
        unit = "sshd"

    # We cache the enable sshd step but not the keygen step because it creates a separate file on the host
    # which introduces non-trivial issue when trying to cache it.

    if not cached:
        run(["systemctl", "--root", root, "enable", unit])

    if for_cache:
        return None

    f: TextIO = cast(
        TextIO,
        tempfile.NamedTemporaryFile(
            mode="w+", prefix=".mkosi-", encoding="utf-8", dir=os.path.dirname(args.output_sshkey)
        ),
    )

    with complete_step("Generating SSH keypair"):
        # Write a 'y' to confirm to overwrite the file.
        run(
            ["ssh-keygen", "-f", f.name, "-N", args.password or "", "-C", "mkosi", "-t", "ed25519"],
            input=f"y\n",
            text=True,
            stdout=DEVNULL,
        )

    copy_file(f"{f.name}.pub", os.path.join(root, "root/.ssh/authorized_keys"))
    os.remove(f"{f.name}.pub")

    os.chmod(os.path.join(root, "root/.ssh/authorized_keys"), 0o600)

    return f


def setup_network_veth(args: CommandLineArguments, root: str, do_run_build_script: bool, cached: bool) -> None:
    if do_run_build_script or cached or not args.network_veth:
        return

    with complete_step("Setting up network veth"):
        network_file = os.path.join(root, "etc/systemd/network/80-mkosi-network-veth.network")
        with open(network_file, "w") as f:
            # Adapted from https://github.com/systemd/systemd/blob/v247/network/80-container-host0.network
            f.write(
                dedent(
                    """\
                    [Match]
                    Virtualization=!container
                    Type=ether

                    [Network]
                    DHCP=yes
                    LinkLocalAddressing=yes
                    LLDP=yes
                    EmitLLDP=customer-bridge

                    [DHCP]
                    UseTimezone=yes
                    """
                )
            )

        os.chmod(network_file, 0o644)

        run(["systemctl", "--root", root, "enable", "systemd-networkd"])


def build_image(
    args: CommandLineArguments, root: str, *, do_run_build_script: bool, for_cache: bool = False, cleanup: bool = False
) -> Tuple[Optional[BinaryIO], Optional[BinaryIO], Optional[str], Optional[TextIO]]:
    # If there's no build script set, there's no point in executing
    # the build script iteration. Let's quit early.
    if args.build_script is None and do_run_build_script:
        return None, None, None, None

    make_build_dir(args)

    raw, cached = reuse_cache_image(args, root, do_run_build_script, for_cache)
    if for_cache and cached:
        # Found existing cache image, exiting build_image
        return None, None, None, None

    if not cached:
        raw = create_image(args, root, for_cache)

    with attach_image_loopback(args, raw) as loopdev:

        prepare_swap(args, loopdev, cached)
        prepare_esp(args, loopdev, cached)
        prepare_xbootldr(args, loopdev, cached)

        if loopdev is not None:
            luks_format_root(args, loopdev, do_run_build_script, cached)
            luks_format_home(args, loopdev, do_run_build_script, cached)
            luks_format_srv(args, loopdev, do_run_build_script, cached)
            luks_format_var(args, loopdev, do_run_build_script, cached)
            luks_format_tmp(args, loopdev, do_run_build_script, cached)

        with luks_setup_all(args, loopdev, do_run_build_script) as (
            encrypted_root,
            encrypted_home,
            encrypted_srv,
            encrypted_var,
            encrypted_tmp,
        ):

            prepare_root(args, encrypted_root, cached)
            prepare_home(args, encrypted_home, cached)
            prepare_srv(args, encrypted_srv, cached)
            prepare_var(args, encrypted_var, cached)
            prepare_tmp(args, encrypted_tmp, cached)

            # Mount everything together, but let's not mount the root
            # dir if we still have to generate the root image here
            prepare_tree_root(args, root)
            with mount_image(
                args,
                root,
                loopdev,
                None if args.generated_root() else encrypted_root,
                encrypted_home,
                encrypted_srv,
                encrypted_var,
                encrypted_tmp,
            ):
                prepare_tree(args, root, do_run_build_script, cached)
                if do_run_build_script and args.include_dir and not cached:
                    empty_directory(args.include_dir)
                    # We do a recursive unmount of root so we don't need to explicitly unmount this mount
                    # later.
                    mount_bind(args.include_dir, os.path.join(root, "usr/include"))

                cached_tree = reuse_cache_tree(args, root, do_run_build_script, for_cache, cached)
                install_skeleton_trees(args, root, for_cache)
                install_distribution(args, root, do_run_build_script, cached_tree)
                install_etc_hostname(args, root, cached_tree)
                install_boot_loader(args, root, loopdev, do_run_build_script, cached_tree)
                run_prepare_script(args, root, do_run_build_script, cached_tree)
                install_extra_trees(args, root, for_cache)
                install_build_src(args, root, do_run_build_script, for_cache)
                install_build_dest(args, root, do_run_build_script, for_cache)
                set_root_password(args, root, do_run_build_script, cached_tree)
                set_serial_terminal(args, root, do_run_build_script, cached_tree)
                set_autologin(args, root, do_run_build_script, cached_tree)
                sshkey = setup_ssh(args, root, do_run_build_script, for_cache, cached_tree)
                setup_network_veth(args, root, do_run_build_script, cached_tree)
                run_postinst_script(args, root, loopdev, do_run_build_script, for_cache)

                if cleanup:
                    clean_package_manager_metadata(root)
                reset_machine_id(args, root, do_run_build_script, for_cache)
                reset_random_seed(args, root)
                run_finalize_script(args, root, do_run_build_script, for_cache)
                make_read_only(args, root, for_cache)

            generated_root = make_generated_root(args, root, for_cache)
            insert_generated_root(args, root, raw, loopdev, generated_root, for_cache)

            verity, root_hash = make_verity(args, root, encrypted_root, do_run_build_script, for_cache)
            patch_root_uuid(args, loopdev, root_hash, for_cache)
            insert_verity(args, root, raw, loopdev, verity, root_hash, for_cache)

            # This time we mount read-only, as we already generated
            # the verity data, and hence really shouldn't modify the
            # image anymore.
            mount = lambda: mount_image(
                args,
                root,
                loopdev,
                None if args.generated_root() and for_cache else encrypted_root,
                encrypted_home,
                encrypted_srv,
                encrypted_var,
                encrypted_tmp,
                root_read_only=True,
            )

            install_unified_kernel(args, root, root_hash, do_run_build_script, for_cache, cached, mount)
            secure_boot_sign(args, root, do_run_build_script, for_cache, cached, mount)

    tar = make_tar(args, root, do_run_build_script, for_cache)

    return raw or generated_root, tar, root_hash, sshkey


def workspace(root: str) -> str:
    return os.path.dirname(root)


def var_tmp(root: str) -> str:
    return mkdir_last(os.path.join(workspace(root), "var-tmp"))


def one_zero(b: bool) -> str:
    return "1" if b else "0"


def install_dir(args: CommandLineArguments, root: str) -> str:
    return args.install_dir or os.path.join(workspace(root), "dest")


def nspawn_knows_arg(arg: str) -> bool:
    return bytes("unrecognized option", "UTF-8") not in run(["systemd-nspawn", arg], stderr=PIPE, check=False).stderr


def run_build_script(args: CommandLineArguments, root: str, raw: Optional[BinaryIO]) -> None:
    if args.build_script is None:
        return

    with complete_step("Running build script"):
        os.makedirs(install_dir(args, root), mode=0o755, exist_ok=True)

        target = "--directory=" + root if raw is None else "--image=" + raw.name

        cmdline = [
            "systemd-nspawn",
            "--quiet",
            target,
            "--uuid=" + args.machine_id,
            "--machine=mkosi-" + uuid.uuid4().hex,
            "--as-pid2",
            "--register=no",
            "--bind",
            install_dir(args, root) + ":/root/dest",
            "--bind=" + var_tmp(root) + ":/var/tmp",
            "--setenv=WITH_DOCS=" + one_zero(args.with_docs),
            "--setenv=WITH_TESTS=" + one_zero(args.with_tests),
            "--setenv=WITH_NETWORK=" + one_zero(args.with_network),
            "--setenv=DESTDIR=/root/dest",
        ]

        for env in args.build_env:
            cmdline.append(f"--setenv={env}")

        # TODO: Use --autopipe once systemd v247 is widely available.
        console_arg = f"--console={'interactive' if sys.stdout.isatty() else 'pipe'}"
        if nspawn_knows_arg(console_arg):
            cmdline.append(console_arg)

        if args.default_path is not None:
            cmdline.append("--setenv=MKOSI_DEFAULT=" + args.default_path)

        cmdline += nspawn_params_for_build_sources(args, args.source_file_transfer)

        if args.build_dir is not None:
            cmdline.append("--setenv=BUILDDIR=/root/build")
            cmdline.append("--bind=" + args.build_dir + ":/root/build")

        if args.include_dir is not None:
            cmdline.append(f"--bind={args.include_dir}:/usr/include")

        if args.with_network:
            # If we're using the host network namespace, use the same resolver
            cmdline.append("--bind-ro=/etc/resolv.conf")
        else:
            cmdline.append("--private-network")

        cmdline.append("/root/" + os.path.basename(args.build_script))
        cmdline += args.cmdline

        # build-script output goes to stdout so we can run language servers from within mkosi build-scripts.
        # See https://github.com/systemd/mkosi/pull/566 for more information.
        result = run(cmdline, stdout=sys.stdout, check=False)
        if result.returncode != 0:
            if "build-script" in arg_debug:
                run(cmdline[:-1], check=False)
            die(f"Build script returned non-zero exit code {result.returncode}.")


def need_cache_images(args: CommandLineArguments) -> bool:
    if not args.incremental:
        return False

    if args.force_count > 1:
        return True

    return not os.path.exists(args.cache_pre_dev) or not os.path.exists(args.cache_pre_inst)


def remove_artifacts(
    args: CommandLineArguments,
    root: str,
    raw: Optional[BinaryIO],
    tar: Optional[BinaryIO],
    do_run_build_script: bool,
    for_cache: bool = False,
) -> None:
    if for_cache:
        what = "cache build"
    elif do_run_build_script:
        what = "development build"
    else:
        return

    if raw is not None:
        with complete_step("Removing disk image from " + what):
            del raw

    if tar is not None:
        with complete_step("Removing tar image from " + what):
            del tar

    with complete_step("Removing artifacts from " + what):
        unlink_try_hard(root)
        unlink_try_hard(var_tmp(root))


def build_stuff(args: CommandLineArguments) -> None:
    # Let's define a fixed machine ID for all our build-time
    # runs. We'll strip it off the final image, but some build-time
    # tools (dracut...) want a fixed one, hence provide one, and
    # always the same
    args.machine_id = uuid.uuid4().hex

    make_output_dir(args)
    setup_package_cache(args)
    workspace = setup_workspace(args)

    # Make sure tmpfiles' aging doesn't interfere with our workspace
    # while we are working on it.
    with open_close(
        workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    ) as dir_fd, btrfs_forget_stale_devices():
        fcntl.flock(dir_fd, fcntl.LOCK_EX)

        root = os.path.join(workspace.name, "root")

        # If caching is requested, then make sure we have cache images around we can make use of
        if need_cache_images(args):

            # There is no point generating a pre-dev cache image if no build script is provided
            if args.build_script:
                with complete_step("Running first (development) stage to generate cached copy"):
                    # Generate the cache version of the build image, and store it as "cache-pre-dev"
                    raw, tar, root_hash, sshkey = build_image(args, root, do_run_build_script=True, for_cache=True)
                    save_cache(args, root, raw.name if raw is not None else None, args.cache_pre_dev)

                    remove_artifacts(args, root, raw, tar, do_run_build_script=True)

            with complete_step("Running second (final) stage to generate cached copy"):
                # Generate the cache version of the build image, and store it as "cache-pre-inst"
                raw, tar, root_hash, sshkey = build_image(args, root, do_run_build_script=False, for_cache=True)

                if raw:
                    save_cache(args, root, raw.name, args.cache_pre_inst)
                    remove_artifacts(args, root, raw, tar, do_run_build_script=False)

        if args.build_script:
            with complete_step("Running first (development) stage"):
                # Run the image builder for the first (development) stage in preparation for the build script
                raw, tar, root_hash, sshkey = build_image(args, root, do_run_build_script=True)

                run_build_script(args, root, raw)
                remove_artifacts(args, root, raw, tar, do_run_build_script=True)

        # Run the image builder for the second (final) stage
        if not args.skip_final_phase:
            with complete_step("Running second (final) stage"):
                raw, tar, root_hash, sshkey = build_image(args, root, do_run_build_script=False, cleanup=True)
        else:
            MkosiPrinter.print_step("Skipping (second) final image build phase.")

        raw = qcow2_output(args, raw)
        raw = xz_output(args, raw)
        root_hash_file = write_root_hash_file(args, root_hash)
        settings = copy_nspawn_settings(args)
        checksum = calculate_sha256sum(args, raw, tar, root_hash_file, settings)
        signature = calculate_signature(args, checksum)
        bmap = calculate_bmap(args, raw)

        link_output(args, root, raw or tar)
        link_output_root_hash_file(args, root_hash_file.name if root_hash_file is not None else None)
        link_output_checksum(args, checksum.name if checksum is not None else None)
        link_output_signature(args, signature.name if signature is not None else None)
        link_output_bmap(args, bmap.name if bmap is not None else None)
        link_output_nspawn_settings(args, settings.name if settings is not None else None)
        link_output_sshkey(args, sshkey.name if sshkey is not None else None)

        if root_hash is not None:
            MkosiPrinter.print_step(f"Root hash is {root_hash}.")


def check_root() -> None:
    if os.getuid() != 0:
        die("Must be invoked as root.")


def check_native(args: CommandLineArguments) -> None:
    if args.architecture is not None and args.architecture != platform.machine() and args.build_script:
        die("Cannot (currently) override the architecture and run build commands")


@contextlib.contextmanager
def suppress_stacktrace() -> Generator[None, None, None]:
    try:
        yield
    except subprocess.CalledProcessError as e:
        # MkosiException is silenced in main() so it doesn't print a stacktrace.
        raise MkosiException(e)


def virt_name(args: CommandLineArguments) -> str:
    name = args.hostname or os.path.splitext(os.path.basename(args.output))[0]
    # Shorten to 13 characters so we can prefix with ve- or vt- for the network veth ifname which is limited
    # to 16 characters.
    return cast(str, name[:13])


def has_networkd_vm_vt() -> bool:
    for path in ["/usr/lib/systemd/network", "/lib/systemd/network", "/etc/systemd/network"]:
        if os.path.exists(os.path.join(path, "80-vm-vt.network")):
            return True

    return False


def ensure_networkd(args: CommandLineArguments) -> None:
    networkd_is_running = run(["systemctl", "is-active", "--quiet", "systemd-networkd"], check=False).returncode == 0
    if not networkd_is_running:
        warn(
            """
            --network-veth requires systemd-networkd to be running to initialize the host interface of the
            veth link (`systemctl enable --now systemd-networkd`)")
            """
        )

    if args.verb == "qemu" and not has_networkd_vm_vt():
        warn(
            r"""
            mkosi didn't find 80-vm-vt.network. This is one of systemd's built-in systemd-networkd config
            files which configures vt-* interfaces. mkosi needs this file in order for --network-veth to work
            properly for QEMU virtual machines. The file likely cannot be found because the systemd version
            on the host is too old (< 246) and it isn't included yet.

            As a workaround until the file is shipped by the systemd package of your distro, add a user
            network file /etc/systemd/network/80-vm-vt.network with the following contents:

            ```
            [Match]
            Name=vt-*
            Driver=tun

            [Network]
            # Default to using a /28 prefix, giving up to 13 addresses per VM.
            Address=0.0.0.0/28
            LinkLocalAddressing=yes
            DHCPServer=yes
            IPMasquerade=yes
            LLDP=yes
            EmitLLDP=customer-bridge
            IPv6PrefixDelegation=yes
            ```
            """
        )


def run_shell(args: CommandLineArguments) -> None:
    if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        target = f"--directory={args.output}"
    else:
        target = f"--image={args.output}"

    cmdline = ["systemd-nspawn", target]

    if args.read_only:
        cmdline.append("--read-only")

    # If we copied in a .nspawn file, make sure it's actually honoured
    if args.nspawn_settings is not None:
        cmdline.append("--settings=trusted")

    if args.verb == "boot":
        cmdline.append("--boot")

    if args.generated_root() or args.verity:
        cmdline.append("--volatile=overlay")

    if args.network_veth:
        ensure_networkd(args)
        cmdline.append("--network-veth")

    if args.ephemeral:
        cmdline.append("--ephemeral")

    cmdline += ["--machine", virt_name(args)]

    if args.cmdline:
        # If the verb is shell, args.cmdline contains the command to run. Otherwise (boot), we assume
        # args.cmdline contains nspawn arguments.
        if args.verb == "shell":
            cmdline.append("--")
        cmdline += args.cmdline

    with suppress_stacktrace():
        run(cmdline, stdout=sys.stdout, stderr=sys.stderr)


def find_qemu_binary() -> str:
    ARCH_BINARIES = {"x86_64": "qemu-system-x86_64", "i386": "qemu-system-i386"}
    arch_binary = ARCH_BINARIES.get(platform.machine())

    binaries: List[str] = []
    if arch_binary is not None:
        binaries.append(arch_binary)
    binaries += ["qemu", "qemu-kvm"]
    for binary in binaries:
        if shutil.which(binary) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_qemu_firmware() -> Tuple[str, bool]:
    # UEFI firmware blobs are found in a variety of locations,
    # depending on distribution and package.
    FIRMWARE_LOCATIONS = []

    if platform.machine() == "x86_64":
        FIRMWARE_LOCATIONS.append("/usr/share/ovmf/x64/OVMF_CODE.secboot.fd")
    elif platform.machine() == "i386":
        FIRMWARE_LOCATIONS.append("/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd")

    FIRMWARE_LOCATIONS.append("/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd")
    FIRMWARE_LOCATIONS.append("/usr/share/qemu/OVMF_CODE.secboot.fd")
    FIRMWARE_LOCATIONS.append("/usr/share/ovmf/OVMF.secboot.fd")

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return firmware, True

    warn(
        """\
        Couldn't find OVMF firmware blob with secure boot support,
        falling back to OVMF firmware blobs without secure boot support.
        """
    )

    FIRMWARE_LOCATIONS = []

    # First, we look in paths that contain the architecture –
    # if they exist, they’re almost certainly correct.
    if platform.machine() == "x86_64":
        FIRMWARE_LOCATIONS.append("/usr/share/ovmf/ovmf_code_x64.bin")
        FIRMWARE_LOCATIONS.append("/usr/share/ovmf/x64/OVMF_CODE.fd")
        FIRMWARE_LOCATIONS.append("/usr/share/qemu/ovmf-x86_64.bin")
    elif platform.machine() == "i386":
        FIRMWARE_LOCATIONS.append("/usr/share/ovmf/ovmf_code_ia32.bin")
        FIRMWARE_LOCATIONS.append("/usr/share/edk2/ovmf-ia32/OVMF_CODE.fd")
    # After that, we try some generic paths and hope that if they exist,
    # they’ll correspond to the current architecture, thanks to the package manager.
    FIRMWARE_LOCATIONS.append("/usr/share/edk2/ovmf/OVMF_CODE.fd")
    FIRMWARE_LOCATIONS.append("/usr/share/qemu/OVMF_CODE.fd")
    FIRMWARE_LOCATIONS.append("/usr/share/ovmf/OVMF.fd")

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return firmware, False

    die("Couldn't find OVMF UEFI firmware blob.")


def find_ovmf_vars() -> str:
    OVMF_VARS_LOCATIONS = []

    if platform.machine() == "x86_64":
        OVMF_VARS_LOCATIONS.append("/usr/share/ovmf/x64/OVMF_VARS.fd")
    elif platform.machine() == "i386":
        OVMF_VARS_LOCATIONS.append("/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd")

    OVMF_VARS_LOCATIONS.append("/usr/share/edk2/ovmf/OVMF_VARS.fd")
    OVMF_VARS_LOCATIONS.append("/usr/share/qemu/OVMF_VARS.fd")
    OVMF_VARS_LOCATIONS.append("/usr/share/ovmf/OVMF_VARS.fd")

    for location in OVMF_VARS_LOCATIONS:
        if os.path.exists(location):
            return location

    die("Couldn't find OVMF UEFI variables file.")


def run_qemu(args: CommandLineArguments) -> None:
    has_kvm = os.path.exists("/dev/kvm")
    accel = "kvm" if has_kvm else "tcg"

    firmware, fw_supports_sb = find_qemu_firmware()

    cmdline = [
        find_qemu_binary(),
        "-machine",
        f"type=q35,accel={accel},smm={'on' if fw_supports_sb else 'off'}",
        "-smp",
        "2",
        "-m",
        "1024",
        "-object",
        "rng-random,filename=/dev/urandom,id=rng0",
        "-device",
        "virtio-rng-pci,rng=rng0,id=rng-device0",
    ]

    if has_kvm:
        cmdline += ["-cpu", "host"]

    if args.qemu_headless:
        # -nodefaults removes the default CDROM device which avoids an error message during boot
        # -serial mon:stdio adds back the serial device removed by -nodefaults.
        cmdline += ["-nographic", "-nodefaults", "-serial", "mon:stdio"]
        # Fix for https://github.com/systemd/mkosi/issues/559. QEMU gets stuck in a boot loop when using BIOS
        # if there's no vga device.

    if not args.qemu_headless or (args.qemu_headless and "bios" in args.boot_protocols):
        cmdline += ["-vga", "virtio"]

    if args.network_veth:
        ensure_networkd(args)
        # Use vt- prefix so we can take advantage of systemd-networkd's builtin network file for VMs.
        ifname = f"vt-{virt_name(args)}"
        # vt-<image-name> is the ifname on the host and is automatically picked up by systemd-networkd which
        # starts a DHCP server on that interface. This gives IP connectivity to the VM. By default, QEMU
        # itself tries to bring up the vt network interface which conflicts with systemd-networkd which is
        # trying to do the same. By specifiying script=no and downscript=no, We tell QEMU to not touch vt
        # after it is created.
        cmdline += ["-nic", f"tap,script=no,downscript=no,ifname={ifname},model=virtio-net-pci"]

    if "uefi" in args.boot_protocols:
        cmdline += ["-drive", f"if=pflash,format=raw,readonly,file={firmware}"]

    with contextlib.ExitStack() as stack:
        if fw_supports_sb:
            ovmf_vars = stack.enter_context(copy_file_temporary(src=find_ovmf_vars(), dir=tmp_dir()))
            cmdline += [
                "-global",
                "ICH9-LPC.disable_s3=1",
                "-global",
                "driver=cfi.pflash01,property=secure,value=on",
                "-drive",
                f"file={ovmf_vars.name},if=pflash,format=raw",
            ]

        if args.ephemeral:
            f = stack.enter_context(copy_image_temporary(src=args.output, dir=os.path.dirname(args.output)))
            fname = f.name
        else:
            fname = args.output

        cmdline += [
            "-drive",
            f"if=none,id=hd,file={fname},format={'qcow2' if args.qcow2 else 'raw'}",
            "-device",
            "virtio-scsi-pci,id=scsi",
            "-device",
            "scsi-hd,drive=hd,bootindex=1",
        ]

        cmdline += args.cmdline

        print_running_cmd(cmdline)

        with suppress_stacktrace():
            run(cmdline, stdout=sys.stdout, stderr=sys.stderr)


def interface_exists(dev: str) -> bool:
    return run(["ip", "link", "show", dev], stdout=DEVNULL, stderr=DEVNULL, check=False).returncode == 0


def find_address(args: CommandLineArguments) -> Tuple[str, str]:
    name = virt_name(args)

    if interface_exists(f"ve-{name}"):
        dev = f"ve-{name}"
    elif interface_exists(f"vt-{name}"):
        dev = f"vt-{name}"
    else:
        die("Container/VM interface not found")

    link = json.loads(run(["ip", "-j", "link", "show", "dev", dev], stdout=PIPE, text=True).stdout)[0]
    if link["operstate"] == "DOWN":
        die(f"{dev} is not enabled. Make sure systemd-networkd is running so it can manage the interface.")

    # Trigger IPv6 neighbor discovery of which we can access the results via `ip neighbor`. This allows us to
    # find out the link-local IPv6 address of the container/VM via which we can connect to it.
    run(["ping", "-c", "1", "-w", "15", f"ff02::1%{dev}"], stdout=DEVNULL)

    for _ in range(50):
        neighbors = json.loads(run(["ip", "-j", "neighbor", "show", "dev", dev], stdout=PIPE, text=True).stdout)

        for neighbor in neighbors:
            dst = cast(str, neighbor["dst"])
            if dst.startswith("fe80"):
                return dev, dst

        time.sleep(0.4)

    die("Container/VM address not found")


def run_ssh(args: CommandLineArguments) -> None:
    if not os.path.exists(args.output_sshkey):
        die(
            f"SSH key not found at {args.output_sshkey}. Are you running from the project's root directory "
            "and did you build with the --ssh option?"
        )

    dev, address = find_address(args)

    with suppress_stacktrace():
        run(
            [
                "ssh",
                "-i",
                args.output_sshkey,
                # Silence known hosts file errors/warnings.
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "LogLevel ERROR",
                f"root@{address}%{dev}",
                *args.cmdline,
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )


def generate_secure_boot_key(args: CommandLineArguments) -> NoReturn:
    """Generate secure boot keys using openssl"""
    args.secure_boot_key = args.secure_boot_key or "./mkosi.secure-boot.key"
    args.secure_boot_certificate = args.secure_boot_certificate or "./mkosi.secure-boot.crt"

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(args.secure_boot_valid_days))
    cn = expand_specifier(args.secure_boot_common_name)

    for f in (args.secure_boot_key, args.secure_boot_certificate):
        if os.path.exists(f) and not args.force:
            die(
                dedent(
                    f"""\
                    {f} already exists.
                    If you are sure you want to generate new secure boot keys
                    remove {args.secure_boot_key} and {args.secure_boot_certificate} first.
                    """
                )
            )

    MkosiPrinter.print_step(f"Generating secure boot keys rsa:{keylength} for CN `{cn}`.")
    MkosiPrinter.info(
        dedent(
            f"""
            The keys will expire in {args.secure_boot_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    cmd = [
        "openssl",
        "req",
        "-new",
        "-x509",
        "-newkey",
        f"rsa:{keylength}",
        "-keyout",
        args.secure_boot_key,
        "-out",
        args.secure_boot_certificate,
        "-days",
        str(args.secure_boot_valid_days),
        "-subj",
        f"/CN={cn}/",
    ]

    os.execvp(cmd[0], cmd)


def expand_paths(paths: List[str]) -> List[str]:
    if not paths:
        return []

    environ = os.environ.copy()
    # Add a fake SUDO_HOME variable to allow non-root users specify
    # paths in their home when using mkosi via sudo.
    sudo_user = os.getenv("SUDO_USER")
    if sudo_user and "SUDO_HOME" not in environ:
        environ["SUDO_HOME"] = os.path.expanduser(f"~{sudo_user}")

    # No os.path.expandvars because it treats unset variables as empty.
    expanded = []
    for path in paths:
        try:
            path = string.Template(path).substitute(environ)
            expanded.append(path)
        except KeyError:
            # Skip path if it uses a variable not defined.
            pass
    return expanded


def prepend_to_environ_path(paths: List[str]) -> None:
    if not paths:
        return

    original_path = os.getenv("PATH", None)
    new_path = ":".join(paths)

    if original_path is None:
        os.environ["PATH"] = new_path
    else:
        os.environ["PATH"] = new_path + ":" + original_path


def expand_specifier(s: str) -> str:
    user = os.getenv("SUDO_USER") or os.getenv("USER")
    assert user is not None
    return s.replace("%u", user)


def needs_build(args: CommandLineArguments) -> bool:
    return args.verb == "build" or (not os.path.exists(args.output) and args.verb in MKOSI_COMMANDS_NEED_BUILD)


def run_verb(args: CommandLineArguments) -> None:
    load_args(args)

    prepend_to_environ_path(args.extra_search_paths)

    if args.verb == "genkey":
        generate_secure_boot_key(args)

    if args.verb in MKOSI_COMMANDS_SUDO:
        check_root()
        unlink_output(args)

    if args.verb == "build":
        check_output(args)

    if args.verb == "summary" or (needs_build(args) and need_cache_images(args)):
        print_summary(args)

    if needs_build(args):
        check_root()
        check_native(args)
        init_namespace(args)
        build_stuff(args)
        print_output_size(args)

    if args.verb in ("shell", "boot"):
        run_shell(args)

    if args.verb == "qemu":
        run_qemu(args)

    if args.verb == "ssh":
        run_ssh(args)
