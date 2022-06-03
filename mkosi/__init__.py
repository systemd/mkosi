# SPDX-License-Identifier: LGPL-2.1+

from __future__ import annotations

import argparse
import ast
import base64
import collections
import configparser
import contextlib
import crypt
import ctypes
import ctypes.util
import dataclasses
import datetime
import errno
import fcntl
import functools
import getpass
import glob
import hashlib
import http.server
import importlib.resources
import json
import os
import platform
import re
import shlex
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from subprocess import DEVNULL, PIPE
from textwrap import dedent
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
    ContextManager,
    Deque,
    Dict,
    Iterable,
    Iterator,
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
)

from .backend import (
    _FILE,
    ARG_DEBUG,
    Distribution,
    ManifestFormat,
    MkosiArgs,
    MkosiException,
    MkosiNotSupportedException,
    MkosiPrinter,
    OutputFormat,
    PackageType,
    Partition,
    PartitionIdentifier,
    PartitionTable,
    SourceFileTransfer,
    Verb,
    die,
    install_grub,
    is_rpm_distribution,
    nspawn_executable,
    nspawn_params_for_blockdev_access,
    nspawn_rlimit_params,
    nspawn_version,
    patch_file,
    path_relative_to_cwd,
    run,
    run_workspace_command,
    set_umask,
    should_compress_fs,
    should_compress_output,
    spawn,
    tmp_dir,
    var_tmp,
    warn,
    workspace,
    write_grub_config,
)
from .manifest import Manifest

complete_step = MkosiPrinter.complete_step

__version__ = "12"


# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[Any]
    TempDir = tempfile.TemporaryDirectory[str]
else:
    CompletedProcess = subprocess.CompletedProcess
    TempDir = tempfile.TemporaryDirectory

SomeIO = Union[BinaryIO, TextIO]
PathString = Union[Path, str]

MKOSI_COMMANDS_NEED_BUILD = (Verb.shell, Verb.boot, Verb.qemu, Verb.serve)
MKOSI_COMMANDS_SUDO = (Verb.build, Verb.clean, Verb.shell, Verb.boot, Verb.qemu, Verb.serve)
MKOSI_COMMANDS_CMDLINE = (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.ssh)

DRACUT_SYSTEMD_EXTRAS = [
    "/usr/bin/systemd-repart",
    "/usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "/usr/lib/systemd/system/initrd-root-fs.target.wants/systemd-repart.service",
    "/usr/lib/systemd/system/initrd-usr-fs.target",
    "/usr/lib/systemd/system/systemd-repart.service",
    "/usr/lib/systemd/system/systemd-volatile-root.service",
    "/usr/lib/systemd/systemd-veritysetup",
    "/usr/lib/systemd/systemd-volatile-root",
    "/usr/bin/systemd-ask-password",
    "/usr/bin/systemd-tty-ask-password-agent"
]


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


T = TypeVar("T")
V = TypeVar("V")


def dictify(f: Callable[..., Iterator[Tuple[T, V]]]) -> Callable[..., Dict[T, V]]:
    def wrapper(*args: Any, **kwargs: Any) -> Dict[T, V]:
        return dict(f(*args, **kwargs))

    return functools.update_wrapper(wrapper, f)


@dictify
def read_os_release() -> Iterator[Tuple[str, str]]:
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
            m = re.match(r"([A-Z][A-Z_0-9]+)=(.*)", line)
            if m:
                name, val = m.groups()
                if val and val[0] in "\"'":
                    val = ast.literal_eval(val)
                yield name, val
            else:
                print(f"{filename}:{line_number}: bad line {line!r}", file=sys.stderr)


def print_running_cmd(cmdline: Iterable[str]) -> None:
    MkosiPrinter.print_step("Running command:")
    MkosiPrinter.print_step(" ".join(shlex.quote(x) for x in cmdline) + "\n")


GPT_ROOT_ALPHA                  = uuid.UUID("6523f8ae3eb14e2aa05a18b695ae656f")  # NOQA: E221
GPT_ROOT_ARC                    = uuid.UUID("d27f46ed29194cb8bd259531f3c16534")  # NOQA: E221
GPT_ROOT_ARM                    = uuid.UUID("69dad7102ce44e3cb16c21a1d49abed3")  # NOQA: E221
GPT_ROOT_ARM64                  = uuid.UUID("b921b0451df041c3af444c6f280d3fae")  # NOQA: E221
GPT_ROOT_IA64                   = uuid.UUID("993d8d3df80e4225855a9daf8ed7ea97")  # NOQA: E221
GPT_ROOT_LOONGARCH64            = uuid.UUID("77055800792c4f94b39a98c91b762bb6")  # NOQA: E221
GPT_ROOT_MIPS_LE                = uuid.UUID("37c58c8ad9134156a25f48b1b64e07f0")  # NOQA: E221
GPT_ROOT_MIPS64_LE              = uuid.UUID("700bda437a344507b179eeb93d7a7ca3")  # NOQA: E221
GPT_ROOT_PPC                    = uuid.UUID("1de3f1effa9847b58dcd4a860a654d78")  # NOQA: E221
GPT_ROOT_PPC64                  = uuid.UUID("912ade1da83949138964a10eee08fbd2")  # NOQA: E221
GPT_ROOT_PPC64LE                = uuid.UUID("c31c45e63f39412e80fb4809c4980599")  # NOQA: E221
GPT_ROOT_RISCV32                = uuid.UUID("60d5a7fe8e7d435cb7143dd8162144e1")  # NOQA: E221
GPT_ROOT_RISCV64                = uuid.UUID("72ec70a6cf7440e6bd494bda08e8f224")  # NOQA: E221
GPT_ROOT_S390                   = uuid.UUID("08a7acea624c4a2091e86e0fa67d23f9")  # NOQA: E221
GPT_ROOT_S390X                  = uuid.UUID("5eead9a9fe094a1ea1d7520d00531306")  # NOQA: E221
GPT_ROOT_TILEGX                 = uuid.UUID("c50cdd7038624cc390e1809a8c93ee2c")  # NOQA: E221
GPT_ROOT_X86                    = uuid.UUID("44479540f29741b29af7d131d5f0458a")  # NOQA: E221
GPT_ROOT_X86_64                 = uuid.UUID("4f68bce3e8cd4db196e7fbcaf984b709")  # NOQA: E221

GPT_USR_ALPHA                   = uuid.UUID("e18cf08c33ec4c0d8246c6c6fb3da024")  # NOQA: E221
GPT_USR_ARC                     = uuid.UUID("7978a68363164922bbee38bff5a2fecc")  # NOQA: E221
GPT_USR_ARM                     = uuid.UUID("7d0359a302b34f0a865c654403e70625")  # NOQA: E221
GPT_USR_ARM64                   = uuid.UUID("b0e01050ee5f4390949a9101b17104e9")  # NOQA: E221
GPT_USR_IA64                    = uuid.UUID("4301d2a64e3b4b2abb949e0b2c4225ea")  # NOQA: E221
GPT_USR_LOONGARCH64             = uuid.UUID("e611c702575c4cbe9a46434fa0bf7e3f")  # NOQA: E221
GPT_USR_MIPS_LE                 = uuid.UUID("0f4868e999524706979f3ed3a473e947")  # NOQA: E221
GPT_USR_MIPS64_LE               = uuid.UUID("c97c1f32ba0640b49f22236061b08aa8")  # NOQA: E221
GPT_USR_PPC                     = uuid.UUID("7d14fec5cc71415d9d6c06bf0b3c3eaf")  # NOQA: E221
GPT_USR_PPC64                   = uuid.UUID("2c9739e2f06846b39fd001c5a9afbcca")  # NOQA: E221
GPT_USR_PPC64LE                 = uuid.UUID("15bb03af77e74d4ab12bc0d084f7491c")  # NOQA: E221
GPT_USR_RISCV32                 = uuid.UUID("b933fb225c3f4f91af90e2bb0fa50702")  # NOQA: E221
GPT_USR_RISCV64                 = uuid.UUID("beaec34b8442439ba40b984381ed097d")  # NOQA: E221
GPT_USR_S390                    = uuid.UUID("cd0f869bd0fb4ca0b1419ea87cc78d66")  # NOQA: E221
GPT_USR_S390X                   = uuid.UUID("8a4f577050aa4ed3874a99b710db6fea")  # NOQA: E221
GPT_USR_TILEGX                  = uuid.UUID("55497029c7c144ccaa39815ed1558630")  # NOQA: E221
GPT_USR_X86                     = uuid.UUID("75250d768cc6458ebd66bd47cc81a812")  # NOQA: E221
GPT_USR_X86_64                  = uuid.UUID("8484680c952148c69c11b0720656f69e")  # NOQA: E221

GPT_ROOT_ALPHA_VERITY           = uuid.UUID("fc56d9e9e6e54c06be32e74407ce09a5")  # NOQA: E221
GPT_ROOT_ARC_VERITY             = uuid.UUID("24b2d9750f974521afa1cd531e421b8d")  # NOQA: E221
GPT_ROOT_ARM_VERITY             = uuid.UUID("7386cdf2203c47a9a498f2ecce45a2d6")  # NOQA: E221
GPT_ROOT_ARM64_VERITY           = uuid.UUID("df3300ced69f4c92978c9bfb0f38d820")  # NOQA: E221
GPT_ROOT_IA64_VERITY            = uuid.UUID("86ed10d5b60745bb8957d350f23d0571")  # NOQA: E221
GPT_ROOT_LOONGARCH64_VERITY     = uuid.UUID("f3393b22e9af4613a9489d3bfbd0c535")  # NOQA: E221
GPT_ROOT_MIPS_LE_VERITY         = uuid.UUID("d7d150d22a044a338f1216651205ff7b")  # NOQA: E221
GPT_ROOT_MIPS64_LE_VERITY       = uuid.UUID("16b417f83e064f578dd29b5232f41aa6")  # NOQA: E221
GPT_ROOT_PPC64LE_VERITY         = uuid.UUID("906bd94445894aaea4e4dd983917446a")  # NOQA: E221
GPT_ROOT_PPC64_VERITY           = uuid.UUID("9225a9a33c194d89b4f6eeff88f17631")  # NOQA: E221
GPT_ROOT_PPC_VERITY             = uuid.UUID("98cfe649158846dcb2f0add147424925")  # NOQA: E221
GPT_ROOT_RISCV32_VERITY         = uuid.UUID("ae0253be11674007ac6843926c14c5de")  # NOQA: E221
GPT_ROOT_RISCV64_VERITY         = uuid.UUID("b6ed5582440b4209b8da5ff7c419ea3d")  # NOQA: E221
GPT_ROOT_S390X_VERITY           = uuid.UUID("b325bfbec7be4ab88357139e652d2f6b")  # NOQA: E221
GPT_ROOT_S390_VERITY            = uuid.UUID("7ac63b47b25c463b8df8b4a94e6c90e1")  # NOQA: E221
GPT_ROOT_TILEGX_VERITY          = uuid.UUID("966061ec28e44b2eb4a51f0a825a1d84")  # NOQA: E221
GPT_ROOT_X86_64_VERITY          = uuid.UUID("2c7357edebd246d9aec123d437ec2bf5")  # NOQA: E221
GPT_ROOT_X86_VERITY             = uuid.UUID("d13c5d3bb5d1422ab29f9454fdc89d76")  # NOQA: E221

GPT_USR_ALPHA_VERITY            = uuid.UUID("8cce0d25c0d04a44bd8746331bf1df67")  # NOQA: E221
GPT_USR_ARC_VERITY              = uuid.UUID("fca0598cd88045918c164eda05c7347c")  # NOQA: E221
GPT_USR_ARM_VERITY              = uuid.UUID("c215d7517bcd4649be906627490a4c05")  # NOQA: E221
GPT_USR_ARM64_VERITY            = uuid.UUID("6e11a4e7fbca4dedb9e9e1a512bb664e")  # NOQA: E221
GPT_USR_IA64_VERITY             = uuid.UUID("6a491e033be745458e3883320e0ea880")  # NOQA: E221
GPT_USR_LOONGARCH64_VERITY      = uuid.UUID("f46b2c2659ae48f09106c50ed47f673d")  # NOQA: E221
GPT_USR_MIPS_LE_VERITY          = uuid.UUID("46b98d8db55c4e8faab337fca7f80752")  # NOQA: E221
GPT_USR_MIPS64_LE_VERITY        = uuid.UUID("3c3d61feb5f3414dbb718739a694a4ef")  # NOQA: E221
GPT_USR_PPC64LE_VERITY          = uuid.UUID("ee2b998321e8415386d9b6901a54d1ce")  # NOQA: E221
GPT_USR_PPC64_VERITY            = uuid.UUID("bdb528a5a259475fa87dda53fa736a07")  # NOQA: E221
GPT_USR_PPC_VERITY              = uuid.UUID("df765d00270e49e5bc75f47bb2118b09")  # NOQA: E221
GPT_USR_RISCV32_VERITY          = uuid.UUID("cb1ee4e38cd04136a0a4aa61a32e8730")  # NOQA: E221
GPT_USR_RISCV64_VERITY          = uuid.UUID("8f1056be9b0547c481d6be53128e5b54")  # NOQA: E221
GPT_USR_S390X_VERITY            = uuid.UUID("31741cc41a2a4111a581e00b447d2d06")  # NOQA: E221
GPT_USR_S390_VERITY             = uuid.UUID("b663c618e7bc4d6d90aa11b756bb1797")  # NOQA: E221
GPT_USR_TILEGX_VERITY           = uuid.UUID("2fb4bf5607fa42da81326b139f2026ae")  # NOQA: E221
GPT_USR_X86_64_VERITY           = uuid.UUID("77ff5f63e7b64633acf41565b864c0e6")  # NOQA: E221
GPT_USR_X86_VERITY              = uuid.UUID("8f461b0d14ee4e819aa9049b6fb97abd")  # NOQA: E221

GPT_ROOT_ALPHA_VERITY_SIG       = uuid.UUID("d46495b7a053414f80f7700c99921ef8")  # NOQA: E221
GPT_ROOT_ARC_VERITY_SIG         = uuid.UUID("143a70bacbd34f06919f6c05683a78bc")  # NOQA: E221
GPT_ROOT_ARM_VERITY_SIG         = uuid.UUID("42b0455feb11491d98d356145ba9d037")  # NOQA: E221
GPT_ROOT_ARM64_VERITY_SIG       = uuid.UUID("6db69de629f44758a7a5962190f00ce3")  # NOQA: E221
GPT_ROOT_IA64_VERITY_SIG        = uuid.UUID("e98b36ee32ba48829b120ce14655f46a")  # NOQA: E221
GPT_ROOT_LOONGARCH64_VERITY_SIG = uuid.UUID("5afb67ebecc84f85ae8eac1e7c50e7d0")  # NOQA: E221
GPT_ROOT_MIPS_LE_VERITY_SIG     = uuid.UUID("c919cc1f44564eff918cf75e94525ca5")  # NOQA: E221
GPT_ROOT_MIPS64_LE_VERITY_SIG   = uuid.UUID("904e58ef5c654a319c576af5fc7c5de7")  # NOQA: E221
GPT_ROOT_PPC64LE_VERITY_SIG     = uuid.UUID("d4a236e7e8734c07bf1dbf6cf7f1c3c6")  # NOQA: E221
GPT_ROOT_PPC64_VERITY_SIG       = uuid.UUID("f5e2c20c45b24ffabce92a60737e1aaf")  # NOQA: E221
GPT_ROOT_PPC_VERITY_SIG         = uuid.UUID("1b31b5aaadd9463ab2edbd467fc857e7")  # NOQA: E221
GPT_ROOT_RISCV32_VERITY_SIG     = uuid.UUID("3a112a7587294380b4cf764d79934448")  # NOQA: E221
GPT_ROOT_RISCV64_VERITY_SIG     = uuid.UUID("efe0f087ea8d4469821a4c2a96a8386a")  # NOQA: E221
GPT_ROOT_S390X_VERITY_SIG       = uuid.UUID("c80187a573a3491a901a017c3fa953e9")  # NOQA: E221
GPT_ROOT_S390_VERITY_SIG        = uuid.UUID("3482388e4254435aa241766a065f9960")  # NOQA: E221
GPT_ROOT_TILEGX_VERITY_SIG      = uuid.UUID("b367143997b04a5390f72d5a8f3ad47b")  # NOQA: E221
GPT_ROOT_X86_64_VERITY_SIG      = uuid.UUID("41092b059fc84523994f2def0408b176")  # NOQA: E221
GPT_ROOT_X86_VERITY_SIG         = uuid.UUID("5996fc05109c48de808b23fa0830b676")  # NOQA: E221

GPT_USR_ALPHA_VERITY_SIG        = uuid.UUID("5c6e1c76076a457aa0fef3b4cd21ce6e")  # NOQA: E221
GPT_USR_ARC_VERITY_SIG          = uuid.UUID("94f9a9a19971427aa40050cb297f0f35")  # NOQA: E221
GPT_USR_ARM_VERITY_SIG          = uuid.UUID("d7ff812f37d14902a810d76ba57b975a")  # NOQA: E221
GPT_USR_ARM64_VERITY_SIG        = uuid.UUID("c23ce4ff44bd4b00b2d4b41b3419e02a")  # NOQA: E221
GPT_USR_IA64_VERITY_SIG         = uuid.UUID("8de58bc22a43460db14ea76e4a17b47f")  # NOQA: E221
GPT_USR_LOONGARCH64_VERITY_SIG  = uuid.UUID("b024f315d330444c846144bbde524e99")  # NOQA: E221
GPT_USR_MIPS_LE_VERITY_SIG      = uuid.UUID("3e23ca0ba4bc4b4e80875ab6a26aa8a9")  # NOQA: E221
GPT_USR_MIPS64_LE_VERITY_SIG    = uuid.UUID("f2c2c7eeadcc4351b5c6ee9816b66e16")  # NOQA: E221
GPT_USR_PPC64LE_VERITY_SIG      = uuid.UUID("c8bfbd1e268e45218bbabf314c399557")  # NOQA: E221
GPT_USR_PPC64_VERITY_SIG        = uuid.UUID("0b888863d7f84d9e9766239fce4d58af")  # NOQA: E221
GPT_USR_PPC_VERITY_SIG          = uuid.UUID("7007891dd3714a8086a45cb875b9302e")  # NOQA: E221
GPT_USR_RISCV32_VERITY_SIG      = uuid.UUID("c3836a13313745bab583b16c50fe5eb4")  # NOQA: E221
GPT_USR_RISCV64_VERITY_SIG      = uuid.UUID("d2f9000a7a18453fb5cd4d32f77a7b32")  # NOQA: E221
GPT_USR_S390X_VERITY_SIG        = uuid.UUID("3f324816667b46ae86ee9b0c0c6c11b4")  # NOQA: E221
GPT_USR_S390_VERITY_SIG         = uuid.UUID("17440e4fa8d0467fa46e3912ae6ef2c5")  # NOQA: E221
GPT_USR_TILEGX_VERITY_SIG       = uuid.UUID("4ede75e26ccc4cc8b9c770334b087510")  # NOQA: E221
GPT_USR_X86_64_VERITY_SIG       = uuid.UUID("e7bb33fb06cf4e818273e543b413e2e2")  # NOQA: E221
GPT_USR_X86_VERITY_SIG          = uuid.UUID("974a71c0de4143c3be5d5c5ccd1ad2c0")  # NOQA: E221

GPT_ESP                         = uuid.UUID("c12a7328f81f11d2ba4b00a0c93ec93b")  # NOQA: E221
GPT_XBOOTLDR                    = uuid.UUID("bc13c2ff59e64262a352b275fd6f7172")  # NOQA: E221
GPT_SWAP                        = uuid.UUID("0657fd6da4ab43c484e50933c84b4f4f")  # NOQA: E221
GPT_HOME                        = uuid.UUID("933ac7e12eb44f13b8440e14e2aef915")  # NOQA: E221
GPT_SRV                         = uuid.UUID("3b8f842520e04f3b907f1a25a76f98e8")  # NOQA: E221
GPT_VAR                         = uuid.UUID("4d21b016b53445c2a9fb5c16e091fd2d")  # NOQA: E221
GPT_TMP                         = uuid.UUID("7ec6f5573bc54acab29316ef5df639d1")  # NOQA: E221
GPT_USER_HOME                   = uuid.UUID("773f91ef66d449b5bd83d683bf40ad16")  # NOQA: E221
GPT_LINUX_GENERIC               = uuid.UUID("0fc63daf848347728e793d69d8477de4")  # NOQA: E221

# Mkosi specific addition to support BIOS images
GPT_BIOS                        = uuid.UUID("2168614864496e6f744e656564454649")  # NOQA: E221


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
    "7":  "CAB44B996F27744E86127CDFB44269D04F2A6FD2",
    "8":  "4FFF1F04010DEDCAE203591D62AEC3DC6DF2196F",
    "9":  "4FFF1F04010DEDCAE203591D62AEC3DC6DF2196F",
    "10": "61A8ABE091FF9FBBF4B07709BF226FCC4EBFC273",
    "11": "AEE40C04E34560A71F043D7C1DC5C758D22E77F2",
    "12": "6BF178D28A789C74AC0DC63B9D1CC34857BBCCBA",
    "13": "8E5F73FF2A1817654D358FCA7EDC6AD6E8E40FDE",
    "14": "235C2936B4B70E61B373A020421CADDB97A1071F",
    "15": "25DBB54BDED70987F4C10042B4EBF579069C8460",
    "16": "05A912AC70457C3DBC82D352067F00B6A82BA4B7",
    "17": "CAC43FB774A4A673D81C5DE750E94C991ACA3465",
    "18": "7EFB8811DD11E380B679FCEDFF01125CDE7F38BD",
    "19": "CA81B2C85E4F4D4A1A3F723407477E65FB4B18E6",
    "20": "C7C9A9C89153F20183CE7CBA2EB161FA246110C1",
    "21": "6596B8FBABDA5227A9C5B59E89AD4E8795A43F54",
    "22": "C527EA07A9349B589C35E1BF11ADC0948E1431D5",
    "23": "EF45510680FB02326B045AFB32474CF834EC9CBA",
    "24": "5048BDBBA5E776E547B09CCC73BDE98381B46521",
    "25": "C437DCCD558A66A37D6F43724089D8F2FDB19C98",
    "26": "E641850B77DF435378D1D7E2812A6B4B64DAB85D",
    "27": "860E19B0AFA800A1751881A6F55E7430F5282EE4",
    "28": "128CF232A9371991C8A65695E08E7E629DB62FB1",
    "29": "5A03B4DD8254ECA02FDA1637A20AA56B429476B4",
    "30": "F1D8EC98F241AAF20DF69420EF3C111FCFC659B9",
    "31": "7D22D5867F2A4236474BF7B850CB390B3C3359C4",
    "32": "97A1AE57C3A2372CCA3A4ABA6C13026D12C944D0",
    "33": "963A2BEB02009608FE67EA4249FD77499570FF31",
    "34": "8C5BA6990BDB26E19F2A1A801161AE6945719A39",
    "35": "787EA6AE1147EEE56C40B30CDB4639719867C58F",
    "36": "53DED2CB922D8B8D9E63FD18999F7CBF38AB71F4",
}

def fedora_release_cmp(a: str, b: str) -> int:
    """Return negative if a<b, 0 if a==b, positive otherwise"""

    # This will throw ValueError on non-integer strings
    anum = 1000 if a == "rawhide" else int(a)
    bnum = 1000 if b == "rawhide" else int(b)
    return anum - bnum


# Debian calls their architectures differently, so when calling debootstrap we
# will have to map to their names
DEBIAN_ARCHITECTURES = {
    "x86_64": "amd64",
    "x86": "i386",
    "aarch64": "arm64",
    "armhfp": "armhf",
}


class GPTRootTypeTriplet(NamedTuple):
    root: uuid.UUID
    verity: uuid.UUID
    verity_sig: uuid.UUID


def gpt_root_native(arch: Optional[str], usr_only: bool = False) -> GPTRootTypeTriplet:
    """The type UUID for the native GPT root partition for the given architecture

    Returns a tuple of three UUIDs: for the root partition, for the
    matching verity partition, and for the matching Verity signature
    partition.
    """
    if arch is None:
        arch = platform.machine()

    if usr_only:
        if arch == "alpha":
            return GPTRootTypeTriplet(GPT_USR_ALPHA, GPT_USR_ALPHA_VERITY, GPT_USR_ALPHA_VERITY_SIG)
        elif arch == "arc":
            return GPTRootTypeTriplet(GPT_USR_ARC, GPT_USR_ARC_VERITY, GPT_USR_ARC_VERITY_SIG)
        elif arch.startswith("armv"):
            return GPTRootTypeTriplet(GPT_USR_ARM, GPT_USR_ARM_VERITY, GPT_USR_ARM_VERITY_SIG)
        elif arch == "aarch64":
            return GPTRootTypeTriplet(GPT_USR_ARM64, GPT_USR_ARM64_VERITY, GPT_USR_ARM64_VERITY_SIG)
        elif arch == "ia64":
            return GPTRootTypeTriplet(GPT_USR_IA64, GPT_USR_IA64_VERITY, GPT_USR_IA64_VERITY_SIG)
        elif arch == "loongarch64":
            return GPTRootTypeTriplet(GPT_USR_LOONGARCH64, GPT_USR_LOONGARCH64_VERITY, GPT_USR_LOONGARCH64_VERITY_SIG)
        elif arch == "mipsel":
            return GPTRootTypeTriplet(GPT_USR_MIPS_LE, GPT_USR_MIPS_LE_VERITY, GPT_USR_MIPS_LE_VERITY_SIG)
        elif arch == "mipsel64":
            return GPTRootTypeTriplet(GPT_USR_MIPS64_LE, GPT_USR_MIPS64_LE_VERITY, GPT_USR_MIPS64_LE_VERITY_SIG)
        elif arch == "ppc":
            return GPTRootTypeTriplet(GPT_USR_PPC, GPT_USR_PPC_VERITY, GPT_USR_PPC_VERITY_SIG)
        elif arch == "ppc64":
            return GPTRootTypeTriplet(GPT_USR_PPC64, GPT_USR_PPC64_VERITY, GPT_USR_PPC64_VERITY_SIG)
        elif arch == "ppc64le":
            return GPTRootTypeTriplet(GPT_USR_PPC64LE, GPT_USR_PPC64LE_VERITY, GPT_USR_PPC64LE_VERITY_SIG)
        elif arch == "riscv32":
            return GPTRootTypeTriplet(GPT_USR_RISCV32, GPT_USR_RISCV32_VERITY, GPT_USR_RISCV32_VERITY_SIG)
        elif arch == "riscv64":
            return GPTRootTypeTriplet(GPT_USR_RISCV64, GPT_USR_RISCV64_VERITY, GPT_USR_RISCV64_VERITY_SIG)
        elif arch == "s390":
            return GPTRootTypeTriplet(GPT_USR_S390, GPT_USR_S390_VERITY, GPT_USR_S390_VERITY_SIG)
        elif arch == "s390x":
            return GPTRootTypeTriplet(GPT_USR_S390X, GPT_USR_S390X_VERITY, GPT_USR_S390X_VERITY_SIG)
        elif arch == "tilegx":
            return GPTRootTypeTriplet(GPT_USR_TILEGX, GPT_USR_TILEGX_VERITY, GPT_USR_TILEGX_VERITY_SIG)
        elif arch in ("i386", "i486", "i586", "i686"):
            return GPTRootTypeTriplet(GPT_USR_X86, GPT_USR_X86_VERITY, GPT_USR_X86_VERITY_SIG)
        elif arch == "x86_64":
            return GPTRootTypeTriplet(GPT_USR_X86_64, GPT_USR_X86_64_VERITY, GPT_USR_X86_64_VERITY_SIG)
        else:
            die(f"Unknown architecture {arch}.")
    else:
        if arch == "alpha":
            return GPTRootTypeTriplet(GPT_ROOT_ALPHA, GPT_ROOT_ALPHA_VERITY, GPT_ROOT_ALPHA_VERITY_SIG)
        elif arch == "arc":
            return GPTRootTypeTriplet(GPT_ROOT_ARC, GPT_ROOT_ARC_VERITY, GPT_ROOT_ARC_VERITY_SIG)
        elif arch.startswith("armv"):
            return GPTRootTypeTriplet(GPT_ROOT_ARM, GPT_ROOT_ARM_VERITY, GPT_ROOT_ARM_VERITY_SIG)
        elif arch == "aarch64":
            return GPTRootTypeTriplet(GPT_ROOT_ARM64, GPT_ROOT_ARM64_VERITY, GPT_ROOT_ARM64_VERITY_SIG)
        elif arch == "ia64":
            return GPTRootTypeTriplet(GPT_ROOT_IA64, GPT_ROOT_IA64_VERITY, GPT_ROOT_IA64_VERITY_SIG)
        elif arch == "loongarch64":
            return GPTRootTypeTriplet(GPT_ROOT_LOONGARCH64, GPT_ROOT_LOONGARCH64_VERITY, GPT_ROOT_LOONGARCH64_VERITY_SIG)
        elif arch == "mipsel":
            return GPTRootTypeTriplet(GPT_ROOT_MIPS_LE, GPT_ROOT_MIPS_LE_VERITY, GPT_ROOT_MIPS_LE_VERITY_SIG)
        elif arch == "mipsel64":
            return GPTRootTypeTriplet(GPT_ROOT_MIPS64_LE, GPT_ROOT_MIPS64_LE_VERITY, GPT_ROOT_MIPS64_LE_VERITY_SIG)
        elif arch == "ppc":
            return GPTRootTypeTriplet(GPT_ROOT_PPC, GPT_ROOT_PPC_VERITY, GPT_ROOT_PPC_VERITY_SIG)
        elif arch == "ppc64":
            return GPTRootTypeTriplet(GPT_ROOT_PPC64, GPT_ROOT_PPC64_VERITY, GPT_ROOT_PPC64_VERITY_SIG)
        elif arch == "ppc64le":
            return GPTRootTypeTriplet(GPT_ROOT_PPC64LE, GPT_ROOT_PPC64LE_VERITY, GPT_ROOT_PPC64LE_VERITY_SIG)
        elif arch == "riscv32":
            return GPTRootTypeTriplet(GPT_ROOT_RISCV32, GPT_ROOT_RISCV32_VERITY, GPT_ROOT_RISCV32_VERITY_SIG)
        elif arch == "riscv64":
            return GPTRootTypeTriplet(GPT_ROOT_RISCV64, GPT_ROOT_RISCV64_VERITY, GPT_ROOT_RISCV64_VERITY_SIG)
        elif arch == "s390":
            return GPTRootTypeTriplet(GPT_ROOT_S390, GPT_ROOT_S390_VERITY, GPT_ROOT_S390_VERITY_SIG)
        elif arch == "s390x":
            return GPTRootTypeTriplet(GPT_ROOT_S390X, GPT_ROOT_S390X_VERITY, GPT_ROOT_S390X_VERITY_SIG)
        elif arch == "tilegx":
            return GPTRootTypeTriplet(GPT_ROOT_TILEGX, GPT_ROOT_TILEGX_VERITY, GPT_ROOT_TILEGX_VERITY_SIG)
        elif arch in ("i386", "i486", "i586", "i686"):
            return GPTRootTypeTriplet(GPT_ROOT_X86, GPT_ROOT_X86_VERITY, GPT_ROOT_X86_VERITY_SIG)
        elif arch == "x86_64":
            return GPTRootTypeTriplet(GPT_ROOT_X86_64, GPT_ROOT_X86_64_VERITY, GPT_ROOT_X86_64_VERITY_SIG)
        else:
            die(f"Unknown architecture {arch}.")


def roothash_suffix(usr_only: bool = False) -> str:
    if usr_only:
        return ".usrhash"

    return ".roothash"


def roothash_p7s_suffix(usr_only: bool = False) -> str:
    return roothash_suffix(usr_only) + ".p7s"


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


def _IOC(dir_rw: int, type_drv: int, nr: int, argtype: str) -> int:
    size = {"int": 4, "size_t": 8}[argtype]
    return dir_rw << _IOC_DIRSHIFT | type_drv << _IOC_TYPESHIFT | nr << _IOC_NRSHIFT | size << _IOC_SIZESHIFT


def _IOW(type_drv: int, nr: int, size: str) -> int:
    return _IOC(_IOC_WRITE, type_drv, nr, size)


FICLONE = _IOW(0x94, 9, "int")


@contextlib.contextmanager
def open_close(path: PathString, flags: int, mode: int = 0o664) -> Iterator[int]:
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
        # While mypy handles this correctly, Pyright doesn't yet.
        shutil.copyfileobj(open(oldfd, "rb", closefd=False), cast(Any, open(newfd, "wb", closefd=False)))


def copy_file_object(oldobject: BinaryIO, newobject: BinaryIO) -> None:
    try:
        _reflink(oldobject.fileno(), newobject.fileno())
    except OSError as e:
        if e.errno not in {errno.EXDEV, errno.EOPNOTSUPP}:
            raise
        shutil.copyfileobj(oldobject, newobject)


def copy_file(oldpath: PathString, newpath: PathString) -> None:
    oldpath = Path(oldpath)
    newpath = Path(newpath)

    if oldpath.is_symlink():
        src = os.readlink(oldpath)  # TODO: use oldpath.readlink() with python3.9+
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


def copy_path(oldpath: PathString, newpath: Path) -> None:
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
    shutil.copystat(oldpath, newpath, follow_symlinks=True)


@complete_step("Detaching namespace")
def init_namespace(args: MkosiArgs) -> None:
    unshare(CLONE_NEWNS)
    run(["mount", "--make-rslave", "/"])


def setup_workspace(args: MkosiArgs) -> TempDir:
    with complete_step("Setting up temporary workspace.", "Temporary workspace set up in {.name}") as output:
        if args.workspace_dir is not None:
            d = tempfile.TemporaryDirectory(dir=args.workspace_dir, prefix="")
        elif args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
            d = tempfile.TemporaryDirectory(dir=args.output.parent, prefix=".mkosi-")
        else:
            d = tempfile.TemporaryDirectory(dir=tmp_dir(), prefix="mkosi-")
        output.append(d)

    return d


def btrfs_subvol_create(path: Path, mode: int = 0o755) -> None:
    with set_umask(~mode & 0o7777):
        run(["btrfs", "subvol", "create", path])


def btrfs_subvol_delete(path: Path) -> None:
    # Extract the path of the subvolume relative to the filesystem
    c = run(["btrfs", "subvol", "show", path], stdout=PIPE, stderr=DEVNULL, text=True)
    subvol_path = c.stdout.splitlines()[0]
    # Make the subvolume RW again if it was set RO by btrfs_subvol_delete
    run(["btrfs", "property", "set", path, "ro", "false"])
    # Recursively delete the direct children of the subvolume
    c = run(["btrfs", "subvol", "list", "-o", path], stdout=PIPE, stderr=DEVNULL, text=True)
    for line in c.stdout.splitlines():
        if not line:
            continue
        child_subvol_path = line.split(" ", 8)[-1]
        child_path = path / cast(str, os.path.relpath(child_subvol_path, subvol_path))
        btrfs_subvol_delete(child_path)
    # Delete the subvolume now that all its descendants have been deleted
    run(["btrfs", "subvol", "delete", path], stdout=DEVNULL, stderr=DEVNULL)


def btrfs_subvol_make_ro(path: Path, b: bool = True) -> None:
    run(["btrfs", "property", "set", path, "ro", "true" if b else "false"])


@contextlib.contextmanager
def btrfs_forget_stale_devices(args: MkosiArgs) -> Iterator[None]:
    # When using cached images (-i), mounting btrfs images would sometimes fail
    # with EEXIST. This is likely because a stale device is leftover somewhere
    # from the previous run. To fix this, we make sure to always clean up stale
    # btrfs devices after unmounting the image.
    try:
        yield
    finally:
        if args.output_format.is_btrfs() and shutil.which("btrfs"):
            run(["btrfs", "device", "scan", "-u"])


def is_generated_root(args: Union[argparse.Namespace, MkosiArgs]) -> bool:
    """Returns whether this configuration means we need to generate a file system from a prepared tree

    This is needed for anything squashfs and when root minimization is required."""
    return args.minimize or args.output_format.is_squashfs() or args.usr_only


def disable_cow(path: PathString) -> None:
    """Disable copy-on-write if applicable on filesystem"""

    run(["chattr", "+C", path], stdout=DEVNULL, stderr=DEVNULL, check=False)


def root_partition_description(
    args: Optional[MkosiArgs],
    suffix: Optional[str] = None,
    image_id: Optional[str] = None,
    image_version: Optional[str] = None,
    usr_only: Optional[bool] = False,
) -> str:

    # Support invocation with "args" or with separate parameters (which is useful when invoking it before we allocated a MkosiArgs object)
    if args is not None:
        image_id = args.image_id
        image_version = args.image_version
        usr_only = args.usr_only

    # We implement two naming regimes for the partitions. If image_id
    # is specified we assume that there's a naming and maybe
    # versioning regime for the image in place, and thus use that to
    # generate the image. If not we pick descriptive names instead.

    # If an image id is specified, let's generate the root, /usr/ or
    # verity partition name from it, in a uniform way for all three
    # types. The image ID is after all a great way to identify what is
    # *in* the image, while the partition type UUID indicates what
    # *kind* of data it is. If we also have a version we include it
    # too. The latter is particularly useful for systemd's image
    # dissection logic, which will always pick the newest root or
    # /usr/ partition if multiple exist.
    if image_id is not None:
        if image_version is not None:
            return f"{image_id}_{image_version}"
        else:
            return image_id

    # If no image id is specified we just return a descriptive string
    # for the partition.
    prefix = "System Resources" if usr_only else "Root"
    return prefix + ' ' + (suffix if suffix is not None else 'Partition')


def initialize_partition_table(args: MkosiArgs) -> None:
    if args.partition_table is not None:
        return

    if not args.output_format.is_disk():
        return

    table = PartitionTable(first_lba=args.gpt_first_lba)
    no_btrfs = args.output_format != OutputFormat.gpt_btrfs

    for condition, label, size, type_uuid, name, read_only in (
            (args.bootable and "uefi" in args.boot_protocols,
             PartitionIdentifier.esp, args.esp_size, GPT_ESP, "ESP System Partition", False),
            (args.bootable and "bios" in args.boot_protocols,
             PartitionIdentifier.bios, BIOS_PARTITION_SIZE, GPT_BIOS, "BIOS Boot Partition", False),
            (args.xbootldr_size is not None,
             PartitionIdentifier.xbootldr, args.xbootldr_size, GPT_XBOOTLDR, "Boot Loader Partition", False),
            (args.swap_size is not None,
             PartitionIdentifier.swap, args.swap_size, GPT_SWAP, "Swap Partition", False),
            (no_btrfs and args.home_size is not None,
             PartitionIdentifier.home, args.home_size, GPT_HOME, "Home Partition", False),
            (no_btrfs and args.srv_size is not None,
             PartitionIdentifier.srv, args.srv_size, GPT_SRV, "Server Data Partition", False),
            (no_btrfs and args.var_size is not None,
             PartitionIdentifier.var, args.var_size, GPT_VAR, "Variable Data Partition", False),
            (no_btrfs and args.tmp_size is not None,
             PartitionIdentifier.tmp, args.tmp_size, GPT_TMP, "Temporary Data Partition", False),
            (not is_generated_root(args),
             PartitionIdentifier.root, args.root_size,
             gpt_root_native(args.architecture, args.usr_only).root,
             root_partition_description(args),
             args.read_only)):

        if condition and size is not None:
            table.add(label, size, type_uuid, name, read_only=read_only)

    args.partition_table = table


def create_image(args: MkosiArgs, for_cache: bool) -> Optional[BinaryIO]:
    initialize_partition_table(args)
    if args.partition_table is None:
        return None

    with complete_step("Creating image with partition table…",
                       "Created image with partition table as {.name}") as output:

        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(prefix=".mkosi-", delete=not for_cache, dir=args.output.parent),
        )
        output.append(f)
        disable_cow(f.name)
        disk_size = args.partition_table.disk_size()
        f.truncate(disk_size)

        if args.partition_table.partitions:
            args.partition_table.run_sfdisk(f.name)

    return f


def refresh_partition_table(args: MkosiArgs, f: BinaryIO) -> None:
    initialize_partition_table(args)
    if args.partition_table is None:
        return

    # Let's refresh all UUIDs and labels to match the new build. This
    # is called whenever we reuse a cached image, to ensure that the
    # UUIDs/labels of partitions are generated the same way as for
    # non-cached builds. Note that we refresh the UUIDs/labels simply
    # by invoking sfdisk again. If the build parameters didn't change
    # this should have the effect that offsets and sizes should remain
    # identical, and we thus only update the UUIDs and labels.
    #
    # FIXME: One of those days we should generate the UUIDs as hashes
    # of the used configuration, so that they remain stable as the
    # configuration is identical.

    with complete_step("Refreshing partition table…", "Refreshed partition table."):
        if args.partition_table.partitions:
            args.partition_table.run_sfdisk(f.name, quiet=True)


def refresh_file_system(args: MkosiArgs, dev: Optional[Path], cached: bool) -> None:

    if dev is None:
        return
    if not cached:
        return

    # Similar to refresh_partition_table() but refreshes the UUIDs of
    # the file systems themselves. We want that build artifacts from
    # cached builds are as similar as possible to those from uncached
    # builds, and hence we want to randomize UUIDs explicitly like
    # they are for uncached builds. This is particularly relevant for
    # btrfs since it prohibits mounting multiple file systems at the
    # same time that carry the same UUID.
    #
    # FIXME: One of those days we should generate the UUIDs as hashes
    # of the used configuration, so that they remain stable as the
    # configuration is identical.

    with complete_step(f"Refreshing file system {dev}…"):
        if args.output_format == OutputFormat.gpt_btrfs:
            # We use -M instead of -m here, for compatibility with
            # older btrfs, where -M didn't exist yet.
            run(["btrfstune", "-M", str(uuid.uuid4()), dev])
        elif args.output_format == OutputFormat.gpt_ext4:
            # We connect stdin to /dev/null since tune2fs otherwise
            # asks an unnecessary safety question on stdin, and we
            # don't want that, our script doesn't operate on essential
            # file systems anyway, but just our build images.
            run(["tune2fs", "-U", "random", dev], stdin=subprocess.DEVNULL)
        elif args.output_format == OutputFormat.gpt_xfs:
            run(["xfs_admin", "-U", "generate", dev])


def copy_image_temporary(src: Path, dir: Path) -> BinaryIO:
    with src.open("rb") as source:
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


def copy_file_temporary(src: PathString, dir: Path) -> BinaryIO:
    with open(src, "rb") as source:
        f = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=dir))
        copy_file_object(source, f)
        return f


def reuse_cache_image(
    args: MkosiArgs, do_run_build_script: bool, for_cache: bool
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

    with complete_step(f"Basing off cached image {fname}", "Copied cached image as {.name}") as output:

        try:
            f = copy_image_temporary(src=fname, dir=args.output.parent)
        except FileNotFoundError:
            return None, False

        output.append(f)

    return f, True


@contextlib.contextmanager
def attach_image_loopback(image: Optional[BinaryIO]) -> Iterator[Optional[Path]]:
    if image is None:
        yield None
        return

    with complete_step(f"Attaching {image.name} as loopback…", "Attached {}") as output:
        c = run(["losetup", "--find", "--show", "--partscan", image.name],
                stdout=PIPE,
                text=True)
        loopdev = Path(c.stdout.strip())
        output += [loopdev]

    try:
        yield loopdev
    finally:
        with complete_step(f"Detaching {loopdev}"):
            run(["losetup", "--detach", loopdev])

@contextlib.contextmanager
def attach_base_image(base_image: Optional[Path]) -> Iterator[Optional[Path]]:
    """Context manager that attaches/detaches the base image directory or device"""

    if base_image is None:
        yield None
        return

    with complete_step(f"Using {base_image} as the base image"):
        if base_image.is_dir():
            yield base_image
        else:
            with base_image.open('rb') as f, \
                 attach_image_loopback(f) as loopdev:

                yield loopdev


def prepare_swap(args: MkosiArgs, loopdev: Optional[Path], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return
    part = args.get_partition(PartitionIdentifier.swap)
    if not part:
        return

    with complete_step("Formatting swap partition"):
        run(["mkswap", "-Lswap", part.blockdev(loopdev)])


def prepare_esp(args: MkosiArgs, loopdev: Optional[Path], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return
    part = args.get_partition(PartitionIdentifier.esp)
    if not part:
        return

    with complete_step("Formatting ESP partition"):
        run(["mkfs.fat", "-nEFI", "-F32", part.blockdev(loopdev)])


def prepare_xbootldr(args: MkosiArgs, loopdev: Optional[Path], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return

    part = args.get_partition(PartitionIdentifier.xbootldr)
    if not part:
        return

    with complete_step("Formatting XBOOTLDR partition"):
        run(["mkfs.fat", "-nXBOOTLDR", "-F32", part.blockdev(loopdev)])


def mkfs_ext4_cmd(label: str, mount: PathString) -> List[str]:
    return ["mkfs.ext4", "-I", "256", "-L", label, "-M", str(mount)]


def mkfs_xfs_cmd(label: str) -> List[str]:
    return ["mkfs.xfs", "-n", "ftype=1", "-L", label]


def mkfs_btrfs_cmd(label: str) -> List[str]:
    return ["mkfs.btrfs", "-L", label, "-d", "single", "-m", "single"]


def mkfs_generic(args: MkosiArgs, label: str, mount: PathString, dev: Path) -> None:
    cmdline: Sequence[PathString]

    if args.output_format == OutputFormat.gpt_btrfs:
        cmdline = mkfs_btrfs_cmd(label)
    elif args.output_format == OutputFormat.gpt_xfs:
        cmdline = mkfs_xfs_cmd(label)
    else:
        cmdline = mkfs_ext4_cmd(label, mount)

    if args.output_format == OutputFormat.gpt_ext4:
        if (args.distribution in (Distribution.centos, Distribution.centos_epel) and
            is_older_than_centos8(args.release)):

            # e2fsprogs in centos7 is too old and doesn't support this feature
            cmdline += ["-O", "^metadata_csum"]

        if args.architecture in ("x86_64", "aarch64"):
            # enable 64bit filesystem feature on supported architectures
            cmdline += ["-O", "64bit"]

    run([*cmdline, dev])


def luks_format(dev: Path, passphrase: Dict[str, str]) -> None:
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


def luks_format_root(
    args: MkosiArgs,
    loopdev: Path,
    do_run_build_script: bool,
    cached: bool,
    inserting_generated_root: bool = False,
) -> None:
    if args.encrypt != "all":
        return
    part = args.get_partition(PartitionIdentifier.root)
    if not part:
        return
    if is_generated_root(args) and not inserting_generated_root:
        return
    if do_run_build_script:
        return
    if cached:
        return
    assert args.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), args.passphrase)


def luks_format_home(args: MkosiArgs, loopdev: Path, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    part = args.get_partition(PartitionIdentifier.home)
    if not part:
        return
    if do_run_build_script:
        return
    if cached:
        return
    assert args.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), args.passphrase)


def luks_format_srv(args: MkosiArgs, loopdev: Path, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    part = args.get_partition(PartitionIdentifier.srv)
    if not part:
        return
    if do_run_build_script:
        return
    if cached:
        return
    assert args.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), args.passphrase)


def luks_format_var(args: MkosiArgs, loopdev: Path, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    part = args.get_partition(PartitionIdentifier.var)
    if not part:
        return
    if do_run_build_script:
        return
    if cached:
        return
    assert args.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), args.passphrase)


def luks_format_tmp(args: MkosiArgs, loopdev: Path, do_run_build_script: bool, cached: bool) -> None:
    if args.encrypt is None:
        return
    part = args.get_partition(PartitionIdentifier.tmp)
    if not part:
        return
    if do_run_build_script:
        return
    if cached:
        return
    assert args.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), args.passphrase)


@contextlib.contextmanager
def luks_open(part: Partition, loopdev: Path, passphrase: Dict[str, str]) -> Iterator[Path]:
    name = str(uuid.uuid4())
    dev = part.blockdev(loopdev)

    with complete_step(f"Setting up LUKS on {part.description}…"):
        if passphrase["type"] == "stdin":
            passphrase_content = (passphrase["content"] + "\n").encode("utf-8")
            run(["cryptsetup", "open", "--type", "luks", dev, name], input=passphrase_content)
        else:
            assert passphrase["type"] == "file"
            run(["cryptsetup", "--key-file", passphrase["content"], "open", "--type", "luks", dev, name])

    path = Path("/dev/mapper", name)

    try:
        yield path
    finally:
        with complete_step(f"Closing LUKS on {part.description}"):
            run(["cryptsetup", "close", path])


def luks_setup_root(
    args: MkosiArgs, loopdev: Path, do_run_build_script: bool, inserting_generated_root: bool = False
) -> ContextManager[Optional[Path]]:
    if args.encrypt != "all":
        return contextlib.nullcontext()
    part = args.get_partition(PartitionIdentifier.root)
    if not part:
        return contextlib.nullcontext()
    if is_generated_root(args) and not inserting_generated_root:
        return contextlib.nullcontext()
    if do_run_build_script:
        return contextlib.nullcontext()
    assert args.passphrase is not None

    return luks_open(part, loopdev, args.passphrase)


def luks_setup_home(
    args: MkosiArgs, loopdev: Path, do_run_build_script: bool
) -> ContextManager[Optional[Path]]:
    if args.encrypt is None:
        return contextlib.nullcontext()
    part = args.get_partition(PartitionIdentifier.home)
    if not part:
        return contextlib.nullcontext()
    if do_run_build_script:
        return contextlib.nullcontext()
    assert args.passphrase is not None

    return luks_open(part, loopdev, args.passphrase)


def luks_setup_srv(
    args: MkosiArgs, loopdev: Path, do_run_build_script: bool
) -> ContextManager[Optional[Path]]:
    if args.encrypt is None:
        return contextlib.nullcontext()
    part = args.get_partition(PartitionIdentifier.srv)
    if not part:
        return contextlib.nullcontext()
    if do_run_build_script:
        return contextlib.nullcontext()
    assert args.passphrase is not None

    return luks_open(part, loopdev, args.passphrase)


def luks_setup_var(
    args: MkosiArgs, loopdev: Path, do_run_build_script: bool
) -> ContextManager[Optional[Path]]:
    if args.encrypt is None:
        return contextlib.nullcontext()
    part = args.get_partition(PartitionIdentifier.var)
    if not part:
        return contextlib.nullcontext()
    if do_run_build_script:
        return contextlib.nullcontext()
    assert args.passphrase is not None

    return luks_open(part, loopdev, args.passphrase)


def luks_setup_tmp(
    args: MkosiArgs, loopdev: Path, do_run_build_script: bool
) -> ContextManager[Optional[Path]]:
    if args.encrypt is None:
        return contextlib.nullcontext()
    part = args.get_partition(PartitionIdentifier.tmp)
    if not part:
        return contextlib.nullcontext()
    if do_run_build_script:
        return contextlib.nullcontext()
    assert args.passphrase is not None

    return luks_open(part, loopdev, args.passphrase)


class LuksSetupOutput(NamedTuple):
    root: Optional[Path]
    home: Optional[Path]
    srv: Optional[Path]
    var: Optional[Path]
    tmp: Optional[Path]

    @classmethod
    def empty(cls) -> LuksSetupOutput:
        return cls(None, None, None, None, None)

    def without_generated_root(self, args: MkosiArgs) -> LuksSetupOutput:
        "A copy of self with .root optionally supressed"
        return LuksSetupOutput(
            None if is_generated_root(args) else self.root,
            *self[1:],
        )


@contextlib.contextmanager
def luks_setup_all(
    args: MkosiArgs, loopdev: Optional[Path], do_run_build_script: bool
) -> Iterator[LuksSetupOutput]:
    if not args.output_format.is_disk():
        yield LuksSetupOutput.empty()
        return

    assert loopdev is not None
    assert args.partition_table is not None

    with luks_setup_root(args, loopdev, do_run_build_script) as root, \
         luks_setup_home(args, loopdev, do_run_build_script) as home, \
         luks_setup_srv(args, loopdev, do_run_build_script) as srv, \
         luks_setup_var(args, loopdev, do_run_build_script) as var, \
         luks_setup_tmp(args, loopdev, do_run_build_script) as tmp:

        yield LuksSetupOutput(
            root or args.partition_table.partition_path(PartitionIdentifier.root, loopdev),
            home or args.partition_table.partition_path(PartitionIdentifier.home, loopdev),
            srv or args.partition_table.partition_path(PartitionIdentifier.srv, loopdev),
            var or args.partition_table.partition_path(PartitionIdentifier.var, loopdev),
            tmp or args.partition_table.partition_path(PartitionIdentifier.tmp, loopdev))


def prepare_root(args: MkosiArgs, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if is_generated_root(args):
        return
    if cached:
        return

    label, path = ("usr", "/usr") if args.usr_only else ("root", "/")
    with complete_step(f"Formatting {label} partition…"):
        mkfs_generic(args, label, path, dev)


def prepare_home(args: MkosiArgs, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting home partition…"):
        mkfs_generic(args, "home", "/home", dev)


def prepare_srv(args: MkosiArgs, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting server data partition…"):
        mkfs_generic(args, "srv", "/srv", dev)


def prepare_var(args: MkosiArgs, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting variable data partition…"):
        mkfs_generic(args, "var", "/var", dev)


def prepare_tmp(args: MkosiArgs, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting temporary data partition…"):
        mkfs_generic(args, "tmp", "/var/tmp", dev)


def stat_is_whiteout(st: os.stat_result) -> bool:
    return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0


def delete_whiteout_files(path: Path) -> None:
    """Delete any char(0,0) device nodes underneath @path

    Overlayfs uses such files to mark "whiteouts" (files present in
    the lower layers, but removed in the upper one).
    """

    with complete_step("Removing overlay whiteout files…"):
        for entry in cast(Iterator[os.DirEntry[str]], scandir_recursive(path)):
            if stat_is_whiteout(entry.stat(follow_symlinks=False)):
                os.unlink(entry.path)


def do_mount(
        what: PathString,
        where: Path,
        options: Sequence[str] = (),
        type: Optional[str] = None,
        read_only: bool = False,
) -> None:
    os.makedirs(where, 0o755, True)

    if read_only:
        options = ["ro", *options]

    cmd: List[PathString] = ["mount", "-n", what, where]

    if type:
        cmd += ["-t", type]

    if options:
        cmd += ["-o", ",".join(options)]

    run(cmd)


def mount_loop(args: MkosiArgs, dev: Path, where: Path, read_only: bool = False) -> None:
    options = []
    if not args.output_format.is_squashfs():
        options += ["discard"]

    compress = should_compress_fs(args)
    if compress and args.output_format == OutputFormat.gpt_btrfs and where.name not in {"efi", "boot"}:
        options += ["compress" if compress is True else f"compress={compress}"]

    do_mount(dev, where, options, read_only=read_only)


def mount_bind(what: Path, where: Optional[Path] = None) -> Path:
    if where is None:
        where = what

    os.makedirs(what, 0o755, True)
    os.makedirs(where, 0o755, True)
    run(["mount", "--bind", what, where])
    return where


def mount_tmpfs(where: Path) -> None:
    do_mount("tmpfs", where, type="tmpfs")


def mount_overlay(
    args: MkosiArgs,
    base_image: Path,  # the path to the mounted base image root
    root: Path,        # the path to the destination image root
    read_only: bool = False,
) -> Tuple[Path, TempDir]:
    """Set up the overlay mount on `root` with `base_image` as the lower layer.

    Sadly the overlay cannot be mounted onto the root directly, because the
    workdir must be on the same filesystem as "upperdir", but cannot be its
    subdirectory. Thus, we set up the overlay and then bind-mount the overlay
    structure into the expected location.
    """

    workdir = tempfile.TemporaryDirectory(dir=root, prefix='overlayfs-workdir')
    realroot = root / 'mkosi-real-root'

    options = [f'lowerdir={base_image}',
               f'upperdir={realroot}',
               f'workdir={workdir.name}']

    do_mount("overlay", realroot, options, type="overlay", read_only=read_only)
    mount_bind(realroot, root)
    return realroot, workdir


@complete_step("Cleaning up overlayfs")
def clean_up_overlay(root: Path, realroot: Path, workdir: TempDir) -> None:
    """Destroy the overlayfs structure set up by `mount_overlay`.

    When this function returns, the contents of the root file system have been
    moved into root, and `realroot` and `workdir` are gone.

    If `realroot` is set, it means we mounted `root` twice: the first mount is
    the overlayfs mount, and the second is a bind-mount to adjust the location
    one level up. Thus we need unmount twice too; after the first unmount here,
    the image remains mounted at `root`.
    """

    umount(root)
    umount(realroot)

    workdir.cleanup()

    # Let's now move the contents of realroot into root
    for entry in os.scandir(realroot):
        os.rename(realroot / entry.name, root / entry.name)
    realroot.rmdir()

    delete_whiteout_files(root)


@contextlib.contextmanager
def mount_image(
    args: MkosiArgs,
    root: Path,
    base_image: Optional[Path],  # the path to the mounted base image root
    loopdev: Optional[Path],
    image: LuksSetupOutput,
    root_read_only: bool = False,
) -> Iterator[None]:
    with complete_step("Mounting image…"):

        realroot: Optional[Path] = None
        workdir: Optional[TempDir] = None

        if base_image is not None:
            mount_bind(root)
            realroot, workdir = mount_overlay(args, base_image, root, root_read_only)

        elif image.root is not None:
            if args.usr_only:
                # In UsrOnly mode let's have a bind mount at the top so that umount --recursive works nicely later
                mount_bind(root)
                mount_loop(args, image.root, root / "usr", root_read_only)
            else:
                mount_loop(args, image.root, root, root_read_only)
        else:
            # always have a root of the tree as a mount point so we can
            # recursively unmount anything that ends up mounted there
            mount_bind(root)

        if image.home is not None:
            mount_loop(args, image.home, root / "home")

        if image.srv is not None:
            mount_loop(args, image.srv, root / "srv")

        if image.var is not None:
            mount_loop(args, image.var, root / "var")

        if image.tmp is not None:
            mount_loop(args, image.tmp, root / "var/tmp")

        if loopdev is not None:
            assert args.partition_table is not None
            path = args.partition_table.partition_path(PartitionIdentifier.esp, loopdev)

            if path:
                mount_loop(args, path, root / "efi")

            path = args.partition_table.partition_path(PartitionIdentifier.xbootldr, loopdev)
            if path:
                mount_loop(args, path, root / "boot")

        # Make sure /tmp and /run are not part of the image
        mount_tmpfs(root / "run")
        mount_tmpfs(root / "tmp")

    try:
        yield
    finally:
        if realroot is not None:
            assert workdir is not None
            clean_up_overlay(root, realroot, workdir)

        with complete_step("Unmounting image"):
            umount(root)


def install_etc_locale(args: MkosiArgs, root: Path, cached: bool) -> None:
    if cached:
        return

    etc_locale = root / "etc/locale.conf"

    try:
        etc_locale.unlink()
    except FileNotFoundError:
        pass

    # Let's ensure we use a UTF-8 locale everywhere.
    etc_locale.write_text("LANG=C.UTF-8\n")

    # Debian/Ubuntu use a different path to store the locale so let's make sure that path is a symlink to
    # etc/locale.conf.
    if args.distribution in (Distribution.debian, Distribution.ubuntu):
        try:
            root.joinpath("etc/default/locale").unlink()
        except FileNotFoundError:
            pass
        root.joinpath("etc/default/locale").symlink_to("../locale.conf")


def install_etc_hostname(args: MkosiArgs, root: Path, cached: bool) -> None:
    if cached:
        return

    etc_hostname = root / "etc/hostname"

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
            etc_hostname.write_text(args.hostname + "\n")


@contextlib.contextmanager
def mount_api_vfs(args: MkosiArgs, root: Path) -> Iterator[None]:
    subdirs = ("proc", "dev", "sys")

    with complete_step("Mounting API VFS"):
        for subdir in subdirs:
            mount_bind(Path("/") / subdir, root / subdir)
    try:
        yield
    finally:
        with complete_step("Unmounting API VFS"):
            for subdir in subdirs:
                umount(root / subdir)


@contextlib.contextmanager
def mount_cache(args: MkosiArgs, root: Path) -> Iterator[None]:
    if args.cache_path is None:
        yield
        return

    caches = []

    # We can't do this in mount_image() yet, as /var itself might have to be created as a subvolume first
    with complete_step("Mounting Package Cache"):
        if args.distribution in (Distribution.fedora, Distribution.mageia, Distribution.openmandriva):
            caches = [mount_bind(args.cache_path, root / "var/cache/dnf")]
        elif args.distribution in (
            Distribution.centos,
            Distribution.centos_epel,
            Distribution.rocky,
            Distribution.rocky_epel,
            Distribution.alma,
            Distribution.alma_epel,
        ):
            # We mount both the YUM and the DNF cache in this case, as
            # YUM might just be redirected to DNF even if we invoke
            # the former
            caches = [
                mount_bind(args.cache_path / "yum", root / "var/cache/yum"),
                mount_bind(args.cache_path / "dnf", root / "var/cache/dnf"),
            ]
        elif args.distribution in (Distribution.debian, Distribution.ubuntu):
            caches = [mount_bind(args.cache_path, root / "var/cache/apt/archives")]
        elif args.distribution == Distribution.arch:
            caches = [mount_bind(args.cache_path, root / "var/cache/pacman/pkg")]
        elif args.distribution == Distribution.gentoo:
            caches = [mount_bind(args.cache_path, root / "var/cache/binpkgs")]
        elif args.distribution == Distribution.opensuse:
            caches = [mount_bind(args.cache_path, root / "var/cache/zypp/packages")]
        elif args.distribution == Distribution.photon:
            caches = [mount_bind(args.cache_path / "tdnf", root / "var/cache/tdnf")]
    try:
        yield
    finally:
        with complete_step("Unmounting Package Cache"):
            for d in caches:  # NOQA: E501
                umount(d)


def umount(where: Path) -> None:
    run(["umount", "--recursive", "-n", where])


def configure_dracut(args: MkosiArgs, packages: Set[str], root: Path) -> None:
    if "dracut" not in packages:
        return

    dracut_dir = root / "etc/dracut.conf.d"
    dracut_dir.mkdir(mode=0o755)

    dracut_dir.joinpath('30-mkosi-hostonly.conf').write_text(
        f'hostonly={yes_no(args.hostonly_initrd)}\n'
        'hostonly_default_device=no\n'
    )

    dracut_dir.joinpath("30-mkosi-qemu.conf").write_text('add_dracutmodules+=" qemu "\n')

    with dracut_dir.joinpath("30-mkosi-systemd-extras.conf").open("w") as f:
        for extra in DRACUT_SYSTEMD_EXTRAS:
            f.write(f'install_optional_items+=" {extra} "\n')

    if args.hostonly_initrd:
        dracut_dir.joinpath("30-mkosi-filesystem.conf").write_text(
            f'filesystems+=" {(args.output_format.needed_kernel_module())} "\n'
        )

    if args.get_partition(PartitionIdentifier.esp):
        # These distros need uefi_stub configured explicitly for dracut to find the systemd-boot uefi stub.
        if args.distribution in (Distribution.ubuntu,
                                 Distribution.debian,
                                 Distribution.mageia,
                                 Distribution.openmandriva,
                                 Distribution.gentoo):
            dracut_dir.joinpath("30-mkosi-uefi-stub.conf").write_text(
                "uefi_stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub\n"
            )

        # efivarfs must be present in order to GPT root discovery work
        dracut_dir.joinpath("30-mkosi-efivarfs.conf").write_text(
            '[[ $(modinfo -k "$kernel" -F filename efivarfs 2>/dev/null) == /* ]] && add_drivers+=" efivarfs "\n'
        )


def prepare_tree_root(args: MkosiArgs, root: Path) -> None:
    if args.output_format == OutputFormat.subvolume and not is_generated_root(args):
        with complete_step("Setting up OS tree root…"):
            btrfs_subvol_create(root)


def root_home(args: MkosiArgs, root: Path) -> Path:

    # If UsrOnly= is turned on the /root/ directory (i.e. the root
    # user's home directory) is not persistent (after all everything
    # outside of /usr/ is not around). In that case let's mount it in
    # from an external place, so that we can have persistency. It is
    # after all where we place our build sources and suchlike.

    if args.usr_only:
        return workspace(root) / "home-root"

    return root / "root"


def prepare_tree(args: MkosiArgs, root: Path, do_run_build_script: bool, cached: bool) -> None:
    if cached:
        # Reuse machine-id from cached image.
        args.machine_id = uuid.UUID(root.joinpath("etc/machine-id").read_text().strip()).hex
        # Always update kernel command line.
        if not do_run_build_script and args.bootable:
            root.joinpath("etc/kernel/cmdline").write_text(" ".join(args.kernel_command_line) + "\n")
        return

    with complete_step("Setting up basic OS tree…"):
        if args.output_format in (OutputFormat.subvolume, OutputFormat.gpt_btrfs) and not is_generated_root(args):
            btrfs_subvol_create(root / "home")
            btrfs_subvol_create(root / "srv")
            btrfs_subvol_create(root / "var")
            btrfs_subvol_create(root / "var/tmp", 0o1777)
            root.joinpath("var/lib").mkdir()
            btrfs_subvol_create(root / "var/lib/machines", 0o700)

        # We need an initialized machine ID for the build & boot logic to work
        root.joinpath("etc").mkdir(mode=0o755, exist_ok=True)
        root.joinpath("etc/machine-id").write_text(f"{args.machine_id}\n")

        if not do_run_build_script and args.bootable:
            if args.get_partition(PartitionIdentifier.xbootldr):
                # Create directories for kernels and entries if this is enabled
                root.joinpath("boot/EFI").mkdir(mode=0o700)
                root.joinpath("boot/EFI/Linux").mkdir(mode=0o700)
                root.joinpath("boot/loader").mkdir(mode=0o700)
                root.joinpath("boot/loader/entries").mkdir(mode=0o700)
                root.joinpath("boot", args.machine_id).mkdir(mode=0o700)
            else:
                # If this is not enabled, let's create an empty directory on /boot
                root.joinpath("boot").mkdir(mode=0o700)

            if args.get_partition(PartitionIdentifier.esp):
                root.joinpath("efi/EFI").mkdir(mode=0o700)
                root.joinpath("efi/EFI/BOOT").mkdir(mode=0o700)
                root.joinpath("efi/EFI/systemd").mkdir(mode=0o700)
                root.joinpath("efi/loader").mkdir(mode=0o700)

                if not args.get_partition(PartitionIdentifier.xbootldr):
                    # Create directories for kernels and entries, unless the XBOOTLDR partition is turned on
                    root.joinpath("efi/EFI/Linux").mkdir(mode=0o700)
                    root.joinpath("efi/loader/entries").mkdir(mode=0o700)
                    root.joinpath("efi", args.machine_id).mkdir(mode=0o700)

                    # Create some compatibility symlinks in /boot in case that is not set up otherwise
                    root.joinpath("boot/efi").symlink_to("../efi")
                    root.joinpath("boot/loader").symlink_to("../efi/loader")
                    root.joinpath("boot", args.machine_id).symlink_to(f"../efi/{args.machine_id}")

            root.joinpath("etc/kernel").mkdir(mode=0o755)

            root.joinpath("etc/kernel/cmdline").write_text(" ".join(args.kernel_command_line) + "\n")

        if do_run_build_script or args.ssh:
            root_home(args, root).mkdir(mode=0o750)

        if args.ssh and not do_run_build_script:
            root_home(args, root).joinpath(".ssh").mkdir(mode=0o700)

        if do_run_build_script:
            root_home(args, root).joinpath("dest").mkdir(mode=0o755)

            if args.include_dir is not None:
                root.joinpath("usr").mkdir(mode=0o755)
                root.joinpath("usr/include").mkdir(mode=0o755)

            if args.build_dir is not None:
                root_home(args, root).joinpath("build").mkdir(0o755)

        if args.netdev and not do_run_build_script:
            root.joinpath("etc/systemd").mkdir(mode=0o755)
            root.joinpath("etc/systemd/network").mkdir(mode=0o755)


def disable_pam_securetty(root: Path) -> None:
    def _rm_securetty(line: str) -> str:
        if "pam_securetty.so" in line:
            return ""
        return line

    patch_file(root / "etc/pam.d/login", _rm_securetty)


def url_exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD")
    try:
        if urllib.request.urlopen(req):
            return True
    except Exception:
        pass
    return False


def make_executable(path: Path) -> None:
    st = path.stat()
    os.chmod(path, st.st_mode | stat.S_IEXEC)


def add_packages(
    args: MkosiArgs, packages: Set[str], *names: str, conditional: Optional[str] = None
) -> None:

    """Add packages in @names to @packages, if enabled by --base-packages.

    If @conditional is specified, rpm-specific syntax for boolean
    dependencies will be used to include @names if @conditional is
    satisfied.
    """
    assert args.base_packages is True or args.base_packages is False or args.base_packages == "conditional"

    if args.base_packages is True or (args.base_packages == "conditional" and conditional):
        for name in names:
            packages.add(f"({name} if {conditional})" if conditional else name)


def sort_packages(packages: Iterable[str]) -> List[str]:
    """Sorts packages: normal first, paths second, conditional third"""

    m = {"(": 2, "/": 1}
    sort = lambda name: (m.get(name[0], 0), name)
    return sorted(packages, key=sort)


def make_rpm_list(args: MkosiArgs, packages: Set[str], do_run_build_script: bool) -> Set[str]:
    packages = packages.copy()

    if args.bootable:
        # Temporary hack: dracut only adds crypto support to the initrd, if the cryptsetup binary is installed
        if args.encrypt or args.verity:
            add_packages(args, packages, "cryptsetup", conditional="dracut")

        if args.output_format == OutputFormat.gpt_ext4:
            add_packages(args, packages, "e2fsprogs")

        if args.output_format == OutputFormat.gpt_xfs:
            add_packages(args, packages, "xfsprogs")

        if args.output_format == OutputFormat.gpt_btrfs:
            add_packages(args, packages, "btrfs-progs")

        if args.get_partition(PartitionIdentifier.bios):
            if args.distribution in (Distribution.mageia, Distribution.openmandriva):
                add_packages(args, packages, "grub2")
            else:
                add_packages(args, packages, "grub2-pc")

    if not do_run_build_script and args.ssh:
        add_packages(args, packages, "openssh-server")

    return packages


def clean_dnf_metadata(root: Path, always: bool) -> None:
    """Remove dnf metadata if /bin/dnf is not present in the image

    If dnf is not installed, there doesn't seem to be much use in
    keeping the dnf metadata, since it's not usable from within the
    image anyway.
    """
    paths = [
        root / "var/lib/dnf",
        *root.glob("var/log/dnf.*"),
        *root.glob("var/log/hawkey.*"),
        root / "var/cache/dnf",
    ]

    cond = always or not os.access(root / "bin/dnf", os.F_OK, follow_symlinks=False)

    if not cond or not any(path.exists() for path in paths):
        return

    with complete_step("Cleaning dnf metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_yum_metadata(root: Path, always: bool) -> None:
    """Remove yum metadata if /bin/yum is not present in the image"""
    paths = [
        root / "var/lib/yum",
        *root.glob("var/log/yum.*"),
        root / "var/cache/yum",
    ]

    cond = always or not os.access(root / "bin/yum", os.F_OK, follow_symlinks=False)

    if not cond or not any(path.exists() for path in paths):
        return

    with complete_step("Cleaning yum metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_rpm_metadata(root: Path, always: bool) -> None:
    """Remove rpm metadata if /bin/rpm is not present in the image"""
    path = root / "var/lib/rpm"

    cond = always or not os.access(root / "bin/rpm", os.F_OK, follow_symlinks=False)

    if not cond or not path.exists():
        return

    with complete_step("Cleaning rpm metadata…"):
        unlink_try_hard(path)


def clean_tdnf_metadata(root: Path, always: bool) -> None:
    """Remove tdnf metadata if /bin/tdnf is not present in the image"""
    paths = [
        *root.glob("var/log/tdnf.*"),
        root / "var/cache/tdnf",
    ]

    cond = always or not os.access(root / "usr/bin/tdnf", os.F_OK, follow_symlinks=False)

    if not cond or not any(path.exists() for path in paths):
        return

    with complete_step("Cleaning tdnf metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_apt_metadata(root: Path, always: bool) -> None:
    """Remove apt metadata if /usr/bin/apt is not present in the image"""
    paths = [
        root / "var/lib/apt",
        root / "var/log/apt",
        root / "var/cache/apt",
    ]

    cond = always or not os.access(root / "usr/bin/apt", os.F_OK, follow_symlinks=False)

    if not cond or not any(path.exists() for path in paths):
        return

    with complete_step("Cleaning apt metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_dpkg_metadata(root: Path, always: bool) -> None:
    """Remove dpkg metadata if /usr/bin/dpkg is not present in the image"""
    paths = [
        root / "var/lib/dpkg",
        root / "var/log/dpkg.log",
    ]

    cond = always or not os.access(root / "usr/bin/dpkg", os.F_OK, follow_symlinks=False)

    if not cond or not any(path.exists() for path in paths):
        return

    with complete_step("Cleaning dpkg metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_package_manager_metadata(args: MkosiArgs, root: Path) -> None:
    """Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if the
    package manager is present in the image.
    """

    assert args.clean_package_metadata in (False, True, 'auto')
    if args.clean_package_metadata is False:
        return

    # we try then all: metadata will only be touched if any of them are in the
    # final image
    clean_dnf_metadata(root, always=args.clean_package_metadata is True)
    clean_yum_metadata(root, always=args.clean_package_metadata is True)
    clean_rpm_metadata(root, always=args.clean_package_metadata is True)
    clean_tdnf_metadata(root, always=args.clean_package_metadata is True)
    clean_apt_metadata(root, always=args.clean_package_metadata is True)
    clean_dpkg_metadata(root, always=args.clean_package_metadata is True)
    # FIXME: implement cleanup for other package managers: swupd, pacman


def remove_files(args: MkosiArgs, root: Path) -> None:
    """Remove files based on user-specified patterns"""

    if not args.remove_files:
        return

    with complete_step("Removing files…"):
        # Note: Path('/foo') / '/bar' == '/bar'. We need to strip the slash.
        # https://bugs.python.org/issue44452
        paths = [root / str(p).lstrip("/") for p in args.remove_files]
        remove_glob(*paths)


def invoke_dnf(
    args: MkosiArgs,
    root: Path,
    command: str,
    packages: Iterable[str],
) -> None:

    config_file = workspace(root) / "dnf.conf"

    cmd = 'dnf' if shutil.which('dnf') else 'yum'

    cmdline = [
        cmd,
        "-y",
        f"--config={config_file}",
        "--best",
        "--allowerasing",
        f"--releasever={args.release}",
        f"--installroot={root}",
        "--setopt=keepcache=1",
        "--setopt=install_weak_deps=0",
    ]

    if args.repositories:
        cmdline += ["--disablerepo=*"] + [f"--enablerepo={repo}" for repo in args.repositories]

    if args.with_network == "never":
        cmdline += ["-C"]

    if args.architecture is not None:
        cmdline += [f"--forcearch={args.architecture}"]

    if not args.with_docs:
        cmdline += ["--nodocs"]

    cmdline += [command, *sort_packages(packages)]

    with mount_api_vfs(args, root):
        run(cmdline)

    distribution, release = detect_distribution()
    if distribution not in (Distribution.debian, Distribution.ubuntu):
        return

    # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/
    # so it needs to be copied back in the right location, otherwise
    # the rpmdb will be broken. See: https://bugs.debian.org/1004863
    rpmdb_home = root / "root/.rpmdb"
    if rpmdb_home.exists():
        # Take into account the new location in F36
        rpmdb = root / "usr/lib/sysimage/rpm"
        if not rpmdb.exists():
            rpmdb = root / "var/lib/rpm"
        unlink_try_hard(rpmdb)
        shutil.move(cast(str, rpmdb_home), rpmdb)


def install_packages_dnf(
    args: MkosiArgs,
    root: Path,
    packages: Set[str],
    do_run_build_script: bool,
) -> None:

    packages = make_rpm_list(args, packages, do_run_build_script)
    invoke_dnf(args, root, 'install', packages)


def invoke_tdnf(
    args: MkosiArgs,
    root: Path,
    command: str,
    packages: Set[str],
    gpgcheck: bool,
    do_run_build_script: bool,
) -> None:

    config_file = workspace(root) / "dnf.conf"
    packages = make_rpm_list(args, packages, do_run_build_script)

    cmdline = [
        "tdnf",
        "-y",
        f"--config={config_file}",
        f"--releasever={args.release}",
        f"--installroot={root}",
    ]

    if args.repositories:
        cmdline += ["--disablerepo=*"] + [f"--enablerepo={repo}" for repo in args.repositories]

    if not gpgcheck:
        cmdline += ["--nogpgcheck"]

    cmdline += [command, *sort_packages(packages)]

    with mount_api_vfs(args, root):
        run(cmdline)


def install_packages_tdnf(
    args: MkosiArgs,
    root: Path,
    packages: Set[str],
    gpgcheck: bool,
    do_run_build_script: bool,
) -> None:

    packages = make_rpm_list(args, packages, do_run_build_script)
    invoke_tdnf(args, root, 'install', packages, gpgcheck, do_run_build_script)


class Repo(NamedTuple):
    id: str
    name: str
    url: str
    gpgpath: Path
    gpgurl: Optional[str] = None


def setup_dnf(args: MkosiArgs, root: Path, repos: Sequence[Repo] = ()) -> None:
    gpgcheck = True

    repo_file = workspace(root) / "mkosi.repo"
    with repo_file.open("w") as f:
        for repo in repos:
            gpgkey: Optional[str] = None

            if repo.gpgpath.exists():
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
                    enabled=1
                    """
                )
            )

    if args.use_host_repositories:
        default_repos  = ""
    else:
        option = "repodir" if args.distribution == Distribution.photon else "reposdir"
        default_repos  = f"{option}={workspace(root)} {args.repos_dir if args.repos_dir else ''}"

    vars_dir = workspace(root) / "vars"
    vars_dir.mkdir(exist_ok=True)

    config_file = workspace(root) / "dnf.conf"
    config_file.write_text(
        dedent(
            f"""\
            [main]
            gpgcheck={'1' if gpgcheck else '0'}
            {default_repos }
            varsdir={vars_dir}
            """
        )
    )


@complete_step("Installing Photon…")
def install_photon(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    release_url = "baseurl=https://packages.vmware.com/photon/$releasever/photon_release_$releasever_$basearch"
    updates_url = "baseurl=https://packages.vmware.com/photon/$releasever/photon_updates_$releasever_$basearch"
    gpgpath = Path("/etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY")

    repos = [Repo("photon", f"VMware Photon OS {args.release} Release", release_url, gpgpath),
             Repo("photon-updates", f"VMware Photon OS {args.release} Updates", updates_url, gpgpath)]

    setup_dnf(args, root, repos)

    packages = {*args.packages}
    add_packages(args, packages, "minimal")
    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "linux", "initramfs")

    install_packages_tdnf(args, root, packages, gpgpath.exists(), do_run_build_script)


@complete_step("Installing Clear Linux…")
def install_clear(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    if args.release == "latest":
        release = "clear"
    else:
        release = "clear/" + args.release

    packages = {*args.packages}
    add_packages(args, packages, "os-core-plus")
    if do_run_build_script:
        packages.update(args.build_packages)
    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "kernel-native")
    if not do_run_build_script and args.ssh:
        add_packages(args, packages, "openssh-server")

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

    cmdline: List[PathString] = [swupd_extract, "-output", root]
    if args.cache_path:
        cmdline += ["-state", args.cache_path]
    cmdline += [release, *sort_packages(packages)]

    run(cmdline)

    root.joinpath("etc/resolv.conf").symlink_to("../run/systemd/resolve/resolv.conf")

    # Clear Linux doesn't have a /etc/shadow at install time, it gets created
    # when the root first logs in. To set the password via mkosi, create one.
    if not do_run_build_script and args.password is not None:
        shadow_file = root / "etc/shadow"
        shadow_file.write_text("root::::::::\n")
        shadow_file.chmod(0o400)
        # Password is already empty for root, so no need to reset it later.
        if args.password == "":
            args.password = None


@complete_step("Installing Fedora Linux…")
def install_fedora(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    if args.release == "rawhide":
        last = list(FEDORA_KEYS_MAP)[-1]
        warn(f"Assuming rawhide is version {last} — " + "You may specify otherwise with --release=rawhide-<version>")
        releasever = last
    elif args.release.startswith("rawhide-"):
        args.release, releasever = args.release.split("-")
        MkosiPrinter.info(f"Fedora rawhide — release version: {releasever}")
    else:
        releasever = args.release

    arch = args.architecture or platform.machine()

    if args.mirror:
        baseurl = urllib.parse.urljoin(args.mirror, f"releases/{args.release}/Everything/$basearch/os/")
        media = urllib.parse.urljoin(baseurl.replace("$basearch", arch), "media.repo")
        if not url_exists(media):
            baseurl = urllib.parse.urljoin(args.mirror, f"development/{args.release}/Everything/$basearch/os/")

        release_url = f"baseurl={baseurl}"
        updates_url = f"baseurl={args.mirror}/updates/{args.release}/Everything/$basearch/"
    else:
        release_url = f"metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-{args.release}&arch=$basearch"
        updates_url = (
            "metalink=https://mirrors.fedoraproject.org/metalink?"
            f"repo=updates-released-f{args.release}&arch=$basearch"
        )

    if releasever in FEDORA_KEYS_MAP:
        key = FEDORA_KEYS_MAP[releasever]

        # The website uses short identifiers for Fedora < 35: https://pagure.io/fedora-web/websites/issue/196
        if int(releasever) < 35:
            key = FEDORA_KEYS_MAP[releasever][-8:]

        gpgid = f"keys/{key}.txt"
    else:
        gpgid = "fedora.gpg"

    gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-{releasever}-{arch}")
    gpgurl = urllib.parse.urljoin("https://getfedora.org/static/", gpgid)

    repos = [Repo("fedora", f"Fedora {args.release.capitalize()} - base", release_url, gpgpath, gpgurl)]
    if args.release != 'rawhide':
        # On rawhide, the "updates" repo is the same as the "fedora" repo.
        # In other versions, the "fedora" repo is frozen at release, and "updates" provides any new packages.
        repos += [Repo("updates", f"Fedora {args.release.capitalize()} - updates", updates_url, gpgpath, gpgurl)]

    setup_dnf(args, root, repos)

    packages = {*args.packages}
    add_packages(args, packages, "fedora-release", "systemd", "util-linux")

    if fedora_release_cmp(args.release, "34") < 0:
        add_packages(args, packages, "glibc-minimal-langpack", conditional="glibc")

    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "kernel-core", "kernel-modules", "dracut", "binutils")
        add_packages(args, packages, "systemd-udev", conditional="systemd")
        configure_dracut(args, packages, root)
    if do_run_build_script:
        packages.update(args.build_packages)
    if not do_run_build_script and args.netdev:
        add_packages(args, packages, "systemd-networkd", conditional="systemd")
    install_packages_dnf(args, root, packages, do_run_build_script)

    # FIXME: should this be conditionalized on args.with_docs like in install_debian_or_ubuntu()?
    #        But we set LANG=C.UTF-8 anyway.
    shutil.rmtree(root / "usr/share/locale", ignore_errors=True)


@complete_step("Installing Mageia…")
def install_mageia(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    if args.mirror:
        baseurl = f"{args.mirror}/distrib/{args.release}/x86_64/media/core/"
        release_url = f"baseurl={baseurl}/release/"
        updates_url = f"baseurl={baseurl}/updates/"
    else:
        baseurl = f"https://www.mageia.org/mirrorlist/?release={args.release}&arch=x86_64&section=core"
        release_url = f"mirrorlist={baseurl}&repo=release"
        updates_url = f"mirrorlist={baseurl}&repo=updates"

    gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-Mageia")

    repos = [Repo("mageia", f"Mageia {args.release} Core Release", release_url, gpgpath),
             Repo("updates", f"Mageia {args.release} Core Updates", updates_url, gpgpath)]

    setup_dnf(args, root, repos)

    packages = {*args.packages}
    add_packages(args, packages, "basesystem-minimal")
    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "kernel-server-latest", "dracut", "binutils")
        configure_dracut(args, packages, root)
        # Mageia ships /etc/50-mageia.conf that omits systemd from the initramfs and disables hostonly.
        # We override that again so our defaults get applied correctly on Mageia as well.
        root.joinpath("etc/dracut.conf.d/51-mkosi-override-mageia.conf").write_text(
            'hostonly=no\n'
            'omit_dracutmodules=""\n'
        )

    if do_run_build_script:
        packages.update(args.build_packages)
    install_packages_dnf(args, root, packages, do_run_build_script)

    disable_pam_securetty(root)


@complete_step("Installing OpenMandriva…")
def install_openmandriva(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    release = args.release.strip("'")
    arch = args.architecture or platform.machine()

    if release[0].isdigit():
        release_model = "rock"
    elif release == "cooker":
        release_model = "cooker"
    else:
        release_model = release

    if args.mirror:
        baseurl = f"{args.mirror}/{release_model}/repository/{arch}/main"
        release_url = f"baseurl={baseurl}/release/"
        updates_url = f"baseurl={baseurl}/updates/"
    else:
        baseurl = f"http://mirrors.openmandriva.org/mirrors.php?platform={release_model}&arch={arch}&repo=main"
        release_url = f"mirrorlist={baseurl}&release=release"
        updates_url = f"mirrorlist={baseurl}&release=updates"

    gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-OpenMandriva")

    repos = [Repo("openmandriva", f"OpenMandriva {release_model} Main", release_url, gpgpath),
             Repo("updates", f"OpenMandriva {release_model} Main Updates", updates_url, gpgpath)]

    setup_dnf(args, root, repos)

    packages = {*args.packages}
    # well we may use basesystem here, but that pulls lot of stuff
    add_packages(args, packages, "basesystem-minimal", "systemd")
    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "systemd-boot", "systemd-cryptsetup", conditional="systemd")
        add_packages(args, packages, "kernel-release-server", "dracut", "binutils", "timezone")
        configure_dracut(args, packages, root)
    if args.netdev:
        add_packages(args, packages, "systemd-networkd", conditional="systemd")

    if do_run_build_script:
        packages.update(args.build_packages)
    install_packages_dnf(args, root, packages, do_run_build_script)

    disable_pam_securetty(root)


def install_centos_repos_old(args: MkosiArgs, root: Path, epel_release: int) -> None:
    # Repos for CentOS Linux 7 and earlier

    gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-{args.release}")
    gpgurl = f"https://www.centos.org/keys/RPM-GPG-KEY-CentOS-{args.release}"
    epel_gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}")
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        release_url = f"baseurl={args.mirror}/centos/{args.release}/os/$basearch"
        updates_url = f"baseurl={args.mirror}/centos/{args.release}/updates/$basearch/"
        extras_url = f"baseurl={args.mirror}/centos/{args.release}/extras/$basearch/"
        centosplus_url = f"baseurl={args.mirror}/centos/{args.release}/centosplus/$basearch/"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/$basearch/"
    else:
        release_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=os"
        updates_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=updates"
        extras_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=extras"
        centosplus_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=centosplus"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=$basearch"

    repos = [Repo("base", f"CentOS-{args.release} - Base", release_url, gpgpath, gpgurl),
             Repo("updates", f"CentOS-{args.release} - Updates", updates_url, gpgpath, gpgurl),
             Repo("extras", f"CentOS-{args.release} - Extras", extras_url, gpgpath, gpgurl),
             Repo("centosplus", f"CentOS-{args.release} - Plus", centosplus_url, gpgpath, gpgurl)]

    if 'epel' in args.distribution.name:
        repos += [Repo("epel", f"Extra Packages for Enterprise Linux {epel_release} - $basearch",
                       epel_url, epel_gpgpath, epel_gpgurl)]

    setup_dnf(args, root, repos)


def install_centos_repos_new(args: MkosiArgs, root: Path, epel_release: int) -> None:
    # Repos for CentOS Linux 8 and CentOS Stream 8

    gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial")
    gpgurl = "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official"
    epel_gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}")
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        appstream_url = f"baseurl={args.mirror}/centos/{args.release}/AppStream/$basearch/os"
        baseos_url = f"baseurl={args.mirror}/centos/{args.release}/BaseOS/$basearch/os"
        extras_url = f"baseurl={args.mirror}/centos/{args.release}/extras/$basearch/os"
        centosplus_url = f"baseurl={args.mirror}/centos/{args.release}/centosplus/$basearch/os"
        powertools_url = f"baseurl={args.mirror}/centos/{args.release}/PowerTools/$basearch/os"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/Everything/$basearch"
    else:
        appstream_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=AppStream"
        baseos_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=BaseOS"
        extras_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=extras"
        centosplus_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=centosplus"
        powertools_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=$basearch&repo=PowerTools"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=$basearch"

    repos = [Repo("AppStream", f"CentOS-{args.release} - AppStream", appstream_url, gpgpath, gpgurl),
             Repo("BaseOS", f"CentOS-{args.release} - Base", baseos_url, gpgpath, gpgurl),
             Repo("extras", f"CentOS-{args.release} - Extras", extras_url, gpgpath, gpgurl),
             Repo("centosplus", f"CentOS-{args.release} - Plus", centosplus_url, gpgpath, gpgurl),
             Repo("PowerTools", f"CentOS-{args.release} - PowerTools", powertools_url, gpgpath, gpgurl)]

    if 'epel' in args.distribution.name:
        repos += [Repo("epel", f"Extra Packages for Enterprise Linux {epel_release} - $basearch",
                       epel_url, epel_gpgpath, epel_gpgurl)]

    setup_dnf(args, root, repos)


def install_centos_stream_repos(args: MkosiArgs, root: Path, epel_release: int) -> None:
    # Repos for CentOS Stream 9 and later

    gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial")
    gpgurl = "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official"
    epel_gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}")
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    release = f"{epel_release}-stream"

    if args.mirror:
        appstream_url = f"baseurl={args.mirror}/centos-stream/{release}/AppStream/$basearch/os"
        baseos_url = f"baseurl={args.mirror}/centos-stream/{release}/BaseOS/$basearch/os"
        crb_url = f"baseurl={args.mirror}/centos-stream/{release}/CRB/$basearch/os"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/Everything/$basearch"
    else:
        appstream_url = f"metalink=https://mirrors.centos.org/metalink?repo=centos-appstream-{release}&arch=$basearch"
        baseos_url = f"metalink=https://mirrors.centos.org/metalink?repo=centos-baseos-{release}&arch=$basearch"
        crb_url = f"metalink=https://mirrors.centos.org/metalink?repo=centos-crb-{release}&arch=$basearch"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=$basearch"

    repos = [Repo("AppStream", f"CentOS Stream {release} - AppStream", appstream_url, gpgpath, gpgurl),
             Repo("BaseOS", f"CentOS Stream {release} - BaseOS", baseos_url, gpgpath, gpgurl),
             Repo("CRB", f"CentOS Stream {release} - CRB", crb_url, gpgpath, gpgurl)]

    if 'epel' in args.distribution.name:
        repos += [Repo("epel", f"Extra Packages for Enterprise Linux {epel_release} - $basearch",
                       epel_url, epel_gpgpath, epel_gpgurl)]

    setup_dnf(args, root, repos)


def install_rocky_repos(args: MkosiArgs, root: Path, epel_release: int) -> None:
    # Repos for Rocky Linux 8 and later

    if epel_release >= 9:
        keyname = f"Rocky-{epel_release}"
    else:
        keyname = "rockyofficial"

    gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-{keyname}")
    gpgurl = f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-{keyname}"
    epel_gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}")
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        appstream_url = f"baseurl={args.mirror}/rocky/{args.release}/AppStream/$basearch/os"
        baseos_url = f"baseurl={args.mirror}/rocky/{args.release}/BaseOS/$basearch/os"
        extras_url = f"baseurl={args.mirror}/rocky/{args.release}/extras/$basearch/os"
        plus_url = f"baseurl={args.mirror}/rocky/{args.release}/plus/$basearch/os"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/Everything/$basearch"
    else:
        appstream_url = (
            f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=AppStream-{args.release}"
        )
        baseos_url = f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=BaseOS-{args.release}"
        extras_url = f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=extras-{args.release}"
        plus_url = f"mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=rockyplus-{args.release}"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=$basearch"

    repos = [Repo("AppStream", f"Rocky-{args.release} - AppStream", appstream_url, gpgpath, gpgurl),
             Repo("BaseOS", f"Rocky-{args.release} - Base", baseos_url, gpgpath, gpgurl),
             Repo("extras", f"Rocky-{args.release} - Extras", extras_url, gpgpath, gpgurl),
             Repo("plus", f"Rocky-{args.release} - Plus", plus_url, gpgpath, gpgurl)]
    if 'epel' in args.distribution.name:
        repos += [Repo("epel", f"Extra Packages for Enterprise Linux {epel_release} - $basearch",
                       epel_url, epel_gpgpath, epel_gpgurl)]

    setup_dnf(args, root, repos)


def install_alma_repos(args: MkosiArgs, root: Path, epel_release: int) -> None:
    # Repos for Alma Linux 8 and later
    gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux")
    gpgurl = "https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux"
    epel_gpgpath = Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}")
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        appstream_url = f"baseurl={args.mirror}/almalinux/{args.release}/AppStream/$basearch/os"
        baseos_url = f"baseurl={args.mirror}/almalinux/{args.release}/BaseOS/$basearch/os"
        extras_url = f"baseurl={args.mirror}/almalinux/{args.release}/extras/$basearch/os"
        powertools_url = f"baseurl={args.mirror}/almalinux/{args.release}/PowerTools/$basearch/os"
        ha_url = f"baseurl={args.mirror}/almalinux/{args.release}/HighAvailability/$basearch/os"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/Everything/$basearch"
    else:
        appstream_url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/{args.release}/appstream"
        baseos_url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/{args.release}/baseos"
        extras_url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/{args.release}/extras"
        powertools_url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/{args.release}/powertools"
        ha_url = f"mirrorlist=https://mirrors.almalinux.org/mirrorlist/{args.release}/ha"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=$basearch"

    repos = [Repo("AppStream", f"AlmaLinux-{args.release} - AppStream", appstream_url, gpgpath, gpgurl),
             Repo("BaseOS", f"AlmaLinux-{args.release} - Base", baseos_url, gpgpath, gpgurl),
             Repo("extras", f"AlmaLinux-{args.release} - Extras", extras_url, gpgpath, gpgurl),
             Repo("Powertools", f"AlmaLinux-{args.release} - Powertools", powertools_url, gpgpath, gpgurl),
             Repo("HighAvailability", f"AlmaLinux-{args.release} - HighAvailability", ha_url, gpgpath, gpgurl)]

    if 'epel' in args.distribution.name:
        repos += [Repo("epel", f"Extra Packages for Enterprise Linux {epel_release} - $basearch",
                       epel_url, epel_gpgpath, epel_gpgurl)]

    setup_dnf(args, root, repos)


def parse_epel_release(release: str) -> int:
    fields = release.split(".")
    if fields[0].endswith("-stream"):
        epel_release = fields[0].split("-")[0]
    else:
        epel_release = fields[0]

    return int(epel_release)


def is_older_than_centos8(release: str) -> bool:
    # CentOS 7 contains some very old versions of certain libraries
    # which require workarounds in different places.
    # Additionally the repositories have been changed between 7 and 8
    epel_release = parse_epel_release(release)
    return epel_release <= 7


@complete_step("Installing CentOS…")
def install_centos(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    epel_release = parse_epel_release(args.release)

    if epel_release <= 7:
        install_centos_repos_old(args, root, epel_release)
    elif epel_release <= 8:
        install_centos_repos_new(args, root, epel_release)
    else:
        install_centos_stream_repos(args, root, epel_release)

    if "-stream" in args.release:
        workspace(root).joinpath("vars/stream").write_text(args.release)

    packages = {*args.packages}
    add_packages(args, packages, "centos-release", "systemd")
    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "kernel", "dracut", "binutils")
        configure_dracut(args, packages, root)
        if epel_release <= 7:
            add_packages(
                args,
                packages,
                "grub2-efi",
                "grub2-tools",
                "grub2-efi-x64-modules",
                "shim-x64",
                "efibootmgr",
                "efivar-libs",
            )
        else:
            # this does not exist on CentOS 7
            add_packages(args, packages, "systemd-udev", conditional="systemd")

    if do_run_build_script:
        packages.update(args.build_packages)

    if args.distribution == Distribution.centos_epel:
        add_packages(args, packages, "epel-release")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.distribution == Distribution.centos_epel:
        if args.netdev:
            add_packages(args, packages, "systemd-networkd", conditional="systemd")
        if epel_release >= 9:
            add_packages(args, packages, "systemd-boot", conditional="systemd")

    install_packages_dnf(args, root, packages, do_run_build_script)

    # Centos Stream 8 and below can't write to the sqlite db backend used by
    # default in newer RPM releases so let's rebuild the DB to use the old bdb
    # backend instead. Because newer RPM releases have dropped support for the
    # bdb backend completely, we check if rpm is installed and use
    # run_workspace_command() to rebuild the rpm db.
    if epel_release <= 8 and root.joinpath("usr/bin/rpm").exists():
        cmdline = ["rpm", "--rebuilddb", "--define", "_db_backend bdb"]
        run_workspace_command(args, root, cmdline)


@complete_step("Installing Rocky Linux…")
def install_rocky(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    epel_release = int(args.release.split(".")[0])
    install_rocky_repos(args, root, epel_release)

    packages = {*args.packages}
    add_packages(args, packages, "rocky-release", "systemd")
    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "kernel", "dracut", "binutils")
        configure_dracut(args, packages, root)
        add_packages(args, packages, "systemd-udev", conditional="systemd")

    if do_run_build_script:
        packages.update(args.build_packages)

    if args.distribution == Distribution.rocky_epel:
        add_packages(args, packages, "epel-release")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.distribution == Distribution.rocky_epel and args.netdev:
        add_packages(args, packages, "systemd-networkd", conditional="systemd")

    install_packages_dnf(args, root, packages, do_run_build_script)

    if root.joinpath("usr/bin/rpm").exists():
        cmdline = ["rpm", "--rebuilddb", "--define", "_db_backend bdb"]
        run_workspace_command(args, root, cmdline)



@complete_step("Installing Alma Linux…")
def install_alma(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    epel_release = int(args.release.split(".")[0])
    install_alma_repos(args, root, epel_release)

    packages = {*args.packages}
    add_packages(args, packages, "almalinux-release", "systemd")
    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "kernel", "dracut", "binutils")
        configure_dracut(args, packages, root)
        add_packages(args, packages, "systemd-udev", conditional="systemd")

    if do_run_build_script:
        packages.update(args.build_packages)

    if args.distribution == Distribution.alma_epel:
        add_packages(args, packages, "epel-release")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.distribution == Distribution.alma_epel and args.netdev:
        add_packages(args, packages, "systemd-networkd", conditional="systemd")

    install_packages_dnf(args, root, packages, do_run_build_script)


def debootstrap_knows_arg(arg: str) -> bool:
    return bytes("invalid option", "UTF-8") not in run(["debootstrap", arg], stdout=PIPE, check=False).stdout


def invoke_apt(
    args: MkosiArgs,
    do_run_build_script: bool,
    root: Path,
    command: str,
    extra: Iterable[str],
) -> None:

    cmdline = ["/usr/bin/apt-get", "--assume-yes", command, *extra]
    env = {
        "DEBIAN_FRONTEND": "noninteractive",
        "DEBCONF_NONINTERACTIVE_SEEN": "true",
    }

    run_workspace_command(args, root, cmdline, network=True, env=env)


def install_debian_or_ubuntu(args: MkosiArgs, root: Path, *, do_run_build_script: bool) -> None:
    # Either the image builds or it fails and we restart, we don't need safety fsyncs when bootstrapping
    # Add it before debootstrap, as the second stage already uses dpkg from the chroot
    dpkg_io_conf = root / "etc/dpkg/dpkg.cfg.d/unsafe_io"
    os.makedirs(dpkg_io_conf.parent, mode=0o755, exist_ok=True)
    dpkg_io_conf.write_text("force-unsafe-io\n")

    repos = set(args.repositories) or {"main"}
    # Ubuntu needs the 'universe' repo to install 'dracut'
    if args.distribution == Distribution.ubuntu and args.bootable:
        repos.add("universe")

    # debootstrap fails if a base image is used with an already populated root, so skip it.
    if args.base_image is None:
        cmdline: List[PathString] = [
            "debootstrap",
            "--variant=minbase",
            "--include=ca-certificates",
            "--merged-usr",
            f"--components={','.join(repos)}",
        ]

        if args.architecture is not None:
            debarch = DEBIAN_ARCHITECTURES.get(args.architecture)
            cmdline += [f"--arch={debarch}"]

        # Let's use --no-check-valid-until only if debootstrap knows it
        if debootstrap_knows_arg("--no-check-valid-until"):
            cmdline += ["--no-check-valid-until"]

        assert args.mirror is not None
        cmdline += [args.release, root, args.mirror]
        run(cmdline)

    # Install extra packages via the secondary APT run, because it is smarter and can deal better with any
    # conflicts. dbus and libpam-systemd are optional dependencies for systemd in debian so we include them
    # explicitly.
    extra_packages: Set[str] = set()
    add_packages(args, extra_packages, "systemd", "systemd-sysv", "dbus", "libpam-systemd")
    extra_packages.update(args.packages)

    if do_run_build_script:
        extra_packages.update(args.build_packages)

    if not do_run_build_script and args.bootable:
        add_packages(args, extra_packages, "dracut", "binutils")
        configure_dracut(args, extra_packages, root)

        if args.distribution == Distribution.ubuntu:
            add_packages(args, extra_packages, "linux-generic")
        else:
            add_packages(args, extra_packages, "linux-image-amd64")

        if args.get_partition(PartitionIdentifier.bios):
            add_packages(args, extra_packages, "grub-pc")

        if args.output_format == OutputFormat.gpt_btrfs:
            add_packages(args, extra_packages, "btrfs-progs")

    if not do_run_build_script and args.ssh:
        add_packages(args, extra_packages, "openssh-server")

    # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
    # start. Let's install one that denies all daemon startups.
    # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
    # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
    # the admin.
    policyrcd = root / "usr/sbin/policy-rc.d"
    policyrcd.write_text("#!/bin/sh\nexit 101\n")
    policyrcd.chmod(0o755)

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
        cmdline = ["/bin/rm", "-rf", *doc_paths]
        run_workspace_command(args, root, cmdline)
        # Create dpkg.cfg to ignore documentation on new packages
        dpkg_nodoc_conf = root / "etc/dpkg/dpkg.cfg.d/01_nodoc"
        with dpkg_nodoc_conf.open("w") as f:
            f.writelines(f"path-exclude {d}/*\n" for d in doc_paths)

    if not do_run_build_script and args.bootable and args.with_unified_kernel_images and args.base_image is None:
        # systemd-boot won't boot unified kernel images generated without a BUILD_ID or VERSION_ID in
        # /etc/os-release. Build one with the mtime of os-release if we don't find them.
        with root.joinpath("etc/os-release").open("r+") as f:
            os_release = f.read()
            if "VERSION_ID" not in os_release and "BUILD_ID" not in os_release:
                f.write(f"BUILD_ID=mkosi-{args.release}\n")

    if args.release not in ("testing", "unstable"):
        if args.distribution == Distribution.ubuntu:
            updates = f"deb http://archive.ubuntu.com/ubuntu {args.release}-updates {' '.join(repos)}"
        else:
            updates = f"deb http://deb.debian.org/debian {args.release}-updates {' '.join(repos)}"

        root.joinpath(f"etc/apt/sources.list.d/{args.release}-updates.list").write_text(f"{updates}\n")

        if args.distribution == Distribution.ubuntu:
            security = f"deb http://archive.ubuntu.com/ubuntu {args.release}-security {' '.join(repos)}"
        elif args.release in ("stretch", "buster"):
            security = f"deb http://security.debian.org/debian-security/ {args.release}/updates main"
        else:
            security = f"deb https://security.debian.org/debian-security {args.release}-security main"

        root.joinpath(f"etc/apt/sources.list.d/{args.release}-security.list").write_text(f"{security}\n")

    install_skeleton_trees(args, root, False, late=True)

    invoke_apt(args, do_run_build_script, root, "update", [])
    invoke_apt(args, do_run_build_script, root, "install", ["--no-install-recommends", *extra_packages])

    policyrcd.unlink()
    dpkg_io_conf.unlink()
    if not args.with_docs and args.base_image is not None:
        # Don't ship dpkg config files in extensions, they belong with dpkg in the base image.
        dpkg_nodoc_conf.unlink() # type: ignore

    if args.base_image is None:
        # Debian still has pam_securetty module enabled, disable it in the base image.
        disable_pam_securetty(root)

    if args.distribution == Distribution.debian and "systemd" in extra_packages:
        # The default resolv.conf points to 127.0.0.1, and resolved is disabled, fix it in
        # the base image.
        root.joinpath("etc/resolv.conf").unlink()
        root.joinpath("etc/resolv.conf").symlink_to("../run/systemd/resolve/resolv.conf")
        run(["systemctl", "--root", root, "enable", "systemd-resolved"])

    if args.bootable and not do_run_build_script and "uefi" in args.boot_protocols:
        for kver, kimg in gen_kernel_images(args, root):
            run_workspace_command(args, root, ["kernel-install", "add", kver, Path("/") / kimg])


@complete_step("Installing Debian…")
def install_debian(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    install_debian_or_ubuntu(args, root, do_run_build_script=do_run_build_script)


@complete_step("Installing Ubuntu…")
def install_ubuntu(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
    install_debian_or_ubuntu(args, root, do_run_build_script=do_run_build_script)


def run_pacman(root: Path, pacman_conf: Path, packages: Set[str]) -> None:
    try:
        run(["pacman-key", "--config", pacman_conf, "--init"])
        run(["pacman-key", "--config", pacman_conf, "--populate"])
        run(["pacman", "--config", pacman_conf, "--noconfirm", "-Sy", *sort_packages(packages)])
    finally:
        # Kill the gpg-agent started by pacman and pacman-key.
        run(["gpgconf", "--homedir", root / "etc/pacman.d/gnupg", "--kill", "all"])


def patch_locale_gen(args: MkosiArgs, root: Path) -> None:
    # If /etc/locale.gen exists, uncomment the desired locale and leave the rest of the file untouched.
    # If it doesn’t exist, just write the desired locale in it.
    try:

        def _patch_line(line: str) -> str:
            if line.startswith("#C.UTF-8"):
                return line[1:]
            return line

        patch_file(root / "etc/locale.gen", _patch_line)

    except FileNotFoundError:
        root.joinpath("etc/locale.gen").write_text("C.UTF-8 UTF-8\n")


@complete_step("Installing Arch Linux…")
def install_arch(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
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
        mirrorlist = workspace(root) / "mirrorlist"
        with urllib.request.urlopen(
            "https://www.archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4&use_mirror_status=on"
        ) as r:
            mirrors = r.readlines()
            uncommented = [line.decode("utf-8")[1:] for line in mirrors]
            with mirrorlist.open("w") as f:
                f.writelines(uncommented)
            server = f"Include = {mirrorlist}"

    # Create base layout for pacman and pacman-key
    os.makedirs(root / "var/lib/pacman", 0o755, exist_ok=True)
    os.makedirs(root / "etc/pacman.d/gnupg", 0o755, exist_ok=True)

    # Permissions on these directories are all 0o777 because of 'mount --bind'
    # limitations but pacman expects them to be 0o755 so we fix them before
    # calling pacman (except /var/tmp which is 0o1777).
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
        path = root / dir
        if path.exists():
            path.chmod(permissions)

    pacman_conf = workspace(root) / "pacman.conf"
    with pacman_conf.open("w") as f:
        f.write(
            dedent(
                f"""\
                [options]
                RootDir = {root}
                LogFile = /dev/null
                CacheDir = {root}/var/cache/pacman/pkg/
                GPGDir = {root}/etc/pacman.d/gnupg/
                HookDir = {root}/etc/pacman.d/hooks/
                HoldPkg = pacman glibc
                Architecture = auto
                Color
                CheckSpace
                SigLevel = Required DatabaseOptional TrustAll
                ParallelDownloads = 5

                [core]
                {server}

                [extra]
                {server}

                [community]
                {server}

                {f"Include = {args.repos_dir}/*" if args.repos_dir else ""}
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
        hooks_dir = root / "etc/pacman.d/hooks"
        scripts_dir = root / "etc/pacman.d/scripts"

        os.makedirs(hooks_dir, 0o755, exist_ok=True)
        os.makedirs(scripts_dir, 0o755, exist_ok=True)

        # Disable depmod pacman hook as depmod is handled by kernel-install as well.
        hooks_dir.joinpath("60-depmod.hook").symlink_to("/dev/null")

        write_resource(hooks_dir / "90-mkosi-kernel-add.hook", "mkosi.resources.arch", "90_kernel_add.hook")
        write_resource(scripts_dir / "mkosi-kernel-add", "mkosi.resources.arch", "kernel_add.sh",
                       executable=True)

        write_resource(hooks_dir / "60-mkosi-kernel-remove.hook", "mkosi.resources.arch", "60_kernel_remove.hook")
        write_resource(scripts_dir / "mkosi-kernel-remove", "mkosi.resources.arch", "kernel_remove.sh",
                       executable=True)

        if args.get_partition(PartitionIdentifier.esp):
            write_resource(hooks_dir / "91-mkosi-bootctl-update.hook", "mkosi.resources.arch", "91_bootctl_update.hook")

        if args.get_partition(PartitionIdentifier.bios):
            write_resource(hooks_dir / "90-mkosi-vmlinuz-add.hook", "mkosi.resources.arch", "90_vmlinuz_add.hook")
            write_resource(hooks_dir / "60-mkosi-vmlinuz-remove.hook", "mkosi.resources.arch", "60_vmlinuz_remove.hook")

    keyring = "archlinux"
    if platform.machine() == "aarch64":
        keyring += "arm"

    packages: Set[str] = set()
    add_packages(args, packages, "base")

    if not do_run_build_script and args.bootable:
        if args.output_format == OutputFormat.gpt_btrfs:
            add_packages(args, packages, "btrfs-progs")
        elif args.output_format == OutputFormat.gpt_xfs:
            add_packages(args, packages, "xfsprogs")
        if args.encrypt:
            add_packages(args, packages, "cryptsetup", "device-mapper")
        if args.get_partition(PartitionIdentifier.bios):
            add_packages(args, packages, "grub")

        add_packages(args, packages, "dracut", "binutils")
        configure_dracut(args, packages, root)

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
        add_packages(args, packages, "linux")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.ssh:
        add_packages(args, packages, "openssh")

    with mount_api_vfs(args, root):
        run_pacman(root, pacman_conf, packages)

    # Make sure the C.UTF-8 locale is available.
    patch_locale_gen(args, root)
    run_workspace_command(args, root, ["/usr/bin/locale-gen"])

    # Arch still uses pam_securetty which prevents root login into
    # systemd-nspawn containers. See https://bugs.archlinux.org/task/45903.
    disable_pam_securetty(root)


@complete_step("Installing openSUSE…")
def install_opensuse(args: MkosiArgs, root: Path, do_run_build_script: bool) -> None:
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
        root.joinpath("etc/zypp/zypp.conf").write_text("rpm.install.excludedocs = yes\n")

    packages = {*args.packages}
    add_packages(args, packages, "systemd")

    if release.startswith("42."):
        add_packages(args, packages, "patterns-openSUSE-minimal_base")
    else:
        add_packages(args, packages, "patterns-base-minimal_base")

    if not do_run_build_script and args.bootable:
        add_packages(args, packages, "kernel-default", "dracut", "binutils")
        configure_dracut(args, packages, root)

        if args.get_partition(PartitionIdentifier.bios):
            add_packages(args, packages, "grub2")

    if not do_run_build_script and args.encrypt:
        add_packages(args, packages, "device-mapper")

    if args.output_format in (OutputFormat.subvolume, OutputFormat.gpt_btrfs):
        add_packages(args, packages, "btrfsprogs")

    if do_run_build_script:
        packages.update(args.build_packages)

    if not do_run_build_script and args.ssh:
        add_packages(args, packages, "openssh-server")

    cmdline: List[PathString] = [
        "zypper",
        "--root",
        root,
        "--gpg-auto-import-keys",
        "install",
        "-y",
        "--no-recommends",
        "--download-in-advance",
        *sort_packages(packages),
    ]

    with mount_api_vfs(args, root):
        run(cmdline)

    # Disable package caching in the image that was enabled previously to populate the package cache.
    run(["zypper", "--root", root, "modifyrepo", "-K", "repo-oss"])
    run(["zypper", "--root", root, "modifyrepo", "-K", "repo-update"])

    if args.password == "":
        shutil.copy2(root / "usr/etc/pam.d/common-auth", root / "etc/pam.d/common-auth")

        def jj(line: str) -> str:
            if "pam_unix.so" in line:
                return f"{line.strip()} nullok"
            return line

        patch_file(root / "etc/pam.d/common-auth", jj)

    if args.autologin:
        # copy now, patch later (in set_autologin())
        shutil.copy2(root / "usr/etc/pam.d/login", root / "etc/pam.d/login")

    # Zypper doesn't run dracut automatically so we have to do it manually.
    if args.bootable and not do_run_build_script and "uefi" in args.boot_protocols:
        for kver, kimg in gen_kernel_images(args, root):
            run_workspace_command(args, root, ["kernel-install", "add", kver, Path("/") / kimg])


@complete_step("Installing Gentoo…")
def install_gentoo(
    args: MkosiArgs,
    root: Path,
    do_run_build_script: bool
) -> None:
    from .gentoo import Gentoo

    # this will fetch/fix stage3 tree and portage confgired for mkosi
    gentoo = Gentoo(args, root, do_run_build_script)

    if gentoo.pkgs_fs:
        gentoo.invoke_emerge(args, root, pkgs=gentoo.pkgs_fs)

    if not do_run_build_script and args.bootable:
        # Please don't move, needs to be called before installing dracut
        # dracut is part of gentoo_pkgs_boot
        configure_dracut(args, packages={"dracut"}, root=root)
        # The gentoo stage3 tarball includes packages that may block chosen
        # pkgs_boot. Using Gentoo.EMERGE_UPDATE_OPTS for opts allows the
        # package manager to uninstall blockers.
        gentoo.invoke_emerge(args, root, pkgs=gentoo.pkgs_boot, opts=Gentoo.EMERGE_UPDATE_OPTS)

    if args.packages:
        gentoo.invoke_emerge(args, root, pkgs=args.packages)

    if do_run_build_script:
        gentoo.invoke_emerge(args, root, pkgs=args.build_packages)


def install_distribution(args: MkosiArgs, root: Path, do_run_build_script: bool, cached: bool) -> None:
    if cached:
        return

    install: Dict[Distribution, Callable[[MkosiArgs, Path, bool], None]] = {
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
        Distribution.rocky: install_rocky,
        Distribution.rocky_epel: install_rocky,
        Distribution.alma: install_alma,
        Distribution.alma_epel: install_alma,
        Distribution.gentoo: install_gentoo,
    }

    with mount_cache(args, root):
        install[args.distribution](args, root, do_run_build_script)


def remove_packages(args: MkosiArgs, root: Path) -> None:
    """Remove packages listed in args.remove_packages"""

    remove: Callable[[List[str]], None]

    if (args.distribution.package_type == PackageType.rpm and
        args.distribution != Distribution.photon):
        remove = lambda p: invoke_dnf(args, root, 'remove', p)
    elif args.distribution.package_type == PackageType.deb:
        remove = lambda p: invoke_apt(args, False, root, "purge", ["--auto-remove", *p])
    else:
        # FIXME: implement removal for other package managers: tdnf, swupd, pacman
        return

    if args.remove_packages:
        with complete_step(f"Removing {len(args.packages)} packages…"):
            remove(args.remove_packages)


def reset_machine_id(args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool) -> None:
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
        if not args.machine_id_is_fixed:
            machine_id = root / "etc/machine-id"
            try:
                machine_id.unlink()
            except FileNotFoundError:
                pass
            machine_id.touch()

        dbus_machine_id = root / "var/lib/dbus/machine-id"
        try:
            dbus_machine_id.unlink()
        except FileNotFoundError:
            pass
        else:
            dbus_machine_id.symlink_to("../../../etc/machine-id")


def reset_random_seed(args: MkosiArgs, root: Path) -> None:
    """Remove random seed file, so that it is initialized on first boot"""
    random_seed = root / "var/lib/systemd/random-seed"
    if not random_seed.exists():
        return

    with complete_step("Removing random seed"):
        random_seed.unlink()


def set_root_password(args: MkosiArgs, root: Path, do_run_build_script: bool, cached: bool) -> None:
    "Set the root account password, or just delete it so it's easy to log in"

    if do_run_build_script:
        return
    if cached:
        return

    if args.password == "":
        with complete_step("Deleting root password"):

            def delete_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", ""] + line.split(":")[2:])
                return line

            patch_file(root / "etc/passwd", delete_root_pw)
    elif args.password:
        with complete_step("Setting root password"):
            if args.password_is_hashed:
                password = args.password
            else:
                password = crypt.crypt(args.password, crypt.mksalt(crypt.METHOD_SHA512))

            def set_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", password] + line.split(":")[2:])
                return line

            patch_file(root / "etc/shadow", set_root_pw)


def invoke_fstrim(args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool) -> None:

    if do_run_build_script:
        return
    if is_generated_root(args):
        return
    if not args.output_format.is_disk():
        return
    if for_cache:
        return

    with complete_step("Trimming File System"):
        run(["fstrim", "-v", root], check=False)


def pam_add_autologin(root: Path, ttys: List[str]) -> None:
    login = root / "etc/pam.d/login"
    original = login.read_text() if login.exists() else ""

    login.parent.mkdir(exist_ok=True)
    with open(login, "w") as f:
        for tty in ttys:
            # Some PAM versions require the /dev/ prefix, others don't. Just add both variants.
            f.write(f"auth sufficient pam_succeed_if.so tty = {tty}\n")
            f.write(f"auth sufficient pam_succeed_if.so tty = /dev/{tty}\n")
        f.write(original)


def set_autologin(args: MkosiArgs, root: Path, do_run_build_script: bool, cached: bool) -> None:
    if do_run_build_script or cached or not args.autologin:
        return

    with complete_step("Setting up autologin…"):
        add_dropin_config_from_resource(root, "console-getty.service", "autologin",
                                        "mkosi.resources", "console_getty_autologin.conf")

        ttys = []
        ttys += ["pts/0"]

        add_dropin_config_from_resource(root, "serial-getty@ttyS0.service", "autologin",
                                        "mkosi.resources", "serial_getty_autologin.conf")

        ttys += ["ttyS0"]

        add_dropin_config_from_resource(root, "getty@tty1.service", "autologin",
                                        "mkosi.resources", "getty_autologin.conf")

        ttys += ["tty1"]
        ttys += ["console"]

        pam_add_autologin(root, ttys)


def set_serial_terminal(args: MkosiArgs, root: Path, do_run_build_script: bool, cached: bool) -> None:
    """Override TERM for the serial console with the terminal type from the host."""

    if do_run_build_script or cached or not args.qemu_headless:
        return

    with complete_step("Configuring serial tty (/dev/ttyS0)…"):
        columns, lines = shutil.get_terminal_size(fallback=(80, 24))
        add_dropin_config(root, "serial-getty@ttyS0.service", "term",
                          f"""\
                          [Service]
                          Environment=TERM={os.getenv('TERM', 'vt220')}
                          Environment=COLUMNS={columns}
                          Environment=LINES={lines}
                          TTYColumns={columns}
                          TTYRows={lines}
                          """)


def nspawn_params_for_build_sources(args: MkosiArgs, sft: SourceFileTransfer) -> List[str]:
    params = []

    if args.build_sources is not None:
        params += ["--setenv=SRCDIR=/root/src",
                   "--chdir=/root/src"]
        if sft == SourceFileTransfer.mount:
            params += [f"--bind={args.build_sources}:/root/src"]

        if args.read_only:
            params += ["--overlay=+/root/src::/root/src"]
    else:
        params += ["--chdir=/root"]

    params += [f"--setenv={env}={value}" for env, value in args.environment.items()]

    return params


def run_prepare_script(args: MkosiArgs, root: Path, do_run_build_script: bool, cached: bool) -> None:
    if args.prepare_script is None:
        return
    if cached:
        return

    verb = "build" if do_run_build_script else "final"

    with mount_cache(args, root), complete_step("Running prepare script…"):

        # We copy the prepare script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(args.prepare_script, root_home(args, root) / "prepare")

        nspawn_params = nspawn_params_for_build_sources(args, SourceFileTransfer.mount)
        run_workspace_command(args, root, ["/root/prepare", verb], network=True, nspawn_params=nspawn_params)

        srcdir = root_home(args, root) / "src"
        if srcdir.exists():
            os.rmdir(srcdir)

        os.unlink(root_home(args, root) / "prepare")


def run_postinst_script(
    args: MkosiArgs, root: Path, loopdev: Optional[Path], do_run_build_script: bool, for_cache: bool
) -> None:
    if args.postinst_script is None:
        return
    if for_cache:
        return

    verb = "build" if do_run_build_script else "final"

    with mount_cache(args, root), complete_step("Running postinstall script…"):

        # We copy the postinst script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(args.postinst_script, root_home(args, root) / "postinst")

        nspawn_params = []
        # in order to have full blockdev access, i.e. for making grub2 bootloader changes
        # we need to have these bind mounts for a proper chroot setup
        if args.bootable:
            if loopdev is None:
                raise ValueError("Parameter 'loopdev' required for bootable images.")
            nspawn_params += nspawn_params_for_blockdev_access(args, loopdev)

        run_workspace_command(args, root, ["/root/postinst", verb],
                              network=(args.with_network is True),
                              nspawn_params=nspawn_params,
                              env=args.environment)
        root_home(args, root).joinpath("postinst").unlink()


def output_dir(args: MkosiArgs) -> Path:
    return args.output_dir or Path(os.getcwd())


def run_finalize_script(args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool) -> None:
    if args.finalize_script is None:
        return
    if for_cache:
        return

    verb = "build" if do_run_build_script else "final"

    with complete_step("Running finalize script…"):
        env = collections.ChainMap(dict(BUILDROOT=str(root), OUTPUTDIR=str(output_dir(args))),
                                   args.environment,
                                   os.environ)
        run([args.finalize_script, verb], env=env)


def install_boot_loader_clear(args: MkosiArgs, root: Path, loopdev: Path) -> None:
    # clr-boot-manager uses blkid in the device backing "/" to
    # figure out uuid and related parameters.
    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    cmdline = ["/usr/bin/clr-boot-manager", "update", "-i"]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)


def install_boot_loader_centos_old_efi(args: MkosiArgs, root: Path, loopdev: Path) -> None:
    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    # prepare EFI directory on ESP
    os.makedirs(root / "efi/EFI/centos", exist_ok=True)

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

    patch_file(root / "efi/EFI/centos/grub.cfg", _fix_grub)


def install_boot_loader(
    args: MkosiArgs, root: Path, loopdev: Optional[Path], do_run_build_script: bool, cached: bool
) -> None:
    if not args.bootable or do_run_build_script:
        return
    assert loopdev is not None

    if cached:
        return

    with complete_step("Installing boot loader…"):
        if args.get_partition(PartitionIdentifier.esp):
            if args.distribution == Distribution.clear:
                pass
            elif (args.distribution in (Distribution.centos, Distribution.centos_epel) and
                  is_older_than_centos8(args.release)):
                install_boot_loader_centos_old_efi(args, root, loopdev)
            else:
                run_workspace_command(args, root, ["bootctl", "install"])

        if args.get_partition(PartitionIdentifier.bios) and args.distribution != Distribution.clear:
            grub = (
                "grub"
                if args.distribution in (Distribution.ubuntu,
                                         Distribution.debian,
                                         Distribution.arch,
                                         Distribution.gentoo)
                else "grub2"
            )
            # TODO: Just use "grub" once https://github.com/systemd/systemd/pull/16645 is widely available.
            if args.distribution in (Distribution.ubuntu, Distribution.debian, Distribution.opensuse):
                grub = f"/usr/sbin/{grub}"

            install_grub(args, root, loopdev, grub)

        if args.distribution == Distribution.clear:
            install_boot_loader_clear(args, root, loopdev)


def install_extra_trees(args: MkosiArgs, root: Path, for_cache: bool) -> None:
    if not args.extra_trees:
        return

    if for_cache:
        return

    with complete_step("Copying in extra file trees…"):
        for tree in args.extra_trees:
            if tree.is_dir():
                copy_path(tree, root)
            else:
                # unpack_archive() groks Paths, but mypy doesn't know this.
                # Pretend that tree is a str.
                shutil.unpack_archive(cast(str, tree), root)


def install_skeleton_trees(args: MkosiArgs, root: Path, cached: bool, *, late: bool=False) -> None:
    if not args.skeleton_trees:
        return

    if cached:
        return

    if not late and args.distribution in (Distribution.debian, Distribution.ubuntu):
        return

    with complete_step("Copying in skeleton file trees…"):
        for tree in args.skeleton_trees:
            if tree.is_dir():
                copy_path(tree, root)
            else:
                # unpack_archive() groks Paths, but mypy doesn't know this.
                # Pretend that tree is a str.
                shutil.unpack_archive(cast(str, tree), root)


def copy_git_files(src: Path, dest: Path, *, source_file_transfer: SourceFileTransfer) -> None:
    what_files = ["--exclude-standard", "--cached"]
    if source_file_transfer == SourceFileTransfer.copy_git_others:
        what_files += ["--others", "--exclude=.mkosi-*"]

    uid = int(os.getenv("SUDO_UID", 0))

    c = run(["git", "-C", src, "ls-files", "-z", *what_files], stdout=PIPE, text=False, user=uid)
    files = {x.decode("utf-8") for x in c.stdout.rstrip(b"\0").split(b"\0")}

    # Add the .git/ directory in as well.
    if source_file_transfer == SourceFileTransfer.copy_git_more:
        top = os.path.join(src, ".git/")
        for path, _, filenames in os.walk(top):
            for filename in filenames:
                fp = os.path.join(path, filename)  # full path
                fr = os.path.join(".git/", fp[len(top) :])  # relative to top
                files.add(fr)

    # Get submodule files
    c = run(["git", "-C", src, "submodule", "status", "--recursive"], stdout=PIPE, text=True, user=uid)
    submodules = {x.split()[1] for x in c.stdout.splitlines()}

    # workaround for git-ls-files returning the path of submodules that we will
    # still parse
    files -= submodules

    for sm in submodules:
        c = run(
            ["git", "-C", os.path.join(src, sm), "ls-files", "-z"] + what_files,
            stdout=PIPE,
            text=False,
            user=uid,
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


def install_build_src(args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool) -> None:
    if for_cache:
        return

    if do_run_build_script:
        if args.build_script is not None:
            with complete_step("Copying in build script…"):
                copy_file(args.build_script, root_home(args, root) / args.build_script.name)
        else:
            return

    sft: Optional[SourceFileTransfer] = None
    resolve_symlinks: bool = False
    if do_run_build_script:
        sft = args.source_file_transfer
        resolve_symlinks = args.source_resolve_symlinks
    else:
        sft = args.source_file_transfer_final
        resolve_symlinks = args.source_resolve_symlinks_final

    if args.build_sources is None or sft is None:
        return

    with complete_step("Copying in sources…"):
        target = root_home(args, root) / "src"

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
                f"{args.output_dir.name}/" if args.output_dir else "mkosi.output/",
                f"{args.workspace_dir.name}/" if args.workspace_dir else "mkosi.workspace/",
                f"{args.cache_path.name}/" if args.cache_path else "mkosi.cache/",
                f"{args.build_dir.name}/" if args.build_dir else "mkosi.builddir/",
                f"{args.include_dir.name}/" if args.include_dir else "mkosi.includedir/",
                f"{args.install_dir.name}/" if args.install_dir else "mkosi.installdir/",
            )
            shutil.copytree(args.build_sources, target, symlinks=not resolve_symlinks, ignore=ignore)


def install_build_dest(args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool) -> None:
    if do_run_build_script:
        return
    if for_cache:
        return

    if args.build_script is None:
        return

    with complete_step("Copying in build tree…"):
        copy_path(install_dir(args, root), root)


def make_read_only(args: MkosiArgs, root: Path, for_cache: bool, b: bool = True) -> None:
    if not args.read_only:
        return
    if for_cache:
        return

    if args.output_format not in (OutputFormat.gpt_btrfs, OutputFormat.subvolume):
        return
    if is_generated_root(args):
        return

    with complete_step("Marking root subvolume read-only"):
        btrfs_subvol_make_ro(root, b)


def xz_binary() -> str:
    return "pxz" if shutil.which("pxz") else "xz"


def compressor_command(option: Union[str, bool]) -> List[str]:
    """Returns a command suitable for compressing archives."""

    if option == "xz":
        return [xz_binary(), "--check=crc32", "--lzma2=dict=1MiB", "-T0"]
    elif option == "zstd":
        return ["zstd", "-15", "-q", "-T0"]
    elif option is False:
        return ["cat"]
    else:
        die(f"Unknown compression {option}")


def tar_binary() -> str:
    # Some distros (Mandriva) install BSD tar as "tar", hence prefer
    # "gtar" if it exists, which should be GNU tar wherever it exists.
    # We are interested in exposing same behaviour everywhere hence
    # it's preferable to use the same implementation of tar
    # everywhere. In particular given the limited/different SELinux
    # support in BSD tar and the different command line syntax
    # compared to GNU tar.
    return "gtar" if shutil.which("gtar") else "tar"


def make_tar(args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool) -> Optional[BinaryIO]:
    if do_run_build_script:
        return None
    if args.output_format != OutputFormat.tar:
        return None
    if for_cache:
        return None

    root_dir = root / "usr" if args.usr_only else root

    cmd: List[PathString] = [tar_binary(), "-C", root_dir, "-c", "--xattrs", "--xattrs-include=*"]
    if args.tar_strip_selinux_context:
        cmd += ["--xattrs-exclude=security.selinux"]

    compress = should_compress_output(args)
    if compress:
        cmd += ["--use-compress-program=" + " ".join(compressor_command(compress))]

    cmd += ["."]

    with complete_step("Creating archive…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(args.output), prefix=".mkosi-"))
        run(cmd, stdout=f)

    return f


def scandir_recursive(
        root: Path,
        filter: Optional[Callable[[os.DirEntry[str]], T]] = None,
) -> Iterator[T]:
    """Recursively walk the tree starting at @root, optionally apply filter, yield non-none values"""
    queue: Deque[Union[str, Path]] = collections.deque([root])

    while queue:
        for entry in os.scandir(queue.pop()):
            pred = filter(entry) if filter is not None else entry
            if pred is not None:
                yield cast(T, pred)
            if entry.is_dir(follow_symlinks=False):
                queue.append(entry.path)


def find_files(root: Path) -> Iterator[Path]:
    """Generate a list of all filepaths relative to @root"""
    yield from scandir_recursive(root,
                                 lambda entry: Path(entry.path).relative_to(root))


def make_cpio(
    args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool
) -> Optional[BinaryIO]:
    if do_run_build_script:
        return None
    if args.output_format != OutputFormat.cpio:
        return None
    if for_cache:
        return None

    root_dir = root / "usr" if args.usr_only else root

    with complete_step("Creating archive…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(args.output), prefix=".mkosi-"))

        compressor = compressor_command(should_compress_output(args))
        files = find_files(root_dir)
        cmd: List[PathString] = [
            "cpio", "-o", "--reproducible", "--null", "-H", "newc", "--quiet", "-D", root_dir
        ]

        with spawn(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as cpio:
            #  https://github.com/python/mypy/issues/10583
            assert cpio.stdin is not None

            with spawn(compressor, stdin=cpio.stdout, stdout=f, delay_interrupt=False):
                for file in files:
                    cpio.stdin.write(os.fspath(file).encode("utf8") + b"\0")
                cpio.stdin.close()
        if cpio.wait() != 0:
            die("Failed to create archive")

    return f


def generate_squashfs(args: MkosiArgs, root: Path, for_cache: bool) -> Optional[BinaryIO]:
    if not args.output_format.is_squashfs():
        return None
    if for_cache:
        return None

    command = args.mksquashfs_tool[0] if args.mksquashfs_tool else "mksquashfs"
    comp_args = args.mksquashfs_tool[1:] if args.mksquashfs_tool and args.mksquashfs_tool[1:] else ["-noappend"]

    compress = should_compress_fs(args)
    # mksquashfs default is true, so no need to specify anything to have the default compression.
    if isinstance(compress, str):
        comp_args += ["-comp", compress]
    elif compress is False:
        comp_args += ["-noI", "-noD", "-noF", "-noX"]

    with complete_step("Creating squashfs file system…"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-squashfs", dir=os.path.dirname(args.output))
        )
        run([command, root, f.name, *comp_args])

    return f


def generate_ext4(args: MkosiArgs, root: Path, label: str, for_cache: bool) -> Optional[BinaryIO]:
    if args.output_format != OutputFormat.gpt_ext4:
        return None
    if for_cache:
        return None

    with complete_step("Creating ext4 root file system…"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-mkfs-ext4", dir=os.path.dirname(args.output))
        )
        f.truncate(args.root_size)
        run(["mkfs.ext4", "-I", "256", "-L", label, "-M", "/", "-d", root, f.name])

    if args.minimize:
        with complete_step("Minimizing ext4 root file system…"):
            run(["resize2fs", "-M", f.name])

    return f


def generate_btrfs(args: MkosiArgs, root: Path, label: str, for_cache: bool) -> Optional[BinaryIO]:
    if args.output_format != OutputFormat.gpt_btrfs:
        return None
    if for_cache:
        return None

    with complete_step("Creating minimal btrfs root file system…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-mkfs-btrfs", dir=args.output.parent))
        f.truncate(args.root_size)

        cmdline: Sequence[PathString] = [
            "mkfs.btrfs", "-L", label, "-d", "single", "-m", "single", "--rootdir", root, f.name
        ]

        if args.minimize:
            try:
                run([*cmdline, "--shrink"])
            except subprocess.CalledProcessError:
                # The --shrink option was added in btrfs-tools 4.14.1, before that it was the default behaviour.
                # If the above fails, let's see if things work if we drop it
                run(cmdline)
        else:
            run(cmdline)

    return f


def make_generated_root(args: MkosiArgs, root: Path, for_cache: bool) -> Optional[BinaryIO]:

    if not is_generated_root(args):
        return None

    label = "usr" if args.usr_only else "root"
    patched_root = root / "usr" if args.usr_only else root

    if args.output_format == OutputFormat.gpt_ext4:
        return generate_ext4(args, patched_root, label, for_cache)
    if args.output_format == OutputFormat.gpt_btrfs:
        return generate_btrfs(args, patched_root, label, for_cache)
    if args.output_format.is_squashfs():
        return generate_squashfs(args, patched_root, for_cache)

    return None


def insert_partition(
    args: MkosiArgs,
    raw: BinaryIO,
    loopdev: Path,
    blob: BinaryIO,
    ident: PartitionIdentifier,
    description: str,
    type_uuid: uuid.UUID,
    read_only: bool,
    part_uuid: Optional[uuid.UUID] = None,
) -> Partition:

    assert args.partition_table is not None

    blob.seek(0)

    luks_extra = 16 * 1024 * 1024 if args.encrypt == "all" else 0
    blob_size = os.stat(blob.name).st_size
    part = args.partition_table.add(ident, blob_size + luks_extra, type_uuid, description, part_uuid)

    disk_size = args.partition_table.disk_size()
    ss = f" ({disk_size // args.partition_table.sector_size} sectors)" if 'disk' in ARG_DEBUG else ""
    with complete_step(f"Resizing disk image to {format_bytes(disk_size)}{ss}"):
        os.truncate(raw.name, disk_size)
        run(["losetup", "--set-capacity", loopdev])

    part_size = part.n_sectors * args.partition_table.sector_size
    ss = f" ({part.n_sectors} sectors)" if 'disk' in ARG_DEBUG else ""
    with complete_step(f"Inserting partition of {format_bytes(part_size)}{ss}..."):
        args.partition_table.run_sfdisk(loopdev)

    with complete_step("Writing partition..."):
        if ident == PartitionIdentifier.root:
            luks_format_root(args, loopdev, False, False, True)
            cm = luks_setup_root(args, loopdev, False, True)
        else:
            cm = contextlib.nullcontext()

        with cm as dev:
            path = dev if dev is not None else part.blockdev(loopdev)
            # Let's discard the partition block device first, to ensure the GPT partition table footer that
            # likely is stored in it is flushed out. After all we want to write with dd's sparse option.
            run(["blkdiscard", path])
            path.write_bytes(blob.read())

    return part


def insert_generated_root(
    args: MkosiArgs,
    raw: Optional[BinaryIO],
    loopdev: Optional[Path],
    image: Optional[BinaryIO],
    for_cache: bool,
) -> Optional[Partition]:
    if not is_generated_root(args):
        return None
    if not args.output_format.is_disk():
        return None
    if for_cache:
        return None
    assert raw is not None
    assert loopdev is not None
    assert image is not None
    assert args.partition_table is not None

    with complete_step("Inserting generated root partition…"):
        return insert_partition(
            args,
            raw,
            loopdev,
            image,
            PartitionIdentifier.root,
            root_partition_description(args),
            type_uuid=gpt_root_native(args.architecture, args.usr_only).root,
            read_only=args.read_only)


def make_verity(
    args: MkosiArgs, dev: Optional[Path], do_run_build_script: bool, for_cache: bool
) -> Tuple[Optional[BinaryIO], Optional[str]]:
    if do_run_build_script or args.verity is False:
        return None, None
    if for_cache:
        return None, None
    assert dev is not None

    with complete_step("Generating verity hashes…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=args.output.parent, prefix=".mkosi-"))
        c = run(["veritysetup", "format", dev, f.name], stdout=PIPE)

        for line in c.stdout.decode("utf-8").split("\n"):
            if line.startswith("Root hash:"):
                root_hash = line[10:].strip()
                return f, root_hash

        raise ValueError("Root hash not found")


def insert_verity(
    args: MkosiArgs,
    raw: Optional[BinaryIO],
    loopdev: Optional[Path],
    verity: Optional[BinaryIO],
    root_hash: Optional[str],
    for_cache: bool,
) -> Optional[Partition]:
    if verity is None:
        return None
    if for_cache:
        return None
    assert loopdev is not None
    assert raw is not None
    assert root_hash is not None
    assert args.partition_table is not None

    # Use the final 128 bit of the root hash as partition UUID of the verity partition
    u = uuid.UUID(root_hash[-32:])

    with complete_step("Inserting verity partition…"):
        return insert_partition(
            args,
            raw,
            loopdev,
            verity,
            PartitionIdentifier.verity,
            root_partition_description(args, "Verity"),
            gpt_root_native(args.architecture, args.usr_only).verity,
            read_only=True,
            part_uuid=u)


def make_verity_sig(
    args: MkosiArgs, root_hash: Optional[str], do_run_build_script: bool, for_cache: bool
) -> Tuple[Optional[BinaryIO], Optional[bytes], Optional[str]]:

    if do_run_build_script or args.verity != "signed":
        return None, None, None
    if for_cache:
        return None, None, None

    assert root_hash is not None

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import pkcs7

    with complete_step("Signing verity root hash…"):

        key = serialization.load_pem_private_key(args.secure_boot_key.read_bytes(), password=None)
        certificate = x509.load_pem_x509_certificate(args.secure_boot_certificate.read_bytes())

        if not isinstance(key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
            die(f"Secure boot key has unsupported type {type(key)}")

        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()

        sigbytes = pkcs7.PKCS7SignatureBuilder().add_signer(
            certificate,
            key,
            hashes.SHA256()
        ).set_data(
            root_hash.encode("utf-8")
        ).sign(
            options=[
                pkcs7.PKCS7Options.DetachedSignature,
                pkcs7.PKCS7Options.NoCerts,
                pkcs7.PKCS7Options.NoAttributes,
                pkcs7.PKCS7Options.Binary
            ],
            encoding=serialization.Encoding.DER
        )

        # We base64 the DER result, because we want to include it in JSON. This is not PEM
        # (i.e. no header/footer line, no line breaks), but just base64 encapsulated DER).
        b64encoded = base64.b64encode(sigbytes).decode("ascii")

        print(b64encoded)

        # This is supposed to be extensible, but care should be taken not to include unprotected
        # data here.
        j = json.dumps({
                "rootHash": root_hash,
                "certificateFingerprint": fingerprint,
                "signature": b64encoded
            }).encode("utf-8")

        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(mode="w+b", dir=args.output.parent, prefix=".mkosi-"))
        f.write(j)
        f.flush()

        # Returns a file with JSON data to insert as signature partition as the first element, and
        # the DER PKCS7 signature bytes as second argument (to store as a detached PKCS7 file), and
        # finally the SHA256 fingerprint of the certificate used (which is used to
        # deterministically generate the partition UUID for the signature partition).

        return f, sigbytes, fingerprint


def insert_verity_sig(
    args: MkosiArgs,
    raw: Optional[BinaryIO],
    loopdev: Optional[Path],
    verity_sig: Optional[BinaryIO],
    root_hash: Optional[str],
    fingerprint: Optional[str],
    for_cache: bool,
) -> Optional[Partition]:
    if verity_sig is None:
        return None
    if for_cache:
        return None
    assert loopdev is not None
    assert raw is not None
    assert root_hash is not None
    assert fingerprint is not None
    assert args.partition_table is not None

    # Hash the concatenation of verity roothash and the X509 certificate
    # fingerprint to generate a UUID for the signature partition.
    u = uuid.UUID(hashlib.sha256(bytes.fromhex(root_hash) + bytes.fromhex(fingerprint)).hexdigest()[:32])

    with complete_step("Inserting verity signature partition…"):
        return insert_partition(
            args,
            raw,
            loopdev,
            verity_sig,
            PartitionIdentifier.verity_sig,
            root_partition_description(args, "Signature"),
            gpt_root_native(args.architecture, args.usr_only).verity_sig,
            read_only=True,
            part_uuid=u)


def patch_root_uuid(
    args: MkosiArgs, loopdev: Optional[Path], root_hash: Optional[str], for_cache: bool
) -> None:
    if root_hash is None:
        return
    assert loopdev is not None

    if for_cache:
        return

    # Use the first 128bit of the root hash as partition UUID of the root partition
    u = uuid.UUID(root_hash[:32])

    with complete_step("Patching root partition UUID…"):
        part = args.get_partition(PartitionIdentifier.root)
        assert part is not None

        run(["sfdisk", "--part-uuid", loopdev, str(part.number), str(u)])


def extract_partition(
    args: MkosiArgs, dev: Optional[Path], do_run_build_script: bool, for_cache: bool
) -> Optional[BinaryIO]:

    if do_run_build_script or for_cache or not args.split_artifacts:
        return None

    assert dev is not None

    with complete_step("Extracting partition…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(args.output), prefix=".mkosi-"))
        run(["dd", f"if={dev}", f"of={f.name}", "conv=nocreat,sparse"])

    return f


def gen_kernel_images(args: MkosiArgs, root: Path) -> Iterator[Tuple[str, Path]]:
    # Apparently openmandriva hasn't yet completed its usrmerge so we use lib here instead of usr/lib.
    for kver in root.joinpath("lib/modules").iterdir():
        if not (kver.is_dir() and os.path.isfile(os.path.join(kver, "modules.dep"))): # type: ignore
            continue

        if args.distribution == Distribution.gentoo:
            from .gentoo import ARCHITECTURES

            _, kimg_path = ARCHITECTURES[args.architecture or "x86_64"]

            kimg = Path(f"usr/src/linux-{kver.name}") / kimg_path
        elif args.distribution in (Distribution.debian, Distribution.ubuntu):
            kimg = Path(f"boot/vmlinuz-{kver.name}")
        else:
            kimg = Path("lib/modules") / kver.name / "vmlinuz"

        yield kver.name, kimg


def install_unified_kernel(
    args: MkosiArgs,
    root: Path,
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

    if not (args.bootable and
            args.get_partition(PartitionIdentifier.esp) and
            args.with_unified_kernel_images):
        return

    # Don't run dracut if this is for the cache. The unified kernel
    # typically includes the image ID, roothash and other data that
    # differs between cached version and final result. Moreover, we
    # want that the initrd for the image actually takes the changes we
    # make to the image into account (e.g. when we build a systemd
    # test image with this we want that the systemd we just built is
    # in the initrd, and not one from the cache. Hence even though
    # dracut is slow we invoke it only during the last final build,
    # never for the cached builds.
    if for_cache:
        return

    # Don't bother running dracut if this is a development build. Strictly speaking it would probably be a
    # good idea to run it, so that the development environment differs as little as possible from the final
    # build, but then again the initrd should not be relevant for building, and dracut is simply very slow,
    # hence let's avoid it invoking it needlessly, given that we never actually invoke the boot loader on the
    # development image.
    if do_run_build_script:
        return

    prefix = "boot" if args.get_partition(PartitionIdentifier.xbootldr) else "efi"

    with mount(), complete_step("Generating combined kernel + initrd boot file…"):
        for kver, kimg in gen_kernel_images(args, root):
            if args.image_id:
                image_id = args.image_id
                if args.image_version:
                    partlabel = f"{args.image_id}_{args.image_version}"
                else:
                    partlabel = f"{args.image_id}"
            else:
                image_id = f"mkosi-{args.distribution}"
                partlabel = None

            if args.image_version:
                boot_binary = Path(prefix) / f"EFI/Linux/{image_id}_{args.image_version}.efi"
            elif root_hash:
                boot_binary = Path(prefix) / f"EFI/Linux/{image_id}-{kver}-{root_hash}.efi"
            else:
                boot_binary = Path(prefix) / f"EFI/Linux/{image_id}-{kver}.efi"

            if root.joinpath("etc/kernel/cmdline").exists():
                boot_options = root.joinpath("etc/kernel/cmdline").read_text().strip()
            elif root.joinpath("/usr/lib/kernel/cmdline").exists():
                boot_options = root.joinpath("usr/lib/kernel/cmdline").read_text().strip()
            else:
                boot_options = ""

            if root_hash:
                option = "usrhash" if args.usr_only else "roothash"
                boot_options = f"{boot_options} {option}={root_hash}"
            elif partlabel:
                boot_options = f"{boot_options} root=PARTLABEL={partlabel}"

            cmd: Sequence[PathString] = [
                "dracut",
                "--uefi",
                "--kver", kver,
                "--kernel-image", Path("/") / kimg,
                "--kernel-cmdline", boot_options,
                "--force",
                boot_binary,
            ]

            run_workspace_command(args, root, cmd)


def secure_boot_sign(
    args: MkosiArgs,
    root: Path,
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
    if cached and args.verity is False:
        return

    with mount():
        for path, _, filenames in os.walk(root / "efi"):
            for i in filenames:
                if not i.endswith(".efi") and not i.endswith(".EFI"):
                    continue

                with complete_step(f"Signing EFI binary {i} in ESP…"):
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
                    )

                    os.rename(p + ".signed", p)


def extract_unified_kernel(
    args: MkosiArgs,
    root: Path,
    do_run_build_script: bool,
    for_cache: bool,
    mount: Callable[[], ContextManager[None]],
) -> Optional[BinaryIO]:

    if do_run_build_script or for_cache or not args.split_artifacts or not args.bootable:
        return None

    with mount():
        kernel = None

        for path, _, filenames in os.walk(root / "efi/EFI/Linux"):
            for i in filenames:
                if not i.endswith(".efi") and not i.endswith(".EFI"):
                    continue

                if kernel is not None:
                    raise ValueError(
                        f"Multiple kernels found, don't know which one to extract. ({kernel} vs. {path}/{i})"
                    )

                kernel = os.path.join(path, i)

        if kernel is None:
            raise ValueError("No kernel found in image, can't extract")

        assert args.output_split_kernel is not None

        f = copy_file_temporary(kernel, args.output_split_kernel.parent)

    return f


def compress_output(
    args: MkosiArgs, data: Optional[BinaryIO], suffix: Optional[str] = None
) -> Optional[BinaryIO]:

    if data is None:
        return None
    compress = should_compress_output(args)

    if not compress:
        # If we shan't compress, then at least make the output file sparse
        with complete_step(f"Digging holes into output file {data.name}…"):
            run(["fallocate", "--dig-holes", data.name])

        return data

    with complete_step(f"Compressing output file {data.name}…"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", suffix=suffix, dir=os.path.dirname(args.output))
        )
        run([*compressor_command(compress), "--stdout", data.name], stdout=f)

    return f


def qcow2_output(args: MkosiArgs, raw: Optional[BinaryIO]) -> Optional[BinaryIO]:
    if not args.output_format.is_disk():
        return raw
    assert raw is not None

    if not args.qcow2:
        return raw

    with complete_step("Converting image file to qcow2…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=os.path.dirname(args.output)))
        run(["qemu-img", "convert", "-onocow=on", "-fraw", "-Oqcow2", raw.name, f.name])

    return f


def write_root_hash_file(args: MkosiArgs, root_hash: Optional[str]) -> Optional[BinaryIO]:
    if root_hash is None:
        return None

    assert args.output_root_hash_file is not None

    suffix = roothash_suffix(args.usr_only)
    with complete_step(f"Writing {suffix} file…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(mode="w+b", prefix=".mkosi", dir=os.path.dirname(args.output_root_hash_file)),
        )
        f.write((root_hash + "\n").encode())
        f.flush()

    return f


def write_root_hash_p7s_file(args: MkosiArgs, root_hash_p7s: Optional[bytes]) -> Optional[BinaryIO]:
    if root_hash_p7s is None:
        return None

    assert args.output_root_hash_p7s_file is not None

    suffix = roothash_p7s_suffix(args.usr_only)
    with complete_step(f"Writing {suffix} file…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(
                mode="w+b", prefix=".mkosi", dir=args.output_root_hash_p7s_file.parent
            ),
        )
        f.write(root_hash_p7s)
        f.flush()

    return f


def copy_nspawn_settings(args: MkosiArgs) -> Optional[BinaryIO]:
    if args.nspawn_settings is None:
        return None

    assert args.output_nspawn_settings is not None

    with complete_step("Copying nspawn settings file…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(
                mode="w+b", prefix=".mkosi-", dir=os.path.dirname(args.output_nspawn_settings)
            ),
        )

        with open(args.nspawn_settings, "rb") as c:
            f.write(c.read())
            f.flush()

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
    args: MkosiArgs,
    raw: Optional[BinaryIO],
    archive: Optional[BinaryIO],
    root_hash_file: Optional[BinaryIO],
    root_hash_p7s_file: Optional[BinaryIO],
    split_root: Optional[BinaryIO],
    split_verity: Optional[BinaryIO],
    split_verity_sig: Optional[BinaryIO],
    split_kernel: Optional[BinaryIO],
    nspawn_settings: Optional[BinaryIO],
) -> Optional[TextIO]:
    if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        return None

    if not args.checksum:
        return None

    assert args.output_checksum is not None

    with complete_step("Calculating SHA256SUMS…"):
        f: TextIO = cast(
            TextIO,
            tempfile.NamedTemporaryFile(
                mode="w+", prefix=".mkosi-", encoding="utf-8", dir=os.path.dirname(args.output_checksum)
            ),
        )

        if raw is not None:
            hash_file(f, raw, os.path.basename(args.output))
        if archive is not None:
            hash_file(f, archive, os.path.basename(args.output))
        if root_hash_file is not None:
            assert args.output_root_hash_file is not None
            hash_file(f, root_hash_file, os.path.basename(args.output_root_hash_file))
        if root_hash_p7s_file is not None:
            assert args.output_root_hash_p7s_file is not None
            hash_file(f, root_hash_p7s_file, args.output_root_hash_p7s_file.name)
        if split_root is not None:
            assert args.output_split_root is not None
            hash_file(f, split_root, os.path.basename(args.output_split_root))
        if split_verity is not None:
            assert args.output_split_verity is not None
            hash_file(f, split_verity, os.path.basename(args.output_split_verity))
        if split_verity_sig is not None:
            assert args.output_split_verity_sig is not None
            hash_file(f, split_verity_sig, args.output_split_verity_sig.name)
        if split_kernel is not None:
            assert args.output_split_kernel is not None
            hash_file(f, split_kernel, os.path.basename(args.output_split_kernel))
        if nspawn_settings is not None:
            assert args.output_nspawn_settings is not None
            hash_file(f, nspawn_settings, os.path.basename(args.output_nspawn_settings))

        f.flush()

    return f


def calculate_signature(args: MkosiArgs, checksum: Optional[IO[Any]]) -> Optional[BinaryIO]:
    if not args.sign:
        return None

    if checksum is None:
        return None

    assert args.output_signature is not None

    with complete_step("Signing SHA256SUMS…"):
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


def calculate_bmap(args: MkosiArgs, raw: Optional[BinaryIO]) -> Optional[TextIO]:
    if not args.bmap:
        return None

    if not args.output_format.is_disk_rw():
        return None
    assert raw is not None
    assert args.output_bmap is not None

    with complete_step("Creating BMAP file…"):
        f: TextIO = cast(
            TextIO,
            tempfile.NamedTemporaryFile(
                mode="w+", prefix=".mkosi-", encoding="utf-8", dir=os.path.dirname(args.output_bmap)
            ),
        )

        cmdline = ["bmaptool", "create", raw.name]
        run(cmdline, stdout=f)

    return f


def save_cache(args: MkosiArgs, root: Path, raw: Optional[str], cache_path: Optional[Path]) -> None:
    disk_rw = args.output_format.is_disk_rw()
    if disk_rw:
        if raw is None or cache_path is None:
            return
    else:
        if cache_path is None:
            return

    with complete_step("Installing cache copy…", f"Installed cache copy {path_relative_to_cwd(cache_path)}"):

        if disk_rw:
            assert raw is not None
            os.chmod(raw, 0o666 & ~args.original_umask)
            shutil.move(raw, cache_path)
        else:
            unlink_try_hard(cache_path)
            shutil.move(cast(str, root), cache_path)  # typing bug, .move() accepts Path


def _link_output(
        args: MkosiArgs,
        oldpath: PathString,
        newpath: PathString,
        mode: int = 0o666,
) -> None:

    assert oldpath is not None
    assert newpath is not None

    # Temporary files created by tempfile have mode trimmed to the user.
    # After we are done writing files, adjust the mode to the default specified by umask.
    os.chmod(oldpath, mode & ~args.original_umask)

    os.link(oldpath, newpath)

    if args.no_chown:
        return

    sudo_uid = os.getenv("SUDO_UID")
    sudo_gid = os.getenv("SUDO_GID")
    if not (sudo_uid and sudo_gid):
        return

    relpath = path_relative_to_cwd(newpath)

    sudo_user = os.getenv("SUDO_USER", default=sudo_uid)
    with complete_step(
        f"Changing ownership of output file {relpath} to user {sudo_user} (acquired from sudo)…",
        f"Changed ownership of {relpath}",
    ):
        os.chown(newpath, int(sudo_uid), int(sudo_gid))


def link_output(args: MkosiArgs, root: Path, artifact: Optional[BinaryIO]) -> None:
    with complete_step("Linking image file…", f"Linked {path_relative_to_cwd(args.output)}"):
        if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
            assert artifact is None

            make_read_only(args, root, for_cache=False, b=False)
            os.rename(root, args.output)
            make_read_only(args, args.output, for_cache=False, b=True)

        elif args.output_format.is_disk() or args.output_format in (
            OutputFormat.plain_squashfs,
            OutputFormat.tar,
            OutputFormat.cpio,
        ):
            assert artifact is not None
            _link_output(args, artifact.name, args.output)


def link_output_nspawn_settings(args: MkosiArgs, path: Optional[SomeIO]) -> None:
    if path:
        assert args.output_nspawn_settings
        with complete_step(
            "Linking nspawn settings file…", f"Linked {path_relative_to_cwd(args.output_nspawn_settings)}"
        ):
            _link_output(args, path.name, args.output_nspawn_settings)


def link_output_checksum(args: MkosiArgs, checksum: Optional[SomeIO]) -> None:
    if checksum:
        assert args.output_checksum
        with complete_step("Linking SHA256SUMS file…", f"Linked {path_relative_to_cwd(args.output_checksum)}"):
            _link_output(args, checksum.name, args.output_checksum)


def link_output_root_hash_file(args: MkosiArgs, root_hash_file: Optional[SomeIO]) -> None:
    if root_hash_file:
        assert args.output_root_hash_file
        suffix = roothash_suffix(args.usr_only)
        with complete_step(f"Linking {suffix} file…", f"Linked {path_relative_to_cwd(args.output_root_hash_file)}"):
            _link_output(args, root_hash_file.name, args.output_root_hash_file)


def link_output_root_hash_p7s_file(args: MkosiArgs, root_hash_p7s_file: Optional[SomeIO]) -> None:
    if root_hash_p7s_file:
        assert args.output_root_hash_p7s_file
        suffix = roothash_p7s_suffix(args.usr_only)
        with complete_step(
            f"Linking {suffix} file…", f"Linked {path_relative_to_cwd(args.output_root_hash_p7s_file)}"
        ):
            _link_output(args, root_hash_p7s_file.name, args.output_root_hash_p7s_file)


def link_output_signature(args: MkosiArgs, signature: Optional[SomeIO]) -> None:
    if signature:
        assert args.output_signature is not None
        with complete_step("Linking SHA256SUMS.gpg file…", f"Linked {path_relative_to_cwd(args.output_signature)}"):
            _link_output(args, signature.name, args.output_signature)


def link_output_bmap(args: MkosiArgs, bmap: Optional[SomeIO]) -> None:
    if bmap:
        assert args.output_bmap
        with complete_step("Linking .bmap file…", f"Linked {path_relative_to_cwd(args.output_bmap)}"):
            _link_output(args, bmap.name, args.output_bmap)


def link_output_sshkey(args: MkosiArgs, sshkey: Optional[SomeIO]) -> None:
    if sshkey:
        assert args.output_sshkey
        with complete_step("Linking private ssh key file…", f"Linked {path_relative_to_cwd(args.output_sshkey)}"):
            _link_output(args, sshkey.name, args.output_sshkey, mode=0o600)


def link_output_split_root(args: MkosiArgs, split_root: Optional[SomeIO]) -> None:
    if split_root:
        assert args.output_split_root
        with complete_step(
            "Linking split root file system…", f"Linked {path_relative_to_cwd(args.output_split_root)}"
        ):
            _link_output(args, split_root.name, args.output_split_root)


def link_output_split_verity(args: MkosiArgs, split_verity: Optional[SomeIO]) -> None:
    if split_verity:
        assert args.output_split_verity
        with complete_step("Linking split Verity data…", f"Linked {path_relative_to_cwd(args.output_split_verity)}"):
            _link_output(args, split_verity.name, args.output_split_verity)


def link_output_split_verity_sig(args: MkosiArgs, split_verity_sig: Optional[SomeIO]) -> None:
    if split_verity_sig:
        assert args.output_split_verity_sig
        with complete_step(
            "Linking split Verity Signature data…", f"Linked {path_relative_to_cwd(args.output_split_verity_sig)}"
        ):
            _link_output(args, split_verity_sig.name, args.output_split_verity_sig)


def link_output_split_kernel(args: MkosiArgs, split_kernel: Optional[SomeIO]) -> None:
    if split_kernel:
        assert args.output_split_kernel
        with complete_step("Linking split kernel image…", f"Linked {path_relative_to_cwd(args.output_split_kernel)}"):
            _link_output(args, split_kernel.name, args.output_split_kernel)


def dir_size(path: PathString) -> int:
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


def save_manifest(args: MkosiArgs, manifest: Manifest) -> None:
    if manifest.has_data():
        relpath = path_relative_to_cwd(args.output)

        if ManifestFormat.json in args.manifest_format:
            with complete_step(f"Saving manifest {relpath}.manifest"):
                f: TextIO = cast(
                    TextIO,
                    tempfile.NamedTemporaryFile(
                        mode="w+",
                        encoding="utf-8",
                        prefix=".mkosi-",
                        dir=os.path.dirname(args.output),
                    ),
                )
                with f:
                    manifest.write_json(f)
                    _link_output(args, f.name, f"{args.output}.manifest")

        if ManifestFormat.changelog in args.manifest_format:
            with complete_step(f"Saving report {relpath}.changelog"):
                g: TextIO = cast(
                    TextIO,
                    tempfile.NamedTemporaryFile(
                        mode="w+",
                        encoding="utf-8",
                        prefix=".mkosi-",
                        dir=os.path.dirname(args.output),
                    ),
                )
                with g:
                    manifest.write_package_report(g)
                    _link_output(args, g.name, f"{relpath}.changelog")


def print_output_size(args: MkosiArgs) -> None:
    if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        MkosiPrinter.print_step("Resulting image size is " + format_bytes(dir_size(args.output)) + ".")
    else:
        st = os.stat(args.output)
        size = format_bytes(st.st_size)
        space = format_bytes(st.st_blocks * 512)
        MkosiPrinter.print_step(f"Resulting image size is {size}, consumes {space}.")


def setup_package_cache(args: MkosiArgs) -> Optional[TempDir]:
    if args.cache_path and args.cache_path.exists():
        return None

    d = None
    with complete_step("Setting up package cache…", "Setting up package cache {} complete") as output:
        if args.cache_path is None:
            d = tempfile.TemporaryDirectory(dir=os.path.dirname(args.output), prefix=".mkosi-")
            args.cache_path = Path(d.name)
        else:
            os.makedirs(args.cache_path, 0o755, exist_ok=True)
        output.append(args.cache_path)

    return d


def remove_duplicates(items: List[T]) -> List[T]:
    "Return list with any repetitions removed"
    # We use a dictionary to simulate an ordered set
    return list({x: None for x in items})


class ListAction(argparse.Action):
    delimiter: str

    def __init__(self, *args: Any, choices: Optional[Iterable[Any]] = None, **kwargs: Any) -> None:
        self.list_choices = choices
        # mypy doesn't like the following call due to https://github.com/python/mypy/issues/6799,
        # so let's, temporarily, ignore the error
        super().__init__(choices=choices, *args, **kwargs)  # type: ignore[misc]

    def __call__(
        self,  # These type-hints are copied from argparse.pyi
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        ary = getattr(namespace, self.dest)
        if ary is None:
            ary = []

        if isinstance(values, str):
            # Support list syntax for comma separated lists as well
            if self.delimiter == "," and values.startswith("[") and values.endswith("]"):
                values = values[1:-1]

            # Make sure delimiters between quotes are ignored.
            # Inspired by https://stackoverflow.com/a/2787979.
            values = [x.strip() for x in re.split(f"""{self.delimiter}(?=(?:[^'"]|'[^']*'|"[^"]*")*$)""", values) if x]

        if isinstance(values, list):
            for x in values:
                if self.list_choices is not None and x not in self.list_choices:
                    raise ValueError(f"Unknown value {x!r}")

                # Remove ! prefixed list entries from list. !* removes all entries. This works for strings only now.
                if x == "!*":
                    ary = []
                elif isinstance(x, str) and x.startswith("!"):
                    if x[1:] in ary:
                        ary.remove(x[1:])
                else:
                    ary.append(x)
        else:
            ary.append(values)

        ary = remove_duplicates(ary)
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
        super().__init__(option_strings, dest, nargs="?", const=const, default=default, **kwargs)

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
            raise argparse.ArgumentError(self, f"Invalid argument for {option_string}: {values}")

        # invert the value if the argument name starts with "not" or "without"
        for option in self.option_strings:
            if option[2:].startswith("not-") or option[2:].startswith("without-"):
                new_value = not new_value
                break

        setattr(namespace, self.dest, new_value)


class CleanPackageMetadataAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:

        if isinstance(values, str) and values == "auto":
            setattr(namespace, self.dest, "auto")
        else:
            super().__call__(parser, namespace, values, option_string)


class WithNetworkAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:

        if isinstance(values, str) and values == "never":
            setattr(namespace, self.dest, "never")
        else:
            super().__call__(parser, namespace, values, option_string)


class VerityAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:

        if isinstance(values, str):
            if values == "signed":
                setattr(namespace, self.dest, "signed")
                return

        super().__call__(parser, namespace, values, option_string)


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string


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
        "WorkspaceDirectory": "--workspace-dir",
        "XZ": "--compress-output=xz",
        "NSpawnSettings": "--settings",
        "ESPSize": "--esp-size",
        "CheckSum": "--checksum",
        "BMap": "--bmap",
        "Packages": "--package",
        "RemovePackages": "--remove-package",
        "ExtraTrees": "--extra-tree",
        "SkeletonTrees": "--skeleton-tree",
        "BuildPackages": "--build-package",
        "PostInstallationScript": "--postinst-script",
        "GPTFirstLBA": "--gpt-first-lba",
        "TarStripSELinuxContext": "--tar-strip-selinux-context",
        "MachineID": "--machine-id"
    }

    fromfile_prefix_chars: str = "@"

    def __init__(self, *kargs: Any, **kwargs: Any) -> None:
        self._ini_file_section = ""
        self._ini_file_key = ""  # multi line list processing
        self._ini_file_list_mode = False

        # Add config files to be parsed
        kwargs["fromfile_prefix_chars"] = ArgumentParserMkosi.fromfile_prefix_chars
        kwargs["formatter_class"] = CustomHelpFormatter

        super().__init__(*kargs, **kwargs)

    @staticmethod
    def _camel_to_arg(camel: str) -> str:
        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1-\2", camel)
        return re.sub("([a-z0-9])([A-Z])", r"\1-\2", s1).lower()

    @classmethod
    def _ini_key_to_cli_arg(cls, key: str) -> str:
        return cls.SPECIAL_MKOSI_DEFAULT_PARAMS.get(key) or ("--" + cls._camel_to_arg(key))

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
                config = configparser.RawConfigParser(delimiters="=", inline_comment_prefixes=("#",))
                config.optionxform = str  # type: ignore
                with open(arg_string[1:]) as args_file:
                    config.read_file(args_file)

                # Rename old [Packages] section to [Content]
                if config.has_section("Packages") and not config.has_section("Content"):
                    config.read_dict({"Content": dict(config.items("Packages"))})
                    config.remove_section("Packages")

                for section in config.sections():
                    for key, value in config.items(section):
                        cli_arg = self._ini_key_to_cli_arg(key)

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


def parse_base_packages(value: str) -> Union[str, bool]:
    if value == "conditional":
        return value
    return parse_boolean(value)


def parse_remove_files(value: str) -> List[str]:
    """Normalize paths as relative to / to ensure we don't go outside of our root."""

    # os.path.normpath() leaves leading '//' untouched, even though it normalizes '///'.
    # This follows POSIX specification, see
    # https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_13.
    # Let's use lstrip() to handle zero or more leading slashes correctly.
    return ["/" + os.path.normpath(p).lstrip("/") for p in value.split(",") if p]


def parse_ssh_agent(value: str) -> Optional[Path]:
    """Will return None or a path to a socket."""

    if not value:
        return None

    try:
        if not parse_boolean(value):
            return None
    except ValueError:
        pass
    else:
        value = os.getenv("SSH_AUTH_SOCK", "")
        if not value:
            die("--ssh-agent=true but $SSH_AUTH_SOCK is not set (consider running 'sudo' with '-E')")

    sock = Path(value)
    if not sock.is_socket():
        die(f"SSH agent socket {sock} is not an AF_UNIX socket")
    return sock


def create_parser() -> ArgumentParserMkosi:
    parser = ArgumentParserMkosi(prog="mkosi", description="Build Bespoke OS Images", add_help=False)

    group = parser.add_argument_group("Commands")
    group.add_argument("verb", type=Verb, choices=list(Verb), default=Verb.build, help="Operation to execute")
    group.add_argument(
        "cmdline", nargs=argparse.REMAINDER, help="The command line to use for " + str([verb.name for verb in MKOSI_COMMANDS_CMDLINE])[1:-1]
    )
    group.add_argument("-h", "--help", action="help", help="Show this help")
    group.add_argument("--version", action="version", version="%(prog)s " + __version__)

    group = parser.add_argument_group("Distribution")
    group.add_argument("-d", "--distribution", choices=Distribution.__members__, help="Distribution to install")
    group.add_argument("-r", "--release", help="Distribution release to install")
    group.add_argument("-m", "--mirror", help="Distribution mirror to use")
    group.add_argument(
        "--repositories", action=CommaDelimitedListAction, default=[], help="Repositories to use", metavar="REPOS"
    )
    group.add_argument(
        "--use-host-repositories",
        action=BooleanAction,
        help="Use host's existing software repositories (only for dnf-based distributions)",
    )
    group.add_argument("--repository-directory", metavar="PATH", dest="repos_dir",
                       help="Directory container extra distribution specific repository files")
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
    group.add_argument(
        "--manifest-format",
        action=CommaDelimitedListAction,
        type=cast(Callable[[str], ManifestFormat], ManifestFormat.parse_list),
        help="Manifest Format",
    )
    group.add_argument(
        "-o", "--output",
        help="Output image path",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--output-split-root",
        help="Output root or /usr/ partition image path (if --split-artifacts is used)",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--output-split-verity",
        help="Output Verity partition image path (if --split-artifacts is used)",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--output-split-verity-sig",
        help="Output Verity Signature partition image path (if --split-artifacts is used)",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--output-split-kernel",
        help="Output kernel path (if --split-artifacts is used)",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "-O", "--output-dir",
        help="Output root directory",
        type=Path,
        metavar="DIR",
    )
    group.add_argument(
        "--workspace-dir",
        help="Workspace directory",
        type=Path,
        metavar="DIR",
    )
    group.add_argument(
        "-f",
        "--force",
        action="count",
        dest="force",
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
    group.add_argument(
        "--secure-boot-key",
        help="UEFI SecureBoot private key in PEM format",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--secure-boot-certificate",
        help="UEFI SecureBoot certificate in X509 format",
        type=Path,
        metavar="PATH",
    )
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
    group.add_argument(
        "--verity",
        action=VerityAction,
        help="Add integrity partition, and optionally sign it (implies --read-only)",
    )
    group.add_argument(
        "--compress",
        type=parse_compression,
        nargs="?",
        metavar="ALG",
        help="Enable compression (in-fs if supported, whole-output otherwise)",
    )
    group.add_argument(
        "--compress-fs",
        type=parse_compression,
        nargs="?",
        metavar="ALG",
        help="Enable in-filesystem compression (gpt_btrfs, subvolume, gpt_squashfs, plain_squashfs)",
    )
    group.add_argument(
        "--compress-output",
        type=parse_compression,
        nargs="?",
        metavar="ALG",
        help="Enable whole-output compression (with images or archives)",
    )
    group.add_argument(
        "--mksquashfs", dest="mksquashfs_tool", type=str.split, default=[], help="Script to call instead of mksquashfs"
    )
    group.add_argument(
        "--xz",
        action="store_const",
        dest="compress_output",
        const="xz",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--qcow2",
        action=BooleanAction,
        help="Convert resulting image to qcow2 (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    group.add_argument("--hostname", help="Set hostname")
    group.add_argument("--image-version", help="Set version for image")
    group.add_argument("--image-id", help="Set ID for image")
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
    group.add_argument(
        "--split-artifacts", action=BooleanAction, help="Generate split out root/verity/kernel images, too"
    )

    group = parser.add_argument_group("Content")
    group.add_argument(
        "--base-packages",
        type=parse_base_packages,
        default=True,
        help="Automatically inject basic packages in the system (systemd, kernel, …)",
        metavar="OPTION",
    )
    group.add_argument(
        "-p",
        "--package",
        action=CommaDelimitedListAction,
        dest="packages",
        default=[],
        help="Add an additional package to the OS image",
        metavar="PACKAGE",
    )
    group.add_argument(
        "--remove-package",
        action=CommaDelimitedListAction,
        dest="remove_packages",
        default=[],
        help="Remove package from the image OS image after installation",
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
    group.add_argument(
        "--machine-id",
        help="Defines a fixed machine ID for all our build-time runs.",
        metavar="MACHINE_ID"
    )

    group.add_argument("--password", help="Set the root password")
    group.add_argument(
        "--password-is-hashed", action=BooleanAction, help="Indicate that the root password has already been hashed"
    )
    group.add_argument("--autologin", action=BooleanAction, help="Enable root autologin")

    group.add_argument(
        "--cache",
        dest="cache_path",
        help="Package cache path",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--extra-tree",
        action=CommaDelimitedListAction,
        dest="extra_trees",
        default=[],
        help="Copy an extra tree on top of image",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--skeleton-tree",
        action="append",
        dest="skeleton_trees",
        default=[],
        help="Use a skeleton tree to bootstrap the image before installing anything",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--clean-package-metadata",
        action=CleanPackageMetadataAction,
        help="Remove package manager database and other files",
        default='auto',
    )
    group.add_argument(
        "--remove-files",
        action=CommaDelimitedListAction,
        default=[],
        help="Remove files from built image",
        type=parse_remove_files,
        metavar="GLOB",
    )
    group.add_argument(
        "--environment",
        "-E",
        action=SpaceDelimitedListAction,
        default=[],
        help="Set an environment variable when running scripts",
        metavar="NAME[=VALUE]",
    )
    group.add_argument(
        "--build-environment",  # Compatibility option
        action=SpaceDelimitedListAction,
        default=[],
        dest="environment",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--build-sources",
        help="Path for sources to build",
        metavar="PATH",
        type=Path,
    )
    group.add_argument(
        "--build-dir",  # Compatibility option
        help=argparse.SUPPRESS,
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--build-directory",
        dest="build_dir",
        help="Path to use as persistent build directory",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--include-directory",
        dest="include_dir",
        help="Path to use as persistent include directory",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--install-directory",
        dest="install_dir",
        help="Path to use as persistent install directory",
        type=Path,
        metavar="PATH",
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
    group.add_argument(
        "--build-script",
        help="Build script to run inside image",
        type=script_path,
        metavar="PATH",
    )
    group.add_argument(
        "--prepare-script",
        help="Prepare script to run inside the image before it is cached",
        type=script_path,
        metavar="PATH",
    )
    group.add_argument(
        "--postinst-script",
        help="Postinstall script to run inside image",
        type=script_path,
        metavar="PATH",
    )
    group.add_argument(
        "--finalize-script",
        help="Postinstall script to run outside image",
        type=script_path,
        metavar="PATH",
    )
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
        "--source-resolve-symlinks",
        action=BooleanAction,
        help="If given, any symbolic links in the build sources are resolved and the file contents copied to the"
        + " build image. If not given, they are left as symbolic links in the build image."
        + " Only applies if --source-file-transfer is set to 'copy-all'. (default: keep as symbolic links)",
    )
    group.add_argument(
        "--source-resolve-symlinks-final",
        action=BooleanAction,
        help="If given, any symbolic links in the build sources are resolved and the file contents copied to the"
        + " final image. If not given, they are left as symbolic links in the final image."
        + " Only applies if --source-file-transfer-final is set to 'copy-all'. (default: keep as symbolic links)",
    )
    group.add_argument(
        "--with-network",
        action=WithNetworkAction,
        help="Run build and postinst scripts with network access (instead of private network)",
    )
    group.add_argument(
        "--settings",
        dest="nspawn_settings",
        help="Add in .nspawn settings file",
        type=Path,
        metavar="PATH",
    )

    group = parser.add_argument_group("Partitions")
    group.add_argument('--base-image',
                       help='Use the given image as base (e.g. lower sysext layer)',
                       type=Path,
                       metavar='IMAGE')
    group.add_argument(
        "--root-size", help="Set size of root partition (only gpt_ext4, gpt_xfs, gpt_btrfs)", metavar="BYTES"
    )
    group.add_argument(
        "--esp-size",
        help="Set size of EFI system partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
        metavar="BYTES",
    )
    group.add_argument(
        "--xbootldr-size",
        help="Set size of the XBOOTLDR partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
        metavar="BYTES",
    )
    group.add_argument(
        "--swap-size",
        help="Set size of swap partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
        metavar="BYTES",
    )
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
    group.add_argument(
        "--usr-only", action=BooleanAction, help="Generate a /usr/ partition instead of a root partition"
    )

    group = parser.add_argument_group("Validation (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs, tar, cpio)")
    group.add_argument("--checksum", action=BooleanAction, help="Write SHA256SUMS file")
    group.add_argument("--sign", action=BooleanAction, help="Write and sign SHA256SUMS file")
    group.add_argument("--key", help="GPG key to use for signing")
    group.add_argument(
        "--bmap",
        action=BooleanAction,
        help="Write block map file (.bmap) for bmaptool usage (only gpt_ext4, gpt_btrfs)",
    )

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
    group.add_argument("--qemu-smp", help="Configure guest's SMP settings", metavar="SMP", default="2")
    group.add_argument("--qemu-mem", help="Configure guest's RAM size", metavar="MEM", default="1G")
    group.add_argument("--qemu-kvm", action=BooleanAction, help="Configure whether to use KVM or not",
                       default=qemu_check_kvm_support())
    group.add_argument(
        "--qemu-args",
        action=SpaceDelimitedListAction,
        default=[],
        # Suppress the command line option because it's already possible to pass qemu args as normal
        # arguments.
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--nspawn-keep-unit",
        action=BooleanAction,
        help="If specified, underlying systemd-nspawn containers use the ressources of the current unit."
    )
    group.add_argument(
        "--network-veth",
        dest="netdev",
        action=BooleanAction,
        help=argparse.SUPPRESS,
    ) # Compatibility option
    group.add_argument(
        "--netdev",
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
        "--ssh", action=BooleanAction, help="Set up SSH access from the host to the final image via 'mkosi ssh'"
    )
    group.add_argument(
        "--ssh-key",
        type=Path,
        metavar="PATH",
        help="Use the specified private key when using 'mkosi ssh' (requires a corresponding public key)",
    )
    group.add_argument(
        "--ssh-timeout",
        metavar="SECONDS",
        type=int,
        default=0,
        help="Wait up to SECONDS seconds for the SSH connection to be available when using 'mkosi ssh'",
    )
    group.add_argument(
        "--ssh-agent",
        type=parse_ssh_agent,
        default="",
        metavar="PATH",
        help="Path to the ssh agent socket, or true to use $SSH_AUTH_SOCK.",
    )
    group.add_argument(
        "--ssh-port",
        type=int,
        default=22,
        metavar="PORT",
        help="If specified, 'mkosi ssh' will use this port to connect",
    )

    group = parser.add_argument_group("Additional Configuration")
    group.add_argument(
        "-C", "--directory",
        help="Change to specified directory before doing anything",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--default",
        dest="default_path",
        help="Read configuration data from file",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "-a", "--all", action="store_true", dest="all", default=False, help="Build all settings files in mkosi.files/"
    )
    group.add_argument(
        "--all-directory",
        dest="all_directory",
        help="Specify path to directory to read settings files from",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "-B",
        "--auto-bump",
        action=BooleanAction,
        help="Automatically bump image version after building",
    )
    group.add_argument(
        "--debug",
        action=CommaDelimitedListAction,
        default=[],
        help="Turn on debugging output",
        choices=("run", "build-script", "workspace-command", "disk"),
    )
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    return parser


def load_distribution(args: argparse.Namespace) -> argparse.Namespace:
    if args.distribution is not None:
        args.distribution = Distribution[args.distribution]

    if args.distribution is None or args.release is None:
        d, r = detect_distribution()

        if args.distribution is None:
            args.distribution = d

    if args.distribution is None:
        die("Couldn't detect distribution.")

    return args


def parse_args(argv: Optional[Sequence[str]] = None) -> Dict[str, argparse.Namespace]:
    """Load default values from files and parse command line arguments

    Do all about default files and command line arguments parsing. If --all argument is passed
    more than one job needs to be processed. The returned tuple contains MkosiArgs
    valid for all jobs as well as a dict containing the arguments per job.
    """
    parser = create_parser()

    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)  # make a copy 'cause we'll be modifying the list later on

    # If ArgumentParserMkosi loads settings from mkosi.default files, the settings from files
    # are converted to command line arguments. This breaks ArgumentParser's support for default
    # values of positional arguments. Make sure the verb command gets explicitly passed.
    # Insert a -- before the positional verb argument otherwise it might be considered as an argument of
    # a parameter with nargs='?'. For example mkosi -i summary would be treated as -i=summary.
    for verb in Verb:
        try:
            v_i = argv.index(verb.name)
        except ValueError:
            continue

        if v_i > 0 and argv[v_i - 1] != "--":
            argv.insert(v_i, "--")
        break
    else:
        argv += ["--", "build"]

    # First run of command line arguments parsing to get the directory of mkosi.default file and the verb argument.
    args_pre_parsed, _ = parser.parse_known_args(argv)

    if args_pre_parsed.verb == Verb.help:
        parser.print_help()
        sys.exit(0)

    # Make sure all paths are absolute and valid.
    # Relative paths are not valid yet since we are not in the final working directory yet.
    if args_pre_parsed.directory is not None:
        directory = args_pre_parsed.directory = args_pre_parsed.directory.absolute()
    else:
        directory = Path.cwd()

    # Note that directory will be ignored if .all_directory or .default_path are absolute
    all_directory = directory / (args_pre_parsed.all_directory or "mkosi.files")
    default_path = directory / (args_pre_parsed.default_path or "mkosi.default")
    if args_pre_parsed.default_path and not default_path.exists():
        die(f"No config file found at {default_path}")

    if args_pre_parsed.all and args_pre_parsed.default_path:
        die("--all and --default= may not be combined.")

    # Parse everything in --all mode
    args_all = {}
    if args_pre_parsed.all:
        if not os.path.isdir(all_directory):
            die(f"all-directory {all_directory} does not exist")
        for f in os.scandir(all_directory):
            if not f.name.startswith("mkosi."):
                continue
            args = parse_args_file(argv, Path(f.path))
            args_all[f.name] = args
    # Parse everything in normal mode
    else:
        args = parse_args_file_group(argv, os.fspath(default_path))

        args = load_distribution(args)

        if args.distribution:
            # Parse again with any extra distribution files included.
            args = parse_args_file_group(argv, os.fspath(default_path), args.distribution)

        args_all["default"] = args

    return args_all


def parse_args_file(argv: List[str], default_path: Path) -> argparse.Namespace:
    """Parse just one mkosi.* file (--all mode)."""

    # Parse all parameters handled by mkosi.
    # Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    argv = argv[:1] + [f"{ArgumentParserMkosi.fromfile_prefix_chars}{default_path}"] + argv[1:]

    return create_parser().parse_args(argv)


def parse_args_file_group(
    argv: List[str], default_path: str, distribution: Optional[Distribution] = None
) -> argparse.Namespace:
    """Parse a set of mkosi.default and mkosi.default.d/* files."""
    # Add the @ prefixed filenames to current argument list in inverse priority order.
    defaults_files = []

    if os.path.isfile(default_path):
        defaults_files += [f"{ArgumentParserMkosi.fromfile_prefix_chars}{default_path}"]

    defaults_dir = "mkosi.default.d"
    if os.path.isdir(defaults_dir):
        for file in sorted(os.listdir(defaults_dir)):
            path = os.path.join(defaults_dir, file)
            if os.path.isfile(path):
                defaults_files += [f"{ArgumentParserMkosi.fromfile_prefix_chars}{path}"]

    if distribution is not None:
        distribution_dir = f"mkosi.default.d/{distribution}"
        if os.path.isdir(distribution_dir):
            for subdir in sorted(os.listdir(distribution_dir)):
                path = os.path.join(distribution_dir, subdir)
                if os.path.isfile(path):
                    defaults_files += [f"{ArgumentParserMkosi.fromfile_prefix_chars}{path}"]

    # Parse all parameters handled by mkosi.
    # Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    return create_parser().parse_args(defaults_files + argv)


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

    if dist_id == "clear-linux-os":
        dist_id = "clear"

    d: Optional[Distribution] = None
    for the_id in [dist_id, *dist_id_like]:
        d = Distribution.__members__.get(the_id, None)
        if d is not None:
            break

    if d in {Distribution.debian, Distribution.ubuntu} and (version_codename or extracted_codename):
        # debootstrap needs release codenames, not version numbers
        version_id = version_codename or extracted_codename

    return d, version_id


def unlink_try_hard(path: Optional[PathString]) -> None:
    if path is None:
        return

    path = Path(path)
    try:
        return path.unlink()
    except FileNotFoundError:
        return
    except Exception:
        pass

    if shutil.which("btrfs"):
        try:
            btrfs_subvol_delete(path)
            return
        except Exception:
            pass

    shutil.rmtree(path)


def remove_glob(*patterns: PathString) -> None:
    pathgen = (glob.glob(str(pattern)) for pattern in patterns)
    paths: Set[str] = set(sum(pathgen, []))  # uniquify
    for path in paths:
        unlink_try_hard(Path(path))


def empty_directory(path: Path) -> None:
    try:
        for f in os.listdir(path):
            unlink_try_hard(path / f)
    except FileNotFoundError:
        pass


def unlink_output(args: MkosiArgs) -> None:
    if not args.force and args.verb != Verb.clean:
        return

    if not args.skip_final_phase:
        with complete_step("Removing output files…"):
            unlink_try_hard(args.output)
            unlink_try_hard(f"{args.output}.manifest")
            unlink_try_hard(f"{args.output}.changelog")

            if args.checksum:
                unlink_try_hard(args.output_checksum)

            if args.verity:
                unlink_try_hard(args.output_root_hash_file)
            if args.verity == "signed":
                unlink_try_hard(args.output_root_hash_p7s_file)

            if args.sign:
                unlink_try_hard(args.output_signature)

            if args.bmap:
                unlink_try_hard(args.output_bmap)

            if args.split_artifacts:
                unlink_try_hard(args.output_split_root)
                unlink_try_hard(args.output_split_verity)
                unlink_try_hard(args.output_split_verity_sig)
                unlink_try_hard(args.output_split_kernel)

            if args.nspawn_settings is not None:
                unlink_try_hard(args.output_nspawn_settings)

        if args.ssh and args.output_sshkey is not None:
            unlink_try_hard(args.output_sshkey)

    # We remove any cached images if either the user used --force
    # twice, or he/she called "clean" with it passed once. Let's also
    # remove the downloaded package cache if the user specified one
    # additional "--force".

    if args.verb == Verb.clean:
        remove_build_cache = args.force > 0
        remove_package_cache = args.force > 1
    else:
        remove_build_cache = args.force > 1
        remove_package_cache = args.force > 2

    if remove_build_cache:
        if args.cache_pre_dev is not None or args.cache_pre_inst is not None:
            with complete_step("Removing incremental cache files…"):
                if args.cache_pre_dev is not None:
                    unlink_try_hard(args.cache_pre_dev)

                if args.cache_pre_inst is not None:
                    unlink_try_hard(args.cache_pre_inst)

        if args.build_dir is not None:
            with complete_step("Clearing out build directory…"):
                empty_directory(args.build_dir)

        if args.include_dir is not None:
            with complete_step("Clearing out include directory…"):
                empty_directory(args.include_dir)

        if args.install_dir is not None:
            with complete_step("Clearing out install directory…"):
                empty_directory(args.install_dir)

    if remove_package_cache:
        if args.cache_path is not None:
            with complete_step("Clearing out package cache…"):
                empty_directory(args.cache_path)


def parse_boolean(s: str) -> bool:
    "Parse 1/true/yes/y/t/on as true and 0/false/no/n/f/off/None as false"
    s_l = s.lower()
    if s_l in {"1", "true", "yes", "y", "t", "on"}:
        return True

    if s_l in {"0", "false", "no", "n", "f", "off"}:
        return False

    raise ValueError(f"Invalid literal for bool(): {s!r}")


def find_nspawn_settings(args: argparse.Namespace) -> None:
    if args.nspawn_settings is not None:
        return

    if os.path.exists("mkosi.nspawn"):
        args.nspawn_settings = "mkosi.nspawn"


def find_extra(args: argparse.Namespace) -> None:

    if len(args.extra_trees) > 0:
        return

    if os.path.isdir("mkosi.extra"):
        args.extra_trees.append(Path("mkosi.extra"))
    if os.path.isfile("mkosi.extra.tar"):
        args.extra_trees.append(Path("mkosi.extra.tar"))


def find_skeleton(args: argparse.Namespace) -> None:

    if len(args.skeleton_trees) > 0:
        return

    if os.path.isdir("mkosi.skeleton"):
        args.skeleton_trees.append(Path("mkosi.skeleton"))
    if os.path.isfile("mkosi.skeleton.tar"):
        args.skeleton_trees.append(Path("mkosi.skeleton.tar"))


def args_find_path(args: argparse.Namespace, name: str, path: str, *, as_list: bool = False) -> None:
    if getattr(args, name) is not None:
        return
    abspath = Path(path).absolute()
    if abspath.exists():
        setattr(args, name, [abspath] if as_list else abspath)


def find_cache(args: argparse.Namespace) -> None:
    if args.cache_path is not None:
        return

    if os.path.exists("mkosi.cache/"):
        dirname = args.distribution.name

        # Clear has a release number that can be used, however the
        # cache is valid (and more efficient) across releases.
        if args.distribution != Distribution.clear and args.release is not None:
            dirname += "~" + args.release

        args.cache_path = Path("mkosi.cache", dirname)


def require_private_file(name: str, description: str) -> None:
    mode = os.stat(name).st_mode & 0o777
    if mode & 0o007:
        warn(dedent(f"""\
            Permissions of '{name}' of '{mode:04o}' are too open.
            When creating {description} files use an access mode that restricts access to the owner only.
        """))


def find_passphrase(args: argparse.Namespace) -> None:
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


def find_password(args: argparse.Namespace) -> None:
    if args.password is not None:
        return

    try:
        require_private_file("mkosi.rootpw", "root password")

        with open("mkosi.rootpw") as f:
            args.password = f.read().strip()

    except FileNotFoundError:
        pass


def find_secure_boot(args: argparse.Namespace) -> None:
    if not args.secure_boot and args.verity != "signed":
        return

    if args.secure_boot_key is None:
        if os.path.exists("mkosi.secure-boot.key"):
            args.secure_boot_key = Path("mkosi.secure-boot.key")

    if args.secure_boot_certificate is None:
        if os.path.exists("mkosi.secure-boot.crt"):
            args.secure_boot_certificate = Path("mkosi.secure-boot.crt")


def find_image_version(args: argparse.Namespace) -> None:
    if args.image_version is not None:
        return

    try:
        with open("mkosi.version") as f:
            args.image_version = f.read().strip()
    except FileNotFoundError:
        pass


KNOWN_SUFFIXES = {
    ".xz",
    ".zstd",
    ".raw",
    ".tar",
    ".cpio",
    ".qcow2",
}


def strip_suffixes(path: Path) -> Path:
    while path.suffix in KNOWN_SUFFIXES:
        path = path.with_suffix("")
    return path


def xescape(s: str) -> str:
    "Escape a string udev-style, for inclusion in /dev/disk/by-*/* symlinks"

    ret = ""
    for c in s:
        if ord(c) <= 32 or ord(c) >= 127 or c == "/":
            ret = ret + "\\x%02x" % ord(c)
        else:
            ret = ret + str(c)

    return ret


def build_auxiliary_output_path(args: argparse.Namespace, suffix: str, can_compress: bool = False) -> Path:
    output = strip_suffixes(args.output)
    compression = should_compress_output(args) if can_compress else False
    return output.with_name(f"{output.name}{suffix}{compression or ''}")


DISABLED = Path('DISABLED')  # A placeholder value to suppress autodetection.
                             # This is used as a singleton, i.e. should be compared with
                             # 'is' in other parts of the code.

def script_path(value: Optional[str]) -> Optional[Path]:
    if value is None:
        return None
    if value == '':
        return DISABLED
    return Path(value)


def normalize_script(path: Optional[Path]) -> Optional[Path]:
    if not path or path is DISABLED:
        return None
    path = Path(path).absolute()
    if not path.exists():
        die(f"{path} does not exist")
    if not path.is_file():
        die(f"{path} is not a file")
    if not os.access(path, os.X_OK):
        die(f"{path} is not executable")
    return path


def load_args(args: argparse.Namespace) -> MkosiArgs:
    global ARG_DEBUG
    ARG_DEBUG.update(args.debug)

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
    args_find_path(args, "workspace_dir", "mkosi.workspace/")
    args_find_path(args, "mksquashfs_tool", "mkosi.mksquashfs-tool", as_list=True)
    args_find_path(args, "repos_dir", "mkosi.reposdir/")

    find_extra(args)
    find_skeleton(args)
    find_password(args)
    find_passphrase(args)
    find_secure_boot(args)
    find_image_version(args)

    args.extra_search_paths = expand_paths(args.extra_search_paths)

    if args.cmdline and args.verb not in MKOSI_COMMANDS_CMDLINE:
        die("Additional parameters only accepted for " + str([verb.name for verb in MKOSI_COMMANDS_CMDLINE])[1:-1] + " invocations.")

    if args.output_format is None:
        args.output_format = OutputFormat.gpt_ext4

    args = load_distribution(args)

    if args.release is None:
        if args.distribution == Distribution.fedora:
            args.release = "36"
        elif args.distribution in (Distribution.centos, Distribution.centos_epel):
            args.release = "9-stream"
        elif args.distribution in (Distribution.rocky, Distribution.rocky_epel):
            args.release = "8"
        elif args.distribution in (Distribution.alma, Distribution.alma_epel):
            args.release = "8"
        elif args.distribution == Distribution.mageia:
            args.release = "7"
        elif args.distribution == Distribution.debian:
            args.release = "testing"
        elif args.distribution == Distribution.ubuntu:
            args.release = "jammy"
        elif args.distribution == Distribution.opensuse:
            args.release = "tumbleweed"
        elif args.distribution == Distribution.clear:
            args.release = "latest"
        elif args.distribution == Distribution.photon:
            args.release = "3.0"
        elif args.distribution == Distribution.openmandriva:
            args.release = "cooker"
        elif args.distribution == Distribution.gentoo:
            args.release = "17.1"
        else:
            args.release = "rolling"

    if args.bootable:
        if args.output_format in (
            OutputFormat.directory,
            OutputFormat.subvolume,
            OutputFormat.tar,
            OutputFormat.cpio,
            OutputFormat.plain_squashfs,
        ):
            die("Directory, subvolume, tar, cpio, and plain squashfs images cannot be booted.", MkosiNotSupportedException)

        if not args.boot_protocols:
            args.boot_protocols = ["uefi"]

            if args.distribution == Distribution.photon:
                args.boot_protocols = ["bios"]

        if not {"uefi", "bios"}.issuperset(args.boot_protocols):
            die("Not a valid boot protocol")

        if "uefi" in args.boot_protocols and args.distribution == Distribution.photon:
            die(f"uefi boot not supported for {args.distribution}", MkosiNotSupportedException)

    if args.distribution in (Distribution.centos, Distribution.centos_epel):
        epel_release = parse_epel_release(args.release)
        if epel_release <= 9 and args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, CentOS {epel_release} does not support btrfs", MkosiNotSupportedException)
        if epel_release <= 7 and args.bootable and "uefi" in args.boot_protocols and args.with_unified_kernel_images:
            die(
                f"Sorry, CentOS {epel_release} does not support unified kernel images. "
                "You must use --without-unified-kernel-images.", MkosiNotSupportedException
            )

    if args.distribution in (Distribution.rocky, Distribution.rocky_epel):
        epel_release = int(args.release.split(".")[0])
        if epel_release == 8 and args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, Rocky {epel_release} does not support btrfs", MkosiNotSupportedException)

    if args.distribution in (Distribution.alma, Distribution.alma_epel):
        epel_release = int(args.release.split(".")[0])
        if epel_release == 8 and args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, Alma {epel_release} does not support btrfs", MkosiNotSupportedException)

    # Remove once https://github.com/clearlinux/clr-boot-manager/pull/238 is merged and available.
    if args.distribution == Distribution.clear and args.output_format == OutputFormat.gpt_btrfs:
        die("Sorry, Clear Linux does not support btrfs", MkosiNotSupportedException)

    if args.distribution == Distribution.clear and "," in args.boot_protocols:
        die("Sorry, Clear Linux does not support hybrid BIOS/UEFI images", MkosiNotSupportedException)

    if shutil.which("bsdtar") and args.distribution == Distribution.openmandriva and args.tar_strip_selinux_context:
        die("Sorry, bsdtar on OpenMandriva is incompatible with --tar-strip-selinux-context", MkosiNotSupportedException)

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
        elif args.distribution in (Distribution.rocky, Distribution.rocky_epel):
            args.mirror = None
        elif args.distribution in (Distribution.alma, Distribution.alma_epel):
            args.mirror = None

    if args.minimize and not args.output_format.can_minimize():
        die("Minimal file systems only supported for ext4 and btrfs.", MkosiNotSupportedException)

    if is_generated_root(args) and args.incremental:
        die("Sorry, incremental mode is currently not supported for squashfs or minimized file systems.", MkosiNotSupportedException)

    if args.encrypt is not None:
        if not args.output_format.is_disk():
            die("Encryption is only supported for disk images.", MkosiNotSupportedException)

        if args.encrypt == "data" and args.output_format == OutputFormat.gpt_btrfs:
            die("'data' encryption mode not supported on btrfs, use 'all' instead.", MkosiNotSupportedException)

        if args.encrypt == "all" and args.verity:
            die("'all' encryption mode may not be combined with Verity.", MkosiNotSupportedException)

    if args.sign:
        args.checksum = True

    if args.output is None:
        iid = args.image_id if args.image_id is not None else "image"
        prefix = f"{iid}_{args.image_version}" if args.image_version is not None else iid

        if args.output_format.is_disk():
            compress = should_compress_output(args)
            output = prefix + (".qcow2" if args.qcow2 else ".raw") + (f".{compress}" if compress else "")
        elif args.output_format == OutputFormat.tar:
            output = f"{prefix}.tar.xz"
        elif args.output_format == OutputFormat.cpio:
            output = f"{prefix}.cpio" + (f".{args.compress}" if args.compress else "")
        else:
            output = prefix
        args.output = Path(output)

    if args.manifest_format is None:
        args.manifest_format = [ManifestFormat.json]

    if args.output_dir is not None:
        args.output_dir = args.output_dir.absolute()

        if "/" not in str(args.output):
            args.output = args.output_dir / args.output
        else:
            warn("Ignoring configured output directory as output file is a qualified path.")

    if args.incremental or args.verb == Verb.clean:
        if args.image_id is not None:
            # If the image ID is specified, use cache file names that are independent of the image versions, so that
            # rebuilding and bumping versions is cheap and reuses previous versions if cached.
            if args.output_dir:
                args.cache_pre_dev = args.output_dir / f"{args.image_id}.cache-pre-dev"
                args.cache_pre_inst = args.output_dir / f"{args.image_id}.cache-pre-inst"
            else:
                args.cache_pre_dev = Path(f"{args.image_id}.cache-pre-dev")
                args.cache_pre_inst = Path(f"{args.image_id}.cache-pre-inst")
        else:
            # Otherwise, derive the cache file names directly from the output file names.
            args.cache_pre_dev = Path(f"{args.output}.cache-pre-dev")
            args.cache_pre_inst = Path(f"{args.output}.cache-pre-inst")
    else:
        args.cache_pre_dev = None
        args.cache_pre_inst = None

    args.output = args.output.absolute()

    if args.output_format == OutputFormat.tar:
        args.compress_output = "xz"
    if not args.output_format.is_disk():
        args.split_artifacts = False

    if args.output_format.is_squashfs():
        args.read_only = True
        args.root_size = None
        if args.compress is False:
            die("Cannot disable compression with squashfs", MkosiNotSupportedException)
        if args.compress is None:
            args.compress = True

    if args.verity:
        args.read_only = True
        args.output_root_hash_file = build_auxiliary_output_path(args, roothash_suffix(args.usr_only))

        if args.verity == "signed":
            args.output_root_hash_p7s_file = build_auxiliary_output_path(args, roothash_p7s_suffix(args.usr_only))

    if args.checksum:
        args.output_checksum = args.output.with_name("SHA256SUMS")

    if args.sign:
        args.output_signature = args.output.with_name("SHA256SUMS.gpg")

    if args.bmap:
        args.output_bmap = build_auxiliary_output_path(args, ".bmap")

    if args.nspawn_settings is not None:
        args.nspawn_settings = args.nspawn_settings.absolute()
        args.output_nspawn_settings = build_auxiliary_output_path(args, ".nspawn")

    # We want this set even if --ssh is not specified so we can find the SSH key when verb == "ssh".
    if args.ssh_key is None and args.ssh_agent is None:
        args.output_sshkey = args.output.with_name("id_rsa")

    if args.split_artifacts:
        args.output_split_root = build_auxiliary_output_path(args, ".usr" if args.usr_only else ".root", True)
        if args.verity:
            args.output_split_verity = build_auxiliary_output_path(args, ".verity", True)
            if args.verity == "signed":
                args.output_split_verity_sig = build_auxiliary_output_path(args, ".verity-sig", True)
        if args.bootable:
            args.output_split_kernel = build_auxiliary_output_path(args, ".efi", True)

    if args.build_sources is not None:
        args.build_sources = args.build_sources.absolute()

    if args.build_dir is not None:
        args.build_dir = args.build_dir.absolute()

    if args.include_dir is not None:
        args.include_dir = args.include_dir.absolute()

    if args.install_dir is not None:
        args.install_dir = args.install_dir.absolute()

    args.build_script = normalize_script(args.build_script)
    args.prepare_script = normalize_script(args.prepare_script)
    args.postinst_script = normalize_script(args.postinst_script)
    args.finalize_script = normalize_script(args.finalize_script)

    if args.environment:
        env = {}
        for s in args.environment:
            key, _, value = s.partition("=")
            value = value or os.getenv(key, "")
            env[key] = value
        args.environment = env
    else:
        args.environment = {}

    if args.cache_path is not None:
        args.cache_path = args.cache_path.absolute()

    if args.extra_trees:
        for i in range(len(args.extra_trees)):
            args.extra_trees[i] = args.extra_trees[i].absolute()

    if args.skeleton_trees is not None:
        for i in range(len(args.skeleton_trees)):
            args.skeleton_trees[i] = args.skeleton_trees[i].absolute()

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

    if args.secure_boot_key is not None:
        args.secure_boot_key = args.secure_boot_key.absolute()

    if args.secure_boot_certificate is not None:
        args.secure_boot_certificate = args.secure_boot_certificate.absolute()

    if args.secure_boot or args.verity == "signed":
        if args.secure_boot_key is None:
            die(
                "UEFI SecureBoot or signed Verity enabled, but couldn't find private key. (Consider placing it in mkosi.secure-boot.key?)"
            )  # NOQA: E501

        if args.secure_boot_certificate is None:
            die(
                "UEFI SecureBoot or signed Verity enabled, but couldn't find certificate. (Consider placing it in mkosi.secure-boot.crt?)"
            )  # NOQA: E501

    if args.verb in (Verb.shell, Verb.boot):
        opname = "acquire shell" if args.verb == Verb.shell else "boot"
        if args.output_format in (OutputFormat.tar, OutputFormat.cpio):
            die(f"Sorry, can't {opname} with a {args.output_format} archive.", MkosiNotSupportedException)
        if should_compress_output(args):
            die(f"Sorry, can't {opname} with a compressed image.", MkosiNotSupportedException)
        if args.qcow2:
            die(f"Sorry, can't {opname} using a qcow2 image.", MkosiNotSupportedException)

    if args.verb == Verb.qemu:
        if not args.output_format.is_disk():
            die("Sorry, can't boot non-disk images with qemu.", MkosiNotSupportedException)

    if needs_build(args) and args.verb == Verb.qemu and not args.bootable:
        die("Images built without the --bootable option cannot be booted using qemu", MkosiNotSupportedException)

    if needs_build(args) and args.qemu_headless and not args.bootable:
        die("--qemu-headless requires --bootable", MkosiNotSupportedException)

    if args.qemu_headless and "console=ttyS0" not in args.kernel_command_line:
        args.kernel_command_line.append("console=ttyS0")

    # By default, the serial console gets spammed with kernel log messages.
    # Let's up the log level to only show warning and error messages when
    # --qemu-headless is enabled to avoid this spam.
    if args.qemu_headless and not any("loglevel" in x for x in args.kernel_command_line):
        args.kernel_command_line.append("loglevel=4")

    if args.bootable and args.usr_only and not args.verity:
        # GPT auto-discovery on empty kernel command lines only looks for root partitions
        # (in order to avoid ambiguities), if we shall operate without one (and only have
        # a /usr partition) we thus need to explicitly say which partition to mount.
        name = root_partition_description(args=None,
                                          image_id=args.image_id,
                                          image_version=args.image_version,
                                          usr_only=args.usr_only)
        args.kernel_command_line.append(f"mount.usr=/dev/disk/by-partlabel/{xescape(name)}")

    if not args.read_only:
        args.kernel_command_line.append("rw")

    if is_generated_root(args) and "bios" in args.boot_protocols:
        die("Sorry, BIOS cannot be combined with --minimize or squashfs filesystems", MkosiNotSupportedException)

    if args.bootable and args.distribution in (Distribution.clear, Distribution.photon):
        die("Sorry, --bootable is not supported on this distro", MkosiNotSupportedException)

    if args.verity and not args.with_unified_kernel_images:
        die("Sorry, --verity can only be used with unified kernel images", MkosiNotSupportedException)

    if args.source_file_transfer is None:
        if os.path.exists(".git") or args.build_sources.joinpath(".git").exists():
            args.source_file_transfer = SourceFileTransfer.copy_git_others
        else:
            args.source_file_transfer = SourceFileTransfer.copy_all

    if args.source_file_transfer_final == SourceFileTransfer.mount:
        die("Sorry, --source-file-transfer-final=mount is not supported")

    if args.skip_final_phase and args.verb != Verb.build:
        die("--skip-final-phase can only be used when building an image using 'mkosi build'", MkosiNotSupportedException)

    if args.ssh_timeout < 0:
        die("--ssh-timeout must be >= 0")

    if args.ssh_port <= 0:
        die("--ssh-port must be > 0")

    if args.repos_dir and not (is_rpm_distribution(args.distribution) or args.distribution == Distribution.arch):
        die("--repository-directory is only supported on RPM based distributions and Arch")

    # We set a reasonable umask so that files that are created in the image
    # will have reasonable permissions. We don't want those permissions to be
    # influenced by the caller's umask which will be used only for output files.
    args.original_umask = os.umask(0o022)

    # Let's define a fixed machine ID for all our build-time
    # runs. We'll strip it off the final image, but some build-time
    # tools (dracut...) want a fixed one, hence provide one, and
    # always the same
    if args.machine_id is None:
        args.machine_id = uuid.uuid4().hex
        args.machine_id_is_fixed = False
    else:
        args.machine_id_is_fixed = True
        try:
            uuid.UUID(hex=args.machine_id)
        except ValueError:
            die(f"Sorry, {args.machine_id} is not a valid machine ID.")

    # If we are building a sysext we don't want to add base packages to the
    # extension image, as they will already be in the base image.
    if args.base_image is not None:
        args.base_packages = False

    if args.qemu_kvm and not qemu_check_kvm_support():
        die("Sorry, the host machine does not support KVM acceleration.")

    return MkosiArgs(**vars(args))


def check_output(args: MkosiArgs) -> None:
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
        args.output_split_root if args.split_artifacts else None,
        args.output_split_verity if args.split_artifacts else None,
        args.output_split_verity_sig if args.split_artifacts else None,
        args.output_split_kernel if args.split_artifacts else None,
    ):

        if f and f.exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def yes_no(b: Optional[bool]) -> str:
    return "yes" if b else "no"


def yes_no_or(b: Union[bool, str]) -> str:
    return b if isinstance(b, str) else yes_no(b)


def format_bytes_or_disabled(sz: Optional[int]) -> str:
    if sz is None:
        return "(disabled)"

    return format_bytes(sz)


def format_bytes_or_auto(sz: Optional[int]) -> str:
    if sz is None:
        return "(automatic)"

    return format_bytes(sz)


def none_to_na(s: Optional[T]) -> Union[T, str]:
    return "n/a" if s is None else s


def none_to_no(s: Optional[T]) -> Union[T, str]:
    return "no" if s is None else s


def none_to_none(o: Optional[object]) -> str:
    return "none" if o is None else str(o)


def line_join_list(array: Sequence[PathString]) -> str:
    if not array:
        return "none"
    return "\n                            ".join(str(item) for item in array)


def print_summary(args: MkosiArgs) -> None:
    # FIXME: normal print
    MkosiPrinter.info("COMMANDS:")
    MkosiPrinter.info(f"                      verb: {args.verb}")
    MkosiPrinter.info("                   cmdline: " + " ".join(args.cmdline))
    MkosiPrinter.info("\nDISTRIBUTION:")
    MkosiPrinter.info("              Distribution: " + args.distribution.name)
    MkosiPrinter.info("                   Release: " + none_to_na(args.release))
    if args.architecture:
        MkosiPrinter.info("              Architecture: " + args.architecture)
    if args.mirror is not None:
        MkosiPrinter.info("                    Mirror: " + args.mirror)
    if args.repositories is not None and len(args.repositories) > 0:
        MkosiPrinter.info("              Repositories: " + ",".join(args.repositories))
    MkosiPrinter.info("     Use Host Repositories: " + yes_no(args.use_host_repositories))
    MkosiPrinter.info("\nOUTPUT:")
    if args.hostname:
        MkosiPrinter.info("                  Hostname: " + args.hostname)
    if args.image_id is not None:
        MkosiPrinter.info("                  Image ID: " + args.image_id)
    if args.image_version is not None:
        MkosiPrinter.info("             Image Version: " + args.image_version)
    MkosiPrinter.info("             Output Format: " + args.output_format.name)
    maniformats = (" ".join(str(i) for i in args.manifest_format)) or "(none)"
    MkosiPrinter.info("          Manifest Formats: " + maniformats)
    if args.output_format.can_minimize():
        MkosiPrinter.info("                  Minimize: " + yes_no(args.minimize))
    if args.output_dir:
        MkosiPrinter.info(f"          Output Directory: {args.output_dir}")
    if args.workspace_dir:
        MkosiPrinter.info(f"       Workspace Directory: {args.workspace_dir}")
    MkosiPrinter.info(f"                    Output: {args.output}")
    MkosiPrinter.info(f"           Output Checksum: {none_to_na(args.output_checksum if args.checksum else None)}")
    MkosiPrinter.info(f"          Output Signature: {none_to_na(args.output_signature if args.sign else None)}")
    MkosiPrinter.info(f"               Output Bmap: {none_to_na(args.output_bmap if args.bmap else None)}")
    MkosiPrinter.info(f"  Generate split artifacts: {yes_no(args.split_artifacts)}")
    MkosiPrinter.info(
        f"      Output Split Root FS: {none_to_na(args.output_split_root if args.split_artifacts else None)}"
    )
    MkosiPrinter.info(
        f"       Output Split Verity: {none_to_na(args.output_split_verity if args.split_artifacts else None)}"
    )
    MkosiPrinter.info(
        f"  Output Split Verity Sig.: {none_to_na(args.output_split_verity_sig if args.split_artifacts else None)}"
    )
    MkosiPrinter.info(
        f"       Output Split Kernel: {none_to_na(args.output_split_kernel if args.split_artifacts else None)}"
    )
    MkosiPrinter.info(
        f"    Output nspawn Settings: {none_to_na(args.output_nspawn_settings if args.nspawn_settings is not None else None)}"
    )
    MkosiPrinter.info(
        f"                   SSH key: {none_to_na((args.ssh_key or args.output_sshkey or args.ssh_agent) if args.ssh else None)}"
    )
    if args.ssh_port != 22:
        MkosiPrinter.info(f"                  SSH port: {args.ssh_port}")

    MkosiPrinter.info("               Incremental: " + yes_no(args.incremental))

    MkosiPrinter.info("                 Read-only: " + yes_no(args.read_only))

    MkosiPrinter.info(" Internal (FS) Compression: " + yes_no_or(should_compress_fs(args)))
    MkosiPrinter.info("Outer (output) Compression: " + yes_no_or(should_compress_output(args)))

    if args.mksquashfs_tool:
        MkosiPrinter.info("           Mksquashfs tool: " + " ".join(map(str, args.mksquashfs_tool)))

    if args.output_format.is_disk():
        MkosiPrinter.info("                     QCow2: " + yes_no(args.qcow2))

    MkosiPrinter.info("                Encryption: " + none_to_no(args.encrypt))
    MkosiPrinter.info("                    Verity: " + yes_no_or(args.verity))

    if args.output_format.is_disk():
        MkosiPrinter.info("                  Bootable: " + yes_no(args.bootable))

        if args.bootable:
            MkosiPrinter.info("       Kernel Command Line: " + " ".join(args.kernel_command_line))
            MkosiPrinter.info("           UEFI SecureBoot: " + yes_no(args.secure_boot))

            MkosiPrinter.info("            Boot Protocols: " + line_join_list(args.boot_protocols))
            MkosiPrinter.info("     Unified Kernel Images: " + yes_no(args.with_unified_kernel_images))
            MkosiPrinter.info("             GPT First LBA: " + str(args.gpt_first_lba))
            MkosiPrinter.info("           Hostonly Initrd: " + yes_no(args.hostonly_initrd))

    if args.secure_boot or args.verity == "sign":
        MkosiPrinter.info(f"SecureBoot/Verity Sign Key: {args.secure_boot_key}")
        MkosiPrinter.info(f"   SecureBoot/verity Cert.: {args.secure_boot_certificate}")

    MkosiPrinter.info("                Machine ID: " + args.machine_id)

    MkosiPrinter.info("\nCONTENT:")
    MkosiPrinter.info("                  Packages: " + line_join_list(args.packages))

    if args.distribution in (
        Distribution.fedora,
        Distribution.centos,
        Distribution.centos_epel,
        Distribution.mageia,
        Distribution.rocky,
        Distribution.rocky_epel,
        Distribution.alma,
        Distribution.alma_epel,
    ):
        MkosiPrinter.info("        With Documentation: " + yes_no(args.with_docs))

    MkosiPrinter.info("             Package Cache: " + none_to_none(args.cache_path))
    MkosiPrinter.info("               Extra Trees: " + line_join_list(args.extra_trees))
    MkosiPrinter.info("            Skeleton Trees: " + line_join_list(args.skeleton_trees))
    MkosiPrinter.info("      CleanPackageMetadata: " + yes_no_or(args.clean_package_metadata))
    if args.remove_files:
        MkosiPrinter.info("              Remove Files: " + line_join_list(args.remove_files))
    if args.remove_packages:
        MkosiPrinter.info("           Remove Packages: " + line_join_list(args.remove_packages))
    MkosiPrinter.info("              Build Script: " + none_to_none(args.build_script))
    env = [f"{k}={v}" for k, v in args.environment.items()]
    MkosiPrinter.info("        Script Environment: " + line_join_list(env))

    if args.build_script:
        MkosiPrinter.info("                 Run tests: " + yes_no(args.with_tests))

    MkosiPrinter.info("                  Password: " + ("default" if args.password is None else "set"))
    MkosiPrinter.info("                 Autologin: " + yes_no(args.autologin))

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
    MkosiPrinter.info("      Scripts with network: " + yes_no_or(args.with_network))
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
        MkosiPrinter.info("                 /usr only: " + yes_no(args.usr_only))

        MkosiPrinter.info("\nVALIDATION:")
        MkosiPrinter.info("                  Checksum: " + yes_no(args.checksum))
        MkosiPrinter.info("                      Sign: " + yes_no(args.sign))
        MkosiPrinter.info("                   GPG Key: " + ("default" if args.key is None else args.key))

    MkosiPrinter.info("\nHOST CONFIGURATION:")
    MkosiPrinter.info("        Extra search paths: " + line_join_list(args.extra_search_paths))
    MkosiPrinter.info("             QEMU Headless: " + yes_no(args.qemu_headless))
    MkosiPrinter.info("      QEMU Extra Arguments: " + line_join_list(args.qemu_args))
    MkosiPrinter.info("                    Netdev: " + yes_no(args.netdev))


def reuse_cache_tree(
    args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool, cached: bool
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

    if fname.exists():
        with complete_step(f"Copying in cached tree {fname}…"):
            copy_path(fname, root)

    return True


def make_output_dir(args: MkosiArgs) -> None:
    """Create the output directory if set and not existing yet"""
    if args.output_dir is None:
        return

    args.output_dir.mkdir(mode=0o755, exist_ok=True)


def make_build_dir(args: MkosiArgs) -> None:
    """Create the build directory if set and not existing yet"""
    if args.build_dir is None:
        return

    args.build_dir.mkdir(mode=0o755, exist_ok=True)


def setup_ssh(
    args: MkosiArgs, root: Path, do_run_build_script: bool, for_cache: bool, cached: bool
) -> Optional[TextIO]:
    if do_run_build_script or not args.ssh:
        return None

    if args.distribution in (Distribution.debian, Distribution.ubuntu):
        unit = "ssh.socket"

        if args.ssh_port != 22:
            add_dropin_config(root, unit, "port",
                              f"""\
                              [Socket]
                              ListenStream=
                              ListenStream={args.ssh_port}
                              """)

        add_dropin_config(root, "ssh@.service", "runtime-directory-preserve",
                          """\
                          [Service]
                          RuntimeDirectoryPreserve=yes
                          """)
    else:
        unit = "sshd"

    # We cache the enable sshd step but not the keygen step because it creates a separate file on the host
    # which introduces non-trivial issue when trying to cache it.

    if not cached:
        run(["systemctl", "--root", root, "enable", unit])

    if for_cache:
        return None

    authorized_keys = root_home(args, root) / ".ssh/authorized_keys"
    f: Optional[TextIO]
    if args.ssh_key:
        f = open(args.ssh_key, mode="r", encoding="utf-8")
        copy_file(f"{args.ssh_key}.pub", authorized_keys)
    elif args.ssh_agent is not None:
        env = {"SSH_AUTH_SOCK": args.ssh_agent}
        result = run(["ssh-add", "-L"], env=env, text=True, stdout=subprocess.PIPE)
        authorized_keys.write_text(result.stdout)
        f = None
    else:
        assert args.output_sshkey is not None

        f = cast(
            TextIO,
            tempfile.NamedTemporaryFile(mode="w+", prefix=".mkosi-", encoding="utf-8", dir=args.output_sshkey.parent),
        )

        with complete_step("Generating SSH key pair…"):
            # Write a 'y' to confirm to overwrite the file.
            run(
                ["ssh-keygen", "-f", f.name, "-N", args.password or "", "-C", "mkosi", "-t", "ed25519"],
                input="y\n",
                text=True,
                stdout=DEVNULL,
            )

        copy_file(f"{f.name}.pub", authorized_keys)
        os.remove(f"{f.name}.pub")

    authorized_keys.chmod(0o600)

    return f


def setup_netdev(args: MkosiArgs, root: Path, do_run_build_script: bool, cached: bool) -> None:
    if do_run_build_script or cached or not args.netdev:
        return

    with complete_step("Setting up netdev…"):
        network_file = root / "etc/systemd/network/80-mkosi-netdev.network"
        with open(network_file, "w") as f:
            # Adapted from https://github.com/systemd/systemd/blob/v247/network/80-container-host0.network
            f.write(
                dedent(
                    """\
                    [Match]
                    Virtualization=!container
                    Type=ether
                    Driver=virtio_net

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


@dataclasses.dataclass
class BuildOutput:
    raw: Optional[BinaryIO]
    archive: Optional[BinaryIO]
    root_hash: Optional[str]
    root_hash_p7s: Optional[bytes]
    sshkey: Optional[TextIO]

    # Partition contents
    split_root: Optional[BinaryIO]
    split_verity: Optional[BinaryIO]
    split_verity_sig: Optional[BinaryIO]
    split_kernel: Optional[BinaryIO]

    def raw_name(self) -> Optional[str]:
        return self.raw.name if self.raw is not None else None

    @classmethod
    def empty(cls) -> BuildOutput:
        return cls(None, None, None, None, None, None, None, None, None)


def build_image(
    args: MkosiArgs,
    root: Path,
    *,
    manifest: Optional[Manifest] = None,
    do_run_build_script: bool,
    for_cache: bool = False,
    cleanup: bool = False,
) -> BuildOutput:
    # If there's no build script set, there's no point in executing
    # the build script iteration. Let's quit early.
    if args.build_script is None and do_run_build_script:
        return BuildOutput.empty()

    make_build_dir(args)

    raw, cached = reuse_cache_image(args, do_run_build_script, for_cache)
    if for_cache and cached:
        # Found existing cache image, exiting build_image
        return BuildOutput.empty()

    if cached:
        assert raw is not None
        refresh_partition_table(args, raw)
    else:
        raw = create_image(args, for_cache)

    with attach_base_image(args.base_image) as base_image, \
         attach_image_loopback(raw) as loopdev:

        prepare_swap(args, loopdev, cached)
        prepare_esp(args, loopdev, cached)
        prepare_xbootldr(args, loopdev, cached)

        if loopdev is not None:
            luks_format_root(args, loopdev, do_run_build_script, cached)
            luks_format_home(args, loopdev, do_run_build_script, cached)
            luks_format_srv(args, loopdev, do_run_build_script, cached)
            luks_format_var(args, loopdev, do_run_build_script, cached)
            luks_format_tmp(args, loopdev, do_run_build_script, cached)

        with luks_setup_all(args, loopdev, do_run_build_script) as encrypted:
            prepare_root(args, encrypted.root, cached)
            prepare_home(args, encrypted.home, cached)
            prepare_srv(args, encrypted.srv, cached)
            prepare_var(args, encrypted.var, cached)
            prepare_tmp(args, encrypted.tmp, cached)

            for dev in encrypted:
                refresh_file_system(args, dev, cached)

            # Mount everything together, but let's not mount the root
            # dir if we still have to generate the root image here
            prepare_tree_root(args, root)

            with mount_image(args, root, base_image, loopdev, encrypted.without_generated_root(args)):

                prepare_tree(args, root, do_run_build_script, cached)
                if do_run_build_script and args.include_dir and not cached:
                    empty_directory(args.include_dir)
                    # We do a recursive unmount of root so we don't need to explicitly unmount this mount
                    # later.
                    mount_bind(args.include_dir, root / "usr/include")

                cached_tree = reuse_cache_tree(args, root, do_run_build_script, for_cache, cached)
                install_skeleton_trees(args, root, cached_tree)
                install_distribution(args, root, do_run_build_script, cached_tree)
                install_etc_locale(args, root, cached_tree)
                install_etc_hostname(args, root, cached_tree)
                install_boot_loader(args, root, loopdev, do_run_build_script, cached_tree)
                run_prepare_script(args, root, do_run_build_script, cached_tree)
                install_build_src(args, root, do_run_build_script, for_cache)
                install_build_dest(args, root, do_run_build_script, for_cache)
                install_extra_trees(args, root, for_cache)
                set_root_password(args, root, do_run_build_script, cached_tree)
                set_serial_terminal(args, root, do_run_build_script, cached_tree)
                set_autologin(args, root, do_run_build_script, cached_tree)
                sshkey = setup_ssh(args, root, do_run_build_script, for_cache, cached_tree)
                setup_netdev(args, root, do_run_build_script, cached_tree)
                run_postinst_script(args, root, loopdev, do_run_build_script, for_cache)

                if cleanup:
                    remove_packages(args, root)

                if manifest:
                    with complete_step("Recording packages in manifest…"):
                        manifest.record_packages(root)

                if cleanup:
                    clean_package_manager_metadata(args, root)
                    remove_files(args, root)
                reset_machine_id(args, root, do_run_build_script, for_cache)
                reset_random_seed(args, root)
                run_finalize_script(args, root, do_run_build_script, for_cache)
                invoke_fstrim(args, root, do_run_build_script, for_cache)
                make_read_only(args, root, for_cache)

            generated_root = make_generated_root(args, root, for_cache)
            generated_root_part = insert_generated_root(args, raw, loopdev, generated_root, for_cache)
            split_root = (
                (generated_root or extract_partition(args, encrypted.root, do_run_build_script, for_cache))
                if args.split_artifacts
                else None
            )

            if args.verity:
                root_for_verity = encrypted.root
                if root_for_verity is None and generated_root_part is not None:
                    assert loopdev is not None
                    root_for_verity = generated_root_part.blockdev(loopdev)
            else:
                root_for_verity = None

            verity, root_hash = make_verity(args, root_for_verity, do_run_build_script, for_cache)

            patch_root_uuid(args, loopdev, root_hash, for_cache)

            insert_verity(args, raw, loopdev, verity, root_hash, for_cache)
            split_verity = verity if args.split_artifacts else None

            verity_sig, root_hash_p7s, fingerprint = make_verity_sig(args, root_hash, do_run_build_script, for_cache)
            insert_verity_sig(args, raw, loopdev, verity_sig, root_hash, fingerprint, for_cache)
            split_verity_sig = verity_sig if args.split_artifacts else None

            # This time we mount read-only, as we already generated
            # the verity data, and hence really shouldn't modify the
            # image anymore.
            mount = lambda: mount_image(args, root, base_image, loopdev,
                                        encrypted.without_generated_root(args),
                                        root_read_only=True)

            install_unified_kernel(args, root, root_hash, do_run_build_script, for_cache, cached, mount)
            secure_boot_sign(args, root, do_run_build_script, for_cache, cached, mount)
            split_kernel = (
                extract_unified_kernel(args, root, do_run_build_script, for_cache, mount)
                if args.split_artifacts
                else None
            )

    archive = make_tar(args, root, do_run_build_script, for_cache) or \
              make_cpio(args, root, do_run_build_script, for_cache)

    return BuildOutput(
        raw or generated_root,
        archive,
        root_hash,
        root_hash_p7s,
        sshkey,
        split_root,
        split_verity,
        split_verity_sig,
        split_kernel,
    )


def one_zero(b: bool) -> str:
    return "1" if b else "0"


def install_dir(args: MkosiArgs, root: Path) -> Path:
    return args.install_dir or workspace(root).joinpath("dest")


def nspawn_knows_arg(arg: str) -> bool:
    return bytes("unrecognized option", "UTF-8") not in run([nspawn_executable(), arg], stderr=PIPE, check=False).stderr


def run_build_script(args: MkosiArgs, root: Path, raw: Optional[BinaryIO]) -> None:
    if args.build_script is None:
        return

    with complete_step("Running build script…"):
        os.makedirs(install_dir(args, root), mode=0o755, exist_ok=True)

        target = f"--directory={root}" if raw is None else f"--image={raw.name}"

        with_network = 1 if args.with_network is True else 0

        cmdline = [
            nspawn_executable(),
            "--quiet",
            target,
            f"--uuid={args.machine_id}",
            f"--machine=mkosi-{uuid.uuid4().hex}",
            "--as-pid2",
            "--register=no",
            f"--bind={install_dir(args, root)}:/root/dest",
            f"--bind={var_tmp(root)}:/var/tmp",
            f"--setenv=WITH_DOCS={one_zero(args.with_docs)}",
            f"--setenv=WITH_TESTS={one_zero(args.with_tests)}",
            f"--setenv=WITH_NETWORK={with_network}",
            "--setenv=DESTDIR=/root/dest",
            *nspawn_rlimit_params(),
        ]

        cmdline.extend(f"--setenv={env}={value}" for env, value in args.environment.items())

        # TODO: Use --autopipe once systemd v247 is widely available.
        console_arg = f"--console={'interactive' if sys.stdout.isatty() else 'pipe'}"
        if nspawn_knows_arg(console_arg):
            cmdline += [console_arg]

        if args.default_path is not None:
            cmdline += [f"--setenv=MKOSI_DEFAULT={args.default_path}"]

        if args.image_version is not None:
            cmdline += [f"--setenv=IMAGE_VERSION={args.image_version}"]

        if args.image_id is not None:
            cmdline += [f"--setenv=IMAGE_ID={args.image_id}"]

        cmdline += nspawn_params_for_build_sources(args, args.source_file_transfer)

        if args.build_dir is not None:
            cmdline += ["--setenv=BUILDDIR=/root/build",
                        f"--bind={args.build_dir}:/root/build"]

        if args.include_dir is not None:
            cmdline += [f"--bind={args.include_dir}:/usr/include"]

        if args.with_network is True:
            # If we're using the host network namespace, use the same resolver
            cmdline += ["--bind-ro=/etc/resolv.conf"]
        else:
            cmdline += ["--private-network"]

        if args.usr_only:
            cmdline += [f"--bind={root_home(args, root)}:/root"]

        if args.nspawn_keep_unit:
            cmdline += ["--keep-unit"]

        cmdline += [f"/root/{args.build_script.name}"]
        cmdline += args.cmdline

        # build-script output goes to stdout so we can run language servers from within mkosi build-scripts.
        # See https://github.com/systemd/mkosi/pull/566 for more information.
        result = run(cmdline, stdout=sys.stdout, check=False)
        if result.returncode != 0:
            if "build-script" in ARG_DEBUG:
                run(cmdline[:-1], check=False)
            die(f"Build script returned non-zero exit code {result.returncode}.")


def need_cache_images(args: MkosiArgs) -> bool:
    if not args.incremental:
        return False

    if args.force > 1:
        return True

    assert args.cache_pre_dev
    assert args.cache_pre_inst

    return not args.cache_pre_dev.exists() or not args.cache_pre_inst.exists()


def remove_artifacts(
    args: MkosiArgs,
    root: Path,
    raw: Optional[BinaryIO],
    archive: Optional[BinaryIO],
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
        with complete_step(f"Removing disk image from {what}…"):
            del raw

    if archive is not None:
        with complete_step(f"Removing archive image from {what}…"):
            del archive

    with complete_step(f"Removing artifacts from {what}…"):
        unlink_try_hard(root)
        unlink_try_hard(var_tmp(root))
        if args.usr_only:
            unlink_try_hard(root_home(args, root))


def build_stuff(args: MkosiArgs) -> Manifest:
    make_output_dir(args)
    setup_package_cache(args)
    workspace = setup_workspace(args)

    image = BuildOutput.empty()
    manifest = Manifest(args)

    # Make sure tmpfiles' aging doesn't interfere with our workspace
    # while we are working on it.
    with open_close(workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC) as dir_fd, \
         btrfs_forget_stale_devices(args):

        fcntl.flock(dir_fd, fcntl.LOCK_EX)

        root = Path(workspace.name, "root")

        # If caching is requested, then make sure we have cache images around we can make use of
        if need_cache_images(args):

            # There is no point generating a pre-dev cache image if no build script is provided
            if args.build_script:
                with complete_step("Running first (development) stage to generate cached copy…"):
                    # Generate the cache version of the build image, and store it as "cache-pre-dev"
                    image = build_image(args, root, do_run_build_script=True, for_cache=True)
                    save_cache(args, root, image.raw_name(), args.cache_pre_dev)
                    remove_artifacts(args, root, image.raw, image.archive, do_run_build_script=True)

            with complete_step("Running second (final) stage to generate cached copy…"):
                # Generate the cache version of the build image, and store it as "cache-pre-inst"
                image = build_image(args, root, do_run_build_script=False, for_cache=True)
                save_cache(args, root, image.raw_name(), args.cache_pre_inst)
                remove_artifacts(args, root, image.raw, image.archive, do_run_build_script=False)

        if args.build_script:
            with complete_step("Running first (development) stage…"):
                # Run the image builder for the first (development) stage in preparation for the build script
                image = build_image(args, root, do_run_build_script=True)

                run_build_script(args, root, image.raw)
                remove_artifacts(args, root, image.raw, image.archive, do_run_build_script=True)

        # Run the image builder for the second (final) stage
        if not args.skip_final_phase:
            with complete_step("Running second (final) stage…"):
                image = build_image(args, root, manifest=manifest, do_run_build_script=False, cleanup=True)
        else:
            MkosiPrinter.print_step("Skipping (second) final image build phase.")

        raw = qcow2_output(args, image.raw)
        bmap = calculate_bmap(args, raw)
        raw = compress_output(args, raw)
        split_root = compress_output(args, image.split_root, ".usr" if args.usr_only else ".root")
        split_verity = compress_output(args, image.split_verity, ".verity")
        split_verity_sig = compress_output(args, image.split_verity_sig, ".verity-sig")
        split_kernel = compress_output(args, image.split_kernel, ".efi")
        root_hash_file = write_root_hash_file(args, image.root_hash)
        root_hash_p7s_file = write_root_hash_p7s_file(args, image.root_hash_p7s)
        settings = copy_nspawn_settings(args)
        checksum = calculate_sha256sum(
            args,
            raw,
            image.archive,
            root_hash_file,
            root_hash_p7s_file,
            split_root,
            split_verity,
            split_verity_sig,
            split_kernel,
            settings,
        )
        signature = calculate_signature(args, checksum)

        link_output(args, root, raw or image.archive)
        link_output_root_hash_file(args, root_hash_file)
        link_output_root_hash_p7s_file(args, root_hash_p7s_file)
        link_output_checksum(args, checksum)
        link_output_signature(args, signature)
        link_output_bmap(args, bmap)
        link_output_nspawn_settings(args, settings)
        if args.output_sshkey is not None:
            link_output_sshkey(args, image.sshkey)
        link_output_split_root(args, split_root)
        link_output_split_verity(args, split_verity)
        link_output_split_verity_sig(args, split_verity_sig)
        link_output_split_kernel(args, split_kernel)

        if image.root_hash is not None:
            MkosiPrinter.print_step(f"Root hash is {image.root_hash}.")

        return manifest


def check_root() -> None:
    if os.getuid() != 0:
        die("Must be invoked as root.")


def check_native(args: MkosiArgs) -> None:
    if args.architecture is not None and args.architecture != platform.machine() and args.build_script and nspawn_version() < 250:
        die("Cannot (currently) override the architecture and run build commands")


@contextlib.contextmanager
def suppress_stacktrace() -> Iterator[None]:
    try:
        yield
    except subprocess.CalledProcessError as e:
        # MkosiException is silenced in main() so it doesn't print a stacktrace.
        raise MkosiException() from e


def machine_name(args: MkosiArgs) -> str:
    return args.hostname or args.image_id or args.output.with_suffix("").name.partition("_")[0]


def interface_name(args: MkosiArgs) -> str:
    # Shorten to 12 characters so we can prefix with ve- or vt- for the netdev ifname which is limited
    # to 15 characters.
    return machine_name(args)[:12]


def has_networkd_vm_vt() -> bool:
    return any(
        Path(path, "80-vm-vt.network").exists()
        for path in ("/usr/lib/systemd/network", "/lib/systemd/network", "/etc/systemd/network")
    )


def ensure_networkd(args: MkosiArgs) -> bool:
    networkd_is_running = run(["systemctl", "is-active", "--quiet", "systemd-networkd"], check=False).returncode == 0
    if not networkd_is_running:
        if args.verb != Verb.ssh:
            # Some programs will use 'mkosi ssh' with pexpect, so don't print warnings that will break
            # them.
            warn("--netdev requires systemd-networkd to be running to initialize the host interface "
                 "of the virtual link ('systemctl enable --now systemd-networkd')")
        return False

    if args.verb == Verb.qemu and not has_networkd_vm_vt():
        warn(dedent(r"""\
            mkosi didn't find 80-vm-vt.network. This is one of systemd's built-in
            systemd-networkd config files which configures vt-* interfaces.
            mkosi needs this file in order for --netdev to work properly for QEMU
            virtual machines. The file likely cannot be found because the systemd version
            on the host is too old (< 246) and it isn't included yet.

            As a workaround until the file is shipped by the systemd package of your distro,
            add a network file /etc/systemd/network/80-vm-vt.network with the following
            contents:

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
            """
        ))
        return False

    return True


def run_shell_cmdline(args: MkosiArgs, pipe: bool = False, commands: Optional[Sequence[str]] = None) -> List[str]:
    if args.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        target = f"--directory={args.output}"
    else:
        target = f"--image={args.output}"

    cmdline = [nspawn_executable(), "--quiet", target]

    # Redirecting output correctly when not running directly from the terminal.
    console_arg = f"--console={'interactive' if not pipe else 'pipe'}"
    if nspawn_knows_arg(console_arg):
        cmdline += [console_arg]

    if args.read_only:
        cmdline += ["--read-only"]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if args.nspawn_settings is not None:
        cmdline += ["--settings=trusted"]

    if args.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += nspawn_rlimit_params()

    if is_generated_root(args) or args.verity:
        cmdline += ["--volatile=overlay"]

    if args.netdev:
        if ensure_networkd(args):
            cmdline += ["--network-veth"]

    if args.ephemeral:
        cmdline += ["--ephemeral"]

    cmdline += ["--machine", machine_name(args)]

    if args.nspawn_keep_unit:
        cmdline += ["--keep-unit"]

    if commands or args.cmdline:
        # If the verb is 'shell', args.cmdline contains the command to run.
        # Otherwise, the verb is 'boot', and we assume args.cmdline contains nspawn arguments.
        if args.verb == Verb.shell:
            cmdline += ["--"]
        cmdline += commands or args.cmdline

    return cmdline


def run_shell(args: MkosiArgs) -> None:
    run(run_shell_cmdline(args, pipe=not sys.stdout.isatty()), stdout=sys.stdout, stderr=sys.stderr)


def find_qemu_binary(args: MkosiArgs) -> str:
    binaries = ["qemu", "qemu-kvm", f"qemu-system-{args.architecture or platform.machine()}"]
    for binary in binaries:
        if shutil.which(binary) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_qemu_firmware() -> Tuple[Path, bool]:
    FIRMWARE_LOCATIONS = [
        # UEFI firmware blobs are found in a variety of locations,
        # depending on distribution and package.
        *{
            "x86_64": ["/usr/share/ovmf/x64/OVMF_CODE.secboot.fd"],
            "i386": ["/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd"],
        }.get(platform.machine(), []),
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.secboot.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.secboot.fd",
        "/usr/share/ovmf/OVMF.secboot.fd",
        "/usr/share/OVMF/OVMF_CODE.secboot.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    warn("Couldn't find OVMF firmware blob with secure boot support, "
         "falling back to OVMF firmware blobs without secure boot support.")

    FIRMWARE_LOCATIONS = [
        # First, we look in paths that contain the architecture –
        # if they exist, they’re almost certainly correct.
        *{
            "x86_64": [
                "/usr/share/ovmf/ovmf_code_x64.bin",
                "/usr/share/ovmf/x64/OVMF_CODE.fd",
                "/usr/share/qemu/ovmf-x86_64.bin",
            ],
            "i386": ["/usr/share/ovmf/ovmf_code_ia32.bin", "/usr/share/edk2/ovmf-ia32/OVMF_CODE.fd"],
        }.get(platform.machine(), []),
        # After that, we try some generic paths and hope that if they exist,
        # they’ll correspond to the current architecture, thanks to the package manager.
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), False

    die("Couldn't find OVMF UEFI firmware blob.")


def find_ovmf_vars() -> Path:
    OVMF_VARS_LOCATIONS = []

    if platform.machine() == "x86_64":
        OVMF_VARS_LOCATIONS += ["/usr/share/ovmf/x64/OVMF_VARS.fd"]
    elif platform.machine() == "i386":
        OVMF_VARS_LOCATIONS += ["/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd"]

    OVMF_VARS_LOCATIONS += ["/usr/share/edk2/ovmf/OVMF_VARS.fd",
                            "/usr/share/edk2-ovmf/OVMF_VARS.fd",  # GENTOO:
                            "/usr/share/qemu/OVMF_VARS.fd",
                            "/usr/share/ovmf/OVMF_VARS.fd",
                            "/usr/share/OVMF/OVMF_VARS.fd"]

    for location in OVMF_VARS_LOCATIONS:
        if os.path.exists(location):
            return Path(location)

    die("Couldn't find OVMF UEFI variables file.")


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


@contextlib.contextmanager
def run_qemu_cmdline(args: MkosiArgs) -> Iterator[List[str]]:
    accel = "kvm" if args.qemu_kvm else "tcg"

    if "uefi" in args.boot_protocols:
        mode = "uefi"
    elif "bios" in args.boot_protocols:
        mode = "bios"
    else:
        mode = "uefi"

    firmware, fw_supports_sb = find_qemu_firmware()
    smm = "on" if fw_supports_sb and mode == "uefi" else "off"

    cmdline = [
        find_qemu_binary(args),
        "-machine",
        f"type=q35,accel={accel},smm={smm}",
        "-smp",
        args.qemu_smp,
        "-m",
        args.qemu_mem,
        "-object",
        "rng-random,filename=/dev/urandom,id=rng0",
        "-device",
        "virtio-rng-pci,rng=rng0,id=rng-device0",
    ]

    if args.qemu_kvm:
        cmdline += ["-cpu", "host"]

    if args.qemu_headless:
        # -nodefaults removes the default CDROM device which avoids an error message during boot
        # -serial mon:stdio adds back the serial device removed by -nodefaults.
        cmdline += ["-nographic", "-nodefaults", "-serial", "mon:stdio"]
        # Fix for https://github.com/systemd/mkosi/issues/559. QEMU gets stuck in a boot loop when using BIOS
        # if there's no vga device.

    if not args.qemu_headless or (args.qemu_headless and mode == "bios"):
        cmdline += ["-vga", "virtio"]

    if args.netdev:
        if not ensure_networkd(args):
            # Fall back to usermode networking if the host doesn't have networkd (eg: Debian)
            fwd = f",hostfwd=tcp::{args.ssh_port}-:{args.ssh_port}" if args.ssh_port != 22 else ""
            cmdline += ["-nic", f"user,model=virtio-net-pci{fwd}"]
        else:
            # Use vt- prefix so we can take advantage of systemd-networkd's builtin network file for VMs.
            ifname = f"vt-{interface_name(args)}"
            # vt-<image-name> is the ifname on the host and is automatically picked up by systemd-networkd which
            # starts a DHCP server on that interface. This gives IP connectivity to the VM. By default, QEMU
            # itself tries to bring up the vt network interface which conflicts with systemd-networkd which is
            # trying to do the same. By specifiying script=no and downscript=no, We tell QEMU to not touch vt
            # after it is created.
            cmdline += ["-nic", f"tap,script=no,downscript=no,ifname={ifname},model=virtio-net-pci"]

    if mode == "uefi":
        cmdline += ["-drive", f"if=pflash,format=raw,readonly=on,file={firmware}"]

    with contextlib.ExitStack() as stack:
        if mode == "uefi" and fw_supports_sb:
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
            f = stack.enter_context(copy_image_temporary(src=args.output, dir=args.output.parent))
            fname = Path(f.name)
        else:
            fname = args.output

        # Debian images fail to boot with virtio-scsi, see: https://github.com/systemd/mkosi/issues/725
        if args.distribution == Distribution.debian:
            cmdline += [
                "-drive",
                f"if=virtio,id=hd,file={fname},format={'qcow2' if args.qcow2 else 'raw'}",
            ]
        else:
            cmdline += [
                "-drive",
                f"if=none,id=hd,file={fname},format={'qcow2' if args.qcow2 else 'raw'}",
                "-device",
                "virtio-scsi-pci,id=scsi",
                "-device",
                "scsi-hd,drive=hd,bootindex=1",
            ]

        cmdline += args.qemu_args
        cmdline += args.cmdline

        print_running_cmd(cmdline)
        yield cmdline


def run_qemu(args: MkosiArgs) -> None:
    with run_qemu_cmdline(args) as cmdline:
        run(cmdline, stdout=sys.stdout, stderr=sys.stderr)


def interface_exists(dev: str) -> bool:
    return run(["ip", "link", "show", dev], stdout=DEVNULL, stderr=DEVNULL, check=False).returncode == 0


def find_address(args: MkosiArgs) -> Tuple[str, str]:
    if not ensure_networkd(args) and args.ssh_port != 22:
        return "", "127.0.0.1"

    name = interface_name(args)
    timeout = float(args.ssh_timeout)

    while timeout >= 0:
        stime = time.time()
        try:
            if interface_exists(f"ve-{name}"):
                dev = f"ve-{name}"
            elif interface_exists(f"vt-{name}"):
                dev = f"vt-{name}"
            else:
                die(f"Container/VM interface ve-{name}/vt-{name} not found")

            link = json.loads(run(["ip", "-j", "link", "show", "dev", dev], stdout=PIPE, text=True).stdout)[0]
            if link["operstate"] == "DOWN":
                raise MkosiException(
                    f"{dev} is not enabled. Make sure systemd-networkd is running so it can manage the interface."
                )

            # Trigger IPv6 neighbor discovery of which we can access the results via 'ip neighbor'. This allows us to
            # find out the link-local IPv6 address of the container/VM via which we can connect to it.
            run(["ping", "-c", "1", "-w", "15", f"ff02::1%{dev}"], stdout=DEVNULL)

            for _ in range(50):
                neighbors = json.loads(
                    run(["ip", "-j", "neighbor", "show", "dev", dev], stdout=PIPE, text=True).stdout
                )

                for neighbor in neighbors:
                    dst = cast(str, neighbor["dst"])
                    if dst.startswith("fe80"):
                        return f"%{dev}", dst

                time.sleep(0.4)
        except MkosiException as e:
            if time.time() - stime > timeout:
                die(str(e))

        time.sleep(1)
        timeout -= time.time() - stime

    die("Container/VM address not found")


def run_command_image(args: MkosiArgs, commands: Sequence[str], timeout: int, check: bool, stdout: _FILE = sys.stdout, stderr: _FILE = sys.stderr) -> CompletedProcess:
    if args.verb == Verb.qemu:
        return run_ssh(args, commands, check, stdout, stderr, timeout)
    elif args.verb == Verb.boot:
        cmdline = ["systemd-run", "--quiet", "--wait", "--pipe", "-M", machine_name(args), "/usr/bin/env", *commands]
        return run(cmdline, check=check, stdout=stdout, stderr=stderr, text=True, timeout=timeout)
    else:
        return run(run_shell_cmdline(args, pipe=True, commands=commands), check=check, stdout=stdout, stderr=stderr, text=True, timeout=timeout)


def run_ssh_cmdline(args: MkosiArgs, commands: Optional[Sequence[str]] = None) -> Sequence[str]:
    cmd = [
            "ssh",
            # Silence known hosts file errors/warnings.
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "LogLevel=ERROR",
        ]

    if args.ssh_agent is None:
        ssh_key = args.ssh_key or args.output_sshkey
        assert ssh_key is not None

        if not ssh_key.exists():
            die(
                f"SSH key not found at {ssh_key}. Are you running from the project's root directory "
                "and did you build with the --ssh option?"
            )

        cmd += ["-i", cast(str, ssh_key)]
    else:
        cmd += ["-o", f"IdentityAgent={args.ssh_agent}"]

    if args.ssh_port != 22:
        cmd += ["-p", f"{args.ssh_port}"]

    dev, address = find_address(args)
    cmd += [f"root@{address}{dev}"]
    cmd += commands or args.cmdline

    return cmd


def run_ssh(
    args: MkosiArgs,
    commands: Optional[Sequence[str]] = None,
    check: bool = True,
    stdout: _FILE = sys.stdout,
    stderr: _FILE = sys.stderr,
    timeout: Optional[int] = None,
) -> CompletedProcess:
    return run(run_ssh_cmdline(args, commands), check=check, stdout=stdout, stderr=stderr, text=True, timeout=timeout)


def run_serve(args: MkosiArgs) -> None:
    """Serve the output directory via a tiny embedded HTTP server"""

    port = 8081
    image = args.output.parent

    if args.output_dir is not None:
        os.chdir(args.output_dir)

    with http.server.HTTPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Serving HTTP on port {port}: http://localhost:{port}/{image}")
        httpd.serve_forever()


def generate_secure_boot_key(args: MkosiArgs) -> NoReturn:
    """Generate secure boot keys using openssl"""
    args.secure_boot_key = args.secure_boot_key or Path("./mkosi.secure-boot.key")
    args.secure_boot_certificate = args.secure_boot_certificate or Path("./mkosi.secure-boot.crt")

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(args.secure_boot_valid_days))
    cn = expand_specifier(args.secure_boot_common_name)

    for f in (args.secure_boot_key, args.secure_boot_certificate):
        if f.exists() and not args.force:
            die(
                dedent(
                    f"""\
                    {f} already exists.
                    If you are sure you want to generate new secure boot keys
                    remove {args.secure_boot_key} and {args.secure_boot_certificate} first.
                    """
                )
            )

    MkosiPrinter.print_step(f"Generating secure boot keys rsa:{keylength} for CN {cn!r}.")
    MkosiPrinter.info(
        dedent(
            f"""
            The keys will expire in {args.secure_boot_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    cmd: List[str] = [
        "openssl",
        "req",
        "-new",
        "-x509",
        "-newkey",
        f"rsa:{keylength}",
        "-keyout",
        os.fspath(args.secure_boot_key),
        "-out",
        os.fspath(args.secure_boot_certificate),
        "-days",
        str(args.secure_boot_valid_days),
        "-subj",
        f"/CN={cn}/",
        "-nodes",
    ]

    os.execvp(cmd[0], cmd)


def bump_image_version(args: MkosiArgs) -> None:
    """Write current image version plus one to mkosi.version"""

    if args.image_version is None or args.image_version == "":
        print("No version configured so far, starting with version 1.")
        new_version = "1"
    else:
        v = args.image_version.split(".")

        try:
            m = int(v[-1])
        except ValueError:
            new_version = args.image_version + ".2"
            print(
                f"Last component of current version is not a decimal integer, appending '.2', bumping '{args.image_version}' → '{new_version}'."
            )
        else:
            new_version = ".".join(v[:-1] + [str(m + 1)])
            print(f"Increasing last component of version by one, bumping '{args.image_version}' → '{new_version}'.")

    open("mkosi.version", "w").write(new_version + "\n")


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
            expanded += [string.Template(path).substitute(environ)]
        except KeyError:
            # Skip path if it uses a variable not defined.
            pass
    return expanded


def prepend_to_environ_path(paths: List[Path]) -> None:
    if not paths:
        return

    news = [os.fspath(path) for path in paths]
    olds = os.getenv("PATH", "").split(":")
    os.environ["PATH"] = ":".join(news + olds)


def expand_specifier(s: str) -> str:
    user = os.getenv("SUDO_USER") or os.getenv("USER")
    assert user is not None
    return s.replace("%u", user)


def needs_build(args: Union[argparse.Namespace, MkosiArgs]) -> bool:
    return args.verb == Verb.build or (args.verb in MKOSI_COMMANDS_NEED_BUILD and (not args.output.exists() or args.force > 0))


def run_verb(raw: argparse.Namespace) -> None:
    args = load_args(raw)

    prepend_to_environ_path(args.extra_search_paths)

    if args.verb == Verb.genkey:
        generate_secure_boot_key(args)

    if args.verb == Verb.bump:
        bump_image_version(args)

    if args.verb in MKOSI_COMMANDS_SUDO:
        check_root()
        unlink_output(args)

    if args.verb == Verb.build:
        check_output(args)

    if args.verb == Verb.summary:
        print_summary(args)

    if needs_build(args):
        check_root()
        check_native(args)
        init_namespace(args)
        manifest = build_stuff(args)

        if args.auto_bump:
            bump_image_version(args)

        save_manifest(args, manifest)

        print_output_size(args)

    with suppress_stacktrace():
        if args.verb in (Verb.shell, Verb.boot):
            run_shell(args)

        if args.verb == Verb.qemu:
            run_qemu(args)

        if args.verb == Verb.ssh:
            run_ssh(args)

    if args.verb == Verb.serve:
        run_serve(args)
