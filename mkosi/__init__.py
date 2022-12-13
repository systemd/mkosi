# SPDX-License-Identifier: LGPL-2.1+

from __future__ import annotations

import argparse
import base64
import configparser
import contextlib
import crypt
import ctypes
import ctypes.util
import dataclasses
import datetime
import errno
import fcntl
import getpass
import glob
import hashlib
import http.server
import importlib
import itertools
import json
import math
import os
import platform
import re
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from textwrap import dedent, wrap
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
    ContextManager,
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

from mkosi.backend import (
    ARG_DEBUG,
    Distribution,
    ManifestFormat,
    MkosiConfig,
    MkosiException,
    MkosiNotSupportedException,
    MkosiPrinter,
    MkosiState,
    OutputFormat,
    Partition,
    PartitionIdentifier,
    PartitionTable,
    SourceFileTransfer,
    Verb,
    add_packages,
    chown_to_running_user,
    detect_distribution,
    die,
    is_centos_variant,
    is_epel_variant,
    is_rpm_distribution,
    mkdirp_chown_current_user,
    nspawn_knows_arg,
    nspawn_rlimit_params,
    nspawn_version,
    patch_file,
    path_relative_to_cwd,
    root_home,
    run,
    run_workspace_command,
    scandir_recursive,
    set_umask,
    should_compress_fs,
    should_compress_output,
    spawn,
    tmp_dir,
    warn,
)
from mkosi.install import (
    add_dropin_config,
    add_dropin_config_from_resource,
    copy_file,
    copy_file_object,
    copy_path,
    install_skeleton_trees,
    open_close,
)
from mkosi.manifest import Manifest
from mkosi.mounts import mount, mount_bind, mount_overlay, mount_tmpfs
from mkosi.remove import unlink_try_hard
from mkosi.syscall import blkpg_add_partition, blkpg_del_partition

complete_step = MkosiPrinter.complete_step
color_error = MkosiPrinter.color_error


__version__ = "14"


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
MKOSI_COMMANDS_SUDO = (Verb.build, Verb.clean, Verb.shell, Verb.boot)
MKOSI_COMMANDS_CMDLINE = (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.ssh)

DRACUT_SYSTEMD_EXTRAS = [
    "/usr/bin/systemd-ask-password",
    "/usr/bin/systemd-repart",
    "/usr/bin/systemd-tty-ask-password-agent",
    "/usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "/usr/lib/systemd/system/initrd-root-fs.target.wants/systemd-repart.service",
    "/usr/lib/systemd/system/initrd-usr-fs.target",
    "/usr/lib/systemd/system/initrd.target.wants/systemd-pcrphase-initrd.service",
    "/usr/lib/systemd/system/sysinit.target.wants/veritysetup.target",
    "/usr/lib/systemd/system/systemd-pcrphase-initrd.service",
    "/usr/lib/systemd/system/systemd-repart.service",
    "/usr/lib/systemd/system/systemd-volatile-root.service",
    "/usr/lib/systemd/system/veritysetup.target",
    "/usr/lib/systemd/systemd-pcrphase",
    "/usr/lib/systemd/systemd-veritysetup",
    "/usr/lib/systemd/systemd-volatile-root",
    "/usr/lib64/libtss2-esys.so.0",
    "/usr/lib64/libtss2-mu.so.0",
    "/usr/lib64/libtss2-rc.so.0",
    "/usr/lib64/libtss2-tcti-device.so.0",
]


T = TypeVar("T")


def list_to_string(seq: Iterator[str]) -> str:
    """Print contents of a list to a comma-separated string

    ['a', "b", 11] → "'a', 'b', 11"
    """
    return str(list(seq))[1:-1]


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

# EFI has its own conventions too
EFI_ARCHITECTURES = {
    "x86_64": "x64",
    "x86": "ia32",
    "aarch64": "aa64",
    "armhfp": "arm",
    "riscv64:": "riscv64",
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


def root_or_usr(config: Union[MkosiConfig, argparse.Namespace]) -> str:
    return ".usr" if config.usr_only else ".root"


def roothash_suffix(config: Union[MkosiConfig, argparse.Namespace]) -> str:
    # For compatibility with what systemd and other tools expect, we need to use "foo.raw" with "foo.roothash",
    # "foo.verity" and "foo.roothash.p7s". Given we name the artifacts differently for "usr" and "root", we need
    # to duplicate it for the roothash suffix. "foo.root.raw" and "foo.roothash" would not work for autodetection
    # and usage.
    return f"{root_or_usr(config)}{root_or_usr(config)}hash"


def roothash_p7s_suffix(config: Union[MkosiConfig, argparse.Namespace]) -> str:
    return f"{roothash_suffix(config)}.p7s"


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


@complete_step("Detaching namespace")
def init_namespace() -> None:
    unshare(CLONE_NEWNS)
    run(["mount", "--make-rslave", "/"])


def setup_workspace(config: MkosiConfig) -> TempDir:
    with complete_step("Setting up temporary workspace.", "Temporary workspace set up in {.name}") as output:
        if config.workspace_dir is not None:
            d = tempfile.TemporaryDirectory(dir=config.workspace_dir, prefix="")
        elif config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
            d = tempfile.TemporaryDirectory(dir=config.output.parent, prefix=".mkosi-")
        else:
            d = tempfile.TemporaryDirectory(dir=tmp_dir(), prefix="mkosi-")
        output.append(d)

    return d


def btrfs_subvol_create(path: Path, mode: int = 0o755) -> None:
    with set_umask(~mode & 0o7777):
        run(["btrfs", "subvol", "create", path])


def btrfs_subvol_make_ro(path: Path, b: bool = True) -> None:
    run(["btrfs", "property", "set", path, "ro", "true" if b else "false"])


@contextlib.contextmanager
def btrfs_forget_stale_devices(config: MkosiConfig) -> Iterator[None]:
    # When using cached images (-i), mounting btrfs images would sometimes fail
    # with EEXIST. This is likely because a stale device is leftover somewhere
    # from the previous run. To fix this, we make sure to always clean up stale
    # btrfs devices after unmounting the image.
    try:
        yield
    finally:
        if config.output_format.is_btrfs() and shutil.which("btrfs"):
            run(["btrfs", "device", "scan", "-u"])


def is_generated_root(config: Union[argparse.Namespace, MkosiConfig]) -> bool:
    """Returns whether this configuration means we need to generate a file system from a prepared tree

    This is needed for anything squashfs and when root minimization is required."""
    return config.minimize or config.output_format.is_squashfs() or config.usr_only


def disable_cow(path: PathString) -> None:
    """Disable copy-on-write if applicable on filesystem"""

    run(["chattr", "+C", path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def root_partition_description(
    config: Optional[MkosiConfig],
    suffix: Optional[str] = None,
    image_id: Optional[str] = None,
    image_version: Optional[str] = None,
    usr_only: Optional[bool] = False,
) -> str:

    # Support invocation with "config" or with separate parameters (which is useful when invoking it before we allocated a MkosiConfig object)
    if config is not None:
        image_id = config.image_id
        image_version = config.image_version
        usr_only = config.usr_only

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


def initialize_partition_table(state: MkosiState, force: bool = False) -> None:
    if state.partition_table is not None and not force:
        return

    if not state.config.output_format.is_disk():
        return

    table = PartitionTable(first_lba=state.config.gpt_first_lba)
    no_btrfs = state.config.output_format != OutputFormat.gpt_btrfs

    for condition, label, size, type_uuid, name, read_only in (
            (state.config.bootable,
             PartitionIdentifier.esp, state.config.esp_size, GPT_ESP, "ESP System Partition", False),
            (state.config.bios_size > 0,
             PartitionIdentifier.bios, state.config.bios_size, GPT_BIOS, "BIOS Boot Partition", False),
            (state.config.xbootldr_size > 0,
             PartitionIdentifier.xbootldr, state.config.xbootldr_size, GPT_XBOOTLDR, "Boot Loader Partition", False),
            (state.config.swap_size > 0,
             PartitionIdentifier.swap, state.config.swap_size, GPT_SWAP, "Swap Partition", False),
            (no_btrfs and state.config.home_size > 0,
             PartitionIdentifier.home, state.config.home_size, GPT_HOME, "Home Partition", False),
            (no_btrfs and state.config.srv_size > 0,
             PartitionIdentifier.srv, state.config.srv_size, GPT_SRV, "Server Data Partition", False),
            (no_btrfs and state.config.var_size > 0,
             PartitionIdentifier.var, state.config.var_size, GPT_VAR, "Variable Data Partition", False),
            (no_btrfs and state.config.tmp_size > 0,
             PartitionIdentifier.tmp, state.config.tmp_size, GPT_TMP, "Temporary Data Partition", False),
            (not is_generated_root(state.config),
             PartitionIdentifier.root, state.config.root_size,
             gpt_root_native(state.config.architecture, state.config.usr_only).root,
             root_partition_description(state.config),
             state.config.read_only)):

        if condition and size > 0:
            table.add(label, size, type_uuid, name, read_only=read_only)

    state.partition_table = table


def create_image(state: MkosiState) -> Optional[BinaryIO]:
    initialize_partition_table(state, force=True)
    if state.partition_table is None:
        return None

    with complete_step("Creating image with partition table…",
                       "Created image with partition table as {.name}") as output:

        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(prefix=".mkosi-", delete=not state.for_cache, dir=state.config.output.parent),
        )
        output.append(f)
        disable_cow(f.name)
        disk_size = state.partition_table.disk_size()
        f.truncate(disk_size)

        if state.partition_table.partitions:
            state.partition_table.run_sfdisk(f.name)

    return f


def refresh_partition_table(state: MkosiState, f: BinaryIO) -> None:
    initialize_partition_table(state)
    if state.partition_table is None:
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
        if state.partition_table.partitions:
            state.partition_table.run_sfdisk(f.name, quiet=True)


def refresh_file_system(config: MkosiConfig, dev: Optional[Path], cached: bool) -> None:

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
        if config.output_format == OutputFormat.gpt_btrfs:
            # We use -M instead of -m here, for compatibility with
            # older btrfs, where -M didn't exist yet.
            run(["btrfstune", "-M", str(uuid.uuid4()), dev])
        elif config.output_format == OutputFormat.gpt_ext4:
            # We connect stdin to /dev/null since tune2fs otherwise
            # asks an unnecessary safety question on stdin, and we
            # don't want that, our script doesn't operate on essential
            # file systems anyway, but just our build images.
            run(["tune2fs", "-U", "random", dev], stdin=subprocess.DEVNULL)
        elif config.output_format == OutputFormat.gpt_xfs:
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


def reuse_cache_image(state: MkosiState) -> Tuple[Optional[BinaryIO], bool]:
    if not state.config.incremental:
        return None, False
    if not state.config.output_format.is_disk_rw():
        return None, False

    fname = state.cache_pre_dev if state.do_run_build_script else state.cache_pre_inst
    if state.for_cache:
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
            f = copy_image_temporary(src=fname, dir=state.config.output.parent)
        except FileNotFoundError:
            return None, False

        output.append(f)

    return f, True


@contextlib.contextmanager
def flock(file: BinaryIO) -> Iterator[None]:
    fcntl.flock(file, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(file, fcntl.LOCK_UN)


@contextlib.contextmanager
def get_loopdev(f: BinaryIO) -> Iterator[BinaryIO]:
    with complete_step(f"Attaching {f.name} as loopback…", "Detaching {}") as output:
        c = run(["losetup", "--find", "--show", "--partscan", f.name], stdout=subprocess.PIPE, text=True)
        loopdev = Path(c.stdout.strip())
        output += [loopdev]

        try:
            with open(loopdev, 'rb+') as f:
                yield f
        finally:
            run(["losetup", "--detach", loopdev])


@contextlib.contextmanager
def attach_image_loopback(image: Optional[BinaryIO], table: Optional[PartitionTable]) -> Iterator[Optional[Path]]:
    if image is None:
        yield None
        return

    assert table

    with get_loopdev(image) as loopdev, flock(loopdev):
        # losetup --partscan instructs the kernel to scan the partition table and add separate partition
        # devices for each of the partitions it finds. However, this operation is asynchronous which
        # means losetup will return before all partition devices have been initialized. This can result
        # in a race condition where we try to access a partition device before it's been initialized by
        # the kernel. To avoid this race condition, let's explicitly try to add all the partitions
        # ourselves using the BLKPKG BLKPG_ADD_PARTITION ioctl().
        for p in table.partitions.values():
            blkpg_add_partition(loopdev.fileno(), p.number, table.partition_offset(p), table.partition_size(p))

        try:
            yield Path(loopdev.name)
        finally:
            # Similarly to above, partition devices are removed asynchronously by the kernel, so again
            # let's avoid race conditions by explicitly removing all partition devices before detaching
            # the loop device using the BLKPG BLKPG_DEL_PARTITION ioctl().
            for p in table.partitions.values():
                blkpg_del_partition(loopdev.fileno(), p.number)


@contextlib.contextmanager
def attach_base_image(base_image: Optional[Path], table: Optional[PartitionTable]) -> Iterator[Optional[Path]]:
    """Context manager that attaches/detaches the base image directory or device"""

    if base_image is None:
        yield None
        return

    with complete_step(f"Using {base_image} as the base image"):
        if base_image.is_dir():
            yield base_image
        else:
            with base_image.open('rb') as f, \
                 attach_image_loopback(f, table) as loopdev:

                yield loopdev


def prepare_swap(state: MkosiState, loopdev: Optional[Path], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return
    part = state.get_partition(PartitionIdentifier.swap)
    if not part:
        return

    with complete_step("Formatting swap partition"):
        run(["mkswap", "-Lswap", part.blockdev(loopdev)])


def prepare_esp(state: MkosiState, loopdev: Optional[Path], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return
    part = state.get_partition(PartitionIdentifier.esp)
    if not part:
        return

    with complete_step("Formatting ESP partition"):
        run(["mkfs.fat", "-nEFI", "-F32", part.blockdev(loopdev)])


def prepare_xbootldr(state: MkosiState, loopdev: Optional[Path], cached: bool) -> None:
    if loopdev is None:
        return
    if cached:
        return

    part = state.get_partition(PartitionIdentifier.xbootldr)
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


def mkfs_generic(config: MkosiConfig, label: str, mount: PathString, dev: Path) -> None:
    cmdline: Sequence[PathString]

    if config.output_format == OutputFormat.gpt_btrfs:
        cmdline = mkfs_btrfs_cmd(label)
    elif config.output_format == OutputFormat.gpt_xfs:
        cmdline = mkfs_xfs_cmd(label)
    else:
        cmdline = mkfs_ext4_cmd(label, mount)

    if config.output_format == OutputFormat.gpt_ext4 and config.architecture in ("x86_64", "aarch64"):
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
    state: MkosiState,
    loopdev: Path,
    cached: bool,
    inserting_generated_root: bool = False,
) -> None:
    if state.config.encrypt != "all":
        return
    part = state.get_partition(PartitionIdentifier.root)
    if not part:
        return
    if is_generated_root(state.config) and not inserting_generated_root:
        return
    if state.do_run_build_script:
        return
    if cached:
        return
    assert state.config.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), state.config.passphrase)


def luks_format_home(state: MkosiState, loopdev: Path, cached: bool) -> None:
    if state.config.encrypt is None:
        return
    part = state.get_partition(PartitionIdentifier.home)
    if not part:
        return
    if state.do_run_build_script:
        return
    if cached:
        return
    assert state.config.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), state.config.passphrase)


def luks_format_srv(state: MkosiState, loopdev: Path, cached: bool) -> None:
    if state.config.encrypt is None:
        return
    part = state.get_partition(PartitionIdentifier.srv)
    if not part:
        return
    if state.do_run_build_script:
        return
    if cached:
        return
    assert state.config.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), state.config.passphrase)


def luks_format_var(state: MkosiState, loopdev: Path, cached: bool) -> None:
    if state.config.encrypt is None:
        return
    part = state.get_partition(PartitionIdentifier.var)
    if not part:
        return
    if state.do_run_build_script:
        return
    if cached:
        return
    assert state.config.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), state.config.passphrase)


def luks_format_tmp(state: MkosiState, loopdev: Path, cached: bool) -> None:
    if state.config.encrypt is None:
        return
    part = state.get_partition(PartitionIdentifier.tmp)
    if not part:
        return
    if state.do_run_build_script:
        return
    if cached:
        return
    assert state.config.passphrase is not None

    with complete_step(f"Setting up LUKS on {part.description}…"):
        luks_format(part.blockdev(loopdev), state.config.passphrase)


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
    state: MkosiState, loopdev: Path, inserting_generated_root: bool = False
) -> ContextManager[Optional[Path]]:
    if state.config.encrypt != "all":
        return contextlib.nullcontext()
    part = state.get_partition(PartitionIdentifier.root)
    if not part:
        return contextlib.nullcontext()
    if is_generated_root(state.config) and not inserting_generated_root:
        return contextlib.nullcontext()
    if state.do_run_build_script:
        return contextlib.nullcontext()
    assert state.config.passphrase is not None

    return luks_open(part, loopdev, state.config.passphrase)


def luks_setup_home(
    state: MkosiState, loopdev: Path
) -> ContextManager[Optional[Path]]:
    if state.config.encrypt is None:
        return contextlib.nullcontext()
    part = state.get_partition(PartitionIdentifier.home)
    if not part:
        return contextlib.nullcontext()
    if state.do_run_build_script:
        return contextlib.nullcontext()
    assert state.config.passphrase is not None

    return luks_open(part, loopdev, state.config.passphrase)


def luks_setup_srv(
    state: MkosiState, loopdev: Path
) -> ContextManager[Optional[Path]]:
    if state.config.encrypt is None:
        return contextlib.nullcontext()
    part = state.get_partition(PartitionIdentifier.srv)
    if not part:
        return contextlib.nullcontext()
    if state.do_run_build_script:
        return contextlib.nullcontext()
    assert state.config.passphrase is not None

    return luks_open(part, loopdev, state.config.passphrase)


def luks_setup_var(
    state: MkosiState, loopdev: Path
) -> ContextManager[Optional[Path]]:
    if state.config.encrypt is None:
        return contextlib.nullcontext()
    part = state.get_partition(PartitionIdentifier.var)
    if not part:
        return contextlib.nullcontext()
    if state.do_run_build_script:
        return contextlib.nullcontext()
    assert state.config.passphrase is not None

    return luks_open(part, loopdev, state.config.passphrase)


def luks_setup_tmp(
    state: MkosiState, loopdev: Path
) -> ContextManager[Optional[Path]]:
    if state.config.encrypt is None:
        return contextlib.nullcontext()
    part = state.get_partition(PartitionIdentifier.tmp)
    if not part:
        return contextlib.nullcontext()
    if state.do_run_build_script:
        return contextlib.nullcontext()
    assert state.config.passphrase is not None

    return luks_open(part, loopdev, state.config.passphrase)


class LuksSetupOutput(NamedTuple):
    root: Optional[Path]
    home: Optional[Path]
    srv: Optional[Path]
    var: Optional[Path]
    tmp: Optional[Path]

    @classmethod
    def empty(cls) -> LuksSetupOutput:
        return cls(None, None, None, None, None)

    def without_generated_root(self, config: MkosiConfig) -> LuksSetupOutput:
        "A copy of self with .root optionally supressed"
        return LuksSetupOutput(
            None if is_generated_root(config) else self.root,
            *self[1:],
        )


@contextlib.contextmanager
def luks_setup_all(
    state: MkosiState, loopdev: Optional[Path]
) -> Iterator[LuksSetupOutput]:
    if not state.config.output_format.is_disk():
        yield LuksSetupOutput.empty()
        return

    assert loopdev is not None
    assert state.partition_table is not None

    with luks_setup_root(state, loopdev) as root, \
         luks_setup_home(state, loopdev) as home, \
         luks_setup_srv(state, loopdev) as srv, \
         luks_setup_var(state, loopdev) as var, \
         luks_setup_tmp(state, loopdev) as tmp:

        yield LuksSetupOutput(
            root or state.partition_table.partition_path(PartitionIdentifier.root, loopdev),
            home or state.partition_table.partition_path(PartitionIdentifier.home, loopdev),
            srv or state.partition_table.partition_path(PartitionIdentifier.srv, loopdev),
            var or state.partition_table.partition_path(PartitionIdentifier.var, loopdev),
            tmp or state.partition_table.partition_path(PartitionIdentifier.tmp, loopdev))


def prepare_root(config: MkosiConfig, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if is_generated_root(config):
        return
    if cached:
        return

    label, path = ("usr", "/usr") if config.usr_only else ("root", "/")
    with complete_step(f"Formatting {label} partition…"):
        mkfs_generic(config, label, path, dev)


def prepare_home(config: MkosiConfig, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting home partition…"):
        mkfs_generic(config, "home", "/home", dev)


def prepare_srv(config: MkosiConfig, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting server data partition…"):
        mkfs_generic(config, "srv", "/srv", dev)


def prepare_var(config: MkosiConfig, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting variable data partition…"):
        mkfs_generic(config, "var", "/var", dev)


def prepare_tmp(config: MkosiConfig, dev: Optional[Path], cached: bool) -> None:
    if dev is None:
        return
    if cached:
        return

    with complete_step("Formatting temporary data partition…"):
        mkfs_generic(config, "tmp", "/var/tmp", dev)


def mount_loop(config: MkosiConfig, dev: Path, where: Path, read_only: bool = False) -> ContextManager[Path]:
    options = []
    if not config.output_format.is_squashfs():
        options += ["discard"]

    compress = should_compress_fs(config)
    if compress and config.output_format == OutputFormat.gpt_btrfs and where.name not in {"efi", "boot"}:
        options += ["compress" if compress is True else f"compress={compress}"]

    return mount(dev, where, options=options, read_only=read_only)


@contextlib.contextmanager
def mount_image(
    state: MkosiState,
    cached: bool,
    base_image: Optional[Path],  # the path to the mounted base image root
    loopdev: Optional[Path],
    image: LuksSetupOutput,
    root_read_only: bool = False,
) -> Iterator[None]:
    with complete_step("Mounting image…", "Unmounting image…"), contextlib.ExitStack() as stack:

        if base_image is not None:
            stack.enter_context(mount_bind(state.root))
            stack.enter_context(mount_overlay(base_image, state.root, root_read_only))

        elif image.root is not None:
            if state.config.usr_only:
                # In UsrOnly mode let's have a bind mount at the top so that umount --recursive works nicely later
                stack.enter_context(mount_bind(state.root))
                stack.enter_context(mount_loop(state.config, image.root, state.root / "usr", root_read_only))
            else:
                stack.enter_context(mount_loop(state.config, image.root, state.root, root_read_only))
        else:
            # always have a root of the tree as a mount point so we can
            # recursively unmount anything that ends up mounted there
            stack.enter_context(mount_bind(state.root))

        if image.home is not None:
            stack.enter_context(mount_loop(state.config, image.home, state.root / "home"))

        if image.srv is not None:
            stack.enter_context(mount_loop(state.config, image.srv, state.root / "srv"))

        if image.var is not None:
            stack.enter_context(mount_loop(state.config, image.var, state.root / "var"))

        if image.tmp is not None:
            stack.enter_context(mount_loop(state.config, image.tmp, state.root / "var/tmp"))

        if loopdev is not None:
            assert state.partition_table is not None
            path = state.partition_table.partition_path(PartitionIdentifier.esp, loopdev)

            if path:
                stack.enter_context(mount_loop(state.config, path, state.root / "efi"))

            path = state.partition_table.partition_path(PartitionIdentifier.xbootldr, loopdev)
            if path:
                stack.enter_context(mount_loop(state.config, path, state.root / "boot"))

        # Make sure /tmp and /run are not part of the image
        stack.enter_context(mount_tmpfs(state.root / "run"))
        stack.enter_context(mount_tmpfs(state.root / "tmp"))

        if state.do_run_build_script and state.config.include_dir and not cached:
            stack.enter_context(mount_bind(state.config.include_dir, state.root / "usr/include"))

        yield


def configure_locale(root: Path, cached: bool) -> None:
    if cached:
        return

    etc_locale = root / "etc/locale.conf"

    try:
        etc_locale.unlink()
    except FileNotFoundError:
        pass

    # Let's ensure we use a UTF-8 locale everywhere.
    etc_locale.write_text("LANG=C.UTF-8\n")


def configure_hostname(state: MkosiState, cached: bool) -> None:
    if cached:
        return

    etc_hostname = state.root / "etc/hostname"

    # Always unlink first, so that we don't get in trouble due to a
    # symlink or suchlike. Also if no hostname is configured we really
    # don't want the file to exist, so that systemd's implicit
    # hostname logic can take effect.
    try:
        os.unlink(etc_hostname)
    except FileNotFoundError:
        pass

    if state.config.hostname:
        with complete_step("Assigning hostname"):
            etc_hostname.write_text(state.config.hostname + "\n")


@contextlib.contextmanager
def mount_cache(state: MkosiState) -> Iterator[None]:
    cache_paths = state.installer.cache_path()

    # We can't do this in mount_image() yet, as /var itself might have to be created as a subvolume first
    with complete_step("Mounting Package Cache", "Unmounting Package Cache"), contextlib.ExitStack() as stack:
        for cache_path in cache_paths:
            stack.enter_context(mount_bind(state.cache, state.root / cache_path))
        yield


def configure_dracut(state: MkosiState, cached: bool) -> None:
    if not state.config.bootable or state.do_run_build_script or cached:
        return

    dracut_dir = state.root / "etc/dracut.conf.d"
    dracut_dir.mkdir(mode=0o755, exist_ok=True)

    dracut_dir.joinpath('30-mkosi-hostonly.conf').write_text(
        f'hostonly={yes_no(state.config.hostonly_initrd)}\n'
        'hostonly_default_device=no\n'
    )

    dracut_dir.joinpath("30-mkosi-qemu.conf").write_text('add_dracutmodules+=" qemu "\n')

    with dracut_dir.joinpath("30-mkosi-systemd-extras.conf").open("w") as f:
        for extra in DRACUT_SYSTEMD_EXTRAS:
            f.write(f'install_optional_items+=" {extra} "\n')
        f.write('install_optional_items+=" /etc/systemd/system.conf "\n')
        if state.root.joinpath("etc/systemd/system.conf.d").exists():
            for conf in state.root.joinpath("etc/systemd/system.conf.d").iterdir():
                f.write(f'install_optional_items+=" {Path("/") / conf.relative_to(state.root)} "\n')

    if state.config.hostonly_initrd:
        dracut_dir.joinpath("30-mkosi-filesystem.conf").write_text(
            f'filesystems+=" {(state.config.output_format.needed_kernel_module())} "\n'
        )

    if state.get_partition(PartitionIdentifier.esp):
        # efivarfs must be present in order to GPT root discovery work
        dracut_dir.joinpath("30-mkosi-efivarfs.conf").write_text(
            '[[ $(modinfo -k "$kernel" -F filename efivarfs 2>/dev/null) == /* ]] && add_drivers+=" efivarfs "\n'
        )


def prepare_tree_root(state: MkosiState) -> None:
    if state.config.output_format == OutputFormat.subvolume and not is_generated_root(state.config):
        with complete_step("Setting up OS tree root…"):
            btrfs_subvol_create(state.root)


def prepare_tree(state: MkosiState, cached: bool) -> None:
    if cached:
        # Reuse machine-id from cached image.
        state.machine_id = uuid.UUID(state.root.joinpath("etc/machine-id").read_text().strip()).hex
        # Always update kernel command line.
        if not state.do_run_build_script and state.config.bootable:
            state.root.joinpath("etc/kernel/cmdline").write_text(" ".join(state.config.kernel_command_line) + "\n")
        return

    with complete_step("Setting up basic OS tree…"):
        if state.config.output_format in (OutputFormat.subvolume, OutputFormat.gpt_btrfs) and not is_generated_root(state.config):
            btrfs_subvol_create(state.root / "home")
            btrfs_subvol_create(state.root / "srv")
            btrfs_subvol_create(state.root / "var")
            btrfs_subvol_create(state.root / "var/tmp", 0o1777)
            state.root.joinpath("var/lib").mkdir()
            btrfs_subvol_create(state.root / "var/lib/machines", 0o700)

        # We need an initialized machine ID for the build & boot logic to work
        state.root.joinpath("etc").mkdir(mode=0o755, exist_ok=True)
        state.root.joinpath("etc/machine-id").write_text(f"{state.machine_id}\n")

        if not state.do_run_build_script and state.config.bootable:
            if state.get_partition(PartitionIdentifier.xbootldr):
                # Create directories for kernels and entries if this is enabled
                state.root.joinpath("boot/EFI").mkdir(mode=0o700)
                state.root.joinpath("boot/EFI/Linux").mkdir(mode=0o700)
                state.root.joinpath("boot/loader").mkdir(mode=0o700)
                state.root.joinpath("boot/loader/entries").mkdir(mode=0o700)
                state.root.joinpath("boot", state.machine_id).mkdir(mode=0o700)
            else:
                # If this is not enabled, let's create an empty directory on /boot
                state.root.joinpath("boot").mkdir(mode=0o700)

            if state.get_partition(PartitionIdentifier.esp):
                state.root.joinpath("efi/EFI").mkdir(mode=0o700)
                state.root.joinpath("efi/EFI/BOOT").mkdir(mode=0o700)
                state.root.joinpath("efi/EFI/systemd").mkdir(mode=0o700)
                state.root.joinpath("efi/loader").mkdir(mode=0o700)

                if not state.get_partition(PartitionIdentifier.xbootldr):
                    # Create directories for kernels and entries, unless the XBOOTLDR partition is turned on
                    state.root.joinpath("efi/EFI/Linux").mkdir(mode=0o700)
                    state.root.joinpath("efi/loader/entries").mkdir(mode=0o700)
                    state.root.joinpath("efi", state.machine_id).mkdir(mode=0o700)

                    # Create some compatibility symlinks in /boot in case that is not set up otherwise
                    state.root.joinpath("boot/efi").symlink_to("../efi")
                    state.root.joinpath("boot/loader").symlink_to("../efi/loader")
                    state.root.joinpath("boot", state.machine_id).symlink_to(f"../efi/{state.machine_id}")

            state.root.joinpath("etc/kernel").mkdir(mode=0o755)

            state.root.joinpath("etc/kernel/cmdline").write_text(" ".join(state.config.kernel_command_line) + "\n")
            state.root.joinpath("etc/kernel/entry-token").write_text(f"{state.machine_id}\n")
            state.root.joinpath("etc/kernel/install.conf").write_text("layout=bls\n")

        if state.do_run_build_script or state.config.ssh or state.config.usr_only:
            root_home(state).mkdir(mode=0o750)

        if state.config.ssh and not state.do_run_build_script:
            root_home(state).joinpath(".ssh").mkdir(mode=0o700)

        if state.do_run_build_script:
            root_home(state).joinpath("dest").mkdir(mode=0o755)

            if state.config.build_dir is not None:
                root_home(state).joinpath("build").mkdir(0o755)

        if state.config.netdev and not state.do_run_build_script:
            state.root.joinpath("etc/systemd").mkdir(mode=0o755)
            state.root.joinpath("etc/systemd/network").mkdir(mode=0o755)


def make_rpm_list(state: MkosiState, packages: Set[str]) -> Set[str]:
    packages = packages.copy()

    if state.config.bootable:
        # Temporary hack: dracut only adds crypto support to the initrd, if the cryptsetup binary is installed
        if state.config.encrypt or state.config.verity:
            add_packages(state.config, packages, "cryptsetup", conditional="dracut")

        if state.config.output_format == OutputFormat.gpt_ext4:
            add_packages(state.config, packages, "e2fsprogs")

        if state.config.output_format == OutputFormat.gpt_xfs:
            add_packages(state.config, packages, "xfsprogs")

        if state.config.output_format == OutputFormat.gpt_btrfs:
            add_packages(state.config, packages, "btrfs-progs")

    if not state.do_run_build_script and state.config.ssh:
        add_packages(state.config, packages, "openssh-server")

    return packages


def flatten(lists: Iterable[Iterable[T]]) -> List[T]:
    """Flatten a sequence of sequences into a single list."""
    return list(itertools.chain.from_iterable(lists))


def clean_paths(
        root: Path,
        globs: Sequence[str],
        tool: str,
        always: bool) -> None:
    """Remove globs under root if always or if tool is not found under root."""

    toolp = root / tool.lstrip('/')
    cond = always or not os.access(toolp, os.F_OK, follow_symlinks=False)

    paths = flatten(root.glob(glob.lstrip('/')) for glob in globs)

    if not cond or not paths:
        return

    with complete_step(f"Cleaning {toolp.name} metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_dnf_metadata(root: Path, always: bool) -> None:
    """Remove dnf metadata if /bin/dnf is not present in the image

    If dnf is not installed, there doesn't seem to be much use in keeping the
    dnf metadata, since it's not usable from within the image anyway.
    """
    paths = [
        "/var/lib/dnf",
        "/var/log/dnf.*",
        "/var/log/hawkey.*",
        "/var/cache/dnf",
    ]

    clean_paths(root, paths, tool='/bin/dnf', always=always)


def clean_yum_metadata(root: Path, always: bool) -> None:
    """Remove yum metadata if /bin/yum is not present in the image"""
    paths = [
        "/var/lib/yum",
        "/var/log/yum.*",
        "/var/cache/yum",
    ]

    clean_paths(root, paths, tool='/bin/yum', always=always)


def clean_rpm_metadata(root: Path, always: bool) -> None:
    """Remove rpm metadata if /bin/rpm is not present in the image"""
    paths = [
        "/var/lib/rpm",
        "/usr/lib/sysimage/rpm",
    ]

    clean_paths(root, paths, tool='/bin/rpm', always=always)


def clean_apt_metadata(root: Path, always: bool) -> None:
    """Remove apt metadata if /usr/bin/apt is not present in the image"""
    paths = [
        "/var/lib/apt",
        "/var/log/apt",
        "/var/cache/apt",
    ]

    clean_paths(root, paths, tool='/usr/bin/apt', always=always)


def clean_dpkg_metadata(root: Path, always: bool) -> None:
    """Remove dpkg metadata if /usr/bin/dpkg is not present in the image"""
    paths = [
        "/var/lib/dpkg",
        "/var/log/dpkg.log",
    ]

    clean_paths(root, paths, tool='/usr/bin/dpkg', always=always)


def clean_pacman_metadata(root: Path, always: bool) -> None:
    """Remove pacman metadata if /usr/bin/pacman is not present in the image"""
    paths = [
        "/var/lib/pacman",
        "/var/cache/pacman",
        "/var/log/pacman.log"
    ]

    clean_paths(root, paths, tool='/usr/bin/pacman', always=always)


def clean_package_manager_metadata(state: MkosiState) -> None:
    """Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if the
    package manager is present in the image.
    """

    assert state.config.clean_package_metadata in (False, True, 'auto')
    if state.config.clean_package_metadata is False:
        return

    # we try then all: metadata will only be touched if any of them are in the
    # final image
    always = state.config.clean_package_metadata is True
    clean_dnf_metadata(state.root, always=always)
    clean_yum_metadata(state.root, always=always)
    clean_rpm_metadata(state.root, always=always)
    clean_apt_metadata(state.root, always=always)
    clean_dpkg_metadata(state.root, always=always)
    clean_pacman_metadata(state.root, always=always)
    # FIXME: implement cleanup for other package managers: swupd


def remove_files(state: MkosiState) -> None:
    """Remove files based on user-specified patterns"""

    if not state.config.remove_files:
        return

    with complete_step("Removing files…"):
        # Note: Path('/foo') / '/bar' == '/bar'. We need to strip the slash.
        # https://bugs.python.org/issue44452
        paths = [state.root / str(p).lstrip("/") for p in state.config.remove_files]
        remove_glob(*paths)


def link_rpm_db(root: Path) -> None:
    """Link /var/lib/rpm to /usr/lib/sysimage/rpm for compat with old rpm"""
    rpmdb = root / "usr/lib/sysimage/rpm"
    rpmdb_old = root / "var/lib/rpm"
    if rpmdb.exists() and not rpmdb_old.is_symlink():
        with complete_step("Creating compat symlink /var/lib/rpm → /usr/lib/sysimage/rpm"):
            # Move content, if any, from the old location to the new one
            if rpmdb_old.exists():
                unlink_try_hard(rpmdb)
                shutil.move(cast(str, rpmdb_old), rpmdb)

            # Create the symlink in exactly the same fashion that Fedora does
            rpmdb_old.symlink_to("../../usr/lib/sysimage/rpm")


def parse_epel_release(release: str) -> int:
    fields = release.split(".")
    if fields[0].endswith("-stream"):
        epel_release = fields[0].split("-")[0]
    else:
        epel_release = fields[0]

    return int(epel_release)


def install_distribution(state: MkosiState, cached: bool) -> None:
    if cached:
        return

    with mount_cache(state):
        state.installer.install(state)

    # Link /var/lib/rpm→/usr/lib/sysimage/rpm for compat with old rpm.
    # We do this only if the new location is used, which depends on the dnf
    # version and configuration on the host. Thus we do this reactively, after the
    # installation has completed.
    link_rpm_db(state.root)


def remove_packages(state: MkosiState) -> None:
    """Remove packages listed in config.remove_packages"""

    if not state.config.remove_packages:
        return

    with complete_step(f"Removing {len(state.config.packages)} packages…"):
        try:
            state.installer.remove_packages(state, state.config.remove_packages)
        except NotImplementedError:
            die(f"Removing packages is not supported for {state.config.distribution}")


def reset_machine_id(state: MkosiState) -> None:
    """Make /etc/machine-id an empty file.

    This way, on the next boot is either initialized and committed (if /etc is
    writable) or the image runs with a transient machine ID, that changes on
    each boot (if the image is read-only).
    """

    if state.do_run_build_script:
        return
    if state.for_cache:
        return

    with complete_step("Resetting machine ID"):
        if not state.config.machine_id:
            machine_id = state.root / "etc/machine-id"
            try:
                machine_id.unlink()
            except FileNotFoundError:
                pass
            machine_id.write_text("uninitialized\n")

        dbus_machine_id = state.root / "var/lib/dbus/machine-id"
        try:
            dbus_machine_id.unlink()
        except FileNotFoundError:
            pass
        else:
            dbus_machine_id.symlink_to("../../../etc/machine-id")


def reset_random_seed(root: Path) -> None:
    """Remove random seed file, so that it is initialized on first boot"""
    random_seed = root / "var/lib/systemd/random-seed"
    if not random_seed.exists():
        return

    with complete_step("Removing random seed"):
        random_seed.unlink()


def configure_root_password(state: MkosiState, cached: bool) -> None:
    "Set the root account password, or just delete it so it's easy to log in"

    if state.do_run_build_script:
        return
    if cached:
        return

    if state.config.password == "":
        with complete_step("Deleting root password"):

            def delete_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", ""] + line.split(":")[2:])
                return line

            patch_file(state.root / "etc/passwd", delete_root_pw)
    elif state.config.password:
        with complete_step("Setting root password"):
            if state.config.password_is_hashed:
                password = state.config.password
            else:
                password = crypt.crypt(state.config.password, crypt.mksalt(crypt.METHOD_SHA512))

            def set_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", password] + line.split(":")[2:])
                return line

            patch_file(state.root / "etc/shadow", set_root_pw)


def invoke_fstrim(state: MkosiState) -> None:

    if state.do_run_build_script:
        return
    if is_generated_root(state.config):
        return
    if not state.config.output_format.is_disk():
        return
    if state.for_cache:
        return

    with complete_step("Trimming File System"):
        run(["fstrim", "-v", state.root], check=False)


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


def configure_autologin(state: MkosiState, cached: bool) -> None:
    if state.do_run_build_script or cached or not state.config.autologin:
        return

    with complete_step("Setting up autologin…"):
        add_dropin_config_from_resource(state.root, "console-getty.service", "autologin",
                                        "mkosi.resources", "console_getty_autologin.conf")

        ttys = []
        ttys += ["pts/0"]

        add_dropin_config_from_resource(state.root, "serial-getty@ttyS0.service", "autologin",
                                        "mkosi.resources", "serial_getty_autologin.conf")

        ttys += ["ttyS0"]

        add_dropin_config_from_resource(state.root, "getty@tty1.service", "autologin",
                                        "mkosi.resources", "getty_autologin.conf")

        ttys += ["tty1"]
        ttys += ["console"]

        pam_add_autologin(state.root, ttys)


def configure_serial_terminal(state: MkosiState, cached: bool) -> None:
    """Override TERM for the serial console with the terminal type from the host."""

    if state.do_run_build_script or cached or not state.config.qemu_headless:
        return

    with complete_step("Configuring serial tty (/dev/ttyS0)…"):
        columns, lines = shutil.get_terminal_size(fallback=(80, 24))
        add_dropin_config(state.root, "serial-getty@ttyS0.service", "term",
                          f"""\
                          [Service]
                          Environment=TERM={os.getenv('TERM', 'vt220')}
                          Environment=COLUMNS={columns}
                          Environment=LINES={lines}
                          TTYColumns={columns}
                          TTYRows={lines}
                          """)


def nspawn_id_map_supported() -> bool:
    if nspawn_version() < 252:
        return False

    try:
        # Not part of stdlib
        from packaging import version
    except ImportError:
        # If we can't check assume the kernel is new enough
        return True

    return version.parse(platform.release()) >= version.LegacyVersion("5.12")


def nspawn_params_for_build_sources(config: MkosiConfig, sft: SourceFileTransfer) -> List[str]:
    params = []

    if config.build_sources is not None:
        params += ["--setenv=SRCDIR=/root/src",
                   "--chdir=/root/src"]
        if sft == SourceFileTransfer.mount:
            idmap_opt = ":rootidmap" if nspawn_id_map_supported() else ""
            params += [f"--bind={config.build_sources}:/root/src{idmap_opt}"]

        if config.read_only:
            params += ["--overlay=+/root/src::/root/src"]
    else:
        params += ["--chdir=/root"]

    return params


def run_prepare_script(state: MkosiState, cached: bool) -> None:
    if state.config.prepare_script is None:
        return
    if cached:
        return

    verb = "build" if state.do_run_build_script else "final"

    with mount_cache(state), complete_step("Running prepare script…"):

        # We copy the prepare script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(state.config.prepare_script, root_home(state) / "prepare")

        nspawn_params = nspawn_params_for_build_sources(state.config, SourceFileTransfer.mount)
        run_workspace_command(state, ["/root/prepare", verb],
                              network=True, nspawn_params=nspawn_params, env=state.environment)

        srcdir = root_home(state) / "src"
        if srcdir.exists():
            os.rmdir(srcdir)

        os.unlink(root_home(state) / "prepare")


def run_postinst_script(state: MkosiState) -> None:
    if state.config.postinst_script is None:
        return
    if state.for_cache:
        return

    verb = "build" if state.do_run_build_script else "final"

    with mount_cache(state), complete_step("Running postinstall script…"):

        # We copy the postinst script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(state.config.postinst_script, root_home(state) / "postinst")

        run_workspace_command(state, ["/root/postinst", verb],
                              network=(state.config.with_network is True), env=state.environment)
        root_home(state).joinpath("postinst").unlink()


def output_dir(config: MkosiConfig) -> Path:
    return config.output_dir or Path(os.getcwd())


def run_finalize_script(state: MkosiState) -> None:
    if state.config.finalize_script is None:
        return
    if state.for_cache:
        return

    verb = "build" if state.do_run_build_script else "final"

    with complete_step("Running finalize script…"):
        run([state.config.finalize_script, verb],
            env={**state.environment, "BUILDROOT": str(state.root), "OUTPUTDIR": str(output_dir(state.config))})


def install_boot_loader(state: MkosiState) -> None:
    if not state.config.bootable or state.do_run_build_script or state.for_cache:
        return

    with complete_step("Installing boot loader…"):
        if state.get_partition(PartitionIdentifier.esp):
            run_workspace_command(state, ["bootctl", "install"])


def install_extra_trees(state: MkosiState) -> None:
    if not state.config.extra_trees:
        return

    if state.for_cache:
        return

    with complete_step("Copying in extra file trees…"):
        for tree in state.config.extra_trees:
            if tree.is_dir():
                copy_path(tree, state.root, copystat=False)
            else:
                # unpack_archive() groks Paths, but mypy doesn't know this.
                # Pretend that tree is a str.
                shutil.unpack_archive(cast(str, tree), state.root)


def copy_git_files(src: Path, dest: Path, *, source_file_transfer: SourceFileTransfer) -> None:
    what_files = ["--exclude-standard", "--cached"]
    if source_file_transfer == SourceFileTransfer.copy_git_others:
        what_files += ["--others", "--exclude=.mkosi-*"]

    uid = int(os.getenv("SUDO_UID", 0))

    c = run(["git", "-C", src, "ls-files", "-z", *what_files], stdout=subprocess.PIPE, text=False, user=uid)
    files: Set[str] = {x.decode("utf-8") for x in c.stdout.rstrip(b"\0").split(b"\0")}

    # Add the .git/ directory in as well.
    if source_file_transfer == SourceFileTransfer.copy_git_more:
        top = os.path.join(src, ".git/")
        for path, _, filenames in os.walk(top):
            for filename in filenames:
                fp = os.path.join(path, filename)  # full path
                fr = os.path.join(".git/", fp[len(top) :])  # relative to top
                files.add(fr)

    # Get submodule files
    c = run(["git", "-C", src, "submodule", "status", "--recursive"], stdout=subprocess.PIPE, text=True, user=uid)
    submodules = {x.split()[1] for x in c.stdout.splitlines()}

    # workaround for git ls-files returning the path of submodules that we will
    # still parse
    files -= submodules

    for sm in submodules:
        sm = Path(sm)
        c = run(
            ["git", "-C", src / sm, "ls-files", "-z"] + what_files,
            stdout=subprocess.PIPE,
            text=False,
            user=uid,
        )
        files |= {sm / x.decode("utf-8") for x in c.stdout.rstrip(b"\0").split(b"\0")}
        files -= submodules

        # Add the .git submodule file well.
        if source_file_transfer == SourceFileTransfer.copy_git_more:
            files.add(os.path.join(sm, ".git"))

    del c

    for path in files:
        src_path = src / path
        dest_path = dest / path

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if src_path.is_dir():
            copy_path(src_path, dest_path)
        else:
            copy_file(src_path, dest_path)


def install_build_src(state: MkosiState) -> None:
    if state.for_cache:
        return

    if state.do_run_build_script:
        if state.config.build_script is not None:
            with complete_step("Copying in build script…"):
                copy_file(state.config.build_script, root_home(state) / state.config.build_script.name)
        else:
            return

    sft: Optional[SourceFileTransfer] = None
    resolve_symlinks: bool = False
    if state.do_run_build_script:
        sft = state.config.source_file_transfer
        resolve_symlinks = state.config.source_resolve_symlinks
    else:
        sft = state.config.source_file_transfer_final
        resolve_symlinks = state.config.source_resolve_symlinks_final

    if state.config.build_sources is None or sft is None:
        return

    with complete_step("Copying in sources…"):
        target = root_home(state) / "src"

        if sft in (
            SourceFileTransfer.copy_git_others,
            SourceFileTransfer.copy_git_cached,
            SourceFileTransfer.copy_git_more,
        ):
            copy_git_files(state.config.build_sources, target, source_file_transfer=sft)
        elif sft == SourceFileTransfer.copy_all:
            ignore = shutil.ignore_patterns(
                ".git",
                ".mkosi-*",
                "*.cache-pre-dev",
                "*.cache-pre-inst",
                f"{state.config.output_dir.name}/" if state.config.output_dir else "mkosi.output/",
                f"{state.config.workspace_dir.name}/" if state.config.workspace_dir else "mkosi.workspace/",
                f"{state.config.cache_path.name}/" if state.config.cache_path else "mkosi.cache/",
                f"{state.config.build_dir.name}/" if state.config.build_dir else "mkosi.builddir/",
                f"{state.config.include_dir.name}/" if state.config.include_dir else "mkosi.includedir/",
                f"{state.config.install_dir.name}/" if state.config.install_dir else "mkosi.installdir/",
            )
            shutil.copytree(state.config.build_sources, target, symlinks=not resolve_symlinks, ignore=ignore)


def install_build_dest(state: MkosiState) -> None:
    if state.do_run_build_script:
        return
    if state.for_cache:
        return

    if state.config.build_script is None:
        return

    with complete_step("Copying in build tree…"):
        copy_path(install_dir(state), state.root, copystat=False)


def make_read_only(state: MkosiState, directory: Path, b: bool = True) -> None:
    if not state.config.read_only:
        return
    if state.for_cache:
        return

    if state.config.output_format not in (OutputFormat.gpt_btrfs, OutputFormat.subvolume):
        return
    if is_generated_root(state.config):
        return

    with complete_step("Marking subvolume read-only"):
        btrfs_subvol_make_ro(directory, b)


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


def make_tar(state: MkosiState) -> Optional[BinaryIO]:
    if state.do_run_build_script:
        return None
    if state.config.output_format != OutputFormat.tar:
        return None
    if state.for_cache:
        return None

    root_dir = state.root / "usr" if state.config.usr_only else state.root

    cmd: List[PathString] = [tar_binary(), "-C", root_dir, "-c", "--xattrs", "--xattrs-include=*"]
    if state.config.tar_strip_selinux_context:
        cmd += ["--xattrs-exclude=security.selinux"]

    compress = should_compress_output(state.config)
    if compress:
        cmd += ["--use-compress-program=" + " ".join(compressor_command(compress))]

    cmd += ["."]

    with complete_step("Creating archive…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(state.config.output), prefix=".mkosi-"))
        run(cmd, stdout=f)

    return f


def find_files(root: Path) -> Iterator[Path]:
    """Generate a list of all filepaths relative to @root"""
    yield from scandir_recursive(root,
                                 lambda entry: Path(entry.path).relative_to(root))


def make_cpio(state: MkosiState) -> Optional[BinaryIO]:
    if state.do_run_build_script:
        return None
    if state.config.output_format != OutputFormat.cpio:
        return None
    if state.for_cache:
        return None

    root_dir = state.root / "usr" if state.config.usr_only else state.root

    with complete_step("Creating archive…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(state.config.output), prefix=".mkosi-"))

        compressor = compressor_command(should_compress_output(state.config))
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


def generate_squashfs(state: MkosiState, directory: Path) -> Optional[BinaryIO]:
    if not state.config.output_format.is_squashfs():
        return None
    if state.for_cache:
        return None

    command = state.config.mksquashfs_tool[0] if state.config.mksquashfs_tool else "mksquashfs"
    comp_args = state.config.mksquashfs_tool[1:] if state.config.mksquashfs_tool and state.config.mksquashfs_tool[1:] else ["-noappend"]

    compress = should_compress_fs(state.config)
    # mksquashfs default is true, so no need to specify anything to have the default compression.
    if isinstance(compress, str):
        comp_args += ["-comp", compress]
    elif compress is False:
        comp_args += ["-noI", "-noD", "-noF", "-noX"]

    with complete_step("Creating squashfs file system…"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-squashfs", dir=os.path.dirname(state.config.output))
        )
        run([command, directory, f.name, *comp_args])

    return f


def generate_ext4(state: MkosiState, directory: Path, label: str) -> Optional[BinaryIO]:
    if state.config.output_format != OutputFormat.gpt_ext4:
        return None
    if state.for_cache:
        return None

    with complete_step("Creating ext4 root file system…"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-mkfs-ext4", dir=os.path.dirname(state.config.output))
        )
        f.truncate(state.config.root_size)
        run(["mkfs.ext4", "-I", "256", "-L", label, "-M", "/", "-d", directory, f.name])

    if state.config.minimize:
        with complete_step("Minimizing ext4 root file system…"):
            run(["resize2fs", "-M", f.name])

    return f


def generate_btrfs(state: MkosiState, directory: Path, label: str) -> Optional[BinaryIO]:
    if state.config.output_format != OutputFormat.gpt_btrfs:
        return None
    if state.for_cache:
        return None

    with complete_step("Creating minimal btrfs root file system…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-mkfs-btrfs", dir=state.config.output.parent))
        f.truncate(state.config.root_size)

        cmdline: Sequence[PathString] = [
            "mkfs.btrfs", "-L", label, "-d", "single", "-m", "single", "--rootdir", directory, f.name
        ]

        if state.config.minimize:
            try:
                run([*cmdline, "--shrink"])
            except subprocess.CalledProcessError:
                # The --shrink option was added in btrfs-tools 4.14.1, before that it was the default behaviour.
                # If the above fails, let's see if things work if we drop it
                run(cmdline)
        else:
            run(cmdline)

    return f


def generate_xfs(state: MkosiState, directory: Path, label: str) -> Optional[BinaryIO]:
    if state.config.output_format != OutputFormat.gpt_xfs:
        return None
    if state.for_cache:
        return None

    with complete_step("Creating xfs root file system…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(prefix=".mkosi-mkfs-xfs", dir=os.path.dirname(state.config.output))
        )

        f.truncate(state.config.root_size)
        run(mkfs_xfs_cmd(label) + [f.name])

        xfs_dir = state.workspace / "xfs"
        xfs_dir.mkdir()
        with get_loopdev(f) as loopdev, mount_loop(state.config, Path(loopdev.name), xfs_dir) as mp:
            copy_path(directory, mp)

    return f


def make_generated_root(state: MkosiState) -> Optional[BinaryIO]:

    if not is_generated_root(state.config):
        return None

    label = "usr" if state.config.usr_only else "root"
    patched_root = state.root / "usr" if state.config.usr_only else state.root

    if state.config.output_format == OutputFormat.gpt_xfs:
        return generate_xfs(state, patched_root, label)
    if state.config.output_format == OutputFormat.gpt_ext4:
        return generate_ext4(state, patched_root, label)
    if state.config.output_format == OutputFormat.gpt_btrfs:
        return generate_btrfs(state, patched_root, label)
    if state.config.output_format.is_squashfs():
        return generate_squashfs(state, patched_root)

    return None


def insert_partition(
    state: MkosiState,
    raw: BinaryIO,
    loopdev: Path,
    blob: BinaryIO,
    ident: PartitionIdentifier,
    description: str,
    type_uuid: uuid.UUID,
    read_only: bool,
    part_uuid: Optional[uuid.UUID] = None,
) -> Partition:

    assert state.partition_table is not None

    blob.seek(0)

    luks_extra = 16 * 1024 * 1024 if state.config.encrypt == "all" else 0
    blob_size = os.stat(blob.name).st_size
    if ident == PartitionIdentifier.root and not state.config.minimize:
        # Make root partition at least as big as the specified size
        blob_size = max(blob_size, state.config.root_size)
    part = state.partition_table.add(ident, blob_size + luks_extra, type_uuid, description, part_uuid)

    disk_size = state.partition_table.disk_size()
    ss = f" ({disk_size // state.partition_table.sector_size} sectors)" if 'disk' in ARG_DEBUG else ""
    with complete_step(f"Resizing disk image to {format_bytes(disk_size)}{ss}"):
        os.truncate(raw.name, disk_size)
        run(["losetup", "--set-capacity", loopdev])

    part_size = part.n_sectors * state.partition_table.sector_size
    ss = f" ({part.n_sectors} sectors)" if 'disk' in ARG_DEBUG else ""
    with complete_step(f"Inserting partition of {format_bytes(part_size)}{ss}..."):
        state.partition_table.run_sfdisk(loopdev)

    with complete_step("Writing partition..."):
        if ident == PartitionIdentifier.root:
            luks_format_root(state, loopdev, False, False)
            cm = luks_setup_root(state, loopdev, False)
        else:
            cm = contextlib.nullcontext()

        with cm as dev:
            path = dev if dev is not None else part.blockdev(loopdev)

            # Without this the entire blob will be read into memory which could exceed system memory
            with open(path, mode='wb') as path_fp:
                # Chunk size for 32/64-bit systems
                # Chunking required because sendfile under Linux has a maximum copy size
                chunksize = 2 ** 30 if sys.maxsize < 2 ** 32 else 0x7ffff000
                offset = 0
                while True:
                    sent = os.sendfile(path_fp.fileno(), blob.fileno(), offset=offset, count=chunksize)
                    if not sent:
                        break
                    offset += sent

    return part


def insert_generated_root(
    state: MkosiState,
    raw: Optional[BinaryIO],
    loopdev: Optional[Path],
    image: Optional[BinaryIO],
) -> Optional[Partition]:
    if not is_generated_root(state.config):
        return None
    if not state.config.output_format.is_disk():
        return None
    if state.for_cache:
        return None
    assert raw is not None
    assert loopdev is not None
    assert image is not None
    assert state.partition_table is not None

    with complete_step("Inserting generated root partition…"):
        return insert_partition(
            state,
            raw,
            loopdev,
            image,
            PartitionIdentifier.root,
            root_partition_description(state.config),
            type_uuid=gpt_root_native(state.config.architecture, state.config.usr_only).root,
            read_only=state.config.read_only)


def make_verity(state: MkosiState, dev: Optional[Path]) -> Tuple[Optional[BinaryIO], Optional[str]]:
    if state.do_run_build_script or state.config.verity is False:
        return None, None
    if state.for_cache:
        return None, None
    assert dev is not None

    with complete_step("Generating verity hashes…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=state.config.output.parent, prefix=".mkosi-"))
        c = run(["veritysetup", "format", dev, f.name], stdout=subprocess.PIPE)

        for line in c.stdout.decode("utf-8").split("\n"):
            if line.startswith("Root hash:"):
                root_hash = line[10:].strip()
                return f, root_hash

        raise ValueError("Root hash not found")


def insert_verity(
    state: MkosiState,
    raw: Optional[BinaryIO],
    loopdev: Optional[Path],
    verity: Optional[BinaryIO],
    root_hash: Optional[str],
) -> Optional[Partition]:
    if verity is None:
        return None
    if state.for_cache:
        return None
    assert loopdev is not None
    assert raw is not None
    assert root_hash is not None
    assert state.partition_table is not None

    # Use the final 128 bit of the root hash as partition UUID of the verity partition
    u = uuid.UUID(root_hash[-32:])

    with complete_step("Inserting verity partition…"):
        return insert_partition(
            state,
            raw,
            loopdev,
            verity,
            PartitionIdentifier.verity,
            root_partition_description(state.config, "Verity"),
            gpt_root_native(state.config.architecture, state.config.usr_only).verity,
            read_only=True,
            part_uuid=u)


def make_verity_sig(
    state: MkosiState, root_hash: Optional[str]
) -> Tuple[Optional[BinaryIO], Optional[bytes], Optional[str]]:

    if state.do_run_build_script or state.config.verity != "signed":
        return None, None, None
    if state.for_cache:
        return None, None, None

    assert root_hash is not None

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:
        die("Verity support needs the cryptography module. Please install it.")

    with complete_step("Signing verity root hash…"):

        key = serialization.load_pem_private_key(state.config.secure_boot_key.read_bytes(), password=None)
        certificate = x509.load_pem_x509_certificate(state.config.secure_boot_certificate.read_bytes())

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

        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(mode="w+b", dir=state.config.output.parent, prefix=".mkosi-"))
        f.write(j)
        f.flush()

        # Returns a file with JSON data to insert as signature partition as the first element, and
        # the DER PKCS7 signature bytes as second argument (to store as a detached PKCS7 file), and
        # finally the SHA256 fingerprint of the certificate used (which is used to
        # deterministically generate the partition UUID for the signature partition).

        return f, sigbytes, fingerprint


def insert_verity_sig(
    state: MkosiState,
    raw: Optional[BinaryIO],
    loopdev: Optional[Path],
    verity_sig: Optional[BinaryIO],
    root_hash: Optional[str],
    fingerprint: Optional[str],
) -> Optional[Partition]:
    if verity_sig is None:
        return None
    if state.for_cache:
        return None
    assert loopdev is not None
    assert raw is not None
    assert root_hash is not None
    assert fingerprint is not None
    assert state.partition_table is not None

    # Hash the concatenation of verity roothash and the X509 certificate
    # fingerprint to generate a UUID for the signature partition.
    u = uuid.UUID(hashlib.sha256(bytes.fromhex(root_hash) + bytes.fromhex(fingerprint)).hexdigest()[:32])

    with complete_step("Inserting verity signature partition…"):
        return insert_partition(
            state,
            raw,
            loopdev,
            verity_sig,
            PartitionIdentifier.verity_sig,
            root_partition_description(state.config, "Signature"),
            gpt_root_native(state.config.architecture, state.config.usr_only).verity_sig,
            read_only=True,
            part_uuid=u)


def patch_root_uuid(state: MkosiState, loopdev: Optional[Path], root_hash: Optional[str]) -> None:
    if root_hash is None:
        return
    assert loopdev is not None

    if state.for_cache:
        return

    # Use the first 128bit of the root hash as partition UUID of the root partition
    u = uuid.UUID(root_hash[:32])

    part = state.get_partition(PartitionIdentifier.root)
    assert part is not None
    part.part_uuid = u

    print('Root partition-type UUID:', u)


def extract_partition(state: MkosiState, dev: Optional[Path]) -> Optional[BinaryIO]:
    if state.do_run_build_script or state.for_cache or not state.config.split_artifacts:
        return None

    assert dev is not None

    with complete_step("Extracting partition…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(dir=os.path.dirname(state.config.output), prefix=".mkosi-"))
        run(["dd", f"if={dev}", f"of={f.name}", "conv=nocreat,sparse"])

    return f


def gen_kernel_images(state: MkosiState) -> Iterator[Tuple[str, Path]]:
    # Apparently openmandriva hasn't yet completed its usrmerge so we use lib here instead of usr/lib.
    for kver in state.root.joinpath("lib/modules").iterdir():
        if not kver.is_dir():
            continue

        kimg = state.installer.kernel_image(kver.name, state.config.architecture)

        yield kver.name, kimg


def initrd_path(state: MkosiState, kver: str) -> Path:
    # initrd file is versioned in Debian Bookworm
    initrd = state.root / boot_directory(state, kver) / f"initrd.img-{kver}"
    if not initrd.exists():
        initrd = state.root / boot_directory(state, kver) / "initrd"

    return initrd


def install_unified_kernel(
    state: MkosiState,
    root_hash: Optional[str],
    mount: Callable[[], ContextManager[None]],
) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if not (state.config.bootable and
            state.get_partition(PartitionIdentifier.esp) and
            state.config.with_unified_kernel_images):
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
    if state.for_cache:
        return

    # Don't bother running dracut if this is a development build. Strictly speaking it would probably be a
    # good idea to run it, so that the development environment differs as little as possible from the final
    # build, but then again the initrd should not be relevant for building, and dracut is simply very slow,
    # hence let's avoid it invoking it needlessly, given that we never actually invoke the boot loader on the
    # development image.
    if state.do_run_build_script:
        return

    prefix = "boot" if state.get_partition(PartitionIdentifier.xbootldr) else "efi"

    with mount(), complete_step("Generating combined kernel + initrd boot file…"):
        for kver, kimg in gen_kernel_images(state):
            if state.config.image_id:
                image_id = state.config.image_id
                if state.config.image_version:
                    partlabel = f"{state.config.image_id}_{state.config.image_version}"
                else:
                    partlabel = f"{state.config.image_id}"
            else:
                image_id = f"mkosi-{state.config.distribution}"
                partlabel = None

            # See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/#boot-counting
            boot_count = ""
            if state.root.joinpath("etc/kernel/tries").exists():
                boot_count = f'+{state.root.joinpath("etc/kernel/tries").read_text().strip()}'

            if state.config.image_version:
                boot_binary = state.root / prefix / f"EFI/Linux/{image_id}_{state.config.image_version}{boot_count}.efi"
            elif root_hash:
                boot_binary = state.root / prefix / f"EFI/Linux/{image_id}-{kver}-{root_hash}{boot_count}.efi"
            else:
                boot_binary = state.root / prefix / f"EFI/Linux/{image_id}-{kver}{boot_count}.efi"

            if state.root.joinpath("etc/kernel/cmdline").exists():
                boot_options = state.root.joinpath("etc/kernel/cmdline").read_text().strip()
            elif state.root.joinpath("/usr/lib/kernel/cmdline").exists():
                boot_options = state.root.joinpath("usr/lib/kernel/cmdline").read_text().strip()
            else:
                boot_options = ""

            if root_hash:
                option = "usrhash" if state.config.usr_only else "roothash"
                boot_options = f"{boot_options} {option}={root_hash}"
            elif partlabel:
                option = "mount.usr" if state.config.usr_only else "root"
                boot_options = f"{boot_options} {option}=PARTLABEL={partlabel}"

            osrelease = state.root / "usr/lib/os-release"
            cmdline = state.workspace / "cmdline"
            cmdline.write_text(boot_options)
            initrd = initrd_path(state, kver)
            pcrsig = None
            pcrpkey = None

            # If a SecureBoot key is configured, and we have the
            # systemd-measure binary around, then also include a
            # signature of expected PCR 11 values in the kernel image
            if state.config.secure_boot and state.config.sign_expected_pcr:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization

                with complete_step("Generating PCR 11 signature…"):
                    # Extract the public key from the SecureBoot certificate
                    cert = x509.load_pem_x509_certificate(state.config.secure_boot_certificate.read_bytes())
                    pcrpkey = state.workspace / "pcrpkey.pem"
                    pcrpkey.write_bytes(cert.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo))

                    cmd_measure = [
                        "systemd-measure",
                        "sign",
                        f"--linux={state.root / kimg}",
                        f"--osrel={osrelease}",
                        f"--cmdline={cmdline}",
                        f"--initrd={initrd}",
                        f"--pcrpkey={pcrpkey}",
                        f"--private-key={state.config.secure_boot_key}",
                        f"--public-key={pcrpkey}",
                        "--bank=sha1",
                        "--bank=sha256",
                    ]

                    c = run(cmd_measure, stdout=subprocess.PIPE)

                    pcrsig = state.workspace / "pcrsig.json"
                    pcrsig.write_bytes(c.stdout)

            cmd: List[PathString] = [
                "objcopy",
                "--add-section", f".osrel={osrelease}",         "--change-section-vma",   ".osrel=0x20000",
                "--add-section", f".cmdline={cmdline}",         "--change-section-vma", ".cmdline=0x30000",
                "--add-section", f".linux={state.root / kimg}", "--change-section-vma",   ".linux=0x2000000",
                "--add-section", f".initrd={initrd}",           "--change-section-vma",  ".initrd=0x3000000",
            ]

            if pcrsig is not None:
                cmd += [
                    "--add-section", f".pcrsig={pcrsig}",       "--change-section-vma",  ".pcrsig=0x80000",
                    "--add-section", f".pcrpkey={pcrpkey}",     "--change-section-vma", ".pcrpkey=0x100000",
                ]

            cmd += [
                state.root / f"lib/systemd/boot/efi/linux{EFI_ARCHITECTURES[state.config.architecture]}.efi.stub",
                boot_binary,
            ]

            run(cmd)

            cmdline.unlink()
            if pcrsig is not None:
                pcrsig.unlink()
            if pcrpkey is not None:
                pcrpkey.unlink()


def secure_boot_sign(
    state: MkosiState,
    directory: Path,
    cached: bool,
    mount: Callable[[], ContextManager[None]],
    replace: bool = False,
) -> None:
    if state.do_run_build_script:
        return
    if not state.config.bootable:
        return
    if not state.config.secure_boot:
        return
    if state.for_cache and state.config.verity:
        return
    if cached and state.config.verity is False:
        return

    with mount():
        for f in itertools.chain(directory.glob('*.efi'), directory.glob('*.EFI')):
            if os.path.exists(f"{f}.signed"):
                MkosiPrinter.info(f"Not overwriting existing signed EFI binary {f}.signed")
                continue

            with complete_step(f"Signing EFI binary {f}…"):
                run(
                    [
                        "sbsign",
                        "--key",
                        state.config.secure_boot_key,
                        "--cert",
                        state.config.secure_boot_certificate,
                        "--output",
                        f"{f}.signed",
                        f,
                    ],
                )

                if replace:
                    os.rename(f"{f}.signed", f)


def extract_unified_kernel(
    state: MkosiState,
    mount: Callable[[], ContextManager[None]],
) -> Optional[BinaryIO]:

    if state.do_run_build_script or state.for_cache or not state.config.split_artifacts or not state.config.bootable:
        return None

    with mount():
        kernel = None

        for path, _, filenames in os.walk(state.root / "efi/EFI/Linux"):
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

        assert state.config.output_split_kernel is not None

        f = copy_file_temporary(kernel, state.config.output_split_kernel.parent)

    return f


def extract_kernel_image_initrd(
    state: MkosiState,
    mount: Callable[[], ContextManager[None]],
) -> Union[Tuple[BinaryIO, BinaryIO], Tuple[None, None]]:
    if state.do_run_build_script or state.for_cache or not state.config.bootable:
        return None, None

    with mount():
        kimgabs = None
        initrd = None

        for kver, kimg in gen_kernel_images(state):
            kimgabs = state.root / kimg
            initrd = initrd_path(state, kver)

        if kimgabs is None:
            die("No kernel image found, can't extract.")
        assert initrd is not None

        fkimg = copy_file_temporary(kimgabs, state.config.output_dir or Path())
        finitrd = copy_file_temporary(initrd, state.config.output_dir or Path())

    return (fkimg, finitrd)


def extract_kernel_cmdline(
    state: MkosiState,
    mount: Callable[[], ContextManager[None]],
) -> Optional[TextIO]:
    if state.do_run_build_script or state.for_cache or not state.config.bootable:
        return None

    with mount():
        if state.root.joinpath("etc/kernel/cmdline").exists():
            p = state.root / "etc/kernel/cmdline"
        elif state.root.joinpath("usr/lib/kernel/cmdline").exists():
            p = state.root / "usr/lib/kernel/cmdline"
        else:
            die("No cmdline found")

        # Direct Linux boot means we can't rely on systemd-gpt-auto-generator to
        # figure out the root partition for us so we have to encode it manually
        # in the kernel cmdline.
        cmdline = f"{p.read_text().strip()} root=LABEL={PartitionIdentifier.root.name}\n"

        f = cast(
            TextIO,
            tempfile.NamedTemporaryFile(mode="w+", prefix=".mkosi-", encoding="utf-8", dir=state.config.output_dir or Path()),
        )

        f.write(cmdline)
        f.flush()

    return f


def compress_output(
    config: MkosiConfig, data: Optional[BinaryIO], suffix: Optional[str] = None
) -> Optional[BinaryIO]:

    if data is None:
        return None
    compress = should_compress_output(config)

    if not compress:
        # If we shan't compress, then at least make the output file sparse
        with complete_step(f"Digging holes into output file {data.name}…"):
            run(["fallocate", "--dig-holes", data.name])

        return data

    with complete_step(f"Compressing output file {data.name}…"):
        f: BinaryIO = cast(
            BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", suffix=suffix, dir=os.path.dirname(config.output))
        )
        run([*compressor_command(compress), "--stdout", data.name], stdout=f)

    return f


def qcow2_output(config: MkosiConfig, raw: Optional[BinaryIO]) -> Optional[BinaryIO]:
    if not config.output_format.is_disk():
        return raw
    assert raw is not None

    if not config.qcow2:
        return raw

    with complete_step("Converting image file to qcow2…"):
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=os.path.dirname(config.output)))
        run(["qemu-img", "convert", "-onocow=on", "-fraw", "-Oqcow2", raw.name, f.name])

    return f


def write_root_hash_file(config: MkosiConfig, root_hash: Optional[str]) -> Optional[BinaryIO]:
    if root_hash is None:
        return None

    assert config.output_root_hash_file is not None

    suffix = roothash_suffix(config)
    with complete_step(f"Writing {suffix} file…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(mode="w+b", prefix=".mkosi", dir=os.path.dirname(config.output_root_hash_file)),
        )
        f.write((root_hash + "\n").encode())
        f.flush()

    return f


def write_root_hash_p7s_file(config: MkosiConfig, root_hash_p7s: Optional[bytes]) -> Optional[BinaryIO]:
    if root_hash_p7s is None:
        return None

    assert config.output_root_hash_p7s_file is not None

    suffix = roothash_p7s_suffix(config)
    with complete_step(f"Writing {suffix} file…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(
                mode="w+b", prefix=".mkosi", dir=config.output_root_hash_p7s_file.parent
            ),
        )
        f.write(root_hash_p7s)
        f.flush()

    return f


def copy_nspawn_settings(config: MkosiConfig) -> Optional[BinaryIO]:
    if config.nspawn_settings is None:
        return None

    assert config.output_nspawn_settings is not None

    with complete_step("Copying nspawn settings file…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(
                mode="w+b", prefix=".mkosi-", dir=os.path.dirname(config.output_nspawn_settings)
            ),
        )

        with open(config.nspawn_settings, "rb") as c:
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
    config: MkosiConfig, raw: Optional[BinaryIO],
    archive: Optional[BinaryIO],
    root_hash_file: Optional[BinaryIO],
    root_hash_p7s_file: Optional[BinaryIO],
    split_root: Optional[BinaryIO],
    split_verity: Optional[BinaryIO],
    split_verity_sig: Optional[BinaryIO],
    split_kernel: Optional[BinaryIO],
    nspawn_settings: Optional[BinaryIO],
) -> Optional[TextIO]:
    if config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        return None

    if not config.checksum:
        return None

    assert config.output_checksum is not None

    with complete_step("Calculating SHA256SUMS…"):
        f: TextIO = cast(
            TextIO,
            tempfile.NamedTemporaryFile(
                mode="w+", prefix=".mkosi-", encoding="utf-8", dir=os.path.dirname(config.output_checksum)
            ),
        )

        if raw is not None:
            hash_file(f, raw, os.path.basename(config.output))
        if archive is not None:
            hash_file(f, archive, os.path.basename(config.output))
        if root_hash_file is not None:
            assert config.output_root_hash_file is not None
            hash_file(f, root_hash_file, os.path.basename(config.output_root_hash_file))
        if root_hash_p7s_file is not None:
            assert config.output_root_hash_p7s_file is not None
            hash_file(f, root_hash_p7s_file, config.output_root_hash_p7s_file.name)
        if split_root is not None:
            assert config.output_split_root is not None
            hash_file(f, split_root, os.path.basename(config.output_split_root))
        if split_verity is not None:
            assert config.output_split_verity is not None
            hash_file(f, split_verity, os.path.basename(config.output_split_verity))
        if split_verity_sig is not None:
            assert config.output_split_verity_sig is not None
            hash_file(f, split_verity_sig, config.output_split_verity_sig.name)
        if split_kernel is not None:
            assert config.output_split_kernel is not None
            hash_file(f, split_kernel, os.path.basename(config.output_split_kernel))
        if nspawn_settings is not None:
            assert config.output_nspawn_settings is not None
            hash_file(f, nspawn_settings, os.path.basename(config.output_nspawn_settings))

        f.flush()

    return f


def calculate_signature(state: MkosiState, checksum: Optional[IO[Any]]) -> Optional[BinaryIO]:
    if not state.config.sign:
        return None

    if checksum is None:
        return None

    assert state.config.output_signature is not None

    with complete_step("Signing SHA256SUMS…"):
        f: BinaryIO = cast(
            BinaryIO,
            tempfile.NamedTemporaryFile(mode="wb", prefix=".mkosi-", dir=os.path.dirname(state.config.output_signature)),
        )

        cmdline = ["gpg", "--detach-sign"]

        if state.config.key is not None:
            cmdline += ["--default-key", state.config.key]

        checksum.seek(0)
        run(cmdline, stdin=checksum, stdout=f)

    return f


def calculate_bmap(config: MkosiConfig, raw: Optional[BinaryIO]) -> Optional[TextIO]:
    if not config.bmap:
        return None

    if not config.output_format.is_disk_rw():
        return None
    assert raw is not None
    assert config.output_bmap is not None

    with complete_step("Creating BMAP file…"):
        f: TextIO = cast(
            TextIO,
            tempfile.NamedTemporaryFile(
                mode="w+", prefix=".mkosi-", encoding="utf-8", dir=os.path.dirname(config.output_bmap)
            ),
        )

        cmdline = ["bmaptool", "create", raw.name]
        run(cmdline, stdout=f)

    return f


def save_cache(state: MkosiState, raw: Optional[str], cache_path: Optional[Path]) -> None:
    disk_rw = state.config.output_format.is_disk_rw()
    if disk_rw:
        if raw is None or cache_path is None:
            return
    else:
        if cache_path is None:
            return

    with complete_step("Installing cache copy…", f"Installed cache copy {path_relative_to_cwd(cache_path)}"):

        if disk_rw:
            assert raw is not None
            shutil.move(raw, cache_path)
        else:
            unlink_try_hard(cache_path)
            shutil.move(cast(str, state.root), cache_path)  # typing bug, .move() accepts Path

    if not state.config.no_chown:
        chown_to_running_user(cache_path)


def _link_output(
        config: MkosiConfig,
        oldpath: PathString,
        newpath: PathString,
        mode: int = 0o666,
) -> None:

    assert oldpath is not None
    assert newpath is not None

    os.chmod(oldpath, mode)

    os.link(oldpath, newpath)

    if config.no_chown:
        return

    relpath = path_relative_to_cwd(newpath)
    chown_to_running_user(relpath)


def link_output(state: MkosiState, artifact: Optional[BinaryIO]) -> None:
    with complete_step("Linking image file…", f"Linked {path_relative_to_cwd(state.config.output)}"):
        if state.config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
            if not state.root.exists():
                return

            assert artifact is None

            make_read_only(state, state.root, b=False)
            os.rename(state.root, state.config.output)
            make_read_only(state, state.config.output, b=True)

        elif state.config.output_format.is_disk() or state.config.output_format in (
            OutputFormat.plain_squashfs,
            OutputFormat.tar,
            OutputFormat.cpio,
        ):
            if artifact is None:
                return

            _link_output(state.config, artifact.name, state.config.output)


def link_output_nspawn_settings(config: MkosiConfig, path: Optional[SomeIO]) -> None:
    if path:
        assert config.output_nspawn_settings
        with complete_step(
            "Linking nspawn settings file…", f"Linked {path_relative_to_cwd(config.output_nspawn_settings)}"
        ):
            _link_output(config, path.name, config.output_nspawn_settings)


def link_output_checksum(config: MkosiConfig, checksum: Optional[SomeIO]) -> None:
    if checksum:
        assert config.output_checksum
        with complete_step("Linking SHA256SUMS file…", f"Linked {path_relative_to_cwd(config.output_checksum)}"):
            _link_output(config, checksum.name, config.output_checksum)


def link_output_root_hash_file(config: MkosiConfig, root_hash_file: Optional[SomeIO]) -> None:
    if root_hash_file:
        assert config.output_root_hash_file
        suffix = roothash_suffix(config)
        with complete_step(f"Linking {suffix} file…", f"Linked {path_relative_to_cwd(config.output_root_hash_file)}"):
            _link_output(config, root_hash_file.name, config.output_root_hash_file)


def link_output_root_hash_p7s_file(config: MkosiConfig, root_hash_p7s_file: Optional[SomeIO]) -> None:
    if root_hash_p7s_file:
        assert config.output_root_hash_p7s_file
        suffix = roothash_p7s_suffix(config)
        with complete_step(
            f"Linking {suffix} file…", f"Linked {path_relative_to_cwd(config.output_root_hash_p7s_file)}"
        ):
            _link_output(config, root_hash_p7s_file.name, config.output_root_hash_p7s_file)


def link_output_signature(config: MkosiConfig, signature: Optional[SomeIO]) -> None:
    if signature:
        assert config.output_signature is not None
        with complete_step("Linking SHA256SUMS.gpg file…", f"Linked {path_relative_to_cwd(config.output_signature)}"):
            _link_output(config, signature.name, config.output_signature)


def link_output_bmap(config: MkosiConfig, bmap: Optional[SomeIO]) -> None:
    if bmap:
        assert config.output_bmap
        with complete_step("Linking .bmap file…", f"Linked {path_relative_to_cwd(config.output_bmap)}"):
            _link_output(config, bmap.name, config.output_bmap)


def link_output_sshkey(config: MkosiConfig, sshkey: Optional[SomeIO]) -> None:
    if sshkey:
        assert config.output_sshkey
        with complete_step("Linking private ssh key file…", f"Linked {path_relative_to_cwd(config.output_sshkey)}"):
            _link_output(config, sshkey.name, config.output_sshkey, mode=0o600)


def link_output_split_root(config: MkosiConfig, split_root: Optional[SomeIO]) -> None:
    if split_root:
        assert config.output_split_root
        with complete_step(
            "Linking split root file system…", f"Linked {path_relative_to_cwd(config.output_split_root)}"
        ):
            _link_output(config, split_root.name, config.output_split_root)


def link_output_split_verity(config: MkosiConfig, split_verity: Optional[SomeIO]) -> None:
    if split_verity:
        assert config.output_split_verity
        with complete_step("Linking split Verity data…", f"Linked {path_relative_to_cwd(config.output_split_verity)}"):
            _link_output(config, split_verity.name, config.output_split_verity)


def link_output_split_verity_sig(config: MkosiConfig, split_verity_sig: Optional[SomeIO]) -> None:
    if split_verity_sig:
        assert config.output_split_verity_sig
        with complete_step(
            "Linking split Verity Signature data…", f"Linked {path_relative_to_cwd(config.output_split_verity_sig)}"
        ):
            _link_output(config, split_verity_sig.name, config.output_split_verity_sig)


def link_output_split_kernel(config: MkosiConfig, split_kernel: Optional[SomeIO]) -> None:
    if split_kernel:
        assert config.output_split_kernel
        with complete_step("Linking split kernel…", f"Linked {path_relative_to_cwd(config.output_split_kernel)}"):
            _link_output(config, split_kernel.name, config.output_split_kernel)


def link_output_split_kernel_image(config: MkosiConfig, split_kernel_image: Optional[SomeIO]) -> None:
    if split_kernel_image:
        output = build_auxiliary_output_path(config, '.vmlinuz')
        with complete_step("Linking split kernel image…", f"Linked {path_relative_to_cwd(output)}"):
            _link_output(config, split_kernel_image.name, output)


def link_output_split_initrd(config: MkosiConfig, split_initrd: Optional[SomeIO]) -> None:
    if split_initrd:
        output = build_auxiliary_output_path(config, '.initrd')
        with complete_step("Linking split initrd…", f"Linked {path_relative_to_cwd(output)}"):
            _link_output(config, split_initrd.name, output)


def link_output_split_kernel_cmdline(config: MkosiConfig, split_kernel_cmdline: Optional[SomeIO]) -> None:
    if split_kernel_cmdline:
        output = build_auxiliary_output_path(config, '.cmdline')
        with complete_step("Linking split cmdline…", f"Linked {path_relative_to_cwd(output)}"):
            _link_output(config, split_kernel_cmdline.name, output)


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


def save_manifest(config: MkosiConfig, manifest: Manifest) -> None:
    if manifest.has_data():
        relpath = path_relative_to_cwd(config.output)

        if ManifestFormat.json in config.manifest_format:
            with complete_step(f"Saving manifest {relpath}.manifest"):
                f: TextIO = cast(
                    TextIO,
                    tempfile.NamedTemporaryFile(
                        mode="w+",
                        encoding="utf-8",
                        prefix=".mkosi-",
                        dir=os.path.dirname(config.output),
                    ),
                )
                with f:
                    manifest.write_json(f)
                    _link_output(config, f.name, f"{config.output}.manifest")

        if ManifestFormat.changelog in config.manifest_format:
            with complete_step(f"Saving report {relpath}.changelog"):
                g: TextIO = cast(
                    TextIO,
                    tempfile.NamedTemporaryFile(
                        mode="w+",
                        encoding="utf-8",
                        prefix=".mkosi-",
                        dir=os.path.dirname(config.output),
                    ),
                )
                with g:
                    manifest.write_package_report(g)
                    _link_output(config, g.name, f"{relpath}.changelog")


def print_output_size(config: MkosiConfig) -> None:
    if not config.output.exists():
        return

    if config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        MkosiPrinter.print_step("Resulting image size is " + format_bytes(dir_size(config.output)) + ".")
    else:
        st = os.stat(config.output)
        size = format_bytes(st.st_size)
        space = format_bytes(st.st_blocks * 512)
        MkosiPrinter.print_step(f"Resulting image size is {size}, consumes {space}.")


def setup_package_cache(config: MkosiConfig, workspace: Path) -> Path:
    if not config.cache_path:
        cache = workspace / "cache"
    else:
        cache = config.cache_path
        mkdirp_chown_current_user(cache, skip_chown=config.no_chown, mode=0o755)

    return cache


def remove_duplicates(items: List[T]) -> List[T]:
    "Return list with any repetitions removed"
    # We use a dictionary to simulate an ordered set
    return list({x: None for x in items})


class ListAction(argparse.Action):
    delimiter: str
    deduplicate: bool = True

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

        if isinstance(values, (str, Path)):
            # Save the actual type so we can restore it later after processing the argument
            t = type(values)
            values = str(values)
            # Support list syntax for comma separated lists as well
            if self.delimiter == "," and values.startswith("[") and values.endswith("]"):
                values = values[1:-1]

            # Make sure delimiters between quotes are ignored.
            # Inspired by https://stackoverflow.com/a/2787979.
            values = [t(x.strip()) for x in re.split(f"""{self.delimiter}(?=(?:[^'"]|'[^']*'|"[^"]*")*$)""", values) if x]

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

        if self.deduplicate:
            ary = remove_duplicates(ary)
        setattr(namespace, self.dest, ary)


class CommaDelimitedListAction(ListAction):
    delimiter = ","


class ColonDelimitedListAction(ListAction):
    delimiter = ":"


class SpaceDelimitedListAction(ListAction):
    delimiter = " "


class RepeatableSpaceDelimitedListAction(SpaceDelimitedListAction):
    deduplicate = False


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


def parse_sign_expected_pcr(value: Union[bool, str]) -> bool:
    if isinstance(value, bool):
        return value

    if value == "auto":
        try:
            # TODO: pyright stumbles over this with
            # "import_module" is not a known member of module (reportGeneralTypeIssues)
            # although importlib.import_module exists in Python 3.7
            # a regular import trips pyflakes, though and I haven't found a way
            # to silence that
            importlib.import_module("cryptography") # type: ignore
            return True if shutil.which('systemd-measure') else False
        except ImportError:
            return False

    val = parse_boolean(value)
    if val:
        try:
            importlib.import_module("cryptography") # type: ignore
        except ImportError:
            die("Couldn't import the cryptography Python module. This is needed for the --sign-expected-pcr option.")

        if not shutil.which('systemd-measure'):
            die("Couldn't find systemd-measure binary. It is needed for the --sign-expected-pcr option.")

    return val


class SignExpectedPcrAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:
        if values is None:
            parsed = False
        elif isinstance(values, bool) or isinstance(values, str):
            parsed = parse_sign_expected_pcr(values)
        else:
            raise argparse.ArgumentError(self, f"Invalid argument for {option_string}: {values}")
        setattr(namespace, self.dest, parsed)


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string

    def _split_lines(self, text: str, width: int) -> List[str]:
        """Wraps text to width, each line separately.
        If the first line of text ends in a colon, we assume that
        this is a list of option descriptions, and subindent them.
        Otherwise, the text is wrapped without indentation.
        """
        lines = text.splitlines()
        subindent = '    ' if lines[0].endswith(':') else ''
        return list(itertools.chain.from_iterable(wrap(line, width,
                                                       break_long_words=False, break_on_hyphens=False,
                                                       subsequent_indent=subindent) for line in lines))


class ArgumentParserMkosi(argparse.ArgumentParser):
    """ArgumentParser with support for mkosi configuration file(s)

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
        "MachineID": "--machine-id",
        "SignExpectedPCR": "--sign-expected-pcr",
    }

    def __init__(self, *kargs: Any, **kwargs: Any) -> None:
        self._ini_file_section = ""
        self._ini_file_key = ""  # multi line list processing
        self._ini_file_list_mode = False

        # we need to suppress mypy here: https://github.com/python/mypy/issues/6799
        super().__init__(*kargs,
                         # Add config files to be parsed:
                         fromfile_prefix_chars='@',
                         formatter_class=CustomHelpFormatter,
                         # Tweak defaults:
                         allow_abbrev=False,
                         # Pass through the other options:
                         **kwargs,
                         ) # type: ignore

    @staticmethod
    def _camel_to_arg(camel: str) -> str:
        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1-\2", camel)
        return re.sub("([a-z0-9])([A-Z])", r"\1-\2", s1).lower()

    @classmethod
    def _ini_key_to_cli_arg(cls, key: str) -> str:
        return cls.SPECIAL_MKOSI_DEFAULT_PARAMS.get(key) or ("--" + cls._camel_to_arg(key))

    def _read_args_from_files(self, arg_strings: List[str]) -> List[str]:
        """Convert @-prefixed command line arguments with corresponding file content

        Regular arguments are just returned. Arguments prefixed with @ are considered
        configuration file paths. The settings of each file are parsed and returned as
        command line arguments.
        Example:
          The following mkosi config is loaded.
          [Distribution]
          Distribution=fedora

          mkosi is called like: mkosi -p httpd

          arg_strings: ['@mkosi.conf', '-p', 'httpd']
          return value: ['--distribution', 'fedora', '-p', 'httpd']
        """

        # expand arguments referencing files
        new_arg_strings = []
        for arg_string in arg_strings:
            # for regular arguments, just add them back into the list
            if not arg_string.startswith('@'):
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
                        new_arg_strings.append(f"{cli_arg}={value}")
            except OSError as e:
                self.error(str(e))
        # return the modified argument list
        return new_arg_strings

    def error(self, message: str) -> NoReturn:
        # This is a copy of super's method but with self.print_usage() removed
        self.exit(2, f'{self.prog}: error: {message}\n')


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

USAGE = """
       mkosi [options...] {b}summary{e}
       mkosi [options...] {b}build{e} [script parameters...]
       mkosi [options...] {b}shell{e} [command line...]
       mkosi [options...] {b}boot{e} [nspawn settings...]
       mkosi [options...] {b}qemu{e} [qemu parameters...]
       mkosi [options...] {b}ssh{e} [command line...]
       mkosi [options...] {b}clean{e}
       mkosi [options...] {b}serve{e}
       mkosi [options...] {b}bump{e}
       mkosi [options...] {b}genkey{e}
       mkosi [options...] {b}help{e}
       mkosi -h | --help
       mkosi --version
""".format(b=MkosiPrinter.bold, e=MkosiPrinter.reset)

def create_parser() -> ArgumentParserMkosi:
    parser = ArgumentParserMkosi(
        prog="mkosi",
        description="Build Bespoke OS Images",
        usage=USAGE,
        add_help=False,
    )

    parser.add_argument(
        "verb",
        type=Verb,
        choices=list(Verb),
        default=Verb.build,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "cmdline",
        nargs=argparse.REMAINDER,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-h", "--help",
        action="help",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + __version__,
        help=argparse.SUPPRESS,
    )

    group = parser.add_argument_group("Distribution options")
    group.add_argument("-d", "--distribution", choices=Distribution.__members__, help="Distribution to install")
    group.add_argument("-r", "--release", help="Distribution release to install")
    group.add_argument("--architecture", help="Override the architecture of installation", default=platform.machine())
    group.add_argument("-m", "--mirror", help="Distribution mirror to use")
    group.add_argument("--local-mirror", help="Use a single local, flat and plain mirror to build the image",
    )
    group.add_argument(
        "--repository-key-check",
        metavar="BOOL",
        action=BooleanAction,
        help="Controls signature and key checks on repositories",
        default=True,
    )

    group.add_argument(
        "--repositories",
        metavar="REPOS",
        action=CommaDelimitedListAction,
        default=[],
        help="Repositories to use",
    )
    group.add_argument(
        "--use-host-repositories",
        metavar="BOOL",
        action=BooleanAction,
        help="Use host's existing software repositories (only for dnf-based distributions)",
    )
    group.add_argument(
        "--repository-directory",
        metavar="PATH",
        dest="repos_dir",
        help="Directory container extra distribution specific repository files",
    )

    group = parser.add_argument_group("Output options")
    group.add_argument(
        "-t", "--format",
        dest="output_format",
        metavar="FORMAT",
        choices=OutputFormat,
        type=OutputFormat.from_string,
        help="Output Format",
    )
    group.add_argument(
        "--manifest-format",
        metavar="FORMAT",
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
        "-f", "--force",
        action="count",
        dest="force",
        default=0,
        help="Remove existing image file before operation",
    )
    group.add_argument(
        "-b", "--bootable",
        metavar="BOOL",
        action=BooleanAction,
        help="Make image bootable on EFI (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    group.add_argument(
        "--boot-protocols",
        action=CommaDelimitedListAction,
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--kernel-command-line",
        metavar="OPTIONS",
        action=SpaceDelimitedListAction,
        default=["rhgb", "selinux=0", "audit=0"],
        help="Set the kernel command line (only bootable images)",
    )
    group.add_argument(
        "--kernel-commandline",       # Compatibility option
        action=SpaceDelimitedListAction,
        dest="kernel_command_line",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--secure-boot",
        metavar="BOOL",
        action=BooleanAction,
        help="Sign the resulting kernel/initrd image for UEFI SecureBoot",
    )
    group.add_argument(
        "--secure-boot-key",
        help="UEFI SecureBoot private key in PEM format",
        type=Path,
        metavar="PATH",
        default=Path("./mkosi.secure-boot.key"),
    )
    group.add_argument(
        "--secure-boot-certificate",
        help="UEFI SecureBoot certificate in X509 format",
        type=Path,
        metavar="PATH",
        default=Path("./mkosi.secure-boot.crt"),
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
        metavar="BOOL",
        action=BooleanAction,
        help="Make root volume read-only (only gpt_ext4, gpt_xfs, gpt_btrfs, subvolume, implied with gpt_squashfs and plain_squashfs)",
    )
    group.add_argument(
        "--encrypt",
        choices=("all", "data"),
        help='Encrypt everything except: ESP ("all") or ESP and root ("data")'
    )
    group.add_argument(
        "--verity",
        action=VerityAction,
        help="Add integrity partition, and optionally sign it (implies --read-only)",
    )
    group.add_argument(
        "--sign-expected-pcr",
        metavar="BOOL",
        default="auto",
        action=SignExpectedPcrAction,
        type=parse_sign_expected_pcr,
        help="Measure the components of the unified kernel image (UKI) and embed the PCR signature into the UKI",
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
        metavar="BOOL",
        help="Convert resulting image to qcow2 (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    group.add_argument("--hostname", help="Set hostname")
    group.add_argument("--image-version", help="Set version for image")
    group.add_argument("--image-id", help="Set ID for image")
    group.add_argument(
        "--no-chown",
        metavar="BOOL",
        action=BooleanAction,
        help="When running with sudo, disable reassignment of ownership of the generated files to the original user",
    )  # NOQA: E501
    group.add_argument(
        "--tar-strip-selinux-context",
        metavar="BOOL",
        action=BooleanAction,
        help="Do not include SELinux file context information in tar. Not compatible with bsdtar.",
    )
    group.add_argument(
        "-i", "--incremental",
        metavar="BOOL",
        action=BooleanAction,
        help="Make use of and generate intermediary cache images",
    )
    group.add_argument(
        "-M", "--minimize",
        metavar="BOOL",
        action=BooleanAction,
        help="Minimize root file system size",
    )
    group.add_argument(
        "--without-unified-kernel-images",
        action=BooleanAction,
        dest="with_unified_kernel_images",
        default=True,
        help="Do not install unified kernel images",
    )
    group.add_argument(
        "--with-unified-kernel-images",
        metavar="BOOL",
        action=BooleanAction,
        default=True,
        help=argparse.SUPPRESS,
    )
    group.add_argument("--gpt-first-lba", type=int, help="Set the first LBA within GPT Header", metavar="FIRSTLBA")
    group.add_argument(
        "--hostonly-initrd",
        metavar="BOOL",
        action=BooleanAction,
        help="Enable dracut hostonly option",
    )
    group.add_argument(
        "--cache-initrd",
        metavar="BOOL",
        action=BooleanAction,
        help="When using incremental mode, build the initrd in the cache image and don't rebuild it in the final image",
    )
    group.add_argument(
        "--split-artifacts",
        metavar="BOOL",
        action=BooleanAction,
        help="Generate split out root/verity/kernel images, too",
    )

    group = parser.add_argument_group("Content options")
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
    group.add_argument(
        "--with-docs",
        metavar="BOOL",
        action=BooleanAction,
        help="Install documentation",
    )
    group.add_argument(
        "-T", "--without-tests",
        action=BooleanAction,
        dest="with_tests",
        default=True,
        help="Do not run tests as part of build script, if supported",
    )
    group.add_argument(
        "--with-tests",       # Compatibility option
        action=BooleanAction,
        default=True,
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--machine-id",
        help="Defines a fixed machine ID for all our build-time runs.",
    )

    group.add_argument("--password", help="Set the root password")
    group.add_argument(
        "--password-is-hashed",
        metavar="BOOL",
        action=BooleanAction,
        help="Indicate that the root password has already been hashed",
    )
    group.add_argument(
        "--autologin",
        metavar="BOOL",
        action=BooleanAction,
        help="Enable root autologin",
    )
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
        "--build-environment",   # Compatibility option
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
        "--build-dir",           # Compatibility option
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
        "--skip-final-phase",
        metavar="BOOL",
        action=BooleanAction,
        help="Skip the (second) final image building phase.",
        default=False,
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
        metavar="METHOD",
        default=None,
        help='\n'.join(('How to copy build sources to the build image:',
                        *(f"'{k}': {v}" for k, v in SourceFileTransfer.doc().items()),
                        '(default: copy-git-others if in a git repository, otherwise copy-all)')),
    )
    group.add_argument(
        "--source-file-transfer-final",
        type=parse_source_file_transfer,
        choices=[*list(SourceFileTransfer), None],
        metavar="METHOD",
        default=None,
        help='\n'.join(('How to copy build sources to the final image:',
                        *(f"'{k}': {v}" for k, v in SourceFileTransfer.doc().items()
                          if k != SourceFileTransfer.mount),
                        '(default: None)')),
    )
    group.add_argument(
        "--source-resolve-symlinks",
        metavar="BOOL",
        action=BooleanAction,
        help=("If true, symbolic links in the build sources are followed and the "
              "file contents copied to the build image. If false, they are left as "
              "symbolic links. "
              "Only applies if --source-file-transfer-final is set to 'copy-all'.\n"
              "(default: false)"),
    )
    group.add_argument(
        "--source-resolve-symlinks-final",
        metavar="BOOL",
        action=BooleanAction,
        help=("If true, symbolic links in the build sources are followed and the "
              "file contents copied to the final image. If false, they are left as "
              "symbolic links in the final image. "
              "Only applies if --source-file-transfer-final is set to 'copy-all'.\n"
              "(default: false)"),
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

    group = parser.add_argument_group("Partitions options")
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
        "--home-size", help="Set size of /home partition (only for GPT images)", metavar="BYTES"
    )
    group.add_argument(
        "--srv-size", help="Set size of /srv partition (only for GPT images)", metavar="BYTES"
    )
    group.add_argument(
        "--var-size", help="Set size of /var partition (only for GPT images)", metavar="BYTES"
    )
    group.add_argument(
        "--tmp-size", help="Set size of /var/tmp partition (only for GPT images)", metavar="BYTES"
    )
    group.add_argument(
        "--bios-size", help="Set size of BIOS boot partition (only for GPT images)", metavar="BYTES",
    )
    group.add_argument(
        "--usr-only",
        metavar="BOOL",
        action=BooleanAction,
        help="Generate a /usr/ partition instead of a root partition",
    )

    group = parser.add_argument_group("Validation options (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs, tar, cpio)")
    group.add_argument(
        "--checksum",
        metavar="BOOL",
        action=BooleanAction,
        help="Write SHA256SUMS file",
    )
    group.add_argument(
        "--sign",
        metavar="BOOL",
        action=BooleanAction,
        help="Write and sign SHA256SUMS file",
    )
    group.add_argument("--key", help="GPG key to use for signing")
    group.add_argument(
        "--bmap",
        metavar="BOOL",
        action=BooleanAction,
        help="Write block map file (.bmap) for bmaptool usage (only gpt_ext4, gpt_btrfs)",
    )

    group = parser.add_argument_group("Host configuration options")
    group.add_argument(
        "--extra-search-path",
        dest="extra_search_paths",
        action=ColonDelimitedListAction,
        default=[],
        type=Path,
        help="List of colon-separated paths to look for programs before looking in PATH",
    )
    group.add_argument(
        "--extra-search-paths",    # Compatibility option
        dest="extra_search_paths",
        action=ColonDelimitedListAction,
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--qemu-headless",
        metavar="BOOL",
        action=BooleanAction,
        help="Configure image for qemu's -nographic mode",
    )
    group.add_argument(
        "--qemu-smp",
        metavar="SMP",
        default="1",
        help="Configure guest's SMP settings",
    )
    group.add_argument(
        "--qemu-mem",
        metavar="MEM",
        default="1G",
        help="Configure guest's RAM size",
    )
    group.add_argument(
        "--qemu-kvm",
        metavar="BOOL",
        action=BooleanAction,
        help="Configure whether to use KVM or not",
        default=qemu_check_kvm_support(),
    )
    group.add_argument(
        "--qemu-args",
        action=RepeatableSpaceDelimitedListAction,
        default=[],
        # Suppress the command line option because it's already possible to pass qemu args as normal
        # arguments.
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--nspawn-keep-unit",
        metavar="BOOL",
        action=BooleanAction,
        help="If specified, underlying systemd-nspawn containers use the resources of the current unit.",
    )
    group.add_argument(
        "--qemu-boot",
        help="Configure which qemu boot protocol to use",
        choices=["uefi", "linux", None],
        metavar="PROTOCOL",
        default="uefi",
    )
    group.add_argument(
        "--network-veth",     # Compatibility option
        dest="netdev",
        metavar="BOOL",
        action=BooleanAction,
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--netdev",
        metavar="BOOL",
        action=BooleanAction,
        help="Create a virtual Ethernet link between the host and the container/VM",
    )
    group.add_argument(
        "--ephemeral",
        metavar="BOOL",
        action=BooleanAction,
        help=('If specified, the container/VM is run with a temporary snapshot of the output '
              'image that is removed immediately when the container/VM terminates'),
    )
    group.add_argument(
        "--ssh",
        metavar="BOOL",
        action=BooleanAction,
        help="Set up SSH access from the host to the final image via 'mkosi ssh'",
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

    group = parser.add_argument_group("Additional configuration options")
    group.add_argument(
        "-C", "--directory",
        help="Change to specified directory before doing anything",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--config",
        dest="config_path",
        help="Read configuration data from file",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--default",
        dest="config_path",
        help=argparse.SUPPRESS,
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "-a", "--all",
        action="store_true",
        dest="all",
        default=False,
        help="Build all settings files in mkosi.files/",
    )
    group.add_argument(
        "--all-directory",
        metavar="PATH",
        type=Path,
        dest="all_directory",
        help="Specify path to directory to read settings files from",
    )
    group.add_argument(
        "-B",
        "--auto-bump",
        metavar="BOOL",
        action=BooleanAction,
        help="Automatically bump image version after building",
    )
    group.add_argument(
        "--debug",
        action=CommaDelimitedListAction,
        default=[],
        help="Turn on debugging output",
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

        if args.distribution == d and args.release is None:
            args.release = r

    if args.distribution is None:
        die("Couldn't detect distribution.")

    return args


def parse_args(argv: Optional[Sequence[str]] = None) -> Dict[str, argparse.Namespace]:
    """Load config values from files and parse command line arguments

    Do all about config files and command line arguments parsing. If --all argument is passed
    more than one job needs to be processed. The returned tuple contains MkosiConfig
    valid for all jobs as well as a dict containing the arguments per job.
    """
    parser = create_parser()

    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)  # make a copy 'cause we'll be modifying the list later on

    # If ArgumentParserMkosi loads settings from mkosi configuration files, the settings from files
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

    # First run of command line arguments parsing to get the directory of the config file and the verb argument.
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

    # Note that directory will be ignored if .all_directory or .config_path are absolute
    all_directory = directory / (args_pre_parsed.all_directory or "mkosi.files")
    if args_pre_parsed.config_path and not directory.joinpath(args_pre_parsed.config_path).exists():
        die(f"No config file found at {directory / args_pre_parsed.config_path}")

    for name in (args_pre_parsed.config_path, "mkosi.conf"):
        if not name:
            continue

        config_path = directory / name
        if config_path.exists():
            break
    else:
        config_path = directory / "mkosi.default"

    if args_pre_parsed.all and args_pre_parsed.config_path:
        die("--all and --config= may not be combined.")

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
        args = parse_args_file_group(argv, config_path)

        args = load_distribution(args)

        if args.distribution:
            # Parse again with any extra distribution files included.
            args = parse_args_file_group(argv, config_path, args.distribution)

        args_all["default"] = args

    return args_all


def parse_args_file(argv: List[str], config_path: Path) -> argparse.Namespace:
    """Parse just one mkosi.* file (--all mode)."""

    # Parse all parameters handled by mkosi.
    # Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    argv = argv[:1] + [f"@{config_path}"] + argv[1:]

    return create_parser().parse_args(argv)


def parse_args_file_group(
    argv: List[str], config_path: Path, distribution: Optional[Distribution] = None
) -> argparse.Namespace:
    """Parse a set of mkosi config files"""
    # Add the @ prefixed filenames to current argument list in inverse priority order.
    config_files = []

    if config_path.exists():
        config_files += [f"@{config_path}"]

    d = config_path.parent

    dirs = [Path("mkosi.conf.d"), Path("mkosi.default.d")]
    if not d.samefile(Path.cwd()):
        dirs += [Path(d / "mkosi.conf.d"), Path(d / "mkosi.default.d")]

    if distribution is not None:
        dirs += [d / str(distribution) for d in dirs]

    for dropin_dir in dirs:
        if dropin_dir.is_dir():
            for entry in sorted(dropin_dir.iterdir()):
                if entry.is_file():
                    config_files += [f"@{entry}"]

    # Parse all parameters handled by mkosi.
    # Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    return create_parser().parse_args(config_files + argv)


def parse_bytes(num_bytes: Optional[str], *, sector_size: int = 512) -> int:
    """Convert a string for a number of bytes into a number rounding up to sector size."""
    if num_bytes is None:
        return 0

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

    result = math.ceil(float(num_bytes) * factor)
    if result <= 0:
        raise ValueError("Size out of range")

    rem = result % sector_size
    if rem != 0:
        result += sector_size - rem

    return result


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


def unlink_output(config: MkosiConfig) -> None:
    if not config.skip_final_phase:
        with complete_step("Removing output files…"):
            unlink_try_hard(config.output)
            unlink_try_hard(f"{config.output}.manifest")
            unlink_try_hard(f"{config.output}.changelog")

            if config.checksum:
                unlink_try_hard(config.output_checksum)

            if config.verity:
                unlink_try_hard(config.output_root_hash_file)
            if config.verity == "signed":
                unlink_try_hard(config.output_root_hash_p7s_file)

            if config.sign:
                unlink_try_hard(config.output_signature)

            if config.bmap:
                unlink_try_hard(config.output_bmap)

            if config.split_artifacts:
                unlink_try_hard(config.output_split_root)
                unlink_try_hard(config.output_split_verity)
                unlink_try_hard(config.output_split_verity_sig)
                unlink_try_hard(config.output_split_kernel)

            unlink_try_hard(build_auxiliary_output_path(config, ".vmlinuz"))
            unlink_try_hard(build_auxiliary_output_path(config, ".initrd"))
            unlink_try_hard(build_auxiliary_output_path(config, ".cmdline"))

            if config.nspawn_settings is not None:
                unlink_try_hard(config.output_nspawn_settings)

        if config.ssh and config.output_sshkey is not None:
            unlink_try_hard(config.output_sshkey)

    # We remove any cached images if either the user used --force
    # twice, or he/she called "clean" with it passed once. Let's also
    # remove the downloaded package cache if the user specified one
    # additional "--force".

    if config.verb == Verb.clean:
        remove_build_cache = config.force > 0
        remove_package_cache = config.force > 1
    else:
        remove_build_cache = config.force > 1
        remove_package_cache = config.force > 2

    if remove_build_cache:
        cache_pre_dev = cache_image_path(config, is_final_image=False)
        cache_pre_inst = cache_image_path(config, is_final_image=True)

        if cache_pre_dev is not None or cache_pre_inst is not None:
            with complete_step("Removing incremental cache files…"):
                if cache_pre_dev is not None:
                    unlink_try_hard(cache_pre_dev)

                if cache_pre_inst is not None:
                    unlink_try_hard(cache_pre_inst)

        if config.build_dir is not None:
            with complete_step("Clearing out build directory…"):
                empty_directory(config.build_dir)

        if config.include_dir is not None:
            with complete_step("Clearing out include directory…"):
                empty_directory(config.include_dir)

        if config.install_dir is not None:
            with complete_step("Clearing out install directory…"):
                empty_directory(config.install_dir)

    if remove_package_cache:
        if config.cache_path is not None:
            with complete_step("Clearing out package cache…"):
                empty_directory(config.cache_path)


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


def find_output(args: argparse.Namespace) -> None:
    subdir = f"{args.distribution}~{args.release}"

    if args.output_dir is not None:
        args.output_dir = Path(args.output_dir, subdir)
    elif os.path.exists("mkosi.output/"):
        args.output_dir = Path("mkosi.output", subdir)
    else:
        return


def find_builddir(args: argparse.Namespace) -> None:
    subdir = f"{args.distribution}~{args.release}"

    if args.build_dir is not None:
        args.build_dir = Path(args.build_dir, subdir)
    elif os.path.exists("mkosi.builddir/"):
        args.build_dir = Path("mkosi.builddir", subdir)
    else:
        return


def find_cache(args: argparse.Namespace) -> None:
    subdir = f"{args.distribution}~{args.release}"

    if args.cache_path is not None:
        args.cache_path = Path(args.cache_path, subdir)
    elif os.path.exists("mkosi.cache/"):
        args.cache_path = Path("mkosi.cache", subdir)
    else:
        return


def require_private_file(name: str, description: str) -> None:
    mode = os.stat(name).st_mode & 0o777
    if mode & 0o007:
        warn(dedent(f"""\
            Permissions of '{name}' of '{mode:04o}' are too open.
            When creating {description} files use an access mode that restricts access to the owner only.
        """))


def find_passphrase(args: argparse.Namespace) -> None:
    if not needs_build(args) or args.encrypt is None:
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
    if not needs_build(args) or args.password is not None:
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


def build_auxiliary_output_path(args: Union[argparse.Namespace, MkosiConfig], suffix: str, can_compress: bool = False) -> Path:
    output = strip_suffixes(args.output)
    should_compress = should_compress_output(args)
    compression = f".{should_compress}" if can_compress and should_compress else ''
    return output.with_name(f"{output.name}{suffix}{compression}")


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
    return Path(path).absolute()


def load_args(args: argparse.Namespace) -> MkosiConfig:
    global ARG_DEBUG
    ARG_DEBUG.update(args.debug)

    args_find_path(args, "nspawn_settings", "mkosi.nspawn")
    args_find_path(args, "build_script", "mkosi.build")
    args_find_path(args, "build_sources", ".")
    args_find_path(args, "include_dir", "mkosi.includedir/")
    args_find_path(args, "install_dir", "mkosi.installdir/")
    args_find_path(args, "postinst_script", "mkosi.postinst")
    args_find_path(args, "prepare_script", "mkosi.prepare")
    args_find_path(args, "finalize_script", "mkosi.finalize")
    args_find_path(args, "workspace_dir", "mkosi.workspace/")
    args_find_path(args, "mksquashfs_tool", "mkosi.mksquashfs-tool", as_list=True)
    args_find_path(args, "repos_dir", "mkosi.reposdir/")

    find_extra(args)
    find_skeleton(args)
    find_secure_boot(args)
    find_image_version(args)

    args.extra_search_paths = expand_paths(args.extra_search_paths)

    if args.cmdline and args.verb not in MKOSI_COMMANDS_CMDLINE:
        die(f"Parameters after verb are only accepted for {list_to_string(verb.name for verb in MKOSI_COMMANDS_CMDLINE)}.")

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
        elif args.distribution == Distribution.openmandriva:
            args.release = "cooker"
        elif args.distribution == Distribution.gentoo:
            args.release = "17.1"
        else:
            args.release = "rolling"

    if args.bootable:
        if args.verb == Verb.qemu and args.output_format in (
            OutputFormat.directory,
            OutputFormat.subvolume,
            OutputFormat.tar,
            OutputFormat.cpio,
            OutputFormat.plain_squashfs,
        ):
            die("Directory, subvolume, tar, cpio, and plain squashfs images cannot be booted.", MkosiNotSupportedException)

    if is_centos_variant(args.distribution):
        epel_release = parse_epel_release(args.release)
        if epel_release <= 9 and args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, CentOS {epel_release} does not support btrfs", MkosiNotSupportedException)

    if args.distribution in (Distribution.rocky, Distribution.rocky_epel):
        epel_release = int(args.release.split(".")[0])
        if epel_release == 8 and args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, Rocky {epel_release} does not support btrfs", MkosiNotSupportedException)

    if args.distribution in (Distribution.alma, Distribution.alma_epel):
        epel_release = int(args.release.split(".")[0])
        if epel_release == 8 and args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, Alma {epel_release} does not support btrfs", MkosiNotSupportedException)

    if shutil.which("bsdtar") and args.distribution == Distribution.openmandriva and args.tar_strip_selinux_context:
        die("Sorry, bsdtar on OpenMandriva is incompatible with --tar-strip-selinux-context", MkosiNotSupportedException)

    find_cache(args)
    find_output(args)
    find_builddir(args)

    if args.mirror is None:
        if args.distribution in (Distribution.fedora, Distribution.centos):
            args.mirror = None
        elif args.distribution == Distribution.debian:
            args.mirror = "http://deb.debian.org/debian"
        elif args.distribution == Distribution.ubuntu:
            if args.architecture == "x86" or args.architecture == "x86_64":
                args.mirror = "http://archive.ubuntu.com/ubuntu"
            else:
                args.mirror = "http://ports.ubuntu.com"
        elif args.distribution == Distribution.arch:
            if args.architecture == "aarch64":
                args.mirror = "http://mirror.archlinuxarm.org"
            else:
                args.mirror = "https://geo.mirror.pkgbuild.com"
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
        compress = should_compress_output(args)

        if args.output_format.is_disk():
            output = prefix + (".qcow2" if args.qcow2 else ".raw") + (f".{compress}" if compress else "")
        elif args.output_format == OutputFormat.tar:
            output = f"{prefix}.tar" + (f".{compress}" if compress else "")
        elif args.output_format == OutputFormat.cpio:
            output = f"{prefix}.cpio" + (f".{compress}" if compress else "")
        elif args.output_format.is_squashfs():
            output = f"{prefix}.raw"
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

    args.output = args.output.absolute()

    if not args.output_format.is_disk():
        args.split_artifacts = False

    if args.output_format.is_squashfs():
        args.read_only = True
        if args.root_size is None:
            # Size will be automatic
            args.minimize = True
        if args.compress is None:
            args.compress = True

    if args.verity:
        args.read_only = True
        args.output_root_hash_file = build_auxiliary_output_path(args, roothash_suffix(args))

        if args.verity == "signed":
            args.output_root_hash_p7s_file = build_auxiliary_output_path(args, roothash_p7s_suffix(args))

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
        args.output_split_root = build_auxiliary_output_path(args, f"{root_or_usr(args)}.raw", True)
        if args.verity:
            args.output_split_verity = build_auxiliary_output_path(args, f"{root_or_usr(args)}.verity", True)
            if args.verity == "signed":
                args.output_split_verity_sig = build_auxiliary_output_path(args, f"{roothash_suffix(args)}.p7s", True)
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
    args.bios_size = parse_bytes(args.bios_size)

    if args.root_size == 0:
        args.root_size = 3 * 1024 * 1024 * 1024

    if args.bootable and args.esp_size == 0:
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

    # Resolve passwords late so we can accurately determine whether a build is needed
    find_password(args)
    find_passphrase(args)

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
        name = root_partition_description(config=None,
                                          image_id=args.image_id,
                                          image_version=args.image_version,
                                          usr_only=args.usr_only)
        args.kernel_command_line.append(f"mount.usr=/dev/disk/by-partlabel/{xescape(name)}")

    if not args.read_only:
        args.kernel_command_line.append("rw")

    if args.verity and not args.with_unified_kernel_images:
        die("Sorry, --verity can only be used with unified kernel images", MkosiNotSupportedException)

    if args.source_file_transfer is None:
        if os.path.exists(".git") or args.build_sources.joinpath(".git").exists():
            args.source_file_transfer = SourceFileTransfer.copy_git_others
        else:
            args.source_file_transfer = SourceFileTransfer.copy_all

    if args.source_file_transfer_final == SourceFileTransfer.mount and args.verb == Verb.qemu:
        die("Sorry, --source-file-transfer-final=mount is not supported when booting in QEMU")

    if args.skip_final_phase and args.verb != Verb.build:
        die("--skip-final-phase can only be used when building an image using 'mkosi build'", MkosiNotSupportedException)

    if args.ssh_timeout < 0:
        die("--ssh-timeout must be >= 0")

    if args.ssh_port <= 0:
        die("--ssh-port must be > 0")

    if args.repos_dir and not (is_rpm_distribution(args.distribution) or args.distribution == Distribution.arch):
        die("--repository-directory is only supported on RPM based distributions and Arch")

    if args.netdev and is_centos_variant(args.distribution) and not is_epel_variant(args.distribution):
        die("--netdev is only supported on EPEL centOS variants")

    if args.machine_id is not None:
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

    if args.boot_protocols is not None:
        warn("The --boot-protocols is deprecated and has no effect anymore")
    delattr(args, "boot_protocols")

    return MkosiConfig(**vars(args))


def cache_image_path(config: MkosiConfig, is_final_image: bool) -> Optional[Path]:
    suffix = "cache-pre-inst" if is_final_image else "cache-pre-dev"

    # If the image ID is specified, use cache file names that are independent of the image versions, so that
    # rebuilding and bumping versions is cheap and reuses previous versions if cached.
    if config.image_id is not None and config.output_dir:
        return config.output_dir / f"{config.image_id}.{suffix}"
    elif config.image_id:
        return Path(f"{config.image_id}.{suffix}")
    # Otherwise, derive the cache file names directly from the output file names.
    else:
        return Path(f"{config.output}.{suffix}")


def check_tree_input(path: Optional[Path]) -> None:
    # Each path may be a directory or a tarball.
    # Open the file or directory to simulate an access check.
    # If that fails, an exception will be thrown.
    if not path:
        return

    os.open(path, os.R_OK)


def check_script_input(path: Optional[Path]) -> None:
    if not path:
        return

    os.open(path, os.R_OK)
    if not path.is_file():
        raise OSError(errno.ENOENT, 'Not a normal file')
    if not os.access(path, os.X_OK):
        raise OSError(errno.ENOENT, 'Not executable')
    return None


def check_inputs(config: MkosiConfig) -> None:
    try:
        check_tree_input(config.base_image)

        for tree in (config.skeleton_trees,
                     config.extra_trees):
            for item in tree:
                check_tree_input(item)

        for path in (config.build_script,
                     config.prepare_script,
                     config.postinst_script,
                     config.finalize_script):
            check_script_input(path)
    except OSError as e:
        die(f'{e.filename} {e.strerror}')


def check_outputs(config: MkosiConfig) -> None:
    if config.skip_final_phase:
        return

    for f in (
        config.output,
        config.output_checksum if config.checksum else None,
        config.output_signature if config.sign else None,
        config.output_bmap if config.bmap else None,
        config.output_nspawn_settings if config.nspawn_settings is not None else None,
        config.output_root_hash_file if config.verity else None,
        config.output_sshkey if config.ssh else None,
        config.output_split_root if config.split_artifacts else None,
        config.output_split_verity if config.split_artifacts else None,
        config.output_split_verity_sig if config.split_artifacts else None,
        config.output_split_kernel if config.split_artifacts else None,
    ):
        if f and f.exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def yes_no(b: Optional[bool]) -> str:
    return "yes" if b else "no"


def yes_no_or(b: Union[bool, str]) -> str:
    return b if isinstance(b, str) else yes_no(b)


def format_bytes_or_disabled(sz: int) -> str:
    if sz == 0:
        return "(disabled)"

    return format_bytes(sz)


def format_bytes_or_auto(sz: int) -> str:
    if sz == 0:
        return "(automatic)"

    return format_bytes(sz)


def none_to_na(s: Optional[T]) -> Union[T, str]:
    return "n/a" if s is None else s

def none_to_no(s: Optional[T]) -> Union[T, str]:
    return "no" if s is None else s

def none_to_none(s: Optional[T]) -> Union[T, str]:
    return "none" if s is None else s


def path_or_none(
        path: Optional[Path],
        checker: Optional[Callable[[Optional[Path]], None]] = None,
) -> Union[Optional[Path], str]:
    try:
        if checker:
            checker(path)
    except OSError as e:
        return f'{color_error(path)} ({e.strerror})'
    else:
        return path

def line_join_list(
        array: Sequence[PathString],
        checker: Optional[Callable[[Optional[Path]], None]] = None,
) -> str:
    if not array:
        return "none"

    items = (str(path_or_none(cast(Path, item), checker=checker)) for item in array)
    return "\n                            ".join(items)


def print_summary(config: MkosiConfig) -> None:
    print("COMMANDS:")

    print("                      verb:", config.verb)
    print("                   cmdline:", " ".join(config.cmdline))

    print("\nDISTRIBUTION:")

    print("              Distribution:", config.distribution.name)
    print("                   Release:", none_to_na(config.release))
    print("              Architecture:", config.architecture)

    if config.mirror is not None:
        print("                    Mirror:", config.mirror)

    if config.local_mirror is not None:
        print("      Local Mirror (build):", config.local_mirror)

    print("  Repo Signature/Key check:", yes_no(config.repository_key_check))

    if config.repositories is not None and len(config.repositories) > 0:
        print("              Repositories:", ",".join(config.repositories))

    print("     Use Host Repositories:", yes_no(config.use_host_repositories))

    print("\nOUTPUT:")

    if config.hostname:
        print("                  Hostname:", config.hostname)

    if config.image_id is not None:
        print("                  Image ID:", config.image_id)

    if config.image_version is not None:
        print("             Image Version:", config.image_version)

    print("             Output Format:", config.output_format.name)

    maniformats = (" ".join(str(i) for i in config.manifest_format)) or "(none)"
    print("          Manifest Formats:", maniformats)

    if config.output_format.can_minimize():
        print("                  Minimize:", yes_no(config.minimize))

    if config.output_dir:
        print("          Output Directory:", config.output_dir)

    if config.workspace_dir:
        print("       Workspace Directory:", config.workspace_dir)

    print("                    Output:", config.output)
    print("           Output Checksum:", none_to_na(config.output_checksum if config.checksum else None))
    print("          Output Signature:", none_to_na(config.output_signature if config.sign else None))
    print("               Output Bmap:", none_to_na(config.output_bmap if config.bmap else None))
    print("  Generate split artifacts:", yes_no(config.split_artifacts))
    print("      Output Split Root FS:", none_to_na(config.output_split_root if config.split_artifacts else None))
    print("       Output Split Verity:", none_to_na(config.output_split_verity if config.split_artifacts else None))
    print("  Output Split Verity Sig.:", none_to_na(config.output_split_verity_sig if config.split_artifacts else None))
    print("       Output Split Kernel:", none_to_na(config.output_split_kernel if config.split_artifacts else None))
    print("    Output nspawn Settings:", none_to_na(config.output_nspawn_settings if config.nspawn_settings is not None else None))
    print("                   SSH key:", none_to_na((config.ssh_key or config.output_sshkey or config.ssh_agent) if config.ssh else None))
    if config.ssh_port != 22:
        print("                  SSH port:", config.ssh_port)

    print("               Incremental:", yes_no(config.incremental))
    print("                 Read-only:", yes_no(config.read_only))
    print(" Internal (FS) Compression:", yes_no_or(should_compress_fs(config)))
    print("Outer (output) Compression:", yes_no_or(should_compress_output(config)))

    if config.mksquashfs_tool:
        print("           Mksquashfs tool:", " ".join(map(str, config.mksquashfs_tool)))

    if config.output_format.is_disk():
        print("                     QCow2:", yes_no(config.qcow2))

    print("                Encryption:", none_to_no(config.encrypt))
    print("                    Verity:", yes_no_or(config.verity))

    if config.output_format.is_disk():
        print("                  Bootable:", yes_no(config.bootable))

        if config.bootable:
            print("       Kernel Command Line:", " ".join(config.kernel_command_line))
            print("           UEFI SecureBoot:", yes_no(config.secure_boot))
            print("     Unified Kernel Images:", yes_no(config.with_unified_kernel_images))
            print("             GPT First LBA:", str(config.gpt_first_lba))
            print("           Hostonly Initrd:", yes_no(config.hostonly_initrd))

    if config.secure_boot or config.verity == "sign":
        print("SecureBoot/Verity Sign Key:", config.secure_boot_key)
        print("   SecureBoot/verity Cert.:", config.secure_boot_certificate)

    print("                Machine ID:", none_to_no(config.machine_id))

    print("\nCONTENT:")

    print("                  Packages:", line_join_list(config.packages))

    if config.distribution in (
        Distribution.fedora,
        Distribution.centos,
        Distribution.centos_epel,
        Distribution.mageia,
        Distribution.rocky,
        Distribution.rocky_epel,
        Distribution.alma,
        Distribution.alma_epel,
    ):
        print("        With Documentation:", yes_no(config.with_docs))

    print("             Package Cache:", none_to_none(config.cache_path))
    print("               Extra Trees:", line_join_list(config.extra_trees, check_tree_input))
    print("            Skeleton Trees:", line_join_list(config.skeleton_trees, check_tree_input))
    print("      CleanPackageMetadata:", yes_no_or(config.clean_package_metadata))

    if config.remove_files:
        print("              Remove Files:", line_join_list(config.remove_files))
    if config.remove_packages:
        print("           Remove Packages:", line_join_list(config.remove_packages))

    print("             Build Sources:", none_to_none(config.build_sources))
    print("      Source File Transfer:", none_to_none(config.source_file_transfer))
    print("Source File Transfer Final:", none_to_none(config.source_file_transfer_final))
    print("           Build Directory:", none_to_none(config.build_dir))
    print("         Include Directory:", none_to_none(config.include_dir))
    print("         Install Directory:", none_to_none(config.install_dir))
    print("            Build Packages:", line_join_list(config.build_packages))
    print("          Skip final phase:", yes_no(config.skip_final_phase))

    print("              Build Script:", path_or_none(config.build_script, check_script_input))

    env = [f"{k}={v}" for k, v in config.environment.items()]
    if config.build_script:
        print("                 Run tests:", yes_no(config.with_tests))

    print("        Postinstall Script:", path_or_none(config.postinst_script, check_script_input))
    print("            Prepare Script:", path_or_none(config.prepare_script, check_script_input))
    print("           Finalize Script:", path_or_none(config.finalize_script, check_script_input))

    print("        Script Environment:", line_join_list(env))
    print("      Scripts with network:", yes_no_or(config.with_network))
    print("           nspawn Settings:", none_to_none(config.nspawn_settings))

    print("                  Password:", ("(default)" if config.password is None else "(set)"))
    print("                 Autologin:", yes_no(config.autologin))

    if config.output_format.is_disk():
        print("\nPARTITIONS:")

        print("            Root Partition:", format_bytes_or_auto(config.root_size))
        print("            Swap Partition:", format_bytes_or_disabled(config.swap_size))
        print("             EFI Partition:", format_bytes_or_disabled(config.esp_size))
        print("        XBOOTLDR Partition:", format_bytes_or_disabled(config.xbootldr_size))
        print("           /home Partition:", format_bytes_or_disabled(config.home_size))
        print("            /srv Partition:", format_bytes_or_disabled(config.srv_size))
        print("            /var Partition:", format_bytes_or_disabled(config.var_size))
        print("        /var/tmp Partition:", format_bytes_or_disabled(config.tmp_size))
        print("            BIOS Partition:", format_bytes_or_disabled(config.bios_size))
        print("                 /usr only:", yes_no(config.usr_only))

        print("\nVALIDATION:")

        print("                  Checksum:", yes_no(config.checksum))
        print("                      Sign:", yes_no(config.sign))
        print("                   GPG Key:", ("default" if config.key is None else config.key))

    print("\nHOST CONFIGURATION:")

    print("        Extra search paths:", line_join_list(config.extra_search_paths))
    print("             QEMU Headless:", yes_no(config.qemu_headless))
    print("      QEMU Extra Arguments:", line_join_list(config.qemu_args))
    print("                    Netdev:", yes_no(config.netdev))


def reuse_cache_tree(state: MkosiState, cached: bool) -> bool:
    """If there's a cached version of this tree around, use it and
    initialize our new root directly from it. Returns a boolean indicating
    whether we are now operating on a cached version or not."""

    if cached:
        return True

    if not state.config.incremental:
        return False
    if state.for_cache:
        return False
    if state.config.output_format.is_disk_rw():
        return False

    fname = state.cache_pre_dev if state.do_run_build_script else state.cache_pre_inst
    if fname is None:
        return False

    if fname.exists():
        with complete_step(f"Copying in cached tree {fname}…"):
            copy_path(fname, state.root, copystat=False)

    return True


def make_output_dir(config: MkosiConfig) -> None:
    """Create the output directory if set and not existing yet"""
    if config.output_dir is None:
        return

    mkdirp_chown_current_user(config.output_dir, skip_chown=config.no_chown, mode=0o755)


def make_build_dir(config: MkosiConfig) -> None:
    """Create the build directory if set and not existing yet"""
    if config.build_dir is None:
        return

    mkdirp_chown_current_user(config.build_dir, skip_chown=config.no_chown, mode=0o755)


def make_cache_dir(config: MkosiConfig) -> None:
    """Create the output directory if set and not existing yet"""
    # TODO: mypy complains that having the same structure as above, makes  the
    # return on None unreachable code. I can't see right now, why it *should* be
    # unreachable, so invert the structure here to be on the safe side.
    if config.cache_path is not None:
        mkdirp_chown_current_user(config.cache_path, skip_chown=config.no_chown, mode=0o755)


def configure_ssh(state: MkosiState, cached: bool) -> Optional[TextIO]:
    if state.do_run_build_script or not state.config.ssh:
        return None

    if state.config.distribution in (Distribution.debian, Distribution.ubuntu):
        unit = "ssh.socket"

        if state.config.ssh_port != 22:
            add_dropin_config(state.root, unit, "port",
                              f"""\
                              [Socket]
                              ListenStream=
                              ListenStream={state.config.ssh_port}
                              """)

        add_dropin_config(state.root, "ssh@.service", "runtime-directory-preserve",
                          """\
                          [Service]
                          RuntimeDirectoryPreserve=yes
                          """)
    else:
        unit = "sshd"

    # We cache the enable sshd step but not the keygen step because it creates a separate file on the host
    # which introduces non-trivial issue when trying to cache it.

    if not cached:
        run(["systemctl", "--root", state.root, "enable", unit])

    if state.for_cache:
        return None

    authorized_keys = root_home(state) / ".ssh/authorized_keys"
    f: Optional[TextIO]
    if state.config.ssh_key:
        f = open(state.config.ssh_key, mode="r", encoding="utf-8")
        copy_file(f"{state.config.ssh_key}.pub", authorized_keys)
    elif state.config.ssh_agent is not None:
        env = {"SSH_AUTH_SOCK": state.config.ssh_agent}
        result = run(["ssh-add", "-L"], env=env, text=True, stdout=subprocess.PIPE)
        authorized_keys.write_text(result.stdout)
        f = None
    else:
        assert state.config.output_sshkey is not None

        f = cast(
            TextIO,
            tempfile.NamedTemporaryFile(mode="w+", prefix=".mkosi-", encoding="utf-8", dir=state.config.output_sshkey.parent),
        )

        with complete_step("Generating SSH key pair…"):
            # Write a 'y' to confirm to overwrite the file.
            run(
                ["ssh-keygen", "-f", f.name, "-N", state.config.password or "", "-C", "mkosi", "-t", "ed25519"],
                input="y\n",
                text=True,
                stdout=subprocess.DEVNULL,
            )

        authorized_keys.parent.mkdir(parents=True, exist_ok=True)
        copy_file(f"{f.name}.pub", authorized_keys)
        os.remove(f"{f.name}.pub")

    authorized_keys.chmod(0o600)

    return f


def configure_netdev(state: MkosiState, cached: bool) -> None:
    if state.do_run_build_script or cached or not state.config.netdev:
        return

    with complete_step("Setting up netdev…"):
        network_file = state.root / "etc/systemd/network/80-mkosi-netdev.network"
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

        run(["systemctl", "--root", state.root, "enable", "systemd-networkd"])


def boot_directory(state: MkosiState, kver: str) -> Path:
    prefix = "boot" if state.get_partition(PartitionIdentifier.xbootldr) or not state.get_partition(PartitionIdentifier.esp) else "efi"
    return Path(prefix) / state.machine_id / kver


def run_kernel_install(state: MkosiState, cached: bool) -> None:
    if not state.config.bootable or state.do_run_build_script:
        return

    if not state.config.cache_initrd and state.for_cache:
        return

    if state.config.cache_initrd and cached:
        return

    with complete_step("Generating initramfs images…"):
        for kver, kimg in gen_kernel_images(state):
            run_workspace_command(state, ["kernel-install", "add", kver, Path("/") / kimg])


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
    split_kernel_image: Optional[BinaryIO]
    split_initrd: Optional[BinaryIO]
    split_kernel_cmdline: Optional[TextIO]

    def raw_name(self) -> Optional[str]:
        return self.raw.name if self.raw is not None else None

    @classmethod
    def empty(cls) -> BuildOutput:
        return cls(None, None, None, None, None, None, None, None, None, None, None, None)


def build_image(
    state: MkosiState,
    *,
    manifest: Optional[Manifest] = None,
) -> BuildOutput:
    # If there's no build script set, there's no point in executing
    # the build script iteration. Let's quit early.
    if state.config.build_script is None and state.do_run_build_script:
        return BuildOutput.empty()

    make_build_dir(state.config)

    raw, cached = reuse_cache_image(state)
    if state.for_cache and cached:
        # Found existing cache image, exiting build_image
        return BuildOutput.empty()

    if cached:
        assert raw is not None
        refresh_partition_table(state, raw)
    else:
        raw = create_image(state)

    with attach_base_image(state.config.base_image, state.partition_table) as base_image, \
         attach_image_loopback(raw, state.partition_table) as loopdev, \
         set_umask(0o022):

        prepare_swap(state, loopdev, cached)
        prepare_esp(state, loopdev, cached)
        prepare_xbootldr(state, loopdev, cached)

        if loopdev is not None:
            luks_format_root(state, loopdev, cached)
            luks_format_home(state, loopdev, cached)
            luks_format_srv(state, loopdev, cached)
            luks_format_var(state, loopdev, cached)
            luks_format_tmp(state, loopdev, cached)

        with luks_setup_all(state, loopdev) as encrypted:
            prepare_root(state.config, encrypted.root, cached)
            prepare_home(state.config, encrypted.home, cached)
            prepare_srv(state.config, encrypted.srv, cached)
            prepare_var(state.config, encrypted.var, cached)
            prepare_tmp(state.config, encrypted.tmp, cached)

            for dev in encrypted:
                refresh_file_system(state.config, dev, cached)

            # Mount everything together, but let's not mount the root
            # dir if we still have to generate the root image here
            prepare_tree_root(state)

            with mount_image(state, cached, base_image, loopdev, encrypted.without_generated_root(state.config)):

                prepare_tree(state, cached)
                cached_tree = reuse_cache_tree(state, cached)
                install_skeleton_trees(state, cached_tree)
                install_distribution(state, cached_tree)
                configure_locale(state.root, cached_tree)
                configure_hostname(state, cached_tree)
                configure_root_password(state, cached_tree)
                configure_serial_terminal(state, cached_tree)
                configure_autologin(state, cached_tree)
                configure_dracut(state, cached_tree)
                configure_netdev(state, cached_tree)
                run_prepare_script(state, cached_tree)
                install_build_src(state)
                install_build_dest(state)
                install_extra_trees(state)
                run_kernel_install(state, cached_tree)
                install_boot_loader(state)
                sshkey = configure_ssh(state, cached_tree)
                run_postinst_script(state)
                # Sign systemd-boot / sd-boot EFI binaries
                secure_boot_sign(state, state.root / 'usr/lib/systemd/boot/efi', cached,
                                 mount=contextlib.nullcontext)

                cleanup = not state.for_cache and not state.do_run_build_script

                if cleanup:
                    remove_packages(state)

                if manifest:
                    with complete_step("Recording packages in manifest…"):
                        manifest.record_packages(state.root)

                if cleanup:
                    clean_package_manager_metadata(state)
                    remove_files(state)
                reset_machine_id(state)
                reset_random_seed(state.root)
                run_finalize_script(state)
                invoke_fstrim(state)
                make_read_only(state, state.root)

            generated_root = make_generated_root(state)
            generated_root_part = insert_generated_root(state, raw, loopdev, generated_root)
            split_root = (
                (generated_root or extract_partition(state, encrypted.root))
                if state.config.split_artifacts
                else None
            )

            if state.config.verity:
                root_for_verity = encrypted.root
                if root_for_verity is None and generated_root_part is not None:
                    assert loopdev is not None
                    root_for_verity = generated_root_part.blockdev(loopdev)
            else:
                root_for_verity = None

            verity, root_hash = make_verity(state, root_for_verity)

            patch_root_uuid(state, loopdev, root_hash)

            insert_verity(state, raw, loopdev, verity, root_hash)
            split_verity = verity if state.config.split_artifacts else None

            verity_sig, root_hash_p7s, fingerprint = make_verity_sig(state, root_hash)
            insert_verity_sig(state, raw, loopdev, verity_sig, root_hash, fingerprint)
            split_verity_sig = verity_sig if state.config.split_artifacts else None

            # This time we mount read-only, as we already generated
            # the verity data, and hence really shouldn't modify the
            # image anymore.
            mount = lambda: mount_image(state, cached, base_image, loopdev,
                                        encrypted.without_generated_root(state.config),
                                        root_read_only=True)

            install_unified_kernel(state, root_hash, mount)
            # Sign EFI binaries under these directories within the ESP
            for esp_dir in ['efi/EFI/BOOT', 'efi/EFI/systemd', 'efi/EFI/Linux']:
                secure_boot_sign(state, state.root / esp_dir, cached, mount, replace=True)
            split_kernel = (
                extract_unified_kernel(state, mount)
                if state.config.split_artifacts
                else None
            )
            split_kernel_image, split_initrd = extract_kernel_image_initrd(state, mount)
            split_kernel_cmdline = extract_kernel_cmdline(state, mount)

    archive = make_tar(state) or make_cpio(state)

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
        split_kernel_image,
        split_initrd,
        split_kernel_cmdline,
    )


def one_zero(b: bool) -> str:
    return "1" if b else "0"


def install_dir(state: MkosiState) -> Path:
    return state.config.install_dir or state.workspace / "dest"


def run_build_script(state: MkosiState, raw: Optional[BinaryIO]) -> None:
    if state.config.build_script is None:
        return

    idmap_opt = ":rootidmap" if nspawn_id_map_supported() else ""

    with complete_step("Running build script…"):
        os.makedirs(install_dir(state), mode=0o755, exist_ok=True)

        target = f"--directory={state.root}" if raw is None else f"--image={raw.name}"

        with_network = 1 if state.config.with_network is True else 0

        cmdline = [
            "systemd-nspawn",
            "--quiet",
            target,
            f"--machine=mkosi-{uuid.uuid4().hex}",
            "--as-pid2",
            "--link-journal=no",
            "--register=no",
            f"--bind={install_dir(state)}:/root/dest{idmap_opt}",
            f"--bind={state.var_tmp()}:/var/tmp{idmap_opt}",
            f"--setenv=WITH_DOCS={one_zero(state.config.with_docs)}",
            f"--setenv=WITH_TESTS={one_zero(state.config.with_tests)}",
            f"--setenv=WITH_NETWORK={with_network}",
            "--setenv=DESTDIR=/root/dest",
            *nspawn_rlimit_params(),
        ]

        # TODO: Use --autopipe once systemd v247 is widely available.
        console_arg = f"--console={'interactive' if sys.stdout.isatty() else 'pipe'}"
        if nspawn_knows_arg(console_arg):
            cmdline += [console_arg]

        if state.config.config_path is not None:
            cmdline += [
                f"--setenv=MKOSI_CONFIG={state.config.config_path}",
                f"--setenv=MKOSI_DEFAULT={state.config.config_path}"
            ]

        cmdline += nspawn_params_for_build_sources(state.config, state.config.source_file_transfer)

        if state.config.build_dir is not None:
            cmdline += ["--setenv=BUILDDIR=/root/build",
                        f"--bind={state.config.build_dir}:/root/build{idmap_opt}"]

        if state.config.include_dir is not None:
            cmdline += [f"--bind={state.config.include_dir}:/usr/include{idmap_opt}"]

        if state.config.with_network is True:
            # If we're using the host network namespace, use the same resolver
            cmdline += ["--bind-ro=/etc/resolv.conf"]
        else:
            cmdline += ["--private-network"]

        if state.config.usr_only:
            cmdline += [f"--bind={root_home(state)}:/root{idmap_opt}"]

        if state.config.nspawn_keep_unit:
            cmdline += ["--keep-unit"]

        cmdline += [f"--setenv={env}={value}" for env, value in state.environment.items()]

        cmdline += [f"/root/{state.config.build_script.name}"]

        # When we're building the image because it's required for another verb, any passed arguments are most
        # likely intended for the target verb, and not for "build", so don't add them in that case.
        if state.config.verb == Verb.build:
            cmdline += state.config.cmdline

        # build-script output goes to stdout so we can run language servers from within mkosi build-scripts.
        # See https://github.com/systemd/mkosi/pull/566 for more information.
        result = run(cmdline, stdout=sys.stdout, check=False)
        if result.returncode != 0:
            if "build-script" in ARG_DEBUG:
                run(cmdline[:-1], check=False)
            die(f"Build script returned non-zero exit code {result.returncode}.")


def need_cache_images(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    if state.config.force > 1:
        return True

    assert state.cache_pre_dev
    assert state.cache_pre_inst

    return not state.cache_pre_dev.exists() or not state.cache_pre_inst.exists()


def remove_artifacts(
    state: MkosiState,
    raw: Optional[BinaryIO],
    archive: Optional[BinaryIO],
    for_cache: bool = False,
) -> None:
    if for_cache:
        what = "cache build"
    elif state.do_run_build_script:
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
        unlink_try_hard(state.root)
        unlink_try_hard(state.var_tmp())
        if state.config.usr_only:
            unlink_try_hard(root_home(state))


def build_stuff(config: MkosiConfig) -> Manifest:
    make_output_dir(config)
    make_cache_dir(config)
    workspace = setup_workspace(config)
    cache = setup_package_cache(config, Path(workspace.name))

    image = BuildOutput.empty()
    manifest = Manifest(config)

    # Make sure tmpfiles' aging doesn't interfere with our workspace
    # while we are working on it.
    with open_close(workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC) as dir_fd, \
         btrfs_forget_stale_devices(config):

        fcntl.flock(dir_fd, fcntl.LOCK_EX)

        state = MkosiState(
            config=config,
            cache_pre_dev=cache_image_path(config, is_final_image=False) if config.incremental else None,
            cache_pre_inst=cache_image_path(config, is_final_image=True) if config.incremental else None,
            workspace=Path(workspace.name),
            cache=cache,
            do_run_build_script=False,
            machine_id=config.machine_id or uuid.uuid4().hex,
            for_cache=False,
        )

        # If caching is requested, then make sure we have cache images around we can make use of
        if need_cache_images(state):

            # There is no point generating a pre-dev cache image if no build script is provided
            if config.build_script:
                with complete_step("Running first (development) stage to generate cached copy…"):
                    # Generate the cache version of the build image, and store it as "cache-pre-dev"
                    state = dataclasses.replace(state, do_run_build_script=True, for_cache=True)
                    image = build_image(state)
                    save_cache(state, image.raw_name(), state.cache_pre_dev)
                    remove_artifacts(state, image.raw, image.archive)

            with complete_step("Running second (final) stage to generate cached copy…"):
                # Generate the cache version of the build image, and store it as "cache-pre-inst"
                state = dataclasses.replace(state, do_run_build_script=False, for_cache=True)
                image = build_image(state)
                save_cache(state, image.raw_name(), state.cache_pre_inst)
                remove_artifacts(state, image.raw, image.archive)

        if config.build_script:
            with complete_step("Running first (development) stage…"):
                # Run the image builder for the first (development) stage in preparation for the build script
                state = dataclasses.replace(state, do_run_build_script=True, for_cache=False)
                image = build_image(state)

                run_build_script(state, image.raw)
                remove_artifacts(state, image.raw, image.archive)

        # Run the image builder for the second (final) stage
        if not config.skip_final_phase:
            with complete_step("Running second (final) stage…"):
                state = dataclasses.replace(state, do_run_build_script=False, for_cache=False)
                image = build_image(state, manifest=manifest)
        else:
            MkosiPrinter.print_step("Skipping (second) final image build phase.")

        raw = qcow2_output(config, image.raw)
        bmap = calculate_bmap(config, raw)
        raw = compress_output(config, raw)
        split_root = compress_output(config, image.split_root, f"{root_or_usr(config)}.raw")
        split_verity = compress_output(config, image.split_verity, f"{root_or_usr(config)}.verity")
        split_verity_sig = compress_output(config, image.split_verity_sig, roothash_p7s_suffix(config))
        split_kernel = compress_output(config, image.split_kernel, ".efi")
        root_hash_file = write_root_hash_file(config, image.root_hash)
        root_hash_p7s_file = write_root_hash_p7s_file(config, image.root_hash_p7s)
        settings = copy_nspawn_settings(config)
        checksum = calculate_sha256sum(
            config, raw,
            image.archive,
            root_hash_file,
            root_hash_p7s_file,
            split_root,
            split_verity,
            split_verity_sig,
            split_kernel,
            settings,
        )
        signature = calculate_signature(state, checksum)

        link_output(state, raw or image.archive)
        link_output_root_hash_file(config, root_hash_file)
        link_output_root_hash_p7s_file(config, root_hash_p7s_file)
        link_output_checksum(config, checksum)
        link_output_signature(config, signature)
        link_output_bmap(config, bmap)
        link_output_nspawn_settings(config, settings)
        if config.output_sshkey is not None:
            link_output_sshkey(config, image.sshkey)
        link_output_split_root(config, split_root)
        link_output_split_verity(config, split_verity)
        link_output_split_verity_sig(config, split_verity_sig)
        link_output_split_kernel(config, split_kernel)
        link_output_split_kernel_image(config, image.split_kernel_image)
        link_output_split_initrd(config, image.split_initrd)
        link_output_split_kernel_cmdline(config, image.split_kernel_cmdline)

        if image.root_hash is not None:
            MkosiPrinter.print_step(f"Root hash is {image.root_hash}.")

        return manifest


def check_root() -> None:
    if os.getuid() != 0:
        die("Must be invoked as root.")


def check_native(config: MkosiConfig) -> None:
    if not config.architecture_is_native() and config.build_script and nspawn_version() < 250:
        die("Cannot (currently) override the architecture and run build commands")


@contextlib.contextmanager
def suppress_stacktrace() -> Iterator[None]:
    try:
        yield
    except subprocess.CalledProcessError as e:
        # MkosiException is silenced in main() so it doesn't print a stacktrace.
        raise MkosiException() from e


def machine_name(config: MkosiConfig) -> str:
    return config.hostname or config.image_id or config.output.with_suffix("").name.partition("_")[0]


def interface_name(config: MkosiConfig) -> str:
    # Shorten to 12 characters so we can prefix with ve- or vt- for the netdev ifname which is limited
    # to 15 characters.
    return machine_name(config)[:12]


def has_networkd_vm_vt() -> bool:
    return any(
        Path(path, "80-vm-vt.network").exists()
        for path in ("/usr/lib/systemd/network", "/lib/systemd/network", "/etc/systemd/network")
    )


def ensure_networkd(config: MkosiConfig) -> bool:
    networkd_is_running = run(["systemctl", "is-active", "--quiet", "systemd-networkd"], check=False).returncode == 0
    if not networkd_is_running:
        if config.verb != Verb.ssh:
            # Some programs will use 'mkosi ssh' with pexpect, so don't print warnings that will break
            # them.
            warn("--netdev requires systemd-networkd to be running to initialize the host interface "
                 "of the virtual link ('systemctl enable --now systemd-networkd')")
        return False

    if config.verb == Verb.qemu and not has_networkd_vm_vt():
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


def run_shell_setup(config: MkosiConfig, pipe: bool = False, commands: Optional[Sequence[str]] = None) -> List[str]:
    if config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        target = f"--directory={config.output}"
    else:
        target = f"--image={config.output}"

    cmdline = ["systemd-nspawn", "--quiet", target]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings is not None:
        cmdline += ["--settings=trusted"]

    if config.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += nspawn_rlimit_params()

        # Redirecting output correctly when not running directly from the terminal.
        console_arg = f"--console={'interactive' if not pipe else 'pipe'}"
        if nspawn_knows_arg(console_arg):
            cmdline += [console_arg]

    if config.netdev:
        if ensure_networkd(config):
            cmdline += ["--network-veth"]

    if config.ephemeral:
        cmdline += ["--ephemeral"]

    cmdline += ["--machine", machine_name(config)]

    if config.nspawn_keep_unit:
        cmdline += ["--keep-unit"]

    if config.source_file_transfer_final == SourceFileTransfer.mount:
        cmdline += [f"--bind={config.build_sources}:/root/src", "--chdir=/root/src"]

    if config.verb == Verb.boot:
        # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
        cmdline += commands or config.cmdline
        # kernel cmdline config of the form systemd.xxx= get interpreted by systemd when running in nspawn as
        # well.
        cmdline += config.kernel_command_line
    elif commands or config.cmdline:
        cmdline += ["--"]
        cmdline += commands or config.cmdline

    return cmdline


def run_shell(config: MkosiConfig) -> None:
    run(run_shell_setup(config, pipe=not sys.stdout.isatty()), stdout=sys.stdout, stderr=sys.stderr)


def find_qemu_binary(config: MkosiConfig) -> str:
    binaries = ["qemu", "qemu-kvm", f"qemu-system-{config.architecture}"]
    for binary in binaries:
        if shutil.which(binary) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_qemu_firmware(config: MkosiConfig) -> Tuple[Path, bool]:
    FIRMWARE_LOCATIONS = {
        "x86_64": ["/usr/share/ovmf/x64/OVMF_CODE.secboot.fd"],
        "i386": [
            "/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd",
            "/usr/share/OVMF/OVMF32_CODE_4M.secboot.fd"
        ],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = {
        "x86_64": [
            "/usr/share/ovmf/ovmf_code_x64.bin",
            "/usr/share/ovmf/x64/OVMF_CODE.fd",
            "/usr/share/qemu/ovmf-x86_64.bin",
        ],
        "i386": ["/usr/share/ovmf/ovmf_code_ia32.bin", "/usr/share/edk2/ovmf-ia32/OVMF_CODE.fd"],
        "aarch64": ["/usr/share/AAVMF/AAVMF_CODE.fd"],
        "armhfp": ["/usr/share/AAVMF/AAVMF32_CODE.fd"],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            warn("Couldn't find OVMF firmware blob with secure boot support, "
                 "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    # If we can't find an architecture specific path, fall back to some generic paths that might also work.

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.secboot.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.secboot.fd",
        "/usr/share/ovmf/OVMF.secboot.fd",
        "/usr/share/OVMF/OVMF_CODE.secboot.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            warn("Couldn't find OVMF firmware blob with secure boot support, "
                 "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    die("Couldn't find OVMF UEFI firmware blob.")


def find_ovmf_vars(config: MkosiConfig) -> Path:
    OVMF_VARS_LOCATIONS = []

    if config.architecture == "x86_64":
        OVMF_VARS_LOCATIONS += ["/usr/share/ovmf/x64/OVMF_VARS.fd"]
    elif config.architecture == "i386":
        OVMF_VARS_LOCATIONS += [
            "/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd",
            "/usr/share/OVMF/OVMF32_VARS_4M.fd",
        ]
    elif config.architecture == "armhfp":
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF32_VARS.fd"]
    elif config.architecture == "aarch64":
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF_VARS.fd"]

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
def start_swtpm() -> Iterator[Optional[Path]]:

    if not shutil.which("swtpm"):
        MkosiPrinter.info("Couldn't find swtpm binary, not invoking qemu with TPM2 device.")
        yield None
        return

    with tempfile.TemporaryDirectory() as swtpm_state:
        swtpm_sock = Path(swtpm_state) / Path("sock")

        cmd = ["swtpm",
               "socket",
               "--tpm2",
               "--tpmstate", f"dir={swtpm_state}",
               "--ctrl", f"type=unixio,path={swtpm_sock}",
         ]

        swtpm_proc = spawn(cmd)

        try:
            yield swtpm_sock
        finally:
            swtpm_proc.wait()


@contextlib.contextmanager
def run_qemu_setup(config: MkosiConfig) -> Iterator[List[str]]:
    accel = "kvm" if config.qemu_kvm else "tcg"

    firmware, fw_supports_sb = find_qemu_firmware(config)
    smm = "on" if fw_supports_sb and config.qemu_boot == "uefi" else "off"

    if config.architecture == "aarch64":
        machine = f"type=virt,accel={accel}"
    else:
        machine = f"type=q35,accel={accel},smm={smm}"

    cmdline = [
        find_qemu_binary(config),
        "-machine",
        machine,
        "-smp",
        config.qemu_smp,
        "-m",
        config.qemu_mem,
        "-object",
        "rng-random,filename=/dev/urandom,id=rng0",
        "-device",
        "virtio-rng-pci,rng=rng0,id=rng-device0",
    ]

    cmdline += ["-cpu", "max"]

    if config.qemu_headless:
        # -nodefaults removes the default CDROM device which avoids an error message during boot
        # -serial mon:stdio adds back the serial device removed by -nodefaults.
        cmdline += ["-nographic", "-nodefaults", "-serial", "mon:stdio"]
    else:
        cmdline += ["-vga", "virtio"]

    if config.netdev:
        if not ensure_networkd(config) or os.getuid() != 0:
            # Fall back to usermode networking if the host doesn't have networkd (eg: Debian).
            # Also fall back if running as an unprivileged user, which likely can't set up the tap interface.
            fwd = f",hostfwd=tcp::{config.ssh_port}-:{config.ssh_port}" if config.ssh_port != 22 else ""
            cmdline += ["-nic", f"user,model=virtio-net-pci{fwd}"]
        else:
            # Use vt- prefix so we can take advantage of systemd-networkd's builtin network file for VMs.
            ifname = f"vt-{interface_name(config)}"
            # vt-<image-name> is the ifname on the host and is automatically picked up by systemd-networkd which
            # starts a DHCP server on that interface. This gives IP connectivity to the VM. By default, QEMU
            # itself tries to bring up the vt network interface which conflicts with systemd-networkd which is
            # trying to do the same. By specifiying script=no and downscript=no, We tell QEMU to not touch vt
            # after it is created.
            cmdline += ["-nic", f"tap,script=no,downscript=no,ifname={ifname},model=virtio-net-pci"]

    if config.qemu_boot == "uefi":
        cmdline += ["-drive", f"if=pflash,format=raw,readonly=on,file={firmware}"]

    if config.qemu_boot == "linux":
        cmdline += [
            "-kernel", str(build_auxiliary_output_path(config, ".vmlinuz")),
            "-initrd", str(build_auxiliary_output_path(config, ".initrd")),
            "-append", build_auxiliary_output_path(config, ".cmdline").read_text().strip(),
        ]

    with contextlib.ExitStack() as stack:
        if config.qemu_boot == "uefi" and fw_supports_sb:
            ovmf_vars = stack.enter_context(copy_file_temporary(src=find_ovmf_vars(config), dir=tmp_dir()))
            cmdline += [
                "-global",
                "ICH9-LPC.disable_s3=1",
                "-global",
                "driver=cfi.pflash01,property=secure,value=on",
                "-drive",
                f"file={ovmf_vars.name},if=pflash,format=raw",
            ]

        if config.ephemeral:
            f = stack.enter_context(copy_image_temporary(src=config.output, dir=config.output.parent))
            fname = Path(f.name)
        else:
            fname = config.output

        # Debian images fail to boot with virtio-scsi, see: https://github.com/systemd/mkosi/issues/725
        if config.distribution == Distribution.debian:
            cmdline += [
                "-drive",
                f"if=virtio,id=hd,file={fname},format={'qcow2' if config.qcow2 else 'raw'}",
            ]
        else:
            cmdline += [
                "-drive",
                f"if=none,id=hd,file={fname},format={'qcow2' if config.qcow2 else 'raw'}",
                "-device",
                "virtio-scsi-pci,id=scsi",
                "-device",
                "scsi-hd,drive=hd,bootindex=1",
            ]

        swtpm_socket = stack.enter_context(start_swtpm())
        if swtpm_socket is not None:
            cmdline += [
                "-chardev", f"socket,id=chrtpm,path={swtpm_socket}",
                "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            ]

            if config.architecture == "x86_64":
                cmdline += ["-device", "tpm-tis,tpmdev=tpm0"]
            elif config.architecture == "aarch64":
                cmdline += ["-device", "tpm-tis-device,tpmdev=tpm0"]

        cmdline += config.qemu_args
        cmdline += config.cmdline

        print_running_cmd(cmdline)
        yield cmdline


def run_qemu(config: MkosiConfig) -> None:
    with run_qemu_setup(config) as cmdline:
        run(cmdline, stdout=sys.stdout, stderr=sys.stderr)


def interface_exists(dev: str) -> bool:
    rc = run(["ip", "link", "show", dev],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode
    return rc == 0


def find_address(config: MkosiConfig) -> Tuple[str, str]:
    if not ensure_networkd(config) and config.ssh_port != 22:
        return "", "127.0.0.1"

    name = interface_name(config)
    timeout = float(config.ssh_timeout)

    while timeout >= 0:
        stime = time.time()
        try:
            if interface_exists(f"ve-{name}"):
                dev = f"ve-{name}"
            elif interface_exists(f"vt-{name}"):
                dev = f"vt-{name}"
            else:
                die(f"Container/VM interface ve-{name}/vt-{name} not found")

            link = json.loads(run(["ip", "-j", "link", "show", "dev", dev],
                                  stdout=subprocess.PIPE, text=True).stdout)[0]
            if link["operstate"] == "DOWN":
                raise MkosiException(
                    f"{dev} is not enabled. Make sure systemd-networkd is running so it can manage the interface."
                )

            # Trigger IPv6 neighbor discovery of which we can access the results via 'ip neighbor'. This allows us to
            # find out the link-local IPv6 address of the container/VM via which we can connect to it.
            run(["ping", "-c", "1", "-w", "15", f"ff02::1%{dev}"], stdout=subprocess.DEVNULL)

            for _ in range(50):
                neighbors = json.loads(
                    run(["ip", "-j", "neighbor", "show", "dev", dev], stdout=subprocess.PIPE, text=True).stdout
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


def run_systemd_cmdline(config: MkosiConfig, commands: Sequence[str]) -> List[str]:
    return ["systemd-run", "--quiet", "--wait", "--pipe", "-M", machine_name(config), "/usr/bin/env", *commands]


def run_ssh_setup(config: MkosiConfig, commands: Optional[Sequence[str]] = None) -> List[str]:
    cmd = [
            "ssh",
            # Silence known hosts file errors/warnings.
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "LogLevel=ERROR",
        ]

    if config.ssh_agent is None:
        ssh_key = config.ssh_key or config.output_sshkey
        assert ssh_key is not None

        if not ssh_key.exists():
            die(
                f"SSH key not found at {ssh_key}. Are you running from the project's root directory "
                "and did you build with the --ssh option?"
            )

        cmd += ["-i", cast(str, ssh_key)]
    else:
        cmd += ["-o", f"IdentityAgent={config.ssh_agent}"]

    if config.ssh_port != 22:
        cmd += ["-p", f"{config.ssh_port}"]

    dev, address = find_address(config)
    cmd += [f"root@{address}{dev}"]
    cmd += commands or config.cmdline

    return cmd


def run_ssh(config: MkosiConfig) -> CompletedProcess:
    return run(run_ssh_setup(config), stdout=sys.stdout, stderr=sys.stderr)


def run_serve(config: MkosiConfig) -> None:
    """Serve the output directory via a tiny embedded HTTP server"""

    port = 8081

    if config.output_dir is not None:
        os.chdir(config.output_dir)

    with http.server.HTTPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Serving HTTP on port {port}: http://localhost:{port}/")
        httpd.serve_forever()


def generate_secure_boot_key(config: MkosiConfig) -> None:
    """Generate secure boot keys using openssl"""

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(config.secure_boot_valid_days))
    cn = expand_specifier(config.secure_boot_common_name)

    for f in (config.secure_boot_key, config.secure_boot_certificate):
        if f.exists() and not config.force:
            die(
                dedent(
                    f"""\
                    {f} already exists.
                    If you are sure you want to generate new secure boot keys
                    remove {config.secure_boot_key} and {config.secure_boot_certificate} first.
                    """
                )
            )

    MkosiPrinter.print_step(f"Generating secure boot keys rsa:{keylength} for CN {cn!r}.")
    MkosiPrinter.info(
        dedent(
            f"""
            The keys will expire in {config.secure_boot_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    cmd: List[PathString] = [
        "openssl",
        "req",
        "-new",
        "-x509",
        "-newkey",
        f"rsa:{keylength}",
        "-keyout",
        config.secure_boot_key,
        "-out",
        config.secure_boot_certificate,
        "-days",
        str(config.secure_boot_valid_days),
        "-subj",
        f"/CN={cn}/",
        "-nodes",
    ]
    run(cmd)


def bump_image_version(config: MkosiConfig) -> None:
    """Write current image version plus one to mkosi.version"""

    if config.image_version is None or config.image_version == "":
        print("No version configured so far, starting with version 1.")
        new_version = "1"
    else:
        v = config.image_version.split(".")

        try:
            m = int(v[-1])
        except ValueError:
            new_version = config.image_version + ".2"
            print(
                f"Last component of current version is not a decimal integer, appending '.2', bumping '{config.image_version}' → '{new_version}'."
            )
        else:
            new_version = ".".join(v[:-1] + [str(m + 1)])
            print(f"Increasing last component of version by one, bumping '{config.image_version}' → '{new_version}'.")

    Path("mkosi.version").write_text(new_version + "\n")


def expand_paths(paths: Sequence[str]) -> List[Path]:
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
            expanded += [Path(string.Template(path).substitute(environ))]
        except KeyError:
            # Skip path if it uses a variable not defined.
            pass
    return expanded


@contextlib.contextmanager
def prepend_to_environ_path(paths: Sequence[Path]) -> Iterator[None]:
    if not paths:
        yield
        return

    with tempfile.TemporaryDirectory(prefix="mkosi.path", dir=tmp_dir()) as d:

        for path in paths:
            if not path.is_dir():
                Path(d).joinpath(path.name).symlink_to(path.absolute())

        paths = [Path(d), *paths]

        news = [os.fspath(path) for path in paths if path.is_dir()]
        olds = os.getenv("PATH", "").split(":")
        os.environ["PATH"] = ":".join(news + olds)

        yield


def expand_specifier(s: str) -> str:
    user = os.getenv("SUDO_USER") or os.getenv("USER")
    assert user is not None
    return s.replace("%u", user)


def needs_build(config: Union[argparse.Namespace, MkosiConfig]) -> bool:
    return config.verb == Verb.build or (config.verb in MKOSI_COMMANDS_NEED_BUILD and (not config.output.exists() or config.force > 0))


def run_verb(raw: argparse.Namespace) -> None:
    config: MkosiConfig = load_args(raw)

    with prepend_to_environ_path(config.extra_search_paths):
        if config.verb == Verb.genkey:
            return generate_secure_boot_key(config)

        if config.verb == Verb.bump:
            bump_image_version(config)

        if config.verb in MKOSI_COMMANDS_SUDO:
            check_root()

        if config.verb == Verb.build:
            check_inputs(config)

            if not config.force:
                check_outputs(config)

        if needs_build(config) or config.verb == Verb.clean:
            check_root()
            unlink_output(config)

        if config.verb == Verb.summary:
            print_summary(config)

        if needs_build(config):
            check_native(config)
            init_namespace()
            manifest = build_stuff(config)

            if config.auto_bump:
                bump_image_version(config)

            save_manifest(config, manifest)

            print_output_size(config)

        with suppress_stacktrace():
            if config.verb in (Verb.shell, Verb.boot):
                run_shell(config)

            if config.verb == Verb.qemu:
                run_qemu(config)

            if config.verb == Verb.ssh:
                run_ssh(config)

        if config.verb == Verb.serve:
            run_serve(config)
