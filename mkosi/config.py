# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import base64
import copy
import dataclasses
import enum
import fnmatch
import functools
import getpass
import graphlib
import io
import itertools
import json
import logging
import math
import operator
import os.path
import platform
import re
import shlex
import string
import subprocess
import sys
import tempfile
import textwrap
import typing
import uuid
from collections.abc import Collection, Iterable, Iterator, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Callable, ClassVar, Generic, Optional, Protocol, TypeVar, Union, cast

from mkosi.distribution import Distribution, detect_distribution
from mkosi.log import ARG_DEBUG, ARG_DEBUG_SANDBOX, ARG_DEBUG_SHELL, complete_step, die
from mkosi.pager import page
from mkosi.run import SandboxProtocol, find_binary, nosandbox, run, sandbox_cmd, workdir
from mkosi.sandbox import Style, __version__
from mkosi.user import INVOKING_USER
from mkosi.util import (
    PathString,
    StrEnum,
    SupportsRead,
    chdir,
    flatten,
    is_power_of_2,
    make_executable,
    startswith,
)
from mkosi.versioncomp import GenericVersion


# taken from
# https://github.com/python/typeshed/blob/c67f9da3732f4374bc208f896a18c60435863e1b/stdlib/_typeshed/__init__.pyi#L352
class DataclassInstance(Protocol):
    __dataclass_fields__: ClassVar[dict[str, dataclasses.Field[Any]]]


T = TypeVar("T")
D = TypeVar("D", bound=DataclassInstance)
SE = TypeVar("SE", bound=StrEnum)

ConfigParseCallback = Callable[[Optional[str], Optional[T]], Optional[T]]
ConfigMatchCallback = Callable[[str, T], bool]
ConfigDefaultCallback = Callable[[dict[str, Any]], T]

BUILTIN_CONFIGS = ("mkosi-tools", "mkosi-initrd", "mkosi-vm", "mkosi-addon", "mkosi-obs")


class Verb(StrEnum):
    build = enum.auto()
    clean = enum.auto()
    summary = enum.auto()
    cat_config = enum.auto()
    shell = enum.auto()
    boot = enum.auto()
    vm = enum.auto()
    qemu = enum.auto()
    ssh = enum.auto()
    serve = enum.auto()
    bump = enum.auto()
    help = enum.auto()
    genkey = enum.auto()
    documentation = enum.auto()
    journalctl = enum.auto()
    coredumpctl = enum.auto()
    burn = enum.auto()
    dependencies = enum.auto()
    completion = enum.auto()
    sysupdate = enum.auto()
    box = enum.auto()
    sandbox = enum.auto()
    init = enum.auto()
    latest_snapshot = enum.auto()

    def supports_cmdline(self) -> bool:
        return self in (
            Verb.build,
            Verb.shell,
            Verb.boot,
            Verb.vm,
            Verb.qemu,
            Verb.ssh,
            Verb.journalctl,
            Verb.coredumpctl,
            Verb.burn,
            Verb.completion,
            Verb.documentation,
            Verb.sysupdate,
            Verb.box,
            Verb.sandbox,
            Verb.dependencies,
        )

    def needs_tools(self) -> bool:
        return self in (
            Verb.box,
            Verb.sandbox,
            Verb.journalctl,
            Verb.coredumpctl,
            Verb.ssh,
            Verb.latest_snapshot,
        )

    def needs_build(self) -> bool:
        return self in (
            Verb.build,
            Verb.shell,
            Verb.boot,
            Verb.vm,
            Verb.qemu,
            Verb.serve,
            Verb.burn,
            Verb.sysupdate,
        )

    def needs_config(self) -> bool:
        return self not in (
            Verb.help,
            Verb.genkey,
            Verb.documentation,
            Verb.dependencies,
            Verb.completion,
            Verb.init,
        )


class ConfigFeature(StrEnum):
    auto = enum.auto()
    enabled = enum.auto()
    disabled = enum.auto()

    def to_tristate(self) -> str:
        if self == ConfigFeature.enabled:
            return "yes"
        if self == ConfigFeature.disabled:
            return "no"
        return ""


@dataclasses.dataclass(frozen=True)
class ConfigTree:
    source: Path
    target: Optional[Path]

    def with_prefix(self, prefix: PathString = "/") -> tuple[Path, Path]:
        return (
            self.source,
            Path(prefix) / os.fspath(self.target).lstrip("/") if self.target else Path(prefix),
        )

    def __str__(self) -> str:
        return f"{self.source}:{self.target}" if self.target else f"{self.source}"


class DriveFlag(StrEnum):
    persist = enum.auto()


@dataclasses.dataclass(frozen=True)
class Drive:
    id: str
    size: int
    directory: Optional[Path]
    options: Optional[str]
    file_id: str
    flags: list[DriveFlag]


# We use negative numbers for specifying special constants
# for VSock CIDs since they're not valid CIDs anyway.
class VsockCID(enum.IntEnum):
    auto = -1
    hash = -2

    @classmethod
    def format(cls, cid: int) -> str:
        if cid == VsockCID.auto:
            return "auto"

        if cid == VsockCID.hash:
            return "hash"

        return str(cid)


class SecureBootSignTool(StrEnum):
    auto = enum.auto()
    sbsign = enum.auto()
    systemd_sbsign = enum.auto()


class OutputFormat(StrEnum):
    confext = enum.auto()
    cpio = enum.auto()
    directory = enum.auto()
    disk = enum.auto()
    esp = enum.auto()
    none = enum.auto()
    portable = enum.auto()
    sysext = enum.auto()
    tar = enum.auto()
    uki = enum.auto()
    oci = enum.auto()
    addon = enum.auto()

    def extension(self) -> str:
        return {
            OutputFormat.confext:      "raw",
            OutputFormat.cpio:         "cpio",
            OutputFormat.disk:         "raw",
            OutputFormat.esp:          "raw",
            OutputFormat.portable:     "raw",
            OutputFormat.sysext:       "raw",
            OutputFormat.tar:          "tar",
            OutputFormat.uki:          "efi",
            OutputFormat.addon:        "efi",
        }.get(self, "")  # fmt: skip

    def use_outer_compression(self) -> bool:
        return self in (
            OutputFormat.tar,
            OutputFormat.cpio,
            OutputFormat.disk,
            OutputFormat.sysext,
            OutputFormat.confext,
            OutputFormat.portable,
        )

    def is_extension_image(self) -> bool:
        return self in (OutputFormat.sysext, OutputFormat.confext, OutputFormat.addon)

    def is_extension_or_portable_image(self) -> bool:
        return self.is_extension_image() or self == OutputFormat.portable


class ManifestFormat(StrEnum):
    json = enum.auto()  # the standard manifest in json format
    changelog = enum.auto()  # human-readable text file with package changelogs


class Compression(StrEnum):
    # fmt: off
    none = enum.auto()
    zstd = enum.auto()
    zst  = zstd
    xz   = enum.auto()
    bz2  = enum.auto()
    gz   = enum.auto()
    gzip = gz
    lz4  = enum.auto()
    lzma = enum.auto()
    # fmt: on

    def __bool__(self) -> bool:
        return self != Compression.none

    def extension(self) -> str:
        return {Compression.zstd: "zst"}.get(self, str(self))

    def oci_media_type_suffix(self) -> str:
        suffix = {
            Compression.none: "",
            Compression.gz:   "+gzip",
            Compression.zstd: "+zstd",
        }.get(self)  # fmt: skip

        if not suffix:
            die(f"Compression {self} not supported for OCI layers")

        return suffix


class DocFormat(StrEnum):
    auto = enum.auto()
    markdown = enum.auto()
    man = enum.auto()
    pandoc = enum.auto()
    system = enum.auto()

    @classmethod
    def all(cls) -> list["DocFormat"]:
        # this excludes auto and encodes the order in which these should be
        # checked when searching for docs
        return [cls.man, cls.pandoc, cls.markdown, cls.system]


class Bootloader(StrEnum):
    none = enum.auto()
    uki = enum.auto()
    systemd_boot = enum.auto()
    grub = enum.auto()
    uki_signed = enum.auto()
    systemd_boot_signed = enum.auto()
    grub_signed = enum.auto()

    def is_uki(self) -> bool:
        return self in (Bootloader.uki, Bootloader.uki_signed)

    def is_systemd_boot(self) -> bool:
        return self in (Bootloader.systemd_boot, Bootloader.systemd_boot_signed)

    def is_grub(self) -> bool:
        return self in (Bootloader.grub, Bootloader.grub_signed)

    def is_signed(self) -> bool:
        return self in (Bootloader.uki_signed, Bootloader.systemd_boot_signed, Bootloader.grub_signed)


class BiosBootloader(StrEnum):
    none = enum.auto()
    grub = enum.auto()


class ShimBootloader(StrEnum):
    none = enum.auto()
    signed = enum.auto()
    unsigned = enum.auto()


class UnifiedKernelImage(StrEnum):
    none = enum.auto()
    auto = enum.auto()
    signed = enum.auto()
    unsigned = enum.auto()

    def enabled(self) -> bool:
        return self in (UnifiedKernelImage.signed, UnifiedKernelImage.unsigned)


class Cacheonly(StrEnum):
    always = enum.auto()
    auto = enum.auto()
    none = auto
    metadata = enum.auto()
    never = enum.auto()


class Firmware(StrEnum):
    auto = enum.auto()
    linux = enum.auto()
    linux_noinitrd = enum.auto()
    uefi = enum.auto()
    uefi_secure_boot = enum.auto()
    bios = enum.auto()

    def is_uefi(self) -> bool:
        return self in (Firmware.uefi, Firmware.uefi_secure_boot)

    def is_linux(self) -> bool:
        return self in (Firmware.linux, Firmware.linux_noinitrd)


class ConsoleMode(StrEnum):
    interactive = enum.auto()
    read_only = enum.auto()
    native = enum.auto()
    gui = enum.auto()


class Network(StrEnum):
    interface = enum.auto()
    user = enum.auto()
    none = enum.auto()


class Vmm(StrEnum):
    qemu = enum.auto()
    vmspawn = enum.auto()


class Ssh(StrEnum):
    always = enum.auto()
    auto = enum.auto()
    runtime = enum.auto()
    never = enum.auto()


class Incremental(StrEnum):
    yes = enum.auto()
    no = enum.auto()
    strict = enum.auto()

    def __bool__(self) -> bool:
        return self != Incremental.no


class BuildSourcesEphemeral(StrEnum):
    yes = enum.auto()
    no = enum.auto()
    buildcache = enum.auto()

    def __bool__(self) -> bool:
        return self != BuildSourcesEphemeral.no


class Verity(StrEnum):
    disabled = enum.auto()
    hash = enum.auto()
    signed = enum.auto()
    defer = enum.auto()
    auto = enum.auto()


class Architecture(StrEnum):
    alpha = enum.auto()
    arc = enum.auto()
    arm = enum.auto()
    arm64 = enum.auto()
    ia64 = enum.auto()
    loongarch64 = enum.auto()
    mips_le = enum.auto()
    mips64_le = enum.auto()
    parisc = enum.auto()
    ppc = enum.auto()
    ppc64 = enum.auto()
    ppc64_le = enum.auto()
    riscv32 = enum.auto()
    riscv64 = enum.auto()
    s390 = enum.auto()
    s390x = enum.auto()
    tilegx = enum.auto()
    x86 = enum.auto()
    x86_64 = enum.auto()

    @staticmethod
    def from_uname(s: str) -> "Architecture":
        a = {
            "aarch64":     Architecture.arm64,
            "aarch64_be":  Architecture.arm64,
            "armv8l":      Architecture.arm,
            "armv8b":      Architecture.arm,
            "armv7ml":     Architecture.arm,
            "armv7mb":     Architecture.arm,
            "armv7l":      Architecture.arm,
            "armv7b":      Architecture.arm,
            "armv6l":      Architecture.arm,
            "armv6b":      Architecture.arm,
            "armv5tl":     Architecture.arm,
            "armv5tel":    Architecture.arm,
            "armv5tejl":   Architecture.arm,
            "armv5tejb":   Architecture.arm,
            "armv5teb":    Architecture.arm,
            "armv5tb":     Architecture.arm,
            "armv4tl":     Architecture.arm,
            "armv4tb":     Architecture.arm,
            "armv4l":      Architecture.arm,
            "armv4b":      Architecture.arm,
            "alpha":       Architecture.alpha,
            "arc":         Architecture.arc,
            "arceb":       Architecture.arc,
            "x86_64":      Architecture.x86_64,
            "i686":        Architecture.x86,
            "i586":        Architecture.x86,
            "i486":        Architecture.x86,
            "i386":        Architecture.x86,
            "ia64":        Architecture.ia64,
            "parisc64":    Architecture.parisc,
            "parisc":      Architecture.parisc,
            "loongarch64": Architecture.loongarch64,
            "mips64":      Architecture.mips64_le,
            "mips":        Architecture.mips_le,
            "ppc64le":     Architecture.ppc64_le,
            "ppc64":       Architecture.ppc64,
            "ppc":         Architecture.ppc,
            "riscv64":     Architecture.riscv64,
            "riscv32":     Architecture.riscv32,
            "riscv":       Architecture.riscv64,
            "s390x":       Architecture.s390x,
            "s390":        Architecture.s390,
            "tilegx":      Architecture.tilegx,
        }.get(s)  # fmt: skip

        if not a:
            die(f"Architecture {s} is not supported")

        return a

    def to_efi(self) -> Optional[str]:
        return {
            Architecture.x86:         "ia32",
            Architecture.x86_64:      "x64",
            Architecture.arm:         "arm",
            Architecture.arm64:       "aa64",
            Architecture.riscv32:     "riscv32",
            Architecture.riscv64:     "riscv64",
            Architecture.loongarch64: "loongarch64",
        }.get(self)  # fmt: skip

    def to_grub(self) -> Optional[str]:
        return {
            Architecture.x86_64: "x86_64",
            Architecture.x86:    "i386",
            Architecture.arm64:  "arm64",
            Architecture.arm:    "arm",
        }.get(self)  # fmt: skip

    def to_qemu(self) -> str:
        a = {
            Architecture.alpha:       "alpha",
            Architecture.arm:         "arm",
            Architecture.arm64:       "aarch64",
            Architecture.loongarch64: "loongarch64",
            Architecture.mips64_le:   "mips",
            Architecture.mips_le:     "mips",
            Architecture.parisc:      "hppa",
            Architecture.ppc:         "ppc",
            Architecture.ppc64:       "ppc64",
            Architecture.ppc64_le:    "ppc64",
            Architecture.riscv32:     "riscv32",
            Architecture.riscv64:     "riscv64",
            Architecture.s390x:       "s390x",
            Architecture.x86:         "i386",
            Architecture.x86_64:      "x86_64",
        }.get(self)  # fmt: skip

        if not a:
            die(f"Architecture {self} not supported by QEMU")

        return a

    def to_oci(self) -> str:
        a = {
            Architecture.arm:         "arm",
            Architecture.arm64:       "arm64",
            Architecture.loongarch64: "loong64",
            Architecture.mips64_le:   "mips64le",
            Architecture.mips_le:     "mipsle",
            Architecture.ppc:         "ppc",
            Architecture.ppc64:       "ppc64",
            Architecture.ppc64_le:    "ppc64le",
            Architecture.riscv32:     "riscv",
            Architecture.riscv64:     "riscv64",
            Architecture.s390x:       "s390x",
            Architecture.x86:         "386",
            Architecture.x86_64:      "amd64",
        }.get(self)  # fmt: skip

        if not a:
            die(f"Architecture {self} not supported by OCI")

        return a

    def supports_smbios(self, firmware: Firmware) -> bool:
        if self.is_x86_variant():
            return True

        return self.is_arm_variant() and firmware.is_uefi()

    def supports_fw_cfg(self) -> bool:
        return self.is_x86_variant() or self.is_arm_variant()

    def supports_smm(self) -> bool:
        return self.is_x86_variant()

    def supports_hpet(self) -> bool:
        return self.is_x86_variant()

    def supports_cxl(self) -> bool:
        return self.is_x86_variant() or self.is_arm_variant()

    def can_kvm(self) -> bool:
        return self == Architecture.native() or (
            Architecture.native() == Architecture.x86_64 and self == Architecture.x86
        )

    def default_qemu_machine(self) -> str:
        m = {
            Architecture.x86:      "q35",
            Architecture.x86_64:   "q35",
            Architecture.arm:      "virt",
            Architecture.arm64:    "virt",
            Architecture.s390:     "s390-ccw-virtio",
            Architecture.s390x:    "s390-ccw-virtio",
            Architecture.ppc:      "pseries",
            Architecture.ppc64:    "pseries",
            Architecture.ppc64_le: "pseries",
            Architecture.riscv64:  "virt",
        }  # fmt: skip

        if self not in m:
            die(f"No qemu machine defined for architecture {self}")

        return m[self]

    def default_qemu_nic_model(self) -> str:
        return {
            Architecture.s390:  "virtio",
            Architecture.s390x: "virtio",
        }.get(self, "virtio-net-pci")  # fmt: skip

    def is_native(self) -> bool:
        return self == self.native()

    def is_x86_variant(self) -> bool:
        return self in (Architecture.x86, Architecture.x86_64)

    def is_arm_variant(self) -> bool:
        return self in (Architecture.arm, Architecture.arm64)

    @classmethod
    def native(cls) -> "Architecture":
        return cls.from_uname(platform.machine())


class ArtifactOutput(StrEnum):
    uki = enum.auto()
    kernel = enum.auto()
    initrd = enum.auto()
    partitions = enum.auto()
    tar = enum.auto()
    pcrs = enum.auto()
    roothash = enum.auto()
    os_release = enum.auto()
    kernel_modules_initrd = enum.auto()

    @staticmethod
    def compat_no() -> list["ArtifactOutput"]:
        return [
            ArtifactOutput.uki,
            ArtifactOutput.kernel,
            ArtifactOutput.initrd,
        ]

    @staticmethod
    def compat_yes() -> list["ArtifactOutput"]:
        return [
            ArtifactOutput.uki,
            ArtifactOutput.kernel,
            ArtifactOutput.initrd,
            ArtifactOutput.partitions,
        ]


class ToolsTreeProfile(StrEnum):
    devel = enum.auto()
    misc = enum.auto()
    package_manager = enum.auto()
    runtime = enum.auto()

    @classmethod
    def default(cls) -> tuple["ToolsTreeProfile", ...]:
        return (cls.misc, cls.package_manager, cls.runtime)


class InitrdProfile(StrEnum):
    lvm = enum.auto()
    network = enum.auto()
    nfs = enum.auto()
    pkcs11 = enum.auto()
    plymouth = enum.auto()
    raid = enum.auto()


def expand_delayed_specifiers(specifiers: dict[str, str], text: str) -> str:
    def replacer(match: re.Match[str]) -> str:
        m = match.group("specifier")
        if (specifier := specifiers.get(m)) is not None:
            return specifier

        logging.warning(f"Unknown specifier '&{m}' found in {text}, ignoring")
        return ""

    return re.sub(r"&(?P<specifier>[&a-zA-Z])", replacer, text)


def try_parse_boolean(s: str) -> Optional[bool]:
    "Parse 1/true/yes/y/t/on as true and 0/false/no/n/f/off/None as false"

    s_l = s.lower()
    if s_l in {"1", "true", "yes", "y", "t", "on", "always"}:
        return True

    if s_l in {"0", "false", "no", "n", "f", "off", "never"}:
        return False

    return None


def parse_boolean(s: str) -> bool:
    value = try_parse_boolean(s)

    if value is None:
        die(f"Invalid boolean literal: {s!r}")

    return value


def in_box() -> bool:
    return parse_boolean(os.getenv("MKOSI_IN_BOX", "0"))


def parse_path(
    value: str,
    *,
    required: bool = True,
    resolve: bool = True,
    expanduser: bool = True,
    expandvars: bool = True,
    secret: bool = False,
    absolute: bool = False,
    directory: bool = False,
    exclude: Sequence[PathString] = (),
    constants: Sequence[str] = (),
) -> Path:
    if value in constants:
        return Path(value)

    if expandvars:
        value = os.path.expandvars(value)

    path = Path(value)

    if expanduser:
        path = path.expanduser()

    if required:
        if not path.exists():
            die(f"{value} does not exist")

        if directory and not path.is_dir():
            die(f"{value} is not a directory")

    if absolute and not path.is_absolute():
        die(f"{value} must be an absolute path")

    for e in exclude:
        if path.is_relative_to(e):
            die(f"{path} can not be relative to {e}")

    if resolve:
        path = path.resolve()

    if secret and path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o007:
            die(
                textwrap.dedent(f"""\
                Permissions of '{path}' of '{mode:04o}' are too open.
                When creating secret files use an access mode that restricts access to the owner only.
            """)
            )

    return path


def parse_paths_from_directory(
    value: str,
    *,
    required: bool = True,
    resolve: bool = True,
    expanduser: bool = True,
    expandvars: bool = True,
    secret: bool = False,
    absolute: bool = False,
    constants: Sequence[str] = (),
) -> list[Path]:
    base = os.path.dirname(value)
    glob = os.path.basename(value)

    path = parse_path(
        base,
        required=required,
        resolve=resolve,
        expanduser=expanduser,
        expandvars=expandvars,
        secret=secret,
        absolute=absolute,
        constants=constants,
    )
    if not path.exists():
        return []

    if path.exists() and not path.is_dir():
        die(f"{path} should be a directory, but isn't.")

    return sorted(parse_path(os.fspath(p), resolve=resolve, secret=secret) for p in path.glob(glob))


def config_parse_key(value: Optional[str], old: Optional[str]) -> Optional[Path]:
    if not value:
        return None

    return parse_path(value, secret=True) if Path(value).exists() else Path(value)


def config_parse_certificate(value: Optional[str], old: Optional[str]) -> Optional[Path]:
    if not value:
        return None

    return parse_path(value) if Path(value).exists() else Path(value)


def make_tree_parser(
    absolute: bool = True,
    required: bool = False,
    directory: bool = False,
) -> Callable[[str], ConfigTree]:
    def parse_tree(value: str) -> ConfigTree:
        src, sep, tgt = value.partition(":")

        return ConfigTree(
            source=parse_path(
                src,
                required=required,
                directory=directory,
            ),
            target=parse_path(
                tgt,
                required=False,
                resolve=False,
                expanduser=False,
                absolute=absolute,
            )
            if sep
            else None,
        )

    return parse_tree


def config_match_build_sources(match: str, value: list[ConfigTree]) -> bool:
    return Path(match.lstrip("/")) in [tree.target for tree in value if tree.target]


def config_make_list_matcher(parse: Callable[[str], T]) -> ConfigMatchCallback[list[T]]:
    def config_match_list(match: str, value: list[T]) -> bool:
        if not match:
            return len(value) == 0

        return parse(match) in value

    return config_match_list


def config_parse_string(value: Optional[str], old: Optional[str]) -> Optional[str]:
    return value or None


def config_make_string_matcher(allow_globs: bool = False) -> ConfigMatchCallback[str]:
    def config_match_string(match: str, value: str) -> bool:
        if allow_globs:
            return fnmatch.fnmatchcase(value, match)
        else:
            return match == value

    return config_match_string


def config_match_key_value(match: str, value: dict[str, str]) -> bool:
    k, sep, v = match.partition("=")
    if not sep:
        return k in value

    return value.get(k, None) == v


def config_parse_boolean(value: Optional[str], old: Optional[bool]) -> Optional[bool]:
    if value is None:
        return False

    if not value:
        return None

    return parse_boolean(value)


def parse_feature(value: str) -> ConfigFeature:
    try:
        return ConfigFeature(value)
    except ValueError:
        return ConfigFeature.enabled if parse_boolean(value) else ConfigFeature.disabled


def config_parse_feature(value: Optional[str], old: Optional[ConfigFeature]) -> Optional[ConfigFeature]:
    if value is None:
        return ConfigFeature.auto

    if not value:
        return None

    return parse_feature(value)


def config_match_feature(match: str, value: ConfigFeature) -> bool:
    return value == parse_feature(match)


def config_parse_compression(value: Optional[str], old: Optional[Compression]) -> Optional[Compression]:
    if not value:
        return None

    try:
        return Compression[value]
    except KeyError:
        return Compression.zstd if parse_boolean(value) else Compression.none


def config_parse_uuid(value: Optional[str], old: Optional[str]) -> Optional[uuid.UUID]:
    if not value:
        return None

    if value == "random":
        return uuid.uuid4()

    try:
        return uuid.UUID(value)
    except ValueError:
        die(f"{value} is not a valid UUID")


def config_parse_source_date_epoch(value: Optional[str], old: Optional[int]) -> Optional[int]:
    if not value:
        return None

    try:
        timestamp = int(value)
    except ValueError:
        die(f"Timestamp {value!r} is not a valid integer")

    if timestamp < 0:
        die(f"Source date epoch timestamp cannot be negative (got {value})")

    return timestamp


def config_parse_compress_level(value: Optional[str], old: Optional[int]) -> Optional[int]:
    if not value:
        return None

    try:
        level = int(value)
    except ValueError:
        die(f"Compression level {value!r} is not a valid integer")

    if level < 0:
        die(f"Compression level cannot be negative (got {value})")

    return level


def config_parse_mode(value: Optional[str], old: Optional[int]) -> Optional[int]:
    if not value:
        return None

    try:
        mode = int(value, base=8)
    except ValueError:
        die(f"Access mode {value!r} is not a valid integer in base 8")

    if mode < 0:
        die(f"Access mode cannot be negative (got {value})")

    if mode > 0o1777:
        die(f"Access mode cannot be greater than 1777 (got {value})")

    return mode


def config_default_compression(namespace: dict[str, Any]) -> Compression:
    if namespace["output_format"] in (
        OutputFormat.tar,
        OutputFormat.cpio,
        OutputFormat.uki,
        OutputFormat.esp,
        OutputFormat.addon,
    ):
        return Compression.zstd
    elif namespace["output_format"] == OutputFormat.oci:
        return Compression.gz
    else:
        return Compression.none


def config_default_output(namespace: dict[str, Any]) -> str:
    if namespace["image"] != "main":
        output = cast(str, namespace["image"])
    else:
        output = namespace["image_id"] or "image"

    if namespace["image_version"]:
        output += f"_{namespace['image_version']}"

    return output


def config_default_distribution(namespace: dict[str, Any]) -> Distribution:
    if d := os.getenv("MKOSI_HOST_DISTRIBUTION"):
        return Distribution(d)

    detected = detect_distribution()[0]

    if not detected:
        logging.info(
            "Distribution of your host can't be detected or isn't a supported target. "
            "Defaulting to Distribution=custom."
        )
        return Distribution.custom

    return detected


def config_default_release(namespace: dict[str, Any]) -> str:
    hd: Optional[Distribution]
    hr: Optional[str]

    if (d := os.getenv("MKOSI_HOST_DISTRIBUTION")) and (r := os.getenv("MKOSI_HOST_RELEASE")):
        hd, hr = Distribution(d), r
    else:
        hd, hr = detect_distribution()

    # If the configured distribution matches the host distribution, use the same release as the host.
    if namespace["distribution"] == hd and hr is not None:
        return hr

    return cast(str, namespace["distribution"].installer.default_release())


def config_default_tools_tree_distribution(namespace: dict[str, Any]) -> Distribution:
    if d := os.getenv("MKOSI_HOST_DISTRIBUTION"):
        return Distribution(d).installer.default_tools_tree_distribution() or Distribution(d)

    detected = detect_distribution()[0]

    if not detected:
        return Distribution.custom

    return detected.installer.default_tools_tree_distribution() or detected


def config_default_repository_key_fetch(namespace: dict[str, Any]) -> bool:
    def needs_repository_key_fetch(distribution: Distribution) -> bool:
        return distribution == Distribution.arch or distribution.is_rpm_distribution()

    if namespace["tools_tree"] != Path("default"):
        return (
            detect_distribution(namespace["tools_tree"] or Path("/"))[0] == Distribution.ubuntu
            and needs_repository_key_fetch(namespace["distribution"])
        )  # fmt: skip

    return namespace["tools_tree_distribution"] == Distribution.ubuntu and needs_repository_key_fetch(
        namespace["distribution"]
    )


def config_default_source_date_epoch(namespace: dict[str, Any]) -> Optional[int]:
    for env in namespace["environment"]:
        if s := startswith(env, "SOURCE_DATE_EPOCH="):
            break
    else:
        s = os.environ.get("SOURCE_DATE_EPOCH")
    return config_parse_source_date_epoch(s, None)


def config_default_proxy_url(namespace: dict[str, Any]) -> Optional[str]:
    names = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")

    for env in namespace["environment"]:
        k, _, v = env.partition("=")
        if k in names:
            return cast(str, v)

    for k, v in os.environ.items():
        if k in names:
            return v

    return None


def config_default_proxy_peer_certificate(namespace: dict[str, Any]) -> Optional[Path]:
    for p in (Path("/etc/pki/tls/certs/ca-bundle.crt"), Path("/etc/ssl/certs/ca-certificates.crt")):
        if p.exists():
            return p

    return None


def make_enum_parser(type: type[SE]) -> Callable[[str], SE]:
    def parse_enum(value: str) -> SE:
        try:
            return type(value)
        except ValueError:
            die(f"'{value}' is not a valid {type.__name__}")

    return parse_enum


def config_make_enum_parser(type: type[SE]) -> ConfigParseCallback[SE]:
    def config_parse_enum(value: Optional[str], old: Optional[SE]) -> Optional[SE]:
        return make_enum_parser(type)(value) if value else None

    return config_parse_enum


def config_make_enum_parser_with_boolean(type: type[SE], *, yes: SE, no: SE) -> ConfigParseCallback[SE]:
    def config_parse_enum(value: Optional[str], old: Optional[SE]) -> Optional[SE]:
        if not value:
            return None

        if value in type.values():
            return type(value)

        return yes if parse_boolean(value) else no

    return config_parse_enum


def config_make_enum_matcher(type: type[SE]) -> ConfigMatchCallback[SE]:
    def config_match_enum(match: str, value: SE) -> bool:
        return make_enum_parser(type)(match) == value

    return config_match_enum


def config_match_architecture(match: str, value: Architecture) -> bool:
    if match == "uefi":
        return value.to_efi() is not None

    return config_make_enum_matcher(Architecture)(match, value)


def package_sort_key(package: str) -> tuple[int, str]:
    """Sorts packages: normal first, paths second, conditional third"""

    if package.startswith("("):
        return 2, package
    elif package.startswith("/"):
        return 1, package
    return 0, package


def config_make_list_parser(
    *,
    delimiter: Optional[str] = None,
    parse: Callable[[str], T] = str,  # type: ignore # see mypy#3737
    unescape: bool = False,
    reset: bool = True,
    key: Optional[Callable[[T], Any]] = None,
) -> ConfigParseCallback[list[T]]:
    def config_parse_list(value: Optional[str], old: Optional[list[T]]) -> Optional[list[T]]:
        new = old.copy() if old else []

        if value is None:
            return []

        # Empty strings reset the list.

        if unescape:
            lex = shlex.shlex(value, posix=True)
            lex.whitespace_split = True
            lex.whitespace = f"\n{delimiter or ''}"
            lex.commenters = ""
            values = list(lex)
            if reset and not values:
                return None
        else:
            if delimiter:
                value = value.replace(delimiter, "\n")
            values = value.split("\n")
            if reset and len(values) == 1 and values[0] == "":
                return None

        new += [parse(v) for v in values if v]

        if key:
            new.sort(key=key)

        return new

    return config_parse_list


def config_match_version(match: str, value: str) -> bool:
    version = GenericVersion(value)

    for sigil, opfunc in {
        "==": operator.eq,
        "!=": operator.ne,
        "<=": operator.le,
        ">=": operator.ge,
        ">": operator.gt,
        "<": operator.lt,
    }.items():
        if (rhs := startswith(match, sigil)) is not None:
            op = opfunc
            comp_version = GenericVersion(rhs)
            break
    else:
        # default to equality if no operation is specified
        op = operator.eq
        comp_version = GenericVersion(match)

    # all constraints must be fulfilled
    if not op(version, comp_version):
        return False

    return True


def config_make_dict_parser(
    *,
    delimiter: Optional[str] = None,
    parse: Callable[[str], tuple[str, PathString]],
    unescape: bool = False,
    allow_paths: bool = False,
    reset: bool = True,
) -> ConfigParseCallback[dict[str, PathString]]:
    def config_parse_dict(
        value: Optional[str],
        old: Optional[dict[str, PathString]],
    ) -> Optional[dict[str, PathString]]:
        new = old.copy() if old else {}

        if value is None:
            return {}

        if allow_paths and value and "=" not in value:
            if Path(value).is_dir():
                new.update({p.name: p.absolute() for p in sorted(Path(value).iterdir()) if not p.is_dir()})
            elif (p := Path(value)).exists():
                new[p.name] = p.absolute()
            else:
                die(f"{p.absolute()} does not exist")

            return new

        # Empty strings reset the dict.

        if unescape:
            lex = shlex.shlex(value, posix=True)
            lex.whitespace_split = True
            lex.whitespace = f"\n{delimiter or ''}"
            lex.commenters = ""
            values = list(lex)
            if reset and not values:
                return None
        else:
            if delimiter:
                value = value.replace(delimiter, "\n")
            values = value.split("\n")
            if reset and len(values) == 1 and values[0] == "":
                return None

        return new | dict(parse(v) for v in values if v)

    return config_parse_dict


def parse_environment(value: str) -> tuple[str, str]:
    key, sep, value = value.partition("=")
    key, value = key.strip(), value.strip()
    value = value if sep else os.getenv(key, "")
    return (key, value)


def parse_key_value(value: str) -> tuple[str, str]:
    key, _, value = value.partition("=")
    key, value = key.strip(), value.strip()
    return (key, value)


def make_path_parser(
    *,
    required: bool = True,
    resolve: bool = True,
    expanduser: bool = True,
    expandvars: bool = True,
    secret: bool = False,
    exclude: Sequence[PathString] = (),
    constants: Sequence[str] = (),
) -> Callable[[str], Path]:
    return functools.partial(
        parse_path,
        required=required,
        resolve=resolve,
        expanduser=expanduser,
        expandvars=expandvars,
        secret=secret,
        exclude=exclude,
        constants=constants,
    )


def config_make_path_parser(
    *,
    required: bool = True,
    resolve: bool = True,
    expanduser: bool = True,
    expandvars: bool = True,
    secret: bool = False,
    absolute: bool = False,
    constants: Sequence[str] = (),
) -> ConfigParseCallback[Path]:
    def config_parse_path(value: Optional[str], old: Optional[Path]) -> Optional[Path]:
        if not value:
            return None

        return parse_path(
            value,
            required=required,
            resolve=resolve,
            expanduser=expanduser,
            expandvars=expandvars,
            secret=secret,
            absolute=absolute,
            constants=constants,
        )

    return config_parse_path


def is_valid_filename(s: str) -> bool:
    s = s.strip()
    return not (s == "." or s == ".." or "/" in s)


def config_make_filename_parser(hint: str) -> ConfigParseCallback[str]:
    def config_parse_filename(value: Optional[str], old: Optional[str]) -> Optional[str]:
        if not value:
            return None

        if not is_valid_filename(value):
            die(
                f"{value!r} is not a valid filename.",
                hint=hint,
            )

        return value

    return config_parse_filename


def match_path_exists(image: str, value: str) -> bool:
    if not value:
        return False

    return Path(value).exists()


def config_parse_root_password(
    value: Optional[str], old: Optional[tuple[str, bool]]
) -> Optional[tuple[str, bool]]:
    if not value:
        return None

    value = value.strip()
    hashed = value.startswith("hashed:")
    value = value.removeprefix("hashed:")

    return (value, hashed)


def match_systemd_version(image: str, value: str) -> bool:
    if not value:
        return False

    version = run(["systemctl", "--version"], stdout=subprocess.PIPE).stdout.strip().split()[1]
    return config_match_version(value, version)


def match_host_architecture(image: str, value: str) -> bool:
    return Architecture(value) == Architecture.native()


def match_image(image: str, value: str) -> bool:
    return value == image


def parse_bytes(value: str) -> int:
    if value.endswith("G"):
        factor = 1024**3
    elif value.endswith("M"):
        factor = 1024**2
    elif value.endswith("K"):
        factor = 1024
    else:
        factor = 1

    if factor > 1:
        value = value[:-1]

    result = math.ceil(float(value) * factor)
    if result <= 0:
        die("Size out of range")

    rem = result % 4096
    if rem != 0:
        result += 4096 - rem

    return result


def config_parse_bytes(value: Optional[str], old: Optional[int] = None) -> Optional[int]:
    if not value:
        return None

    return parse_bytes(value)


def config_parse_number(value: Optional[str], old: Optional[int] = None) -> Optional[int]:
    if not value:
        return None

    try:
        return int(value)
    except ValueError:
        die(f"{value!r} is not a valid number")


def parse_profile(value: str) -> str:
    if not is_valid_filename(value):
        die(
            f"{value!r} is not a valid profile",
            hint="Profiles= or --profile= requires a name with no path components.",
        )

    return value


def parse_drive(value: str) -> Drive:
    parts = value.split(":")

    if len(parts) > 6:
        die(f"Too many components in drive '{value}")

    if len(parts) < 1:
        die(f"No ID specified for drive '{value}'")

    if len(parts) < 2:
        die(f"Missing size in drive '{value}")

    id = parts[0]
    if not is_valid_filename(id):
        die(f"Unsupported path character in drive id '{id}'")

    flag_parser = make_enum_parser(DriveFlag)
    flag_list = p.split(",") if len(parts) > 5 and (p := parts[5]) else []

    return Drive(
        id=id,
        size=parse_bytes(parts[1]),
        directory=parse_path(p) if len(parts) > 2 and (p := parts[2]) else None,
        options=p if len(parts) > 3 and (p := parts[3]) else None,
        file_id=p if len(parts) > 4 and (p := parts[4]) else id,
        flags=[flag_parser(f) for f in flag_list],
    )


def config_parse_sector_size(value: Optional[str], old: Optional[int]) -> Optional[int]:
    if not value:
        return None

    try:
        size = int(value)
    except ValueError:
        die(f"'{value}' is not a valid number")

    if size < 512 or size > 4096:
        die(f"Sector size not between 512 and 4096: {size}")

    if not is_power_of_2(size):
        die(f"Sector size not power of 2: {size}")

    return size


def config_parse_vsock_cid(value: Optional[str], old: Optional[int]) -> Optional[int]:
    if not value:
        return None

    if value == "auto":
        return VsockCID.auto

    if value == "hash":
        return VsockCID.hash

    try:
        cid = int(value)
    except ValueError:
        die(f"VSock connection ID '{value}' is not a valid number or one of 'auto' or 'hash'")

    if cid not in range(3, 0xFFFFFFFF):
        die(f"{cid} is not in the valid VSock connection ID range [3, 0xFFFFFFFF)")

    return cid


def config_parse_minimum_version(value: Optional[str], old: Optional[str]) -> Optional[str]:
    if not value:
        return old

    if hash := startswith(value, "commit:"):
        if not in_box():
            gitdir = Path(__file__).parent.parent
            if not (gitdir / ".git").exists():
                die("Cannot check mkosi git version, not running mkosi from a git repository")

            git: list[PathString] = ["git", "-C", gitdir]
            if os.getuid() == 0:
                git += ["-c", f"safe.directory={gitdir}"]

            current = run([*git, "rev-parse", "HEAD"], stdout=subprocess.PIPE).stdout.strip()

            result = run(
                [*git, "rev-parse", "--quiet", "--verify", f"{hash}^{{commit}}"],
                # git rev-parse seems to produce output even with --quiet added to the options.
                stdout=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                result = run([*git, "merge-base", "--is-ancestor", hash, current], check=False)
            if result.returncode == 1:
                die(
                    f"mkosi commit {hash} or newer is required by this configuration",
                    hint=f"Currently checked out commit is {current}",
                )
            elif result.returncode != 0:
                die(f"Failed to check if mkosi git checkout is newer than commit {hash}")

        return value

    new = GenericVersion(value)

    if new > __version__:
        die(f"mkosi {new} or newer is required by this configuration (found {__version__})")

    if not old:
        return value

    return value if new > old else old


def file_run_or_read(file: Path) -> str:
    "Run the specified file and capture its output if it's executable, else read file contents"

    if os.access(file, os.X_OK):
        return run([file.absolute()], stdout=subprocess.PIPE, env=os.environ).stdout

    content = file.read_text()

    if content.startswith("#!/"):
        die(
            f"{file} starts with a shebang ({content.splitlines()[0]})",
            hint="This file should be executable",
        )

    return content


class KeySourceType(StrEnum):
    file = enum.auto()
    engine = enum.auto()
    provider = enum.auto()


@dataclasses.dataclass(frozen=True)
class KeySource:
    type: KeySourceType
    source: str = ""

    def __str__(self) -> str:
        return f"{self.type}:{self.source}" if self.source else str(self.type)


def config_parse_key_source(value: Optional[str], old: Optional[KeySource]) -> Optional[KeySource]:
    if not value:
        return KeySource(type=KeySourceType.file)

    typ, _, source = value.partition(":")
    try:
        type = KeySourceType(typ)
    except ValueError:
        die(f"'{value}' is not a valid key source")

    return KeySource(type=type, source=source)


class CertificateSourceType(StrEnum):
    file = enum.auto()
    provider = enum.auto()


@dataclasses.dataclass(frozen=True)
class CertificateSource:
    type: CertificateSourceType
    source: str = ""

    def __str__(self) -> str:
        return f"{self.type}:{self.source}" if self.source else str(self.type)


def config_parse_certificate_source(
    value: Optional[str],
    old: Optional[CertificateSource],
) -> Optional[CertificateSource]:
    if not value:
        return CertificateSource(type=CertificateSourceType.file)

    typ, _, source = value.partition(":")
    try:
        type = CertificateSourceType(typ)
    except ValueError:
        die(f"'{value}' is not a valid certificate source")

    return CertificateSource(type=type, source=source)


def config_parse_artifact_output_list(
    value: Optional[str], old: Optional[list[ArtifactOutput]]
) -> Optional[list[ArtifactOutput]]:
    if not value:
        return []

    # Keep for backwards compatibility
    boolean_value = try_parse_boolean(value)
    if boolean_value is not None:
        return ArtifactOutput.compat_yes() if boolean_value else ArtifactOutput.compat_no()

    list_parser = config_make_list_parser(delimiter=",", parse=make_enum_parser(ArtifactOutput))
    return list_parser(value, old)


class SettingScope(StrEnum):
    # Not passed down to tools tree or subimages, can be configured everywhere.
    local = enum.auto()
    # Passed down to subimages from main image, can be configured in main and tools tree images.
    universal = enum.auto()
    # Passed down to subimages and the tools tree, can only be configured in main image.
    multiversal = enum.auto()
    # Passed down to subimages from main image, can be configured everywhere.
    inherit = enum.auto()
    # Not passed down anywhere, can only be configured in main image.
    main = enum.auto()
    # Only passed down to tools tree, can only be configured in main image.
    tools = enum.auto()
    # Only passed down to initrd, can only be configured in main image.
    initrd = enum.auto()

    def is_main_setting(self) -> bool:
        return self in (SettingScope.main, SettingScope.tools, SettingScope.initrd, SettingScope.multiversal)

    def removeprefix(self, setting: str) -> str:
        if self == SettingScope.tools:
            return setting.removeprefix("tools_tree_")
        elif self == SettingScope.initrd:
            return setting.removeprefix("initrd_")
        else:
            return setting


@dataclasses.dataclass(frozen=True)
class ConfigSetting(Generic[T]):
    dest: str
    section: str
    parse: ConfigParseCallback[T] = config_parse_string  # type: ignore # see mypy#3737
    match: Optional[ConfigMatchCallback[T]] = None
    name: str = ""
    default: Optional[T] = None
    default_factory: Optional[ConfigDefaultCallback[T]] = None
    default_factory_depends: tuple[str, ...] = tuple()
    path_suffixes: tuple[str, ...] = ()
    recursive_path_suffixes: tuple[str, ...] = ()
    path_read_text: bool = False
    path_secret: bool = False
    specifier: str = ""
    scope: SettingScope = SettingScope.local

    # settings for argparse
    short: Optional[str] = None
    long: str = ""
    choices: Optional[list[str]] = None
    metavar: Optional[str] = None
    const: Optional[Any] = None
    help: Optional[str] = None

    # backward compatibility
    compat_names: tuple[str, ...] = ()
    compat_longs: tuple[str, ...] = ()

    # Tools tree specific settings
    tools: bool = False

    def __post_init__(self) -> None:
        if not self.name:
            object.__setattr__(self, "name", "".join(x.capitalize() for x in self.dest.split("_") if x))
        if not self.long:
            object.__setattr__(self, "long", f"--{self.dest.replace('_', '-')}")


@dataclasses.dataclass(frozen=True)
class Match:
    name: str
    match: Callable[[str, str], bool]


@dataclasses.dataclass(frozen=True)
class Specifier:
    char: str
    callback: Callable[[dict[str, Any], Path], str]
    depends: tuple[str, ...] = tuple()


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string

    def _split_lines(self, text: str, width: int) -> list[str]:
        """Wraps text to width, each line separately.
        If the first line of text ends in a colon, we assume that
        this is a list of option descriptions, and subindent them.
        Otherwise, the text is wrapped without indentation.
        """
        lines = text.splitlines()
        subindent = "    " if lines[0].endswith(":") else ""
        return flatten(
            textwrap.wrap(
                line, width, break_long_words=False, break_on_hyphens=False, subsequent_indent=subindent
            )
            for line in lines
        )


def parse_chdir(path: str) -> Optional[Path]:
    if not path:
        # The current directory should be ignored
        return None

    # Immediately change the current directory so that it's taken into
    # account when parsing the following options that take a relative path
    try:
        os.chdir(path)
    except (FileNotFoundError, NotADirectoryError):
        die(f"{path} is not a directory!")
    except OSError as e:
        die(f"Cannot change the directory to {path}: {e}")

    # Keep track of the current directory
    return Path.cwd()


class IgnoreAction(argparse.Action):
    """Argparse action for deprecated options that can be ignored."""

    def __init__(
        self,
        option_strings: Sequence[str],
        dest: str,
        nargs: Union[int, str, None] = None,
        default: Any = argparse.SUPPRESS,
        help: Optional[str] = argparse.SUPPRESS,
    ) -> None:
        super().__init__(option_strings, dest, nargs=nargs, default=default, help=help)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        logging.warning(f"{option_string} is no longer supported")


class PagerHelpAction(argparse._HelpAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None] = None,
        option_string: Optional[str] = None,
    ) -> None:
        page(parser.format_help(), namespace.pager)
        parser.exit()


def dict_with_capitalised_keys_factory(pairs: list[tuple[str, T]]) -> dict[str, T]:
    def key_transformer(k: str) -> str:
        if (s := SETTINGS_LOOKUP_BY_DEST.get(k)) is not None:
            return s.name
        return "".join(p.capitalize() for p in k.split("_"))

    return {key_transformer(k): v for k, v in dict(pairs).items()}


@dataclasses.dataclass(frozen=True)
class Args:
    verb: Verb
    cmdline: list[str]
    force: int
    directory: Optional[Path]
    debug: bool
    debug_shell: bool
    debug_workspace: bool
    debug_sandbox: bool
    pager: bool
    genkey_valid_days: str
    genkey_common_name: str
    auto_bump: bool
    doc_format: DocFormat
    json: bool
    wipe_build_dir: bool
    rerun_build_scripts: bool

    @classmethod
    def default(cls) -> "Args":
        """Alternative constructor to generate an all-default Args.

        This prevents Args being generated with defaults values implicitly.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            with chdir(tempdir):
                args, _, _ = parse_config([])

        return args

    @classmethod
    @functools.lru_cache(maxsize=1)
    def fields(cls) -> dict[str, dataclasses.Field[Any]]:
        return {f.name: f for f in dataclasses.fields(cls)}

    @classmethod
    def from_namespace(cls, ns: dict[str, Any]) -> "Args":
        return cls(**{k: v for k, v in ns.items() if k in cls.fields()})

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self, dict_factory=dict_with_capitalised_keys_factory)

    @classmethod
    def from_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "Args":
        """Instantiate a Args object from a (partial) JSON dump."""

        if isinstance(s, str):
            j = json.loads(s)
        elif isinstance(s, dict):
            j = s
        elif hasattr(s, "read"):
            j = json.load(s)
        else:
            raise ValueError(
                f"{cls.__name__} can only be constructed from JSON from strings, dictionaries and files."
            )

        def key_transformer(k: str) -> str:
            return "_".join(part.lower() for part in FALLBACK_NAME_TO_DEST_SPLITTER.split(k))

        for k, v in j.items():
            k = key_transformer(k)

            if k not in cls.fields() and (not isinstance(v, (dict, list, set)) or v):
                die(
                    f"Serialized JSON has unknown field {k} with value {v}",
                    hint="Re-running mkosi once with -f should solve the issue by re-generating the JSON",
                )

        value_transformer = json_type_transformer(cls)
        j = {(tk := key_transformer(k)): value_transformer(tk, v) for k, v in j.items()}

        return dataclasses.replace(cls.default(), **{k: v for k, v in j.items() if k in cls.fields()})


@dataclasses.dataclass(frozen=True)
class UKIProfile:
    profile: dict[str, str]
    cmdline: list[str]
    sign_expected_pcr: bool


def make_simple_config_parser(
    settings: Sequence[ConfigSetting[object]],
    valtype: type[D],
) -> Callable[[str], D]:
    lookup_by_name = {s.name: s for s in settings}
    lookup_by_dest = {s.dest: s for s in settings}

    def finalize_value(config: dict[str, Any], setting: ConfigSetting[object]) -> None:
        if setting.dest in config:
            return

        if setting.default_factory:
            for d in setting.default_factory_depends:
                finalize_value(config, lookup_by_dest[d])

            default = setting.default_factory(config)
        elif setting.default:
            default = setting.default
        else:
            default = setting.parse(None, None)

        config[setting.dest] = default

    def parse_simple_config(value: str) -> D:
        path = parse_path(value)
        config: dict[str, Any] = {}

        for section, name, value in parse_ini(path, only_sections=[s.section for s in settings]):
            if not name and not value:
                continue

            if not (s := lookup_by_name.get(name)):
                die(f"{path.absolute()}: Unknown setting {name}")

            if section != s.section:
                logging.warning(
                    f"{path.absolute()}: Setting {name} should be configured in [{s.section}], not "
                    f"[{section}]."
                )

            if name != s.name:
                logging.warning(
                    f"{path.absolute()}: Setting {name} is deprecated, please use {s.name} instead."
                )

            config[s.dest] = s.parse(value, config.get(s.dest))

        for setting in settings:
            finalize_value(config, setting)

        parameters = {f.name for f in dataclasses.fields(valtype)}
        return valtype(**{k: v for k, v in config.items() if k in parameters})

    return parse_simple_config


@dataclasses.dataclass(frozen=True)
class Config:
    """Type-hinted storage for command line arguments.

    Only user configuration is stored here while dynamic state exists in
    Mkosicontext. If a field of the same name exists in both classes always
    access the value from context.
    """

    profiles: list[str]
    files: list[Path]
    dependencies: list[str]
    minimum_version: Optional[str]
    pass_environment: list[str]

    distribution: Distribution
    release: str
    architecture: Architecture
    mirror: Optional[str]
    snapshot: Optional[str]
    local_mirror: Optional[str]
    repository_key_check: bool
    repository_key_fetch: bool
    repositories: list[str]

    output_format: OutputFormat
    manifest_format: list[ManifestFormat]
    output: str
    output_extension: str
    compress_output: Compression
    compress_level: int
    output_dir: Optional[Path]
    output_mode: Optional[int]
    image_id: Optional[str]
    image_version: Optional[str]
    split_artifacts: list[ArtifactOutput]
    repart_dirs: list[Path]
    sysupdate_dir: Optional[Path]
    sector_size: Optional[int]
    overlay: bool
    seed: uuid.UUID

    packages: list[str]
    build_packages: list[str]
    volatile_packages: list[str]
    package_directories: list[Path]
    volatile_package_directories: list[Path]
    with_recommends: bool
    with_docs: bool

    base_trees: list[Path]
    skeleton_trees: list[ConfigTree]
    extra_trees: list[ConfigTree]

    remove_packages: list[str]
    remove_files: list[str]
    clean_package_metadata: ConfigFeature
    source_date_epoch: Optional[int]

    configure_scripts: list[Path]
    sync_scripts: list[Path]
    prepare_scripts: list[Path]
    build_scripts: list[Path]
    postinst_scripts: list[Path]
    finalize_scripts: list[Path]
    postoutput_scripts: list[Path]
    clean_scripts: list[Path]

    bootable: ConfigFeature
    bootloader: Bootloader
    bios_bootloader: BiosBootloader
    shim_bootloader: ShimBootloader
    unified_kernel_images: UnifiedKernelImage
    unified_kernel_image_format: str
    unified_kernel_image_profiles: list[UKIProfile]
    initrds: list[Path]
    initrd_profiles: list[str]
    initrd_packages: list[str]
    initrd_volatile_packages: list[str]
    microcode_host: bool
    devicetrees: list[str]
    splash: Optional[Path]
    kernel_command_line: list[str]
    kernel_modules_include: list[str]
    kernel_modules_exclude: list[str]
    kernel_modules_include_host: bool
    firmware_include: list[str]
    firmware_exclude: list[str]

    kernel_modules_initrd: bool
    kernel_modules_initrd_include: list[str]
    kernel_modules_initrd_exclude: list[str]
    kernel_modules_initrd_include_host: bool

    locale: Optional[str]
    locale_messages: Optional[str]
    keymap: Optional[str]
    timezone: Optional[str]
    hostname: Optional[str]
    root_password: Optional[tuple[str, bool]]
    root_shell: Optional[str]
    machine_id: Optional[uuid.UUID]

    autologin: bool
    make_initrd: bool
    ssh: Ssh
    selinux_relabel: ConfigFeature

    secure_boot: bool
    secure_boot_auto_enroll: bool
    secure_boot_key: Optional[Path]
    secure_boot_key_source: KeySource
    secure_boot_certificate: Optional[Path]
    secure_boot_certificate_source: CertificateSource
    secure_boot_sign_tool: SecureBootSignTool
    verity: Verity
    verity_key: Optional[Path]
    verity_key_source: KeySource
    verity_certificate: Optional[Path]
    verity_certificate_source: CertificateSource
    sign_expected_pcr: ConfigFeature
    sign_expected_pcr_key: Optional[Path]
    sign_expected_pcr_key_source: KeySource
    sign_expected_pcr_certificate: Optional[Path]
    sign_expected_pcr_certificate_source: CertificateSource
    passphrase: Optional[Path]
    checksum: bool
    sign: bool
    openpgp_tool: str
    key: Optional[str]

    tools_tree: Optional[Path]
    tools_tree_certificates: bool
    extra_search_paths: list[Path]
    incremental: Incremental
    cacheonly: Cacheonly
    sandbox_trees: list[ConfigTree]
    workspace_dir: Optional[Path]
    cache_dir: Optional[Path]
    cache_key: str
    package_cache_dir: Optional[Path]
    build_dir: Optional[Path]
    build_key: str
    use_subvolumes: ConfigFeature
    repart_offline: bool
    history: bool
    build_sources: list[ConfigTree]
    build_sources_ephemeral: BuildSourcesEphemeral
    environment: dict[str, str]
    environment_files: list[Path]
    with_tests: bool
    with_network: bool
    proxy_url: Optional[str]
    proxy_exclude: list[str]
    proxy_peer_certificate: Optional[Path]
    proxy_client_certificate: Optional[Path]
    proxy_client_key: Optional[Path]

    nspawn_settings: Optional[Path]
    ephemeral: bool
    credentials: dict[str, PathString]
    kernel_command_line_extra: list[str]
    register: ConfigFeature
    storage_target_mode: ConfigFeature
    runtime_trees: list[ConfigTree]
    runtime_size: Optional[int]
    runtime_network: Network
    runtime_build_sources: bool
    bind_user: bool
    unit_properties: list[str]
    ssh_key: Optional[Path]
    ssh_certificate: Optional[Path]
    machine: Optional[str]
    forward_journal: Optional[Path]

    vmm: Vmm
    console: ConsoleMode
    cpus: int
    ram: int
    maxmem: int
    kvm: ConfigFeature
    cxl: bool
    vsock: ConfigFeature
    vsock_cid: int
    tpm: ConfigFeature
    removable: bool
    firmware: Firmware
    firmware_variables: Optional[Path]
    linux: Optional[str]
    drives: list[Drive]
    qemu_args: list[str]

    image: str

    def finalize_environment(self) -> dict[str, str]:
        env = {
            "SYSTEMD_TMPFILES_FORCE_SUBVOL": "0",
            "SYSTEMD_ASK_PASSWORD_KEYRING_TIMEOUT_SEC": "infinity",
            "SYSTEMD_ASK_PASSWORD_KEYRING_TYPE": "session",
            "TERM": finalize_term(),
        }

        if self.image != "main":
            env["SUBIMAGE"] = self.image
        if self.image_id is not None:
            env["IMAGE_ID"] = self.image_id
        if self.image_version is not None:
            env["IMAGE_VERSION"] = self.image_version
        if self.source_date_epoch is not None:
            env["SOURCE_DATE_EPOCH"] = str(self.source_date_epoch)
        if self.proxy_url is not None:
            for e in ("http_proxy", "https_proxy"):
                env[e] = self.proxy_url
                env[e.upper()] = self.proxy_url
        if self.proxy_exclude:
            env["no_proxy"] = ",".join(self.proxy_exclude)
            env["NO_PROXY"] = ",".join(self.proxy_exclude)
        if self.proxy_peer_certificate:
            env["GIT_PROXY_SSL_CAINFO"] = "/proxy.cacert"
        if self.proxy_client_certificate:
            env["GIT_PROXY_SSL_CERT"] = "/proxy.clientcert"
        if self.proxy_client_key:
            env["GIT_PROXY_SSL_KEY"] = "/proxy.clientkey"
        if dnf := os.getenv("MKOSI_DNF"):
            env["MKOSI_DNF"] = dnf
        if gnupghome := os.getenv("GNUPGHOME"):
            env["GNUPGHOME"] = os.fspath(Path(gnupghome).absolute())

        env |= dict(
            parse_environment(line)
            for f in self.environment_files
            for line in f.read_text().strip().splitlines()
        )
        env |= self.environment
        env |= finalize_git_config(self.proxy_url, env)

        return env

    def is_incremental(self) -> bool:
        return bool(self.incremental) and not self.base_trees and not self.overlay

    def machine_or_name(self) -> str:
        return self.machine or self.image

    def output_dir_or_cwd(self) -> Path:
        return self.output_dir or Path.cwd()

    def workspace_dir_or_default(self) -> Path:
        if self.workspace_dir:
            return self.workspace_dir

        if (
            (cache := INVOKING_USER.cache_dir())
            and cache != Path("/var/cache")
            and os.access(cache, os.W_OK)
        ):
            return cache / "mkosi"

        return Path("/var/tmp")

    def package_cache_dir_or_default(self) -> Path:
        key = f"{self.distribution}~{self.release}~{self.architecture}"
        return self.package_cache_dir or (INVOKING_USER.cache_dir() / "mkosi" / key)

    def tools(self) -> Path:
        if in_box():
            return Path("/")

        return self.tools_tree or Path("/")

    @classmethod
    def default(cls) -> "Config":
        """Alternative constructor to generate an all-default Config.

        This prevents Config being generated with defaults values implicitly.
        """
        with chdir("/proc"):
            _, _, [config] = parse_config([])

        return config

    @classmethod
    @functools.lru_cache(maxsize=1)
    def fields(cls) -> dict[str, dataclasses.Field[Any]]:
        return {f.name: f for f in dataclasses.fields(cls)}

    @classmethod
    def from_dict(cls, ns: dict[str, Any]) -> "Config":
        return cls(**{k: v for k, v in ns.items() if k in cls.fields()})

    @property
    def output_with_format(self) -> str:
        ext = self.output_extension

        if not ext:
            return self.output

        return f"{self.output}.{ext}"

    @property
    def output_with_compression(self) -> str:
        output = self.output_with_format

        if self.compress_output and self.output_format.use_outer_compression():
            output += f".{self.compress_output.extension()}"

        return output

    @property
    def output_split_uki(self) -> str:
        return f"{self.output}.efi"

    @property
    def output_split_kernel(self) -> str:
        return f"{self.output}.vmlinuz"

    @property
    def output_split_initrd(self) -> str:
        return f"{self.output}.initrd"

    @property
    def output_split_pcrs(self) -> str:
        return f"{self.output}.pcrs"

    @property
    def output_split_roothash(self) -> str:
        return f"{self.output}.roothash"

    @property
    def output_split_os_release(self) -> str:
        return f"{self.output}.osrelease"

    @property
    def output_split_kernel_modules_initrd(self) -> str:
        return f"{self.output}.kernel-modules-initrd"

    @property
    def output_nspawn_settings(self) -> str:
        return f"{self.output}.nspawn"

    @property
    def output_checksum(self) -> str:
        return f"{self.output}.SHA256SUMS"

    @property
    def output_signature(self) -> str:
        return f"{self.output}.SHA256SUMS.gpg"

    @property
    def output_manifest(self) -> str:
        return f"{self.output}.manifest"

    @property
    def output_changelog(self) -> str:
        return f"{self.output}.changelog"

    @property
    def output_tar(self) -> str:
        output = f"{self.output}.tar"

        if self.compress_output:
            output += f".{self.compress_output.extension()}"

        return output

    @property
    def outputs(self) -> list[str]:
        return [
            self.output,
            self.output_with_format,
            self.output_with_compression,
            self.output_split_uki,
            self.output_split_kernel,
            self.output_split_initrd,
            self.output_split_pcrs,
            self.output_split_roothash,
            self.output_split_os_release,
            self.output_split_kernel_modules_initrd,
            self.output_nspawn_settings,
            self.output_checksum,
            self.output_signature,
            self.output_manifest,
            self.output_changelog,
            self.output_tar,
        ]

    @property
    def build_subdir(self) -> Path:
        assert self.build_dir
        subdir = self.expand_key_specifiers(self.build_key)

        if subdir == "-":
            return self.build_dir

        return self.build_dir / subdir

    def cache_manifest(self) -> dict[str, Any]:
        return {
            "distribution": self.distribution,
            "release": self.release,
            "mirror": self.mirror,
            "snapshot": self.snapshot,
            "architecture": self.architecture,
            # Caching the package manager used does not matter for the default tools tree because we don't
            # cache the package manager metadata for the tools tree either. In fact, it can cause issues as
            # the cache manifest for the tools tree will sometimes be different depending on whether we're
            # running inside or outside of the mkosi box environment. To avoid these issues, don't cache the
            # package manager used in the tools tree cache manifest.
            **(
                {"package_manager": self.distribution.installer.package_manager(self).executable(self)}
                if self.image != "tools"
                else {}
            ),
            "packages": sorted(self.packages),
            "build_packages": sorted(self.build_packages),
            "remove_packages": sorted(self.remove_packages),
            "package_directories": [
                (p.name, p.stat().st_mtime_ns)
                for d in self.package_directories
                for p in sorted(
                    flatten(
                        d.glob(glob)
                        for glob in self.distribution.installer.package_manager(self).package_globs()
                    )
                )
            ],
            "repositories": sorted(self.repositories),
            "overlay": self.overlay,
            "prepare_scripts": sorted(
                base64.b64encode(script.read_bytes()).decode() for script in self.prepare_scripts
            ),
        }

    def expand_key_specifiers(self, key: str) -> str:
        specifiers = {
            "&": "&",
            "d": str(self.distribution),
            "r": self.release,
            "a": str(self.architecture),
            "i": self.image_id or "",
            "v": self.image_version or "",
            "I": self.image,
        }

        return expand_delayed_specifiers(specifiers, key)

    def expand_linux_specifiers(self) -> Path:
        assert self.linux

        specifiers = {
            "&": "&",
            "b": os.fspath(self.build_subdir) if self.build_dir else "",
        }

        return parse_path(expand_delayed_specifiers(specifiers, self.linux))

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self, dict_factory=dict_with_capitalised_keys_factory)

        if self.build_dir:
            d["BuildSubdirectory"] = self.build_subdir

        return d

    @classmethod
    def to_partial_dict(cls, partial: dict[str, Any]) -> dict[str, Any]:
        return dict_with_capitalised_keys_factory([(k, v) for k, v in partial.items() if k in cls.fields()])

    @classmethod
    def from_partial_json(
        cls,
        s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]],
    ) -> dict[str, Any]:
        """Instantiate a Config object from a (partial) JSON dump."""
        if isinstance(s, str):
            j = json.loads(s)
        elif isinstance(s, dict):
            j = s
        elif hasattr(s, "read"):
            j = json.load(s)
        else:
            raise ValueError(
                f"{cls.__name__} can only be constructed from JSON from strings, dictionaries and files."
            )

        def key_transformer(k: str) -> str:
            if (s := SETTINGS_LOOKUP_BY_NAME.get(k)) is not None:
                return s.dest
            return "_".join(part.lower() for part in FALLBACK_NAME_TO_DEST_SPLITTER.split(k))

        j.pop("BuildSubdirectory", None)

        for k, v in j.items():
            k = key_transformer(k)

            if k not in cls.fields() and (not isinstance(v, (dict, list, set)) or v):
                die(
                    f"Serialized JSON has unknown field {k} with value {v}",
                    hint="Re-running mkosi once with -f should solve the issue by re-generating the JSON",
                )

        value_transformer = json_type_transformer(cls)
        return {(tk := key_transformer(k)): value_transformer(tk, v) for k, v in j.items()}

    @classmethod
    def from_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "Config":
        return dataclasses.replace(
            cls.default(), **{k: v for k, v in cls.from_partial_json(s).items() if k in cls.fields()}
        )

    def find_binary(self, *names: PathString, tools: bool = True) -> Optional[Path]:
        return find_binary(*names, root=self.tools() if tools else Path("/"), extra=self.extra_search_paths)

    def sandbox(
        self,
        *,
        network: bool = False,
        devices: bool = False,
        relaxed: bool = False,
        tools: bool = True,
        scripts: Optional[Path] = None,
        overlay: Optional[Path] = None,
        options: Sequence[PathString] = (),
        setup: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]:
        opt: list[PathString] = [*options]

        if not relaxed:
            opt += flatten(("--ro-bind", d, d) for d in self.extra_search_paths)

            if p := self.proxy_peer_certificate:
                opt += ["--ro-bind", os.fspath(p), "/proxy.cacert"]
            if p := self.proxy_client_certificate:
                opt += ["--ro-bind", os.fspath(p), "/proxy.clientcert"]
            if p := self.proxy_client_key:
                opt += ["--ro-bind", os.fspath(p), "/proxy.clientkey"]

        return sandbox_cmd(
            network=network,
            devices=devices,
            relaxed=relaxed,
            scripts=scripts,
            tools=self.tools() if tools else Path("/"),
            overlay=overlay,
            options=opt,
            setup=setup,
            extra=self.extra_search_paths,
        )


def parse_ini(path: Path, only_sections: Collection[str] = ()) -> Iterator[tuple[str, str, str]]:
    """
    We have our own parser instead of using configparser as the latter does not support specifying the same
    setting multiple times in the same configuration file.
    """
    section: Optional[str] = None
    setting: Optional[str] = None
    value: Optional[str] = None

    for line in textwrap.dedent(path.read_text()).splitlines():
        comment = line.find("#")
        if comment >= 0:
            line = line[:comment]

        if not line.strip():
            continue

        # If we have a section, setting and value, any line that's indented is considered part of the
        # setting's value.
        if section and setting and value is not None and line[0].isspace():
            value = f"{value}\n{line.strip()}"
            continue

        # So the line is not indented, that means we either found a new section or a new setting. Either way,
        # let's yield the previous setting and its value before parsing the new section/setting.
        if section and setting and value is not None:
            yield section, setting, value
            setting = value = None

        line = line.strip()

        if line[0] == "[":
            if line[-1] != "]":
                die(f"{line} is not a valid section")

            # Yield the section name with an empty key and value to indicate we've finished the current
            # section.
            if section:
                yield section, "", ""

            section = line[1:-1].strip()
            if not section:
                die("Section name cannot be empty or whitespace")

            continue

        if not section:
            die(f"Setting {line} is located outside of section")

        if only_sections and section not in only_sections:
            continue

        setting, delimiter, value = line.partition("=")
        if not delimiter:
            die(f"Setting {setting} must be followed by '='")
        if not setting:
            die(f"Missing setting name before '=' in {line}")

        setting = setting.strip()
        value = value.strip()

    # Make sure we yield any final setting and its value.
    if section and setting and value is not None:
        yield section, setting, value

    if section and (not only_sections or section in only_sections):
        yield section, "", ""


def parse_kernel_module_filter_regexp(p: str) -> str:
    if p in ("default", "host"):
        return p
    return f"re:{p}"


UKI_PROFILE_SETTINGS: list[ConfigSetting[Any]] = [
    ConfigSetting(
        dest="profile",
        section="UKIProfile",
        parse=config_make_dict_parser(parse=parse_key_value),
    ),
    ConfigSetting(
        dest="cmdline",
        section="UKIProfile",
        parse=config_make_list_parser(delimiter=" "),
    ),
    ConfigSetting(
        dest="sign_expected_pcr",
        section="UKIProfile",
        parse=config_parse_boolean,
        default=True,
    ),
]


SETTINGS: list[ConfigSetting[Any]] = [
    # Include section
    ConfigSetting(
        dest="include",
        short="-I",
        section="Include",
        parse=config_make_list_parser(
            delimiter=",",
            reset=False,
            parse=make_path_parser(constants=BUILTIN_CONFIGS),
        ),
        help="Include configuration from the specified file or directory",
        tools=True,
    ),
    # Config section
    ConfigSetting(
        dest="profiles",
        long="--profile",
        section="Config",
        help="Build the specified profiles",
        parse=config_make_list_parser(delimiter=",", parse=parse_profile),
        match=config_make_list_matcher(parse=parse_profile),
        scope=SettingScope.inherit,
        compat_names=("Profile",),
        tools=True,
    ),
    ConfigSetting(
        dest="dependencies",
        long="--dependency",
        section="Config",
        parse=config_make_list_parser(delimiter=","),
        help="Specify other images that this image depends on",
    ),
    ConfigSetting(
        dest="minimum_version",
        section="Config",
        parse=config_parse_minimum_version,
        help="Specify the minimum required mkosi version",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="configure_scripts",
        long="--configure-script",
        metavar="PATH",
        section="Config",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("configure",),
        help="Configure script to run before doing anything",
    ),
    ConfigSetting(
        dest="pass_environment",
        metavar="NAME",
        section="Config",
        parse=config_make_list_parser(delimiter=" "),
        help="Environment variables to pass to subimages",
        scope=SettingScope.main,
    ),
    # Distribution section
    ConfigSetting(
        dest="distribution",
        short="-d",
        section="Distribution",
        specifier="d",
        parse=config_make_enum_parser(Distribution),
        match=config_make_enum_matcher(Distribution),
        default_factory=config_default_distribution,
        choices=Distribution.choices(),
        help="Distribution to install",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="release",
        short="-r",
        section="Distribution",
        specifier="r",
        parse=config_parse_string,
        match=config_make_string_matcher(),
        default_factory=config_default_release,
        default_factory_depends=("distribution",),
        help="Distribution release to install",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="architecture",
        section="Distribution",
        specifier="a",
        parse=config_make_enum_parser(Architecture),
        match=config_match_architecture,
        default=Architecture.native(),
        choices=Architecture.choices(),
        help="Override the architecture of installation",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="mirror",
        short="-m",
        section="Distribution",
        help="Distribution mirror to use",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="snapshot",
        section="Distribution",
        help="Distribution snapshot to use",
        path_suffixes=("snapshot",),
        path_read_text=True,
        scope=SettingScope.universal,
        tools=True,
    ),
    ConfigSetting(
        dest="local_mirror",
        section="Distribution",
        help="Use a single local, flat and plain mirror to build the image",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="repository_key_check",
        metavar="BOOL",
        section="Distribution",
        default=True,
        parse=config_parse_boolean,
        help="Controls signature and key checks on repositories",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="repository_key_fetch",
        metavar="BOOL",
        section="Distribution",
        default_factory_depends=("distribution", "tools_tree", "tools_tree_distribution"),
        default_factory=config_default_repository_key_fetch,
        parse=config_parse_boolean,
        help="Controls whether distribution GPG keys can be fetched remotely",
        scope=SettingScope.universal,
        tools=True,
    ),
    ConfigSetting(
        dest="repositories",
        metavar="REPOS",
        section="Distribution",
        parse=config_make_list_parser(delimiter=","),
        match=config_make_list_matcher(parse=str),
        help="Repositories to use",
        scope=SettingScope.universal,
        tools=True,
    ),
    # Output section
    ConfigSetting(
        dest="output_format",
        short="-t",
        long="--format",
        name="Format",
        section="Output",
        specifier="t",
        parse=config_make_enum_parser(OutputFormat),
        match=config_make_enum_matcher(OutputFormat),
        default=OutputFormat.disk,
        choices=OutputFormat.choices(),
        help="Output Format",
    ),
    ConfigSetting(
        dest="manifest_format",
        metavar="FORMAT",
        section="Output",
        parse=config_make_list_parser(delimiter=",", parse=make_enum_parser(ManifestFormat)),
        help="Manifest Format",
    ),
    ConfigSetting(
        dest="output",
        short="-o",
        metavar="NAME",
        section="Output",
        specifier="o",
        parse=config_make_filename_parser(
            "Output= or --output= requires a filename with no path components. "
            "Use OutputDirectory= or --output-directory= to configure the output directory."
        ),
        default_factory=config_default_output,
        default_factory_depends=("image_id", "image_version"),
        help="Output name",
        tools=True,
    ),
    ConfigSetting(
        dest="output_extension",
        metavar="EXTENSION",
        section="Output",
        parse=config_make_filename_parser(
            "OutputExtension= or --output-extension= requires a valid extension with no path components."
        ),
        help="Output extension",
        default_factory=lambda ns: ns["output_format"].extension(),
        default_factory_depends=("output_format",),
    ),
    ConfigSetting(
        dest="compress_output",
        metavar="ALG",
        section="Output",
        parse=config_parse_compression,
        default_factory=config_default_compression,
        default_factory_depends=("distribution", "release", "output_format"),
        help="Enable whole-output compression (with images or archives)",
    ),
    ConfigSetting(
        dest="compress_level",
        metavar="LEVEL",
        section="Output",
        parse=config_parse_compress_level,
        default=3,
        help="Set the compression level to use",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="output_dir",
        short="-O",
        long="--output-directory",
        compat_longs=("--output-dir",),
        metavar="DIR",
        name="OutputDirectory",
        section="Output",
        specifier="O",
        parse=config_make_path_parser(required=False),
        path_suffixes=("output",),
        help="Output directory",
        scope=SettingScope.universal,
        tools=True,
    ),
    ConfigSetting(
        dest="output_mode",
        metavar="MODE",
        section="Output",
        parse=config_parse_mode,
        help="Set file system access mode for image",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="image_version",
        match=config_match_version,
        section="Output",
        specifier="v",
        help="Set version for image",
        path_suffixes=("version",),
        path_read_text=True,
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="image_id",
        match=config_make_string_matcher(allow_globs=True),
        section="Output",
        specifier="i",
        help="Set ID for image",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="split_artifacts",
        section="Output",
        parse=config_parse_artifact_output_list,
        default=ArtifactOutput.compat_no(),
        help="Split artifacts out of the final image",
    ),
    ConfigSetting(
        dest="repart_dirs",
        long="--repart-directory",
        compat_longs=("--repart-dir",),
        metavar="PATH",
        name="RepartDirectories",
        section="Output",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("repart",),
        help="Directory containing systemd-repart partition definitions",
    ),
    ConfigSetting(
        dest="sector_size",
        section="Output",
        parse=config_parse_sector_size,
        help="Set the disk image sector size",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="overlay",
        metavar="BOOL",
        section="Output",
        parse=config_parse_boolean,
        help="Only output the additions on top of the given base trees",
    ),
    ConfigSetting(
        dest="seed",
        metavar="UUID",
        section="Output",
        parse=config_parse_uuid,
        default=uuid.uuid4(),
        path_suffixes=("seed",),
        path_read_text=True,
        help="Set the seed for systemd-repart",
    ),
    ConfigSetting(
        dest="clean_scripts",
        long="--clean-script",
        metavar="PATH",
        section="Output",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("clean",),
        recursive_path_suffixes=("clean.d/*",),
        help="Clean script to run after cleanup",
    ),
    # Content section
    ConfigSetting(
        dest="packages",
        short="-p",
        long="--package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=",", key=package_sort_key),
        help="Add an additional package to the OS image",
        tools=True,
    ),
    ConfigSetting(
        dest="build_packages",
        long="--build-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=",", key=package_sort_key),
        help="Additional packages needed for build scripts",
    ),
    ConfigSetting(
        dest="volatile_packages",
        long="--volatile-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=",", key=package_sort_key),
        help="Packages to install after executing build scripts",
    ),
    ConfigSetting(
        dest="package_directories",
        long="--package-directory",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("packages",),
        help="Specify a directory containing extra packages",
        scope=SettingScope.universal,
        tools=True,
    ),
    ConfigSetting(
        dest="volatile_package_directories",
        long="--volatile-package-directory",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        help="Specify a directory containing extra volatile packages",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="with_recommends",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="Install recommended packages",
    ),
    ConfigSetting(
        dest="with_docs",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        default=True,
        help="Install documentation",
    ),
    ConfigSetting(
        dest="base_trees",
        long="--base-tree",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
        help="Use the given tree as base tree (e.g. lower sysext layer)",
    ),
    ConfigSetting(
        dest="skeleton_trees",
        long="--skeleton-tree",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser(required=True)),
        path_suffixes=("skeleton", "skeleton.tar"),
        help="Use a skeleton tree to bootstrap the image before installing anything",
    ),
    ConfigSetting(
        dest="extra_trees",
        long="--extra-tree",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser()),
        path_suffixes=("extra", "extra.tar"),
        help="Copy an extra tree on top of image",
    ),
    ConfigSetting(
        dest="remove_packages",
        long="--remove-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Remove package from the image OS image after installation",
    ),
    ConfigSetting(
        dest="remove_files",
        metavar="GLOB",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Remove files from built image",
    ),
    ConfigSetting(
        dest="clean_package_metadata",
        metavar="FEATURE",
        section="Content",
        parse=config_parse_feature,
        help="Remove package manager database and other files",
    ),
    ConfigSetting(
        dest="source_date_epoch",
        metavar="TIMESTAMP",
        section="Content",
        parse=config_parse_source_date_epoch,
        default_factory=config_default_source_date_epoch,
        default_factory_depends=("environment",),
        help="Set the $SOURCE_DATE_EPOCH timestamp",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="sync_scripts",
        long="--sync-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("sync",),
        recursive_path_suffixes=("sync.d/*",),
        help="Sync script to run before starting the build",
        tools=True,
    ),
    ConfigSetting(
        dest="prepare_scripts",
        long="--prepare-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("prepare", "prepare.chroot"),
        recursive_path_suffixes=("prepare.d/*",),
        help="Prepare script to run inside the image before it is cached",
        compat_names=("PrepareScript",),
        tools=True,
    ),
    ConfigSetting(
        dest="build_scripts",
        long="--build-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("build", "build.chroot"),
        recursive_path_suffixes=("build.d/*",),
        help="Build script to run inside image",
        compat_names=("BuildScript",),
    ),
    ConfigSetting(
        dest="postinst_scripts",
        long="--postinst-script",
        metavar="PATH",
        name="PostInstallationScripts",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("postinst", "postinst.chroot"),
        recursive_path_suffixes=("postinst.d/*",),
        help="Postinstall script to run inside image",
        compat_names=("PostInstallationScript",),
    ),
    ConfigSetting(
        dest="finalize_scripts",
        long="--finalize-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("finalize", "finalize.chroot"),
        recursive_path_suffixes=("finalize.d/*",),
        help="Postinstall script to run outside image",
        compat_names=("FinalizeScript",),
    ),
    ConfigSetting(
        dest="postoutput_scripts",
        long="--postoutput-script",
        metavar="PATH",
        name="PostOutputScripts",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("postoutput",),
        recursive_path_suffixes=("postoutput.d/*",),
        help="Output postprocessing script to run outside image",
    ),
    ConfigSetting(
        dest="bootable",
        metavar="FEATURE",
        section="Content",
        parse=config_parse_feature,
        match=config_match_feature,
        help="Generate ESP partition with systemd-boot and UKIs for installed kernels",
    ),
    ConfigSetting(
        dest="bootloader",
        section="Content",
        parse=config_make_enum_parser(Bootloader),
        choices=Bootloader.choices(),
        default=Bootloader.systemd_boot,
        help="Specify which UEFI bootloader to use",
    ),
    ConfigSetting(
        dest="bios_bootloader",
        section="Content",
        parse=config_make_enum_parser(BiosBootloader),
        choices=BiosBootloader.choices(),
        default=BiosBootloader.none,
        help="Specify which BIOS bootloader to use",
    ),
    ConfigSetting(
        dest="shim_bootloader",
        section="Content",
        parse=config_make_enum_parser(ShimBootloader),
        choices=ShimBootloader.choices(),
        default=ShimBootloader.none,
        help="Specify whether to use shim",
    ),
    ConfigSetting(
        dest="unified_kernel_images",
        metavar="FEATURE",
        section="Content",
        parse=config_make_enum_parser_with_boolean(
            UnifiedKernelImage, yes=UnifiedKernelImage.signed, no=UnifiedKernelImage.none
        ),
        default=UnifiedKernelImage.auto,
        help="Specify whether to use UKIs with grub/systemd-boot in UEFI mode",
    ),
    ConfigSetting(
        dest="unified_kernel_image_format",
        section="Content",
        parse=config_make_filename_parser(
            "UnifiedKernelImageFormat= or --unified-kernel-image-format= "
            "requires a filename with no path components."
        ),
        # The default value is set in `__init__.py` in `install_uki`.
        # `None` is used to determine if the roothash should be appended
        # to the filename if they are found.
        # default=
        help="Specify the format used for the UKI filename",
    ),
    ConfigSetting(
        dest="unified_kernel_image_profiles",
        long="--uki-profile",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(
            delimiter=",",
            parse=make_simple_config_parser(UKI_PROFILE_SETTINGS, UKIProfile),
        ),
        recursive_path_suffixes=("uki-profiles/*.conf",),
        help="Configuration files to generate UKI profiles",
    ),
    ConfigSetting(
        dest="initrds",
        long="--initrd",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
        help="Add a user-provided initrd to image",
    ),
    ConfigSetting(
        dest="microcode_host",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        default=False,
        help="Only include the host CPU's microcode",
    ),
    ConfigSetting(
        dest="initrd_profiles",
        long="--initrd-profile",
        metavar="PROFILE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        choices=InitrdProfile.values(),
        default=[],
        help="Which profiles to enable for the default initrd",
        scope=SettingScope.initrd,
    ),
    ConfigSetting(
        dest="initrd_packages",
        long="--initrd-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Add additional packages to the default initrd",
        scope=SettingScope.initrd,
    ),
    ConfigSetting(
        dest="initrd_volatile_packages",
        long="--initrd-volatile-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Packages to install in the initrd that are not cached",
        scope=SettingScope.initrd,
    ),
    ConfigSetting(
        dest="devicetrees",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Devicetree(s) to be used by the booting kernel",
        compat_names=("Devicetree",),
    ),
    ConfigSetting(
        dest="splash",
        section="Content",
        parse=config_make_path_parser(required=False, absolute=True),
        help="Splash screen image to be used by the booting kernel",
    ),
    ConfigSetting(
        dest="kernel_command_line",
        metavar="OPTIONS",
        section="Content",
        parse=config_make_list_parser(delimiter=" "),
        help="Set the kernel command line (only bootable images)",
    ),
    ConfigSetting(
        dest="kernel_modules_include",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(
            delimiter=",",
            parse=parse_kernel_module_filter_regexp,
        ),
        help="Include the specified kernel modules in the image",
    ),
    ConfigSetting(
        dest="kernel_modules_exclude",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(
            delimiter=",",
            parse=parse_kernel_module_filter_regexp,
        ),
        help="Exclude the specified kernel modules from the image",
    ),
    ConfigSetting(
        dest="kernel_modules_include",
        name="KernelModules",
        long="--kernel-modules",
        metavar="GLOB",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Include/exclude the specified kernel modules in the image",
    ),
    ConfigSetting(
        dest="kernel_modules_include_host",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="Include the currently loaded modules on the host in the image",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        default=True,
        help="When building a bootable image, add an extra initrd containing the kernel modules",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd_include",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(
            delimiter=",",
            parse=parse_kernel_module_filter_regexp,
        ),
        help="When building a kernel modules initrd, include the specified kernel modules",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd_exclude",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(
            delimiter=",",
            parse=parse_kernel_module_filter_regexp,
        ),
        help="When building a kernel modules initrd, exclude the specified kernel modules",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd_include",
        name="KernelInitrdModules",
        long="--kernel-initrd-modules",
        metavar="GLOB",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Include/exclude modules in the initrd",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd_include_host",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="When building a kernel modules initrd, include the currently loaded modules "
        "on the host in the image",
    ),
    ConfigSetting(
        dest="firmware_include",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(
            delimiter=",",
            parse=parse_kernel_module_filter_regexp,
        ),
        help="Include the specified firmware in the image",
    ),
    ConfigSetting(
        dest="firmware_exclude",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(
            delimiter=",",
            parse=parse_kernel_module_filter_regexp,
        ),
        help="Exclude the specified firmware from the image",
    ),
    ConfigSetting(
        dest="firmware_include",
        name="FirmwareFiles",
        long="--firmware-files",
        metavar="GLOB",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Include/exclude the specified firmware in the image",
    ),
    ConfigSetting(
        dest="locale",
        section="Content",
        parse=config_parse_string,
        help="Set the system locale",
    ),
    ConfigSetting(
        dest="locale_messages",
        metavar="LOCALE",
        section="Content",
        parse=config_parse_string,
        help="Set the messages locale",
    ),
    ConfigSetting(
        dest="keymap",
        metavar="KEYMAP",
        section="Content",
        parse=config_parse_string,
        help="Set the system keymap",
    ),
    ConfigSetting(
        dest="timezone",
        metavar="TIMEZONE",
        section="Content",
        parse=config_parse_string,
        help="Set the system timezone",
    ),
    ConfigSetting(
        dest="hostname",
        metavar="HOSTNAME",
        section="Content",
        parse=config_parse_string,
        help="Set the system hostname",
    ),
    ConfigSetting(
        dest="root_password",
        metavar="PASSWORD",
        section="Content",
        parse=config_parse_root_password,
        path_suffixes=("rootpw",),
        path_read_text=True,
        path_secret=True,
        help="Set the password for root",
    ),
    ConfigSetting(
        dest="root_shell",
        metavar="SHELL",
        section="Content",
        parse=config_parse_string,
        help="Set the shell for root",
    ),
    ConfigSetting(
        dest="machine_id",
        metavar="MACHINE_ID",
        section="Content",
        parse=config_parse_uuid,
        path_suffixes=("machine-id",),
        path_read_text=True,
        help="Set the machine ID to use",
    ),
    ConfigSetting(
        dest="autologin",
        short="-a",
        const=True,
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="Enable root autologin",
    ),
    ConfigSetting(
        dest="make_initrd",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="Make sure the image can be used as an initramfs",
    ),
    ConfigSetting(
        dest="ssh",
        section="Content",
        parse=config_make_enum_parser_with_boolean(Ssh, yes=Ssh.always, no=Ssh.never),
        default=Ssh.auto,
        choices=Ssh.choices(),
        help="Set up SSH access from the host to the final image via 'mkosi ssh'",
    ),
    ConfigSetting(
        dest="selinux_relabel",
        name="SELinuxRelabel",
        metavar="FEATURE",
        section="Content",
        parse=config_parse_feature,
        help="Specify whether to relabel all files with setfiles",
    ),
    # Validation section
    ConfigSetting(
        dest="secure_boot",
        metavar="BOOL",
        section="Validation",
        parse=config_parse_boolean,
        help="Sign the resulting kernel/initrd image for UEFI SecureBoot",
    ),
    ConfigSetting(
        dest="secure_boot_auto_enroll",
        metavar="BOOL",
        section="Validation",
        parse=config_parse_boolean,
        default=True,
        help="Automatically enroll the secureboot signing key on first boot",
    ),
    ConfigSetting(
        dest="secure_boot_key",
        metavar="KEY",
        section="Validation",
        parse=config_parse_key,
        path_suffixes=("key",),
        help="UEFI SecureBoot private key",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="secure_boot_key_source",
        section="Validation",
        metavar="SOURCE[:ENGINE]",
        parse=config_parse_key_source,
        default=KeySource(type=KeySourceType.file),
        help="The source to use to retrieve the secure boot signing key",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="secure_boot_certificate",
        metavar="PATH",
        section="Validation",
        parse=config_parse_certificate,
        path_suffixes=("crt",),
        help="UEFI SecureBoot certificate in X509 format",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="secure_boot_certificate_source",
        section="Validation",
        metavar="SOURCE[:PROVIDER]",
        parse=config_parse_certificate_source,
        default=CertificateSource(type=CertificateSourceType.file),
        help="The source to use to retrieve the secure boot signing certificate",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="secure_boot_sign_tool",
        section="Validation",
        parse=config_make_enum_parser(SecureBootSignTool),
        default=SecureBootSignTool.auto,
        choices=SecureBootSignTool.choices(),
        help="Tool to use for signing PE binaries for secure boot",
    ),
    ConfigSetting(
        dest="verity",
        section="Validation",
        metavar="FEATURE",
        parse=config_make_enum_parser_with_boolean(Verity, yes=Verity.signed, no=Verity.disabled),
        default=Verity.auto,
        choices=Verity.values(),
        help="Configure whether to enforce or disable verity partitions for disk images",
    ),
    ConfigSetting(
        dest="verity_key",
        metavar="KEY",
        section="Validation",
        parse=config_parse_key,
        path_suffixes=("key",),
        help="Private key for signing verity signature",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="verity_key_source",
        section="Validation",
        metavar="SOURCE[:ENGINE]",
        parse=config_parse_key_source,
        default=KeySource(type=KeySourceType.file),
        help="The source to use to retrieve the verity signing key",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="verity_certificate",
        metavar="PATH",
        section="Validation",
        parse=config_parse_certificate,
        path_suffixes=("crt",),
        help="Certificate for signing verity signature in X509 format",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="verity_certificate_source",
        section="Validation",
        metavar="SOURCE[:PROVIDER]",
        parse=config_parse_certificate_source,
        default=CertificateSource(type=CertificateSourceType.file),
        help="The source to use to retrieve the verity signing certificate",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="sign_expected_pcr",
        metavar="FEATURE",
        section="Validation",
        parse=config_parse_feature,
        help="Measure the components of the unified kernel image (UKI) and "
        "embed the PCR signature into the UKI",
    ),
    ConfigSetting(
        dest="sign_expected_pcr_key",
        metavar="KEY",
        section="Validation",
        parse=config_parse_key,
        path_suffixes=("key",),
        help="Private key for signing expected PCR signature",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="sign_expected_pcr_key_source",
        section="Validation",
        metavar="SOURCE[:ENGINE]",
        parse=config_parse_key_source,
        default=KeySource(type=KeySourceType.file),
        help="The source to use to retrieve the expected PCR signing key",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="sign_expected_pcr_certificate",
        metavar="PATH",
        section="Validation",
        parse=config_parse_certificate,
        path_suffixes=("crt",),
        help="Certificate for signing expected PCR signature in X509 format",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="sign_expected_pcr_certificate_source",
        section="Validation",
        metavar="SOURCE[:PROVIDER]",
        parse=config_parse_certificate_source,
        default=CertificateSource(type=CertificateSourceType.file),
        help="The source to use to retrieve the expected PCR signing certificate",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="passphrase",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(required=False, secret=True),
        path_suffixes=("passphrase",),
        help="Path to a file containing the passphrase to use when LUKS encryption is selected",
    ),
    ConfigSetting(
        dest="checksum",
        metavar="BOOL",
        section="Validation",
        parse=config_parse_boolean,
        default_factory=lambda ns: True if ns["sign"] else False,
        default_factory_depends=("sign",),
        help="Write SHA256SUMS file",
    ),
    ConfigSetting(
        dest="sign",
        metavar="BOOL",
        section="Validation",
        parse=config_parse_boolean,
        help="Write and sign SHA256SUMS file",
    ),
    ConfigSetting(
        dest="key",
        section="Validation",
        help="GPG key to use for signing",
    ),
    ConfigSetting(
        name="OpenPGPTool",
        dest="openpgp_tool",
        section="Validation",
        default="gpg",
        help="OpenPGP implementation to use for signing",
    ),
    # Build section
    ConfigSetting(
        dest="tools_tree",
        metavar="PATH",
        section="Build",
        parse=config_make_path_parser(constants=("default",)),
        path_suffixes=("tools",),
        help="Look up programs to execute inside the given tree",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="tools_tree_distribution",
        section="Build",
        parse=config_make_enum_parser(Distribution),
        match=config_make_enum_matcher(Distribution),
        choices=Distribution.choices(),
        default_factory=config_default_tools_tree_distribution,
        help="Set the distribution to use for the default tools tree",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_release",
        metavar="RELEASE",
        section="Build",
        parse=config_parse_string,
        match=config_make_string_matcher(),
        default_factory_depends=("tools_tree_distribution",),
        default_factory=(
            lambda ns: d.installer.default_release() if (d := ns["tools_tree_distribution"]) else None
        ),
        help="Set the release to use for the default tools tree",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_profiles",
        long="--tools-tree-profile",
        metavar="PROFILE",
        section="Build",
        parse=config_make_list_parser(delimiter=","),
        choices=ToolsTreeProfile.values(),
        default=[str(s) for s in ToolsTreeProfile.default()],
        help="Which profiles to enable for the default tools tree",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_mirror",
        metavar="MIRROR",
        section="Build",
        default_factory_depends=("distribution", "mirror", "tools_tree_distribution"),
        default_factory=(
            lambda ns: ns["mirror"]
            if ns["mirror"] and ns["distribution"] == ns["tools_tree_distribution"]
            else None
        ),
        help="Set the mirror to use for the default tools tree",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_repositories",
        long="--tools-tree-repository",
        metavar="REPOS",
        section="Build",
        parse=config_make_list_parser(delimiter=","),
        help="Repositories to use for the default tools tree",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_sandbox_trees",
        long="--tools-tree-sandbox-tree",
        compat_names=("ToolsTreePackageManagerTrees",),
        compat_longs=("--tools-tree-package-manager-tree",),
        metavar="PATH",
        section="Build",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser(required=True)),
        help="Sandbox trees for the default tools tree",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_packages",
        long="--tools-tree-package",
        metavar="PACKAGE",
        section="Build",
        parse=config_make_list_parser(delimiter=","),
        help="Add additional packages to the default tools tree",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_package_directories",
        long="--tools-tree-package-directory",
        metavar="PATH",
        section="Build",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        help="Specify a directory containing extra tools tree packages",
        scope=SettingScope.tools,
    ),
    ConfigSetting(
        dest="tools_tree_certificates",
        metavar="BOOL",
        section="Build",
        parse=config_parse_boolean,
        help="Use certificates from the tools tree",
        default=True,
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="extra_search_paths",
        long="--extra-search-path",
        metavar="PATH",
        section="Build",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(exclude=["/usr"])),
        help="List of comma-separated paths to look for programs before looking in PATH",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="incremental",
        short="-i",
        const=Incremental.yes,
        section="Build",
        parse=config_make_enum_parser_with_boolean(Incremental, yes=Incremental.yes, no=Incremental.no),
        default=Incremental.no,
        help="Make use of and generate intermediary cache images",
        scope=SettingScope.universal,
        choices=Incremental.values(),
    ),
    ConfigSetting(
        dest="cacheonly",
        long="--cache-only",
        name="CacheOnly",
        section="Build",
        parse=config_make_enum_parser_with_boolean(Cacheonly, yes=Cacheonly.always, no=Cacheonly.auto),
        default=Cacheonly.auto,
        help="Only use the package cache when installing packages",
        choices=Cacheonly.choices(),
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="sandbox_trees",
        long="--sandbox-tree",
        compat_names=("PackageManagerTrees",),
        compat_longs=("--package-manager-tree",),
        metavar="PATH",
        section="Build",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser(required=True)),
        help="Use a sandbox tree to configure the various tools that mkosi executes",
        path_suffixes=("sandbox", "sandbox.tar", "pkgmngr", "pkgmngr.tar"),
        scope=SettingScope.universal,
        tools=True,
    ),
    ConfigSetting(
        dest="workspace_dir",
        long="--workspace-directory",
        compat_longs=("--workspace-dir",),
        metavar="DIR",
        name="WorkspaceDirectory",
        section="Build",
        parse=config_make_path_parser(required=False),
        help="Workspace directory",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="cache_dir",
        long="--cache-directory",
        compat_longs=("--cache-dir",),
        metavar="PATH",
        name="CacheDirectory",
        section="Build",
        parse=config_make_path_parser(required=False),
        path_suffixes=("cache",),
        help="Incremental cache directory",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="cache_key",
        metavar="KEY",
        section="Build",
        parse=config_parse_string,
        help="Cache key to use within cache directory",
        default="&d~&r~&a~&I",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="package_cache_dir",
        long="--package-cache-directory",
        compat_longs=("--package-cache-dir",),
        metavar="PATH",
        name="PackageCacheDirectory",
        section="Build",
        parse=config_make_path_parser(required=False),
        path_suffixes=("pkgcache",),
        help="Package cache directory",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="build_dir",
        long="--build-directory",
        compat_longs=("--build-dir",),
        metavar="PATH",
        name="BuildDirectory",
        section="Build",
        parse=config_make_path_parser(required=False),
        path_suffixes=("builddir",),
        help="Path to use as persistent build directory",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="build_key",
        metavar="KEY",
        section="Build",
        parse=config_parse_string,
        help="Build key to use within build directory",
        default="&d~&r~&a",
        scope=SettingScope.inherit,
    ),
    ConfigSetting(
        dest="use_subvolumes",
        metavar="FEATURE",
        section="Build",
        parse=config_parse_feature,
        help="Use btrfs subvolumes for faster directory operations where possible",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="repart_offline",
        section="Build",
        parse=config_parse_boolean,
        help="Build disk images without using loopback devices",
        default=True,
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="history",
        metavar="BOOL",
        section="Build",
        parse=config_parse_boolean,
        help="Whether mkosi can store information about previous builds",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="build_sources",
        metavar="PATH",
        section="Build",
        parse=config_make_list_parser(
            delimiter=",",
            parse=make_tree_parser(
                absolute=False,
                required=True,
                directory=True,
            ),
        ),
        match=config_match_build_sources,
        default_factory=lambda ns: [ConfigTree(ns["directory"], None)] if ns["directory"] else [],
        help="Path for sources to build",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="build_sources_ephemeral",
        section="Build",
        parse=config_make_enum_parser_with_boolean(
            BuildSourcesEphemeral, yes=BuildSourcesEphemeral.yes, no=BuildSourcesEphemeral.no
        ),
        default=BuildSourcesEphemeral.no,
        help="Make build sources ephemeral when running scripts",
        scope=SettingScope.multiversal,
        choices=BuildSourcesEphemeral.values(),
    ),
    ConfigSetting(
        dest="environment",
        short="-E",
        metavar="NAME[=VALUE]",
        section="Build",
        parse=config_make_dict_parser(delimiter=" ", parse=parse_environment, unescape=True),
        match=config_match_key_value,
        help="Set an environment variable when running scripts",
        tools=True,
    ),
    ConfigSetting(
        dest="environment_files",
        long="--env-file",
        metavar="PATH",
        section="Build",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        path_suffixes=("env",),
        help="Environment files to set when running scripts",
        tools=True,
    ),
    ConfigSetting(
        dest="with_tests",
        short="-T",
        const=False,
        section="Build",
        parse=config_parse_boolean,
        default=True,
        help="Do not run tests as part of build scripts, if supported",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="with_network",
        metavar="BOOL",
        section="Build",
        parse=config_parse_boolean,
        help="Run build and postinst scripts with network access (instead of private network)",
        scope=SettingScope.universal,
    ),
    ConfigSetting(
        dest="proxy_url",
        section="Build",
        default_factory=config_default_proxy_url,
        default_factory_depends=("environment",),
        metavar="URL",
        help="Set the proxy to use",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="proxy_exclude",
        section="Build",
        metavar="HOST",
        parse=config_make_list_parser(delimiter=","),
        help="Don't use the configured proxy for the specified host(s)",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="proxy_peer_certificate",
        section="Build",
        parse=config_make_path_parser(),
        default_factory=config_default_proxy_peer_certificate,
        help="Set the proxy peer certificate",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="proxy_client_certificate",
        section="Build",
        parse=config_make_path_parser(secret=True),
        help="Set the proxy client certificate",
        scope=SettingScope.multiversal,
    ),
    ConfigSetting(
        dest="proxy_client_key",
        section="Build",
        default_factory=lambda ns: ns["proxy_client_certificate"],
        default_factory_depends=("proxy_client_certificate",),
        parse=config_make_path_parser(secret=True),
        help="Set the proxy client key",
        scope=SettingScope.multiversal,
    ),
    # Runtime section
    ConfigSetting(
        dest="nspawn_settings",
        name="NSpawnSettings",
        long="--settings",
        metavar="PATH",
        section="Runtime",
        parse=config_make_path_parser(),
        path_suffixes=("nspawn",),
        help="Add in .nspawn settings file",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="ephemeral",
        metavar="BOOL",
        section="Runtime",
        parse=config_parse_boolean,
        help=(
            "If specified, the container/VM is run with a temporary snapshot of the output "
            "image that is removed immediately when the container/VM terminates"
        ),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="credentials",
        long="--credential",
        metavar="NAME=VALUE",
        section="Runtime",
        parse=config_make_dict_parser(delimiter=" ", parse=parse_key_value, allow_paths=True, unescape=True),
        help="Pass a systemd credential to a systemd-nspawn container or a virtual machine",
        path_suffixes=("credentials",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="kernel_command_line_extra",
        metavar="OPTIONS",
        section="Runtime",
        parse=config_make_list_parser(delimiter=" "),
        help="Append extra entries to the kernel command line when booting the image",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="runtime_trees",
        long="--runtime-tree",
        metavar="SOURCE:[TARGET]",
        section="Runtime",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser(absolute=False)),
        help="Additional mounts to add when booting the image",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="runtime_size",
        metavar="SIZE",
        section="Runtime",
        parse=config_parse_bytes,
        help="Grow disk images to the specified size before booting them",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="runtime_network",
        section="Runtime",
        parse=config_make_enum_parser(Network),
        choices=Network.choices(),
        help="Set networking backend to use when booting the image",
        default=Network.user,
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="runtime_build_sources",
        metavar="BOOL",
        section="Runtime",
        parse=config_parse_boolean,
        help="Mount build sources and build directory in /work when booting the image",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="bind_user",
        metavar="BOOL",
        section="Runtime",
        parse=config_parse_boolean,
        help="Bind current user from host into container or virtual machine",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="unit_properties",
        long="--unit-property",
        metavar="PROPERTY",
        section="Runtime",
        parse=config_make_list_parser(delimiter=" ", unescape=True),
        help="Set properties on the scopes spawned by systemd-nspawn or systemd-run",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="ssh_key",
        metavar="PATH",
        section="Runtime",
        parse=config_make_path_parser(secret=True),
        path_suffixes=("key",),
        help="Private key for use with mkosi ssh in PEM format",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="ssh_certificate",
        metavar="PATH",
        section="Runtime",
        parse=config_make_path_parser(),
        path_suffixes=("crt",),
        help="Certificate for use with mkosi ssh in X509 format",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="vmm",
        name="VirtualMachineMonitor",
        section="Runtime",
        choices=Vmm.choices(),
        parse=config_make_enum_parser(Vmm),
        default=Vmm.qemu,
        help="Set the virtual machine monitor to use for mkosi vm",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="machine",
        metavar="NAME",
        section="Runtime",
        help="Set the machine name to use when booting the image",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="forward_journal",
        metavar="PATH",
        section="Runtime",
        parse=config_make_path_parser(required=False),
        help="Set the path used to store forwarded machine journals",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="sysupdate_dir",
        long="--sysupdate-directory",
        compat_longs=("--sysupdate-dir",),
        metavar="PATH",
        name="SysupdateDirectory",
        section="Runtime",
        parse=config_make_path_parser(),
        path_suffixes=("sysupdate",),
        help="Directory containing systemd-sysupdate transfer definitions",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="console",
        metavar="MODE",
        section="Runtime",
        parse=config_make_enum_parser(ConsoleMode),
        help="Configure the virtual machine console mode to use",
        default=ConsoleMode.native,
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="cpus",
        name="CPUs",
        metavar="CPUS",
        section="Runtime",
        parse=config_parse_number,
        default=1,
        help="Configure number of CPUs in virtual machine",
        compat_longs=("--qemu-smp",),
        compat_names=("QemuSmp",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="ram",
        name="RAM",
        metavar="BYTES",
        section="Runtime",
        parse=config_parse_bytes,
        default=parse_bytes("2G"),
        help="Configure guest's RAM size",
        compat_longs=("--qemu-mem",),
        compat_names=("QemuMem",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="maxmem",
        name="MaxMem",
        metavar="BYTES",
        section="Runtime",
        parse=config_parse_bytes,
        help="Configure guest's MaxMem size",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="kvm",
        name="KVM",
        metavar="FEATURE",
        section="Runtime",
        parse=config_parse_feature,
        help="Configure whether to use KVM or not",
        compat_longs=("--qemu-kvm",),
        compat_names=("QemuKvm",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="cxl",
        name="CXL",
        metavar="BOOLEAN",
        section="Runtime",
        parse=config_parse_boolean,
        help="Enable CXL device support",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="vsock",
        name="VSock",
        metavar="FEATURE",
        section="Runtime",
        parse=config_parse_feature,
        help="Configure whether to use vsock or not",
        compat_longs=("--qemu-vsock",),
        compat_names=("QemuVsock",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="vsock_cid",
        name="VSockCID",
        long="--vsock-cid",
        metavar="NUMBER|auto|hash",
        section="Runtime",
        parse=config_parse_vsock_cid,
        default=VsockCID.auto,
        help="Specify the vsock connection ID to use",
        compat_longs=("--qemu-vsock-cid",),
        compat_names=("QemuVsockConnectionId",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="tpm",
        name="TPM",
        metavar="FEATURE",
        section="Runtime",
        parse=config_parse_feature,
        help="Configure whether to use a virtual tpm or not",
        compat_longs=("--qemu-swtpm",),
        compat_names=("QemuSwtpm",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="removable",
        metavar="BOOLEAN",
        section="Runtime",
        parse=config_parse_boolean,
        help="Attach the image as a removable drive to the virtual machine",
        compat_longs=("--qemu-removable",),
        compat_names=("QemuRemovable",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="firmware",
        section="Runtime",
        parse=config_make_enum_parser(Firmware),
        default=Firmware.auto,
        help="Select the virtual machine firmware to use",
        choices=Firmware.choices(),
        compat_longs=("--qemu-firmware",),
        compat_names=("QemuFirmware",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="firmware_variables",
        metavar="PATH",
        section="Runtime",
        parse=config_make_path_parser(constants=("custom", "microsoft", "microsoft-mok"), required=False),
        help="Set the path to the firmware variables file to use",
        compat_longs=("--qemu-firmware-variables",),
        compat_names=("QemuFirmwareVariables",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="linux",
        metavar="PATH",
        section="Runtime",
        parse=config_parse_string,
        help="Specify the kernel to use for direct kernel boot",
        compat_longs=("--qemu-kernel",),
        compat_names=("QemuKernel",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="drives",
        long="--drive",
        metavar="DRIVE",
        section="Runtime",
        parse=config_make_list_parser(delimiter=" ", parse=parse_drive),
        help="Specify drive that mkosi should create and pass to the virtual machine",
        compat_longs=("--qemu-drive",),
        compat_names=("QemuDrives",),
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="qemu_args",
        metavar="ARGS",
        section="Runtime",
        parse=config_make_list_parser(delimiter=" ", unescape=True),
        # Suppress the command line option because it's already possible to pass qemu args as normal
        # arguments.
        help=argparse.SUPPRESS,
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="register",
        metavar="BOOL",
        section="Runtime",
        parse=config_parse_feature,
        default=ConfigFeature.auto,
        help="Register booted vm/container with systemd-machined",
        scope=SettingScope.main,
    ),
    ConfigSetting(
        dest="storage_target_mode",
        metavar="FEATURE",
        section="Runtime",
        parse=config_parse_feature,
        default=ConfigFeature.auto,
        help="Run systemd-storagetm as part of the serve verb",
        scope=SettingScope.main,
    ),
]
SETTINGS_LOOKUP_BY_NAME = {name: s for s in SETTINGS for name in [s.name, *s.compat_names]}
SETTINGS_LOOKUP_BY_DEST = {s.dest: s for s in SETTINGS}
SETTINGS_LOOKUP_BY_OPTION = {
    name: s
    for s in SETTINGS
    for name in [s.long, *s.compat_longs, s.short] if name
}  # fmt: skip
SETTINGS_LOOKUP_BY_SPECIFIER = {s.specifier: s for s in SETTINGS if s.specifier}

MATCHES = (
    Match(
        name="PathExists",
        match=match_path_exists,
    ),
    Match(
        name="SystemdVersion",
        match=match_systemd_version,
    ),
    Match(
        name="HostArchitecture",
        match=match_host_architecture,
    ),
    Match(
        name="Image",
        match=match_image,
    ),
)

MATCH_LOOKUP = {m.name: m for m in MATCHES}

SPECIFIERS = (
    Specifier(
        char="C",
        callback=lambda ns, config: os.fspath(config.resolve().parent),
    ),
    Specifier(
        char="P",
        callback=lambda ns, config: os.fspath(Path.cwd()),
    ),
    Specifier(
        char="D",
        callback=lambda ns, config: os.fspath(ns["directory"].resolve()),
    ),
    Specifier(
        char="F",
        callback=lambda ns, config: ns["distribution"].installer.filesystem(),
        depends=("distribution",),
    ),
    Specifier(
        char="I",
        callback=lambda ns, config: ns["image"],
    ),
)

SPECIFIERS_LOOKUP_BY_CHAR = {s.char: s for s in SPECIFIERS}

# This regular expression can be used to split "AutoBump" -> ["Auto", "Bump"]
# and "NSpawnSettings" -> ["NSpawn", "Settings"]
# The first part (?<=[a-z]) is a positive look behind for a lower case letter
# and (?=[A-Z]) is a lookahead assertion matching an upper case letter but not
# consuming it
FALLBACK_NAME_TO_DEST_SPLITTER = re.compile("(?<=[a-z])(?=[A-Z])")


def create_argument_parser(chdir: bool = True) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mkosi",
        description="Build Bespoke OS Images",
        # the synopsis below is supposed to be indented by two spaces
        usage="\n  "
        + textwrap.dedent("""\
              mkosi [options…] {b}init{e}
                mkosi [options…] {b}summary{e}
                mkosi [options…] {b}cat-config{e}
                mkosi [options…] {b}build{e}         [-- command line…]
                mkosi [options…] {b}shell{e}         [-- command line…]
                mkosi [options…] {b}boot{e}          [-- nspawn settings…]
                mkosi [options…] {b}vm{e}            [-- vmm parameters…]
                mkosi [options…] {b}ssh{e}           [-- command line…]
                mkosi [options…] {b}journalctl{e}    [-- command line…]
                mkosi [options…] {b}coredumpctl{e}   [-- command line…]
                mkosi [options…] {b}sysupdate{e}     [-- command line…]
                mkosi [options…] {b}sandbox{e}       [-- command line…]
                mkosi [options…] {b}dependencies{e}  [-- options…]
                mkosi [options…] {b}clean{e}
                mkosi [options…] {b}serve{e}
                mkosi [options…] {b}burn{e}          [device]
                mkosi [options…] {b}bump{e}
                mkosi [options…] {b}genkey{e}
                mkosi [options…] {b}documentation{e} [manual]
                mkosi [options…] {b}completion{e}    [shell]
                mkosi [options…] {b}help{e}
                mkosi -h | --help
                mkosi --version
        """).format(b=Style.bold, e=Style.reset),
        add_help=False,
        allow_abbrev=False,
        argument_default=argparse.SUPPRESS,
        formatter_class=CustomHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + __version__,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-f",
        "--force",
        action="count",
        dest="force",
        default=0,
        help="Remove existing image file before operation",
    )
    parser.add_argument(
        "-C",
        "--directory",
        type=parse_chdir if chdir else str,
        default=Path.cwd(),
        help="Change to specified directory before doing anything",
        metavar="PATH",
    )
    parser.add_argument(
        "--debug",
        help="Turn on debugging output",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--debug-shell",
        help="Spawn an interactive shell in the image if a chroot command fails",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--debug-workspace",
        help="When an error occurs, the workspace directory will not be deleted",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--debug-sandbox",
        help="Run mkosi-sandbox with strace",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--no-pager",
        action="store_false",
        dest="pager",
        default=True,
        help="Enable paging for long output",
    )
    parser.add_argument(
        "--genkey-valid-days",
        metavar="DAYS",
        help="Number of days keys should be valid when generating keys",
        default="730",
    )
    parser.add_argument(
        "--genkey-common-name",
        metavar="CN",
        help="Template for the CN when generating keys",
        default=f"mkosi of {getpass.getuser()}",
    )
    parser.add_argument(
        "-B",
        "--auto-bump",
        help="Automatically bump image version after building",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--doc-format",
        help="The format to show documentation in",
        default=DocFormat.auto,
        type=DocFormat,
        choices=list(DocFormat),
    )
    parser.add_argument(
        "--json",
        help="Show summary as JSON",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-w",
        "--wipe-build-dir",
        help="Remove the build directory before building the image",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-R",
        "--rerun-build-scripts",
        help="Run build scripts even if the image is not rebuilt",
        action="store_true",
        default=False,
    )
    # These can be removed once mkosi v15 is available in LTS distros and compatibility with <= v14
    # is no longer needed in build infrastructure (e.g.: OBS).
    parser.add_argument(
        "--nspawn-keep-unit",
        nargs=0,
        action=IgnoreAction,
    )
    for arg in ("--default", "--cache", "--runtime-scratch"):
        parser.add_argument(arg, action=IgnoreAction)

    parser.add_argument(
        "verb",
        type=Verb,
        nargs="?",
        choices=list(Verb),
        default=Verb.build,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "cmdline",
        nargs="*",
        help=argparse.SUPPRESS,
        default=[],
    )
    parser.add_argument(
        "-h",
        "--help",
        action=PagerHelpAction,
        help=argparse.SUPPRESS,
    )

    last_section: Optional[str] = None

    for s in SETTINGS:
        if s.section != last_section:
            group = parser.add_argument_group(f"{s.section} configuration options")
            last_section = s.section

        if s.short and s.const is not None:
            group.add_argument(  # type: ignore
                s.short,
                metavar="",
                dest=s.dest,
                const=s.const,
                help="",
                action="store_const",
                default=argparse.SUPPRESS,
            )

        for long in [s.long, *s.compat_longs]:
            opts = [s.short, long] if s.short and long == s.long and s.const is None else [long]

            group.add_argument(  # type: ignore
                *opts,
                dest=s.dest,
                choices=s.choices,
                metavar=s.metavar,
                help=s.help if long == s.long else argparse.SUPPRESS,
                action=ConfigAction,
                # TODO: Remove once https://github.com/openSUSE/obs-build/pull/1059 is deployed in OBS.
                nargs="?" if s.dest == "checksum" else None,
                const="yes" if s.dest == "checksum" else None,
            )

    return parser


def resolve_deps(images: Sequence[Config], include: Sequence[str]) -> list[Config]:
    graph = {config.image: config.dependencies for config in images}

    if any((missing := i) not in graph for i in include):
        die(f"No image found with name {missing}")

    deps = set()
    queue = [*include]

    while queue:
        if (image := queue.pop(0)) not in deps:
            deps.add(image)
            queue.extend(graph[image])

    images = [config for config in images if config.image in deps]

    graph = {config.image: config.dependencies for config in images}

    try:
        order = list(graphlib.TopologicalSorter(graph).static_order())
    except graphlib.CycleError as e:
        die(f"Image dependency cycle detected: {' => '.join(e.args[1])}")

    return sorted(images, key=lambda i: order.index(i.image))


class ConfigAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        assert option_string is not None

        # For options that have the same dest, try to figure out the right
        # option by matching the option name
        s = SETTINGS_LOOKUP_BY_OPTION[self.option_strings[0]]

        if values is None or isinstance(values, str):
            values = [values]

        for v in values:
            assert isinstance(v, str) or v is None
            parsed_value = s.parse(v, getattr(namespace, self.dest, None))
            if parsed_value is None:
                setattr(namespace, f"{s.dest}_was_none", True)
            setattr(namespace, s.dest, parsed_value)


class ParseContext:
    def __init__(self, resources: Path = Path("/")) -> None:
        self.resources = resources
        # We keep two namespaces around, one for the settings specified on the CLI and one for
        # the settings specified in configuration files. This is required to implement both [Match]
        # support and the behavior where settings specified on the CLI always override settings
        # specified in configuration files.
        self.cli: dict[str, Any] = {}
        self.config: dict[str, Any] = {"files": []}
        self.defaults: dict[str, Any] = {}
        # Compare inodes instead of paths so we can't get tricked by bind mounts and such.
        self.includes: set[tuple[int, int]] = set()

    def setting_prohibited(self, setting: ConfigSetting[T]) -> bool:
        image = self.config["image"]

        return (
            (not setting.tools and image == "tools")
            or (setting.scope.is_main_setting() and image != "main")
            or (setting.scope == SettingScope.universal and image not in ("main", "tools"))
        )

    def expand_specifiers(self, text: str, path: Path) -> str:
        percent = False
        result: list[str] = []

        for c in text:
            if percent:
                percent = False

                if c == "%":
                    result += "%"
                elif setting := SETTINGS_LOOKUP_BY_SPECIFIER.get(c):
                    if (v := self.finalize_value(setting)) is None:
                        logging.warning(
                            f"{path.absolute()}: Setting {setting.name} specified by specifier '%{c}' "
                            f"in {text} is not yet set, ignoring"
                        )
                        continue

                    result += str(v)
                elif specifier := SPECIFIERS_LOOKUP_BY_CHAR.get(c):
                    # Some specifier methods might want to access the image name or directory mkosi was
                    # invoked in so let's make sure those are available.
                    specifierns = {
                        "image": self.config["image"],
                        "directory": self.config["directory"],
                    }

                    for d in specifier.depends:
                        setting = SETTINGS_LOOKUP_BY_DEST[d]

                        if (v := self.finalize_value(setting)) is None:
                            logging.warning(
                                f"{path.absolute()}: Setting {setting.name} which specifier '%{c}' in "
                                f"{text} depends on is not yet set, ignoring"
                            )
                            break

                        specifierns[d] = v
                    else:
                        result += specifier.callback(specifierns, path)
                else:
                    logging.warning(f"{path.absolute()}: Unknown specifier '%{c}' found in {text}, ignoring")
            elif c == "%":
                percent = True
            else:
                result += c

        if percent:
            result += "%"

        return "".join(result)

    def parse_new_includes(self) -> None:
        # Parse any includes that were added after yielding.
        for p in self.cli.get("include", []) + self.config.get("include", []):
            for c in BUILTIN_CONFIGS:
                if p == Path(c):
                    path = self.resources / c
                    break
            else:
                path = p

            st = path.stat()

            if (st.st_dev, st.st_ino) in self.includes:
                continue

            self.includes.add((st.st_dev, st.st_ino))

            if any(p == Path(c) for c in BUILTIN_CONFIGS):
                context = ParseContext(self.resources)

                context.config["image"] = "main"
                context.config["directory"] = path

                with chdir(path):
                    context.parse_config_one(path)

                config = Config.from_dict(context.finalize())

                make_executable(
                    *config.configure_scripts,
                    *config.clean_scripts,
                    *config.sync_scripts,
                    *config.prepare_scripts,
                    *config.build_scripts,
                    *config.postinst_scripts,
                    *config.finalize_scripts,
                    *config.postoutput_scripts,
                )

            with chdir(path if path.is_dir() else Path.cwd()):
                self.parse_config_one(path if path.is_file() else Path.cwd(), parse_profiles=path.is_dir())

    def finalize_value(self, setting: ConfigSetting[T]) -> Optional[T]:
        # If a value was specified on the CLI, it always takes priority. If the setting is a collection of
        # values, we merge the value from the CLI with the value from the configuration, making sure that the
        # value from the CLI always takes priority.
        if (v := cast(Optional[T], self.cli.get(setting.dest))) is not None:
            cfg_value = self.config.get(setting.dest)
            # We either have no corresponding value in the config files
            # or the values was assigned the empty string on the CLI
            # and should thus be treated as a reset and override of the value from the config file.
            if cfg_value is None or self.cli.get(f"{setting.dest}_was_none", False):
                return v

            # The instance asserts are pushed down to help mypy/pylance narrow the types.
            # Mypy still cannot properly infer that the merged collections conform to T
            # so we ignore the return-value error for it.
            if isinstance(v, list):
                assert isinstance(cfg_value, type(v))
                return cfg_value + v  # type: ignore[return-value]
            elif isinstance(v, dict):
                assert isinstance(cfg_value, type(v))
                return cfg_value | v  # type: ignore[return-value]
            elif isinstance(v, set):
                assert isinstance(cfg_value, type(v))
                return cfg_value | v  # type: ignore[return-value]
            else:
                return v

        # If the setting was assigned the empty string on the CLI, we don't use any value configured in the
        # configuration file. Additionally, if the setting is a collection of values, we won't use any
        # default value either if the setting is set to the empty string on the command line.

        if (
            setting.dest not in self.cli
            and setting.dest in self.config
            and (v := cast(Optional[T], self.config[setting.dest])) is not None
        ):
            return v

        # If the type is a collection or optional and the setting was set explicitly, don't use the default
        # value.
        field = Config.fields().get(setting.scope.removeprefix(setting.dest))
        origin = typing.get_origin(field.type) if field else None
        args = typing.get_args(field.type) if field else []
        if (
            (setting.dest in self.cli or setting.dest in self.config)
            and field
            and (origin in (dict, list, str) or (origin is typing.Union and type(None) in args))
        ):
            default = setting.parse(None, None)
        elif setting.dest in self.defaults:
            default = self.defaults[setting.dest]
        elif setting.default_factory:
            # Some default factory methods want to access the image name or directory mkosi was invoked in so
            # let's make sure those are available.
            factoryns = {
                "image": self.config["image"],
                "directory": self.config["directory"],
            }

            # To determine default values, we need the final values of various settings in a namespace
            # object, but we don't want to copy the final values into the config namespace object just yet so
            # we create a new namespace object instead.
            factoryns |= {
                d: self.finalize_value(SETTINGS_LOOKUP_BY_DEST[d]) for d in setting.default_factory_depends
            }

            default = setting.default_factory(factoryns)
        elif setting.default is not None:
            default = setting.default
        else:
            default = setting.parse(None, None)

        self.defaults[setting.dest] = default

        return default

    def match_config(self, path: Path, asserts: bool = False) -> bool:
        condition_triggered: Optional[bool] = None
        match_triggered: Optional[bool] = None
        skip = False

        # If the config file does not exist, we assume it matches so that we look at the other files in the
        # directory as well (mkosi.conf.d/ and extra files).
        if not path.exists():
            return True

        sections = ("Assert", "TriggerAssert") if asserts else ("Match", "TriggerMatch")

        for section, k, v in parse_ini(path, only_sections=sections):
            if not k and not v:
                if condition_triggered is False:
                    if section == "Assert":
                        die(f"{path.absolute()}: Trigger condition in [Assert] section was not satisfied")
                    elif section == "Match":
                        return False

                if section in ("TriggerAssert", "TriggerMatch"):
                    match_triggered = bool(match_triggered) or condition_triggered is not False

                condition_triggered = None
                skip = False
                continue

            if skip:
                continue

            raw = v
            trigger = v.startswith("|")
            v = v.removeprefix("|")
            negate = v.startswith("!")
            v = v.removeprefix("!")

            v = self.expand_specifiers(v, path)

            if s := SETTINGS_LOOKUP_BY_NAME.get(k):
                if not s.match:
                    die(f"{path.absolute()}: {k} cannot be used in [{section}]")

                if s.scope == SettingScope.main and self.config["image"] != "main":
                    die(f"{path.absolute()}: {k} cannot be matched on outside of the main image")

                if k != s.name:
                    logging.warning(
                        f"{path.absolute()}: Setting {k} is deprecated, please use {s.name} instead."
                    )

                # If we encounter a setting that has not been explicitly configured yet, we assign the
                # default value first so that we can match on default values for settings.
                if (value := self.finalize_value(s)) is None:
                    result = False
                else:
                    result = s.match(v, value)

            elif m := MATCH_LOOKUP.get(k):
                result = m.match(self.config["image"], v)
            else:
                die(f"{path.absolute()}: {k} cannot be used in [{section}]")

            if negate:
                result = not result
            if not trigger and not result:
                if section.startswith("Trigger"):
                    skip = True
                    condition_triggered = False
                    continue

                if asserts:
                    die(f"{path.absolute()}: {k}={raw} in [Assert] section was not satisfied")

                return False
            if trigger:
                condition_triggered = bool(condition_triggered) or result

        if match_triggered is False and asserts:
            die(f"{path.absolute()}: None of the [TriggerAssert] sections was satisfied")

        return match_triggered is not False

    def parse_config_one(self, path: Path, parse_profiles: bool = False, parse_local: bool = False) -> bool:
        s: Optional[ConfigSetting[object]]  # Hint to mypy that we might assign None
        assert path.is_absolute()

        extras = path.is_dir()
        if extras:
            path /= "mkosi.conf"

        if not self.match_config(path):
            return False

        self.match_config(path, asserts=True)

        if extras:
            if parse_local:
                for localpath in (
                    *([p] if (p := path.parent / "mkosi.local").is_dir() else []),
                    *([p] if (p := path.parent / "mkosi.local.conf").is_file() else []),
                ):
                    with chdir(localpath if localpath.is_dir() else Path.cwd()):
                        self.parse_config_one(localpath if localpath.is_file() else Path.cwd())

                    # Local configuration should override other file based
                    # configuration but not the CLI itself so move the finalized
                    # values to the CLI namespace.
                    for s in SETTINGS:
                        if s.dest in self.config:
                            self.cli[s.dest] = self.finalize_value(s)
                            del self.config[s.dest]

            for s in SETTINGS:
                image = self.config["image"]

                if self.setting_prohibited(s):
                    continue

                for f in s.path_suffixes:
                    f = f"mkosi.{f}"

                    extra = parse_path(
                        f,
                        secret=s.path_secret,
                        required=False,
                        resolve=False,
                        expanduser=False,
                        expandvars=False,
                    )
                    if extra.exists():
                        self.config[s.dest] = s.parse(
                            file_run_or_read(extra).rstrip("\n") if s.path_read_text else f,
                            self.config.get(s.dest),
                        )

                for f in s.recursive_path_suffixes:
                    f = f"mkosi.{f}"

                    recursive_extras = parse_paths_from_directory(
                        f,
                        secret=s.path_secret,
                        required=False,
                        resolve=False,
                        expanduser=False,
                        expandvars=False,
                    )
                    for e in recursive_extras:
                        if e.exists():
                            self.config[s.dest] = s.parse(os.fspath(e), self.config.get(s.dest))

        if path.exists():
            logging.debug(f"Loading configuration file {path}")
            files = self.config["files"]
            files += [path]

            for section, k, v in parse_ini(
                path,
                only_sections={s.section for s in SETTINGS} | {"Host"},
            ):
                if not k and not v:
                    continue

                name = k.removeprefix("@")
                if name != k:
                    logging.warning(
                        f"{path.absolute()}: The '@' specifier is deprecated, please use {name} instead of "
                        f"{k}"
                    )

                if not (s := SETTINGS_LOOKUP_BY_NAME.get(name)):
                    die(f"{path.absolute()}: Unknown setting {name}")

                image = self.config["image"]

                if self.setting_prohibited(s):
                    die(f"{path.absolute()}: Setting {name} cannot be configured in {image} image")

                if section != s.section:
                    logging.warning(
                        f"{path.absolute()}: Setting {name} should be configured in [{s.section}], not "
                        f"[{section}]."
                    )

                if name != s.name:
                    logging.warning(
                        f"{path.absolute()}: Setting {name} is deprecated, please use {s.name} instead."
                    )

                v = self.expand_specifiers(v, path)

                self.config[s.dest] = s.parse(v, self.config.get(s.dest))
                self.parse_new_includes()

        if extras and (path.parent / "mkosi.conf.d").exists():
            for p in sorted((path.parent / "mkosi.conf.d").iterdir()):
                p = p.absolute()

                if p.is_dir() or p.suffix == ".conf":
                    with chdir(p if p.is_dir() else Path.cwd()):
                        self.parse_config_one(p if p.is_file() else Path.cwd())

        if parse_profiles:
            for profile in self.finalize_value(SETTINGS_LOOKUP_BY_DEST["profiles"]) or []:
                for p in (Path(profile), Path(f"{profile}.conf")):
                    p = Path.cwd() / "mkosi.profiles" / p
                    if p.exists():
                        with chdir(p if p.is_dir() else Path.cwd()):
                            self.parse_config_one(p if p.is_file() else Path.cwd())

        return True

    def finalize(self) -> dict[str, Any]:
        ns = copy.deepcopy(self.config)

        # After we've finished parsing the configuration, we'll have values in both namespaces (context.cli,
        # context.config). To be able to parse the values from a single namespace, we merge the final values
        # of each setting into one namespace.
        for s in SETTINGS:
            ns[s.dest] = copy.deepcopy(self.finalize_value(s))

        return ns


def want_new_history(args: Args) -> bool:
    if args.directory is None:
        return False

    if not args.verb.needs_build():
        return False

    if args.rerun_build_scripts:
        return False

    if args.verb != Verb.build and args.force == 0:
        return False

    return True


def have_history(args: Args) -> bool:
    if want_new_history(args):
        return False

    if args.directory is None:
        return False

    if args.verb in (Verb.clean, Verb.sandbox, Verb.latest_snapshot):
        return False

    if args.verb == Verb.summary and args.force > 0:
        return False

    if args.verb.needs_tools() and args.force > 0:
        return False

    if args.verb.needs_build() and args.force > 0:
        return False

    if args.verb == Verb.build and not args.rerun_build_scripts:
        return False

    return Path(".mkosi-private/history/latest.json").exists()


def finalize_default_tools(
    main: ParseContext,
    finalized: dict[str, Any],
    *,
    configdir: Optional[Path],
    resources: Path,
) -> Config:
    context = ParseContext(resources)

    for s in SETTINGS:
        if s.scope == SettingScope.multiversal:
            context.cli[s.dest] = copy.deepcopy(finalized[s.dest])
        elif s.scope == SettingScope.tools:
            # If the setting was specified on the CLI for the main config, we treat it as specified on the
            # CLI for the tools tree as well. Idem for config and defaults.
            dest = s.scope.removeprefix(s.dest)

            if s.dest in main.cli:
                ns = context.cli
                if f"{s.dest}_was_none" in main.cli:
                    ns[f"{dest}_was_none"] = main.cli[f"{s.dest}_was_none"]
            elif s.dest in main.config:
                ns = context.config
            else:
                ns = context.defaults

            ns[dest] = copy.deepcopy(finalized[s.dest])

    context.cli["output_format"] = OutputFormat.directory

    context.config |= {
        "image": "tools",
        "directory": finalized["directory"],
        "files": [],
    }

    context.config["environment"] = {
        name: finalized["environment"][name]
        for name in finalized.get("environment", {}).keys() & finalized.get("pass_environment", [])
    }

    if configdir and (p := configdir / "mkosi.tools.conf").exists():
        with chdir(p if p.is_dir() else Path.cwd()):
            context.parse_config_one(p, parse_profiles=p.is_dir(), parse_local=p.is_dir())

    with chdir(resources / "mkosi-tools"):
        context.parse_config_one(resources / "mkosi-tools", parse_profiles=True)

    return Config.from_dict(context.finalize())


def finalize_default_initrd(
    main: ParseContext,
    finalized: dict[str, Any],
    *,
    resources: Path,
) -> Config:
    context = ParseContext(resources)

    for s in SETTINGS:
        if s.scope in (SettingScope.universal, SettingScope.multiversal):
            context.cli[s.dest] = copy.deepcopy(finalized[s.dest])
        elif s.scope == SettingScope.inherit and s.dest in finalized:
            context.config[s.dest] = copy.deepcopy(finalized[s.dest])
        elif s.scope == SettingScope.initrd:
            # If the setting was specified on the CLI for the main config, we treat it as specified on the
            # CLI for the default initrd as well. Idem for config and defaults.
            dest = s.scope.removeprefix(s.dest)

            if s.dest in main.cli:
                ns = context.cli
                if f"{s.dest}_was_none" in main.cli:
                    ns[f"{dest}_was_none"] = main.cli[f"{s.dest}_was_none"]
            elif s.dest in main.config:
                ns = context.config
            else:
                ns = context.defaults

            ns[dest] = copy.deepcopy(finalized[s.dest])

    context.config |= {
        "image": "default-initrd",
        "directory": finalized["directory"],
        "files": [],
    }

    context.config["environment"] = {
        name: finalized["environment"][name]
        for name in finalized.get("environment", {}).keys() & finalized.get("pass_environment", [])
    }

    with chdir(resources / "mkosi-initrd"):
        context.parse_config_one(resources / "mkosi-initrd", parse_profiles=True)

    return Config.from_dict(context.finalize())


def finalize_configdir(directory: Optional[Path]) -> Optional[Path]:
    """Allow locating all mkosi configuration in a mkosi/ subdirectory
    instead of in the top-level directory of a git repository.
    """
    if directory is None:
        return None

    if not ((directory / "mkosi.conf").exists() or (directory / "mkosi.tools.conf").exists()) and (
        (directory / "mkosi/mkosi.conf").is_file() or (directory / "mkosi/mkosi.tools.conf").exists()
    ):
        return directory / "mkosi"

    return directory


def bump_image_version(configdir: Path) -> str:
    version_file = configdir / "mkosi.version"
    if os.access(version_file, os.X_OK):
        die(f"Cannot bump image version, '{version_file}' is executable")

    if version_file.exists():
        version = version_file.read_text().strip()
    else:
        version = None

    if (bump := configdir / "mkosi.bump").exists():
        with complete_step(f"Running bump script {bump}"):
            new_version = run([bump], stdout=subprocess.PIPE).stdout.strip()
    elif version is not None:
        v = version.split(".")

        try:
            v[-1] = str(int(v[-1]) + 1)
        except ValueError:
            v += ["2"]
            logging.warning("Last component of current version is not a decimal integer, appending '.2'")

        new_version = ".".join(v)
    else:
        new_version = "1"

    logging.info(f"Bumping version: '{none_to_na(version)}' → '{new_version}'")
    return new_version


def want_kernel(config: Config) -> bool:
    if config.output_format in (OutputFormat.uki, OutputFormat.esp):
        return False

    if config.bootable == ConfigFeature.disabled:
        return False

    if config.bootable == ConfigFeature.auto and (
        config.output_format == OutputFormat.cpio
        or config.output_format.is_extension_or_portable_image()
        or config.overlay
    ):
        return False

    return True


def want_default_initrd(config: Config) -> bool:
    if not want_kernel(config):
        return False

    if config.initrds:
        return False

    if config.bootable == ConfigFeature.auto and not any(
        config.distribution.installer.is_kernel_package(p)
        for p in itertools.chain(config.packages, config.volatile_packages)
    ):
        return False

    return True


def parse_config(
    argv: Sequence[str] = (),
    *,
    resources: Path = Path("/"),
) -> tuple[Args, Optional[Config], tuple[Config, ...]]:
    argv = list(argv)

    context = ParseContext(resources)

    # The "image" field does not directly map to a setting but is required to determine some default values
    # for settings, so let's set it on the config namespace immediately so it's available.
    context.config["image"] = "main"

    # First, we parse the command line arguments into a separate namespace.
    argparser = create_argument_parser()
    ns = argparse.Namespace()
    ns.__dict__ = context.cli
    argparser.parse_args(argv, ns)

    args = Args.from_namespace(context.cli)

    if args.debug:
        ARG_DEBUG.set(args.debug)
    if args.debug_shell:
        ARG_DEBUG_SHELL.set(args.debug_shell)
    if args.debug_sandbox:
        ARG_DEBUG_SANDBOX.set(args.debug_sandbox)

    if args.rerun_build_scripts and not args.verb.needs_build():
        die(f"--rerun-build-scripts cannot be used with the '{args.verb}' command")

    if args.rerun_build_scripts and args.force:
        die("--force cannot be used together with --rerun-build-scripts")

    if args.cmdline and not args.verb.supports_cmdline():
        die(f"Arguments after verb are not supported for the '{args.verb}' command")

    # If --debug was passed, apply it as soon as possible.
    if ARG_DEBUG.get():
        logging.getLogger().setLevel(logging.DEBUG)

    # Do the same for help.
    if args.verb == Verb.help:
        page(argparser.format_help(), context.cli["pager"])
        sys.exit(0)

    if not args.verb.needs_config():
        return args, None, ()

    if have_history(args):
        history = Config.from_partial_json(Path(".mkosi-private/history/latest.json").read_text())

        # If we're operating on a previously built image (vm, boot, shell, ...), we're not rebuilding the
        # image and the configuration of the latest build is available, we load the config that was used to
        # build the previous image from there instead of parsing configuration files, except for the Host
        # section settings which we allow changing without requiring a rebuild of the image.
        for s in SETTINGS:
            if s.section in ("Include", "Runtime"):
                history.pop(s.dest, None)
                continue

            if s.dest in context.cli and s.dest in history and context.cli[s.dest] != history[s.dest]:
                logging.warning(
                    f"Ignoring {s.long} from the CLI. Run with -f to rebuild the image with this setting"
                )

        context.cli |= history

    cli = copy.deepcopy(context.cli)

    # One of the specifiers needs access to the directory, so make sure it is available.
    context.config["directory"] = args.directory

    context.parse_new_includes()

    context.config["files"] = []

    configdir = finalize_configdir(args.directory)

    if (
        ((args.auto_bump and args.verb.needs_build()) or args.verb == Verb.bump)
        and context.cli.get("image_version") is None
        and configdir is not None
    ):
        context.cli["image_version"] = bump_image_version(configdir)

    # Parse the global configuration unless the user explicitly asked us not to.
    if configdir is not None:
        with chdir(configdir):
            context.parse_config_one(configdir, parse_profiles=True, parse_local=True)

    config = context.finalize()

    if config["history"] and want_new_history(args):
        Path(".mkosi-private/history").mkdir(parents=True, exist_ok=True)
        Path(".mkosi-private/history/latest.json").write_text(dump_json(Config.to_partial_dict(cli)))

    tools = None
    if config.get("tools_tree") == Path("default"):
        if in_box():
            config["tools_tree"] = Path(os.environ["MKOSI_DEFAULT_TOOLS_TREE_PATH"])
        else:
            tools = finalize_default_tools(context, config, configdir=configdir, resources=resources)
            config["tools_tree"] = tools.output_dir_or_cwd() / tools.output

    images = []

    # If Dependencies= was not explicitly specified on the CLI or in the configuration,
    # we want to default to all subimages. However, if a subimage has a [Match] section
    # and does not successfully match, we don't want to add it to the default dependencies.
    # To make this work, we can't use default_factory as it is evaluated too early, so
    # we check here to see if dependencies were explicitly provided and if not we gather
    # the list of default dependencies while we parse the subimages.
    dependencies: Optional[list[str]] = (
        None if "dependencies" in context.cli or "dependencies" in context.config else []
    )

    # For the subimages in mkosi.images/, we want settings that are marked as
    # "universal" to override whatever settings are specified in the subimage
    # configuration files. We achieve this by making it appear like these settings
    # were specified on the CLI by copying them to the CLI namespace. Any settings
    # that are not marked as "universal" are deleted from the CLI namespace.
    for s in SETTINGS:
        if s.scope in (SettingScope.universal, SettingScope.multiversal):
            context.cli[s.dest] = copy.deepcopy(config[s.dest])
        elif s.dest in context.cli:
            del context.cli[s.dest]

    todo = []
    if configdir is not None and (imagedir := configdir / "mkosi.images").exists():
        todo += sorted(imagedir.iterdir())

    for p in todo:
        p = p.absolute()

        if not p.is_dir() and not p.suffix == ".conf":
            continue

        name = p.name.removesuffix(".conf")
        if not name:
            die(f"{p} is not a valid image name")

        context.config = {
            "image": name,
            "directory": args.directory,
            "files": [],
        }

        # Settings that are marked as "inherit" are passed down to subimages but can
        # be overridden, so we copy these to the config namespace so that they'll be
        # overridden if the setting is explicitly configured by the subimage.
        for s in SETTINGS:
            if s.scope == SettingScope.inherit and s.dest in config:
                context.config[s.dest] = copy.deepcopy(config[s.dest])

        context.config["environment"] = {
            name: config["environment"][name]
            for name in config.get("pass_environment", {})
            if name in config.get("environment", {})
        }

        # Allow subimage configuration to include everything again.
        context.includes = set()
        context.defaults = {}

        with chdir(p if p.is_dir() else Path.cwd()):
            if not context.parse_config_one(
                p if p.is_file() else Path.cwd(),
                parse_profiles=p.is_dir(),
                parse_local=True,
            ):
                continue

        images += [context.finalize()]

        if dependencies is not None:
            dependencies += [name]

    if dependencies is not None:
        config["dependencies"] = dependencies

    main = Config.from_dict(config)
    subimages = [Config.from_dict(ns) for ns in images]

    if any(want_default_initrd(image) for image in subimages + [main]):
        initrd = finalize_default_initrd(context, config, resources=resources)

        if want_default_initrd(main):
            main = dataclasses.replace(
                main,
                initrds=[*main.initrds, initrd.output_dir_or_cwd() / initrd.output],
                dependencies=main.dependencies + [initrd.image],
            )

        subimages = [
            (
                dataclasses.replace(
                    image,
                    initrds=[*image.initrds, initrd.output_dir_or_cwd() / initrd.output],
                    dependencies=image.dependencies + [initrd.image],
                )
                if want_default_initrd(image)
                else image
            )
            for image in subimages
        ]

        subimages += [initrd]

    subimages = resolve_deps(subimages, main.dependencies)

    return args, tools, tuple(subimages + [main])


def finalize_term() -> str:
    term = os.getenv("TERM", "unknown")
    if term == "unknown":
        term = "vt220" if sys.stderr.isatty() else "dumb"

    return term if sys.stderr.isatty() else "dumb"


def finalize_git_config(proxy_url: Optional[str], env: dict[str, str]) -> dict[str, str]:
    if proxy_url is None:
        return {}

    try:
        cnt = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        raise ValueError("GIT_CONFIG_COUNT environment variable must be set to a valid integer")

    # Override HTTP/HTTPS proxy in case its set in .gitconfig to a different value than proxy_url.
    # No need to override http.proxy / https.proxy if set in a previous GIT_CONFIG_* variable since
    # the last setting always wins.
    return {
        "GIT_CONFIG_COUNT": str(cnt + 2),
        f"GIT_CONFIG_KEY_{cnt}": "http.proxy",
        f"GIT_CONFIG_VALUE_{cnt}": proxy_url,
        f"GIT_CONFIG_KEY_{cnt + 1}": "https.proxy",
        f"GIT_CONFIG_VALUE_{cnt + 1}": proxy_url,
    }


def yes_no(b: bool) -> str:
    return "yes" if b else "no"


def none_to_na(s: Optional[object]) -> str:
    return "n/a" if s is None else str(s)


def none_to_random(s: Optional[object]) -> str:
    return "random" if s is None else str(s)


def none_to_none(s: Optional[object]) -> str:
    return "none" if s is None else str(s)


def none_to_default(s: Optional[object]) -> str:
    return "default" if s is None else str(s)


def line_join_list(array: Iterable[object]) -> str:
    return "\n                                     ".join(str(item) for item in array) if array else "none"


def format_bytes(num_bytes: int) -> str:
    if num_bytes >= 1024**3:
        return f"{num_bytes / 1024**3:0.1f}G"
    if num_bytes >= 1024**2:
        return f"{num_bytes / 1024**2:0.1f}M"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:0.1f}K"

    return f"{num_bytes}B"


def format_bytes_or_none(num_bytes: Optional[int]) -> str:
    return format_bytes(num_bytes) if num_bytes is not None else "none"


def format_octal(oct_value: int) -> str:
    return f"{oct_value:>04o}"


def format_octal_or_default(oct_value: Optional[int]) -> str:
    return format_octal(oct_value) if oct_value is not None else "default"


def bold(s: Any) -> str:
    return f"{Style.bold}{s}{Style.reset}"


def cat_config(images: Sequence[Config]) -> str:
    c = io.StringIO()
    for n, config in enumerate(images):
        if n > 0:
            print(file=c)

        print(bold(f"### IMAGE: {config.image}"), file=c)

        for path in config.files:
            # Display the paths as relative to ., if underneath.
            if path.is_relative_to(Path.cwd()):
                path = path.relative_to(Path.cwd())
            print(f"{Style.blue}# {path}{Style.reset}", file=c)
            print(path.read_text(), file=c)

    return c.getvalue()


def summary(config: Config) -> str:
    maniformats = (" ".join(i.name for i in config.manifest_format)) or "(none)"
    env = [f"{k}={v}" for k, v in config.environment.items()]

    summary = f"""\
{bold(f"IMAGE: {config.image}")}
"""

    if config.image in ("main", "tools"):
        summary += f"""\

    {bold("CONFIG")}:
                           Profiles: {line_join_list(config.profiles)}
                       Dependencies: {line_join_list(config.dependencies)}
                    Minimum Version: {none_to_none(config.minimum_version)}
                  Configure Scripts: {line_join_list(config.configure_scripts)}
                   Pass Environment: {line_join_list(config.pass_environment)}

    {bold("DISTRIBUTION")}:
                       Distribution: {bold(config.distribution)}
                            Release: {bold(none_to_na(config.release))}
                       Architecture: {config.architecture}
                             Mirror: {none_to_default(config.mirror)}
                           Snapshot: {none_to_none(config.snapshot)}
               Local Mirror (build): {none_to_none(config.local_mirror)}
           Repo Signature/Key check: {yes_no(config.repository_key_check)}
              Fetch Repository Keys: {yes_no(config.repository_key_fetch)}
                       Repositories: {line_join_list(config.repositories)}
"""

    summary += f"""\

    {bold("OUTPUT")}:
                      Output Format: {config.output_format}
                   Manifest Formats: {maniformats}
                             Output: {bold(config.output_with_compression)}
                        Compression: {config.compress_output}
                  Compression Level: {config.compress_level}
                   Output Directory: {config.output_dir_or_cwd()}
                        Output Mode: {format_octal_or_default(config.output_mode)}
                           Image ID: {config.image_id}
                      Image Version: {config.image_version}
                    Split Artifacts: {line_join_list(config.split_artifacts)}
                 Repart Directories: {line_join_list(config.repart_dirs)}
                        Sector Size: {none_to_default(config.sector_size)}
                            Overlay: {yes_no(config.overlay)}
                               Seed: {none_to_random(config.seed)}
                      Clean Scripts: {line_join_list(config.clean_scripts)}

    {bold("CONTENT")}:
                           Packages: {line_join_list(config.packages)}
                     Build Packages: {line_join_list(config.build_packages)}
                  Volatile Packages: {line_join_list(config.volatile_packages)}
                Package Directories: {line_join_list(config.package_directories)}
       Volatile Package Directories: {line_join_list(config.volatile_package_directories)}
                 With Documentation: {yes_no(config.with_docs)}

                         Base Trees: {line_join_list(config.base_trees)}
                     Skeleton Trees: {line_join_list(config.skeleton_trees)}
                        Extra Trees: {line_join_list(config.extra_trees)}

                    Remove Packages: {line_join_list(config.remove_packages)}
                       Remove Files: {line_join_list(config.remove_files)}
     Clean Package Manager Metadata: {config.clean_package_metadata}
                  Source Date Epoch: {none_to_none(config.source_date_epoch)}

                       Sync Scripts: {line_join_list(config.sync_scripts)}
                    Prepare Scripts: {line_join_list(config.prepare_scripts)}
                      Build Scripts: {line_join_list(config.build_scripts)}
                Postinstall Scripts: {line_join_list(config.postinst_scripts)}
                   Finalize Scripts: {line_join_list(config.finalize_scripts)}
                 Postoutput Scripts: {line_join_list(config.postoutput_scripts)}

                           Bootable: {config.bootable}
                         Bootloader: {config.bootloader}
                    BIOS Bootloader: {config.bios_bootloader}
                    Shim Bootloader: {config.shim_bootloader}
              Unified Kernel Images: {config.unified_kernel_images}
        Unified Kernel Image Format: {config.unified_kernel_image_format}
      Unified Kernel Image Profiles: {line_join_list(config.unified_kernel_image_profiles)}
                            Initrds: {line_join_list(config.initrds)}
                    Initrd Profiles: {line_join_list(config.initrd_profiles)}
                    Initrd Packages: {line_join_list(config.initrd_packages)}
           Initrd Volatile Packages: {line_join_list(config.initrd_volatile_packages)}
                        Devicetrees: {line_join_list(config.devicetrees)}
                             Splash: {none_to_none(config.splash)}
                Kernel Command Line: {line_join_list(config.kernel_command_line)}
                     Kernel Modules: {line_join_list(config.kernel_modules_include)}
"""

    if config.kernel_modules_exclude:
        summary += f"""\
             Kernel Modules Exclude: {line_join_list(config.kernel_modules_exclude)}
"""

    summary += f"""\
        Kernel Modules Include Host: {yes_no(config.kernel_modules_include_host)}
                     Firmware Files: {line_join_list(config.firmware_include)}
"""

    if config.firmware_exclude:
        summary += f"""\
             Firmware Files Exclude: {line_join_list(config.firmware_exclude)}
"""

    summary += f"""\
              Kernel Modules Initrd: {yes_no(config.kernel_modules_initrd)}
              Kernel Initrd Modules: {line_join_list(config.kernel_modules_initrd_include)}
"""

    if config.kernel_modules_initrd_exclude:
        summary += f"""\
      Kernel Modules Initrd Exclude: {line_join_list(config.kernel_modules_initrd_exclude)}
"""

    summary += f"""\
 Kernel Modules Initrd Include Host: {yes_no(config.kernel_modules_initrd_include_host)}

                             Locale: {none_to_default(config.locale)}
                    Locale Messages: {none_to_default(config.locale_messages)}
                             Keymap: {none_to_default(config.keymap)}
                           Timezone: {none_to_default(config.timezone)}
                           Hostname: {none_to_default(config.hostname)}
                      Root Password: {("(set)" if config.root_password else "(default)")}
                         Root Shell: {none_to_default(config.root_shell)}
                         Machine ID: {none_to_none(config.machine_id)}

                          Autologin: {yes_no(config.autologin)}
                        Make Initrd: {yes_no(config.make_initrd)}
                                SSH: {config.ssh}
                    SELinux Relabel: {config.selinux_relabel}
"""

    if config.output_format.is_extension_or_portable_image() or config.output_format in (
        OutputFormat.disk,
        OutputFormat.uki,
        OutputFormat.esp,
    ):
        summary += f"""\

         {bold("VALIDATION")}:
                    UEFI SecureBoot: {yes_no(config.secure_boot)}
         UEFI SecureBoot AutoEnroll: {yes_no(config.secure_boot_auto_enroll)}
             SecureBoot Signing Key: {none_to_none(config.secure_boot_key)}
      SecureBoot Signing Key Source: {config.secure_boot_key_source}
             SecureBoot Certificate: {none_to_none(config.secure_boot_certificate)}
      SecureBoot Certificate Source: {config.secure_boot_certificate_source}
               SecureBoot Sign Tool: {config.secure_boot_sign_tool}
                             Verity: {config.verity}
                 Verity Signing Key: {none_to_none(config.verity_key)}
          Verity Signing Key Source: {config.verity_key_source}
                 Verity Certificate: {none_to_none(config.verity_certificate)}
          Verity Certificate Source: {config.verity_certificate_source}
                 Sign Expected PCRs: {config.sign_expected_pcr}
          Expected PCRs Signing Key: {none_to_none(config.sign_expected_pcr_key)}
           Expected PCRs Key Source: {config.sign_expected_pcr_key_source}
          Expected PCRs Certificate: {none_to_none(config.sign_expected_pcr_certificate)}
   Expected PCRs Certificate Source: {config.sign_expected_pcr_certificate_source}
                         Passphrase: {none_to_none(config.passphrase)}
                           Checksum: {yes_no(config.checksum)}
                               Sign: {yes_no(config.sign)}
                       OpenPGP Tool: {config.openpgp_tool}
                            GPG Key: ({"default" if config.key is None else config.key})
"""

    if config.image == "main":
        summary += f"""\

    {bold("BUILD CONFIGURATION")}:
                         Tools Tree: {config.tools_tree}
            Tools Tree Certificates: {yes_no(config.tools_tree_certificates)}

                 Extra Search Paths: {line_join_list(config.extra_search_paths)}
                        Incremental: {config.incremental}
             Use Only Package Cache: {config.cacheonly}
                      Sandbox Trees: {line_join_list(config.sandbox_trees)}
                Workspace Directory: {config.workspace_dir_or_default()}
                    Cache Directory: {none_to_none(config.cache_dir)}
                          Cache Key: {config.cache_key}
            Package Cache Directory: {none_to_default(config.package_cache_dir)}
                    Build Directory: {none_to_none(config.build_dir)}
                          Build Key: {config.build_key}
                     Use Subvolumes: {config.use_subvolumes}
                     Repart Offline: {yes_no(config.repart_offline)}
                       Save History: {yes_no(config.history)}
                      Build Sources: {line_join_list(config.build_sources)}
            Build Sources Ephemeral: {config.build_sources_ephemeral}
                 Script Environment: {line_join_list(env)}
                  Environment Files: {line_join_list(config.environment_files)}
         Run Tests in Build Scripts: {yes_no(config.with_tests)}
               Scripts With Network: {yes_no(config.with_network)}

                          Proxy URL: {none_to_none(config.proxy_url)}
             Proxy Peer Certificate: {none_to_none(config.proxy_peer_certificate)}
           Proxy Client Certificate: {none_to_none(config.proxy_client_certificate)}
                   Proxy Client Key: {none_to_none(config.proxy_client_key)}

    {bold("HOST CONFIGURATION")}:
                    NSpawn Settings: {none_to_none(config.nspawn_settings)}
                          Ephemeral: {config.ephemeral}
                        Credentials: {line_join_list(config.credentials.keys())}
          Extra Kernel Command Line: {line_join_list(config.kernel_command_line_extra)}
                      Runtime Trees: {line_join_list(config.runtime_trees)}
                       Runtime Size: {format_bytes_or_none(config.runtime_size)}
                    Runtime Network: {config.runtime_network}
              Runtime Build Sources: {config.runtime_build_sources}
                          Bind User: {yes_no(config.bind_user)}
                    Unit Properties: {line_join_list(config.unit_properties)}
                    SSH Signing Key: {none_to_none(config.ssh_key)}
                    SSH Certificate: {none_to_none(config.ssh_certificate)}
                            Machine: {config.machine_or_name()}
                    Forward Journal: {none_to_none(config.forward_journal)}
       Register guest with machined: {config.register}
                Storage Target Mode: {config.storage_target_mode}

            Virtual Machine Monitor: {config.vmm}
                            Console: {config.console}
                          CPU Cores: {config.cpus}
                                RAM: {format_bytes(config.ram)}
                             MaxMem: {format_bytes_or_none(config.maxmem)}
                                KVM: {config.kvm}
                                CXL: {config.cxl}
                              VSock: {config.vsock}
                VSock Connection ID: {VsockCID.format(config.vsock_cid)}
                                TPM: {config.tpm}
                           Firmware: {config.firmware}
                 Firmware Variables: {none_to_none(config.firmware_variables)}
                              Linux: {none_to_none(config.linux)}
               QEMU Extra Arguments: {line_join_list(config.qemu_args)}
"""

    return summary


class JsonEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, StrEnum):
            return str(o)
        elif isinstance(o, GenericVersion):
            return str(o)
        elif isinstance(o, os.PathLike):
            return os.fspath(o)
        elif isinstance(o, uuid.UUID):
            return str(o)
        elif isinstance(o, (Args, Config)):
            return o.to_dict()
        elif dataclasses.is_dataclass(o) and not isinstance(o, type):
            return dataclasses.asdict(o)
        return super().default(o)


def dump_json(dict: dict[str, Any], indent: Optional[int] = 4) -> str:
    return json.dumps(dict, cls=JsonEncoder, indent=indent, sort_keys=True)


E = TypeVar("E", bound=StrEnum)


def json_type_transformer(refcls: Union[type[Args], type[Config]]) -> Callable[[str, Any], Any]:
    fields_by_name = {field.name: field for field in dataclasses.fields(refcls)}

    def path_transformer(path: str, fieldtype: type[Path]) -> Path:
        return Path(path)

    def optional_path_transformer(path: Optional[str], fieldtype: type[Optional[Path]]) -> Optional[Path]:
        return Path(path) if path is not None else None

    def path_list_transformer(pathlist: list[str], fieldtype: type[list[Path]]) -> list[Path]:
        return [Path(p) for p in pathlist]

    def uuid_transformer(uuidstr: str, fieldtype: type[uuid.UUID]) -> uuid.UUID:
        return uuid.UUID(uuidstr)

    def optional_uuid_transformer(
        uuidstr: Optional[str], fieldtype: type[Optional[uuid.UUID]]
    ) -> Optional[uuid.UUID]:
        return uuid.UUID(uuidstr) if uuidstr is not None else None

    def root_password_transformer(
        rootpw: Optional[list[Union[str, bool]]], fieldtype: type[Optional[tuple[str, bool]]]
    ) -> Optional[tuple[str, bool]]:
        if rootpw is None:
            return None
        return (cast(str, rootpw[0]), cast(bool, rootpw[1]))

    def config_tree_transformer(
        trees: list[dict[str, Any]], fieldtype: type[ConfigTree]
    ) -> list[ConfigTree]:
        # TODO: exchange for TypeGuard and list comprehension once on 3.10
        ret = []
        for d in trees:
            assert "Source" in d
            assert "Target" in d
            ret.append(
                ConfigTree(
                    source=Path(d["Source"]),
                    target=Path(d["Target"]) if d["Target"] is not None else None,
                )
            )
        return ret

    def enum_transformer(enumval: str, fieldtype: type[E]) -> E:
        return fieldtype(enumval)

    def optional_enum_transformer(enumval: Optional[str], fieldtype: type[Optional[E]]) -> Optional[E]:
        return typing.get_args(fieldtype)[0](enumval) if enumval is not None else None

    def enum_list_transformer(enumlist: list[str], fieldtype: type[list[E]]) -> list[E]:
        enumtype = fieldtype.__args__[0]  # type: ignore
        return [enumtype(e) for e in enumlist]

    def config_drive_transformer(drives: list[dict[str, Any]], fieldtype: type[Drive]) -> list[Drive]:
        # TODO: exchange for TypeGuard and list comprehension once on 3.10
        ret = []

        for d in drives:
            assert "Id" in d
            assert "Size" in d
            ret.append(
                Drive(
                    id=d["Id"],
                    size=d["Size"] if isinstance(d["Size"], int) else parse_bytes(d["Size"]),
                    directory=Path(d["Directory"]) if d.get("Directory") else None,
                    options=d.get("Options"),
                    file_id=d.get("FileId", d["Id"]),
                    flags=[DriveFlag(f) for f in d.get("Flags", [])],
                )
            )

        return ret

    def generic_version_transformer(
        version: Optional[str],
        fieldtype: type[Optional[GenericVersion]],
    ) -> Optional[GenericVersion]:
        return GenericVersion(version) if version is not None else None

    def certificate_source_transformer(
        certificate_source: dict[str, Any], fieldtype: type[CertificateSource]
    ) -> CertificateSource:
        assert "Type" in certificate_source
        return CertificateSource(
            type=CertificateSourceType(certificate_source["Type"]),
            source=certificate_source.get("Source", ""),
        )

    def key_source_transformer(keysource: dict[str, Any], fieldtype: type[KeySource]) -> KeySource:
        assert "Type" in keysource
        return KeySource(type=KeySourceType(keysource["Type"]), source=keysource.get("Source", ""))

    def uki_profile_transformer(
        profiles: list[dict[str, Any]],
        fieldtype: type[UKIProfile],
    ) -> list[UKIProfile]:
        return [
            UKIProfile(
                profile=profile["Profile"],
                cmdline=profile["Cmdline"],
                sign_expected_pcr=profile["SignExpectedPcr"],
            )
            for profile in profiles
        ]

    # The type of this should be
    # dict[
    #     type,
    #     Callable[a stringy JSON object (str, null, list or dict of str), type of the key], type of the key
    # ]
    # though this seems impossible to express, since e.g. mypy will make this a
    # builtins.dict[builtins.object, builtins.function]
    # whereas pyright gives the type of the dict keys as the proper union of
    # all functions in the dict. We therefore squash all the types here to Any
    # to shut up the type checkers and rely on the tests.
    transformers: dict[Any, Callable[[Any, Any], Any]] = {
        Path: path_transformer,
        Optional[Path]: optional_path_transformer,
        list[Path]: path_list_transformer,
        uuid.UUID: uuid_transformer,
        Optional[uuid.UUID]: optional_uuid_transformer,
        Optional[tuple[str, bool]]: root_password_transformer,
        list[ConfigTree]: config_tree_transformer,
        Architecture: enum_transformer,
        BiosBootloader: enum_transformer,
        ShimBootloader: enum_transformer,
        Ssh: enum_transformer,
        Bootloader: enum_transformer,
        Compression: enum_transformer,
        ConfigFeature: enum_transformer,
        Distribution: enum_transformer,
        OutputFormat: enum_transformer,
        Firmware: enum_transformer,
        SecureBootSignTool: enum_transformer,
        Incremental: enum_transformer,
        BuildSourcesEphemeral: enum_transformer,
        Optional[Distribution]: optional_enum_transformer,
        list[ManifestFormat]: enum_list_transformer,
        Verb: enum_transformer,
        DocFormat: enum_transformer,
        list[Drive]: config_drive_transformer,
        GenericVersion: generic_version_transformer,
        Cacheonly: enum_transformer,
        Network: enum_transformer,
        KeySource: key_source_transformer,
        Vmm: enum_transformer,
        list[UKIProfile]: uki_profile_transformer,
        UnifiedKernelImage: enum_transformer,
        list[ArtifactOutput]: enum_list_transformer,
        CertificateSource: certificate_source_transformer,
        ConsoleMode: enum_transformer,
        Verity: enum_transformer,
    }

    def json_transformer(key: str, val: Any) -> Any:
        fieldtype: Optional[dataclasses.Field[Any]] = fields_by_name.get(key)
        # It is unlikely that the type of a field will be None only, so let's not bother with a different
        # sentinel value
        if fieldtype is None:
            raise ValueError(f"{refcls} has no field {key}")

        transformer = transformers.get(fieldtype.type)
        if transformer is not None:
            try:
                return transformer(val, fieldtype.type)
            except (ValueError, IndexError, AssertionError) as e:
                raise ValueError(
                    f"Unable to parse {val!r} for attribute {key!r} for {refcls.__name__}"
                ) from e

        return val

    return json_transformer


def want_selinux_relabel(
    config: Config,
    root: Path,
    fatal: bool = True,
) -> Optional[tuple[Path, str, Path, Path]]:
    if config.selinux_relabel == ConfigFeature.disabled:
        return None

    if config.selinux_relabel == ConfigFeature.auto and config.output_format == OutputFormat.directory:
        return None

    selinux = root / "etc/selinux/config"
    if not selinux.exists():
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die("SELinux relabel is requested but could not find selinux config at /etc/selinux/config")
        return None

    policy = run(
        ["sh", "-c", f". {workdir(selinux)} && echo $SELINUXTYPE"],
        sandbox=config.sandbox(options=["--ro-bind", selinux, workdir(selinux)]),
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if not policy:
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die("SELinux relabel is requested but no selinux policy is configured in /etc/selinux/config")
        return None

    if not (setfiles := config.find_binary("setfiles")):
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die("SELinux relabel is requested but setfiles is not installed")
        return None

    fc = root / "etc/selinux" / policy / "contexts/files/file_contexts"
    if not fc.exists():
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die(f"SELinux relabel is requested but SELinux file contexts not found in {fc}")
        return None

    binpolicydir = root / "etc/selinux" / policy / "policy"

    # The policy file is named policy.XX where XX is the policy version that indicates what features are
    # available. We check for string.digits instead of using isdecimal() as the latter checks for more than
    # just digits.
    policies = [
        p for p in binpolicydir.glob("*") if p.suffix and all(c in string.digits for c in p.suffix[1:])
    ]
    if not policies:
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die(f"SELinux relabel is requested but SELinux binary policy not found in {binpolicydir}")
        return None

    binpolicy = sorted(policies, key=lambda p: GenericVersion(p.name), reverse=True)[0]

    return setfiles, policy, fc, binpolicy


def systemd_tool_version(*tool: PathString, sandbox: SandboxProtocol = nosandbox) -> GenericVersion:
    version = GenericVersion(
        run(
            [*tool, "--version"],
            stdout=subprocess.PIPE,
            sandbox=sandbox(),
        )
        .stdout.split()[2]
        .strip("()")
        .removeprefix("v")
    )

    logging.debug(f"Version reported by {tool[-1]} is {version}")

    return version
