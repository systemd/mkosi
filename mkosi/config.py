# SPDX-License-Identifier: LGPL-2.1+

import argparse
import base64
import contextlib
import copy
import dataclasses
import enum
import fnmatch
import functools
import graphlib
import inspect
import json
import logging
import math
import operator
import os.path
import platform
import re
import shlex
import shutil
import string
import subprocess
import tempfile
import textwrap
import uuid
from collections.abc import Collection, Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union, cast

from mkosi.distributions import Distribution, detect_distribution
from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, Style, die
from mkosi.pager import page
from mkosi.run import find_binary, run
from mkosi.sandbox import sandbox_cmd
from mkosi.types import PathString, SupportsRead
from mkosi.user import INVOKING_USER
from mkosi.util import (
    StrEnum,
    chdir,
    flatten,
    is_power_of_2,
    make_executable,
)
from mkosi.versioncomp import GenericVersion

__version__ = "20.2"

ConfigParseCallback = Callable[[Optional[str], Optional[Any]], Any]
ConfigMatchCallback = Callable[[str, Any], bool]
ConfigDefaultCallback = Callable[[argparse.Namespace], Any]


BUILTIN_CONFIGS = ("mkosi-tools", "mkosi-initrd")


class Verb(StrEnum):
    build         = enum.auto()
    clean         = enum.auto()
    summary       = enum.auto()
    shell         = enum.auto()
    boot          = enum.auto()
    qemu          = enum.auto()
    ssh           = enum.auto()
    serve         = enum.auto()
    bump          = enum.auto()
    help          = enum.auto()
    genkey        = enum.auto()
    documentation = enum.auto()
    journalctl    = enum.auto()
    coredumpctl   = enum.auto()
    burn          = enum.auto()

    def supports_cmdline(self) -> bool:
        return self in (
            Verb.build,
            Verb.shell,
            Verb.boot,
            Verb.qemu,
            Verb.ssh,
            Verb.journalctl,
            Verb.coredumpctl,
            Verb.burn,
        )

    def needs_build(self) -> bool:
        return self in (
            Verb.build,
            Verb.shell,
            Verb.boot,
            Verb.qemu,
            Verb.serve,
            Verb.burn,
        )

    def needs_root(self) -> bool:
        return self in (Verb.shell, Verb.boot, Verb.burn)

    def needs_credentials(self) -> bool:
        return self in (Verb.summary, Verb.qemu, Verb.boot, Verb.shell)


class ConfigFeature(StrEnum):
    auto     = enum.auto()
    enabled  = enum.auto()
    disabled = enum.auto()


@dataclasses.dataclass(frozen=True)
class ConfigTree:
    source: Path
    target: Optional[Path]

    def with_prefix(self, prefix: Path = Path("/")) -> tuple[Path, Path]:
        return (self.source, prefix / os.fspath(self.target).lstrip("/") if self.target else prefix)


@dataclasses.dataclass(frozen=True)
class QemuDrive:
    id: str
    size: int
    directory: Optional[Path]
    options: Optional[str]


# We use negative numbers for specifying special constants
# for VSock CIDs since they're not valid CIDs anyway.
class QemuVsockCID(enum.IntEnum):
    auto = -1
    hash = -2

    @classmethod
    def format(cls, cid: int) -> str:
        if cid == QemuVsockCID.auto:
            return "auto"

        if cid == QemuVsockCID.hash:
            return "hash"

        return str(cid)


class SecureBootSignTool(StrEnum):
    auto   = enum.auto()
    sbsign = enum.auto()
    pesign = enum.auto()


class OutputFormat(StrEnum):
    confext   = enum.auto()
    cpio      = enum.auto()
    directory = enum.auto()
    disk      = enum.auto()
    esp       = enum.auto()
    none      = enum.auto()
    portable  = enum.auto()
    sysext    = enum.auto()
    tar       = enum.auto()
    uki       = enum.auto()

    def extension(self) -> str:
        return {
            OutputFormat.confext:  ".raw",
            OutputFormat.cpio:     ".cpio",
            OutputFormat.disk:     ".raw",
            OutputFormat.esp:      ".raw",
            OutputFormat.portable: ".raw",
            OutputFormat.sysext:   ".raw",
            OutputFormat.tar:      ".tar",
            OutputFormat.uki:      ".efi",
        }.get(self, "")

    def use_outer_compression(self) -> bool:
        return self in (OutputFormat.tar, OutputFormat.cpio, OutputFormat.disk) or self.is_extension_image()

    def is_extension_image(self) -> bool:
        return self in (OutputFormat.sysext, OutputFormat.confext, OutputFormat.portable)


class ManifestFormat(StrEnum):
    json      = enum.auto()  # the standard manifest in json format
    changelog = enum.auto()  # human-readable text file with package changelogs


class Compression(StrEnum):
    none = enum.auto()
    zstd = enum.auto()
    zst  = "zstd"
    xz   = enum.auto()
    bz2  = enum.auto()
    gz   = enum.auto()
    lz4  = enum.auto()
    lzma = enum.auto()

    def __bool__(self) -> bool:
        return self != Compression.none

    def extension(self) -> str:
        return {
            Compression.zstd: ".zst"
        }.get(self, f".{self}")


class DocFormat(StrEnum):
    auto     = enum.auto()
    markdown = enum.auto()
    man      = enum.auto()
    pandoc   = enum.auto()
    system   = enum.auto()


class Bootloader(StrEnum):
    none         = enum.auto()
    uki          = enum.auto()
    systemd_boot = enum.auto()
    grub         = enum.auto()


class BiosBootloader(StrEnum):
    none = enum.auto()
    grub = enum.auto()


class ShimBootloader(StrEnum):
    none     = enum.auto()
    signed   = enum.auto()
    unsigned = enum.auto()


class Cacheonly(StrEnum):
    always = enum.auto()
    none = enum.auto()
    metadata = enum.auto()


class QemuFirmware(StrEnum):
    auto   = enum.auto()
    linux  = enum.auto()
    uefi   = enum.auto()
    bios   = enum.auto()


class Architecture(StrEnum):
    alpha       = enum.auto()
    arc         = enum.auto()
    arm         = enum.auto()
    arm64       = enum.auto()
    ia64        = enum.auto()
    loongarch64 = enum.auto()
    mips_le     = enum.auto()
    mips64_le   = enum.auto()
    parisc      = enum.auto()
    ppc         = enum.auto()
    ppc64       = enum.auto()
    ppc64_le    = enum.auto()
    riscv32     = enum.auto()
    riscv64     = enum.auto()
    s390        = enum.auto()
    s390x       = enum.auto()
    tilegx      = enum.auto()
    x86         = enum.auto()
    x86_64      = enum.auto()

    @staticmethod
    def from_uname(s: str) -> "Architecture":
        a = {
            "aarch64"     : Architecture.arm64,
            "aarch64_be"  : Architecture.arm64,
            "armv8l"      : Architecture.arm,
            "armv8b"      : Architecture.arm,
            "armv7ml"     : Architecture.arm,
            "armv7mb"     : Architecture.arm,
            "armv7l"      : Architecture.arm,
            "armv7b"      : Architecture.arm,
            "armv6l"      : Architecture.arm,
            "armv6b"      : Architecture.arm,
            "armv5tl"     : Architecture.arm,
            "armv5tel"    : Architecture.arm,
            "armv5tejl"   : Architecture.arm,
            "armv5tejb"   : Architecture.arm,
            "armv5teb"    : Architecture.arm,
            "armv5tb"     : Architecture.arm,
            "armv4tl"     : Architecture.arm,
            "armv4tb"     : Architecture.arm,
            "armv4l"      : Architecture.arm,
            "armv4b"      : Architecture.arm,
            "alpha"       : Architecture.alpha,
            "arc"         : Architecture.arc,
            "arceb"       : Architecture.arc,
            "x86_64"      : Architecture.x86_64,
            "i686"        : Architecture.x86,
            "i586"        : Architecture.x86,
            "i486"        : Architecture.x86,
            "i386"        : Architecture.x86,
            "ia64"        : Architecture.ia64,
            "parisc64"    : Architecture.parisc,
            "parisc"      : Architecture.parisc,
            "loongarch64" : Architecture.loongarch64,
            "mips64"      : Architecture.mips64_le,
            "mips"        : Architecture.mips_le,
            "ppc64le"     : Architecture.ppc64_le,
            "ppc64"       : Architecture.ppc64,
            "ppc"         : Architecture.ppc,
            "riscv64"     : Architecture.riscv64,
            "riscv32"     : Architecture.riscv32,
            "riscv"       : Architecture.riscv64,
            "s390x"       : Architecture.s390x,
            "s390"        : Architecture.s390,
            "tilegx"      : Architecture.tilegx,
        }.get(s)

        if not a:
            die(f"Architecture {a} is not supported")

        return a

    def to_efi(self) -> Optional[str]:
        return {
            Architecture.x86_64      : "x64",
            Architecture.x86         : "ia32",
            Architecture.arm64       : "aa64",
            Architecture.arm         : "arm",
            Architecture.riscv64     : "riscv64",
            Architecture.loongarch64 : "loongarch64",
        }.get(self)

    def to_qemu(self) -> str:
        a = {
            Architecture.alpha       : "alpha",
            Architecture.arm         : "arm",
            Architecture.arm64       : "aarch64",
            Architecture.loongarch64 : "loongarch64",
            Architecture.mips64_le   : "mips",
            Architecture.mips_le     : "mips",
            Architecture.parisc      : "hppa",
            Architecture.ppc         : "ppc",
            Architecture.ppc64       : "ppc64",
            Architecture.ppc64_le    : "ppc64",
            Architecture.riscv32     : "riscv32",
            Architecture.riscv64     : "riscv64",
            Architecture.s390x       : "s390x",
            Architecture.x86         : "i386",
            Architecture.x86_64      : "x86_64",
        }.get(self)

        if not a:
            die(f"Architecture {self} not supported by QEMU")

        return a

    def default_serial_tty(self) -> str:
        return {
            Architecture.arm      : "ttyAMA0",
            Architecture.arm64    : "ttyAMA0",
            Architecture.s390     : "ttysclp0",
            Architecture.s390x    : "ttysclp0",
            Architecture.ppc      : "hvc0",
            Architecture.ppc64    : "hvc0",
            Architecture.ppc64_le : "hvc0",
        }.get(self, "ttyS0")

    def supports_smbios(self, firmware: QemuFirmware) -> bool:
        if self in (Architecture.x86, Architecture.x86_64):
            return True

        return self in (Architecture.arm, Architecture.arm64) and firmware == QemuFirmware.uefi

    def supports_fw_cfg(self) -> bool:
        return self in (Architecture.x86, Architecture.x86_64, Architecture.arm, Architecture.arm64)

    def supports_smm(self) -> bool:
        return self in (Architecture.x86, Architecture.x86_64)

    def default_qemu_machine(self) -> str:
        m = {
            Architecture.x86      : "q35",
            Architecture.x86_64   : "q35",
            Architecture.arm      : "virt",
            Architecture.arm64    : "virt",
            Architecture.s390     : "s390-ccw-virtio",
            Architecture.s390x    : "s390-ccw-virtio",
            Architecture.ppc      : "pseries",
            Architecture.ppc64    : "pseries",
            Architecture.ppc64_le : "pseries",
        }

        if self not in m:
            die(f"No qemu machine defined for architecture {self}")

        return m[self]

    def default_qemu_nic_model(self) -> str:
        return {
            Architecture.s390  : "virtio",
            Architecture.s390x : "virtio",
        }.get(self, "virtio-net-pci")

    def is_native(self) -> bool:
        return self == self.native()

    @classmethod
    def native(cls) -> "Architecture":
        return cls.from_uname(platform.machine())


def parse_boolean(s: str) -> bool:
    "Parse 1/true/yes/y/t/on as true and 0/false/no/n/f/off/None as false"
    s_l = s.lower()
    if s_l in {"1", "true", "yes", "y", "t", "on", "always"}:
        return True

    if s_l in {"0", "false", "no", "n", "f", "off", "never"}:
        return False

    die(f"Invalid boolean literal: {s!r}")


def parse_path(value: str,
               *,
               required: bool = True,
               resolve: bool = True,
               expanduser: bool = True,
               expandvars: bool = True,
               secret: bool = False,
               absolute: bool = False,
               constants: Sequence[str] = ()) -> Path:
    if value in constants:
        return Path(value)

    if expandvars:
        value = os.path.expandvars(value)

    path = Path(value)

    if expanduser:
        if path.is_relative_to("~") and not INVOKING_USER.is_running_user():
            path = INVOKING_USER.home() / path.relative_to("~")
        path = path.expanduser()

    if required and not path.exists():
        die(f"{value} does not exist")

    if absolute and not path.is_absolute():
        die(f"{value} must be an absolute path")

    if resolve:
        path = path.resolve()

    if secret and path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o007:
            die(textwrap.dedent(f"""\
                Permissions of '{path}' of '{mode:04o}' are too open.
                When creating secret files use an access mode that restricts access to the owner only.
            """))

    return path


def make_tree_parser(absolute: bool = True) -> Callable[[str], ConfigTree]:
    def parse_tree(value: str) -> ConfigTree:
        src, sep, tgt = value.partition(':')

        return ConfigTree(
            source=parse_path(src, required=False),
            target=parse_path(
                tgt,
                required=False,
                resolve=False,
                expanduser=False,
                absolute=absolute,
            ) if sep else None,
        )

    return parse_tree


def config_match_build_sources(match: str, value: list[ConfigTree]) -> bool:
    return Path(match.lstrip("/")) in [tree.target for tree in value if tree.target]


def config_parse_string(value: Optional[str], old: Optional[str]) -> Optional[str]:
    return value or None


def config_make_string_matcher(allow_globs: bool = False) -> ConfigMatchCallback:
    def config_match_string(match: str, value: str) -> bool:
        if allow_globs:
            return fnmatch.fnmatchcase(value, match)
        else:
            return match == value

    return config_match_string


def config_parse_boolean(value: Optional[str], old: Optional[bool]) -> Optional[bool]:
    if value is None:
        return False

    if not value:
        return None

    return parse_boolean(value)


def parse_feature(value: str) -> ConfigFeature:
    if value == ConfigFeature.auto.name:
        return ConfigFeature.auto

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


def config_parse_seed(value: Optional[str], old: Optional[str]) -> Optional[uuid.UUID]:
    if not value or value == "random":
        return None

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
        die(f"{value} is not a valid timestamp")

    if timestamp < 0:
        die(f"Source date epoch timestamp cannot be negative (got {value})")

    return timestamp


def config_parse_compress_level(value: Optional[str], old: Optional[int]) -> Optional[int]:
    if not value:
        return None

    try:
        level = int(value)
    except ValueError:
        die(f"{value} is not a valid compression level")

    if level < 0:
        die(f"Compression level cannot be negative (got {value})")

    return level


def config_default_compression(namespace: argparse.Namespace) -> Compression:
    if namespace.output_format in (OutputFormat.tar, OutputFormat.cpio, OutputFormat.uki, OutputFormat.esp):
        if (
            (namespace.distribution.is_centos_variant() and int(namespace.release) <= 8) or
            (namespace.distribution == Distribution.ubuntu and namespace.release == "focal")
        ):
            return Compression.xz
        else:
            return Compression.zstd
    else:
        return Compression.none


def config_default_output(namespace: argparse.Namespace) -> str:
    output = namespace.image_id or namespace.image or "image"

    if namespace.image_version:
        output += f"_{namespace.image_version}"

    return output


def config_default_distribution(namespace: argparse.Namespace) -> Distribution:
    detected = detect_distribution()[0]

    if not detected:
        logging.info(
            "Distribution of your host can't be detected or isn't a supported target. "
            "Defaulting to Distribution=custom."
        )
        return Distribution.custom

    return detected


def config_default_release(namespace: argparse.Namespace) -> str:
    # If the configured distribution matches the host distribution, use the same release as the host.
    hd, hr = detect_distribution()
    if namespace.distribution == hd and hr is not None:
        return hr

    return cast(str, namespace.distribution.default_release())


def config_default_source_date_epoch(namespace: argparse.Namespace) -> Optional[int]:
    for env in namespace.environment:
        if env.startswith("SOURCE_DATE_EPOCH="):
            return config_parse_source_date_epoch(env.removeprefix("SOURCE_DATE_EPOCH="), None)
    return config_parse_source_date_epoch(os.environ.get("SOURCE_DATE_EPOCH"), None)


def config_default_kernel_command_line(namespace: argparse.Namespace) -> list[str]:
    return [f"console={namespace.architecture.default_serial_tty()}"]


def make_enum_parser(type: type[StrEnum]) -> Callable[[str], StrEnum]:
    def parse_enum(value: str) -> StrEnum:
        try:
            return type(value)
        except ValueError:
            die(f"'{value}' is not a valid {type.__name__}")

    return parse_enum


def config_make_enum_parser(type: type[StrEnum]) -> ConfigParseCallback:
    def config_parse_enum(value: Optional[str], old: Optional[StrEnum]) -> Optional[StrEnum]:
        return make_enum_parser(type)(value) if value else None

    return config_parse_enum


def config_make_enum_parser_with_boolean(type: type[StrEnum], *, yes: StrEnum, no: StrEnum) -> ConfigParseCallback:
    def config_parse_enum(value: Optional[str], old: Optional[StrEnum]) -> Optional[StrEnum]:
        if not value:
            return None

        if value in type.values():
            return type(value)

        return yes if parse_boolean(value) else no

    return config_parse_enum


def config_make_enum_matcher(type: type[StrEnum]) -> ConfigMatchCallback:
    def config_match_enum(match: str, value: StrEnum) -> bool:
        return make_enum_parser(type)(match) == value

    return config_match_enum


def config_make_list_parser(delimiter: str,
                            *,
                            parse: Callable[[str], Any] = str,
                            unescape: bool = False,
                            reset: bool = True) -> ConfigParseCallback:
    def config_parse_list(value: Optional[str], old: Optional[list[Any]]) -> Optional[list[Any]]:
        new = old.copy() if old else []

        if value is None:
            return []

        if unescape:
            lex = shlex.shlex(value, posix=True)
            lex.whitespace_split = True
            lex.whitespace = f"\n{delimiter}"
            lex.commenters = ""
            values = list(lex)
        else:
            values = value.replace(delimiter, "\n").split("\n")

        # Empty strings reset the list.
        if reset and len(values) == 1 and values[0] == "":
            return []

        return new + [parse(v) for v in values if v]

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
        if match.startswith(sigil):
            op = opfunc
            comp_version = GenericVersion(match[len(sigil):])
            break
    else:
        # default to equality if no operation is specified
        op = operator.eq
        comp_version = GenericVersion(match)

    # all constraints must be fulfilled
    if not op(version, comp_version):
        return False

    return True


def config_make_dict_parser(delimiter: str,
                            *,
                            parse: Callable[[str], tuple[str, Any]],
                            unescape: bool = False,
                            reset: bool = True) -> ConfigParseCallback:
    def config_parse_dict(value: Optional[str], old: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        new = old.copy() if old else {}

        if value is None:
            return {}

        if unescape:
            lex = shlex.shlex(value, posix=True)
            lex.whitespace_split = True
            lex.whitespace = f"\n{delimiter}"
            lex.commenters = ""
            values = list(lex)
        else:
            values = value.replace(delimiter, "\n").split("\n")

        # Empty strings reset the dict.
        if reset and len(values) == 1 and values[0] == "":
            return {}

        return new | dict(parse(v) for v in values if v)

    return config_parse_dict


def parse_environment(value: str) -> tuple[str, str]:
    key, sep, value = value.partition("=")
    key, value = key.strip(), value.strip()
    value = value if sep else os.getenv(key, "")
    return (key, value)


def parse_credential(value: str) -> tuple[str, str]:
    key, _, value = value.partition("=")
    key, value = key.strip(), value.strip()
    return (key, value)


def make_path_parser(*,
                     required: bool = True,
                     resolve: bool = True,
                     expanduser: bool = True,
                     expandvars: bool = True,
                     secret: bool = False,
                     constants: Sequence[str] = ()) -> Callable[[str], Path]:
    return functools.partial(
        parse_path,
        required=required,
        resolve=resolve,
        expanduser=expanduser,
        expandvars=expandvars,
        secret=secret,
        constants=constants,
    )


def config_make_path_parser(*,
                            required: bool = True,
                            resolve: bool = True,
                            expanduser: bool = True,
                            expandvars: bool = True,
                            secret: bool = False,
                            constants: Sequence[str] = ()) -> ConfigParseCallback:
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
            constants=constants,
        )

    return config_parse_path


def is_valid_filename(s: str) -> bool:
    s = s.strip()
    return not (s == "." or s == ".." or "/" in s)


def config_parse_output(value: Optional[str], old: Optional[str]) -> Optional[str]:
    if not value:
        return None

    if not is_valid_filename(value):
        die(f"{value!r} is not a valid filename.",
            hint="Output= or --output= requires a filename with no path components. "
                 "Use OutputDirectory= or --output-dir= to configure the output directory.")

    return value


def match_path_exists(value: str) -> bool:
    if not value:
        return False

    return Path(value).exists()


def config_parse_root_password(value: Optional[str], old: Optional[tuple[str, bool]]) -> Optional[tuple[str, bool]]:
    if not value:
        return None

    value = value.strip()
    hashed = value.startswith("hashed:")
    value = value.removeprefix("hashed:")

    return (value, hashed)


def match_systemd_version(value: str) -> bool:
    if not value:
        return False

    version = run(["systemctl", "--version"], stdout=subprocess.PIPE).stdout.strip().split()[1]
    return config_match_version(value, version)


def match_host_architecture(value: str) -> bool:
    return Architecture(value) == Architecture.native()


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


def config_parse_profile(value: Optional[str], old: Optional[int] = None) -> Optional[str]:
    if not value:
        return None

    if not is_valid_filename(value):
        die(f"{value!r} is not a valid profile",
            hint="Profile= or --profile= requires a name with no path components.")

    return value


def parse_drive(value: str) -> QemuDrive:
    parts = value.split(":", maxsplit=3)
    if not parts or not parts[0]:
        die(f"No ID specified for drive '{value}'")

    if len(parts) < 2:
        die(f"Missing size in drive '{value}")

    if len(parts) > 4:
        die(f"Too many components in drive '{value}")

    id = parts[0]
    if not is_valid_filename(id):
        die(f"Unsupported path character in drive id '{id}'")

    size = parse_bytes(parts[1])

    directory = parse_path(parts[2]) if len(parts) > 2 and parts[2] else None
    options = parts[3] if len(parts) > 3 and parts[3] else None

    return QemuDrive(id=id, size=size, directory=directory, options=options)


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
        return QemuVsockCID.auto

    if value == "hash":
        return QemuVsockCID.hash

    try:
        cid = int(value)
    except ValueError:
        die(f"VSock connection ID '{value}' is not a valid number or one of 'auto' or 'hash'")

    if cid not in range(3, 0xFFFFFFFF):
        die(f"{cid} is not in the valid VSock connection ID range [3, 0xFFFFFFFF)")

    return cid


def config_parse_minimum_version(value: Optional[str], old: Optional[GenericVersion]) -> Optional[GenericVersion]:
    if not value:
        return old

    new = GenericVersion(value)

    if not old:
        return new

    return max(old, new)


@dataclasses.dataclass(frozen=True)
class ConfigSetting:
    dest: str
    section: str
    parse: ConfigParseCallback = config_parse_string
    match: Optional[ConfigMatchCallback] = None
    name: str = ""
    default: Any = None
    default_factory: Optional[ConfigDefaultCallback] = None
    default_factory_depends: tuple[str, ...] = tuple()
    paths: tuple[str, ...] = ()
    path_read_text: bool = False
    path_secret: bool = False
    path_default: bool = True
    specifier: str = ""

    # settings for argparse
    short: Optional[str] = None
    long: str = ""
    choices: Optional[Any] = None
    metavar: Optional[str] = None
    nargs: Optional[str] = None
    const: Optional[Any] = None
    help: Optional[str] = None

    # backward compatibility
    compat_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            object.__setattr__(self, 'name', ''.join(x.capitalize() for x in self.dest.split('_') if x))
        if not self.long:
            object.__setattr__(self, "long", f"--{self.dest.replace('_', '-')}")


@dataclasses.dataclass(frozen=True)
class Match:
    name: str
    match: Callable[[str], bool]


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
        subindent = '    ' if lines[0].endswith(':') else ''
        return flatten(textwrap.wrap(line, width, break_long_words=False, break_on_hyphens=False,
                                     subsequent_indent=subindent) for line in lines)


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
        option_string: Optional[str] = None
    ) -> None:
        logging.warning(f"{option_string} is no longer supported")


class PagerHelpAction(argparse._HelpAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None] = None,
        option_string: Optional[str] = None
    ) -> None:
        page(parser.format_help(), namespace.pager)
        parser.exit()


@dataclasses.dataclass(frozen=True)
class Args:
    verb: Verb
    cmdline: list[str]
    force: int
    directory: Optional[Path]
    debug: bool
    debug_shell: bool
    debug_workspace: bool
    pager: bool
    genkey_valid_days: str
    genkey_common_name: str
    auto_bump: bool
    doc_format: DocFormat
    json: bool

    @classmethod
    def default(cls) -> "Args":
        """Alternative constructor to generate an all-default MkosiArgs.

        This prevents MkosiArgs being generated with defaults values implicitly.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            with chdir(tempdir):
                args, _ = parse_config([])

        return args

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> "Args":
        return cls(**{
            k: v for k, v in vars(ns).items()
            if k in inspect.signature(cls).parameters
        })

    def to_dict(self) -> dict[str, Any]:
        def key_transformer(k: str) -> str:
            return "".join(p.capitalize() for p in k.split("_"))

        return {key_transformer(k): v for k, v in dataclasses.asdict(self).items()}

    def to_json(self, *, indent: Optional[int] = 4, sort_keys: bool = True) -> str:
        """Dump MkosiArgs as JSON string."""
        return json.dumps(self.to_dict(), cls=JsonEncoder, indent=indent, sort_keys=sort_keys)

    @classmethod
    def _load_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> dict[str, Any]:
        """Load JSON and transform it into a dictionary suitable compatible with instantiating a MkosiArgs object."""
        if isinstance(s, str):
            j = json.loads(s)
        elif isinstance(s, dict):
            j = s
        elif hasattr(s, "read"):
            j = json.load(s)
        else:
            raise ValueError(f"{cls.__name__} can only be constructed from JSON from strings, dictionaries and files.")

        value_transformer = json_type_transformer(cls)
        def key_transformer(k: str) -> str:
            return "_".join(part.lower() for part in FALLBACK_NAME_TO_DEST_SPLITTER.split(k))

        return {(tk := key_transformer(k)): value_transformer(tk, v) for k, v in j.items()}

    @classmethod
    def from_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "Args":
        """Instantiate a MkosiArgs object from a full JSON dump."""
        j = cls._load_json(s)
        return cls(**j)

    @classmethod
    def from_partial_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "Args":
        """Return a new MkosiArgs with defaults overwritten by the attributes from passed in JSON."""
        j = cls._load_json(s)
        return dataclasses.replace(cls.default(), **j)


@dataclasses.dataclass(frozen=True)
class Config:
    """Type-hinted storage for command line arguments.

    Only user configuration is stored here while dynamic state exists in
    Mkosicontext. If a field of the same name exists in both classes always
    access the value from context.
    """

    profile: Optional[str]
    include: list[Path]
    initrd_include: list[Path]
    images: tuple[str, ...]
    dependencies: tuple[str, ...]
    minimum_version: Optional[GenericVersion]

    distribution: Distribution
    release: str
    architecture: Architecture
    mirror: Optional[str]
    local_mirror: Optional[str]
    repository_key_check: bool
    repositories: list[str]
    cacheonly: Cacheonly
    package_manager_trees: list[ConfigTree]

    output_format: OutputFormat
    manifest_format: list[ManifestFormat]
    output: str
    compress_output: Compression
    compress_level: int
    output_dir: Optional[Path]
    workspace_dir: Optional[Path]
    cache_dir: Optional[Path]
    package_cache_dir: Optional[Path]
    build_dir: Optional[Path]
    image_id: Optional[str]
    image_version: Optional[str]
    split_artifacts: bool
    repart_dirs: list[Path]
    sector_size: Optional[int]
    repart_offline: bool
    overlay: bool
    use_subvolumes: ConfigFeature
    seed: Optional[uuid.UUID]

    packages: list[str]
    build_packages: list[str]
    package_directories: list[Path]
    with_recommends: bool
    with_docs: bool

    base_trees: list[Path]
    skeleton_trees: list[ConfigTree]
    extra_trees: list[ConfigTree]

    remove_packages: list[str]
    remove_files: list[str]
    clean_package_metadata: ConfigFeature
    source_date_epoch: Optional[int]

    prepare_scripts: list[Path]
    build_scripts: list[Path]
    postinst_scripts: list[Path]
    finalize_scripts: list[Path]
    build_sources: list[ConfigTree]
    build_sources_ephemeral: bool
    environment: dict[str, str]
    environment_files: list[Path]
    with_tests: bool
    with_network: bool

    bootable: ConfigFeature
    bootloader: Bootloader
    bios_bootloader: BiosBootloader
    shim_bootloader: ShimBootloader
    initrds: list[Path]
    initrd_packages: list[str]
    microcode_host: bool
    kernel_command_line: list[str]
    kernel_modules_include: list[str]
    kernel_modules_exclude: list[str]
    kernel_modules_include_host: bool

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

    autologin: bool
    make_initrd: bool
    ssh: bool
    selinux_relabel: ConfigFeature

    secure_boot: bool
    secure_boot_auto_enroll: bool
    secure_boot_key: Optional[Path]
    secure_boot_certificate: Optional[Path]
    secure_boot_sign_tool: SecureBootSignTool
    verity_key: Optional[Path]
    verity_certificate: Optional[Path]
    sign_expected_pcr: ConfigFeature
    passphrase: Optional[Path]
    checksum: bool
    sign: bool
    key: Optional[str]

    incremental: bool
    nspawn_settings: Optional[Path]
    extra_search_paths: list[Path]
    ephemeral: bool
    credentials: dict[str, str]
    kernel_command_line_extra: list[str]
    acl: bool
    tools_tree: Optional[Path]
    tools_tree_distribution: Optional[Distribution]
    tools_tree_release: Optional[str]
    tools_tree_mirror: Optional[str]
    tools_tree_packages: list[str]
    runtime_trees: list[ConfigTree]
    runtime_size: Optional[int]
    runtime_scratch: ConfigFeature
    ssh_key: Optional[Path]
    ssh_certificate: Optional[Path]

    # QEMU-specific options
    qemu_gui: bool
    qemu_smp: str
    qemu_mem: str
    qemu_kvm: ConfigFeature
    qemu_vsock: ConfigFeature
    qemu_vsock_cid: int
    qemu_swtpm: ConfigFeature
    qemu_cdrom: bool
    qemu_firmware: QemuFirmware
    qemu_firmware_variables: Optional[Path]
    qemu_kernel: Optional[Path]
    qemu_drives: list[QemuDrive]
    qemu_args: list[str]

    image: Optional[str]

    def name(self) -> str:
        return self.image_id or self.image or "default"

    def output_dir_or_cwd(self) -> Path:
        return self.output_dir or Path.cwd()

    def workspace_dir_or_default(self) -> Path:
        if self.workspace_dir:
            return self.workspace_dir

        if (cache := INVOKING_USER.cache_dir()) and cache != Path("/var/cache/mkosi") and os.access(cache, os.W_OK):
            return cache

        return Path("/var/tmp")

    def package_cache_dir_or_default(self) -> Path:
        return (
            self.package_cache_dir or
            (INVOKING_USER.cache_dir() / f"{self.distribution}~{self.release}~{self.architecture}")
        )

    def tools(self) -> Path:
        return self.tools_tree or Path("/")

    @classmethod
    def default(cls) -> "Config":
        """Alternative constructor to generate an all-default MkosiArgs.

        This prevents MkosiArgs being generated with defaults values implicitly.
        """
        with chdir("/"):
            _, [config] = parse_config([])

        return config

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> "Config":
        return cls(**{
            k: v for k, v in vars(ns).items()
            if k in inspect.signature(cls).parameters
        })

    @property
    def output_with_format(self) -> str:
        return self.output + self.output_format.extension()

    @property
    def output_with_compression(self) -> str:
        output = self.output_with_format

        if self.compress_output and self.output_format.use_outer_compression():
            output += self.compress_output.extension()

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

    def cache_manifest(self) -> dict[str, Any]:
        return {
            "distribution": self.distribution,
            "release": self.release,
            "mirror": self.mirror,
            "architecture": self.architecture,
            "packages": self.packages,
            "build_packages": self.build_packages,
            "repositories": self.repositories,
            "overlay": self.overlay,
            "prepare_scripts": [
                base64.b64encode(script.read_bytes()).decode()
                for script in self.prepare_scripts
            ],
            # We don't use the full path here since tests will often use temporary directories for the output directory
            # which would trigger a rebuild every time.
            "tools_tree": self.tools_tree.name if self.tools_tree else None,
            "tools_tree_distribution": self.tools_tree_distribution,
            "tools_tree_release": self.tools_tree_release,
            "tools_tree_mirror": self.tools_tree_mirror,
            "tools_tree_packages": self.tools_tree_packages,
        }

    def to_dict(self) -> dict[str, Any]:
        def key_transformer(k: str) -> str:
            if (s := SETTINGS_LOOKUP_BY_DEST.get(k)) is not None:
                return s.name
            return "".join(p.capitalize() for p in k.split("_"))

        return {key_transformer(k): v for k, v in dataclasses.asdict(self).items()}

    def to_json(self, *, indent: Optional[int] = 4, sort_keys: bool = True) -> str:
        """Dump MkosiConfig as JSON string."""
        return json.dumps(self.to_dict(), cls=JsonEncoder, indent=indent, sort_keys=sort_keys)

    @classmethod
    def _load_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> dict[str, Any]:
        """Load JSON and transform it into a dictionary suitable compatible with instantiating a MkosiConfig object."""
        if isinstance(s, str):
            j = json.loads(s)
        elif isinstance(s, dict):
            j = s
        elif hasattr(s, "read"):
            j = json.load(s)
        else:
            raise ValueError(f"{cls.__name__} can only be constructed from JSON from strings, dictionaries and files.")

        value_transformer = json_type_transformer(cls)
        def key_transformer(k: str) -> str:
            if (s := SETTINGS_LOOKUP_BY_NAME.get(k)) is not None:
                return s.dest
            return "_".join(part.lower() for part in FALLBACK_NAME_TO_DEST_SPLITTER.split(k))

        return {(tk := key_transformer(k)): value_transformer(tk, v) for k, v in j.items()}

    @classmethod
    def from_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "Config":
        """Instantiate a MkosiConfig object from a full JSON dump."""
        j = cls._load_json(s)
        return cls(**j)

    @classmethod
    def from_partial_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "Config":
        """Return a new MkosiConfig with defaults overwritten by the attributes from passed in JSON."""
        j = cls._load_json(s)
        return dataclasses.replace(cls.default(), **j)

    def sandbox(
        self,
        *,
        network: bool = False,
        devices: bool = False,
        relaxed: bool = False,
        scripts: Optional[Path] = None,
        options: Sequence[PathString] = (),
    ) -> list[PathString]:
        mounts: list[PathString] = (
            flatten(("--ro-bind", d, d) for d in self.extra_search_paths)
            if not relaxed and not self.tools_tree
            else []
        )

        return sandbox_cmd(
            network=network,
            devices=devices,
            relaxed=relaxed,
            scripts=scripts,
            tools=self.tools(),
            options=[*options, *mounts],
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
        # Systemd unit files allow both '#' and ';' to indicate comments so we do the same.
        for c in ("#", ";"):
            comment = line.find(c)
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

        if line[0] == '[':
            if line[-1] != ']':
                die(f"{line} is not a valid section")

            # Yield the section name with an empty key and value to indicate we've finished the current section.
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


SETTINGS = (
    ConfigSetting(
        dest="include",
        section="Config",
        parse=config_make_list_parser(
            delimiter=",",
            reset=False,
            parse=make_path_parser(constants=BUILTIN_CONFIGS),
        ),
        help="Include configuration from the specified file or directory",
    ),
    ConfigSetting(
        dest="initrd_include",
        section="Config",
        parse=config_make_list_parser(delimiter=",", reset=False, parse=make_path_parser()),
        help="Include configuration from the specified file or directory when building the initrd",
    ),
    ConfigSetting(
        dest="profile",
        section="Config",
        help="Build the specified profile",
        parse=config_parse_profile,
        match=config_make_string_matcher(),
    ),
    ConfigSetting(
        dest="images",
        compat_names=("Presets",),
        long="--image",
        section="Config",
        parse=config_make_list_parser(delimiter=","),
        help="Specify which images to build",
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
    ),
    ConfigSetting(
        dest="distribution",
        short="-d",
        section="Distribution",
        specifier="d",
        parse=config_make_enum_parser(Distribution),
        match=config_make_enum_matcher(Distribution),
        default_factory=config_default_distribution,
        choices=Distribution.values(),
        help="Distribution to install",
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
    ),
    ConfigSetting(
        dest="architecture",
        section="Distribution",
        specifier="a",
        parse=config_make_enum_parser(Architecture),
        match=config_make_enum_matcher(Architecture),
        default=Architecture.native(),
        choices=Architecture.values(),
        help="Override the architecture of installation",
    ),
    ConfigSetting(
        dest="mirror",
        short="-m",
        section="Distribution",
        help="Distribution mirror to use",
    ),
    ConfigSetting(
        dest="local_mirror",
        section="Distribution",
        help="Use a single local, flat and plain mirror to build the image",
    ),
    ConfigSetting(
        dest="repository_key_check",
        metavar="BOOL",
        nargs="?",
        section="Distribution",
        default=True,
        parse=config_parse_boolean,
        help="Controls signature and key checks on repositories",
    ),
    ConfigSetting(
        dest="repositories",
        metavar="REPOS",
        section="Distribution",
        parse=config_make_list_parser(delimiter=","),
        help="Repositories to use",
    ),
    ConfigSetting(
        dest="cacheonly",
        long="--cache-only",
        name="CacheOnly",
        metavar="CACHEONLY",
        section="Distribution",
        parse=config_make_enum_parser_with_boolean(Cacheonly, yes=Cacheonly.always, no=Cacheonly.none),
        default=Cacheonly.none,
        help="Only use the package cache when installing packages",
    ),
    ConfigSetting(
        dest="package_manager_trees",
        long="--package-manager-tree",
        metavar="PATH",
        section="Distribution",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser()),
        default_factory=lambda ns: ns.skeleton_trees,
        default_factory_depends=("skeleton_trees",),
        help="Use a package manager tree to configure the package manager",
    ),

    ConfigSetting(
        dest="output_format",
        short="-t",
        long="--format",
        metavar="FORMAT",
        name="Format",
        section="Output",
        specifier="t",
        parse=config_make_enum_parser(OutputFormat),
        match=config_make_enum_matcher(OutputFormat),
        default=OutputFormat.disk,
        choices=OutputFormat.values(),
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
        parse=config_parse_output,
        default_factory=config_default_output,
        default_factory_depends=("image_id", "image_version"),
        help="Output name",
    ),
    ConfigSetting(
        dest="compress_output",
        metavar="ALG",
        nargs="?",
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
    ),
    ConfigSetting(
        dest="output_dir",
        short="-O",
        metavar="DIR",
        name="OutputDirectory",
        section="Output",
        specifier="O",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.output",),
        help="Output directory",
    ),
    ConfigSetting(
        dest="workspace_dir",
        metavar="DIR",
        name="WorkspaceDirectory",
        section="Output",
        parse=config_make_path_parser(required=False),
        help="Workspace directory",
    ),
    ConfigSetting(
        dest="cache_dir",
        metavar="PATH",
        name="CacheDirectory",
        section="Output",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.cache",),
        help="Incremental cache directory",
    ),
    ConfigSetting(
        dest="package_cache_dir",
        metavar="PATH",
        name="PackageCacheDirectory",
        section="Output",
        parse=config_make_path_parser(required=False),
        help="Package cache directory",
    ),
    ConfigSetting(
        dest="build_dir",
        metavar="PATH",
        name="BuildDirectory",
        section="Output",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.builddir",),
        help="Path to use as persistent build directory",
    ),
    ConfigSetting(
        dest="image_version",
        match=config_match_version,
        section="Output",
        specifier="v",
        help="Set version for image",
        paths=("mkosi.version",),
        path_read_text=True,
    ),
    ConfigSetting(
        dest="image_id",
        match=config_make_string_matcher(allow_globs=True),
        section="Output",
        specifier="i",
        help="Set ID for image",
    ),
    ConfigSetting(
        dest="split_artifacts",
        metavar="BOOL",
        nargs="?",
        section="Output",
        parse=config_parse_boolean,
        help="Generate split partitions",
    ),
    ConfigSetting(
        dest="repart_dirs",
        long="--repart-dir",
        metavar="PATH",
        name="RepartDirectories",
        section="Output",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        paths=("mkosi.repart",),
        help="Directory containing systemd-repart partition definitions",
    ),
    ConfigSetting(
        dest="sector_size",
        section="Output",
        parse=config_parse_sector_size,
        help="Set the disk image sector size",
    ),
    ConfigSetting(
        dest="repart_offline",
        section="Output",
        parse=config_parse_boolean,
        help="Build disk images without using loopback devices",
        default=True,
    ),
    ConfigSetting(
        dest="overlay",
        metavar="BOOL",
        nargs="?",
        section="Output",
        parse=config_parse_boolean,
        help="Only output the additions on top of the given base trees",
    ),
    ConfigSetting(
        dest="use_subvolumes",
        metavar="FEATURE",
        nargs="?",
        section="Output",
        parse=config_parse_feature,
        help="Use btrfs subvolumes for faster directory operations where possible",
    ),
    ConfigSetting(
        dest="seed",
        metavar="UUID",
        section="Output",
        parse=config_parse_seed,
        help="Set the seed for systemd-repart",
    ),

    ConfigSetting(
        dest="packages",
        short="-p",
        long="--package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Add an additional package to the OS image",
    ),
    ConfigSetting(
        dest="build_packages",
        long="--build-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Additional packages needed for build scripts",
    ),
    ConfigSetting(
        dest="package_directories",
        long="--package-directory",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        help="Specify a directory containing extra packages",
    ),
    ConfigSetting(
        dest="with_recommends",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Install recommended packages",
    ),
    ConfigSetting(
        dest="with_docs",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        default=True,
        help="Install documentation",
    ),
    ConfigSetting(
        dest="base_trees",
        long='--base-tree',
        metavar='PATH',
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
        help='Use the given tree as base tree (e.g. lower sysext layer)',
    ),
    ConfigSetting(
        dest="skeleton_trees",
        long="--skeleton-tree",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser()),
        paths=("mkosi.skeleton", "mkosi.skeleton.tar"),
        path_default=False,
        help="Use a skeleton tree to bootstrap the image before installing anything",
    ),
    ConfigSetting(
        dest="extra_trees",
        long="--extra-tree",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser()),
        paths=("mkosi.extra", "mkosi.extra.tar"),
        path_default=False,
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
    ),
    ConfigSetting(
        dest="prepare_scripts",
        long="--prepare-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        paths=("mkosi.prepare", "mkosi.prepare.chroot"),
        path_default=False,
        help="Prepare script to run inside the image before it is cached",
        compat_names=("PrepareScript",),
    ),
    ConfigSetting(
        dest="build_scripts",
        long="--build-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        paths=("mkosi.build", "mkosi.build.chroot"),
        path_default=False,
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
        paths=("mkosi.postinst", "mkosi.postinst.chroot"),
        path_default=False,
        help="Postinstall script to run inside image",
        compat_names=("PostInstallationScript",),
    ),
    ConfigSetting(
        dest="finalize_scripts",
        long="--finalize-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        paths=("mkosi.finalize", "mkosi.finalize.chroot"),
        path_default=False,
        help="Postinstall script to run outside image",
        compat_names=("FinalizeScript",),
    ),
    ConfigSetting(
        dest="build_sources",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser(absolute=False)),
        match=config_match_build_sources,
        default_factory=lambda ns: [ConfigTree(ns.directory, None)] if ns.directory else [],
        help="Path for sources to build",
    ),
    ConfigSetting(
        dest="build_sources_ephemeral",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="Make build sources ephemeral when running scripts",
    ),
    ConfigSetting(
        dest="environment",
        short="-E",
        metavar="NAME[=VALUE]",
        section="Content",
        parse=config_make_dict_parser(delimiter=" ", parse=parse_environment, unescape=True),
        help="Set an environment variable when running scripts",
    ),
    ConfigSetting(
        dest="environment_files",
        long="--env-file",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        paths=("mkosi.env",),
        path_default=False,
        help="Enviroment files to set when running scripts",
    ),
    ConfigSetting(
        dest="with_tests",
        short="-T",
        long="--without-tests",
        nargs="?",
        const="no",
        section="Content",
        parse=config_parse_boolean,
        default=True,
        help="Do not run tests as part of build scripts, if supported",
    ),
    ConfigSetting(
        dest="with_network",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Run build and postinst scripts with network access (instead of private network)",
    ),
    ConfigSetting(
        dest="bootable",
        metavar="FEATURE",
        nargs="?",
        section="Content",
        parse=config_parse_feature,
        match=config_match_feature,
        help="Generate ESP partition with systemd-boot and UKIs for installed kernels",
    ),
    ConfigSetting(
        dest="bootloader",
        metavar="BOOTLOADER",
        section="Content",
        parse=config_make_enum_parser(Bootloader),
        choices=Bootloader.values(),
        default=Bootloader.systemd_boot,
        help="Specify which UEFI bootloader to use",
    ),
    ConfigSetting(
        dest="bios_bootloader",
        metavar="BOOTLOADER",
        section="Content",
        parse=config_make_enum_parser(BiosBootloader),
        choices=BiosBootloader.values(),
        default=BiosBootloader.none,
        help="Specify which BIOS bootloader to use",
    ),
    ConfigSetting(
        dest="shim_bootloader",
        metavar="BOOTLOADER",
        section="Content",
        parse=config_make_enum_parser(ShimBootloader),
        choices=ShimBootloader.values(),
        default=ShimBootloader.none,
        help="Specify whether to use shim",
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
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        default=False,
        help="Only include the host CPU's microcode",
    ),
    ConfigSetting(
        dest="initrd_packages",
        long="--initrd-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Add additional packages to the default initrd",
    ),
    ConfigSetting(
        dest="kernel_command_line",
        metavar="OPTIONS",
        section="Content",
        parse=config_make_list_parser(delimiter=" "),
        default_factory_depends=("architecture",),
        default_factory=config_default_kernel_command_line,
        help="Set the kernel command line (only bootable images)",
    ),
    ConfigSetting(
        dest="kernel_modules_include",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Include the specified kernel modules in the image",
    ),
    ConfigSetting(
        dest="kernel_modules_include_host",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="Include the currently loaded modules on the host in the image",
    ),
    ConfigSetting(
        dest="kernel_modules_exclude",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Exclude the specified kernel modules from the image",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        default=True,
        help="When building a bootable image, add an extra initrd containing the kernel modules",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd_include",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="When building a kernel modules initrd, include the specified kernel modules",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd_include_host",
        metavar="BOOL",
        section="Content",
        parse=config_parse_boolean,
        help="When building a kernel modules initrd, include the currently loaded modules on the host in the image",
    ),
    ConfigSetting(
        dest="kernel_modules_initrd_exclude",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="When building a kernel modules initrd, exclude the specified kernel modules",
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
        paths=("mkosi.rootpw",),
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
        dest="autologin",
        short="-a",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Enable root autologin",
    ),
    ConfigSetting(
        dest="make_initrd",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Make sure the image can be used as an initramfs",
    ),
    ConfigSetting(
        dest="ssh",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
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

    ConfigSetting(
        dest="secure_boot",
        metavar="BOOL",
        nargs="?",
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
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(secret=True),
        paths=("mkosi.key",),
        help="UEFI SecureBoot private key in PEM format",
    ),
    ConfigSetting(
        dest="secure_boot_certificate",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(),
        paths=("mkosi.crt",),
        help="UEFI SecureBoot certificate in X509 format",
    ),
    ConfigSetting(
        dest="secure_boot_sign_tool",
        metavar="TOOL",
        section="Validation",
        parse=config_make_enum_parser(SecureBootSignTool),
        default=SecureBootSignTool.auto,
        choices=SecureBootSignTool.values(),
        help="Tool to use for signing PE binaries for secure boot",
    ),
    ConfigSetting(
        dest="verity_key",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(secret=True),
        paths=("mkosi.key",),
        help="Private key for signing verity signature in PEM format",
    ),
    ConfigSetting(
        dest="verity_certificate",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(),
        paths=("mkosi.crt",),
        help="Certificate for signing verity signature in X509 format",
    ),
    ConfigSetting(
        dest="sign_expected_pcr",
        metavar="FEATURE",
        section="Validation",
        parse=config_parse_feature,
        help="Measure the components of the unified kernel image (UKI) and embed the PCR signature into the UKI",
    ),
    ConfigSetting(
        dest="passphrase",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(required=False, secret=True),
        paths=("mkosi.passphrase",),
        help="Path to a file containing the passphrase to use when LUKS encryption is selected",
    ),
    ConfigSetting(
        dest="checksum",
        metavar="BOOL",
        nargs="?",
        section="Validation",
        parse=config_parse_boolean,
        help="Write SHA256SUMS file",
    ),
    ConfigSetting(
        dest="sign",
        metavar="BOOL",
        nargs="?",
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
        dest="incremental",
        short="-i",
        metavar="BOOL",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Make use of and generate intermediary cache images",
    ),
    ConfigSetting(
        dest="nspawn_settings",
        name="NSpawnSettings",
        long="--settings",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(),
        paths=("mkosi.nspawn",),
        help="Add in .nspawn settings file",
    ),
    ConfigSetting(
        dest="extra_search_paths",
        long="--extra-search-path",
        metavar="PATH",
        section="Host",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        help="List of comma-separated paths to look for programs before looking in PATH",
    ),
    ConfigSetting(
        dest="ephemeral",
        metavar="BOOL",
        section="Host",
        parse=config_parse_boolean,
        help=('If specified, the container/VM is run with a temporary snapshot of the output '
                'image that is removed immediately when the container/VM terminates'),
        nargs="?",
    ),
    ConfigSetting(
        dest="credentials",
        long="--credential",
        metavar="NAME=VALUE",
        section="Host",
        parse=config_make_dict_parser(delimiter=" ", parse=parse_credential, unescape=True),
        help="Pass a systemd credential to systemd-nspawn or qemu",
    ),
    ConfigSetting(
        dest="kernel_command_line_extra",
        metavar="OPTIONS",
        section="Host",
        parse=config_make_list_parser(delimiter=" "),
        help="Append extra entries to the kernel command line when booting the image",
    ),
    ConfigSetting(
        dest="acl",
        metavar="BOOL",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Set ACLs on generated directories to permit the user running mkosi to remove them",
    ),
    ConfigSetting(
        dest="tools_tree",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(required=False, constants=("default",)),
        paths=("mkosi.tools",),
        help="Look up programs to execute inside the given tree",
    ),
    ConfigSetting(
        dest="tools_tree_distribution",
        metavar="DISTRIBUTION",
        section="Host",
        parse=config_make_enum_parser(Distribution),
        default_factory_depends=("distribution",),
        default_factory=lambda ns: ns.distribution.default_tools_tree_distribution(),
        help="Set the distribution to use for the default tools tree",
    ),
    ConfigSetting(
        dest="tools_tree_release",
        metavar="RELEASE",
        section="Host",
        parse=config_parse_string,
        default_factory_depends=("tools_tree_distribution",),
        default_factory=lambda ns: d.default_release() if (d := ns.tools_tree_distribution) else None,
        help="Set the release to use for the default tools tree",
    ),
    ConfigSetting(
        dest="tools_tree_mirror",
        metavar="MIRROR",
        section="Host",
        default_factory_depends=("distribution", "tools_tree_distribution"),
        default_factory=lambda ns: ns.mirror if ns.mirror and ns.distribution == ns.tools_tree_distribution else None,
        help="Set the mirror to use for the default tools tree",
    ),
    ConfigSetting(
        dest="tools_tree_packages",
        long="--tools-tree-package",
        metavar="PACKAGE",
        section="Host",
        parse=config_make_list_parser(delimiter=","),
        help="Add additional packages to the default tools tree",
    ),
    ConfigSetting(
        dest="runtime_trees",
        long="--runtime-tree",
        metavar="SOURCE:[TARGET]",
        section="Host",
        parse=config_make_list_parser(delimiter=",", parse=make_tree_parser(absolute=False)),
        help="Additional mounts to add when booting the image",
    ),
    ConfigSetting(
        dest="runtime_size",
        metavar="SIZE",
        section="Host",
        parse=config_parse_bytes,
        help="Grow disk images to the specified size before booting them",
    ),
    ConfigSetting(
        dest="runtime_scratch",
        metavar="FEATURE",
        section="Host",
        parse=config_parse_feature,
        help="Mount extra scratch space to /var/tmp",
    ),
    ConfigSetting(
        dest="ssh_key",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(secret=True),
        paths=("mkosi.key",),
        help="Private key for use with mkosi ssh in PEM format",
    ),
    ConfigSetting(
        dest="ssh_certificate",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(),
        paths=("mkosi.crt",),
        help="Certificate for use with mkosi ssh in X509 format",
    ),
    ConfigSetting(
        dest="qemu_gui",
        metavar="BOOL",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Start QEMU in graphical mode",
    ),
    ConfigSetting(
        dest="qemu_smp",
        metavar="SMP",
        section="Host",
        default="1",
        help="Configure guest's SMP settings",
    ),
    ConfigSetting(
        dest="qemu_mem",
        metavar="MEM",
        section="Host",
        default="2G",
        help="Configure guest's RAM size",
    ),
    ConfigSetting(
        dest="qemu_kvm",
        metavar="FEATURE",
        nargs="?",
        section="Host",
        parse=config_parse_feature,
        help="Configure whether to use KVM or not",
    ),
    ConfigSetting(
        dest="qemu_vsock",
        metavar="FEATURE",
        nargs="?",
        section="Host",
        parse=config_parse_feature,
        help="Configure whether to use qemu with a vsock or not",
    ),
    ConfigSetting(
        dest="qemu_vsock_cid",
        name="QemuVsockConnectionId",
        long="--qemu-vsock-cid",
        metavar="NUMBER|auto|hash",
        section="Host",
        parse=config_parse_vsock_cid,
        default=QemuVsockCID.hash,
        help="Specify the VSock connection ID to use",
    ),
    ConfigSetting(
        dest="qemu_swtpm",
        metavar="FEATURE",
        nargs="?",
        section="Host",
        parse=config_parse_feature,
        help="Configure whether to use qemu with swtpm or not",
    ),
    ConfigSetting(
        dest="qemu_cdrom",
        metavar="BOOLEAN",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Attach the image as a CD-ROM to the virtual machine",
    ),
    ConfigSetting(
        dest="qemu_firmware",
        metavar="FIRMWARE",
        section="Host",
        parse=config_make_enum_parser(QemuFirmware),
        default=QemuFirmware.auto,
        help="Set qemu firmware to use",
        choices=QemuFirmware.values(),
    ),
    ConfigSetting(
        dest="qemu_firmware_variables",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(),
        help="Set the path to the qemu firmware variables file to use",
    ),
    ConfigSetting(
        dest="qemu_kernel",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(),
        help="Specify the kernel to use for qemu direct kernel boot",
    ),
    ConfigSetting(
        dest="qemu_drives",
        long="--qemu-drive",
        metavar="DRIVE",
        section="Host",
        parse=config_make_list_parser(delimiter=" ", parse=parse_drive),
        help="Specify a qemu drive that mkosi should create and pass to qemu",
    ),
    ConfigSetting(
        dest="qemu_args",
        metavar="ARGS",
        section="Host",
        parse=config_make_list_parser(delimiter=" "),
        # Suppress the command line option because it's already possible to pass qemu args as normal
        # arguments.
        help=argparse.SUPPRESS,
    ),
)
SETTINGS_LOOKUP_BY_NAME = {name: s for s in SETTINGS for name in [s.name, *s.compat_names]}
SETTINGS_LOOKUP_BY_DEST = {s.dest: s for s in SETTINGS}
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
)

MATCH_LOOKUP = {m.name: m for m in MATCHES}

# This regular expression can be used to split "AutoBump" -> ["Auto", "Bump"]
# and "NSpawnSettings" -> ["NSpawn", "Settings"]
# The first part (?<=[a-z]) is a positive look behind for a lower case letter
# and (?=[A-Z]) is a lookahead assertion matching an upper case letter but not
# consuming it
FALLBACK_NAME_TO_DEST_SPLITTER = re.compile("(?<=[a-z])(?=[A-Z])")


def create_argument_parser(action: type[argparse.Action]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mkosi",
        description="Build Bespoke OS Images",
        # the synopsis below is supposed to be indented by two spaces
        usage="\n  " + textwrap.dedent("""\
              mkosi [options...] {b}summary{e}
                mkosi [options...] {b}build{e}       [command line...]
                mkosi [options...] {b}shell{e}       [command line...]
                mkosi [options...] {b}boot{e}        [nspawn settings...]
                mkosi [options...] {b}qemu{e}        [qemu parameters...]
                mkosi [options...] {b}ssh{e}         [command line...]
                mkosi [options...] {b}journalctl{e}  [command line...]
                mkosi [options...] {b}coredumpctl{e} [command line...]
                mkosi [options...] {b}clean{e}
                mkosi [options...] {b}serve{e}
                mkosi [options...] {b}bump{e}
                mkosi [options...] {b}genkey{e}
                mkosi [options...] {b}documentation{e}
                mkosi [options...] {b}help{e}
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
        "-f", "--force",
        action="count",
        dest="force",
        default=0,
        help="Remove existing image file before operation",
    )
    parser.add_argument(
        "-C", "--directory",
        type=parse_chdir,
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
        default="mkosi of %u",
    )
    parser.add_argument(
        "-B", "--auto-bump",
        help="Automatically bump image version after building",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--doc-format",
        help="The format to show documentation in",
        default=DocFormat.auto,
        type=DocFormat,
    )
    parser.add_argument(
        "--json",
        help="Show summary as JSON",
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
    parser.add_argument(
        "--default",
        action=IgnoreAction,
    )
    parser.add_argument(
        "--cache",
        action=IgnoreAction,
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
        action=PagerHelpAction,
        help=argparse.SUPPRESS,
    )

    last_section = None

    for s in SETTINGS:
        if s.section != last_section:
            group = parser.add_argument_group(f"{s.section} configuration options")
            last_section = s.section

        opts = [s.short, s.long] if s.short else [s.long]

        group.add_argument(    # type: ignore
            *opts,
            dest=s.dest,
            choices=s.choices,
            metavar=s.metavar,
            nargs=s.nargs,     # type: ignore
            const=s.const,
            help=s.help,
            action=action,
        )


    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    return parser


def resolve_deps(images: Sequence[argparse.Namespace], include: Sequence[str]) -> list[argparse.Namespace]:
    graph = {config.image: config.dependencies for config in images}

    if include:
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


def parse_config(argv: Sequence[str] = (), *, resources: Path = Path("/")) -> tuple[Args, tuple[Config, ...]]:
    # Compare inodes instead of paths so we can't get tricked by bind mounts and such.
    parsed_includes: set[tuple[int, int]] = set()
    immutable_settings: set[str] = set()

    def expand_specifiers(text: str, namespace: argparse.Namespace, defaults: argparse.Namespace) -> str:
        percent = False
        result: list[str] = []

        for c in text:
            if percent:
                percent = False

                if c == "%":
                    result += "%"
                else:
                    s = SETTINGS_LOOKUP_BY_SPECIFIER.get(c)
                    if not s:
                        logging.warning(f"Unknown specifier '%{c}' found in {text}, ignoring")
                        continue

                    if (v := finalize_default(s, namespace, defaults)) is None:
                        logging.warning(
                            f"Setting {s.name} specified by specifier '%{c}' in {text} is not yet set, ignoring"
                        )
                        continue

                    result += str(v)
            elif c == "%":
                percent = True
            else:
                result += c

        if percent:
            result += "%"

        return "".join(result)

    @contextlib.contextmanager
    def parse_new_includes(
        namespace: argparse.Namespace,
        defaults: argparse.Namespace,
    ) -> Iterator[None]:
        current_num_of_includes = len(getattr(namespace, "include", []))

        try:
            yield
        finally:
            # Parse any includes that were added after yielding.
            for p in getattr(namespace, "include", [])[current_num_of_includes:]:
                for c in BUILTIN_CONFIGS:
                    if p == Path(c):
                        path = resources / c
                        break
                else:
                    path = p

                st = path.stat()

                if (st.st_dev, st.st_ino) in parsed_includes:
                    continue

                if any(p == Path(c) for c in BUILTIN_CONFIGS):
                    _, [config] = parse_config(["--include", os.fspath(path)])
                    make_executable(
                        *config.prepare_scripts,
                        *config.postinst_scripts,
                        *config.finalize_scripts,
                        *config.build_scripts,
                    )

                with chdir(path if path.is_dir() else Path.cwd()):
                    parse_config_one(path if path.is_file() else Path("."), namespace, defaults)
                parsed_includes.add((st.st_dev, st.st_ino))

    class ConfigAction(argparse.Action):
        def __call__(
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: Union[str, Sequence[Any], None],
            option_string: Optional[str] = None
        ) -> None:
            assert option_string is not None

            if values is None and self.nargs == "?":
                values = self.const or "yes"

            try:
                s = SETTINGS_LOOKUP_BY_DEST[self.dest]
            except KeyError:
                die(f"Unknown setting {option_string}")

            with parse_new_includes(namespace, defaults):
                if values is None or isinstance(values, str):
                    setattr(namespace, s.dest, s.parse(values, getattr(namespace, self.dest, None)))
                else:
                    for v in values:
                        assert isinstance(v, str)
                        setattr(namespace, s.dest, s.parse(v, getattr(namespace, self.dest, None)))

    def finalize_default(
        setting: ConfigSetting,
        namespace: argparse.Namespace,
        defaults: argparse.Namespace
    ) -> Optional[Any]:
        if (v := getattr(namespace, setting.dest, None)) is not None:
            return v

        for d in setting.default_factory_depends:
            finalize_default(SETTINGS_LOOKUP_BY_DEST[d], namespace, defaults)

        # If the setting was assigned the empty string, we don't use any configured default value.
        if not hasattr(namespace, setting.dest) and setting.dest in defaults:
            default = getattr(defaults, setting.dest)
        elif setting.default_factory:
            default = setting.default_factory(namespace)
        elif setting.default is None:
            default = setting.parse(None, None)
        else:
            default = setting.default

        with parse_new_includes(namespace, defaults):
            setattr(namespace, setting.dest, default)

        return default

    def match_config(path: Path, namespace: argparse.Namespace, defaults: argparse.Namespace) -> bool:
        condition_triggered: Optional[bool] = None
        match_triggered: Optional[bool] = None
        skip = False

        # If the config file does not exist, we assume it matches so that we look at the other files in the
        # directory as well (mkosi.conf.d/ and extra files).
        if not path.exists():
            return True

        for section, k, v in parse_ini(path, only_sections=["Match", "TriggerMatch"]):
            if not k and not v:
                if section == "Match" and condition_triggered is False:
                    return False

                if section == "TriggerMatch":
                    match_triggered = bool(match_triggered) or condition_triggered is not False

                condition_triggered = None
                skip = False
                continue

            if skip:
                continue

            trigger = v.startswith("|")
            v = v.removeprefix("|")
            negate = v.startswith("!")
            v = v.removeprefix("!")

            v = expand_specifiers(v, namespace, defaults)

            if not v:
                die("Match value cannot be empty")

            if s := SETTINGS_LOOKUP_BY_NAME.get(k):
                if not s.match:
                    die(f"{k} cannot be used in [{section}]")

                if k != s.name:
                    logging.warning(f"Setting {k} is deprecated, please use {s.name} instead.")

                # If we encounter a setting that has not been explicitly configured yet, we assign the default value
                # first so that we can match on default values for settings.
                if finalize_default(s, namespace, defaults) is None:
                    result = False
                else:
                    result = s.match(v, getattr(namespace, s.dest))

            elif m := MATCH_LOOKUP.get(k):
                result = m.match(v)
            else:
                die(f"{k} cannot be used in [{section}]")

            if negate:
                result = not result
            if not trigger and not result:
                if section == "TriggerMatch":
                    skip = True
                    condition_triggered = False
                    continue

                return False
            if trigger:
                condition_triggered = bool(condition_triggered) or result

        return match_triggered is not False

    def parse_config_one(
        path: Path,
        namespace: argparse.Namespace,
        defaults: argparse.Namespace,
        profiles: bool = False,
    ) -> bool:
        s: Optional[ConfigSetting] # Make mypy happy
        extras = path.is_dir()

        if path.is_dir():
            path = path / "mkosi.conf"

        if not match_config(path, namespace, defaults):
            return False

        if extras:
            if (path.parent / "mkosi.local.conf").exists():
                parse_config_one(path.parent / "mkosi.local.conf", namespace, defaults)

            for s in SETTINGS:
                ns = defaults if s.path_default else namespace
                for f in s.paths:
                    p = parse_path(
                        f,
                        secret=s.path_secret,
                        required=False,
                        resolve=False,
                        expanduser=False,
                        expandvars=False,
                    )
                    if p.exists():
                        setattr(
                            ns,
                            s.dest,
                            s.parse(p.read_text().rstrip("\n") if s.path_read_text else f, getattr(ns, s.dest, None)),
                        )

        if path.exists():
            logging.debug(f"Including configuration file {Path.cwd() / path}")

            for section, k, v in parse_ini(path, only_sections={s.section for s in SETTINGS} | {"Preset"}):
                if not k and not v:
                    continue

                name = k.removeprefix("@")
                ns = namespace if k == name else defaults

                if not (s := SETTINGS_LOOKUP_BY_NAME.get(name)):
                    die(f"Unknown setting {k}")
                if name in immutable_settings:
                    die(f"Setting {name} cannot be modified anymore at this point")

                if section != s.section:
                    logging.warning(f"Setting {k} should be configured in [{s.section}], not [{section}].")

                if name != s.name:
                    canonical = s.name if k == name else f"@{s.name}"
                    logging.warning(f"Setting {k} is deprecated, please use {canonical} instead.")

                v = expand_specifiers(v, namespace, defaults)

                with parse_new_includes(namespace, defaults):
                    setattr(ns, s.dest, s.parse(v, getattr(ns, s.dest, None)))

        if profiles:
            finalize_default(SETTINGS_LOOKUP_BY_DEST["profile"], namespace, defaults)
            profile = getattr(namespace, "profile")
            immutable_settings.add("Profile")

            if profile:
                for p in (profile, f"{profile}.conf"):
                    p = Path("mkosi.profiles") / p
                    if p.exists():
                        break
                else:
                    die(f"Profile '{profile}' not found in mkosi.profiles/")

                setattr(namespace, "profile", profile)

                with chdir(p if p.is_dir() else Path.cwd()):
                    parse_config_one(p if p.is_file() else Path("."), namespace, defaults)

        if extras and (path.parent / "mkosi.conf.d").exists():
            for p in sorted((path.parent / "mkosi.conf.d").iterdir()):
                if p.is_dir() or p.suffix == ".conf":
                    with chdir(p if p.is_dir() else Path.cwd()):
                        parse_config_one(p if p.is_file() else Path("."), namespace, defaults)

        return True

    def finalize_defaults(namespace: argparse.Namespace, defaults: argparse.Namespace) -> None:
        for s in SETTINGS:
            finalize_default(s, namespace, defaults)

    images = []
    namespace = argparse.Namespace()
    defaults = argparse.Namespace()

    argv = list(argv)

    # Make sure the verb command gets explicitly passed. Insert a -- before the positional verb argument
    # otherwise it might be considered as an argument of a parameter with nargs='?'. For example mkosi -i
    # summary would be treated as -i=summary.
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

    namespace = argparse.Namespace()
    argparser = create_argument_parser(ConfigAction)
    argparser.parse_args(argv, namespace)
    cli_ns = copy.deepcopy(namespace)

    args = load_args(namespace)

    if ARG_DEBUG.get():
        logging.getLogger().setLevel(logging.DEBUG)

    if args.verb == Verb.help:
        PagerHelpAction.__call__(None, argparser, namespace)  # type: ignore

    include = ()

    if args.directory is not None:
        parse_config_one(Path("."), namespace, defaults, profiles=True)

        finalize_default(SETTINGS_LOOKUP_BY_DEST["images"], namespace, defaults)
        include = getattr(namespace, "images")
        immutable_settings.add("Images")

        d: Optional[Path]
        for d in (Path("mkosi.images"), Path("mkosi.presets")):
            if Path(d).exists():
                break
        else:
            d = None

        if d:
            for p in d.iterdir():
                if not p.is_dir() and not p.suffix == ".conf":
                    continue

                name = p.name.removesuffix(".conf")
                if not name:
                    die(f"{p} is not a valid image name")

                ns_copy = copy.deepcopy(namespace)
                defaults_copy = copy.deepcopy(defaults)

                setattr(ns_copy, "image", name)

                with chdir(p if p.is_dir() else Path.cwd()):
                    if not parse_config_one(p if p.is_file() else Path("."), ns_copy, defaults_copy):
                        continue

                finalize_defaults(ns_copy, defaults_copy)
                images += [ns_copy]

    if not images:
        setattr(namespace, "image", None)
        finalize_defaults(namespace, defaults)
        images = [namespace]

    for s in vars(cli_ns):
        if s not in SETTINGS_LOOKUP_BY_DEST:
            continue

        if getattr(cli_ns, s) is None:
            continue

        if isinstance(getattr(cli_ns, s), (list, tuple)):
            continue

        if any(getattr(config, s) == getattr(cli_ns, s) for config in images):
            continue

        setting = SETTINGS_LOOKUP_BY_DEST[s].long
        a = getattr(cli_ns, s)
        die(
            f"{setting}={a} was specified on the command line but is not allowed to be configured by any images.",
            hint="Prefix the setting with '@' in the image configuration file to allow overriding it from the command line.", # noqa: E501
        )

    if not images:
        die("No images defined in mkosi.images/")

    images = resolve_deps(images, include)
    images = [load_config(args, ns) for ns in images]

    return args, tuple(images)


def load_credentials(args: argparse.Namespace) -> dict[str, str]:
    if not args.verb.needs_credentials():
        return {}

    creds = {
        "agetty.autologin": "root",
        "login.noauth": "yes",
    }

    d = Path("mkosi.credentials")
    if args.directory is not None and d.is_dir():
        for e in d.iterdir():
            if os.access(e, os.X_OK):
                creds[e.name] = run([e], stdout=subprocess.PIPE, env=os.environ).stdout
            else:
                creds[e.name] = e.read_text()

    creds |= args.credentials

    if "firstboot.timezone" not in creds and find_binary("timedatectl"):
        tz = run(
            ["timedatectl", "show", "-p", "Timezone", "--value"],
            stdout=subprocess.PIPE,
            check=False,
        ).stdout.strip()
        if tz:
            creds["firstboot.timezone"] = tz

    if "firstboot.locale" not in creds:
        creds["firstboot.locale"] = "C.UTF-8"

    if "ssh.authorized_keys.root" not in creds:
        if args.ssh_certificate:
            pubkey = run(["openssl", "x509", "-in", args.ssh_certificate, "-pubkey", "-noout"],
                          stdout=subprocess.PIPE, env=dict(OPENSSL_CONF="/dev/null")).stdout.strip()
            sshpubkey = run(["ssh-keygen", "-f", "/dev/stdin", "-i", "-m", "PKCS8"],
                            input=pubkey, stdout=subprocess.PIPE).stdout.strip()
            creds["ssh.authorized_keys.root"] = sshpubkey
        elif args.ssh:
            die("Ssh= is enabled but no SSH certificate was found",
                hint="Run 'mkosi genkey' to automatically create one")

    return creds


def load_kernel_command_line_extra(args: argparse.Namespace) -> list[str]:
    tty = args.architecture.default_serial_tty()
    columns, lines = shutil.get_terminal_size()
    cmdline = [
        # Make sure we set up networking in the VM/container.
        "systemd.wants=network.target",
        # Make sure we don't load vmw_vmci which messes with virtio vsock.
        "module_blacklist=vmw_vmci",
        f"systemd.tty.term.{tty}={os.getenv('TERM', 'vt220')}",
        f"systemd.tty.columns.{tty}={columns}",
        f"systemd.tty.rows.{tty}={lines}",
    ]

    if not any(s.startswith("ip=") for s in args.kernel_command_line_extra):
        cmdline += ["ip=enc0:any", "ip=enp0s1:any", "ip=enp0s2:any", "ip=host0:any", "ip=none"]

    if not any(s.startswith("loglevel=") for s in args.kernel_command_line_extra):
        cmdline += ["loglevel=4"]

    if not any(s.startswith("SYSTEMD_SULOGIN_FORCE=") for s in args.kernel_command_line_extra):
        cmdline += ["SYSTEMD_SULOGIN_FORCE=1"]

    if args.qemu_cdrom:
        # CD-ROMs are read-only so tell systemd to boot in volatile mode.
        cmdline += ["systemd.volatile=yes"]

    if not args.qemu_gui:
        columns, lines = shutil.get_terminal_size()
        cmdline += [
            f"systemd.tty.term.console={os.getenv('TERM', 'vt220')}",
            f"systemd.tty.columns.console={columns}",
            f"systemd.tty.rows.console={lines}",
            f"console={tty}",
        ]

    for s in args.kernel_command_line_extra:
        key, sep, value = s.partition("=")
        if " " in value:
            value = f'"{value}"'
        cmdline += [key if not sep else f"{key}={value}"]

    return cmdline


def load_environment(args: argparse.Namespace) -> dict[str, str]:
    env = {
        "SYSTEMD_TMPFILES_FORCE_SUBVOL": "0",
        "KERNEL_INSTALL_BYPASS": "1",
        "SYSTEMD_HWDB_UPDATE_BYPASS": "1",
    }

    if args.image_id is not None:
        env["IMAGE_ID"] = args.image_id
    if args.image_version is not None:
        env["IMAGE_VERSION"] = args.image_version
    if args.source_date_epoch is not None:
        env["SOURCE_DATE_EPOCH"] = str(args.source_date_epoch)
    if proxy := os.getenv("http_proxy"):
        env["http_proxy"] = proxy
    if proxy := os.getenv("https_proxy"):
        env["https_proxy"] = proxy
    if dnf := os.getenv("MKOSI_DNF"):
        env["MKOSI_DNF"] = dnf

    env |= dict(parse_environment(line) for f in args.environment_files for line in f.read_text().strip().splitlines())
    env |= args.environment

    return env


def load_args(args: argparse.Namespace) -> Args:
    if args.cmdline and not args.verb.supports_cmdline():
        die(f"Arguments after verb are not supported for {args.verb}.")

    if args.debug:
        ARG_DEBUG.set(args.debug)
    if args.debug_shell:
        ARG_DEBUG_SHELL.set(args.debug_shell)

    return Args.from_namespace(args)


def load_config(args: Args, config: argparse.Namespace) -> Config:
    if config.build_dir:
        config.build_dir = config.build_dir / f"{config.distribution}~{config.release}~{config.architecture}"

    if config.sign:
        config.checksum = True

    config.credentials = load_credentials(config)
    config.kernel_command_line_extra = load_kernel_command_line_extra(config)
    config.environment = load_environment(config)

    if config.secure_boot and args.verb != Verb.genkey:
        if config.secure_boot_key is None and config.secure_boot_certificate is None:
            die("UEFI SecureBoot enabled, but couldn't find the certificate and private key.",
                hint="Consider generating them with 'mkosi genkey'.")
        if config.secure_boot_key is None:
            die("UEFI SecureBoot enabled, certificate was found, but not the private key.",
                hint="Consider placing it in mkosi.key")
        if config.secure_boot_certificate is None:
            die("UEFI SecureBoot enabled, private key was found, but not the certificate.",
                hint="Consider placing it in mkosi.crt")

    if config.repositories and not (
        config.distribution.is_dnf_distribution() or
        config.distribution.is_apt_distribution() or
        config.distribution == Distribution.arch
    ):
        die("Sorry, the --repositories option is only supported on pacman, dnf and apt based distributions")

    if config.overlay and not config.base_trees:
        die("--overlay can only be used with --base-tree")

    if config.incremental and not config.cache_dir:
        die("A cache directory must be configured in order to use --incremental")

    # For unprivileged builds we need the userxattr OverlayFS mount option, which is only available
    # in Linux v5.11 and later.
    if (
        (config.build_scripts or config.base_trees) and
        GenericVersion(platform.release()) < GenericVersion("5.11") and
        os.geteuid() != 0
    ):
        die("This unprivileged build configuration requires at least Linux v5.11")

    return Config.from_namespace(config)


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


def line_join_list(array: Iterable[PathString]) -> str:
    if not array:
        return "none"

    items = (str(none_to_none(cast(Path, item))) for item in array)
    return "\n                                     ".join(items)


def format_tree(tree: ConfigTree) -> str:
    return f"{tree.source}:{tree.target}" if tree.target else f"{tree.source}"


def line_join_tree_list(array: Sequence[ConfigTree]) -> str:
    if not array:
        return "none"

    items = [format_tree(tree) for tree in array]
    return "\n                                     ".join(items)


def format_bytes(num_bytes: int) -> str:
    if num_bytes >= 1024**3:
        return f"{num_bytes/1024**3 :0.1f}G"
    if num_bytes >= 1024**2:
        return f"{num_bytes/1024**2 :0.1f}M"
    if num_bytes >= 1024:
        return f"{num_bytes/1024 :0.1f}K"

    return f"{num_bytes}B"


def format_bytes_or_none(num_bytes: Optional[int]) -> str:
    return format_bytes(num_bytes) if num_bytes is not None else "none"


def summary(config: Config) -> str:
    def bold(s: Any) -> str:
        return f"{Style.bold}{s}{Style.reset}"

    maniformats = (" ".join(i.name for i in config.manifest_format)) or "(none)"
    env = [f"{k}={v}" for k, v in config.environment.items()]

    summary = f"""\
{bold(f"IMAGE: {config.image or 'default'}")}

    {bold("CONFIG")}:
                            Profile: {none_to_none(config.profile)}
                            Include: {line_join_list(config.include)}
                     Initrd Include: {line_join_list(config.initrd_include)}
                             Images: {line_join_list(config.images)}
                       Dependencies: {line_join_list(config.dependencies)}
                    Minimum Version: {none_to_none(config.minimum_version)}

    {bold("DISTRIBUTION")}:
                       Distribution: {bold(config.distribution)}
                            Release: {bold(none_to_na(config.release))}
                       Architecture: {config.architecture}
                             Mirror: {none_to_default(config.mirror)}
               Local Mirror (build): {none_to_none(config.local_mirror)}
           Repo Signature/Key check: {yes_no(config.repository_key_check)}
                       Repositories: {line_join_list(config.repositories)}
             Use Only Package Cache: {config.cacheonly}
              Package Manager Trees: {line_join_tree_list(config.package_manager_trees)}

    {bold("OUTPUT")}:
                      Output Format: {config.output_format}
                   Manifest Formats: {maniformats}
                             Output: {bold(config.output_with_compression)}
                        Compression: {config.compress_output}
                  Compression Level: {config.compress_level}
                   Output Directory: {config.output_dir_or_cwd()}
                Workspace Directory: {config.workspace_dir_or_default()}
                    Cache Directory: {none_to_none(config.cache_dir)}
            Package Cache Directory: {none_to_default(config.package_cache_dir)}
                    Build Directory: {none_to_none(config.build_dir)}
                           Image ID: {config.image_id}
                      Image Version: {config.image_version}
                    Split Artifacts: {yes_no(config.split_artifacts)}
                 Repart Directories: {line_join_list(config.repart_dirs)}
                        Sector Size: {none_to_default(config.sector_size)}
                     Repart Offline: {yes_no(config.repart_offline)}
                            Overlay: {yes_no(config.overlay)}
                     Use Subvolumes: {config.use_subvolumes}
                               Seed: {none_to_random(config.seed)}

    {bold("CONTENT")}:
                           Packages: {line_join_list(config.packages)}
                     Build Packages: {line_join_list(config.build_packages)}
                 With Documentation: {yes_no(config.with_docs)}

                         Base Trees: {line_join_list(config.base_trees)}
                     Skeleton Trees: {line_join_tree_list(config.skeleton_trees)}
                        Extra Trees: {line_join_tree_list(config.extra_trees)}

                    Remove Packages: {line_join_list(config.remove_packages)}
                       Remove Files: {line_join_list(config.remove_files)}
     Clean Package Manager Metadata: {config.clean_package_metadata}
                  Source Date Epoch: {none_to_none(config.source_date_epoch)}

                    Prepare Scripts: {line_join_list(config.prepare_scripts)}
                      Build Scripts: {line_join_list(config.build_scripts)}
                Postinstall Scripts: {line_join_list(config.postinst_scripts)}
                   Finalize Scripts: {line_join_list(config.finalize_scripts)}
                      Build Sources: {line_join_tree_list(config.build_sources)}
            Build Sources Ephemeral: {yes_no(config.build_sources_ephemeral)}
                 Script Environment: {line_join_list(env)}
                  Environment Files: {line_join_list(config.environment_files)}
         Run Tests in Build Scripts: {yes_no(config.with_tests)}
               Scripts With Network: {yes_no(config.with_network)}

                           Bootable: {config.bootable}
                         Bootloader: {config.bootloader}
                    BIOS Bootloader: {config.bios_bootloader}
                    Shim Bootloader: {config.shim_bootloader}
                            Initrds: {line_join_list(config.initrds)}
                    Initrd Packages: {line_join_list(config.initrd_packages)}
                Kernel Command Line: {line_join_list(config.kernel_command_line)}
             Kernel Modules Include: {line_join_list(config.kernel_modules_include)}
             Kernel Modules Exclude: {line_join_list(config.kernel_modules_exclude)}
        Kernel Modules Include Host: {yes_no(config.kernel_modules_initrd_include_host)}

              Kernel Modules Initrd: {yes_no(config.kernel_modules_initrd)}
      Kernel Modules Initrd Include: {line_join_list(config.kernel_modules_initrd_include)}
      Kernel Modules Initrd Exclude: {line_join_list(config.kernel_modules_initrd_exclude)}
 Kernel Modules Initrd Include Host: {yes_no(config.kernel_modules_initrd_include_host)}

                             Locale: {none_to_default(config.locale)}
                    Locale Messages: {none_to_default(config.locale_messages)}
                             Keymap: {none_to_default(config.keymap)}
                           Timezone: {none_to_default(config.timezone)}
                           Hostname: {none_to_default(config.hostname)}
                      Root Password: {("(set)" if config.root_password else "(default)")}
                         Root Shell: {none_to_default(config.root_shell)}

                          Autologin: {yes_no(config.autologin)}
                        Make Initrd: {yes_no(config.make_initrd)}
                                SSH: {yes_no(config.ssh)}
                    SELinux Relabel: {config.selinux_relabel}
"""

    if config.output_format.is_extension_image() or config.output_format in (
        OutputFormat.disk,
        OutputFormat.uki,
        OutputFormat.esp,
    ):
        summary += f"""\

         {bold("VALIDATION")}:
                    UEFI SecureBoot: {yes_no(config.secure_boot)}
         UEFI SecureBoot AutoEnroll: {yes_no(config.secure_boot_auto_enroll)}
             SecureBoot Signing Key: {none_to_none(config.secure_boot_key)}
             SecureBoot Certificate: {none_to_none(config.secure_boot_certificate)}
               SecureBoot Sign Tool: {config.secure_boot_sign_tool}
                 Verity Signing Key: {none_to_none(config.verity_key)}
                 Verity Certificate: {none_to_none(config.verity_certificate)}
                 Sign Expected PCRs: {config.sign_expected_pcr}
                         Passphrase: {none_to_none(config.passphrase)}
                           Checksum: {yes_no(config.checksum)}
                               Sign: {yes_no(config.sign)}
                            GPG Key: ({"default" if config.key is None else config.key})
"""

    summary += f"""\

    {bold("HOST CONFIGURATION")}:
                        Incremental: {yes_no(config.incremental)}
                    NSpawn Settings: {none_to_none(config.nspawn_settings)}
                 Extra Search Paths: {line_join_list(config.extra_search_paths)}
                          Ephemeral: {config.ephemeral}
                        Credentials: {line_join_list(config.credentials.keys())}
          Extra Kernel Command Line: {line_join_list(config.kernel_command_line_extra)}
                           Use ACLs: {yes_no(config.acl)}
                         Tools Tree: {config.tools_tree}
            Tools Tree Distribution: {none_to_none(config.tools_tree_distribution)}
                 Tools Tree Release: {none_to_none(config.tools_tree_release)}
                  Tools Tree Mirror: {none_to_default(config.tools_tree_mirror)}
                Tools Tree Packages: {line_join_list(config.tools_tree_packages)}
                      Runtime Trees: {line_join_tree_list(config.runtime_trees)}
                       Runtime Size: {format_bytes_or_none(config.runtime_size)}
                    Runtime Scratch: {config.runtime_scratch}
                    SSH Signing Key: {none_to_none(config.ssh_key)}
                    SSH Certificate: {none_to_none(config.ssh_certificate)}

                           QEMU GUI: {yes_no(config.qemu_gui)}
                     QEMU CPU Cores: {config.qemu_smp}
                        QEMU Memory: {config.qemu_mem}
                       QEMU Use KVM: {config.qemu_kvm}
                     QEMU Use VSock: {config.qemu_vsock}
           QEMU VSock Connection ID: {QemuVsockCID.format(config.qemu_vsock_cid)}
                     QEMU Use Swtpm: {config.qemu_swtpm}
                    QEMU Use CD-ROM: {yes_no(config.qemu_cdrom)}
                      QEMU Firmware: {config.qemu_firmware}
            QEMU Firmware Variables: {none_to_none(config.qemu_firmware_variables)}
                        QEMU Kernel: {none_to_none(config.qemu_kernel)}
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
        return json.JSONEncoder.default(self, o)


E = TypeVar("E", bound=StrEnum)


def json_type_transformer(refcls: Union[type[Args], type[Config]]) -> Callable[[str, Any], Any]:
    fields_by_name = {field.name: field for field in dataclasses.fields(refcls)}

    def path_transformer(path: str, fieldtype: type[Path]) -> Path:
        return Path(path)

    def optional_path_transformer(path: Optional[str], fieldtype: type[Optional[Path]]) -> Optional[Path]:
        return Path(path) if path is not None else None

    def path_list_transformer(pathlist: list[str], fieldtype: type[list[Path]]) -> list[Path]:
        return [Path(p) for p in pathlist]

    def optional_uuid_transformer(optuuid: Optional[str], fieldtype: type[Optional[uuid.UUID]]) -> Optional[uuid.UUID]:
        return uuid.UUID(optuuid) if optuuid is not None else None

    def root_password_transformer(
        rootpw: Optional[list[Union[str, bool]]], fieldtype: type[Optional[tuple[str, bool]]]
    ) -> Optional[tuple[str, bool]]:
        if rootpw is None:
            return None
        return (cast(str, rootpw[0]), cast(bool, rootpw[1]))

    def config_tree_transformer(trees: list[dict[str, Any]], fieldtype: type[ConfigTree]) -> list[ConfigTree]:
        # TODO: exchange for TypeGuard and list comprehension once on 3.10
        ret = []
        for d in trees:
            assert "source" in d
            assert "target" in d
            ret.append(
                ConfigTree(
                    source=Path(d["source"]),
                    target=Path(d["target"]) if d["target"] is not None else None,
                )
            )
        return ret

    def enum_transformer(enumval: str, fieldtype: type[E]) -> E:
        return fieldtype(enumval)

    def optional_enum_transformer(enumval: Optional[str], fieldtype: type[Optional[E]]) -> Optional[E]:
        return fieldtype(enumval) if enumval is not None else None  # type: ignore

    def enum_list_transformer(enumlist: list[str], fieldtype: type[list[E]]) -> list[E]:
        enumtype = fieldtype.__args__[0]  # type: ignore
        return [enumtype[e] for e in enumlist]

    def str_tuple_transformer(strtup: list[str], fieldtype: list[tuple[str, ...]]) -> tuple[str, ...]:
        return tuple(strtup)

    def config_drive_transformer(drives: list[dict[str, Any]], fieldtype: type[QemuDrive]) -> list[QemuDrive]:
        # TODO: exchange for TypeGuard and list comprehension once on 3.10
        ret = []
        for d in drives:
            assert "id" in d
            assert "size" in d
            assert "directory" in d
            assert "options" in d
            ret.append(
                QemuDrive(
                    id=d["id"],
                    size=int(d["size"]),
                    directory=Path(d["directory"]) if d["directory"] else None,
                    options=d["options"],
                )
            )
        return ret

    def generic_version_transformer(
        version: Optional[str],
        fieldtype: type[Optional[GenericVersion]],
    ) -> Optional[GenericVersion]:
        return GenericVersion(version) if version is not None else None

    transformers = {
        Path: path_transformer,
        Optional[Path]: optional_path_transformer,
        list[Path]: path_list_transformer,
        Optional[uuid.UUID]: optional_uuid_transformer,
        Optional[tuple[str, bool]]: root_password_transformer,
        list[ConfigTree]: config_tree_transformer,
        tuple[str, ...]: str_tuple_transformer,
        Architecture: enum_transformer,
        BiosBootloader: enum_transformer,
        ShimBootloader: enum_transformer,
        Bootloader: enum_transformer,
        Compression: enum_transformer,
        ConfigFeature: enum_transformer,
        Distribution: enum_transformer,
        OutputFormat: enum_transformer,
        QemuFirmware: enum_transformer,
        SecureBootSignTool: enum_transformer,
        Optional[Distribution]: optional_enum_transformer,
        list[ManifestFormat]: enum_list_transformer,
        Verb: enum_transformer,
        DocFormat: enum_transformer,
        list[QemuDrive]: config_drive_transformer,
        GenericVersion: generic_version_transformer,
        Cacheonly: enum_transformer,
    }

    def json_transformer(key: str, val: Any) -> Any:
        fieldtype: Optional[dataclasses.Field[Any]] = fields_by_name.get(key)
        # It is unlikely that the type of a field will be None only, so let's not bother with a different sentinel
        # value
        if fieldtype is None:
            raise ValueError(f"{refcls} has no field {key}")

        transformer = cast(Optional[Callable[[str, type], Any]], transformers.get(fieldtype.type))
        if transformer is not None:
            try:
                return transformer(val, fieldtype.type)
            except (ValueError, IndexError, AssertionError) as e:
                raise ValueError(f"Unable to parse {val:r} for attribute {key:r} for {refcls.__name__}") from e

        return val

    return json_transformer


def want_selinux_relabel(config: Config, root: Path, fatal: bool = True) -> Optional[tuple[str, Path, Path]]:
    if config.selinux_relabel == ConfigFeature.disabled:
        return None

    selinux = root / "etc/selinux/config"
    if not selinux.exists():
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die("SELinux relabel is requested but could not find selinux config at /etc/selinux/config")
        return None

    policy = run(["sh", "-c", f". {selinux} && echo $SELINUXTYPE"],
                 sandbox=config.sandbox(options=["--ro-bind", selinux, selinux]),
                 stdout=subprocess.PIPE).stdout.strip()
    if not policy:
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die("SELinux relabel is requested but no selinux policy is configured in /etc/selinux/config")
        return None

    if not find_binary("setfiles", root=config.tools()):
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
    # available. We check for string.digits instead of using isdecimal() as the latter checks for more than just
    # digits.
    policies = [p for p in binpolicydir.glob("*") if p.suffix and all(c in string.digits for c in p.suffix[1:])]
    if not policies:
        if fatal and config.selinux_relabel == ConfigFeature.enabled:
            die(f"SELinux relabel is requested but SELinux binary policy not found in {binpolicydir}")
        return None

    binpolicy = sorted(policies, key=lambda p: GenericVersion(p.name), reverse=True)[0]

    return policy, fc, binpolicy


def systemd_tool_version(config: Config, tool: PathString) -> GenericVersion:
    return GenericVersion(
        run([tool, "--version"], stdout=subprocess.PIPE, sandbox=config.sandbox()).stdout.split()[2].strip("()")
    )
