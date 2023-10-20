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
import subprocess
import tempfile
import textwrap
import uuid
from collections.abc import Collection, Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union, cast

from mkosi.architecture import Architecture
from mkosi.distributions import Distribution, detect_distribution
from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, Style, die
from mkosi.pager import page
from mkosi.run import run
from mkosi.types import PathString, SupportsRead
from mkosi.util import INVOKING_USER, StrEnum, chdir, flatten
from mkosi.versioncomp import GenericVersion

__version__ = "18"

ConfigParseCallback = Callable[[Optional[str], Optional[Any]], Any]
ConfigMatchCallback = Callable[[str, Any], bool]
ConfigDefaultCallback = Callable[[argparse.Namespace], Any]


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

    def supports_cmdline(self) -> bool:
        return self in (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.ssh)

    def needs_build(self) -> bool:
        return self in (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.serve)

    def needs_root(self) -> bool:
        return self in (Verb.shell, Verb.boot)


class ConfigFeature(StrEnum):
    auto     = enum.auto()
    enabled  = enum.auto()
    disabled = enum.auto()


class SecureBootSignTool(StrEnum):
    auto   = enum.auto()
    sbsign = enum.auto()
    pesign = enum.auto()


class OutputFormat(StrEnum):
    directory = enum.auto()
    tar       = enum.auto()
    cpio      = enum.auto()
    disk      = enum.auto()
    uki       = enum.auto()
    none      = enum.auto()


class ManifestFormat(StrEnum):
    json      = enum.auto()  # the standard manifest in json format
    changelog = enum.auto()  # human-readable text file with package changelogs


class Compression(StrEnum):
    none = enum.auto()
    zst  = enum.auto()
    xz   = enum.auto()
    bz2  = enum.auto()
    gz   = enum.auto()
    lz4  = enum.auto()
    lzma = enum.auto()

    def __bool__(self) -> bool:
        return self != Compression.none


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


class QemuFirmware(StrEnum):
    auto   = enum.auto()
    linux  = enum.auto()
    uefi   = enum.auto()
    bios   = enum.auto()


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
               executable: bool = False,
               expanduser: bool = True,
               expandvars: bool = True,
               secret: bool = False) -> Path:
    if expandvars:
        value = os.path.expandvars(value)

    path = Path(value)

    if expanduser:
        if path.is_relative_to("~") and not INVOKING_USER.is_running_user():
            path = INVOKING_USER.home / path.relative_to("~")
        path = path.expanduser()

    if required and not path.exists():
        die(f"{value} does not exist")

    if resolve:
        path = path.resolve()

    if executable and not os.access(path, os.X_OK):
        die(f"{value} is not executable")

    if secret and path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o007:
            die(textwrap.dedent(f"""\
                Permissions of '{path}' of '{mode:04o}' are too open.
                When creating secret files use an access mode that restricts access to the owner only.
            """))

    return path


def make_source_target_paths_parser(absolute: bool = True) -> Callable[[str], tuple[Path, Optional[Path]]]:
    def parse_source_target_paths(value: str) -> tuple[Path, Optional[Path]]:
        src, sep, target = value.partition(':')
        src_path = parse_path(src, required=False)
        if sep:
            target_path = parse_path(target, required=False, resolve=False, expanduser=False)
            if absolute and not target_path.is_absolute():
                die("Target path must be absolute")
        else:
            target_path = None
        return src_path, target_path

    return parse_source_target_paths


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
        return Compression.zst if parse_boolean(value) else Compression.none


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
        raise ValueError(f"{value} is not a valid timestamp")
    if timestamp < 0:
        raise ValueError(f"{value} is negative")
    return timestamp


def config_default_compression(namespace: argparse.Namespace) -> Compression:
    if namespace.output_format in (OutputFormat.cpio, OutputFormat.uki):
        if namespace.distribution.is_centos_variant() and int(namespace.release) <= 8:
            return Compression.xz
        else:
            return Compression.zst
    else:
        return Compression.none


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


def make_enum_parser(type: type[enum.Enum]) -> Callable[[str], enum.Enum]:
    def parse_enum(value: str) -> enum.Enum:
        try:
            return type(value)
        except ValueError:
            die(f"'{value}' is not a valid {type.__name__}")

    return parse_enum


def config_make_enum_parser(type: type[enum.Enum]) -> ConfigParseCallback:
    def config_parse_enum(value: Optional[str], old: Optional[enum.Enum]) -> Optional[enum.Enum]:
        return make_enum_parser(type)(value) if value else None

    return config_parse_enum


def config_make_enum_matcher(type: type[enum.Enum]) -> ConfigMatchCallback:
    def config_match_enum(match: str, value: enum.Enum) -> bool:
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
            return None

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


def make_path_parser(*,
                     required: bool = True,
                     resolve: bool = True,
                     executable: bool = False,
                     expanduser: bool = True,
                     expandvars: bool = True,
                     secret: bool = False) -> Callable[[str], Path]:
    return functools.partial(
        parse_path,
        required=required,
        resolve=resolve,
        executable=executable,
        expanduser=expanduser,
        expandvars=expandvars,
        secret=secret,
    )


def config_make_path_parser(*,
                            required: bool = True,
                            resolve: bool = True,
                            executable: bool = False,
                            expanduser: bool = True,
                            expandvars: bool = True,
                            secret: bool = False) -> ConfigParseCallback:
    def config_parse_path(value: Optional[str], old: Optional[Path]) -> Optional[Path]:
        if not value:
            return None

        return parse_path(
            value,
            required=required,
            resolve=resolve,
            executable=executable,
            expanduser=expanduser,
            expandvars=expandvars,
            secret=secret,
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


def config_parse_bytes(value: Optional[str], old: Optional[int] = None) -> Optional[int]:
    if not value:
        return None

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


def config_parse_profile(value: Optional[str], old: Optional[int] = None) -> Optional[str]:
    if not value:
        return None

    if not is_valid_filename(value):
        die(f"{value!r} is not a valid profile",
            hint="Profile= or --profile= requires a name with no path components.")

    return value


@dataclasses.dataclass(frozen=True)
class MkosiConfigSetting:
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
class MkosiMatch:
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
class MkosiArgs:
    verb: Verb
    cmdline: list[str]
    force: int
    directory: Optional[Path]
    debug: bool
    debug_shell: bool
    pager: bool
    genkey_valid_days: str
    genkey_common_name: str
    auto_bump: bool
    doc_format: DocFormat
    json: bool

    @classmethod
    def default(cls) -> "MkosiArgs":
        """Alternative constructor to generate an all-default MkosiArgs.

        This prevents MkosiArgs being generated with defaults values implicitly.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            with chdir(tempdir):
                args, _ = parse_config([])

        return args

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> "MkosiArgs":
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
        return json.dumps(self.to_dict(), cls=MkosiJsonEncoder, indent=indent, sort_keys=sort_keys)

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
    def from_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "MkosiArgs":
        """Instantiate a MkosiArgs object from a full JSON dump."""
        j = cls._load_json(s)
        return cls(**j)

    @classmethod
    def from_partial_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "MkosiArgs":
        """Return a new MkosiArgs with defaults overwritten by the attributes from passed in JSON."""
        j = cls._load_json(s)
        return dataclasses.replace(cls.default(), **j)


@dataclasses.dataclass(frozen=True)
class MkosiConfig:
    """Type-hinted storage for command line arguments.

    Only user configuration is stored here while dynamic state exists in
    MkosiState. If a field of the same name exists in both classes always
    access the value from state.
    """

    profile: Optional[str]
    include: tuple[str, ...]
    images: tuple[str, ...]
    dependencies: tuple[str, ...]

    distribution: Distribution
    release: str
    architecture: Architecture
    mirror: Optional[str]
    local_mirror: Optional[str]
    repository_key_check: bool
    repositories: list[str]
    cache_only: bool
    package_manager_trees: list[tuple[Path, Optional[Path]]]

    output_format: OutputFormat
    manifest_format: list[ManifestFormat]
    output: str
    compress_output: Compression
    output_dir: Optional[Path]
    workspace_dir: Optional[Path]
    cache_dir: Optional[Path]
    build_dir: Optional[Path]
    image_id: Optional[str]
    image_version: Optional[str]
    split_artifacts: bool
    repart_dirs: list[Path]
    sector_size: Optional[str]
    overlay: bool
    use_subvolumes: ConfigFeature
    seed: Optional[uuid.UUID]

    packages: list[str]
    build_packages: list[str]
    with_recommends: bool
    with_docs: bool

    base_trees: list[Path]
    skeleton_trees: list[tuple[Path, Optional[Path]]]
    extra_trees: list[tuple[Path, Optional[Path]]]

    remove_packages: list[str]
    remove_files: list[str]
    clean_package_metadata: ConfigFeature
    source_date_epoch: Optional[int]

    prepare_scripts: list[Path]
    build_scripts: list[Path]
    postinst_scripts: list[Path]
    finalize_scripts: list[Path]
    build_sources: list[tuple[Path, Optional[Path]]]
    environment: dict[str, str]
    with_tests: bool
    with_network: bool

    bootable: ConfigFeature
    bootloader: Bootloader
    bios_bootloader: BiosBootloader
    initrds: list[Path]
    initrd_packages: list[str]
    kernel_command_line: list[str]
    kernel_modules_include: list[str]
    kernel_modules_exclude: list[str]

    kernel_modules_initrd: bool
    kernel_modules_initrd_include: list[str]
    kernel_modules_initrd_exclude: list[str]

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

    secure_boot: bool
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
    runtime_trees: list[tuple[Path, Optional[Path]]]
    runtime_size: Optional[int]

    # QEMU-specific options
    qemu_gui: bool
    qemu_smp: str
    qemu_mem: str
    qemu_kvm: ConfigFeature
    qemu_vsock: ConfigFeature
    qemu_swtpm: ConfigFeature
    qemu_cdrom: bool
    qemu_firmware: QemuFirmware
    qemu_kernel: Optional[Path]
    qemu_args: list[str]

    image: Optional[str]

    def output_dir_or_cwd(self) -> Path:
        return self.output_dir or Path.cwd()

    def workspace_dir_or_cwd(self) -> Path:
        return self.workspace_dir or Path.cwd()

    @classmethod
    def default(cls) -> "MkosiConfig":
        """Alternative constructor to generate an all-default MkosiArgs.

        This prevents MkosiArgs being generated with defaults values implicitly.
        """
        with tempfile.TemporaryDirectory() as tempdir:
            with chdir(tempdir):
                _, [config] = parse_config([])

        return config

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> "MkosiConfig":
        return cls(**{
            k: v for k, v in vars(ns).items()
            if k in inspect.signature(cls).parameters
        })

    @property
    def output_with_version(self) -> str:
        output = self.output

        if self.image_version:
            output += f"_{self.image_version}"

        return output

    @property
    def output_with_format(self) -> str:
        output = self.output_with_version

        output += {
            OutputFormat.disk: ".raw",
            OutputFormat.cpio: ".cpio",
            OutputFormat.tar:  ".tar",
            OutputFormat.uki:  ".efi",
        }.get(self.output_format, "")

        return output

    @property
    def output_with_compression(self) -> str:
        output = self.output_with_format

        if self.compress_output and self.output_format != OutputFormat.uki:
            output += f".{self.compress_output}"

        return output

    @property
    def output_split_uki(self) -> str:
        return f"{self.output_with_version}.efi"

    @property
    def output_split_kernel(self) -> str:
        return f"{self.output_with_version}.vmlinuz"

    @property
    def output_split_initrd(self) -> str:
        return f"{self.output_with_version}.initrd"

    @property
    def output_nspawn_settings(self) -> str:
        return f"{self.output_with_version}.nspawn"

    @property
    def output_checksum(self) -> str:
        return f"{self.output_with_version}.SHA256SUMS"

    @property
    def output_signature(self) -> str:
        return f"{self.output_with_version}.SHA256SUMS.gpg"

    @property
    def output_manifest(self) -> str:
        return f"{self.output_with_version}.manifest"

    @property
    def output_changelog(self) -> str:
        return f"{self.output_with_version}.changelog"

    def cache_manifest(self) -> dict[str, Any]:
        return {
            "packages": self.packages,
            "build_packages": self.build_packages,
            "repositories": self.repositories,
            "prepare_scripts": [
                base64.b64encode(script.read_bytes()).decode()
                for script in self.prepare_scripts
            ]
        }

    def to_dict(self) -> dict[str, Any]:
        def key_transformer(k: str) -> str:
            if (s := SETTINGS_LOOKUP_BY_DEST.get(k)) is not None:
                return s.name
            return "".join(p.capitalize() for p in k.split("_"))

        return {key_transformer(k): v for k, v in dataclasses.asdict(self).items()}

    def to_json(self, *, indent: Optional[int] = 4, sort_keys: bool = True) -> str:
        """Dump MkosiConfig as JSON string."""
        return json.dumps(self.to_dict(), cls=MkosiJsonEncoder, indent=indent, sort_keys=sort_keys)

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
    def from_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "MkosiConfig":
        """Instantiate a MkosiConfig object from a full JSON dump."""
        j = cls._load_json(s)
        return cls(**j)

    @classmethod
    def from_partial_json(cls, s: Union[str, dict[str, Any], SupportsRead[str], SupportsRead[bytes]]) -> "MkosiConfig":
        """Return a new MkosiConfig with defaults overwritten by the attributes from passed in JSON."""
        j = cls._load_json(s)
        return dataclasses.replace(cls.default(), **j)


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
    MkosiConfigSetting(
        dest="include",
        section="Config",
        parse=config_make_list_parser(delimiter=",", reset=False, parse=make_path_parser()),
        help="Include configuration from the specified file or directory",
    ),
    MkosiConfigSetting(
        dest="profile",
        section="Config",
        help="Build the specified profile",
        parse=config_parse_profile,
        match=config_make_string_matcher(),
    ),
    MkosiConfigSetting(
        dest="images",
        compat_names=("Presets",),
        long="--image",
        section="Config",
        parse=config_make_list_parser(delimiter=","),
        help="Specify which images to build",
    ),
    MkosiConfigSetting(
        dest="dependencies",
        long="--dependency",
        section="Config",
        parse=config_make_list_parser(delimiter=","),
        help="Specify other images that this image depends on",
    ),
    MkosiConfigSetting(
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
    MkosiConfigSetting(
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
    MkosiConfigSetting(
        dest="architecture",
        section="Distribution",
        specifier="a",
        parse=config_make_enum_parser(Architecture),
        match=config_make_enum_matcher(Architecture),
        default=Architecture.native(),
        choices=Architecture.values(),
        help="Override the architecture of installation",
    ),
    MkosiConfigSetting(
        dest="mirror",
        short="-m",
        section="Distribution",
        help="Distribution mirror to use",
    ),
    MkosiConfigSetting(
        dest="local_mirror",
        section="Distribution",
        help="Use a single local, flat and plain mirror to build the image",
    ),
    MkosiConfigSetting(
        dest="repository_key_check",
        metavar="BOOL",
        nargs="?",
        section="Distribution",
        default=True,
        parse=config_parse_boolean,
        help="Controls signature and key checks on repositories",
    ),
    MkosiConfigSetting(
        dest="repositories",
        metavar="REPOS",
        section="Distribution",
        parse=config_make_list_parser(delimiter=","),
        help="Repositories to use",
    ),
    MkosiConfigSetting(
        dest="cache_only",
        metavar="BOOL",
        section="Distribution",
        parse=config_parse_boolean,
        help="Only use the package cache when installing packages",
    ),
    MkosiConfigSetting(
        dest="package_manager_trees",
        long="--package-manager-tree",
        metavar="PATH",
        section="Distribution",
        parse=config_make_list_parser(delimiter=",", parse=make_source_target_paths_parser()),
        default_factory=lambda ns: ns.skeleton_trees,
        default_factory_depends=("skeleton_trees",),
        help="Use a package manager tree to configure the package manager",
    ),

    MkosiConfigSetting(
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
    MkosiConfigSetting(
        dest="manifest_format",
        metavar="FORMAT",
        section="Output",
        parse=config_make_list_parser(delimiter=",", parse=make_enum_parser(ManifestFormat)),
        help="Manifest Format",
    ),
    MkosiConfigSetting(
        dest="output",
        short="-o",
        metavar="NAME",
        section="Output",
        specifier="o",
        parse=config_parse_output,
        help="Output name",
    ),
    MkosiConfigSetting(
        dest="compress_output",
        metavar="ALG",
        nargs="?",
        section="Output",
        parse=config_parse_compression,
        default_factory=config_default_compression,
        default_factory_depends=("distribution", "release", "output_format"),
        help="Enable whole-output compression (with images or archives)",
    ),
    MkosiConfigSetting(
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
    MkosiConfigSetting(
        dest="workspace_dir",
        metavar="DIR",
        name="WorkspaceDirectory",
        section="Output",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.workspace",),
        help="Workspace directory",
    ),
    MkosiConfigSetting(
        dest="cache_dir",
        metavar="PATH",
        name="CacheDirectory",
        section="Output",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.cache",),
        help="Package cache path",
    ),
    MkosiConfigSetting(
        dest="build_dir",
        metavar="PATH",
        name="BuildDirectory",
        section="Output",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.builddir",),
        help="Path to use as persistent build directory",
    ),
    MkosiConfigSetting(
        dest="image_version",
        match=config_match_version,
        section="Output",
        specifier="v",
        help="Set version for image",
        paths=("mkosi.version",),
        path_read_text=True,
    ),
    MkosiConfigSetting(
        dest="image_id",
        match=config_make_string_matcher(allow_globs=True),
        section="Output",
        specifier="i",
        help="Set ID for image",
    ),
    MkosiConfigSetting(
        dest="split_artifacts",
        metavar="BOOL",
        nargs="?",
        section="Output",
        parse=config_parse_boolean,
        help="Generate split partitions",
    ),
    MkosiConfigSetting(
        dest="repart_dirs",
        long="--repart-dir",
        metavar="PATH",
        name="RepartDirectories",
        section="Output",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        paths=("mkosi.repart",),
        help="Directory containing systemd-repart partition definitions",
    ),
    MkosiConfigSetting(
        dest="sector_size",
        section="Output",
        parse=config_parse_string,
        help="Set the disk image sector size",
    ),
    MkosiConfigSetting(
        dest="overlay",
        metavar="BOOL",
        nargs="?",
        section="Output",
        parse=config_parse_boolean,
        help="Only output the additions on top of the given base trees",
    ),
    MkosiConfigSetting(
        dest="use_subvolumes",
        metavar="FEATURE",
        nargs="?",
        section="Output",
        parse=config_parse_feature,
        help="Use btrfs subvolumes for faster directory operations where possible",
    ),
    MkosiConfigSetting(
        dest="seed",
        metavar="UUID",
        section="Output",
        parse=config_parse_seed,
        help="Set the seed for systemd-repart",
    ),

    MkosiConfigSetting(
        dest="packages",
        short="-p",
        long="--package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Add an additional package to the OS image",
    ),
    MkosiConfigSetting(
        dest="build_packages",
        long="--build-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Additional packages needed for build scripts",
    ),
    MkosiConfigSetting(
        dest="with_recommends",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Install recommended packages",
    ),
    MkosiConfigSetting(
        dest="with_docs",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        default=True,
        help="Install documentation",
    ),
    MkosiConfigSetting(
        dest="base_trees",
        long='--base-tree',
        metavar='PATH',
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
        help='Use the given tree as base tree (e.g. lower sysext layer)',
    ),
    MkosiConfigSetting(
        dest="skeleton_trees",
        long="--skeleton-tree",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_source_target_paths_parser()),
        paths=("mkosi.skeleton", "mkosi.skeleton.tar"),
        path_default=False,
        help="Use a skeleton tree to bootstrap the image before installing anything",
    ),
    MkosiConfigSetting(
        dest="extra_trees",
        long="--extra-tree",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_source_target_paths_parser()),
        paths=("mkosi.extra", "mkosi.extra.tar"),
        path_default=False,
        help="Copy an extra tree on top of image",
    ),
    MkosiConfigSetting(
        dest="remove_packages",
        long="--remove-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Remove package from the image OS image after installation",
    ),
    MkosiConfigSetting(
        dest="remove_files",
        metavar="GLOB",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Remove files from built image",
    ),
    MkosiConfigSetting(
        dest="clean_package_metadata",
        metavar="FEATURE",
        section="Content",
        parse=config_parse_feature,
        help="Remove package manager database and other files",
    ),
    MkosiConfigSetting(
        dest="source_date_epoch",
        metavar="TIMESTAMP",
        section="Content",
        parse=config_parse_source_date_epoch,
        default_factory=config_default_source_date_epoch,
        default_factory_depends=("environment",),
        help="Set the $SOURCE_DATE_EPOCH timestamp",
    ),
    MkosiConfigSetting(
        dest="prepare_scripts",
        long="--prepare-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(executable=True)),
        paths=("mkosi.prepare", "mkosi.prepare.chroot"),
        path_default=False,
        help="Prepare script to run inside the image before it is cached",
        compat_names=("PrepareScript",),
    ),
    MkosiConfigSetting(
        dest="build_scripts",
        long="--build-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(executable=True)),
        paths=("mkosi.build", "mkosi.build.chroot"),
        path_default=False,
        help="Build script to run inside image",
        compat_names=("BuildScript",),
    ),
    MkosiConfigSetting(
        dest="postinst_scripts",
        long="--postinst-script",
        metavar="PATH",
        name="PostInstallationScripts",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(executable=True)),
        paths=("mkosi.postinst", "mkosi.postinst.chroot"),
        path_default=False,
        help="Postinstall script to run inside image",
        compat_names=("PostInstallationScript",),
    ),
    MkosiConfigSetting(
        dest="finalize_scripts",
        long="--finalize-script",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(executable=True)),
        paths=("mkosi.finalize", "mkosi.finalize.chroot"),
        path_default=False,
        help="Postinstall script to run outside image",
        compat_names=("FinalizeScript",),
    ),
    MkosiConfigSetting(
        dest="build_sources",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_source_target_paths_parser(absolute=False)),
        help="Path for sources to build",
    ),
    MkosiConfigSetting(
        dest="environment",
        short="-E",
        metavar="NAME[=VALUE]",
        section="Content",
        parse=config_make_list_parser(delimiter=" ", unescape=True),
        help="Set an environment variable when running scripts",
    ),
    MkosiConfigSetting(
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
    MkosiConfigSetting(
        dest="with_network",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Run build and postinst scripts with network access (instead of private network)",
    ),
    MkosiConfigSetting(
        dest="bootable",
        metavar="FEATURE",
        nargs="?",
        section="Content",
        parse=config_parse_feature,
        match=config_match_feature,
        help="Generate ESP partition with systemd-boot and UKIs for installed kernels",
    ),
    MkosiConfigSetting(
        dest="bootloader",
        metavar="BOOTLOADER",
        section="Content",
        parse=config_make_enum_parser(Bootloader),
        choices=Bootloader.values(),
        default=Bootloader.systemd_boot,
        help="Specify which UEFI bootloader to use",
    ),
    MkosiConfigSetting(
        dest="bios_bootloader",
        metavar="BOOTLOADER",
        section="Content",
        parse=config_make_enum_parser(BiosBootloader),
        choices=BiosBootloader.values(),
        default=BiosBootloader.none,
        help="Specify which BIOS bootloader to use",
    ),
    MkosiConfigSetting(
        dest="initrds",
        long="--initrd",
        metavar="PATH",
        section="Content",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
        help="Add a user-provided initrd to image",
    ),
    MkosiConfigSetting(
        dest="initrd_packages",
        long="--initrd-package",
        metavar="PACKAGE",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Add additional packages to the default initrd",
    ),
    MkosiConfigSetting(
        dest="kernel_command_line",
        metavar="OPTIONS",
        section="Content",
        parse=config_make_list_parser(delimiter=" "),
        default=["console=ttyS0"],
        help="Set the kernel command line (only bootable images)",
    ),
    MkosiConfigSetting(
        dest="kernel_modules_include",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Only include the specified kernel modules in the image",
    ),
    MkosiConfigSetting(
        dest="kernel_modules_exclude",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="Exclude the specified kernel modules from the image",
    ),
    MkosiConfigSetting(
        dest="kernel_modules_initrd",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        default=True,
        help="When building a bootable image, add an extra initrd containing the kernel modules",
    ),
    MkosiConfigSetting(
        dest="kernel_modules_initrd_include",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="When building a kernel modules initrd, only include the specified kernel modules",
    ),
    MkosiConfigSetting(
        dest="kernel_modules_initrd_exclude",
        metavar="REGEX",
        section="Content",
        parse=config_make_list_parser(delimiter=","),
        help="When building a kernel modules initrd, exclude the specified kernel modules",
    ),
    MkosiConfigSetting(
        dest="locale",
        section="Content",
        parse=config_parse_string,
        help="Set the system locale",
    ),
    MkosiConfigSetting(
        dest="locale_messages",
        metavar="LOCALE",
        section="Content",
        parse=config_parse_string,
        help="Set the messages locale",
    ),
    MkosiConfigSetting(
        dest="keymap",
        metavar="KEYMAP",
        section="Content",
        parse=config_parse_string,
        help="Set the system keymap",
    ),
    MkosiConfigSetting(
        dest="timezone",
        metavar="TIMEZONE",
        section="Content",
        parse=config_parse_string,
        help="Set the system timezone",
    ),
    MkosiConfigSetting(
        dest="hostname",
        metavar="HOSTNAME",
        section="Content",
        parse=config_parse_string,
        help="Set the system hostname",
    ),
    MkosiConfigSetting(
        dest="root_password",
        metavar="PASSWORD",
        section="Content",
        parse=config_parse_root_password,
        paths=("mkosi.rootpw",),
        path_read_text=True,
        path_secret=True,
        help="Set the password for root",
    ),
    MkosiConfigSetting(
        dest="root_shell",
        metavar="SHELL",
        section="Content",
        parse=config_parse_string,
        help="Set the shell for root",
    ),
    MkosiConfigSetting(
        dest="autologin",
        short="-a",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Enable root autologin",
    ),
    MkosiConfigSetting(
        dest="make_initrd",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Make sure the image can be used as an initramfs",
    ),
    MkosiConfigSetting(
        dest="ssh",
        metavar="BOOL",
        nargs="?",
        section="Content",
        parse=config_parse_boolean,
        help="Set up SSH access from the host to the final image via 'mkosi ssh'",
    ),

    MkosiConfigSetting(
        dest="secure_boot",
        metavar="BOOL",
        nargs="?",
        section="Validation",
        parse=config_parse_boolean,
        help="Sign the resulting kernel/initrd image for UEFI SecureBoot",
    ),
    MkosiConfigSetting(
        dest="secure_boot_key",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(),
        paths=("mkosi.key",),
        help="UEFI SecureBoot private key in PEM format",
    ),
    MkosiConfigSetting(
        dest="secure_boot_certificate",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(),
        paths=("mkosi.crt",),
        help="UEFI SecureBoot certificate in X509 format",
    ),
    MkosiConfigSetting(
        dest="secure_boot_sign_tool",
        metavar="TOOL",
        section="Validation",
        parse=config_make_enum_parser(SecureBootSignTool),
        default=SecureBootSignTool.auto,
        choices=SecureBootSignTool.values(),
        help="Tool to use for signing PE binaries for secure boot",
    ),
    MkosiConfigSetting(
        dest="verity_key",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(),
        paths=("mkosi.key",),
        help="Private key for signing verity signature in PEM format",
    ),
    MkosiConfigSetting(
        dest="verity_certificate",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(),
        paths=("mkosi.crt",),
        help="Certificate for signing verity signature in X509 format",
    ),
    MkosiConfigSetting(
        dest="sign_expected_pcr",
        metavar="FEATURE",
        section="Validation",
        parse=config_parse_feature,
        help="Measure the components of the unified kernel image (UKI) and embed the PCR signature into the UKI",
    ),
    MkosiConfigSetting(
        dest="passphrase",
        metavar="PATH",
        section="Validation",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.passphrase",),
        help="Path to a file containing the passphrase to use when LUKS encryption is selected",
    ),
    MkosiConfigSetting(
        dest="checksum",
        metavar="BOOL",
        nargs="?",
        section="Validation",
        parse=config_parse_boolean,
        help="Write SHA256SUMS file",
    ),
    MkosiConfigSetting(
        dest="sign",
        metavar="BOOL",
        nargs="?",
        section="Validation",
        parse=config_parse_boolean,
        help="Write and sign SHA256SUMS file",
    ),
    MkosiConfigSetting(
        dest="key",
        section="Validation",
        help="GPG key to use for signing",
    ),

    MkosiConfigSetting(
        dest="incremental",
        short="-i",
        metavar="BOOL",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Make use of and generate intermediary cache images",
    ),
    MkosiConfigSetting(
        dest="nspawn_settings",
        name="NSpawnSettings",
        long="--settings",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(),
        paths=("mkosi.nspawn",),
        help="Add in .nspawn settings file",
    ),
    MkosiConfigSetting(
        dest="extra_search_paths",
        long="--extra-search-path",
        metavar="PATH",
        section="Host",
        parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        help="List of comma-separated paths to look for programs before looking in PATH",
    ),
    MkosiConfigSetting(
        dest="qemu_gui",
        metavar="BOOL",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Start QEMU in graphical mode",
    ),
    MkosiConfigSetting(
        dest="qemu_smp",
        metavar="SMP",
        section="Host",
        default="1",
        help="Configure guest's SMP settings",
    ),
    MkosiConfigSetting(
        dest="qemu_mem",
        metavar="MEM",
        section="Host",
        default="2G",
        help="Configure guest's RAM size",
    ),
    MkosiConfigSetting(
        dest="qemu_kvm",
        metavar="FEATURE",
        nargs="?",
        section="Host",
        parse=config_parse_feature,
        help="Configure whether to use KVM or not",
    ),
    MkosiConfigSetting(
        dest="qemu_vsock",
        metavar="FEATURE",
        nargs="?",
        section="Host",
        parse=config_parse_feature,
        help="Configure whether to use qemu with a vsock or not",
    ),
    MkosiConfigSetting(
        dest="qemu_swtpm",
        metavar="FEATURE",
        nargs="?",
        section="Host",
        parse=config_parse_feature,
        help="Configure whether to use qemu with swtpm or not",
    ),
    MkosiConfigSetting(
        dest="qemu_cdrom",
        metavar="BOOLEAN",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Attach the image as a CD-ROM to the virtual machine",
    ),
    MkosiConfigSetting(
        dest="qemu_firmware",
        metavar="FIRMWARE",
        section="Host",
        parse=config_make_enum_parser(QemuFirmware),
        default=QemuFirmware.auto,
        help="Set qemu firmware to use",
        choices=QemuFirmware.values(),
    ),
    MkosiConfigSetting(
        dest="qemu_kernel",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(),
        help="Specify the kernel to use for qemu direct kernel boot",
    ),
    MkosiConfigSetting(
        dest="qemu_args",
        metavar="ARGS",
        section="Host",
        parse=config_make_list_parser(delimiter=" "),
        # Suppress the command line option because it's already possible to pass qemu args as normal
        # arguments.
        help=argparse.SUPPRESS,
    ),
    MkosiConfigSetting(
        dest="ephemeral",
        metavar="BOOL",
        section="Host",
        parse=config_parse_boolean,
        help=('If specified, the container/VM is run with a temporary snapshot of the output '
                'image that is removed immediately when the container/VM terminates'),
        nargs="?",
    ),
    MkosiConfigSetting(
        dest="credentials",
        long="--credential",
        metavar="NAME=VALUE",
        section="Host",
        parse=config_make_list_parser(delimiter=" "),
        help="Pass a systemd credential to systemd-nspawn or qemu",
    ),
    MkosiConfigSetting(
        dest="kernel_command_line_extra",
        metavar="OPTIONS",
        section="Host",
        parse=config_make_list_parser(delimiter=" "),
        help="Append extra entries to the kernel command line when booting the image",
    ),
    MkosiConfigSetting(
        dest="acl",
        metavar="BOOL",
        nargs="?",
        section="Host",
        parse=config_parse_boolean,
        help="Set ACLs on generated directories to permit the user running mkosi to remove them",
    ),
    MkosiConfigSetting(
        dest="tools_tree",
        metavar="PATH",
        section="Host",
        parse=config_make_path_parser(required=False),
        paths=("mkosi.tools",),
        help="Look up programs to execute inside the given tree",
    ),
    MkosiConfigSetting(
        dest="tools_tree_distribution",
        metavar="DISTRIBUTION",
        section="Host",
        parse=config_make_enum_parser(Distribution),
        help="Set the distribution to use for the default tools tree",
    ),
    MkosiConfigSetting(
        dest="tools_tree_release",
        metavar="RELEASE",
        section="Host",
        parse=config_parse_string,
        help="Set the release to use for the default tools tree",
    ),
    MkosiConfigSetting(
        dest="tools_tree_mirror",
        metavar="MIRROR",
        section="Host",
        help="Set the mirror to use for the default tools tree",
    ),
    MkosiConfigSetting(
        dest="tools_tree_packages",
        long="--tools-tree-package",
        metavar="PACKAGE",
        section="Host",
        parse=config_make_list_parser(delimiter=","),
        help="Add additional packages to the default tools tree",
    ),
    MkosiConfigSetting(
        dest="runtime_trees",
        long="--runtime-tree",
        metavar="SOURCE:[TARGET]",
        section="Host",
        parse=config_make_list_parser(delimiter=",", parse=make_source_target_paths_parser()),
        help="Additional mounts to add when booting the image",
    ),
    MkosiConfigSetting(
        dest="runtime_size",
        metavar="SIZE",
        section="Host",
        parse=config_parse_bytes,
        help="Grow disk images to the specified size before booting them",
    ),
)
SETTINGS_LOOKUP_BY_NAME = {name: s for s in SETTINGS for name in [s.name, *s.compat_names]}
SETTINGS_LOOKUP_BY_DEST = {s.dest: s for s in SETTINGS}
SETTINGS_LOOKUP_BY_SPECIFIER = {s.specifier: s for s in SETTINGS if s.specifier}

MATCHES = (
    MkosiMatch(
        name="PathExists",
        match=match_path_exists,
    ),
    MkosiMatch(
        name="SystemdVersion",
        match=match_systemd_version,
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
                mkosi [options...] {b}build{e} [command line...]
                mkosi [options...] {b}shell{e} [command line...]
                mkosi [options...] {b}boot{e}  [nspawn settings...]
                mkosi [options...] {b}qemu{e}  [qemu parameters...]
                mkosi [options...] {b}ssh{e}   [command line...]
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
        action=action,
        default="730",
    )
    parser.add_argument(
        "--genkey-common-name",
        metavar="CN",
        help="Template for the CN when generating keys",
        action=action,
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


def resolve_deps(images: Sequence[MkosiConfig], include: Sequence[str]) -> list[MkosiConfig]:
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


def parse_config(argv: Sequence[str] = ()) -> tuple[MkosiArgs, tuple[MkosiConfig, ...]]:
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
                st = p.stat()

                if (st.st_dev, st.st_ino) in parsed_includes:
                    continue

                with chdir(p if p.is_dir() else Path.cwd()):
                    parse_config(p if p.is_file() else Path("."), namespace, defaults)
                parsed_includes.add((st.st_dev, st.st_ino))

    class MkosiAction(argparse.Action):
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
        setting: MkosiConfigSetting,
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
        triggered = None

        # If the config file does not exist, we assume it matches so that we look at the other files in the
        # directory as well (mkosi.conf.d/ and extra files).
        if not path.exists():
            return True

        for _, k, v in parse_ini(path, only_sections=["Match"]):
            trigger = v.startswith("|")
            v = v.removeprefix("|")
            negate = v.startswith("!")
            v = v.removeprefix("!")

            if not v:
                die("Match value cannot be empty")

            if (s := SETTINGS_LOOKUP_BY_NAME.get(k)):
                if not s.match:
                    die(f"{k} cannot be used in [Match]")

                if k != s.name:
                    logging.warning(f"Setting {k} is deprecated, please use {s.name} instead.")

                # If we encounter a setting in [Match] that has not been explicitly configured yet,
                # we assign the default value first so that we can [Match] on default values for
                # settings.
                if finalize_default(s, namespace, defaults) is None:
                    result = False
                else:
                    result = s.match(v, getattr(namespace, s.dest))

            elif (m := MATCH_LOOKUP.get(k)):
                result = m.match(v)
            else:
                die(f"{k} cannot be used in [Match]")

            if negate:
                result = not result
            if not trigger and not result:
                return False
            if trigger:
                triggered = bool(triggered) or result

        return triggered is not False

    def parse_config(
        path: Path,
        namespace: argparse.Namespace,
        defaults: argparse.Namespace,
        profiles: bool = False,
    ) -> bool:
        s: Optional[MkosiConfigSetting] # Make mypy happy
        extras = path.is_dir()

        if path.is_dir():
            path = path / "mkosi.conf"

        if not match_config(path, namespace, defaults):
            return False

        if extras:
            if (path.parent / "mkosi.local.conf").exists():
                parse_config(path.parent / "mkosi.local.conf", namespace, defaults)

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
                        setattr(ns, s.dest,
                                s.parse(p.read_text() if s.path_read_text else f, getattr(ns, s.dest, None)))

        if path.exists():
            logging.debug(f"Including configuration file {Path.cwd() / path}")

            for section, k, v in parse_ini(path, only_sections={s.section for s in SETTINGS} | {"Preset"}):
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
                    parse_config(p if p.is_file() else Path("."), namespace, defaults)

        if extras and (path.parent / "mkosi.conf.d").exists():
            for p in sorted((path.parent / "mkosi.conf.d").iterdir()):
                if p.is_dir() or p.suffix == ".conf":
                    with chdir(p if p.is_dir() else Path.cwd()):
                        parse_config(p if p.is_file() else Path("."), namespace, defaults)

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
    argparser = create_argument_parser(MkosiAction)
    argparser.parse_args(argv, namespace)
    cli_ns = copy.deepcopy(namespace)

    args = load_args(namespace)

    if ARG_DEBUG.get():
        logging.getLogger().setLevel(logging.DEBUG)

    if args.verb == Verb.help:
        PagerHelpAction.__call__(None, argparser, namespace)  # type: ignore

    include = ()

    if args.directory is not None:
        parse_config(Path("."), namespace, defaults, profiles=True)

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
                    if not parse_config(p if p.is_file() else Path("."), ns_copy, defaults_copy):
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

        setting = SETTINGS_LOOKUP_BY_DEST[s]

        die(f"{setting.long}={getattr(cli_ns, s)} was specified on the command line but is not allowed to be configured by any images.",
            hint="Prefix the setting with '@' in the image configuration file to allow overriding it from the command line.")

    if not images:
        die("No images defined in mkosi.images/")

    images = [load_config(ns) for ns in images]
    images = resolve_deps(images, include)

    return args, tuple(images)


def load_credentials(args: argparse.Namespace) -> dict[str, str]:
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

    for s in args.credentials:
        key, _, value = s.partition("=")
        creds[key] = value

    if "firstboot.timezone" not in creds and shutil.which("timedatectl"):
        tz = run(
            ["timedatectl", "show", "-p", "Timezone", "--value"],
            stdout=subprocess.PIPE,
            check=False,
        ).stdout.strip()
        if tz:
            creds["firstboot.timezone"] = tz

    if "firstboot.locale" not in creds:
        creds["firstboot.locale"] = "C.UTF-8"

    if (
        args.ssh and
        "ssh.authorized_keys.root" not in creds and
        "SSH_AUTH_SOCK" in os.environ and shutil.which("ssh-add")
    ):
        key = run(
            ["ssh-add", "-L"],
            stdout=subprocess.PIPE,
            env=os.environ,
            check=False,
        ).stdout.strip()
        if key:
            creds["ssh.authorized_keys.root"] = key

    return creds


def load_kernel_command_line_extra(args: argparse.Namespace) -> list[str]:
    columns, lines = shutil.get_terminal_size()
    cmdline = [
        # Make sure we set up networking in the VM/container.
        "systemd.wants=network.target",
        # Make sure we don't load vmw_vmci which messes with virtio vsock.
        "module_blacklist=vmw_vmci",
        f"systemd.tty.term.ttyS0={os.getenv('TERM', 'vt220')}",
        f"systemd.tty.columns.ttyS0={columns}",
        f"systemd.tty.rows.ttyS0={lines}",
    ]

    if not any(s.startswith("ip=") for s in args.kernel_command_line_extra):
        cmdline += ["ip=enp0s1:any", "ip=enp0s2:any", "ip=host0:any", "ip=none"]

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
            "console=ttyS0",
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
    }

    if args.image_id is not None:
        env["IMAGE_ID"] = args.image_id
    if args.image_version is not None:
        env["IMAGE_VERSION"] = args.image_version
    if args.source_date_epoch is not None:
        env["SOURCE_DATE_EPOCH"] = str(args.source_date_epoch)
    if (proxy := os.environ.get("http_proxy")):
        env["http_proxy"] = proxy
    if (proxy := os.environ.get("https_proxy")):
        env["https_proxy"] = proxy

    for s in args.environment:
        key, sep, value = s.partition("=")
        value = value if sep else os.getenv(key, "")
        env[key] = value

    return env


def load_args(args: argparse.Namespace) -> MkosiArgs:
    if args.debug:
        ARG_DEBUG.set(args.debug)
    if args.debug_shell:
        ARG_DEBUG_SHELL.set(args.debug_shell)

    return MkosiArgs.from_namespace(args)


def load_config(args: argparse.Namespace) -> MkosiConfig:
    if args.cmdline and not args.verb.supports_cmdline():
        die(f"Arguments after verb are not supported for {args.verb}.")

    if args.sign:
        args.checksum = True

    if args.output is None:
        args.output = args.image_id or args.image or "image"

    args.credentials = load_credentials(args)
    args.kernel_command_line_extra = load_kernel_command_line_extra(args)
    args.environment = load_environment(args)

    if args.secure_boot and args.verb != Verb.genkey:
        if args.secure_boot_key is None and args.secure_boot_certificate is None:
            die("UEFI SecureBoot enabled, but couldn't find the certificate and private key.",
                hint="Consider generating them with 'mkosi genkey'.")
        if args.secure_boot_key is None:
            die("UEFI SecureBoot enabled, certificate was found, but not the private key.",
                hint="Consider placing it in mkosi.key")
        if args.secure_boot_certificate is None:
            die("UEFI SecureBoot enabled, private key was found, but not the certificate.",
                hint="Consider placing it in mkosi.crt")

    if args.repositories and not (
        args.distribution.is_dnf_distribution() or
        args.distribution.is_apt_distribution() or
        args.distribution == Distribution.arch
    ):
        die("Sorry, the --repositories option is only supported on pacman, dnf and apt based distributions")

    if args.overlay and not args.base_trees:
        die("--overlay can only be used with --base-tree")

    if args.incremental and not args.cache_dir:
        die("A cache directory must be configured in order to use --incremental")

    # For unprivileged builds we need the userxattr OverlayFS mount option, which is only available
    # in Linux v5.11 and later.
    if (
        (args.build_scripts or args.base_trees) and
        GenericVersion(platform.release()) < GenericVersion("5.11") and
        os.geteuid() != 0
    ):
        die("This unprivileged build configuration requires at least Linux v5.11")

    return MkosiConfig.from_namespace(args)


def yes_no(b: bool) -> str:
    return "yes" if b else "no"


def yes_no_auto(f: ConfigFeature) -> str:
    return "auto" if f is ConfigFeature.auto else yes_no(f == ConfigFeature.enabled)


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
    return "\n                                ".join(items)


def format_source_target(source: Path, target: Optional[Path]) -> str:
    return f"{source}:{target}" if target else f"{source}"


def line_join_source_target_list(array: Sequence[tuple[Path, Optional[Path]]]) -> str:
    if not array:
        return "none"

    items = [format_source_target(source, target) for source, target in array]
    return "\n                                ".join(items)


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


def summary(config: MkosiConfig) -> str:
    def bold(s: Any) -> str:
        return f"{Style.bold}{s}{Style.reset}"

    maniformats = (" ".join(i.name for i in config.manifest_format)) or "(none)"
    env = [f"{k}={v}" for k, v in config.environment.items()]

    summary = f"""\
{bold(f"IMAGE: {config.image or 'default'}")}

    {bold("CONFIG")}:
                       Profile: {none_to_none(config.profile)}
                       Include: {line_join_list(config.include)}
                        Images: {line_join_list(config.images)}
                  Dependencies: {line_join_list(config.dependencies)}

    {bold("DISTRIBUTION")}:
                  Distribution: {bold(config.distribution)}
                       Release: {bold(none_to_na(config.release))}
                  Architecture: {config.architecture}
                        Mirror: {none_to_default(config.mirror)}
          Local Mirror (build): {none_to_none(config.local_mirror)}
      Repo Signature/Key check: {yes_no(config.repository_key_check)}
                  Repositories: {line_join_list(config.repositories)}
        Use Only Package Cache: {yes_no(config.cache_only)}
         Package Manager Trees: {line_join_source_target_list(config.package_manager_trees)}

    {bold("OUTPUT")}:
                 Output Format: {config.output_format}
              Manifest Formats: {maniformats}
                        Output: {bold(config.output_with_compression)}
                   Compression: {config.compress_output}
              Output Directory: {none_to_default(config.output_dir)}
           Workspace Directory: {none_to_default(config.workspace_dir)}
               Cache Directory: {none_to_none(config.cache_dir)}
               Build Directory: {none_to_none(config.build_dir)}
                      Image ID: {config.image_id}
                 Image Version: {config.image_version}
               Split Artifacts: {yes_no(config.split_artifacts)}
            Repart Directories: {line_join_list(config.repart_dirs)}
                   Sector Size: {none_to_default(config.sector_size)}
                       Overlay: {yes_no(config.overlay)}
                Use Subvolumes: {yes_no_auto(config.use_subvolumes)}
                          Seed: {none_to_random(config.seed)}

    {bold("CONTENT")}:
                      Packages: {line_join_list(config.packages)}
                Build Packages: {line_join_list(config.build_packages)}
            With Documentation: {yes_no(config.with_docs)}

                    Base Trees: {line_join_list(config.base_trees)}
                Skeleton Trees: {line_join_source_target_list(config.skeleton_trees)}
                   Extra Trees: {line_join_source_target_list(config.extra_trees)}

               Remove Packages: {line_join_list(config.remove_packages)}
                  Remove Files: {line_join_list(config.remove_files)}
Clean Package Manager Metadata: {yes_no_auto(config.clean_package_metadata)}
             Source Date Epoch: {none_to_none(config.source_date_epoch)}

               Prepare Scripts: {line_join_list(config.prepare_scripts)}
                 Build Scripts: {line_join_list(config.build_scripts)}
           Postinstall Scripts: {line_join_list(config.postinst_scripts)}
              Finalize Scripts: {line_join_list(config.finalize_scripts)}
                 Build Sources: {line_join_source_target_list(config.build_sources)}
            Script Environment: {line_join_list(env)}
    Run Tests in Build Scripts: {yes_no(config.with_tests)}
          Scripts With Network: {yes_no(config.with_network)}

                      Bootable: {yes_no_auto(config.bootable)}
                    Bootloader: {config.bootloader}
               BIOS Bootloader: {config.bios_bootloader}
                       Initrds: {line_join_list(config.initrds)}
               Initrd Packages: {line_join_list(config.initrd_packages)}
           Kernel Command Line: {line_join_list(config.kernel_command_line)}
        Kernel Modules Include: {line_join_list(config.kernel_modules_include)}
        Kernel Modules Exclude: {line_join_list(config.kernel_modules_exclude)}

         Kernel Modules Initrd: {yes_no(config.kernel_modules_initrd)}
 Kernel Modules Initrd Include: {line_join_list(config.kernel_modules_initrd_include)}
 Kernel Modules Initrd Exclude: {line_join_list(config.kernel_modules_initrd_include)}

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
"""

    if config.output_format == OutputFormat.disk:
        summary += f"""\

    {bold("VALIDATION")}:
               UEFI SecureBoot: {yes_no(config.secure_boot)}
        SecureBoot Signing Key: {none_to_none(config.secure_boot_key)}
        SecureBoot Certificate: {none_to_none(config.secure_boot_certificate)}
          SecureBoot Sign Tool: {config.secure_boot_sign_tool}
            Verity Signing Key: {none_to_none(config.verity_key)}
            Verity Certificate: {none_to_none(config.verity_certificate)}
            Sign Expected PCRs: {yes_no_auto(config.sign_expected_pcr)}
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
                 Runtime Trees: {line_join_source_target_list(config.runtime_trees)}
                  Runtime Size: {format_bytes_or_none(config.runtime_size)}

                      QEMU GUI: {yes_no(config.qemu_gui)}
                QEMU CPU Cores: {config.qemu_smp}
                   QEMU Memory: {config.qemu_mem}
                  QEMU Use KVM: {config.qemu_kvm}
                QEMU Use VSock: {config.qemu_vsock}
                QEMU Use Swtpm: {config.qemu_swtpm}
               QEMU Use CD-ROM: {yes_no(config.qemu_cdrom)}
                 QEMU Firmware: {config.qemu_firmware}
          QEMU Extra Arguments: {line_join_list(config.qemu_args)}
"""

    return summary


class MkosiJsonEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, StrEnum):
            return str(obj)
        elif isinstance(obj, os.PathLike):
            return os.fspath(obj)
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, (MkosiArgs, MkosiConfig)):
            return obj.to_dict()
        return json.JSONEncoder.default(self, obj)


E = TypeVar("E", bound=StrEnum)


def json_type_transformer(refcls: Union[type[MkosiArgs], type[MkosiConfig]]) -> Callable[[str, Any], Any]:
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

    def source_target_transformer(
        trees: list[list[Optional[str]]], fieldtype: type[list[tuple[Path, Optional[Path]]]]
    ) -> list[tuple[Path, Optional[Path]]]:
        # TODO: exchange for TypeGuard and list comprehension once on 3.10
        ret = []
        for src, tgt in trees:
            assert src is not None
            source = Path(src)
            target = Path(tgt) if tgt is not None else None
            ret.append((source, target))
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

    transformers = {
        Path: path_transformer,
        Optional[Path]: optional_path_transformer,
        list[Path]: path_list_transformer,
        Optional[uuid.UUID]: optional_uuid_transformer,
        Optional[tuple[str, bool]]: root_password_transformer,
        list[tuple[Path, Optional[Path]]]: source_target_transformer,
        tuple[str, ...]: str_tuple_transformer,
        Architecture: enum_transformer,
        BiosBootloader: enum_transformer,
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
