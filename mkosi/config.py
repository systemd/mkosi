# SPDX-License-Identifier: LGPL-2.1+

import argparse
import base64
import configparser
import copy
import dataclasses
import enum
import fnmatch
import functools
import inspect
import operator
import os.path
import platform
import shlex
import shutil
import string
import subprocess
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable, Optional, Type, Union, cast

from mkosi.architecture import Architecture
from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, Style, die
from mkosi.pager import page
from mkosi.run import run
from mkosi.util import (
    Compression,
    Distribution,
    InvokingUser,
    ManifestFormat,
    OutputFormat,
    Verb,
    chdir,
    detect_distribution,
    flatten,
    is_apt_distribution,
    is_dnf_distribution,
    is_portage_distribution,
    prepend_to_environ_path,
    qemu_check_kvm_support,
    qemu_check_vsock_support,
)

__version__ = "14"

MKOSI_COMMANDS_CMDLINE = (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.ssh)

ConfigParseCallback = Callable[[str, Optional[str], argparse.Namespace], Any]
ConfigMatchCallback = Callable[[str, str, argparse.Namespace], bool]
ConfigDefaultCallback = Callable[[argparse.Namespace], Any]


class ConfigFeature(enum.Enum):
    auto = "auto"
    enabled = "enabled"
    disabled = "disabled"

    def __str__(self) -> str:
        return str(self.value).lower()


class SecureBootSignTool(enum.Enum):
    auto = "auto"
    sbsign = "sbsign"
    pesign = "pesign"

    def __str__(self) -> str:
        return str(self.value).lower()


def parse_boolean(s: str) -> bool:
    "Parse 1/true/yes/y/t/on as true and 0/false/no/n/f/off/None as false"
    s_l = s.lower()
    if s_l in {"1", "true", "yes", "y", "t", "on"}:
        return True

    if s_l in {"0", "false", "no", "n", "f", "off"}:
        return False

    die(f"Invalid boolean literal: {s!r}")


def parse_path(value: str,
               *,
               required: bool = True,
               absolute: bool = True,
               expanduser: bool = True,
               expandvars: bool = True,
               secret: bool = False) -> Path:
    if expandvars:
        value = os.path.expandvars(value)

    path = Path(value)

    if expanduser:
        if path.is_relative_to("~") and not InvokingUser.is_running_user():
            path = InvokingUser.home() / path.relative_to("~")
        path = path.expanduser()

    if required and not path.exists():
        die(f"{value} does not exist")

    if absolute:
        path = path.absolute()

    if secret and path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o007:
            die(textwrap.dedent(f"""\
                Permissions of '{path}' of '{mode:04o}' are too open.
                When creating secret files use an access mode that restricts access to the owner only.
            """))

    return path


def parse_source_target_paths(value: str) -> tuple[Path, Optional[Path]]:
    src, sep, target = value.partition(':')
    src_path = parse_path(src, required=False)
    if sep:
        target_path = parse_path(target, required=False, absolute=False, expanduser=False)
        if not target_path.is_absolute():
            die("Target path must be absolute")
    else:
        target_path = None
    return src_path, target_path


def config_parse_string(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[str]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    return value if value else None


def config_make_string_matcher(allow_globs: bool = False) -> ConfigMatchCallback:
    def config_match_string(dest: str, value: str, namespace: argparse.Namespace) -> bool:
        if getattr(namespace, dest, None) is None:
            return False

        if allow_globs:
            return fnmatch.fnmatchcase(getattr(namespace, dest), value)
        else:
            return cast(bool, value == getattr(namespace, dest))

    return config_match_string


def config_parse_script(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[Path]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if value:
        path = parse_path(value)
        if not os.access(path, os.X_OK):
            die(f"{value} is not executable")
        return path

    return None


def config_parse_boolean(dest: str, value: Optional[str], namespace: argparse.Namespace) -> bool:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    return parse_boolean(value) if value else False


def config_match_boolean(dest: str, value: str, namespace: argparse.Namespace) -> bool:
    return cast(bool, getattr(namespace, dest) == parse_boolean(value))


def parse_feature(value: Optional[str]) -> ConfigFeature:
    if not value or value == ConfigFeature.auto.value:
        return ConfigFeature.auto

    return ConfigFeature.enabled if parse_boolean(value) else ConfigFeature.disabled


def config_parse_feature(dest: str, value: Optional[str], namespace: argparse.Namespace) -> ConfigFeature:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    return parse_feature(value)


def config_match_feature(dest: str, value: Optional[str], namespace: argparse.Namespace) -> bool:
    return cast(bool, getattr(namespace, dest) == parse_feature(value))


def config_parse_compression(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[Compression]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if not value:
        return None

    try:
        return Compression[value]
    except KeyError:
        return Compression.zst if parse_boolean(value) else Compression.none


def config_default_release(namespace: argparse.Namespace) -> str:
    # If we encounter Release in [Match] and no distribution has been set yet, configure the default
    # distribution as well since the default release depends on the selected distribution.
    if "distribution" not in namespace:
        setattr(namespace, "distribution", detect_distribution()[0])

    d = getattr(namespace, "distribution")

    # If the configured distribution matches the host distribution, use the same release as the host.
    hd, hr = detect_distribution()
    if d == hd and hr is not None:
        return hr

    return {
        Distribution.fedora: "38",
        Distribution.centos: "9",
        Distribution.debian: "testing",
        Distribution.ubuntu: "jammy",
        Distribution.opensuse: "tumbleweed",
        Distribution.gentoo: "17.1",
    }.get(d, "rolling")


def config_default_mirror(namespace: argparse.Namespace) -> Optional[str]:
    if "distribution" not in namespace:
        setattr(namespace, "distribution", detect_distribution()[0])
    if "architecture" not in namespace:
        setattr(namespace, "architecture", Architecture.native())

    d = getattr(namespace, "distribution")
    r = getattr(namespace, "release", None)
    a = getattr(namespace, "architecture")

    if d == Distribution.debian:
        return "http://deb.debian.org/debian"
    elif d == Distribution.ubuntu:
        if a == Architecture.x86 or a == Architecture.x86_64:
            return "http://archive.ubuntu.com/ubuntu"
        else:
            return "http://ports.ubuntu.com"
    elif d == Distribution.arch:
        if a == Architecture.arm64:
            return "http://mirror.archlinuxarm.org"
        else:
            return "https://geo.mirror.pkgbuild.com"
    elif d == Distribution.opensuse:
        return "https://download.opensuse.org"
    elif d == Distribution.fedora and r == "eln":
        return "https://odcs.fedoraproject.org/composes/production/latest-Fedora-ELN/compose"
    elif d == Distribution.gentoo:
        return "https://distfiles.gentoo.org"

    return None


def config_default_package_manager_tree(namespace: argparse.Namespace) -> list[tuple[Path, Optional[Path]]]:
    return getattr(namespace, "skeleton_trees", [])


def make_enum_parser(type: Type[enum.Enum]) -> Callable[[str], enum.Enum]:
    def parse_enum(value: str) -> enum.Enum:
        try:
            return type(value)
        except ValueError:
            die(f"'{value}' is not a valid {type.__name__}")

    return parse_enum


def config_make_enum_parser(type: Type[enum.Enum]) -> ConfigParseCallback:
    def config_parse_enum(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[enum.Enum]:
        if dest in namespace:
            return getattr(namespace, dest) # type: ignore

        return make_enum_parser(type)(value) if value else None

    return config_parse_enum


def config_make_enum_matcher(type: Type[enum.Enum]) -> ConfigMatchCallback:
    def config_match_enum(dest: str, value: str, namespace: argparse.Namespace) -> bool:
        return cast(bool, make_enum_parser(type)(value) == getattr(namespace, dest))

    return config_match_enum


def config_make_list_parser(delimiter: str,
                            *,
                            parse: Callable[[str], Any] = str,
                            unescape: bool = False) -> ConfigParseCallback:
    ignore: set[str] = set()

    def config_parse_list(dest: str, value: Optional[str], namespace: argparse.Namespace) -> list[Any]:
        if dest not in namespace:
            ignore.clear()
            l = []
        else:
            l = getattr(namespace, dest).copy()

        if not value:
            return l # type: ignore

        if unescape:
            lex = shlex.shlex(value, posix=True)
            lex.whitespace_split = True
            lex.whitespace = f"\n{delimiter}"
            lex.commenters = ""
            values = list(lex)
        else:
            values = value.replace(delimiter, "\n").split("\n")

        for v in values:
            if not v:
                continue

            if v.startswith("!"):
                ignore.add(v[1:])
                continue

            for i in ignore:
                if fnmatch.fnmatchcase(v, i):
                    break
            else:
                l.insert(0, parse(v))

        return l

    return config_parse_list


def config_match_image_version(dest: str, value: str, namespace: argparse.Namespace) -> bool:
    image_version = getattr(namespace, dest)
    # If the version is not set it cannot positively compare to anything
    if image_version is None:
        return False
    image_version = GenericVersion(image_version)

    for sigil, opfunc in {
        "==": operator.eq,
        "!=": operator.ne,
        "<=": operator.le,
        ">=": operator.ge,
        ">": operator.gt,
        "<": operator.lt,
    }.items():
        if value.startswith(sigil):
            op = opfunc
            comp_version = GenericVersion(value[len(sigil):])
            break
    else:
        # default to equality if no operation is specified
        op = operator.eq
        comp_version = GenericVersion(value)

    # all constraints must be fulfilled
    if not op(image_version, comp_version):
        return False

    return True


def make_path_parser(*,
                     required: bool = True,
                     absolute: bool = True,
                     expanduser: bool = True,
                     expandvars: bool = True,
                     secret: bool = False) -> Callable[[str], Path]:
    return functools.partial(
        parse_path,
        required=required,
        absolute=absolute,
        expanduser=expanduser,
        expandvars=expandvars,
        secret=secret,
    )


def config_make_path_parser(*,
                            required: bool = True,
                            absolute: bool = True,
                            expanduser: bool = True,
                            expandvars: bool = True,
                            secret: bool = False) -> ConfigParseCallback:
    def config_parse_path(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[Path]:
        if dest in namespace:
            return getattr(namespace, dest) # type: ignore

        if value:
            return parse_path(
                value,
                required=required,
                absolute=absolute,
                expanduser=expanduser,
                expandvars=expandvars,
                secret=secret,
            )

        return None

    return config_parse_path


def config_parse_filename(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[str]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if not value:
        return None

    if value == "." or value == "..":
        die(". and .. are not valid filenames")

    if "/" in value:
        die(f"{value} is not a valid filename")

    return value


def match_path_exists(value: str) -> bool:
    if not value:
        return False

    return Path(value).exists()


def config_parse_root_password(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[tuple[str, bool]]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if not value:
        return None

    value = value.strip()
    hashed = value.startswith("hashed:")
    value = value.removeprefix("hashed:")

    return (value, hashed)


class ConfigParserMultipleValues(dict[str, Any]):
    def __setitem__(self, key: str, value: Any) -> None:
        if key in self and isinstance(value, list):
            self[key].extend(value)
        else:
            super().__setitem__(key, value)


@dataclasses.dataclass(frozen=True)
class MkosiConfigSetting:
    dest: str
    section: str
    parse: ConfigParseCallback = config_parse_string
    match: Optional[ConfigMatchCallback] = None
    name: str = ""
    default: Any = None
    default_factory: Optional[ConfigDefaultCallback] = None
    paths: tuple[str, ...] = ()
    path_read_text: bool = False
    path_secret: bool = False

    # settings for argparse
    short: Optional[str] = None
    long: Optional[str] = None
    choices: Optional[Any] = None
    metavar: Optional[str] = None
    nargs: Optional[str] = None
    const: Optional[Any] = None
    help: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.name:
            object.__setattr__(self, 'name', ''.join(x.capitalize() for x in self.dest.split('_') if x))


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


def config_make_action(settings: Sequence[MkosiConfigSetting]) -> Type[argparse.Action]:
    lookup = {s.dest: s for s in settings}

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
                s = lookup[self.dest]
            except KeyError:
                die(f"Unknown setting {option_string}")

            if values is None or isinstance(values, str):
                setattr(namespace, s.dest, s.parse(self.dest, values, namespace))
            else:
                for v in values:
                    assert isinstance(v, str)
                    setattr(namespace, s.dest, s.parse(self.dest, v, namespace))

    return MkosiAction


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
    presets: list[str]

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> "MkosiArgs":
        return cls(**{
            k: v for k, v in vars(ns).items()
            if k in inspect.signature(cls).parameters
        })


@dataclasses.dataclass(frozen=True)
class MkosiConfig:
    """Type-hinted storage for command line arguments.

    Only user configuration is stored here while dynamic state exists in
    MkosiState. If a field of the same name exists in both classes always
    access the value from state.
    """

    distribution: Distribution
    release: str
    mirror: Optional[str]
    local_mirror: Optional[str]
    repository_key_check: bool
    repositories: list[str]
    repart_dirs: list[Path]
    overlay: bool
    architecture: Architecture
    output_format: OutputFormat
    manifest_format: list[ManifestFormat]
    output: str
    output_dir: Path
    kernel_command_line: list[str]
    secure_boot: bool
    secure_boot_key: Optional[Path]
    secure_boot_certificate: Optional[Path]
    secure_boot_sign_tool: SecureBootSignTool
    verity_key: Optional[Path]
    verity_certificate: Optional[Path]
    sign_expected_pcr: ConfigFeature
    compress_output: Compression
    image_version: Optional[str]
    image_id: Optional[str]
    tar_strip_selinux_context: bool
    incremental: bool
    packages: list[str]
    remove_packages: list[str]
    with_docs: bool
    with_tests: bool
    cache_dir: Optional[Path]
    base_trees: list[Path]
    extra_trees: list[tuple[Path, Optional[Path]]]
    skeleton_trees: list[tuple[Path, Optional[Path]]]
    package_manager_trees: list[tuple[Path, Optional[Path]]]
    clean_package_metadata: ConfigFeature
    remove_files: list[str]
    environment: dict[str, str]
    build_sources: Path
    build_dir: Optional[Path]
    build_packages: list[str]
    build_script: Optional[Path]
    prepare_script: Optional[Path]
    postinst_script: Optional[Path]
    finalize_script: Optional[Path]
    with_network: bool
    cache_only: bool
    nspawn_settings: Optional[Path]
    checksum: bool
    split_artifacts: bool
    sign: bool
    key: Optional[str]
    autologin: bool
    extra_search_paths: list[Path]
    ephemeral: bool
    ssh: bool
    credentials: dict[str, str]
    workspace_dir: Optional[Path]
    initrds: list[Path]
    make_initrd: bool
    kernel_modules_include: list[str]
    kernel_modules_exclude: list[str]
    kernel_modules_initrd: bool
    kernel_modules_initrd_include: list[str]
    kernel_modules_initrd_exclude: list[str]
    kernel_command_line_extra: list[str]
    acl: bool
    bootable: ConfigFeature
    use_subvolumes: ConfigFeature
    locale: Optional[str]
    locale_messages: Optional[str]
    keymap: Optional[str]
    timezone: Optional[str]
    hostname: Optional[str]
    root_password: Optional[tuple[str, bool]]
    root_shell: Optional[str]

    # QEMU-specific options
    qemu_gui: bool
    qemu_smp: str
    qemu_mem: str
    qemu_kvm: ConfigFeature
    qemu_vsock: ConfigFeature
    qemu_swtpm: ConfigFeature
    qemu_args: Sequence[str]

    passphrase: Optional[Path]

    preset: Optional[str]

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
            OutputFormat.tar: ".tar",
        }.get(self.output_format, "")

        return output

    @property
    def output_with_compression(self) -> str:
        output = self.output_with_format

        if self.compress_output:
            output += f".{self.compress_output}"

        return output

    @property
    def output_split_uki(self) -> str:
        return f"{self.output_with_version}.efi"

    @property
    def output_split_kernel(self) -> str:
        return f"{self.output_with_version}.vmlinuz"

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
        manifest: dict[str, Any] = {
            "packages": self.packages,
            "build_packages": self.build_packages,
            "repositories": self.repositories,
        }

        if self.prepare_script:
            manifest["prepare_script"] = base64.b64encode(self.prepare_script.read_bytes()).decode()

        return manifest


class MkosiConfigParser:
    SETTINGS = (
        MkosiConfigSetting(
            dest="distribution",
            short="-d",
            section="Distribution",
            parse=config_make_enum_parser(Distribution),
            match=config_make_enum_matcher(Distribution),
            default=detect_distribution()[0],
            choices=Distribution.__members__,
            help="Distribution to install",
        ),
        MkosiConfigSetting(
            dest="release",
            short="-r",
            section="Distribution",
            parse=config_parse_string,
            match=config_make_string_matcher(),
            default_factory=config_default_release,
            help="Distribution release to install",
        ),
        MkosiConfigSetting(
            dest="architecture",
            section="Distribution",
            parse=config_make_enum_parser(Architecture),
            default=Architecture.native(),
            help="Override the architecture of installation",
        ),
        MkosiConfigSetting(
            dest="mirror",
            short="-m",
            section="Distribution",
            default_factory=config_default_mirror,
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
            dest="output_format",
            short="-t",
            long="--format",
            metavar="FORMAT",
            name="Format",
            section="Output",
            parse=config_make_enum_parser(OutputFormat),
            default=OutputFormat.disk,
            choices=OutputFormat.__members__,
            help="Output Format",
        ),
        MkosiConfigSetting(
            dest="manifest_format",
            metavar="FORMAT",
            section="Output",
            parse=config_make_list_parser(delimiter=",", parse=make_enum_parser(ManifestFormat)),
            default=[ManifestFormat.json],
            help="Manifest Format",
        ),
        MkosiConfigSetting(
            dest="output",
            short="-o",
            metavar="PATH",
            section="Output",
            parse=config_parse_filename,
            help="Output name",
        ),
        MkosiConfigSetting(
            dest="output_dir",
            short="-O",
            metavar="DIR",
            name="OutputDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.output",),
            default=Path("."),
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
            dest="compress_output",
            metavar="ALG",
            nargs="?",
            section="Output",
            parse=config_parse_compression,
            help="Enable whole-output compression (with images or archives)",
        ),
        MkosiConfigSetting(
            dest="image_version",
            match=config_match_image_version,
            section="Output",
            help="Set version for image",
        ),
        MkosiConfigSetting(
            dest="image_id",
            match=config_make_string_matcher(allow_globs=True),
            section="Output",
            help="Set ID for image",
        ),
        MkosiConfigSetting(
            dest="tar_strip_selinux_context",
            metavar="BOOL",
            nargs="?",
            section="Output",
            parse=config_parse_boolean,
            help="Do not include SELinux file context information in tar. Not compatible with bsdtar.",
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
            dest="packages",
            short="-p",
            long="--package",
            metavar="PACKAGE",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
            help="Add an additional package to the OS image",
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
            dest="with_docs",
            metavar="BOOL",
            nargs="?",
            section="Content",
            parse=config_parse_boolean,
            help="Install documentation",
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
            help="Do not run tests as part of build script, if supported",
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
            dest="bootable",
            metavar="FEATURE",
            nargs="?",
            section="Content",
            parse=config_parse_feature,
            match=config_match_feature,
            help="Generate ESP partition with systemd-boot and UKIs for installed kernels",
        ),
        MkosiConfigSetting(
            dest="autologin",
            metavar="BOOL",
            nargs="?",
            section="Content",
            parse=config_parse_boolean,
            help="Enable root autologin",
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
            dest="extra_trees",
            long="--extra-tree",
            metavar="PATH",
            section="Content",
            parse=config_make_list_parser(delimiter=",", parse=parse_source_target_paths),
            paths=("mkosi.extra", "mkosi.extra.tar"),
            help="Copy an extra tree on top of image",
        ),
        MkosiConfigSetting(
            dest="skeleton_trees",
            long="--skeleton-tree",
            metavar="PATH",
            section="Content",
            parse=config_make_list_parser(delimiter=",", parse=parse_source_target_paths),
            paths=("mkosi.skeleton", "mkosi.skeleton.tar"),
            help="Use a skeleton tree to bootstrap the image before installing anything",
        ),
        MkosiConfigSetting(
            dest="package_manager_trees",
            long="--package-manager-tree",
            metavar="PATH",
            section="Content",
            parse=config_make_list_parser(delimiter=",", parse=parse_source_target_paths),
            default_factory=config_default_package_manager_tree,
            help="Use a package manager tree to configure the package manager",
        ),
        MkosiConfigSetting(
            dest="clean_package_metadata",
            metavar="FEATURE",
            section="Content",
            parse=config_parse_feature,
            help="Remove package manager database and other files",
        ),
        MkosiConfigSetting(
            dest="remove_files",
            metavar="GLOB",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
            help="Remove files from built image",
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
            dest="build_sources",
            metavar="PATH",
            section="Content",
            parse=config_make_path_parser(),
            default=Path("."),
            help="Path for sources to build",
        ),
        MkosiConfigSetting(
            dest="build_packages",
            long="--build-package",
            metavar="PACKAGE",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
            help="Additional packages needed for build script",
        ),
        MkosiConfigSetting(
            dest="build_script",
            metavar="PATH",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.build",),
            help="Build script to run inside image",
        ),
        MkosiConfigSetting(
            dest="prepare_script",
            metavar="PATH",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.prepare",),
            help="Prepare script to run inside the image before it is cached",
        ),
        MkosiConfigSetting(
            dest="postinst_script",
            metavar="PATH",
            name="PostInstallationScript",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.postinst",),
            help="Postinstall script to run inside image",
        ),
        MkosiConfigSetting(
            dest="finalize_script",
            metavar="PATH",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.finalize",),
            help="Postinstall script to run outside image",
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
            dest="cache_only",
            metavar="BOOL",
            section="Content",
            parse=config_parse_boolean,
            help="Only use the package cache when installing packages",
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
            dest="make_initrd",
            metavar="BOOL",
            nargs="?",
            section="Content",
            parse=config_parse_boolean,
            help="Make sure the image can be used as an initramfs",
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
            help="List of colon-separated paths to look for programs before looking in PATH",
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
            dest="ssh",
            metavar="BOOL",
            nargs="?",
            section="Host",
            parse=config_parse_boolean,
            help="Set up SSH access from the host to the final image via 'mkosi ssh'",
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
    )

    MATCHES = (
        MkosiMatch(
            name="PathExists",
            match=match_path_exists,
        ),
    )

    def __init__(self) -> None:
        self.settings_lookup = {s.name: s for s in self.SETTINGS}
        self.match_lookup = {m.name: m for m in self.MATCHES}

    def parse_config(self, path: Path, namespace: argparse.Namespace) -> bool:
        extras = path.is_dir()

        if path.is_dir():
            path = path / "mkosi.conf"

        parser = configparser.ConfigParser(
            delimiters="=",
            comment_prefixes="#",
            inline_comment_prefixes="#",
            empty_lines_in_values=True,
            interpolation=None,
            strict=False,
            dict_type=ConfigParserMultipleValues,
        )

        parser.optionxform = lambda optionstr: optionstr # type: ignore

        if path.exists():
            parser.read(path)

        if "Match" in parser.sections():
            triggered = None

            for k, values in parser.items("Match"):
                # If a match is specified multiple times, the values are returned concatenated by newlines
                # for some reason.
                for v in values.split("\n"):
                    trigger = v.startswith("|")
                    v = v.removeprefix("|")
                    negate = v.startswith("!")
                    v = v.removeprefix("!")

                    if not v:
                        die("Match value cannot be empty")

                    if (s := self.settings_lookup.get(k)):
                        if not (match := s.match):
                            die(f"{k} cannot be used in [Match]")

                        # If we encounter a setting in [Match] that has not been explicitly configured yet,
                        # we assign the default value first so that we can [Match] on default values for
                        # settings.
                        if s.dest not in namespace:
                            if s.default_factory:
                                default = s.default_factory(namespace)
                            elif s.default is None:
                                default = s.parse(s.dest, None, namespace)
                            else:
                                default = s.default

                            setattr(namespace, s.dest, default)

                        result = match(s.dest, v, namespace)

                    elif (m := self.match_lookup.get(k)):
                        result = m.match(v)
                    else:
                        die(f"{k} cannot be used in [Match]")

                    if negate:
                        result = not result
                    if not trigger and not result:
                        return False
                    if trigger:
                        triggered = bool(triggered) or result

                if triggered is False:
                    return False

        parser.remove_section("Match")

        for section in parser.sections():
            for k, v in parser.items(section):
                if not (s := self.settings_lookup.get(k)):
                    die(f"Unknown setting {k}")

                setattr(namespace, s.dest, s.parse(s.dest, v, namespace))

        if extras:
            # Dropin configuration has priority over any default paths.

            if path.parent.joinpath("mkosi.conf.d").exists():
                for p in sorted(path.parent.joinpath("mkosi.conf.d").iterdir()):
                    if p.is_dir() or p.suffix == ".conf":
                        with chdir(p if p.is_dir() else Path.cwd()):
                            self.parse_config(p if p.is_file() else Path("."), namespace)

            for s in self.SETTINGS:
                for f in s.paths:
                    p = parse_path(f, secret=s.path_secret, required=False, absolute=False, expanduser=False, expandvars=False)
                    if p.exists():
                        setattr(namespace, s.dest,
                                s.parse(s.dest, p.read_text() if s.path_read_text else f, namespace))

        return True

    def create_argument_parser(self) -> argparse.ArgumentParser:
        action = config_make_action(self.SETTINGS)

        parser = argparse.ArgumentParser(
            prog="mkosi",
            description="Build Bespoke OS Images",
            usage="\n  " + textwrap.dedent("""\
                  mkosi [options...] {b}summary{e}
                    mkosi [options...] {b}build{e} [script parameters...]
                    mkosi [options...] {b}shell{e} [command line...]
                    mkosi [options...] {b}boot{e}  [nspawn settings...]
                    mkosi [options...] {b}qemu{e}  [qemu parameters...]
                    mkosi [options...] {b}ssh{e}   [command line...]
                    mkosi [options...] {b}clean{e}
                    mkosi [options...] {b}serve{e}
                    mkosi [options...] {b}bump{e}
                    mkosi [options...] {b}genkey{e}
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
            help="Change to specified directory before doing anything",
            metavar="PATH",
            default=None,
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
            "--preset",
            action="append",
            dest="presets",
            default=[],
            help="Build the specified preset",
        )

        last_section = None

        for s in self.SETTINGS:
            if s.section != last_section:
                group = parser.add_argument_group(f"{s.section} configuration options")
                last_section = s.section

            long = s.long if s.long else f"--{s.dest.replace('_', '-')}"
            opts = [s.short, long] if s.short else [long]

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

    def parse(self, argv: Optional[Sequence[str]] = None) -> tuple[MkosiArgs, tuple[MkosiConfig, ...]]:
        presets = []
        namespace = argparse.Namespace()

        if argv is None:
            argv = sys.argv[1:]
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

        argparser = self.create_argument_parser()
        argparser.parse_args(argv, namespace)

        args = load_args(namespace)

        if args.verb == Verb.help:
            PagerHelpAction.__call__(None, argparser, namespace)  # type: ignore

        if args.directory and not Path(args.directory).is_dir():
            die(f"{args.directory} is not a directory!")

        if args.directory:
            os.chdir(args.directory)

        if args.directory != "":
            self.parse_config(Path("."), namespace)

            if Path("mkosi.presets").exists():
                for p in sorted(Path("mkosi.presets").iterdir()):
                    name = p.name.lstrip(string.digits + "-").removesuffix(".conf")
                    if not name:
                        die(f"{p} is not a valid preset name")
                    if args.presets and name not in args.presets:
                        continue

                    cp = copy.deepcopy(namespace)

                    with chdir(p if p.is_dir() else Path.cwd()):
                        if not self.parse_config(p if p.is_file() else Path("."), cp):
                            continue

                    setattr(cp, "preset", name)

                    presets += [cp]

        if not presets:
            setattr(namespace, "preset", None)
            presets = [namespace]

        if not presets:
            die("No presets defined in mkosi.presets/")

        for ns in presets:
            for s in self.SETTINGS:
                if s.dest in ns:
                    continue

                if s.default_factory:
                    default = s.default_factory(ns)
                elif s.default is None:
                    default = s.parse(s.dest, None, ns)
                else:
                    default = s.default

                setattr(ns, s.dest, default)

        return args, tuple(load_config(ns) for ns in presets)


class GenericVersion:
    def __init__(self, version: str):
        self._version = version

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GenericVersion):
            return False
        cmd = ["systemd-analyze", "compare-versions", self._version, "eq", other._version]
        return run(cmd, check=False).returncode == 0

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, GenericVersion):
            return False
        cmd = ["systemd-analyze", "compare-versions", self._version, "ne", other._version]
        return run(cmd, check=False).returncode == 0

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, GenericVersion):
            return False
        cmd = ["systemd-analyze", "compare-versions", self._version, "lt", other._version]
        return run(cmd, check=False).returncode == 0

    def __le__(self, other: object) -> bool:
        if not isinstance(other, GenericVersion):
            return False
        cmd = ["systemd-analyze", "compare-versions", self._version, "le", other._version]
        return run(cmd, check=False).returncode == 0

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, GenericVersion):
            return False
        cmd = ["systemd-analyze", "compare-versions", self._version, "gt", other._version]
        return run(cmd, check=False).returncode == 0

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, GenericVersion):
            return False
        cmd = ["systemd-analyze", "compare-versions", self._version, "ge", other._version]
        return run(cmd, check=False).returncode == 0


def find_image_version(args: argparse.Namespace) -> None:
    if args.image_version is not None:
        return

    try:
        with open("mkosi.version") as f:
            args.image_version = f.read().strip()
    except FileNotFoundError:
        pass


def load_credentials(args: argparse.Namespace) -> dict[str, str]:
    creds = {}

    d = Path("mkosi.credentials")
    if args.directory != "" and d.is_dir():
        for e in d.iterdir():
            if os.access(e, os.X_OK):
                creds[e.name] = run([e], text=True, stdout=subprocess.PIPE, env=os.environ).stdout
            else:
                creds[e.name] = e.read_text()

    for s in args.credentials:
        key, _, value = s.partition("=")
        creds[key] = value

    if "firstboot.timezone" not in creds:
        tz = run(
            ["timedatectl", "show", "-p", "Timezone", "--value"],
            text=True,
            stdout=subprocess.PIPE,
            check=False,
        ).stdout.strip()
        if tz:
            creds["firstboot.timezone"] = tz

    if "firstboot.locale" not in creds:
        creds["firstboot.locale"] = "C.UTF-8"

    if args.ssh and "ssh.authorized_keys.root" not in creds and "SSH_AUTH_SOCK" in os.environ:
        key = run(
            ["ssh-add", "-L"],
            text=True,
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
        f"systemd.tty.term.console={os.getenv('TERM', 'vt220')}",
        f"systemd.tty.columns.console={columns}",
        f"systemd.tty.rows.console={lines}",
        f"systemd.tty.term.ttyS0={os.getenv('TERM', 'vt220')}",
        f"systemd.tty.columns.ttyS0={columns}",
        f"systemd.tty.rows.ttyS0={lines}",
        "console=ttyS0",
    ]

    if args.output_format == OutputFormat.cpio:
        cmdline += ["rd.systemd.unit=default.target"]

    for s in args.kernel_command_line_extra:
        key, sep, value = s.partition("=")
        if " " in value:
            value = f'"{value}"'
        cmdline += [key if not sep else f"{key}={value}"]

    return cmdline


def load_args(args: argparse.Namespace) -> MkosiArgs:
    if args.debug:
        ARG_DEBUG.set(args.debug)
    if args.debug_shell:
        ARG_DEBUG_SHELL.set(args.debug_shell)

    return MkosiArgs.from_namespace(args)


def load_config(args: argparse.Namespace) -> MkosiConfig:
    find_image_version(args)

    if args.cmdline and args.verb not in MKOSI_COMMANDS_CMDLINE:
        die(f"Parameters after verb are only accepted for {' '.join(verb.name for verb in MKOSI_COMMANDS_CMDLINE)}.")

    if args.cache_dir:
        args.cache_dir = args.cache_dir / f"{args.distribution}~{args.release}"
    if args.build_dir:
        args.build_dir = args.build_dir / f"{args.distribution}~{args.release}"

    if args.sign:
        args.checksum = True

    if args.compress_output is None:
        if args.output_format == OutputFormat.cpio:
            args.compress_output = Compression.xz if args.distribution == Distribution.centos and int(args.release) <= 8 else Compression.zst
        else:
            args.compress_output = Compression.none

    if args.output is None:
        args.output = args.image_id or args.preset or "image"

    if args.environment:
        env = {}
        for s in args.environment:
            key, sep, value = s.partition("=")
            value = value if sep else os.getenv(key, "")
            env[key] = value
        args.environment = env
    else:
        args.environment = {}

    args.credentials = load_credentials(args)
    args.kernel_command_line_extra = load_kernel_command_line_extra(args)

    if args.secure_boot and args.verb != Verb.genkey:
        if args.secure_boot_key is None:
            die("UEFI SecureBoot enabled, but couldn't find private key.",
                hint="Consider placing it in mkosi.key")

        if args.secure_boot_certificate is None:
            die("UEFI SecureBoot enabled, but couldn't find certificate.",
                hint="Consider placing it in mkosi.crt")

    if args.qemu_kvm == ConfigFeature.enabled and not qemu_check_kvm_support():
        die("Sorry, the host machine does not support KVM acceleration.")

    if args.qemu_vsock == ConfigFeature.enabled and not qemu_check_vsock_support(log=False):
        die("Sorry, the host machine does not support vsock")

    if args.qemu_swtpm == ConfigFeature.enabled and not shutil.which("swtpm"):
        die("swtpm is requested but not found in PATH")

    if args.repositories and not (
        is_dnf_distribution(args.distribution) or
        is_apt_distribution(args.distribution) or
        is_portage_distribution(args.distribution)
    ):
        die("Sorry, the --repositories option is only supported on DNF, Debian, Gentoo based distributions")

    if args.initrds:
        args.initrds = [p.absolute() for p in args.initrds]

    if args.overlay and not args.base_trees:
        die("--overlay can only be used with --base-tree")

    if args.incremental and not args.cache_dir:
        die("A cache directory must be configured in order to use --incremental")

    # For unprivileged builds we need the userxattr OverlayFS mount option, which is only available in Linux v5.11 and later.
    with prepend_to_environ_path(args.extra_search_paths):
        if (args.build_script is not None or args.base_trees) and GenericVersion(platform.release()) < GenericVersion("5.11") and os.geteuid() != 0:
            die("This unprivileged build configuration requires at least Linux v5.11")

        if args.sign_expected_pcr == ConfigFeature.enabled and not shutil.which("systemd-measure"):
            die("Couldn't find systemd-measure needed for the --sign-expected-pcr option.")

    return MkosiConfig.from_namespace(args)

