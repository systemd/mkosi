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
    prepend_to_environ_path,
    qemu_check_kvm_support,
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

    if secret:
        mode = path.stat().st_mode & 0o777
        if mode & 0o007:
            die(textwrap.dedent(f"""\
                Permissions of '{path}' of '{mode:04o}' are too open.
                When creating secret files use an access mode that restricts access to the owner only.
            """))

    return path


def parse_source_target_paths(value: str) -> tuple[Path, Optional[Path]]:
    src, sep, target = value.partition(':')
    src_path = parse_path(src, required=True)
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


def config_match_string(dest: str, value: str, namespace: argparse.Namespace) -> bool:
    return cast(bool, value == getattr(namespace, dest))


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


def config_parse_compression(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[Compression]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if not value:
        return None

    try:
        return Compression[value]
    except KeyError:
        return Compression.zst if parse_boolean(value) else Compression.none


def config_default_release(namespace: argparse.Namespace) -> Any:
    # If we encounter Release in [Match] and no distribution has been set yet, configure the default
    # distribution as well since the default release depends on the selected distribution.
    if "distribution" not in namespace:
        setattr(namespace, "distribution", detect_distribution()[0])

    d = getattr(namespace, "distribution")

    # If the configured distribution matches the host distribution, use the same release as the host.
    hd, hr = detect_distribution()
    if d == hd:
        return hr

    return {
        Distribution.fedora: "38",
        Distribution.centos: "9",
        Distribution.rocky: "9",
        Distribution.alma: "9",
        Distribution.mageia: "cauldron",
        Distribution.debian: "testing",
        Distribution.ubuntu: "jammy",
        Distribution.opensuse: "tumbleweed",
        Distribution.openmandriva: "cooker",
        Distribution.gentoo: "17.1",
    }.get(d, "rolling")


def config_default_mirror(namespace: argparse.Namespace) -> Optional[str]:
    if "distribution" not in namespace:
        setattr(namespace, "distribution", detect_distribution()[0])
    if "architecture" not in namespace:
        setattr(namespace, "architecture", platform.machine())

    d = getattr(namespace, "distribution")
    a = getattr(namespace, "architecture")

    if d == Distribution.debian:
        return "http://deb.debian.org/debian"
    elif d == Distribution.ubuntu:
        if a == "x86" or a == "x86_64":
            return "http://archive.ubuntu.com/ubuntu"
        else:
            return "http://ports.ubuntu.com"
    elif d == Distribution.arch:
        if a == "aarch64":
            return "http://mirror.archlinuxarm.org"
        else:
            return "https://geo.mirror.pkgbuild.com"
    elif d == Distribution.opensuse:
        return "https://download.opensuse.org"

    return None


def make_enum_parser(type: Type[enum.Enum]) -> Callable[[str], enum.Enum]:
    def parse_enum(value: str) -> enum.Enum:
        try:
            return type[value]
        except KeyError:
            die(f"Invalid {type.__name__} value \"{value}\"")

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


def config_make_list_matcher(
    delimiter: str,
    *,
    unescape: bool = False,
    allow_globs: bool = False,
    all: bool = False,
    parse: Callable[[str], Any] = str,
) -> ConfigMatchCallback:
    def config_match_list(dest: str, value: str, namespace: argparse.Namespace) -> bool:
        if unescape:
            lex = shlex.shlex(value, posix=True)
            lex.whitespace_split = True
            lex.whitespace = f"\n{delimiter}"
            lex.commenters = ""
            values = list(lex)
        else:
            values = value.replace(delimiter, "\n").split("\n")

        for v in values:
            current_value = getattr(namespace, dest)
            comparison_value = parse(v)
            if allow_globs:
                # check if the option has been set, since fnmatch wants strings
                if isinstance(current_value, str):
                    m = fnmatch.fnmatchcase(current_value, comparison_value)
                else:
                    m = False
            else:
                m = current_value == comparison_value

            if not all and m:
                return True
            if all and not m:
                return False

        return all

    return config_match_list


def config_make_image_version_list_matcher(delimiter: str) -> ConfigMatchCallback:
    def config_match_image_version_list(dest: str, value: str, namespace: argparse.Namespace) -> bool:
        version_specs = value.replace(delimiter, "\n").splitlines()

        image_version = getattr(namespace, dest)
        # If the version is not set it cannot positively compare to anything
        if image_version is None:
            return False
        image_version = GenericVersion(image_version)

        for v in version_specs:
            for sigil, opfunc in {
                "==": operator.eq,
                "!=": operator.ne,
                "<=": operator.le,
                ">=": operator.ge,
                ">": operator.gt,
                "<": operator.lt,
            }.items():
                if v.startswith(sigil):
                    op = opfunc
                    comp_version = GenericVersion(v[len(sigil):])
                    break
            else:
                # default to equality if no operation is specified
                op = operator.eq
                comp_version = GenericVersion(v)

            # all constraints must be fulfilled
            if not op(image_version, comp_version):
                return False

        return True

    return config_match_image_version_list


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


@dataclasses.dataclass(frozen=True)
class MkosiConfigSetting:
    dest: str
    section: str
    parse: ConfigParseCallback = config_parse_string
    match: Optional[ConfigMatchCallback] = None
    name: str = ""
    default: Any = None
    default_factory: Optional[ConfigDefaultCallback] = None
    paths: tuple[str, ...] = tuple()

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
    repo_dirs: list[Path]
    repart_dirs: list[Path]
    overlay: bool
    architecture: str
    output_format: OutputFormat
    manifest_format: list[ManifestFormat]
    output: str
    output_dir: Path
    kernel_command_line: list[str]
    secure_boot: bool
    secure_boot_key: Optional[Path]
    secure_boot_certificate: Optional[Path]
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
    clean_package_metadata: ConfigFeature
    remove_files: list[str]
    environment: dict[str, str]
    build_sources: Path
    build_dir: Optional[Path]
    install_dir: Optional[Path]
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
    root_password: Optional[str]
    root_password_hashed: Optional[str]
    root_password_file: Optional[Path]
    root_shell: Optional[str]

    # QEMU-specific options
    qemu_gui: bool
    qemu_smp: str
    qemu_mem: str
    qemu_kvm: bool
    qemu_args: Sequence[str]

    passphrase: Optional[Path]

    preset: Optional[str]

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace) -> "MkosiConfig":
        return cls(**{
            k: v for k, v in vars(ns).items()
            if k in inspect.signature(cls).parameters
        })

    def architecture_is_native(self) -> bool:
        return self.architecture == platform.machine()

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
            section="Distribution",
            parse=config_make_enum_parser(Distribution),
            match=config_make_list_matcher(delimiter=" ", parse=make_enum_parser(Distribution)),
            default=detect_distribution()[0],
        ),
        MkosiConfigSetting(
            dest="release",
            section="Distribution",
            parse=config_parse_string,
            match=config_make_list_matcher(delimiter=" "),
            default_factory=config_default_release,
        ),
        MkosiConfigSetting(
            dest="architecture",
            section="Distribution",
            default=platform.machine(),
        ),
        MkosiConfigSetting(
            dest="mirror",
            section="Distribution",
            default_factory=config_default_mirror,
        ),
        MkosiConfigSetting(
            dest="local_mirror",
            section="Distribution",
        ),
        MkosiConfigSetting(
            dest="repository_key_check",
            section="Distribution",
            default=True,
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="repositories",
            section="Distribution",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="repo_dirs",
            name="RepositoryDirectories",
            section="Distribution",
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
            paths=("mkosi.reposdir",),
        ),
        MkosiConfigSetting(
            dest="output_format",
            name="Format",
            section="Output",
            parse=config_make_enum_parser(OutputFormat),
            default=OutputFormat.disk,
        ),
        MkosiConfigSetting(
            dest="manifest_format",
            section="Output",
            parse=config_make_list_parser(delimiter=",", parse=make_enum_parser(ManifestFormat)),
            default=[ManifestFormat.json],
        ),
        MkosiConfigSetting(
            dest="output",
            section="Output",
            parse=config_parse_filename,
        ),
        MkosiConfigSetting(
            dest="output_dir",
            name="OutputDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.output",),
            default=Path("."),
        ),
        MkosiConfigSetting(
            dest="workspace_dir",
            name="WorkspaceDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.workspace",),
        ),
        MkosiConfigSetting(
            dest="cache_dir",
            name="CacheDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.cache",),
        ),
        MkosiConfigSetting(
            dest="build_dir",
            name="BuildDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.builddir",),
        ),
        MkosiConfigSetting(
            dest="install_dir",
            name="InstallDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.installdir",),
        ),
        MkosiConfigSetting(
            dest="compress_output",
            section="Output",
            parse=config_parse_compression,
        ),
        MkosiConfigSetting(
            dest="image_version",
            match=config_make_image_version_list_matcher(delimiter=" "),
            section="Output",
        ),
        MkosiConfigSetting(
            dest="image_id",
            match=config_make_list_matcher(delimiter=" ", allow_globs=True),
            section="Output",
        ),
        MkosiConfigSetting(
            dest="tar_strip_selinux_context",
            section="Output",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="split_artifacts",
            section="Output",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="repart_dirs",
            name="RepartDirectories",
            section="Output",
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
            paths=("mkosi.repart",),
        ),
        MkosiConfigSetting(
            dest="overlay",
            section="Output",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="use_subvolumes",
            section="Output",
            parse=config_parse_feature,
        ),
        MkosiConfigSetting(
            dest="packages",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="remove_packages",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="with_docs",
            section="Content",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="with_tests",
            section="Content",
            parse=config_parse_boolean,
            default=True,
        ),
        MkosiConfigSetting(
            dest="kernel_command_line",
            section="Content",
            parse=config_make_list_parser(delimiter=" "),
            default=["console=ttyS0"],
        ),
        MkosiConfigSetting(
            dest="bootable",
            section="Content",
            parse=config_parse_feature,
            match=config_make_list_matcher(delimiter=",", parse=parse_feature),
        ),
        MkosiConfigSetting(
            dest="autologin",
            section="Content",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="base_trees",
            section="Content",
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
        ),
        MkosiConfigSetting(
            dest="extra_trees",
            section="Content",
            parse=config_make_list_parser(delimiter=",", parse=parse_source_target_paths),
            paths=("mkosi.extra", "mkosi.extra.tar"),
        ),
        MkosiConfigSetting(
            dest="skeleton_trees",
            section="Content",
            parse=config_make_list_parser(delimiter=",", parse=parse_source_target_paths),
            paths=("mkosi.skeleton", "mkosi.skeleton.tar"),
        ),
        MkosiConfigSetting(
            dest="clean_package_metadata",
            section="Content",
            parse=config_parse_feature,
        ),
        MkosiConfigSetting(
            dest="remove_files",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="environment",
            section="Content",
            parse=config_make_list_parser(delimiter=" ", unescape=True),
        ),
        MkosiConfigSetting(
            dest="build_sources",
            section="Content",
            parse=config_make_path_parser(),
            default=Path("."),
        ),
        MkosiConfigSetting(
            dest="build_packages",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="build_script",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.build",),
        ),
        MkosiConfigSetting(
            dest="prepare_script",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.prepare",),
        ),
        MkosiConfigSetting(
            dest="postinst_script",
            name="PostInstallationScript",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.postinst",),
        ),
        MkosiConfigSetting(
            dest="finalize_script",
            section="Content",
            parse=config_parse_script,
            paths=("mkosi.finalize",),
        ),
        MkosiConfigSetting(
            dest="with_network",
            section="Content",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="cache_only",
            section="Content",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="initrds",
            section="Content",
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
        ),
        MkosiConfigSetting(
            dest="make_initrd",
            section="Content",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="kernel_modules_include",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="kernel_modules_exclude",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="kernel_modules_initrd",
            section="Content",
            parse=config_parse_boolean,
            default=True,
        ),
        MkosiConfigSetting(
            dest="kernel_modules_initrd_include",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="kernel_modules_initrd_exclude",
            section="Content",
            parse=config_make_list_parser(delimiter=","),
        ),
        MkosiConfigSetting(
            dest="locale",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="locale_messages",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="keymap",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="timezone",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="hostname",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="root_password",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="root_password_hashed",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="root_password_file",
            section="Content",
            parse=config_make_path_parser(secret=True),
            paths=("mkosi.rootpw",),
        ),
        MkosiConfigSetting(
            dest="root_shell",
            section="Content",
            parse=config_parse_string,
        ),
        MkosiConfigSetting(
            dest="secure_boot",
            section="Validation",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="secure_boot_key",
            section="Validation",
            parse=config_make_path_parser(),
            paths=("mkosi.key",),
        ),
        MkosiConfigSetting(
            dest="secure_boot_certificate",
            section="Validation",
            parse=config_make_path_parser(),
            paths=("mkosi.crt",),
        ),
        MkosiConfigSetting(
            dest="verity_key",
            section="Validation",
            parse=config_make_path_parser(),
            paths=("mkosi.key",),
        ),
        MkosiConfigSetting(
            dest="verity_certificate",
            section="Validation",
            parse=config_make_path_parser(),
            paths=("mkosi.crt",),
        ),
        MkosiConfigSetting(
            dest="sign_expected_pcr",
            section="Validation",
            parse=config_parse_feature,
        ),
        MkosiConfigSetting(
            dest="passphrase",
            section="Validation",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.passphrase",),
        ),
        MkosiConfigSetting(
            dest="checksum",
            section="Validation",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="sign",
            section="Validation",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="key",
            section="Validation",
        ),
        MkosiConfigSetting(
            dest="incremental",
            section="Host",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="nspawn_settings",
            name="NSpawnSettings",
            section="Host",
            parse=config_make_path_parser(),
            paths=("mkosi.nspawn",),
        ),
        MkosiConfigSetting(
            dest="extra_search_paths",
            section="Host",
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser()),
        ),
        MkosiConfigSetting(
            dest="qemu_gui",
            section="Host",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="qemu_smp",
            section="Host",
            default="1",
        ),
        MkosiConfigSetting(
            dest="qemu_mem",
            section="Host",
            default="2G",
        ),
        MkosiConfigSetting(
            dest="qemu_kvm",
            section="Host",
            parse=config_parse_feature,
        ),
        MkosiConfigSetting(
            dest="qemu_args",
            section="Host",
            parse=config_make_list_parser(delimiter=" "),
        ),
        MkosiConfigSetting(
            dest="ephemeral",
            section="Host",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="ssh",
            section="Host",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="credentials",
            section="Host",
            parse=config_make_list_parser(delimiter=" "),
        ),
        MkosiConfigSetting(
            dest="kernel_command_line_extra",
            section="Host",
            parse=config_make_list_parser(delimiter=" "),
        ),
        MkosiConfigSetting(
            dest="acl",
            section="Host",
            parse=config_parse_boolean,
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
        )

        parser.optionxform = lambda optionstr: optionstr # type: ignore

        if path.exists():
            parser.read(path)

        if "Match" in parser.sections():
            for k, v in parser.items("Match"):
                if (s := self.settings_lookup.get(k)):
                    if not (match := s.match):
                        die(f"{k} cannot be used in [Match]")

                    # If we encounter a setting in [Match] that has not been explicitly configured yet, we assign
                    # the default value first so that we can [Match] on default values for settings.
                    if s.dest not in namespace:
                        if s.default_factory:
                            default = s.default_factory(namespace)
                        elif s.default is None:
                            default = s.parse(s.dest, None, namespace)
                        else:
                            default = s.default

                        setattr(namespace, s.dest, default)

                    if not match(s.dest, v, namespace):
                        return False

                elif (m := self.match_lookup.get(k)):
                    if not m.match(v):
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
                    if Path(f).exists():
                        setattr(namespace, s.dest, s.parse(s.dest, f, namespace))

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

        group = parser.add_argument_group("Distribution options")
        group.add_argument(
            "-d", "--distribution",
            choices=Distribution.__members__,
            help="Distribution to install",
            action=action,
        )
        group.add_argument(
            "-r", "--release",
            metavar="RELEASE",
            help="Distribution release to install",
            action=action,
        )
        group.add_argument(
            "--architecture",
            metavar="ARCHITECTURE",
            help="Override the architecture of installation",
            action=action,
        )
        group.add_argument(
            "-m", "--mirror",
            metavar="MIRROR",
            help="Distribution mirror to use",
            action=action,
        )
        group.add_argument(
            "--local-mirror",
            help="Use a single local, flat and plain mirror to build the image",
            action=action,
        )
        group.add_argument(
            "--repository-key-check",
            metavar="BOOL",
            help="Controls signature and key checks on repositories",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--repositories",
            metavar="REPOS",
            help="Repositories to use",
            action=action,
        )
        group.add_argument(
            "--repo-dir",
            metavar="PATH",
            help="Specify a directory containing extra distribution specific repository files",
            dest="repo_dirs",
            action=action,
        )

        group = parser.add_argument_group("Output options")
        group.add_argument(
            "-t", "--format",
            metavar="FORMAT",
            choices=OutputFormat.__members__,
            dest="output_format",
            help="Output Format",
            action=action,
        )
        group.add_argument(
            "--manifest-format",
            metavar="FORMAT",
            help="Manifest Format",
            action=action,
        )
        group.add_argument(
            "-o", "--output",
            metavar="PATH",
            help="Output name",
            action=action,
        )
        group.add_argument(
            "-O", "--output-dir",
            metavar="DIR",
            help="Output directory",
            action=action,
        )
        group.add_argument(
            "--workspace-dir",
            metavar="DIR",
            help="Workspace directory",
            action=action,
        )
        group.add_argument(
            "--cache-dir",
            metavar="PATH",
            help="Package cache path",
            action=action,
        )
        group.add_argument(
            "--build-dir",
            metavar="PATH",
            help="Path to use as persistent build directory",
            action=action,
        )
        group.add_argument(
            "--install-dir",
            metavar="PATH",
            help="Path to use as persistent install directory",
            action=action,
        )
        group.add_argument(
            "--compress-output",
            metavar="ALG",
            help="Enable whole-output compression (with images or archives)",
            nargs="?",
            action=action,
        )
        group.add_argument("--image-version", help="Set version for image", action=action)
        group.add_argument("--image-id", help="Set ID for image", action=action)
        group.add_argument(
            "--tar-strip-selinux-context",
            metavar="BOOL",
            help="Do not include SELinux file context information in tar. Not compatible with bsdtar.",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--split-artifacts",
            metavar="BOOL",
            help="Generate split partitions",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--repart-dir",
            metavar="PATH",
            help="Directory containing systemd-repart partition definitions",
            dest="repart_dirs",
            action=action,
        )
        group.add_argument(
            "--overlay",
            metavar="BOOL",
            help="Only output the additions on top of the given base trees",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--use-subvolumes",
            metavar="FEATURE",
            help="Use btrfs subvolumes for faster directory operations where possible",
            nargs="?",
            action=action,
        )

        group = parser.add_argument_group("Content options")
        group.add_argument(
            "-p", "--package",
            metavar="PACKAGE",
            help="Add an additional package to the OS image",
            dest="packages",
            action=action,
        )
        group.add_argument(
            "--remove-package",
            metavar="PACKAGE",
            help="Remove package from the image OS image after installation",
            dest="remove_packages",
            action=action,
        )
        group.add_argument(
            "--with-docs",
            metavar="BOOL",
            help="Install documentation",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "-T", "--without-tests",
            help="Do not run tests as part of build script, if supported",
            nargs="?",
            const="no",
            dest="with_tests",
            action=action,
        )
        group.add_argument(
            "--bootable",
            metavar="FEATURE",
            help="Generate ESP partition with systemd-boot and UKIs for installed kernels",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--kernel-command-line",
            metavar="OPTIONS",
            help="Set the kernel command line (only bootable images)",
            action=action,
        )
        group.add_argument(
            "--autologin",
            metavar="BOOL",
            help="Enable root autologin",
            nargs="?",
            action=action,
        )
        group.add_argument(
            '--base-tree',
            metavar='PATH',
            help='Use the given tree as base tree (e.g. lower sysext layer)',
            dest="base_trees",
            action=action,
        )
        group.add_argument(
            "--extra-tree",
            metavar="PATH",
            help="Copy an extra tree on top of image",
            dest="extra_trees",
            action=action,
        )
        group.add_argument(
            "--skeleton-tree",
            metavar="PATH",
            help="Use a skeleton tree to bootstrap the image before installing anything",
            dest="skeleton_trees",
            action=action,
        )
        group.add_argument(
            "--clean-package-metadata",
            metavar="FEATURE",
            help="Remove package manager database and other files",
            action=action,
        )
        group.add_argument(
            "--remove-files",
            metavar="GLOB",
            help="Remove files from built image",
            action=action,
        )
        group.add_argument(
            "-E", "--environment",
            metavar="NAME[=VALUE]",
            help="Set an environment variable when running scripts",
            action=action,
        )
        group.add_argument(
            "--build-sources",
            metavar="PATH",
            help="Path for sources to build",
            action=action,
        )
        group.add_argument(
            "--build-package",
            metavar="PACKAGE",
            help="Additional packages needed for build script",
            dest="build_packages",
            action=action,
        )
        group.add_argument(
            "--build-script",
            metavar="PATH",
            help="Build script to run inside image",
            action=action,
        )
        group.add_argument(
            "--prepare-script",
            metavar="PATH",
            help="Prepare script to run inside the image before it is cached",
            action=action,
        )
        group.add_argument(
            "--postinst-script",
            metavar="PATH",
            help="Postinstall script to run inside image",
            action=action,
        )
        group.add_argument(
            "--finalize-script",
            metavar="PATH",
            help="Postinstall script to run outside image",
            action=action,
        )
        group.add_argument(
            "--with-network",
            metavar="BOOL",
            help="Run build and postinst scripts with network access (instead of private network)",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--cache-only",
            metavar="BOOL",
            help="Only use the package cache when installing packages",
            action=action,
        )
        group.add_argument(
            "--initrd",
            help="Add a user-provided initrd to image",
            metavar="PATH",
            dest="initrds",
            action=action,
        )
        group.add_argument(
            "--make-initrd",
            help="Make sure the image can be used as an initramfs",
            metavar="BOOL",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--kernel-modules-include",
            help="Only include the specified kernel modules in the image",
            metavar="REGEX",
            action=action,
        )
        group.add_argument(
            "--kernel-modules-exclude",
            help="Exclude the specified kernel modules from the image",
            metavar="REGEX",
            action=action,
        )
        group.add_argument(
            "--kernel-modules-initrd",
            help="When building a bootable image, add an extra initrd containing the kernel modules",
            metavar="BOOL",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--kernel-modules-initrd-include",
            help="When building a kernel modules initrd, only include the specified kernel modules",
            metavar="REGEX",
            action=action,
        )
        group.add_argument(
            "--kernel-modules-initrd-exclude",
            help="When building a kernel modules initrd, exclude the specified kernel modules",
            metavar="REGEX",
            action=action,
        )
        group.add_argument(
            "--locale",
            help="Set the system locale",
            metavar="LOCALE",
            action=action,
        )
        group.add_argument(
            "--locale-messages",
            help="Set the messages locale",
            metavar="LOCALE",
            action=action,
        )
        group.add_argument(
            "--keymap",
            help="Set the system keymap",
            metavar="KEYMAP",
            action=action,
        )
        group.add_argument(
            "--timezone",
            help="Set the system timezone",
            metavar="TIMEZONE",
            action=action,
        )
        group.add_argument(
            "--hostname",
            help="Set the system hostname",
            metavar="HOSTNAME",
            action=action,
        )
        group.add_argument(
            "--root-password",
            help="Set the system root password",
            metavar="PASSWORD",
            action=action,
        )
        group.add_argument(
            "--root-password-hashed",
            help="Set the system root password (hashed)",
            metavar="PASSWORD-HASHED",
            action=action,
        )
        group.add_argument(
            "--root-password-file",
            help="Set the system root password (file)",
            metavar="PATH",
            action=action,
        )
        group.add_argument(
            "--root-shell",
            help="Set the system root shell",
            metavar="SHELL",
            action=action,
        )

        group = parser.add_argument_group("Validation options")
        group.add_argument(
            "--secure-boot",
            metavar="BOOL",
            help="Sign the resulting kernel/initrd image for UEFI SecureBoot",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--secure-boot-key",
            metavar="PATH",
            help="UEFI SecureBoot private key in PEM format",
            action=action,
        )
        group.add_argument(
            "--secure-boot-certificate",
            metavar="PATH",
            help="UEFI SecureBoot certificate in X509 format",
            action=action,
        )
        group.add_argument(
            "--verity-key",
            metavar="PATH",
            help="Private key for signing verity signature in PEM format",
            action=action,
        )
        group.add_argument(
            "--verity-certificate",
            metavar="PATH",
            help="Certificate for signing verity signature in X509 format",
            action=action,
        )
        group.add_argument(
            "--sign-expected-pcr",
            metavar="FEATURE",
            help="Measure the components of the unified kernel image (UKI) and embed the PCR signature into the UKI",
            action=action,
        )
        group.add_argument(
            "--passphrase",
            metavar="PATH",
            help="Path to a file containing the passphrase to use when LUKS encryption is selected",
            action=action,
        )
        group.add_argument(
            "--checksum",
            metavar="BOOL",
            help="Write SHA256SUMS file",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--sign",
            help="Write and sign SHA256SUMS file",
            metavar="BOOL",
            nargs="?",
            action=action,
        )
        group.add_argument("--key", help="GPG key to use for signing", action=action)

        group = parser.add_argument_group("Host configuration options")
        group.add_argument(
            "-i", "--incremental",
            metavar="BOOL",
            help="Make use of and generate intermediary cache images",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--settings",
            metavar="PATH",
            help="Add in .nspawn settings file",
            dest="nspawn_settings",
            action=action,
        )
        group.add_argument(
            "--extra-search-path",
            help="List of colon-separated paths to look for programs before looking in PATH",
            metavar="PATH",
            dest="extra_search_paths",
            action=action,
        )
        group.add_argument(
            "--qemu-gui",
            help="Start QEMU in graphical mode",
            metavar="BOOL",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--qemu-smp",
            metavar="SMP",
            help="Configure guest's SMP settings",
            action=action,
        )
        group.add_argument(
            "--qemu-mem",
            metavar="MEM",
            help="Configure guest's RAM size",
            action=action,
        )
        group.add_argument(
            "--qemu-kvm",
            metavar="BOOL",
            help="Configure whether to use KVM or not",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--qemu-args",
            metavar="ARGS",
            # Suppress the command line option because it's already possible to pass qemu args as normal
            # arguments.
            help=argparse.SUPPRESS,
            action=action,
        )
        group.add_argument(
            "--ephemeral",
            metavar="BOOL",
            help=('If specified, the container/VM is run with a temporary snapshot of the output '
                'image that is removed immediately when the container/VM terminates'),
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--ssh",
            metavar="BOOL",
            help="Set up SSH access from the host to the final image via 'mkosi ssh'",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--credential",
            metavar="NAME=VALUE",
            help="Pass a systemd credential to systemd-nspawn or qemu",
            dest="credentials",
            action=action,
        )
        group.add_argument(
            "--kernel-command-line-extra",
            metavar="OPTIONS",
            help="Append extra entries to the kernel command line when booting the image",
            action=action,
        )
        group.add_argument(
            "--acl",
            metavar="BOOL",
            help="Set ACLs on generated directories to permit the user running mkosi to remove them",
            nargs="?",
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

def strip_suffixes(path: Path) -> Path:
    while path.suffix in {
        ".xz",
        ".zstd",
        ".raw",
        ".tar",
        ".cpio",
    }:
        path = path.with_suffix("")

    return path


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

    if "firstboot.hostname" not in creds:
        creds["firstboot.hostname"] = args.output

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

    if shutil.which("bsdtar") and args.distribution == Distribution.openmandriva and args.tar_strip_selinux_context:
        die("Sorry, bsdtar on OpenMandriva is incompatible with --tar-strip-selinux-context")

    if args.cache_dir:
        args.cache_dir = args.cache_dir / f"{args.distribution}~{args.release}"
    if args.build_dir:
        args.build_dir = args.build_dir / f"{args.distribution}~{args.release}"

    if args.sign:
        args.checksum = True

    if args.compress_output is None:
        args.compress_output = Compression.zst if args.output_format == OutputFormat.cpio else Compression.none

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

    if args.repo_dirs and not (
        is_dnf_distribution(args.distribution)
        or is_apt_distribution(args.distribution)
        or args.distribution == Distribution.arch
    ):
        die("--repo-dir is only supported on DNF/Debian based distributions and Arch")

    if args.qemu_kvm == ConfigFeature.enabled and not qemu_check_kvm_support():
        die("Sorry, the host machine does not support KVM acceleration.")

    if args.qemu_kvm == ConfigFeature.auto:
        args.qemu_kvm = qemu_check_kvm_support()
    else:
        args.qemu_kvm = args.qemu_kvm == ConfigFeature.enabled

    if args.repositories and not (is_dnf_distribution(args.distribution) or is_apt_distribution(args.distribution)):
        die("Sorry, the --repositories option is only supported on DNF/Debian based distributions")

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

