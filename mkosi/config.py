import argparse
import configparser
import dataclasses
import enum
import fnmatch
import os
import platform
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable, Optional, Type, Union, cast

from mkosi.backend import (
    Distribution,
    ManifestFormat,
    OutputFormat,
    Verb,
    detect_distribution,
    flatten,
)
from mkosi.log import MkosiPrinter, die

__version__ = "14"


ConfigParseCallback = Callable[[str, Optional[str], argparse.Namespace], Any]
ConfigMatchCallback = Callable[[str, str, argparse.Namespace], bool]
ConfigDefaultCallback = Callable[[argparse.Namespace], Any]


def parse_boolean(s: str) -> bool:
    "Parse 1/true/yes/y/t/on as true and 0/false/no/n/f/off/None as false"
    s_l = s.lower()
    if s_l in {"1", "true", "yes", "y", "t", "on"}:
        return True

    if s_l in {"0", "false", "no", "n", "f", "off"}:
        return False

    die(f"Invalid boolean literal: {s!r}")


def parse_source_target_paths(value: str) -> tuple[Path, Optional[Path]]:
    src, _, target = value.partition(':')
    if not Path(src).exists():
        die(f"{src} does not exist")
    if target and not Path(target).is_absolute():
        die("Target path must be absolute")
    return Path(src).absolute(), Path(target) if target else None


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
        if not Path(value).exists():
            die(f"{value} does not exist")
        if not os.access(value, os.X_OK):
            die(f"{value} is not executable")

    return Path(value).absolute() if value else None


def config_parse_boolean(dest: str, value: Optional[str], namespace: argparse.Namespace) -> bool:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    return parse_boolean(value) if value else False


def config_match_boolean(dest: str, value: str, namespace: argparse.Namespace) -> bool:
    return cast(bool, getattr(namespace, dest) == parse_boolean(value))


def config_parse_feature(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[bool]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if value and value == "auto":
        return None

    return parse_boolean(value) if value else None


def config_parse_compression(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Union[None, str, bool]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if value in ("zlib", "lzo", "zstd", "lz4", "xz"):
        return value

    return parse_boolean(value) if value else None


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
        Distribution.fedora: "37",
        Distribution.centos: "9",
        Distribution.rocky: "9",
        Distribution.alma: "9",
        Distribution.mageia: "7",
        Distribution.debian: "testing",
        Distribution.ubuntu: "jammy",
        Distribution.opensuse: "tumbleweed",
        Distribution.openmandriva: "cooker",
        Distribution.gentoo: "17.1",
    }.get(d, "rolling")


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


def config_make_list_parser(delimiter: str, parse: Callable[[str], Any] = str) -> ConfigParseCallback:
    ignore: set[str] = set()

    def config_parse_list(dest: str, value: Optional[str], namespace: argparse.Namespace) -> list[Any]:
        if dest not in namespace:
            ignore.clear()
            l = []
        else:
            l = getattr(namespace, dest).copy()

        if not value:
            return l # type: ignore

        value = value.replace("\n", delimiter)
        values = [v for v in value.split(delimiter) if v]

        for v in values:
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


def make_path_parser(required: bool) -> Callable[[str], Path]:
    def parse_path(value: str) -> Path:
        if required and not Path(value).exists():
            die(f"{value} does not exist")

        return Path(value).absolute()

    return parse_path


def config_make_path_parser(required: bool) -> ConfigParseCallback:
    def config_parse_path(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[Path]:
        if dest in namespace:
            return getattr(namespace, dest) # type: ignore

        if value and required and not Path(value).exists():
            die(f"{value} does not exist")

        return Path(value).absolute() if value else None

    return config_parse_path


def match_path_exists(path: Path, value: str) -> bool:
    return path.parent.joinpath(value).exists()


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
    match: Callable[[Path, str], bool]


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


class MkosiConfigParser:
    SETTINGS = (
        MkosiConfigSetting(
            dest="distribution",
            section="Distribution",
            parse=config_make_enum_parser(Distribution),
            match=config_make_enum_matcher(Distribution),
            default=detect_distribution()[0],
        ),
        MkosiConfigSetting(
            dest="release",
            section="Distribution",
            parse=config_parse_string,
            match=config_match_string,
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
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=True)),
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
            parse=config_make_path_parser(required=False),
        ),
        MkosiConfigSetting(
            dest="output_dir",
            name="OutputDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.output",),
        ),
        MkosiConfigSetting(
            dest="workspace_dir",
            name="WorkspaceDirectory",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.workspace",),
        ),
        MkosiConfigSetting(
            dest="kernel_command_line",
            section="Output",
            parse=config_make_list_parser(delimiter=" "),
        ),
        MkosiConfigSetting(
            dest="secure_boot",
            section="Output",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="secure_boot_key",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.secure-boot.key",),
        ),
        MkosiConfigSetting(
            dest="secure_boot_certificate",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.secure-boot.crt",),
        ),
        MkosiConfigSetting(
            dest="secure_boot_valid_days",
            section="Output",
            default="730",
        ),
        MkosiConfigSetting(
            dest="secure_boot_common_name",
            section="Output",
            default="mkosi of %u",
        ),
        MkosiConfigSetting(
            dest="sign_expected_pcr",
            section="Output",
            parse=config_parse_feature,
        ),
        MkosiConfigSetting(
            dest="passphrase",
            section="Output",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.passphrase",),
        ),
        MkosiConfigSetting(
            dest="compress_output",
            section="Output",
            parse=config_parse_compression,
        ),
        MkosiConfigSetting(
            dest="image_version",
            section="Output",
        ),
        MkosiConfigSetting(
            dest="image_id",
            section="Output",
        ),
        MkosiConfigSetting(
            dest="auto_bump",
            section="Output",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="tar_strip_selinux_context",
            section="Output",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="incremental",
            section="Output",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="cache_initrd",
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
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=True)),
            paths=("mkosi.repart",),
        ),
        MkosiConfigSetting(
            dest="initrds",
            section="Output",
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=False)),
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
            dest="password",
            section="Content",
        ),
        MkosiConfigSetting(
            dest="password_is_hashed",
            section="Content",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="autologin",
            section="Content",
            parse=config_parse_boolean,
        ),
        MkosiConfigSetting(
            dest="cache_dir",
            name="CacheDirectory",
            section="Content",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.cache",),
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
            parse=config_make_list_parser(delimiter=" "),
        ),
        MkosiConfigSetting(
            dest="build_sources",
            section="Content",
            parse=config_make_path_parser(required=True),
            default=".",
        ),
        MkosiConfigSetting(
            dest="build_dir",
            name="BuildDirectory",
            section="Content",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.builddir",),
        ),
        MkosiConfigSetting(
            dest="install_dir",
            name="InstallDirectory",
            section="Content",
            parse=config_make_path_parser(required=False),
            paths=("mkosi.installdir",),
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
            dest="nspawn_settings",
            name="NSpawnSettings",
            section="Content",
            parse=config_make_path_parser(required=True),
            paths=("mkosi.nspawn",),
        ),
        MkosiConfigSetting(
            dest="base_image",
            section="Content",
            parse=config_make_path_parser(required=True),
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
            dest="extra_search_paths",
            section="Host",
            parse=config_make_list_parser(delimiter=",", parse=make_path_parser(required=True)),
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

    def parse_config(self, path: Path, namespace: argparse.Namespace) -> None:
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
                    # it it's default value first so that we can [Match] on default values for settings.
                    if s.dest not in namespace:
                        if s.default_factory:
                            default = s.default_factory(namespace)
                        elif s.default is None:
                            default = s.parse(s.dest, None, namespace)
                        else:
                            default = s.default

                        setattr(namespace, s.dest, default)

                    if not match(s.dest, v, namespace):
                        return

                elif (m := self.match_lookup.get(k)):
                    if not m.match(path, v):
                        return

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
                        self.parse_config(p, namespace)

            for s in self.SETTINGS:
                for f in s.paths:
                    if path.parent.joinpath(f).exists():
                        setattr(namespace, s.dest, s.parse(s.dest, str(path.parent / f), namespace))

    def create_argument_parser(self) -> argparse.ArgumentParser:
        action = config_make_action(self.SETTINGS)

        parser = argparse.ArgumentParser(
            prog="mkosi",
            description="Build Bespoke OS Images",
            usage=textwrap.dedent("""
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
            """).format(b=MkosiPrinter.bold, e=MkosiPrinter.reset),
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
            action="help",
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
            type=Path,
            metavar="PATH",
        )
        parser.add_argument(
            "--debug",
            help="Turn on debugging output",
            action="append",
            default=[],
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
            help="Output image path",
            action=action,
        )
        group.add_argument(
            "-O", "--output-dir",
            metavar="DIR",
            help="Output root directory",
            action=action,
        )
        group.add_argument(
            "--workspace-dir",
            metavar="DIR",
            help="Workspace directory",
            action=action,
        )
        group.add_argument(
            "--kernel-command-line",
            metavar="OPTIONS",
            help="Set the kernel command line (only bootable images)",
            action=action,
        )
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
            "--secure-boot-valid-days",
            metavar="DAYS",
            help="Number of days UEFI SecureBoot keys should be valid when generating keys",
            action=action,
        )
        group.add_argument(
            "--secure-boot-common-name",
            metavar="CN",
            help="Template for the UEFI SecureBoot CN when generating keys",
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
            "--compress-output",
            metavar="ALG",
            help="Enable whole-output compression (with images or archives)",
            nargs="?",
            action=action,
        )
        group.add_argument("--image-version", help="Set version for image", action=action)
        group.add_argument("--image-id", help="Set ID for image", action=action)
        group.add_argument(
            "-B", "--auto-bump",
            metavar="BOOL",
            help="Automatically bump image version after building",
            action=action,
        )
        group.add_argument(
            "--tar-strip-selinux-context",
            metavar="BOOL",
            help="Do not include SELinux file context information in tar. Not compatible with bsdtar.",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "-i", "--incremental",
            metavar="BOOL",
            help="Make use of and generate intermediary cache images",
            nargs="?",
            action=action,
        )
        group.add_argument(
            "--cache-initrd",
            metavar="BOOL",
            help="When using incremental mode, build the initrd in the cache image and don't rebuild it in the final image",
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
            "--initrd",
            help="Add a user-provided initrd to image",
            metavar="PATH",
            dest="initrds",
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

        group.add_argument("--password", help="Set the root password", action=action)
        group.add_argument(
            "--password-is-hashed",
            metavar="BOOL",
            help="Indicate that the root password has already been hashed",
            nargs="?",
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
            "--cache-dir",
            metavar="PATH",
            help="Package cache path",
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
            "--settings",
            metavar="PATH",
            help="Add in .nspawn settings file",
            dest="nspawn_settings",
            action=action,
        )
        group.add_argument(
            '--base-image',
            metavar='IMAGE',
            help='Use the given image as base (e.g. lower sysext layer)',
            action=action,
        )

        group = parser.add_argument_group("Validation options")
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

    def parse(self, args: Optional[Sequence[str]] = None) -> argparse.Namespace:
        namespace = argparse.Namespace()

        if args is None:
            args = sys.argv[1:]
        args = list(args)

        # Make sure the verb command gets explicitly passed. Insert a -- before the positional verb argument
        # otherwise it might be considered as an argument of a parameter with nargs='?'. For example mkosi -i
        # summary would be treated as -i=summary.
        for verb in Verb:
            try:
                v_i = args.index(verb.name)
            except ValueError:
                continue

            if v_i > 0 and args[v_i - 1] != "--":
                args.insert(v_i, "--")
            break
        else:
            args += ["--", "build"]

        argparser = self.create_argument_parser()
        argparser.parse_args(args, namespace)

        if namespace.verb == Verb.help:
            argparser.print_help()
            argparser.exit()

        if "directory" not in namespace:
            setattr(namespace, "directory", None)

        if namespace.directory and not namespace.directory.is_dir():
            die(f"Error: {namespace.directory} is not a directory!")

        self.parse_config(namespace.directory or Path("."), namespace)

        for s in self.SETTINGS:
            if s.dest in namespace:
                continue

            if s.default_factory:
                default = s.default_factory(namespace)
            elif s.default is None:
                default = s.parse(s.dest, None, namespace)
            else:
                default = s.default

            setattr(namespace, s.dest, default)

        return namespace

