import argparse
import configparser
import dataclasses
import enum
import fnmatch
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable, Optional, Type, Union, cast

from mkosi.backend import Distribution, detect_distribution
from mkosi.log import die


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
    if target and not Path(target).absolute():
        die("Target path must be absolute")
    return Path(src), Path(target) if target else None


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

    return Path(value) if value else None


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


def config_parse_base_packages(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Union[bool, str]:
    if dest in namespace:
        return getattr(namespace, dest) # type: ignore

    if value == "conditional":
        return value

    return parse_boolean(value) if value else False


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


ConfigParseCallback = Callable[[str, Optional[str], argparse.Namespace], Any]
ConfigMatchCallback = Callable[[str, str, argparse.Namespace], bool]
ConfigDefaultCallback = Callable[[argparse.Namespace], Any]


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


class MkosiConfigParser:
    def __init__(self, settings: Sequence[MkosiConfigSetting]) -> None:
        self.settings = settings
        self.lookup = {s.name: s for s in settings}

    def parse(self, path: Path, namespace: argparse.Namespace) -> argparse.Namespace:
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
                if not (s := self.lookup.get(k)):
                    die(f"Unknown setting {k}")

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
                    return namespace

        parser.remove_section("Match")

        for section in parser.sections():
            for k, v in parser.items(section):
                if not (s := self.lookup.get(k)):
                    die(f"Unknown setting {k}")

                setattr(namespace, s.dest, s.parse(s.dest, v, namespace))

        if extras:
            # Dropin configuration has priority over any default paths.

            if path.parent.joinpath("mkosi.conf.d").exists():
                for p in sorted(path.parent.joinpath("mkosi.conf.d").iterdir()):
                    if p.is_dir() or p.suffix == ".conf":
                        namespace = self.parse(p, namespace)

            for s in self.settings:
                for f in s.paths:
                    if path.parent.joinpath(f).exists():
                        setattr(namespace, s.dest, s.parse(s.dest, str(path.parent / f), namespace))

        return namespace


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


def config_make_path_parser(required: bool) -> ConfigParseCallback:
    def config_parse_path(dest: str, value: Optional[str], namespace: argparse.Namespace) -> Optional[Path]:
        if dest in namespace:
            return getattr(namespace, dest) # type: ignore

        if value and required and not Path(value).exists():
            die(f"{value} does not exist")

        return Path(value) if value else None

    return config_parse_path
