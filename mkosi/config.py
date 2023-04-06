import argparse
import configparser
import dataclasses
import enum
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Callable, Optional, Type, Union, cast

from mkosi.backend import Distribution
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


def config_parse_string(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
    setattr(namespace, dest, value)


def config_match_string(dest: str, value: str, namespace: argparse.Namespace) -> bool:
    return cast(bool, value == getattr(namespace, dest))


def config_parse_script(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
    if value is not None:
        if not Path(value).exists():
            die(f"{value} does not exist")
        if not os.access(value, os.X_OK):
            die(f"{value} is not executable")

    config_make_path_parser(required=True)(dest, value, namespace)


def config_parse_boolean(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
    setattr(namespace, dest, parse_boolean(value) if value is not None else False)


def config_match_boolean(dest: str, value: str, namespace: argparse.Namespace) -> bool:
    return cast(bool, getattr(namespace, dest) == parse_boolean(value))


def config_parse_feature(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
    if value is None:
        value = "auto"
    setattr(namespace, dest, parse_boolean(value) if value != "auto" else None)


def config_parse_compression(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
    if value in ("zlib", "lzo", "zstd", "lz4", "xz"):
        setattr(namespace, dest, value)
    else:
        setattr(namespace, dest, parse_boolean(value) if value is not None else None)


def config_parse_base_packages(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
    if value == "conditional":
        setattr(namespace, dest, value)
    else:
        setattr(namespace, dest, parse_boolean(value) if value is not None else False)


def config_parse_distribution(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
    assert value is not None

    try:
        d = Distribution[value]
    except KeyError:
        die(f"Invalid distribution {value}")

    r = {
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

    setattr(namespace, dest, d)
    setattr(namespace, "release", r)


ConfigParseCallback = Callable[[str, Optional[str], argparse.Namespace], None]
ConfigMatchCallback = Callable[[str, str, argparse.Namespace], bool]


@dataclasses.dataclass(frozen=True)
class MkosiConfigSetting:
    dest: str
    section: str
    parse: ConfigParseCallback = config_parse_string
    match: Optional[ConfigMatchCallback] = None
    name: str = ""
    default: Any = None
    paths: tuple[str, ...] = tuple()

    def __post_init__(self) -> None:
        if not self.name:
            object.__setattr__(self, 'name', ''.join(x.capitalize() for x in self.dest.split('_') if x))


class MkosiConfigParser:
    def __init__(self, settings: Sequence[MkosiConfigSetting], directory: Path) -> None:
        self.settings = settings
        self.directory = directory
        self.lookup = {s.name: s for s in settings}

    def _parse_config(self, path: Path, namespace: argparse.Namespace) -> None:
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

                if s.match and not s.match(s.dest, v, namespace):
                    return

        parser.remove_section("Match")

        if extras:
            for s in self.settings:
                for f in s.paths:
                    if path.parent.joinpath(f).exists():
                        s.parse(s.dest, str(path.parent / f), namespace)

        for section in parser.sections():
            for k, v in parser.items(section):
                if not (s := self.lookup.get(k)):
                    die(f"Unknown setting {k}")

                s.parse(s.dest, v, namespace)

        if extras and path.parent.joinpath("mkosi.conf.d").exists():
            for p in sorted(path.parent.joinpath("mkosi.conf.d").iterdir()):
                if p.is_dir() or p.suffix == ".conf":
                    self._parse_config(p, namespace)


    def parse(self, namespace: argparse.Namespace = argparse.Namespace()) -> argparse.Namespace:
        self._parse_config(self.directory, namespace)
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
                s.parse(self.dest, values, namespace)
            else:
                for v in values:
                    assert isinstance(v, str)
                    s.parse(self.dest, v, namespace)

    return MkosiAction


def make_enum_parser(type: Type[enum.Enum]) -> Callable[[str], enum.Enum]:
    def parse_enum(value: str) -> enum.Enum:
        try:
            return type[value]
        except KeyError:
            die(f"Invalid enum value {value}")

    return parse_enum


def config_make_enum_parser(type: Type[enum.Enum]) -> ConfigParseCallback:
    def config_parse_enum(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
        setattr(namespace, dest, make_enum_parser(type)(value) if value else None)

    return config_parse_enum


def config_make_enum_matcher(type: Type[enum.Enum]) -> ConfigMatchCallback:
    def config_match_enum(dest: str, value: str, namespace: argparse.Namespace) -> bool:
        return cast(bool, make_enum_parser(type)(value) == getattr(namespace, dest))

    return config_match_enum


def config_make_list_parser(delimiter: str, parse: Callable[[str], Any] = str) -> ConfigParseCallback:
    def config_parse_list(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
        if not value:
            setattr(namespace, dest, [])
            return

        value = value.replace("\n", delimiter)
        values = [v for v in value.split(delimiter) if v]

        for v in values:
            if v == "!*":
                getattr(namespace, dest).clear()
            elif v.startswith("!"):
                setattr(namespace, dest, [i for i in getattr(namespace, dest) if i == parse(v[1:])])
            else:
                getattr(namespace, dest).append(parse(v))

    return config_parse_list


def config_make_path_parser(required: bool) -> ConfigParseCallback:
    def config_parse_path(dest: str, value: Optional[str], namespace: argparse.Namespace) -> None:
        if value is not None and required and not Path(value).exists():
            die(f"{value} does not exist")

        setattr(namespace, dest, Path(value) if value else None)

    return config_parse_path
