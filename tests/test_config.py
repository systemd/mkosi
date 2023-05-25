# SPDX-License-Identifier: LGPL-2.1+

import argparse
from pathlib import Path

import pytest

from mkosi.config import (
    config_make_list_matcher,
    config_make_list_parser,
    strip_suffixes,
)


def test_strip_suffixes() -> None:
    assert strip_suffixes(Path("home/test.zstd")) == Path("home/test")
    assert strip_suffixes(Path("home/test.xz")) == Path("home/test")
    assert strip_suffixes(Path("home/test.raw")) == Path("home/test")
    assert strip_suffixes(Path("home/test.tar")) == Path("home/test")
    assert strip_suffixes(Path("home/test.cpio")) == Path("home/test")
    assert strip_suffixes(Path("home.xz/test.xz")) == Path("home.xz/test")
    assert strip_suffixes(Path("home.xz/test")) == Path("home.xz/test")
    assert strip_suffixes(Path("home.xz/test.txt")) == Path("home.xz/test.txt")


@pytest.mark.parametrize(
    "delimiter,inp,result",
    [
        (" ", "a b c d e", ["e", "d", "c", "b", "a"]),
        (",", "a,b,c,d,e", ["e", "d", "c", "b", "a"]),
        (" ", "a b !c", ["b", "a"]),
        (" ", "a b !c c c c d", ["d", "b", "a"]),
        (" ", "a b !!c c", ["c", "b", "a"]),
        (" ", "a b (c)", ["c", "b", "a"]),
        (" ", "a b ((c))", ["c", "b", "a"]),
        (" ", "a b (!(c))", ["b", "a"]),
        (" ", "a (b c)", ["c", "b", "a"]),
        (" ", "a (!(b !c))", ["c", "a"]),
        (" ", "a !(b c) b c d", ["d", "a"]),
        (" ", "a !(b !c d !(e f)) b d e g", ["g", "e", "f", "e", "c", "a"]),
        (" ", "a foo* foobar", ["foobar", "foo*", "a"]),
        (" ", "a !foo* foobar", ["a"]),
    ]
)
def test_config_list_parser(delimiter: str, inp: str, result: list[str]) -> None:
    args = argparse.Namespace()
    parser = config_make_list_parser(delimiter)
    assert parser("dest", inp, args) == result


@pytest.mark.parametrize(
    "delimiter,allow_globs,match,defined,expect",
    [
        (" ", False, "buster", "bookworm", False),
        (" ", False, "buster bullseye", "bookworm", False),
        (" ", False, "bookworm", "bookworm", True,),
        (" ", False, "bookworm trixe", "bookworm", True),
        (" ", False, "!buster", "bookworm", True),
        (" ", True, "buster", "bookworm", False),
        (" ", True, "buster bullseye", "bookworm", False),
        (" ", True, "bookworm", "bookworm", True,),
        (" ", True, "bookworm trixe", "bookworm", True),
        (" ", True, "!buster", "bookworm", True),
        (" ", True, "!bu*", "bullseye", False),
        (" ", True, "!bu*", "bookworm", True),
        (" ", True, "bu*", "bullseye", True),
        (" ", True, "!(buster bullseye)", "bullseye", False),
        (" ", True, "!(buster bullseye)", "trixie", True),
        (" ", True, "!buster !bullseye", "bullseye", True),
        (" ", True, "!buster !bullseye", "trixie", True),
    ]
)
def test_config_list_matcher(delimiter: str, allow_globs: bool, match: str, defined: str, expect: bool) -> None:
    args = argparse.Namespace()
    args.test = defined
    matcher = config_make_list_matcher(delimiter, allow_globs=allow_globs)
    assert matcher("test", match, args) == expect
