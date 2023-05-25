# SPDX-License-Identifier: LGPL-2.1+

import argparse

import pytest

from pathlib import Path

from mkosi.config import strip_suffixes, config_make_list_parser


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
