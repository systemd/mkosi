# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.config import strip_suffixes


def test_strip_suffixes() -> None:
    assert strip_suffixes(Path("home/test.zstd")) == Path("home/test")
    assert strip_suffixes(Path("home/test.xz")) == Path("home/test")
    assert strip_suffixes(Path("home/test.raw")) == Path("home/test")
    assert strip_suffixes(Path("home/test.tar")) == Path("home/test")
    assert strip_suffixes(Path("home/test.cpio")) == Path("home/test")
    assert strip_suffixes(Path("home.xz/test.xz")) == Path("home.xz/test")
    assert strip_suffixes(Path("home.xz/test")) == Path("home.xz/test")
    assert strip_suffixes(Path("home.xz/test.txt")) == Path("home.xz/test.txt")
