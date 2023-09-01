# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.config import Compression, parse_ini


def test_compression_enum_creation() -> None:
    assert Compression("none") == Compression.none
    assert Compression("zst") == Compression.zst
    assert Compression("xz") == Compression.xz
    assert Compression("bz2") == Compression.bz2
    assert Compression("gz") == Compression.gz
    assert Compression("lz4") == Compression.lz4
    assert Compression("lzma") == Compression.lzma


def test_compression_enum_bool() -> None:
    assert bool(Compression.none) == False
    assert bool(Compression.zst)  == True
    assert bool(Compression.xz)   == True
    assert bool(Compression.bz2)  == True
    assert bool(Compression.gz)   == True
    assert bool(Compression.lz4)  == True
    assert bool(Compression.lzma) == True


def test_compression_enum_str() -> None:
    assert str(Compression.none) == "none"
    assert str(Compression.zst)  == "zst"
    assert str(Compression.xz)   == "xz"
    assert str(Compression.bz2)  == "bz2"
    assert str(Compression.gz)   == "gz"
    assert str(Compression.lz4)  == "lz4"
    assert str(Compression.lzma) == "lzma"


def test_parse_ini(tmp_path: Path) -> None:
    p = tmp_path / "ini"
    p.write_text(
        """\
        [MySection]
        Value=abc
        Other=def
        ALLCAPS=txt

        # Comment
        ; Another comment
        [EmptySection]
        [AnotherSection]
        EmptyValue=
        Multiline=abc
                    def
                    qed
                    ord
        """
    )

    g = parse_ini(p)

    assert next(g) == ("MySection", "Value", "abc")
    assert next(g) == ("MySection", "Other", "def")
    assert next(g) == ("MySection", "ALLCAPS", "txt")
    assert next(g) == ("AnotherSection", "EmptyValue", "")
    assert next(g) == ("AnotherSection", "Multiline", "abc\ndef\nqed\nord")
