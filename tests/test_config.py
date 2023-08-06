# SPDX-License-Identifier: LGPL-2.1+

from mkosi.config import Compression


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
