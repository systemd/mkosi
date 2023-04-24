# SPDX-License-Identifier: LGPL-2.1+

import os

from mkosi.util import (
    Compression,
    Distribution,
    PackageType,
    set_umask,
)

def test_distribution() -> None:
    assert Distribution.fedora.package_type == PackageType.rpm
    assert Distribution.fedora is Distribution.fedora
    assert Distribution.fedora.package_type is not Distribution.debian.package_type
    assert str(Distribution.fedora) == "fedora"


def test_set_umask() -> None:
    with set_umask(0o767):
        tmp1 = os.umask(0o777)
        with set_umask(0o757):
            tmp2 = os.umask(0o727)
        tmp3 = os.umask(0o727)

    assert tmp1 == 0o767
    assert tmp2 == 0o757
    assert tmp3 == 0o777


def test_compression_enum_creation() -> None:
    assert Compression(None) == Compression.none
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
