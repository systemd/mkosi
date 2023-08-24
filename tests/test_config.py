# SPDX-License-Identifier: LGPL-2.1+

import argparse
import pathlib
import tempfile

from mkosi.config import Compression, MkosiConfigParser, load_config
from mkosi.distributions import Distribution


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

def test_default_config() -> None:
    with tempfile.NamedTemporaryFile('w') as f:
        f.write("[Distribution]\n")
        f.write("DefaultDistribution=debian\n")
        f.write("Distribution=ubuntu\n")
        f.flush()
        f.seek(0)

        p = MkosiConfigParser()
        def_args, def_config = p.parse([])
        args_ns = argparse.Namespace()
        for k, v in vars(def_args).items():
            setattr(args_ns, k, v)
        def_ns = argparse.Namespace()
        for k, v in vars(def_config[0]).items():
            setattr(args_ns, k, v)

        assert p.parse_config(pathlib.Path(f.name), args_ns, def_ns)
        assert def_ns.distribution == Distribution.debian
        assert args_ns.distribution == Distribution.ubuntu

        conf = load_config(args_ns, def_ns)
        assert conf.distribution == Distribution.ubuntu
