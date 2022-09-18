# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

import pytest

import mkosi


def test_fedora_release_cmp() -> None:
    assert mkosi.fedora_release_cmp("rawhide", "rawhide") == 0
    assert mkosi.fedora_release_cmp("32", "32") == 0
    assert mkosi.fedora_release_cmp("33", "32") > 0
    assert mkosi.fedora_release_cmp("30", "31") < 0
    assert mkosi.fedora_release_cmp("-1", "-2") > 0
    assert mkosi.fedora_release_cmp("1", "-2") > 0
    with pytest.raises(ValueError):
        mkosi.fedora_release_cmp("literal", "rawhide")


def test_strip_suffixes() -> None:
    assert mkosi.strip_suffixes(Path("home/test.zstd")) == Path("home/test")
    assert mkosi.strip_suffixes(Path("home/test.xz")) == Path("home/test")
    assert mkosi.strip_suffixes(Path("home/test.raw")) == Path("home/test")
    assert mkosi.strip_suffixes(Path("home/test.tar")) == Path("home/test")
    assert mkosi.strip_suffixes(Path("home/test.cpio")) == Path("home/test")
    assert mkosi.strip_suffixes(Path("home/test.qcow2")) == Path("home/test")
    assert mkosi.strip_suffixes(Path("home.xz/test.xz")) == Path("home.xz/test")
    assert mkosi.strip_suffixes(Path("home.xz/test")) == Path("home.xz/test")
    assert mkosi.strip_suffixes(Path("home.xz/test.txt")) == Path("home.xz/test.txt")


def test_parse_bytes() -> None:
    assert mkosi.parse_bytes(None) == 0
    assert mkosi.parse_bytes("1") == 512
    assert mkosi.parse_bytes("1000") == 1024
    assert mkosi.parse_bytes("1K") == 1024
    assert mkosi.parse_bytes("1025") == 1536
    assert mkosi.parse_bytes("1M") == 1024**2
    assert mkosi.parse_bytes("1.9M") == 1992704
    assert mkosi.parse_bytes("1G") == 1024**3
    assert mkosi.parse_bytes("7.3G") == 7838315520

    with pytest.raises(ValueError):
        mkosi.parse_bytes("-1")
    with pytest.raises(ValueError):
        mkosi.parse_bytes("-2K")
    with pytest.raises(ValueError):
        mkosi.parse_bytes("-3M")
    with pytest.raises(ValueError):
        mkosi.parse_bytes("-4G")
