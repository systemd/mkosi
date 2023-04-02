# SPDX-License-Identifier: LGPL-2.1+

import os
import secrets
import tarfile
from pathlib import Path

import pytest

from mkosi.backend import (
    Distribution,
    PackageType,
    safe_tar_extract,
    set_umask,
    strip_suffixes,
)
from mkosi.log import MkosiException


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


def test_safe_tar_extract(tmp_path: Path) -> None:
    name = secrets.token_hex()
    testfile = tmp_path / name
    testfile.write_text("Evil exploit\n")

    safe_tar = tmp_path / "safe.tar.gz"
    with tarfile.TarFile.open(safe_tar, "x:gz") as t:
        t.add(testfile, arcname=name)

    evil_tar = tmp_path / "evil.tar.gz"
    with tarfile.TarFile.open(evil_tar, "x:gz") as t:
        t.add(testfile, arcname=f"../../../../../../../../../../../../../../tmp/{name}")

    safe_target = tmp_path / "safe_target"
    with tarfile.TarFile.open(safe_tar) as t:
        safe_tar_extract(t, safe_target)
    assert (safe_target / name).exists()

    evil_target = tmp_path / "evil_target"
    with pytest.raises(MkosiException):
        with tarfile.TarFile.open(evil_tar) as t:
            safe_tar_extract(t, evil_target)
    assert not (evil_target / name).exists()
    assert not (Path("/tmp") / name).exists()


def test_strip_suffixes() -> None:
    assert strip_suffixes(Path("home/test.zstd")) == Path("home/test")
    assert strip_suffixes(Path("home/test.xz")) == Path("home/test")
    assert strip_suffixes(Path("home/test.raw")) == Path("home/test")
    assert strip_suffixes(Path("home/test.tar")) == Path("home/test")
    assert strip_suffixes(Path("home/test.cpio")) == Path("home/test")
    assert strip_suffixes(Path("home.xz/test.xz")) == Path("home.xz/test")
    assert strip_suffixes(Path("home.xz/test")) == Path("home.xz/test")
    assert strip_suffixes(Path("home.xz/test.txt")) == Path("home.xz/test.txt")
