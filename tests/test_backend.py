# SPDX-License-Identifier: LGPL-2.1+

import os
import secrets
import tarfile
from pathlib import Path

import pytest

from mkosi.backend import (
    Distribution,
    MkosiException,
    PackageType,
    PartitionTable,
    safe_tar_extract,
    set_umask,
    workspace,
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


def test_workspace() -> None:
    assert workspace(Path("/home/folder/mkosi/mkosi")) == Path("/home/folder/mkosi")
    assert workspace(Path("/home/../home/folder/mkosi/mkosi")) == Path("/home/../home/folder/mkosi")
    assert workspace(Path("/")) == Path("/")
    assert workspace(Path()) == Path()


def test_footer_size() -> None:
    table = PartitionTable()
    assert table.footer_size() == 16896
    assert table.footer_size(max_partitions=64) == 8704
    assert table.footer_size(max_partitions=1) == 1024
    assert table.footer_size(max_partitions=0) == 512

def test_first_partition_offset() -> None:
    table = PartitionTable()
    table.grain = 4096

    # Grain = 4096, first_lba = None.
    # 20480 = (512 bytes sector size + 16896 bytes footer) rounded up to multiple of 4096 grain.
    assert table.first_partition_offset() == 20480

    # Grain = 4096, first_lba not None.
    # 32768 = first_lba of 64 * 512 bytes of sector_size.
    table.first_lba = 64
    assert table.first_partition_offset() == 32768

    # 0 since first_lba = 0 will be multiplied by some value of sector_size.
    table.first_lba = 0
    assert table.first_partition_offset() == 0

    # Grain = 1024 ** 2, first_lba = None.
    # 1048576 = (512 bytes sector size + 16896 bytes footer) rounded up to multiple of 1024 ** 2 grain.
    table.grain = 1024 ** 2
    table.first_lba = None
    assert table.first_partition_offset() == 1048576

    # Grain = 1024 ** 2, first_lba not None.
    # 65536 = first_lba of 128 * 512 bytes of sector_size.
    table.first_lba = 128
    assert table.first_partition_offset() == 65536

    # Grain = 1024 ** 2, first_lba not None.
    # 131072 = first_lba of 256 * 512 bytes of sector_size.
    table.first_lba = 256
    assert table.first_partition_offset() == 131072


def test_last_partition_offset() -> None:
    table = PartitionTable()
    table.grain = 4096

    table.last_partition_sector = 32
    assert table.last_partition_offset() == 16384

    table.last_partition_sector = 16
    assert table.last_partition_offset() == 8192

    table.last_partition_sector = 1
    assert table.last_partition_offset() == 4096

    table.last_partition_sector = 0
    table.first_lba = 64
    assert table.last_partition_offset() == 32768

    table.first_lba = 0
    assert table.last_partition_offset() == 0


def test_disk_size() -> None:
    table = PartitionTable()
    table.grain = 4096
    table.last_partition_sector = 0
    table.first_lba = 64
    # When disk_size() cascade upwards all the way to first_partition_offset, if clause.
    assert table.disk_size() == 53248

    # When disk_size() cascade upwards all the way to first_partition_offset, else clause.
    table.first_lba = None
    assert table.disk_size() == 40960

    # When disk_size() cascade upwards to last_partition_offset, if clause.
    table.last_partition_sector = 32
    assert table.disk_size() == 36864


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
