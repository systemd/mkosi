# SPDX-License-Identifier: LGPL-2.1+

import os
from pathlib import Path

import mkosi.backend as backend
from mkosi.backend import Distribution, PackageType, set_umask


def test_distribution() -> None:
    assert Distribution.fedora.package_type == PackageType.rpm
    assert Distribution.fedora is Distribution.fedora
    assert Distribution.fedora.package_type is not Distribution.debian.package_type
    assert str(Distribution.photon) == "photon"


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
    assert backend.workspace(Path("/home/folder/mkosi/mkosi")) == Path("/home/folder/mkosi")
    assert backend.workspace(Path("/home/../home/folder/mkosi/mkosi")) == Path("/home/../home/folder/mkosi")
    assert backend.workspace(Path("/")) == Path("/")
    assert backend.workspace(Path()) == Path()


def test_footer_size() -> None:
    table = backend.PartitionTable()
    assert table.footer_size() == 16896
    assert table.footer_size(max_partitions=64) == 8704
    assert table.footer_size(max_partitions=1) == 1024
    assert table.footer_size(max_partitions=0) == 512

def test_first_partition_offset() -> None:
    table = backend.PartitionTable()
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
    table = backend.PartitionTable()
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
    table = backend.PartitionTable()
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
