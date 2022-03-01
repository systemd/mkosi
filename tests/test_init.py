# SPDX-License-Identifier: LGPL-2.1+

import filecmp
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

def test_copy_file(tmpdir: Path) -> None:
        dir_path = Path(tmpdir)
        file_1 = Path(dir_path) / "file_1.txt"
        file_2 = Path(dir_path) / "file_2.txt"
        file_1.touch()
        file_2.touch()

        # Copying two empty files.
        mkosi.copy_file(file_1, file_2)
        assert filecmp.cmp(file_1, file_2)

        # Copying content from one file.
        file_1.write_text("Testing copying content from this file to file_2.")
        mkosi.copy_file(file_1, file_2)
        assert filecmp.cmp(file_1, file_2)

        # Giving a non existing path/file.
        with pytest.raises(OSError):
            mkosi.copy_file("nullFilePath", file_1)

        # Copying when there's already content in both files.
        file_2.write_text("Testing copying content from file_1 to file_2, with previous data.")
        mkosi.copy_file(file_1, file_2)
        assert filecmp.cmp(file_1, file_2)
