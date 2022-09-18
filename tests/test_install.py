# SPDX-License-Identifier: LGPL-2.1+

import filecmp
from pathlib import Path

import pytest

from mkosi.install import copy_file

def test_copy_file(tmpdir: Path) -> None:
    dir_path = Path(tmpdir)
    file_1 = Path(dir_path) / "file_1.txt"
    file_2 = Path(dir_path) / "file_2.txt"
    file_1.touch()
    file_2.touch()

    # Copying two empty files.
    copy_file(file_1, file_2)
    assert filecmp.cmp(file_1, file_2)

    # Copying content from one file.
    file_1.write_text("Testing copying content from this file to file_2.")
    copy_file(file_1, file_2)
    assert filecmp.cmp(file_1, file_2)

    # Giving a non existing path/file.
    with pytest.raises(OSError):
        copy_file("nullFilePath", file_1)

    # Copying when there's already content in both files.
    file_2.write_text("Testing copying content from file_1 to file_2, with previous data.")
    copy_file(file_1, file_2)
    assert filecmp.cmp(file_1, file_2)
