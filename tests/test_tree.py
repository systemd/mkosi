# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path
from unittest.mock import patch

from mkosi.tree import tree_has_ima_xattr, tree_has_selinux_xattr


def test_tree_has_ima_xattr_present() -> None:
    with patch("os.listxattr", return_value=["security.ima", "security.selinux"]):
        with patch.object(Path, "rglob", return_value=[]):
            assert tree_has_ima_xattr(Path("/fake")) is True


def test_tree_has_ima_xattr_absent() -> None:
    with patch("os.listxattr", return_value=["security.selinux", "user.foo"]):
        with patch.object(Path, "rglob", return_value=[]):
            assert tree_has_ima_xattr(Path("/fake")) is False


def test_tree_has_selinux_xattr_present() -> None:
    with patch("os.listxattr", return_value=["security.selinux"]):
        with patch.object(Path, "rglob", return_value=[]):
            assert tree_has_selinux_xattr(Path("/fake")) is True


def test_tree_has_selinux_xattr_absent() -> None:
    with patch("os.listxattr", return_value=["security.ima", "user.foo"]):
        with patch.object(Path, "rglob", return_value=[]):
            assert tree_has_selinux_xattr(Path("/fake")) is False
