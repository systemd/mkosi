# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

import pytest

from mkosi.util import parents_below


def test_parents_below_basic() -> None:
    path = Path("/a/b/c/d/e")
    below = Path("/a/b")
    assert parents_below(path, below) == [Path("/a/b/c/d"), Path("/a/b/c")]


def test_parents_below_root() -> None:
    path = Path("/a/b/c")
    below = Path("/")
    assert parents_below(path, below) == [Path("/a/b"), Path("/a")]


def test_parents_below_direct_child() -> None:
    path = Path("/a/b/c")
    below = Path("/a/b")
    assert parents_below(path, below) == []


def test_parents_below_relative_paths() -> None:
    path = Path("a/b/c/d")
    below = Path("a/b")
    assert parents_below(path, below) == [Path("a/b/c")]


def test_parents_below_same_path_raises() -> None:
    path = Path("/a/b/c")
    below = Path("/a/b/c")
    with pytest.raises(ValueError):
        parents_below(path, below)


def test_parents_below_not_parent_raises() -> None:
    path = Path("/a/b/c")
    below = Path("/x/y/z")
    with pytest.raises(ValueError):
        parents_below(path, below)


def test_parents_below_below_is_child_raises() -> None:
    path = Path("/a/b")
    below = Path("/a/b/c")
    with pytest.raises(ValueError):
        parents_below(path, below)
