# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
from pathlib import Path

import pytest

import mkosi.mounts
from mkosi.config import Config, ConfigTree
from mkosi.mounts import gitdir_mounts
from mkosi.util import PathString


def make_config(*sources: Path) -> Config:
    return dataclasses.replace(
        Config.default(),
        build_sources=[ConfigTree(s, None) for s in sources],
    )


def make_worktree(parent: Path, *, name: str, main: str, relative: bool = False) -> Path:
    """Create a git worktree checkout with its gitdir in the main repository"""
    worktree = parent / name
    worktree.mkdir()
    gitdir = parent / main / ".git" / "worktrees" / name
    gitdir.mkdir(parents=True)
    (gitdir / "commondir").write_text("../..\n")

    location = gitdir if not relative else Path("..") / main / ".git" / "worktrees" / name
    (worktree / ".git").write_text(f"gitdir: {location}\n")

    return worktree


def parse_binds(options: list[PathString]) -> list[tuple[str, Path, Path]]:
    assert len(options) % 3 == 0
    return [(str(options[i]), Path(options[i + 1]), Path(options[i + 2])) for i in range(0, len(options), 3)]


def test_gitdir_mounts_worktree_absolute(tmp_path: Path) -> None:
    worktree = make_worktree(tmp_path, name="worktree", main="main")
    gitdir = tmp_path / "main/.git/worktrees/worktree"
    commondir = tmp_path / "main/.git/worktrees/worktree/../.."

    binds = parse_binds(gitdir_mounts(make_config(worktree), ephemeral=False))
    assert binds == [("--bind", gitdir, gitdir), ("--bind", commondir, commondir)]

    binds = parse_binds(gitdir_mounts(make_config(worktree), ephemeral=True))
    assert all(flag == "--ro-bind" for flag, _, _ in binds)


def test_gitdir_mounts_worktree_relative(tmp_path: Path) -> None:
    worktree = make_worktree(tmp_path, name="worktree", main="main", relative=True)
    gitdir = tmp_path / "worktree/../main/.git/worktrees/worktree"
    commondir = tmp_path / "worktree/../main/.git/worktrees/worktree/../.."
    sandbox_gitdir = Path("/work/src/../main/.git/worktrees/worktree")
    sandbox_commondir = Path("/work/src/../main/.git/worktrees/worktree/../..")

    binds = parse_binds(gitdir_mounts(make_config(worktree), ephemeral=False))
    assert binds == [
        ("--bind", gitdir, sandbox_gitdir),
        ("--bind", commondir, sandbox_commondir),
    ]


def test_gitdir_mounts_no_gitdir(tmp_path: Path) -> None:
    # A plain repository has a .git directory instead of a file.
    (tmp_path / "repo/.git").mkdir(parents=True)
    assert gitdir_mounts(make_config(tmp_path / "repo"), ephemeral=False) == []

    # A dangling gitfile.
    (tmp_path / "dangling").mkdir()
    (tmp_path / "dangling/.git").write_text("gitdir: /nonexistent/repo/.git/worktrees/foo\n")
    assert gitdir_mounts(make_config(tmp_path / "dangling"), ephemeral=False) == []

    # A .git file that is not a gitfile.
    (tmp_path / "notgit").mkdir()
    (tmp_path / "notgit/.git").write_text("something else\n")
    assert gitdir_mounts(make_config(tmp_path / "notgit"), ephemeral=False) == []


def test_gitdir_mounts_submodule(tmp_path: Path) -> None:
    # Submodule checkouts have a gitdir without commondir.
    (tmp_path / "super/sub").mkdir(parents=True)
    (tmp_path / "super/sub/.git").write_text("gitdir: ../.git/modules/sub\n")
    (tmp_path / "super/.git/modules/sub").mkdir(parents=True)

    assert gitdir_mounts(make_config(tmp_path / "super/sub"), ephemeral=False) == []


def test_gitdir_mounts_colliding_destination(tmp_path: Path) -> None:
    # The main repository is a sibling of the worktree named "src", so the gitdir ends up
    # below the build source destination, where the .git file itself is mounted.
    worktree = make_worktree(tmp_path, name="worktree1", main="src", relative=True)
    assert gitdir_mounts(make_config(worktree), ephemeral=False) == []

    # The main repository is a sibling of the worktree named "out", so the gitdir ends up
    # below /work/out which is backed by a host directory.
    worktree = make_worktree(tmp_path, name="worktree2", main="out", relative=True)
    assert gitdir_mounts(make_config(worktree), ephemeral=False) == []

    # The gitdir ends up at /work itself, where all the other work mounts live below.
    (tmp_path / "top").mkdir()
    (tmp_path / "top/.git").write_text("gitdir: ..\n")
    (tmp_path / "commondir").write_text("sub\n")
    (tmp_path / "sub").mkdir()
    assert gitdir_mounts(make_config(tmp_path / "top"), ephemeral=False) == []


def test_gitdir_mounts_tools_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The gitdir is located below a system directory which is mounted read-only from the
    # tools tree, so the mount point cannot be created when a tools tree is used.
    monkeypatch.setattr(mkosi.mounts, "TOOLS_TREE_DIRS", (tmp_path / "usr",))
    monkeypatch.setattr(Config, "tools", lambda self: tmp_path / "tools")
    worktree = make_worktree(tmp_path, name="worktree", main="usr/src")

    assert gitdir_mounts(make_config(worktree), ephemeral=False) == []

    monkeypatch.setattr(Config, "tools", lambda self: Path("/"))
    assert gitdir_mounts(make_config(worktree), ephemeral=False) != []
