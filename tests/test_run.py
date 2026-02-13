# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import subprocess
from pathlib import Path

import pytest

from mkosi.run import fork_and_wait


def test_fork_and_wait_returns_value() -> None:
    result = fork_and_wait(lambda: 42)
    assert result == 42


def test_fork_and_wait_returns_none() -> None:
    result = fork_and_wait(lambda: None)
    assert result is None


def test_fork_and_wait_returns_string() -> None:
    result = fork_and_wait(lambda: "hello world")
    assert result == "hello world"


def test_fork_and_wait_returns_complex_type() -> None:
    result = fork_and_wait(lambda: {"key": [1, 2, 3], "nested": {"a": True}})
    assert result == {"key": [1, 2, 3], "nested": {"a": True}}


def test_fork_and_wait_passes_args() -> None:
    def add(a: int, b: int) -> int:
        return a + b

    result = fork_and_wait(add, 3, 4)
    assert result == 7


def test_fork_and_wait_passes_kwargs() -> None:
    def greet(name: str, greeting: str = "Hello") -> str:
        return f"{greeting}, {name}!"

    result = fork_and_wait(greet, "world", greeting="Hi")
    assert result == "Hi, world!"


def test_fork_and_wait_child_failure() -> None:
    def fail() -> None:
        raise RuntimeError("boom")

    with pytest.raises(subprocess.CalledProcessError):
        fork_and_wait(fail)


def test_fork_and_wait_sandbox(tmp_path: Path) -> None:
    (tmp_path / "abc").mkdir()

    def exists() -> bool:
        return Path("/abc").exists()

    result = fork_and_wait(exists, sandbox=contextlib.nullcontext(["--bind", os.fspath(tmp_path), "/"]))
    assert result
