# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import subprocess
import tempfile
from pathlib import Path

import barrage.assertions as Assert

from mkosi.run import fork_and_wait


async def test_fork_and_wait_returns_value() -> None:
    result = fork_and_wait(lambda: 42)
    Assert.eq(result, 42)


async def test_fork_and_wait_returns_none() -> None:
    result = fork_and_wait(lambda: None)
    Assert.none(result)


async def test_fork_and_wait_returns_string() -> None:
    result = fork_and_wait(lambda: "hello world")
    Assert.eq(result, "hello world")


async def test_fork_and_wait_returns_complex_type() -> None:
    result = fork_and_wait(lambda: {"key": [1, 2, 3], "nested": {"a": True}})
    Assert.eq(result, {"key": [1, 2, 3], "nested": {"a": True}})


async def test_fork_and_wait_passes_args() -> None:
    def add(a: int, b: int) -> int:
        return a + b

    result = fork_and_wait(add, 3, 4)
    Assert.eq(result, 7)


async def test_fork_and_wait_passes_kwargs() -> None:
    def greet(name: str, greeting: str = "Hello") -> str:
        return f"{greeting}, {name}!"

    result = fork_and_wait(greet, "world", greeting="Hi")
    Assert.eq(result, "Hi, world!")


async def test_fork_and_wait_child_failure() -> None:
    def fail() -> None:
        raise RuntimeError("boom")

    with Assert.raises(subprocess.CalledProcessError):
        fork_and_wait(fail)


async def test_fork_and_wait_sandbox() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "abc").mkdir()

        def exists() -> bool:
            return Path("/abc").exists()

        result = fork_and_wait(exists, sandbox=contextlib.nullcontext(["--bind", os.fspath(tmp_path), "/"]))
        Assert.true(result)
