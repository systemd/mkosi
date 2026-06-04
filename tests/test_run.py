# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import subprocess
import time
from pathlib import Path

import pytest

from mkosi.run import fork_and_wait, run


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


def attempts_cmd(counter: Path, succeed_on: int) -> list[str]:
    # Append a line to the counter file on every invocation and fail until it has been invoked
    # succeed_on times.
    return ["sh", "-ec", f"echo x >>{counter}; [ $(wc -l <{counter}) -ge {succeed_on} ]"]


def attempts(counter: Path) -> int:
    return len(counter.read_text().splitlines())


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    durations: list[float] = []
    # Don't actually sleep during the test, but record durations
    monkeypatch.setattr(time, "sleep", durations.append)
    return durations


def test_run_no_retry_by_default(tmp_path: Path, sleeps: list[float]) -> None:
    counter = tmp_path / "counter"

    with pytest.raises(subprocess.CalledProcessError):
        run(attempts_cmd(counter, succeed_on=2), log=False)

    assert attempts(counter) == 1
    assert sleeps == []


def test_run_retry_eventually_succeeds(tmp_path: Path, sleeps: list[float]) -> None:
    counter = tmp_path / "counter"

    result = run(attempts_cmd(counter, succeed_on=3), log=False, num_retries=3)

    assert result.returncode == 0
    assert attempts(counter) == 3
    assert sleeps == [1, 8]


def test_run_retry_exhausted(tmp_path: Path, sleeps: list[float]) -> None:
    counter = tmp_path / "counter"

    with pytest.raises(subprocess.CalledProcessError):
        # num_retries=2 means 3 attempts in total, so succeeding on the 4th is just out of reach
        run(attempts_cmd(counter, succeed_on=4), log=False, num_retries=2)

    assert attempts(counter) == 3
    assert sleeps == [1, 8]


def test_run_retry_immediate_success_does_not_sleep(tmp_path: Path, sleeps: list[float]) -> None:
    counter = tmp_path / "counter"

    result = run(attempts_cmd(counter, succeed_on=1), log=False, num_retries=3)

    assert result.returncode == 0
    assert attempts(counter) == 1
    assert sleeps == []


def test_run_no_retry_without_check(tmp_path: Path, sleeps: list[float]) -> None:
    counter = tmp_path / "counter"

    result = run(attempts_cmd(counter, succeed_on=2), check=False, log=False, num_retries=3)

    assert result.returncode == 1
    assert attempts(counter) == 1
    assert sleeps == []
