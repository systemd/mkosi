# SPDX-License-Identifier: LGPL-2.1+

import os
from subprocess import TimeoutExpired

import pytest

import mkosi.machine as machine
from mkosi.backend import MkosiException

pytestmark = [
    pytest.mark.integration,
    pytest.mark.parametrize("verb", ["boot", "qemu"]),
    pytest.mark.skipif(os.getuid() != 0, reason="Must be invoked as root.")
]


def test_simple_run(verb: str) -> None:
    with machine.Machine([verb]) as m:
        p = m.run(["echo", "This is a test."])
        assert "This is a test." == p.stdout.strip("\n")

    assert m.exit_code == 0


def test_wrong_command(verb: str) -> None:
    # First tests with argument check = True from mkosi.backend.run(), therefore we see if an exception is raised
    with machine.Machine([verb]) as m:
        with pytest.raises(MkosiException):
            m.run(["NonExisting", "Command"])
        with pytest.raises(MkosiException):
            m.run(["ls", "NullDirectory"])

    assert m.exit_code == 0

    # Second group of tests with check = False to see if stderr and returncode have the expected values
    with machine.Machine([verb]) as m:
        result = m.run(["NonExisting", "Command"], check=False)
        assert result.returncode in (203, 127)

        result = m.run(["ls", "-"], check=False)
        assert result.returncode == 2
        assert "No such file or directory" in result.stderr

    assert m.exit_code == 0


def test_infinite_command(verb: str) -> None:
    with machine.Machine([verb]) as m:
        with pytest.raises(TimeoutExpired):
            m.run(["tail", "-f", "/dev/null"], 2)

    assert m.exit_code == 0


def test_before_boot(verb: str) -> None:
    m = machine.Machine([verb])
    with pytest.raises(AssertionError):
        m.run(["ls"])


def test_after_shutdown(verb: str) -> None:
    with machine.Machine([verb]) as m:
        pass

    with pytest.raises(AssertionError):
        m.run(["ls"])
    assert m.exit_code == 0
