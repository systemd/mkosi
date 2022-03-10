# SPDX-License-Identifier: LGPL-2.1+

import os
from subprocess import CalledProcessError, TimeoutExpired

import pytest

from mkosi.backend import Verb
from mkosi.machine import Machine, MkosiMachineTest, test_skip_not_supported

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.getuid() != 0, reason="Must be invoked as root.")
]

class MkosiMachineTestCase(MkosiMachineTest):
    def test_simple_run(self) -> None:
        process = self.machine.run(["echo", "This is a test."])
        assert process.stdout.strip("\n") == "This is a test."

    def test_wrong_command(self) -> None:
        # Check = True from mkosi.backend.run(), therefore we see if an exception is raised
        with pytest.raises(CalledProcessError):
            self.machine.run(["NonExisting", "Command"])
        with pytest.raises(CalledProcessError):
            self.machine.run(["ls", "NullDirectory"])

        # Check = False to see if stderr and returncode have the expected values
        result = self.machine.run(["NonExisting", "Command"], check=False)
        assert result.returncode in (1, 127, 203)

        result = self.machine.run(["ls", "-"], check=False)
        assert result.returncode == 2
        assert "No such file or directory" in result.stderr

    def test_infinite_command(self) -> None:
        with pytest.raises(TimeoutExpired):
            self.machine.run(["tail", "-f", "/dev/null"], 2)


def test_before_boot() -> None:
    with test_skip_not_supported():
        m = Machine()

    if m.args.verb == Verb.shell:
        pytest.skip("Shell never boots the machine.")
    with pytest.raises(AssertionError):
        m.run(["ls"])


def test_after_shutdown() -> None:
    with test_skip_not_supported():
        with Machine() as m:
            pass

    if m.args.verb == Verb.shell:
        pytest.skip("Shell never boots the machine.")
    with pytest.raises(AssertionError):
        m.run(["ls"])

    assert m.exit_code == 0
