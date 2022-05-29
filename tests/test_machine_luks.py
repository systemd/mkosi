# SPDX-License-Identifier: LGPL-2.1+

import os
import pytest

from mkosi.backend import Distribution, Verb
from mkosi.machine import MkosiMachineTest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.getuid() != 0, reason="Must be invoked as root.")
]


class MkosiLuksWithImageIdMachineTestCase(MkosiMachineTest):
    luks_password_file_path: str = './mkosi.passphrase'

    @classmethod
    def setUpClass(cls) -> None:
        luks_password = 'luks'

        with open(cls.luks_password_file_path, 'w', encoding="utf-8") as luks_password_file:
            luks_password_file.write(luks_password)

        command = '-d arch --encrypt all --image-id test-img qemu'.split(' ')

        super().__init_subclass__(command, luks_password)
        super().setUpClass()

        if cls.machine.args.distribution == Distribution.centos_epel and cls.machine.args.verb == Verb.qemu and not cls.machine.args.qemu_kvm:
            pytest.xfail("QEMU's CPU does not support the CentOS EPEL image arch when running without KVM")

    def test_simple_run(self) -> None:
        process = self.machine.run(["echo", "This is a test."], capture_output=True)
        assert process.stdout.strip("\n") == "This is a test."

    def tearDown(self) -> None:
        super().tearDown()
        os.remove(self.luks_password_file_path)
