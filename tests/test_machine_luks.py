# SPDX-License-Identifier: LGPL-2.1+

import os
import pytest

from mkosi.backend import Distribution, Verb
from mkosi.machine import MkosiMachineTest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.getuid() != 0, reason="Must be invoked as root.")
]


class MkosiLuksMachineTestCase(MkosiMachineTest):
    luks_password_file_path: str = './mkosi.passphrase'

    @classmethod
    def setUpClass(cls) -> None:
        luks_password = 'luks'

        with open(cls.luks_password_file_path, 'w', encoding="utf-8") as luks_password_file:
            luks_password_file.write(luks_password)

        command_string = ""
        command_string += "-d arch --architecture x86_64 "
        command_string += "-t gpt_btrfs -b --boot-protocols uefi --encrypt all "
        command_string += "--hostname testhost --image-id test-img "
        command_string += "-p base,linux,util-linux,systemd,bash,cryptsetup "
        command_string += "--root-size 3G --esp-size 256M "
        command_string += "qemu"
        command = command_string.split(' ')

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
