# SPDX-License-Identifier: LGPL-2.1+

import os

import pytest

from mkosi.config import OutputFormat
from mkosi.distributions import Distribution
from mkosi.qemu import find_virtiofsd

from . import Image

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("format", OutputFormat)
def test_boot(format: OutputFormat) -> None:
    with Image(
        options=[
            "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
            "--incremental",
            "--ephemeral",
        ],
    ) as image:
        if image.distribution == Distribution.rhel_ubi and format in (OutputFormat.esp, OutputFormat.uki):
            pytest.skip("Cannot build RHEL-UBI images with format 'esp' or 'uki'")

        options = ["--format", str(format)]

        image.summary(options)
        image.genkey()
        image.build(options=options)

        if format in (OutputFormat.disk, OutputFormat.directory) and os.getuid() == 0:
            # systemd-resolved is enabled by default in Arch/Debian/Ubuntu (systemd default preset) but fails
            # to start in a systemd-nspawn container with --private-users so we mask it out here to avoid CI
            # failures.
            # FIXME: Remove when Arch/Debian/Ubuntu ship systemd v253
            args = ["systemd.mask=systemd-resolved.service"] if format == OutputFormat.directory else []
            image.boot(options=options, args=args)

        if (
            image.distribution == Distribution.ubuntu and
            format in (OutputFormat.cpio, OutputFormat.uki, OutputFormat.esp)
        ):
            # https://bugs.launchpad.net/ubuntu/+source/linux-kvm/+bug/2045561
            pytest.skip("Cannot boot Ubuntu UKI/cpio images in qemu until we switch back to linux-kvm")

        if image.distribution == Distribution.rhel_ubi:
            return

        if format in (OutputFormat.tar, OutputFormat.none) or format.is_extension_image():
            return

        if format == OutputFormat.directory and not find_virtiofsd():
            return

        image.qemu(options=options)

        if format != OutputFormat.disk:
            return

        image.qemu(options=options + ["--qemu-firmware=bios"])
