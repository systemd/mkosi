# SPDX-License-Identifier: LGPL-2.1+

import os

import pytest

from mkosi.config import OutputFormat
from mkosi.distributions import Distribution
from mkosi.qemu import find_virtiofsd

from . import Image


@pytest.mark.integration
@pytest.mark.parametrize("format", [f for f in OutputFormat if f != OutputFormat.none])
def test_boot(format: OutputFormat) -> None:
    with Image(
        options=[
            "--kernel-command-line=console=ttyS0",
            "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
            "--kernel-command-line=systemd.log_target=console",
            "--kernel-command-line=systemd.default_standard_output=journal+console",
            "--qemu-vsock=yes",
            "--qemu-mem=4G",
            "--incremental",
            "--ephemeral",
        ],
    ) as image:
        if image.distribution == Distribution.rhel_ubi and format in (OutputFormat.esp, OutputFormat.uki):
            pytest.skip("Cannot build RHEL-UBI images with format 'esp' or 'uki'")

        options = ["--format", str(format)]

        image.summary(options)

        image.build(options=options)

        if format in (OutputFormat.disk, OutputFormat.directory) and os.getuid() == 0:
            # systemd-resolved is enabled by default in Arch/Debian/Ubuntu (systemd default preset) but fails
            # to start in a systemd-nspawn container with --private-users so we mask it out here to avoid CI
            # failures.
            # FIXME: Remove when Arch/Debian/Ubuntu ship systemd v253
            args = ["systemd.mask=systemd-resolved.service"] if format == OutputFormat.directory else []
            image.boot(options=options, args=args)

        if image.distribution == Distribution.rhel_ubi:
            return

        if format == OutputFormat.tar:
            return

        if format == OutputFormat.directory and not find_virtiofsd():
            return

        image.qemu(options=options)

        if format != OutputFormat.disk:
            return

        image.qemu(options=options + ["--qemu-firmware=bios"])
