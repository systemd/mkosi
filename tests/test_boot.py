# SPDX-License-Identifier: LGPL-2.1+

import os
import subprocess

import pytest

from mkosi.config import OutputFormat
from mkosi.distributions import Distribution
from mkosi.qemu import find_virtiofsd
from mkosi.run import find_binary, run
from mkosi.versioncomp import GenericVersion

from . import Image

pytestmark = pytest.mark.integration


def have_vmspawn() -> bool:
    return (
        find_binary("systemd-vmspawn") is not None
        and GenericVersion(run(["systemd-vmspawn", "--version"],
                               stdout=subprocess.PIPE).stdout.strip()) >= 256
    )


@pytest.mark.parametrize("format", OutputFormat)
def test_boot(config: Image.Config, format: OutputFormat) -> None:
    with Image(
        config,
        options=[
            "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
            "--incremental",
            "--ephemeral",
        ],
    ) as image:
        if image.config.distribution == Distribution.rhel_ubi and format in (OutputFormat.esp, OutputFormat.uki):
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
            image.config.distribution == Distribution.ubuntu and
            format in (OutputFormat.cpio, OutputFormat.uki, OutputFormat.esp)
        ):
            # https://bugs.launchpad.net/ubuntu/+source/linux-kvm/+bug/2045561
            pytest.skip("Cannot boot Ubuntu UKI/cpio images in qemu until we switch back to linux-kvm")

        if image.config.distribution == Distribution.rhel_ubi:
            return

        if format in (OutputFormat.tar, OutputFormat.none) or format.is_extension_image():
            return

        if format == OutputFormat.directory and not find_virtiofsd():
            return

        image.qemu(options=options)

        if have_vmspawn() and format in (OutputFormat.disk, OutputFormat.directory):
            image.vmspawn(options=options)

        if format != OutputFormat.disk:
            return

        image.qemu(options=options + ["--qemu-firmware=bios"])
