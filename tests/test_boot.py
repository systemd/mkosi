# SPDX-License-Identifier: LGPL-2.1+

import os
import subprocess

import pytest

from mkosi.config import Bootloader, OutputFormat, QemuFirmware
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


@pytest.mark.parametrize("format", [f for f in OutputFormat if f not in (OutputFormat.confext, OutputFormat.sysext)])
def test_format(config: Image.Config, format: OutputFormat) -> None:
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
            image.boot(options=options)

        if format in (OutputFormat.cpio, OutputFormat.uki, OutputFormat.esp):
            pytest.skip("Default image is too large to be able to boot in CPIO/UKI/ESP format")

        if image.config.distribution == Distribution.rhel_ubi:
            return

        if format in (OutputFormat.tar, OutputFormat.oci, OutputFormat.none) or format.is_extension_image():
            return

        if format == OutputFormat.directory and not find_virtiofsd():
            return

        image.qemu(options=options)

        if have_vmspawn() and format in (OutputFormat.disk, OutputFormat.directory):
            image.vmspawn(options=options)

        if format != OutputFormat.disk:
            return

        image.qemu(options=options + ["--qemu-firmware=bios"])


@pytest.mark.parametrize("bootloader", Bootloader)
def test_bootloader(config: Image.Config, bootloader: Bootloader) -> None:
    if config.distribution == Distribution.rhel_ubi:
        return

    firmware = QemuFirmware.linux if bootloader == Bootloader.none else QemuFirmware.auto

    with Image(
        config,
        options=[
            "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
            "--incremental",
            "--ephemeral",
            "--format=disk",
            "--bootloader", str(bootloader),
            "--qemu-firmware", str(firmware)
        ],
    ) as image:
        image.summary()
        image.genkey()
        image.build()
        image.qemu()
