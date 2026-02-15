# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import subprocess

import pytest

from mkosi.config import Bootloader, Firmware, OutputFormat
from mkosi.distribution import Distribution
from mkosi.run import find_binary, run
from mkosi.versioncomp import GenericVersion

from . import Image, ImageConfig

pytestmark = pytest.mark.integration


def have_vmspawn() -> bool:
    return find_binary("systemd-vmspawn") is not None and (
        GenericVersion(run(["systemd-vmspawn", "--version"], stdout=subprocess.PIPE).stdout.strip()) >= 256
    )


@pytest.mark.parametrize("format", [f for f in OutputFormat if not f.is_extension_image()])
def test_format(config: ImageConfig, format: OutputFormat) -> None:
    with Image(config) as image:
        if image.config.distribution == Distribution.rhel_ubi and format in (
            OutputFormat.esp,
            OutputFormat.uki,
        ):
            pytest.skip("Cannot build RHEL-UBI images with format 'esp' or 'uki'")

        image.build(options=["--format", str(format)])

        # FIXME: Also boot directory images when the CI runs systemd v260 or newer.
        if format == OutputFormat.directory:
            return

        if format == OutputFormat.disk and os.getuid() == 0:
            image.boot()

        if format in (OutputFormat.cpio, OutputFormat.uki, OutputFormat.esp):
            pytest.skip("Default image is too large to be able to boot in CPIO/UKI/ESP format")

        if image.config.distribution == Distribution.rhel_ubi:
            return

        if format in (OutputFormat.tar, OutputFormat.oci, OutputFormat.none, OutputFormat.portable):
            return

        image.vm()

        if have_vmspawn() and format == OutputFormat.disk:
            image.vm(options=["--vmm=vmspawn"])

        if format != OutputFormat.disk:
            return

        image.vm(["--firmware=bios"])


@pytest.mark.parametrize("bootloader", Bootloader)
def test_bootloader(config: ImageConfig, bootloader: Bootloader) -> None:
    if config.distribution == Distribution.rhel_ubi or bootloader.is_signed():
        return

    firmware = Firmware.linux if bootloader == Bootloader.none else Firmware.auto

    with Image(config) as image:
        image.build(["--format=disk", "--bootloader", str(bootloader)])
        image.vm(["--firmware", str(firmware)])
