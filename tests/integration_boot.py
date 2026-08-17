# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import subprocess

import barrage.assertions as Assert

from mkosi.config import Bootloader, Firmware, OutputFormat
from mkosi.distribution import Distribution
from mkosi.run import find_binary, run
from mkosi.versioncomp import GenericVersion

from . import Image, ImageConfigManager


def have_vmspawn() -> bool:
    return find_binary("systemd-vmspawn") is not None and (
        GenericVersion(run(["systemd-vmspawn", "--version"], stdout=subprocess.PIPE).stdout.strip()) >= 256
    )


async def do_test_format(image_config: ImageConfigManager, format: OutputFormat) -> None:
    with Image(image_config.config) as image:
        if image.config.distribution == Distribution.rhel_ubi and format in (
            OutputFormat.esp,
            OutputFormat.uki,
        ):
            Assert.skip("Cannot build RHEL-UBI images with format 'esp' or 'uki'")

        await image.build(options=["--format", str(format)])

        # FIXME: Also boot directory images when the CI runs systemd v260 or newer.
        if format == OutputFormat.directory:
            return

        if format == OutputFormat.disk and os.getuid() == 0:
            await image.boot()

        if format in (OutputFormat.cpio, OutputFormat.uki, OutputFormat.esp):
            Assert.skip("Default image is too large to be able to boot in CPIO/UKI/ESP format")

        if image.config.distribution == Distribution.rhel_ubi:
            return

        if format in (OutputFormat.tar, OutputFormat.oci, OutputFormat.none, OutputFormat.portable):
            return

        await image.vm()

        if have_vmspawn() and format == OutputFormat.disk:
            await image.vm(options=["--vmm=vmspawn"])

        if format != OutputFormat.disk:
            return


async def test_format_cpio(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.cpio)


async def test_format_directory(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.directory)


async def test_format_disk(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.disk)


async def test_format_esp(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.esp)


async def test_format_none(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.none)


async def test_format_portable(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.portable)


async def test_format_tar(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.tar)


async def test_format_uki(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.uki)


async def test_format_oci(image_config: ImageConfigManager) -> None:
    await do_test_format(image_config, OutputFormat.oci)


async def do_test_bootloader(image_config: ImageConfigManager, bootloader: Bootloader) -> None:
    if image_config.config.distribution == Distribution.rhel_ubi or bootloader.is_signed():
        return

    firmware = Firmware.linux if bootloader == Bootloader.none else Firmware.auto

    with Image(image_config.config) as image:
        await image.build(["--format=disk", "--bootloader", str(bootloader)])
        await image.vm(["--firmware", str(firmware)])


async def test_bootloader_none(image_config: ImageConfigManager) -> None:
    await do_test_bootloader(image_config, Bootloader.none)


async def test_bootloader_uki(image_config: ImageConfigManager) -> None:
    await do_test_bootloader(image_config, Bootloader.uki)


async def test_bootloader_systemd_boot(image_config: ImageConfigManager) -> None:
    await do_test_bootloader(image_config, Bootloader.systemd_boot)


async def test_bootloader_grub(image_config: ImageConfigManager) -> None:
    await do_test_bootloader(image_config, Bootloader.grub)


async def test_bootloader_uki_signed(image_config: ImageConfigManager) -> None:
    await do_test_bootloader(image_config, Bootloader.uki_signed)


async def test_bootloader_systemd_boot_signed(image_config: ImageConfigManager) -> None:
    await do_test_bootloader(image_config, Bootloader.systemd_boot_signed)


async def test_bootloader_grub_signed(image_config: ImageConfigManager) -> None:
    await do_test_bootloader(image_config, Bootloader.grub_signed)
