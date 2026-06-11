# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

from mkosi.config import OutputFormat

from . import Image, ImageConfigManager


async def do_test(image_config: ImageConfigManager, format: OutputFormat) -> None:
    with Image(image_config.config) as image:
        await image.build(["--clean-package-metadata=no", "--format=directory"])

        with Image(image.config) as sysext:
            await sysext.build(
                [
                    "--directory",
                    "",
                    "--incremental=no",
                    "--base-tree", Path(image.output_dir) / "image",
                    "--overlay=yes",
                    "--selinux-relabel=no",
                    "--package=lsof",
                    f"--format={format}",
                ]
            )  # fmt: skip


async def test_confext(image_config: ImageConfigManager) -> None:
    await do_test(image_config, OutputFormat.confext)


async def test_sysext(image_config: ImageConfigManager) -> None:
    await do_test(image_config, OutputFormat.sysext)


async def test_addon(image_config: ImageConfigManager) -> None:
    await do_test(image_config, OutputFormat.addon)
