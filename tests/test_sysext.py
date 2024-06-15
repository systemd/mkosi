# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

import pytest

from . import Image, ImageConfig

pytestmark = pytest.mark.integration


def test_sysext(config: ImageConfig) -> None:
    with Image(
        config,
        options=[
            "--incremental",
            "--clean-package-metadata=no",
            "--format=directory",
        ],
    ) as image:
        image.build()

        with Image(
            image.config,
            options=[
                "--directory", "",
                "--base-tree", Path(image.output_dir) / "image",
                "--overlay",
                "--package=dnsmasq",
                "--format=disk",
            ],
        ) as sysext:
            sysext.build()

