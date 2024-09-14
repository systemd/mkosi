# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

import pytest

from . import Image, ImageConfig

pytestmark = pytest.mark.integration


def test_sysext(config: ImageConfig) -> None:
    with Image(config) as image:
        image.build(["--clean-package-metadata=no", "--format=directory"])

        with Image(image.config) as sysext:
            sysext.build([
                "--directory", "",
                "--incremental=no",
                "--base-tree", Path(image.output_dir) / "image",
                "--overlay",
                "--package=dnsmasq",
                "--format=disk",
            ])

