# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

import pytest

from mkosi.config import OutputFormat

from . import Image, ImageConfig

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("format", [f for f in OutputFormat if f.is_extension_image()])
def test_extension(config: ImageConfig, format: OutputFormat) -> None:
    with Image(config) as image:
        image.build(["--clean-package-metadata=no", "--format=directory"])

        with Image(image.config) as sysext:
            sysext.build(
                [
                    "--directory",
                    "",
                    "--incremental=no",
                    "--base-tree", Path(image.output_dir) / "image",
                    "--overlay",
                    "--package=lsof",
                    f"--format={format}",
                ]
            )  # fmt: skip
