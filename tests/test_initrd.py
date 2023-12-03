# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

import pytest

from mkosi.distributions import Distribution

from . import Image


@pytest.mark.integration
def test_initrd() -> None:
    with Image(
        options=[
            "--directory", "",
            "--include=mkosi-initrd/",
        ],
    ) as initrd:
        if initrd.distribution == Distribution.rhel_ubi:
            pytest.skip("Cannot build RHEL-UBI initrds")

        initrd.build()

        with Image(
            options=[
                "--initrd", Path(initrd.output_dir.name) / "initrd",
                "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
                "--incremental",
                "--ephemeral",
                "--format=disk",
            ]
        ) as image:
            image.build()
            image.qemu()
