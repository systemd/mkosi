# SPDX-License-Identifier: LGPL-2.1-or-later

import tarfile
from pathlib import Path

import pytest

from mkosi.config import OutputFormat
from mkosi.distribution import Distribution

from . import Image, ImageConfig

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("format", [f for f in OutputFormat if f.is_extension_image()])
def test_extension(config: ImageConfig, format: OutputFormat, tmp_path: Path) -> None:
    if config.distribution == Distribution.buildstream:
        pytest.skip("TODO: add extension test for BuildStream")

    duplicate = Path("usr/share" if format == OutputFormat.sysext else "etc") / "mkosi-test-duplicate"
    (tmp_path / duplicate).parent.mkdir(parents=True)
    (tmp_path / duplicate).touch()

    with Image(config) as image:
        image.build(["--clean-package-metadata=no", "--format=directory", "--extra-tree", tmp_path])
        base = image.output_dir / "image"
        assert (base / "usr/bin/sed").exists()
        assert (base / "usr/bin/grep").exists()
        if format == OutputFormat.confext:
            assert (base / "etc/nanorc").is_file()

        with Image(image.config) as sysext:
            sysext.build(
                [
                    "--directory",
                    "",
                    "--incremental=no",
                    "--base-tree", base,
                    "--extra-tree", tmp_path,
                    "--overlay=yes",
                    "--selinux-relabel=no",
                    "--package=lsof,sed",
                    *(["--package=nano"] if format == OutputFormat.confext else []),
                    "--volatile-package=grep",
                    "--split-artifacts=tar",
                    "--compress-output=no",
                    f"--format={format}",
                ]
            )  # fmt: skip

            with tarfile.open(sysext.output_dir / "image.tar") as tar:
                paths = {Path(name) for name in tar.getnames()}
            assert duplicate not in paths
            if format == OutputFormat.sysext:
                assert Path("usr/bin/sed") in paths
                assert Path("usr/bin/grep") in paths
                assert paths & {Path("usr/bin/lsof"), Path("usr/sbin/lsof")}
            elif format == OutputFormat.confext:
                assert Path("etc/nanorc") in paths
