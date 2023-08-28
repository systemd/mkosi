# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import tempfile
from argparse import Namespace
from os import chdir
from pathlib import Path
from typing import Iterator

import pytest

from mkosi.architecture import Architecture
from mkosi.config import Compression, MkosiConfig, MkosiConfigParser, OutputFormat

CONF_DIR = Path(__file__).parent.absolute() / "test-config"


def parse_paths(paths: list[Path]) -> MkosiConfig:
    """Process these paths stacked together"""

    parser = MkosiConfigParser()
    namespace = Namespace()
    defaults = Namespace()
    setattr(namespace, "preset", None)

    for path in paths:
        parser.parse_config(path, namespace, defaults)

    parser.finalize_defaults(namespace, defaults)
    return MkosiConfig.from_namespace(namespace)


def parse_dropins() -> list[MkosiConfig]:
    """Return the configuration for the base config and each processed drop-in"""

    # The configuration is processed this way so that each drop-in can be tested
    # individually to confirm what occurs at each step. This emulates normal
    # drop-in processing but can separate out the steps for testing.

    paths = [CONF_DIR / "mkosi.conf"] + sorted((CONF_DIR / "mkosi.conf.d").iterdir())

    configs = list()
    for i in range(len(paths)):
        configs.append(parse_paths(paths[:i+1]))

    return configs


#TODO: Can be removed once we drop Python <3.11 support
@contextlib.contextmanager
def cd_new_dir(path: Path) -> Iterator[None]:
    cwd = Path().cwd()
    chdir(str(path))
    yield
    chdir(str(cwd))


@pytest.fixture(scope="module")
def get_config() -> dict[str, list[MkosiConfig]]:
    dropins = parse_dropins()
    configs = {
        'drop-ins': dropins[1:],
        'presets': [dropins[0]]
    }

    with cd_new_dir(CONF_DIR):
        args, presets = MkosiConfigParser().parse("")
        configs['presets'].extend(presets)

    return configs


def test_compression_enum_creation() -> None:
    assert Compression("none") == Compression.none
    assert Compression("zst") == Compression.zst
    assert Compression("xz") == Compression.xz
    assert Compression("bz2") == Compression.bz2
    assert Compression("gz") == Compression.gz
    assert Compression("lz4") == Compression.lz4
    assert Compression("lzma") == Compression.lzma


def test_compression_enum_bool() -> None:
    assert bool(Compression.none) == False
    assert bool(Compression.zst)  == True
    assert bool(Compression.xz)   == True
    assert bool(Compression.bz2)  == True
    assert bool(Compression.gz)   == True
    assert bool(Compression.lz4)  == True
    assert bool(Compression.lzma) == True


def test_compression_enum_str() -> None:
    assert str(Compression.none) == "none"
    assert str(Compression.zst)  == "zst"
    assert str(Compression.xz)   == "xz"
    assert str(Compression.bz2)  == "bz2"
    assert str(Compression.gz)   == "gz"
    assert str(Compression.lz4)  == "lz4"
    assert str(Compression.lzma) == "lzma"


def test_get_config(get_config : dict[str, list[MkosiConfig]]) -> None:
    assert get_config['drop-ins'][0].image_id == "00-dropin"
    assert get_config['drop-ins'][1].image_id == "01-dropin"
    assert get_config['drop-ins'][2].image_id == "02-dropin"
    assert get_config['presets'][0].image_id == "base"
    assert get_config['presets'][1].image_id == "test-preset"


def test_dropin_default(get_config : dict[str, list[MkosiConfig]]) -> None:
    # Default set
    assert get_config['drop-ins'][0].repository_key_check == True
    # Default changed
    assert get_config['drop-ins'][1].repository_key_check == False


def test_default_overridden(get_config : dict[str, list[MkosiConfig]]) -> None:
    assert get_config['drop-ins'][0].architecture == Architecture.arm64
    assert get_config['drop-ins'][1].architecture == Architecture.x86_64
    assert get_config['drop-ins'][2].architecture == Architecture.x86_64


def test_def_nondef_def(get_config : dict[str, list[MkosiConfig]]) -> None:
    assert get_config['drop-ins'][0].output_format == OutputFormat.cpio
    assert get_config['drop-ins'][1].output_format == OutputFormat.disk
    assert get_config['drop-ins'][2].output_format == OutputFormat.disk


def test_default_generation(get_config : dict[str, list[MkosiConfig]]) -> None:
    assert get_config['drop-ins'][0].mirror == "http://ports.ubuntu.com"
    assert get_config['drop-ins'][1].mirror == "http://archive.ubuntu.com/ubuntu"
    assert get_config['drop-ins'][2].mirror == "http://deb.debian.org/debian"


def write_config(dir: Path) -> None:
    with open(dir / "mkosi.conf", "w") as f:
        # We need something in the file to parse
        f.write("[Output]\n")
        f.write("ImageId=base\n")


def test_sorted_dropins() -> None:
    def write_dropin(dir: Path, name: str, version: int) -> None:
        with open(dir / name, "w") as f:
            f.write("[Output]\n")
            f.write(f"ImageVersion={version}\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        write_config(tmp_path)

        (tmp_path / "mkosi.conf.d").mkdir()
        # A roughly random order to save files in
        dropin_ids = [0,5,1,4,2,3]
        for i in dropin_ids:
            write_dropin(tmp_path / "mkosi.conf.d", f"0{i}-dropin.conf", i)

        with cd_new_dir(tmp_path):
            args, presets = MkosiConfigParser().parse("")

        assert presets[0].image_version == str(max(dropin_ids))


def test_path_inheritence() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        write_config(tmp_path)
        (tmp_path / "mkosi.output").mkdir()
        with cd_new_dir(tmp_path):
            args, presets = MkosiConfigParser().parse("")

        # Confirm output directory is processed
        assert presets[0].output_dir == Path(tmpdir) / "mkosi.output"

        # Add a preset
        (tmp_path / "mkosi.presets" / "00-test-preset").mkdir(parents=True)
        write_config(tmp_path / "mkosi.presets" / "00-test-preset")
        with cd_new_dir(tmp_path):
            args, presets = MkosiConfigParser().parse("")

        # Confirm output directory remains the same
        assert presets[0].preset == "00-test-preset"
        assert presets[0].output_dir == Path(tmpdir) / "mkosi.output"

        (tmp_path / "mkosi.presets" / "00-test-preset" / "mkosi.output").mkdir()
        with cd_new_dir(tmp_path):
            args, presets = MkosiConfigParser().parse("")

        # Confirm output directory changes
        assert presets[0].preset == "00-test-preset"
        assert presets[0].output_dir == Path(tmpdir) / "mkosi.presets" / "00-test-preset" / "mkosi.output"
