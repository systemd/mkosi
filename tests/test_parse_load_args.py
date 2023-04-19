# SPDX-License-Identifier: LGPL-2.1+

import argparse
import tempfile
from contextlib import contextmanager
from os import chdir, getcwd
from pathlib import Path
from typing import Iterator, List, Optional

import pytest

import mkosi
from mkosi.backend import Compression, Distribution, MkosiConfig, Verb
from mkosi.config import MkosiConfigParser


@contextmanager
def cd_temp_dir() -> Iterator[None]:
    old_dir = getcwd()

    with tempfile.TemporaryDirectory() as tmp_dir:
        chdir(tmp_dir)
        try:
            yield
        finally:
            chdir(old_dir)


def parse(argv: Optional[List[str]] = None) -> MkosiConfig:
    return mkosi.load_args(MkosiConfigParser().parse(argv))


def test_parse_load_verb() -> None:
    with cd_temp_dir():
        assert parse(["build"]).verb == Verb.build
        assert parse(["clean"]).verb == Verb.clean
        with pytest.raises(SystemExit):
            parse(["help"])
        assert parse(["genkey"]).verb == Verb.genkey
        assert parse(["bump"]).verb == Verb.bump
        assert parse(["serve"]).verb == Verb.serve
        assert parse(["build"]).verb == Verb.build
        assert parse(["shell"]).verb == Verb.shell
        assert parse(["boot"]).verb == Verb.boot
        assert parse(["qemu"]).verb == Verb.qemu
        with pytest.raises(SystemExit):
            parse(["invalid"])


def test_os_distribution() -> None:
    with cd_temp_dir():
        for dist in Distribution:
            assert parse(["-d", dist.name]).distribution == dist

        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse(["-d", "invalidDistro"])
        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse(["-d"])

        for dist in Distribution:
            config = Path("mkosi.conf")
            config.write_text(f"[Distribution]\nDistribution={dist}")
            assert parse([]).distribution == dist


def test_parse_config_files_filter() -> None:
    with cd_temp_dir():
        confd = Path("mkosi.conf.d")
        confd.mkdir(0o755)

        (confd / "10-file.conf").write_text("[Content]\nPackages=yes")
        (confd / "20-file.noconf").write_text("[Content]\nPackages=nope")

        assert parse([]).packages == ["yes"]


def test_shell_boot() -> None:
    with cd_temp_dir():
        with pytest.raises(RuntimeError, match=".boot.*tar"):
            parse(["--format", "tar", "boot"])

        with pytest.raises(RuntimeError, match=".boot.*cpio"):
            parse(["--format", "cpio", "boot"])

        with pytest.raises(RuntimeError, match=".boot.*compressed" ):
            parse(["--format", "disk", "--compress-output=yes", "boot"])


def test_compression() -> None:
    with cd_temp_dir():
        assert parse(["--format", "disk", "--compress-output", "False"]).compress_output == Compression.none

