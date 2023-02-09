# SPDX-License-Identifier: LGPL-2.1+

import argparse
import tempfile
from contextlib import contextmanager
from os import chdir, getcwd
from pathlib import Path
from typing import Iterator, List, Optional

import pytest

import mkosi
from mkosi.backend import Distribution, MkosiConfig, Verb
from mkosi.log import MkosiException


def parse(argv: Optional[List[str]] = None) -> MkosiConfig:
    return mkosi.load_args(mkosi.parse_args(argv))


@contextmanager
def cd_temp_dir() -> Iterator[None]:
    old_dir = getcwd()

    with tempfile.TemporaryDirectory() as tmp_dir:
        chdir(tmp_dir)
        try:
            yield
        finally:
            chdir(old_dir)

def test_parse_load_verb() -> None:
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
    assert parse(["--bootable", "qemu"]).verb == Verb.qemu
    with pytest.raises(SystemExit):
        parse(["invalid"])

def test_os_distribution() -> None:
    for dist in Distribution:
        assert parse(["-d", dist.name]).distribution == dist

    with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
        parse(["-d", "invalidDistro"])
    with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
        parse(["-d"])

    for dist in Distribution:
        with cd_temp_dir():
            config = Path("mkosi.conf")
            config.write_text(f"[Distribution]\nDistribution={dist}")
            assert parse([]).distribution == dist


def test_hostname() -> None:
    assert parse(["--hostname", "name"]).hostname == "name"
    with pytest.raises(SystemExit):
        parse(["--hostname", "name", "additional_name"])
    with pytest.raises(SystemExit):
        parse(["--hostname"])

    with cd_temp_dir():
        config = Path("mkosi.conf")
        config.write_text("[Output]\nHostname=name")
        assert parse([]).hostname == "name"

def test_shell_boot() -> None:
    with pytest.raises(MkosiException, match=".boot.*tar"):
        parse(["--format", "tar", "boot"])

    with pytest.raises(MkosiException, match=".boot.*cpio"):
        parse(["--format", "cpio", "boot"])

    with pytest.raises(MkosiException, match=".boot.*compressed" ):
        parse(["--format", "disk", "--compress-output=yes", "boot"])

    with pytest.raises(MkosiException, match=".boot.*qcow2"):
        parse(["--format", "disk", "--qcow2", "boot"])

def test_compression() -> None:
    assert not parse(["--format", "disk", "--compress-output", "False"]).compress_output

