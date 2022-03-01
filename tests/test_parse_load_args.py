# SPDX-License-Identifier: LGPL-2.1+

import argparse
import tempfile
import textwrap
import uuid
from contextlib import contextmanager
from os import chdir, getcwd
from pathlib import Path
from typing import Iterator, List, Optional

import pytest

import mkosi
from mkosi.backend import Distribution, MkosiArgs, MkosiException, Verb


def parse(argv: Optional[List[str]] = None) -> MkosiArgs:
    return mkosi.load_args(mkosi.parse_args(argv)["default"])

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
            config = Path("mkosi.default")
            config.write_text(f"[Distribution]\nDistribution={dist}")
            assert parse([]).distribution == dist

def test_machine_id() -> None:
    id = uuid.uuid4().hex
    load_args = parse(["--machine-id", id])

    assert load_args.machine_id == id
    assert load_args.machine_id_is_fixed

    with pytest.raises(MkosiException):
        parse(["--machine-id", "notValidKey"])
    with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
        parse(["--machine-id"])

    with cd_temp_dir():
        config = Path("mkosi.default")
        config.write_text(f"[Output]\nMachineID={id}")
        load_args = parse([])
        assert load_args.machine_id == id
        assert load_args.machine_id_is_fixed

    with cd_temp_dir():
        config = Path("mkosi.default")
        config.write_text("[Output]\nMachineID=")
        with pytest.raises(MkosiException):
            parse([])

def test_hostname() -> None:
    assert parse(["--hostname", "name"]).hostname == "name"
    with pytest.raises(SystemExit):
        parse(["--hostname", "name", "additional_name"])
    with pytest.raises(SystemExit):
        parse(["--hostname"])

    with cd_temp_dir():
        config = Path("mkosi.default")
        config.write_text("[Output]\nHostname=name")
        assert parse([]).hostname == "name"

    with cd_temp_dir():
        config = Path("mkosi.default")
        config.write_text("[Output]\nHostname=")
        config = Path("hostname.txt")
        assert parse([]).hostname == ""

def test_centos_brtfs() -> None:
    with cd_temp_dir():
        config = Path("mkosi.default")
        for dist in (Distribution.centos, Distribution.centos_epel):
            for release in range (2, 9):
                config.write_text(
                    textwrap.dedent(
                        f"""
                        [Distribution]
                        Distribution={dist}
                        Release={release}
                        [Output]
                        Format=gpt_btrfs
                        """
                    )
                )
                with pytest.raises(MkosiException, match=".CentOS.*btrfs"):
                    parse([])

    with cd_temp_dir():
        config = Path("mkosi.default")
        for dist in (Distribution.centos, Distribution.centos_epel):
            for release in range (2, 8):
                config.write_text(
                    textwrap.dedent(
                        f"""
                        [Distribution]
                        Distribution={Distribution.centos}
                        Release={release}
                        Bootable=yes
                        """
                    )
                )
                with pytest.raises(MkosiException, match=".CentOS.*unified.*kernel"):
                    parse([])

def test_shell_boot() -> None:
    with pytest.raises(MkosiException, match=".boot.*tar"):
        parse(["--format", "tar", "boot"])

    with pytest.raises(MkosiException, match=".boot.*cpio"):
        parse(["--format", "cpio", "boot"])

    with pytest.raises(MkosiException, match=".boot.*compressed" ):
        parse(["--format", "gpt_squashfs", "--compress-output", "True", "boot"])

    with pytest.raises(MkosiException, match=".boot.*qcow2"):
        parse(["--format", "gpt_xfs", "--qcow2", "boot"])

def test_compression() -> None:
    assert parse(["--format", "gpt_squashfs"]).compress

    with pytest.raises(MkosiException, match=".*compression.*squashfs"):
        parse(["--format", "gpt_squashfs", "--compress", "False"])

    with pytest.raises(MkosiException, match=".*BIOS.*squashfs"):
        parse(["--format", "gpt_squashfs", "--boot-protocols", "bios"])
