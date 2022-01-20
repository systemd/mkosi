# SPDX-License-Identifier: LGPL-2.1+

import argparse
import tempfile
import textwrap
import uuid
from contextlib import contextmanager
from os import chdir, getcwd
from pathlib import Path
from typing import List, Optional

import mkosi
import pytest
from mkosi.backend import Distribution, MkosiArgs, MkosiException


def parse(argv: Optional[List[str]] = None) -> MkosiArgs:
    return mkosi.load_args(mkosi.parse_args(argv)["default"])

@contextmanager
def cd_temp_dir():
    old_dir = getcwd()

    with tempfile.TemporaryDirectory() as tmp_dir:
        chdir(tmp_dir)
        try:
            yield
        finally:
            chdir(old_dir)

def test_parse_load_verb():
    assert parse(["build"]).verb == "build"
    assert parse(["clean"]).verb == "clean"
    with pytest.raises(SystemExit):
        parse(["help"])
    assert parse(["genkey"]).verb == "genkey"
    assert parse(["bump"]).verb == "bump"
    assert parse(["serve"]).verb == "serve"
    assert parse(["build"]).verb == "build"
    assert parse(["shell"]).verb == "shell"
    assert parse(["boot"]).verb == "boot"
    assert parse(["qemu"]).verb == "qemu"
    with pytest.raises(SystemExit):
        parse(["invalid"])

def test_os_distribution():
    for dist in Distribution:
        assert parse(["-d", dist.name]).distribution == dist

    with pytest.raises((argparse.ArgumentError, SystemExit)):
        parse(["-d", "invalidDistro"])
    with pytest.raises((argparse.ArgumentError, SystemExit)):
        parse(["-d"])

    for dist in Distribution:
        with cd_temp_dir():
            config = Path("mkosi.default")
            config.write_text(f"[Distribution]\nDistribution={dist}")
            assert parse([]).distribution == dist

def test_machine_id():
    id = uuid.uuid4().hex
    load_args = parse(["--machine-id", id])

    assert load_args.machine_id == id
    assert load_args.machine_id_is_fixed

    with pytest.raises(MkosiException):
        parse(["--machine-id", "notValidKey"])
    with pytest.raises((argparse.ArgumentError, SystemExit)):
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

def test_hostname():
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

def test_centos_brtfs():
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

def test_shell_boot():
    with pytest.raises(MkosiException, match=".boot.*tar"):
        parse(["--format", "tar", "boot"])

    with pytest.raises(MkosiException, match=".boot.*cpio"):
        parse(["--format", "cpio", "boot"])

    with pytest.raises(MkosiException, match=".boot.*compressed" ):
        parse(["--format", "gpt_squashfs", "--compress-output", "True", "boot"])

    with pytest.raises(MkosiException, match=".boot.*qcow2"):
        parse(["--format", "gpt_xfs", "--qcow2", "boot"])

def test_compression():
    assert parse(["--format", "gpt_squashfs"]).compress

    with pytest.raises(MkosiException, match=".*compression.*squashfs"):
        parse(["--format", "gpt_squashfs", "--compress", "False"])

    with pytest.raises(MkosiException, match=".*BIOS.*squashfs"):
        parse(["--format", "gpt_squashfs", "--boot-protocols", "bios"])
