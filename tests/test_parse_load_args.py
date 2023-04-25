# SPDX-License-Identifier: LGPL-2.1+

import argparse
import itertools
import operator
import tempfile
from contextlib import contextmanager
from os import chdir, getcwd
from pathlib import Path
from textwrap import dedent
from typing import Iterator, List, Optional

import pytest

from mkosi.util import Compression, Distribution, Verb
from mkosi.config import MkosiConfigParser, MkosiConfig, load_args


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
    return load_args(MkosiConfigParser().parse(argv))


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
        with pytest.raises(SystemExit):
            parse(["--format", "tar", "boot"])

        with pytest.raises(SystemExit):
            parse(["--format", "cpio", "boot"])

        with pytest.raises(SystemExit):
            parse(["--format", "disk", "--compress-output=yes", "boot"])


def test_compression() -> None:
    with cd_temp_dir():
        assert parse(["--format", "disk", "--compress-output", "False"]).compress_output == Compression.none


@pytest.mark.parametrize("dist1,dist2", itertools.combinations_with_replacement(Distribution, 2))
def test_match_distribution(dist1: Distribution, dist2: Distribution) -> None:
    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                f"""\
                [Distribution]
                Distribution={dist1}
                """
            )
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                Distribution={dist1}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                Distribution={dist2}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                Distribution={dist1} {dist2}

                [Content]
                Packages=testpkg3
                """
            )
        )

        conf = parse([])
        assert "testpkg1" in conf.packages
        if dist1 == dist2:
            assert "testpkg2" in conf.packages
        assert "testpkg3" in conf.packages


@pytest.mark.parametrize(
    "release1,release2", itertools.combinations_with_replacement([36, 37, 38], 2)
)
def test_match_release(release1: int, release2: int) -> None:
    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                f"""\
                [Distribution]
                Distribution=fedora
                Release={release1}
                """
            )
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                Release={release1}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                Release={release2}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                Release={release1} {release2}

                [Content]
                Packages=testpkg3
                """
            )
        )

        conf = parse([])
        assert "testpkg1" in conf.packages
        if release1 == release2:
            assert "testpkg2" in conf.packages
        assert "testpkg3" in conf.packages


@pytest.mark.parametrize(
    "image1,image2", itertools.combinations_with_replacement(
        ["image_a", "image_b", "image_c"], 2
    )
)
def test_match_imageid(image1: str, image2: str) -> None:
    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                f"""\
                [Distribution]
                Distribution=fedora
                ImageId={image1}
                """
            )
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                ImageId={image1}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                ImageId={image2}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                ImageId={image1} {image2}

                [Content]
                Packages=testpkg3
                """
            )
        )
        child4 = Path("mkosi.conf.d/child4.conf")
        child4.write_text(
            dedent(
                """\
                [Match]
                ImageId=image*

                [Content]
                Packages=testpkg4
                """
            )
        )

        conf = parse([])
        assert "testpkg1" in conf.packages
        if image1 == image2:
            assert "testpkg2" in conf.packages
        assert "testpkg3" in conf.packages
        assert "testpkg4" in conf.packages


@pytest.mark.parametrize(
    "op,version", itertools.product(
        ["", "==", "<", ">", "<=", ">="],
        [122, 123, 124],
    )
)
def test_match_imageversion(op: str, version: str) -> None:
    opfunc = {
        "==": operator.eq,
        "!=": operator.ne,
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
    }.get(op, operator.eq,)

    with cd_temp_dir():
        parent = Path("mkosi.conf")
        parent.write_text(
            dedent(
                """\
                [Distribution]
                ImageId=testimage
                ImageVersion=123
                """
            )
        )

        Path("mkosi.conf.d").mkdir()
        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            dedent(
                f"""\
                [Match]
                ImageVersion={op}{version}

                [Content]
                Packages=testpkg1
                """
            )
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            dedent(
                f"""\
                [Match]
                ImageVersion=<200 {op}{version}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            dedent(
                f"""\
                [Match]
                ImageVersion=>9000 {op}{version}

                [Content]
                Packages=testpkg3
                """
            )
        )

        conf = parse([])
        assert ("testpkg1" in conf.packages) == opfunc(123, version)
        assert ("testpkg2" in conf.packages) == opfunc(123, version)
        assert "testpkg3" not in conf.packages
