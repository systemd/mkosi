# SPDX-License-Identifier: LGPL-2.1+

import argparse
import itertools
import operator
import tempfile
from pathlib import Path
import textwrap
from typing import Optional

import pytest

from mkosi.config import Compression, Verb, parse_config
from mkosi.distributions import Distribution
from mkosi.util import chdir


def test_parse_load_verb() -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        assert parse_config(["build"])[0].verb == Verb.build
        assert parse_config(["clean"])[0].verb == Verb.clean
        with pytest.raises(SystemExit):
            parse_config(["help"])
        assert parse_config(["genkey"])[0].verb == Verb.genkey
        assert parse_config(["bump"])[0].verb == Verb.bump
        assert parse_config(["serve"])[0].verb == Verb.serve
        assert parse_config(["build"])[0].verb == Verb.build
        assert parse_config(["shell"])[0].verb == Verb.shell
        assert parse_config(["boot"])[0].verb == Verb.boot
        assert parse_config(["qemu"])[0].verb == Verb.qemu
        with pytest.raises(SystemExit):
            parse_config(["invalid"])


def test_os_distribution() -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        for dist in Distribution:
            assert parse_config(["-d", dist.name])[1][0].distribution == dist

        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse_config(["-d", "invalidDistro"])
        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse_config(["-d"])

        for dist in Distribution:
            config = Path("mkosi.conf")
            config.write_text(f"[Distribution]\nDistribution={dist}")
            assert parse_config([])[1][0].distribution == dist


def test_parse_config_files_filter() -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        confd = Path("mkosi.conf.d")
        confd.mkdir()

        (confd / "10-file.conf").write_text("[Content]\nPackages=yes")
        (confd / "20-file.noconf").write_text("[Content]\nPackages=nope")

        assert parse_config([])[1][0].packages == ["yes"]


def test_compression() -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        assert parse_config(["--format", "disk", "--compress-output", "False"])[1][0].compress_output == Compression.none


@pytest.mark.parametrize("dist1,dist2", itertools.combinations_with_replacement(Distribution, 2))
def test_match_distribution(dist1: Distribution, dist2: Distribution) -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        parent = Path("mkosi.conf")
        parent.write_text(
            textwrap.dedent(
                f"""\
                [Distribution]
                Distribution={dist1}
                """
            )
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            textwrap.dedent(
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
            textwrap.dedent(
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
            textwrap.dedent(
                f"""\
                [Match]
                Distribution=|{dist1}
                Distribution=|{dist2}

                [Content]
                Packages=testpkg3
                """
            )
        )

        conf = parse_config([])[1][0]
        assert "testpkg1" in conf.packages
        if dist1 == dist2:
            assert "testpkg2" in conf.packages
        else:
            assert "testpkg2" not in conf.packages
        assert "testpkg3" in conf.packages


@pytest.mark.parametrize(
    "release1,release2", itertools.combinations_with_replacement([36, 37, 38], 2)
)
def test_match_release(release1: int, release2: int) -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        parent = Path("mkosi.conf")
        parent.write_text(
            textwrap.dedent(
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
            textwrap.dedent(
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
            textwrap.dedent(
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
            textwrap.dedent(
                f"""\
                [Match]
                Release=|{release1}
                Release=|{release2}

                [Content]
                Packages=testpkg3
                """
            )
        )

        conf = parse_config([])[1][0]
        assert "testpkg1" in conf.packages
        if release1 == release2:
            assert "testpkg2" in conf.packages
        else:
            assert "testpkg2" not in conf.packages
        assert "testpkg3" in conf.packages


@pytest.mark.parametrize(
    "image1,image2", itertools.combinations_with_replacement(
        ["image_a", "image_b", "image_c"], 2
    )
)
def test_match_imageid(image1: str, image2: str) -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        parent = Path("mkosi.conf")
        parent.write_text(
            textwrap.dedent(
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
            textwrap.dedent(
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
            textwrap.dedent(
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
            textwrap.dedent(
                f"""\
                [Match]
                ImageId=|{image1}
                ImageId=|{image2}

                [Content]
                Packages=testpkg3
                """
            )
        )
        child4 = Path("mkosi.conf.d/child4.conf")
        child4.write_text(
            textwrap.dedent(
                """\
                [Match]
                ImageId=image*

                [Content]
                Packages=testpkg4
                """
            )
        )

        conf = parse_config([])[1][0]
        assert "testpkg1" in conf.packages
        if image1 == image2:
            assert "testpkg2" in conf.packages
        else:
            assert "testpkg2" not in conf.packages
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

    with tempfile.TemporaryDirectory() as d, chdir(d):
        parent = Path("mkosi.conf")
        parent.write_text(
            textwrap.dedent(
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
            textwrap.dedent(
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
            textwrap.dedent(
                f"""\
                [Match]
                ImageVersion=<200
                ImageVersion={op}{version}

                [Content]
                Packages=testpkg2
                """
            )
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            textwrap.dedent(
                f"""\
                [Match]
                ImageVersion=>9000
                ImageVersion={op}{version}

                [Content]
                Packages=testpkg3
                """
            )
        )

        conf = parse_config([])[1][0]
        assert ("testpkg1" in conf.packages) == opfunc(123, version)
        assert ("testpkg2" in conf.packages) == opfunc(123, version)
        assert "testpkg3" not in conf.packages


@pytest.mark.parametrize(
    "skel,pkgmngr", itertools.product(
        [None, Path("/foo"), Path("/bar")],
        [None, Path("/foo"), Path("/bar")],
    )
)
def test_package_manager_tree(skel: Optional[Path], pkgmngr: Optional[Path]) -> None:
    with tempfile.TemporaryDirectory() as d, chdir(d):
        config = Path("mkosi.conf")
        with config.open("w") as f:
            f.write("[Content]\n")
            if skel is not None:
                f.write(f"SkeletonTrees={skel}\n")
            if pkgmngr is not None:
                f.write(f"PackageManagerTrees={pkgmngr}\n")

        conf = parse_config([])[1][0]

        skel_expected = [(skel, None)] if skel is not None else []
        pkgmngr_expected = [(pkgmngr, None)] if pkgmngr is not None else skel_expected

        assert conf.skeleton_trees == skel_expected
        assert conf.package_manager_trees == pkgmngr_expected
