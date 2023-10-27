# SPDX-License-Identifier: LGPL-2.1+

import argparse
import itertools
import logging
import operator
import os
from pathlib import Path
from typing import Optional

import pytest

from mkosi.architecture import Architecture
from mkosi.config import (
    Compression,
    ConfigFeature,
    MkosiConfig,
    OutputFormat,
    Verb,
    config_parse_bytes,
    parse_config,
    parse_ini,
)
from mkosi.distributions import Distribution
from mkosi.util import chdir


def test_compression_enum_creation() -> None:
    assert Compression("none") == Compression.none
    assert Compression("zst") == Compression.zst
    assert Compression("xz") == Compression.xz
    assert Compression("bz2") == Compression.bz2
    assert Compression("gz") == Compression.gz
    assert Compression("lz4") == Compression.lz4
    assert Compression("lzma") == Compression.lzma


def test_compression_enum_bool() -> None:
    assert not bool(Compression.none)
    assert bool(Compression.zst)
    assert bool(Compression.xz)
    assert bool(Compression.bz2)
    assert bool(Compression.gz)
    assert bool(Compression.lz4)
    assert bool(Compression.lzma)


def test_compression_enum_str() -> None:
    assert str(Compression.none) == "none"
    assert str(Compression.zst)  == "zst"
    assert str(Compression.xz)   == "xz"
    assert str(Compression.bz2)  == "bz2"
    assert str(Compression.gz)   == "gz"
    assert str(Compression.lz4)  == "lz4"
    assert str(Compression.lzma) == "lzma"


def test_parse_ini(tmp_path: Path) -> None:
    p = tmp_path / "ini"
    p.write_text(
        """\
        [MySection]
        Value=abc
        Other=def
        ALLCAPS=txt

        # Comment
        ; Another comment
        [EmptySection]
        [AnotherSection]
        EmptyValue=
        Multiline=abc
                    def
                    qed
                    ord
        """
    )

    g = parse_ini(p)

    assert next(g) == ("MySection", "Value", "abc")
    assert next(g) == ("MySection", "Other", "def")
    assert next(g) == ("MySection", "ALLCAPS", "txt")
    assert next(g) == ("AnotherSection", "EmptyValue", "")
    assert next(g) == ("AnotherSection", "Multiline", "abc\ndef\nqed\nord")


def test_parse_config(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Distribution]

        @Distribution = ubuntu
        Architecture  = arm64

        [Content]
        Packages=abc

        [Output]
        @Format = cpio
        ImageId = base
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    assert config.distribution == Distribution.ubuntu
    assert config.architecture == Architecture.arm64
    assert config.packages == ["abc"]
    assert config.output_format == OutputFormat.cpio
    assert config.image_id == "base"

    with chdir(d):
        _, [config] = parse_config(["--distribution", "fedora"])

    # mkosi.conf sets a default distribution, so the CLI should take priority.
    assert config.distribution == Distribution.fedora

    # Any architecture set on the CLI is overridden by the config file, and we should complain loudly about that.
    with chdir(d), pytest.raises(SystemExit):
        _, [config] = parse_config(["--architecture", "x86-64"])

    (d / "mkosi.conf.d").mkdir()
    (d / "mkosi.conf.d/d1.conf").write_text(
        """\
        [Distribution]
        Distribution = debian
        @Architecture = x86-64

        [Content]
        Packages = qed
                   def

        [Output]
        ImageId = 00-dropin
        ImageVersion = 0
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    # Setting a value explicitly in a dropin should override the default from mkosi.conf.
    assert config.distribution == Distribution.debian
    # Setting a default in a dropin should be ignored since mkosi.conf sets the architecture explicitly.
    assert config.architecture == Architecture.arm64
    # Lists should be merged by appending the new values to the existing values.
    assert config.packages == ["abc", "qed", "def"]
    assert config.output_format == OutputFormat.cpio
    assert config.image_id == "00-dropin"
    assert config.image_version == "0"

    (d / "mkosi.version").write_text("1.2.3")

    (d / "mkosi.conf.d/d2.conf").write_text(
        """\
        [Content]
        Packages=

        [Output]
        ImageId=
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    # Test that empty assignment resets settings.
    assert config.packages == []
    assert config.image_id is None
    # mkosi.version should only be used if no version is set explicitly.
    assert config.image_version == "0"

    (d / "mkosi.conf.d/d1.conf").unlink()

    with chdir(d):
        _, [config] = parse_config()

    # ImageVersion= is not set explicitly anymore, so now the version from mkosi.version should be used.
    assert config.image_version == "1.2.3"

    (d / "abc").mkdir()
    (d / "abc/mkosi.conf").write_text(
        """\
        [Content]
        Bootable=yes
        BuildPackages=abc
        """
    )
    (d / "abc/mkosi.conf.d").mkdir()
    (d / "abc/mkosi.conf.d/abc.conf").write_text(
        """\
        [Output]
        SplitArtifacts=yes
        """
    )

    with chdir(d):
        _, [config] = parse_config()
        assert config.bootable == ConfigFeature.auto
        assert config.split_artifacts is False

        # Passing the directory should include both the main config file and the dropin.
        _, [config] = parse_config(["--include", os.fspath(d / "abc")] * 2)
        assert config.bootable == ConfigFeature.enabled
        assert config.split_artifacts is True
        # The same extra config should not be parsed more than once.
        assert config.build_packages == ["abc"]

        # Passing the main config file should not include the dropin.
        _, [config] = parse_config(["--include", os.fspath(d / "abc/mkosi.conf")])
        assert config.bootable == ConfigFeature.enabled
        assert config.split_artifacts is False


def test_profiles(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.profiles").mkdir()
    (d / "mkosi.profiles/profile.conf").write_text(
        """\
        [Distribution]
        Distribution=fedora

        [Host]
        QemuKvm=yes
        """
    )

    (d / "mkosi.conf").write_text(
        """\
        [Config]
        Profile=profile
        """
    )

    (d / "mkosi.conf.d").mkdir()
    (d / "mkosi.conf.d/abc.conf").write_text(
        """\
        [Distribution]
        Distribution=debian
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    assert config.profile == "profile"
    # mkosi.conf.d/ should override the profile
    assert config.distribution == Distribution.debian
    assert config.qemu_kvm == ConfigFeature.enabled


def test_override_default(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Host]
        @ToolsTree=default
        """
    )

    with chdir(d):
        _, [config] = parse_config(["--tools-tree", ""])

    assert config.tools_tree is None


def test_local_config(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.local.conf").write_text(
        """\
        [Distribution]
        Distribution=debian
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    assert config.distribution == Distribution.debian

    (d / "mkosi.conf").write_text(
        """\
        [Distribution]
        Distribution=fedora
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    assert config.distribution == Distribution.fedora


def test_parse_load_verb(tmp_path: Path) -> None:
    with chdir(tmp_path):
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


def test_os_distribution(tmp_path: Path) -> None:
    with chdir(tmp_path):
        for dist in Distribution:
            _, [config] = parse_config(["-d", dist.value])
            assert config.distribution == dist

        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse_config(["-d", "invalidDistro"])
        with pytest.raises(tuple((argparse.ArgumentError, SystemExit))):
            parse_config(["-d"])

        for dist in Distribution:
            Path("mkosi.conf").write_text(f"[Distribution]\nDistribution={dist}")
            _, [config] = parse_config()
            assert config.distribution == dist


def test_parse_config_files_filter(tmp_path: Path) -> None:
    with chdir(tmp_path):
        confd = Path("mkosi.conf.d")
        confd.mkdir()

        (confd / "10-file.conf").write_text("[Content]\nPackages=yes")
        (confd / "20-file.noconf").write_text("[Content]\nPackages=nope")

        _, [config] = parse_config()
        assert config.packages == ["yes"]


def test_compression(tmp_path: Path) -> None:
    with chdir(tmp_path):
        _, [config] = parse_config(["--format", "disk", "--compress-output", "False"])
        assert config.compress_output == Compression.none


@pytest.mark.parametrize("dist1,dist2", itertools.combinations_with_replacement(Distribution, 2))
def test_match_distribution(tmp_path: Path, dist1: Distribution, dist2: Distribution) -> None:
    with chdir(tmp_path):
        parent = Path("mkosi.conf")
        parent.write_text(
            f"""\
            [Distribution]
            Distribution={dist1}
            """
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            f"""\
            [Match]
            Distribution={dist1}

            [Content]
            Packages=testpkg1
            """
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            f"""\
            [Match]
            Distribution={dist2}

            [Content]
            Packages=testpkg2
            """
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            f"""\
            [Match]
            Distribution=|{dist1}
            Distribution=|{dist2}

            [Content]
            Packages=testpkg3
            """
        )

        _, [conf] = parse_config()
        assert "testpkg1" in conf.packages
        if dist1 == dist2:
            assert "testpkg2" in conf.packages
        else:
            assert "testpkg2" not in conf.packages
        assert "testpkg3" in conf.packages


@pytest.mark.parametrize(
    "release1,release2", itertools.combinations_with_replacement([36, 37, 38], 2)
)
def test_match_release(tmp_path: Path, release1: int, release2: int) -> None:
    with chdir(tmp_path):
        parent = Path("mkosi.conf")
        parent.write_text(
            f"""\
            [Distribution]
            Distribution=fedora
            Release={release1}
            """
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            f"""\
            [Match]
            Release={release1}

            [Content]
            Packages=testpkg1
            """
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            f"""\
            [Match]
            Release={release2}

            [Content]
            Packages=testpkg2
            """
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            f"""\
            [Match]
            Release=|{release1}
            Release=|{release2}

            [Content]
            Packages=testpkg3
            """
        )

        _, [conf] = parse_config()
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
def test_match_imageid(tmp_path: Path, image1: str, image2: str) -> None:
    with chdir(tmp_path):
        parent = Path("mkosi.conf")
        parent.write_text(
            f"""\
            [Distribution]
            Distribution=fedora

            [Output]
            ImageId={image1}
            """
        )

        Path("mkosi.conf.d").mkdir()

        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            f"""\
            [Match]
            ImageId={image1}

            [Content]
            Packages=testpkg1
            """
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            f"""\
            [Match]
            ImageId={image2}

            [Content]
            Packages=testpkg2
            """
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            f"""\
            [Match]
            ImageId=|{image1}
            ImageId=|{image2}

            [Content]
            Packages=testpkg3
            """
        )
        child4 = Path("mkosi.conf.d/child4.conf")
        child4.write_text(
            """\
            [Match]
            ImageId=image*

            [Content]
            Packages=testpkg4
            """
        )

        _, [conf] = parse_config()
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
def test_match_imageversion(tmp_path: Path, op: str, version: str) -> None:
    opfunc = {
        "==": operator.eq,
        "!=": operator.ne,
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
    }.get(op, operator.eq,)

    with chdir(tmp_path):
        parent = Path("mkosi.conf")
        parent.write_text(
            """\
            [Output]
            ImageId=testimage
            ImageVersion=123
            """
        )

        Path("mkosi.conf.d").mkdir()
        child1 = Path("mkosi.conf.d/child1.conf")
        child1.write_text(
            f"""\
            [Match]
            ImageVersion={op}{version}

            [Content]
            Packages=testpkg1
            """
        )
        child2 = Path("mkosi.conf.d/child2.conf")
        child2.write_text(
            f"""\
            [Match]
            ImageVersion=<200
            ImageVersion={op}{version}

            [Content]
            Packages=testpkg2
            """
        )
        child3 = Path("mkosi.conf.d/child3.conf")
        child3.write_text(
            f"""\
            [Match]
            ImageVersion=>9000
            ImageVersion={op}{version}

            [Content]
            Packages=testpkg3
            """
        )

        _, [conf] = parse_config()
        assert ("testpkg1" in conf.packages) == opfunc(123, version)
        assert ("testpkg2" in conf.packages) == opfunc(123, version)
        assert "testpkg3" not in conf.packages


@pytest.mark.parametrize(
    "skel,pkgmngr", itertools.product(
        [None, Path("/foo"), Path("/bar")],
        [None, Path("/foo"), Path("/bar")],
    )
)
def test_package_manager_tree(tmp_path: Path, skel: Optional[Path], pkgmngr: Optional[Path]) -> None:
    with chdir(tmp_path):
        config = Path("mkosi.conf")
        with config.open("w") as f:
            f.write("[Content]\n")
            if skel is not None:
                f.write(f"SkeletonTrees={skel}\n")
            if pkgmngr is not None:
                f.write(f"PackageManagerTrees={pkgmngr}\n")

        _, [conf] = parse_config()

        skel_expected = [(skel, None)] if skel is not None else []
        pkgmngr_expected = [(pkgmngr, None)] if pkgmngr is not None else skel_expected

        assert conf.skeleton_trees == skel_expected
        assert conf.package_manager_trees == pkgmngr_expected


@pytest.mark.parametrize(
    "sections,args,warning_count",
    [
        (["Output"], [], 0),
        (["Content"], [], 1),
        (["Content", "Output"], [], 1),
        (["Output", "Content"], [], 1),
        (["Output", "Content", "Distribution"], [], 2),
        (["Content"], ["--image-id=testimage"], 1),
    ],
)
def test_wrong_section_warning(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    sections: list[str],
    args: list[str],
    warning_count: int,
) -> None:
    with chdir(tmp_path):
        # Create a config with ImageId in the wrong section,
        # and sometimes in the correct section
        Path("mkosi.conf").write_text(
            "\n".join(
                f"""\
                [{section}]
                ImageId=testimage
                """
                for section in sections
            )
        )

        with caplog.at_level(logging.WARNING):
            # Parse the config, with --image-id sometimes given on the command line
            parse_config(args)

        assert len(caplog.records) == warning_count


def test_config_parse_bytes() -> None:
    assert config_parse_bytes(None) is None
    assert config_parse_bytes("1") == 4096
    assert config_parse_bytes("8000") == 8192
    assert config_parse_bytes("8K") == 8192
    assert config_parse_bytes("4097") == 8192
    assert config_parse_bytes("1M") == 1024**2
    assert config_parse_bytes("1.9M") == 1994752
    assert config_parse_bytes("1G") == 1024**3
    assert config_parse_bytes("7.3G") == 7838318592

    with pytest.raises(SystemExit):
        config_parse_bytes("-1")
    with pytest.raises(SystemExit):
        config_parse_bytes("-2K")
    with pytest.raises(SystemExit):
        config_parse_bytes("-3M")
    with pytest.raises(SystemExit):
        config_parse_bytes("-4G")


def test_specifiers(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Distribution]
        Distribution=ubuntu
        Release=lunar
        Architecture=arm64

        [Output]
        ImageId=my-image-id
        ImageVersion=1.2.3
        OutputDirectory=abcde
        Output=test

        [Content]
        Environment=Distribution=%d
                    Release=%r
                    Architecture=%a
                    ImageId=%i
                    ImageVersion=%v
                    OutputDirectory=%O
                    Output=%o
        """
    )

    with chdir(d):
        _, [config] = parse_config()

        expected = {
            "Distribution": "ubuntu",
            "Release": "lunar",
            "Architecture": "arm64",
            "ImageId": "my-image-id",
            "ImageVersion": "1.2.3",
            "OutputDirectory": str(Path.cwd() / "abcde"),
            "Output": "test",
        }

        assert {k: v for k, v in config.environment.items() if k in expected} == expected


def test_deterministic() -> None:
    assert MkosiConfig.default() == MkosiConfig.default()
