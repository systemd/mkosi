# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import itertools
import logging
import operator
import os
from pathlib import Path
from typing import Optional

import pytest

from mkosi import expand_kernel_specifiers
from mkosi.config import (
    Architecture,
    Compression,
    Config,
    ConfigFeature,
    ConfigTree,
    OutputFormat,
    Verb,
    config_parse_bytes,
    parse_config,
    parse_ini,
)
from mkosi.distributions import Distribution, detect_distribution
from mkosi.util import chdir


def test_compression_enum_creation() -> None:
    assert Compression["none"] == Compression.none
    assert Compression["zstd"] == Compression.zstd
    assert Compression["zst"] == Compression.zstd
    assert Compression["xz"] == Compression.xz
    assert Compression["bz2"] == Compression.bz2
    assert Compression["gz"] == Compression.gz
    assert Compression["lz4"] == Compression.lz4
    assert Compression["lzma"] == Compression.lzma


def test_compression_enum_bool() -> None:
    assert not bool(Compression.none)
    assert bool(Compression.zstd)
    assert bool(Compression.xz)
    assert bool(Compression.bz2)
    assert bool(Compression.gz)
    assert bool(Compression.lz4)
    assert bool(Compression.lzma)


def test_compression_enum_str() -> None:
    assert str(Compression.none) == "none"
    assert str(Compression.zstd) == "zstd"
    assert str(Compression.zst)  == "zstd"
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
    assert next(g) == ("MySection", "", "")
    assert next(g) == ("EmptySection", "", "")
    assert next(g) == ("AnotherSection", "EmptyValue", "")
    assert next(g) == ("AnotherSection", "Multiline", "abc\ndef\nqed\nord")


def test_parse_config(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Distribution]
        Distribution=ubuntu
        Architecture=arm64
        Repositories=epel,epel-next

        [Content]
        Packages=abc
        Environment=MY_KEY=MY_VALUE

        [Output]
        Format=cpio
        ImageId=base

        [Host]
        Credentials=my.cred=my.value
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
        _, [config] = parse_config(
            [
                "--distribution", "fedora",
                "--environment", "MY_KEY=CLI_VALUE",
                "--credential", "my.cred=cli.value",
                "--repositories", "universe",
            ]
        )

    # Values from the CLI should take priority.
    assert config.distribution == Distribution.fedora
    assert config.environment["MY_KEY"] == "CLI_VALUE"
    assert config.credentials["my.cred"] == "cli.value"
    assert config.repositories == ["epel", "epel-next", "universe"]

    with chdir(d):
        _, [config] = parse_config(
            [
                "--distribution", "",
                "--environment", "",
                "--credential", "",
                "--repositories", "",
            ]
        )

    # Empty values on the CLIs resets non-collection based settings to their defaults and collection based settings to
    # empty collections.
    assert config.distribution == (detect_distribution()[0] or Distribution.custom)
    assert "MY_KEY" not in config.environment
    assert "my.cred" not in config.credentials
    assert config.repositories == []

    (d / "mkosi.conf.d").mkdir()
    (d / "mkosi.conf.d/d1.conf").write_text(
        """\
        [Distribution]
        Distribution=debian

        [Content]
        Packages=qed
                 def

        [Output]
        ImageId=00-dropin
        ImageVersion=0
        @Output=abc
        """
    )

    with chdir(d):
        _, [config] = parse_config(["--package", "last"])

    # Setting a value explicitly in a dropin should override the default from mkosi.conf.
    assert config.distribution == Distribution.debian
    # Lists should be merged by appending the new values to the existing values. Any values from the CLI should be
    # appended to the values from the configuration files.
    assert config.packages == ["abc", "qed", "def", "last"]
    assert config.output_format == OutputFormat.cpio
    assert config.image_id == "00-dropin"
    assert config.image_version == "0"
    # '@' specifier should be automatically dropped.
    assert config.output == "abc"

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

    (d / "mkosi.images").mkdir()

    for n in ("one", "two"):
        (d / "mkosi.images" / f"{n}.conf").write_text(
            f"""\
            [Distribution]
            Repositories=append

            [Content]
            Packages={n}
            """
        )

    with (d / "mkosi.images" / "two.conf").open("a") as f:
        f.write(
            """
            [Output]
            ImageVersion=4.5.6
            """
        )

    with chdir(d):
        _, [one, two, config] = parse_config(["--package", "qed", "--build-package", "def", "--repositories", "cli"])

    # Universal settings should always come from the main image.
    assert one.distribution == config.distribution
    assert two.distribution == config.distribution
    assert one.release == config.release
    assert two.release == config.release

    # Non-universal settings should not be passed to the subimages.
    assert one.packages == ["one"]
    assert two.packages == ["two"]
    assert one.build_packages == []
    assert two.build_packages == []

    # But should apply to the main image of course.
    assert config.packages == ["qed"]
    assert config.build_packages == ["def"]

    # list based settings should be appended to in subimages
    assert one.repositories == ["append", "epel", "epel-next", "cli"]
    assert two.repositories == ["append", "epel", "epel-next", "cli"]

    # Inherited settings should be passed down to subimages but overridable by subimages.
    assert one.image_version == "1.2.3"
    assert two.image_version == "4.5.6"

    with chdir(d):
        _, [one, two, config] = parse_config(["--image-version", "7.8.9"])

    # Inherited settings specified on the CLI should not override subimages that configure the setting explicitly.
    assert config.image_version == "7.8.9"
    assert one.image_version == "7.8.9"
    assert two.image_version == "4.5.6"


def test_parse_includes_once(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Bootable=yes
        BuildPackages=abc
        """
    )
    (d / "abc.conf").write_text(
        """\
        [Content]
        BuildPackages=def
        """
    )

    with chdir(d):
        _, [config] = parse_config(["--include", "abc.conf", "--include", "abc.conf"])
        assert config.build_packages == ["def", "abc"]

    (d / "mkosi.images").mkdir()

    for n in ("one", "two"):
        (d / "mkosi.images" / f"{n}.conf").write_text(
            """\
            [Config]
            Include=abc.conf
            """
        )

    with chdir(d):
        _, [one, two, config] = parse_config([])
        assert one.build_packages == ["def"]
        assert two.build_packages == ["def"]


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

    (d / "mkosi.conf").unlink()

    with chdir(d):
        _, [config] = parse_config(["--profile", "profile"])

    assert config.profile == "profile"
    # mkosi.conf.d/ should override the profile
    assert config.distribution == Distribution.debian
    assert config.qemu_kvm == ConfigFeature.enabled


def test_override_default(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Environment=MY_KEY=MY_VALUE

        [Host]
        ToolsTree=default
        """
    )

    with chdir(d):
        _, [config] = parse_config(["--tools-tree", "", "--environment", ""])

    assert config.tools_tree is None
    assert "MY_KEY" not in config.environment


def test_local_config(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.local.conf").write_text(
        """\
        [Distribution]
        Distribution=debian

        [Content]
        WithTests=yes
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    assert config.distribution == Distribution.debian

    (d / "mkosi.conf").write_text(
        """\
        [Distribution]
        Distribution=fedora

        [Content]
        WithTests=no
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    # Local config should take precedence over non-local config.
    assert config.distribution == Distribution.debian
    assert config.with_tests

    with chdir(d):
        _, [config] = parse_config(["--distribution", "fedora", "-T"])

    assert config.distribution == Distribution.fedora
    assert not config.with_tests


def test_parse_load_verb(tmp_path: Path) -> None:
    with chdir(tmp_path):
        assert parse_config(["build"])[0].verb == Verb.build
        assert parse_config(["clean"])[0].verb == Verb.clean
        assert parse_config(["genkey"])[0].verb == Verb.genkey
        assert parse_config(["bump"])[0].verb == Verb.bump
        assert parse_config(["serve"])[0].verb == Verb.serve
        assert parse_config(["build"])[0].verb == Verb.build
        assert parse_config(["shell"])[0].verb == Verb.shell
        assert parse_config(["boot"])[0].verb == Verb.boot
        assert parse_config(["qemu"])[0].verb == Verb.qemu
        assert parse_config(["journalctl"])[0].verb == Verb.journalctl
        assert parse_config(["coredumpctl"])[0].verb == Verb.coredumpctl
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


def test_match_only(tmp_path: Path) -> None:
    with chdir(tmp_path):
        Path("mkosi.conf").write_text(
            """\
            [Match]
            Format=|directory
            Format=|disk
            """
        )

        Path("mkosi.conf.d").mkdir()
        Path("mkosi.conf.d/10-abc.conf").write_text(
            """\
            [Output]
            ImageId=abcde
            """
        )

        _, [config] = parse_config(["--format", "tar"])
        assert config.image_id != "abcde"


def test_match_multiple(tmp_path: Path) -> None:
    with chdir(tmp_path):
        Path("mkosi.conf").write_text(
            """\
            [Match]
            Format=|disk
            Format=|directory

            [Match]
            Architecture=|x86-64
            Architecture=|arm64

            [Output]
            ImageId=abcde
            """
        )

        # Both sections are not matched, so image ID should not be "abcde".
        _, [config] = parse_config(["--format", "tar", "--architecture", "s390x"])
        assert config.image_id != "abcde"

        # Only a single section is matched, so image ID should not be "abcde".
        _, [config] = parse_config(["--format", "disk", "--architecture", "s390x"])
        assert config.image_id != "abcde"

        # Both sections are matched, so image ID should be "abcde".
        _, [config] = parse_config(["--format", "disk", "--architecture", "x86-64"])
        assert config.image_id == "abcde"

        Path("mkosi.conf").write_text(
            """\
            [TriggerMatch]
            Format=disk
            Architecture=x86-64

            [TriggerMatch]
            Format=directory
            Architecture=arm64

            [Output]
            ImageId=abcde
            """
        )

        # Both sections are not matched, so image ID should not be "abcde".
        _, [config] = parse_config(["--format", "tar", "--architecture", "s390x"])
        assert config.image_id != "abcde"

        # The first section is matched, so image ID should be "abcde".
        _, [config] = parse_config(["--format", "disk", "--architecture", "x86-64"])
        assert config.image_id == "abcde"

        # The second section is matched, so image ID should be "abcde".
        _, [config] = parse_config(["--format", "directory", "--architecture", "arm64"])
        assert config.image_id == "abcde"

        # Parts of all section are matched, but none is matched fully, so image ID should not be "abcde".
        _, [config] = parse_config(["--format", "disk", "--architecture", "arm64"])
        assert config.image_id != "abcde"

        Path("mkosi.conf").write_text(
            """\
            [TriggerMatch]
            Format=|disk
            Format=|directory

            [TriggerMatch]
            Format=directory
            Architecture=arm64

            [Output]
            ImageId=abcde
            """
        )

        # The first section is matched, so image ID should be "abcde".
        _, [config] = parse_config(["--format", "disk"])
        assert config.image_id == "abcde"

        Path("mkosi.conf").write_text(
            """\
            [TriggerMatch]
            Format=|disk
            Format=|directory
            Architecture=x86-64

            [TriggerMatch]
            Format=directory
            Architecture=arm64

            [Output]
            ImageId=abcde
            """
        )

        # No sections are matched, so image ID should be not "abcde".
        _, [config] = parse_config(["--format", "disk", "--architecture=arm64"])
        assert config.image_id != "abcde"

        # Mixing both [Match] and [TriggerMatch]
        Path("mkosi.conf").write_text(
            """\
            [Match]
            Format=disk

            [TriggerMatch]
            Architecture=arm64

            [TriggerMatch]
            Architecture=x86-64

            [Output]
            ImageId=abcde
            """
        )

        # Match and first TriggerMatch sections match
        _, [config] = parse_config(["--format", "disk", "--architecture=arm64"])
        assert config.image_id == "abcde"

        # Match section matches, but no TriggerMatch section matches
        _, [config] = parse_config(["--format", "disk", "--architecture=s390x"])
        assert config.image_id != "abcde"

        # Second TriggerMatch section matches, but the Match section does not
        _, [config] = parse_config(["--format", "tar", "--architecture=x86-64"])
        assert config.image_id != "abcde"


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


def test_match_build_sources(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Match]
        BuildSources=kernel
        BuildSources=/kernel

        [Output]
        Output=abc
        """
    )

    with chdir(d):
        _, [config] = parse_config(["--build-sources", ".:kernel"])

    assert config.output == "abc"


def test_match_repositories(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Match]
        Repositories=epel

        [Content]
        Output=qed
        """
    )

    with chdir(d):
        _, [config] = parse_config(["--repositories", "epel,epel-next"])

    assert config.output == "qed"


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


def test_match_environment(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Match]
        Environment=MYENV=abc

        [Content]
        ImageId=matched
        """
    )

    with chdir(d):
        _, [conf] = parse_config(["--environment", "MYENV=abc"])
        assert conf.image_id == "matched"
        _, [conf] = parse_config(["--environment", "MYENV=abd"])
        assert conf.image_id != "matched"
        _, [conf] = parse_config(["--environment", "MYEN=abc"])
        assert conf.image_id != "matched"
        _, [conf] = parse_config(["--environment", "MYEN=abd"])
        assert conf.image_id != "matched"

    (d / "mkosi.conf").write_text(
        """\
        [Match]
        Environment=MYENV

        [Content]
        ImageId=matched
        """
    )

    with chdir(d):
        _, [conf] = parse_config(["--environment", "MYENV=abc"])
        assert conf.image_id == "matched"
        _, [conf] = parse_config(["--environment", "MYENV=abd"])
        assert conf.image_id == "matched"
        _, [conf] = parse_config(["--environment", "MYEN=abc"])
        assert conf.image_id != "matched"


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

        skel_expected = [ConfigTree(skel, None)] if skel is not None else []
        pkgmngr_expected = [ConfigTree(pkgmngr, None)] if pkgmngr is not None else skel_expected

        assert conf.skeleton_trees == skel_expected
        assert conf.package_manager_trees == pkgmngr_expected


def test_paths_with_default_factory(tmp_path: Path) -> None:
    """
    If both paths= and default_factory= are defined, default_factory= should not
    be used when at least one of the files/directories from paths= has been found.
    """

    with chdir(tmp_path):

        Path("mkosi.skeleton.tar").touch()
        _, [config] = parse_config()

        assert config.package_manager_trees == [
            ConfigTree(Path.cwd() / "mkosi.skeleton.tar", None),
        ]

        Path("mkosi.pkgmngr.tar").touch()
        _, [config] = parse_config()

        assert config.package_manager_trees == [
            ConfigTree(Path.cwd() / "mkosi.pkgmngr.tar", None),
        ]


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
                    ConfigRootDirectory=%D
                    ConfigRootConfdir=%C
                    ConfigRootPwd=%P
                    Filesystem=%F
        """
    )

    (d / "mkosi.conf.d").mkdir()
    (d / "mkosi.conf.d/abc.conf").write_text(
        """\
        [Content]
        Environment=ConfigAbcDirectory=%D
                    ConfigAbcConfdir=%C
                    ConfigAbcPwd=%P
        """
    )
    (d / "mkosi.conf.d/qed").mkdir()
    (d / "mkosi.conf.d/qed/mkosi.conf").write_text(
        """
        [Content]
        Environment=ConfigQedDirectory=%D
                    ConfigQedConfdir=%C
                    ConfigQedPwd=%P
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
            "ConfigRootDirectory": os.fspath(d),
            "ConfigRootConfdir": os.fspath(d),
            "ConfigRootPwd": os.fspath(d),
            "ConfigAbcDirectory": os.fspath(d),
            "ConfigAbcConfdir": os.fspath(d / "mkosi.conf.d"),
            "ConfigAbcPwd": os.fspath(d),
            "ConfigQedDirectory": os.fspath(d),
            "ConfigQedConfdir": os.fspath(d / "mkosi.conf.d/qed"),
            "ConfigQedPwd": os.fspath(d / "mkosi.conf.d/qed"),
            "Filesystem": "ext4",
        }

        assert {k: v for k, v in config.environment.items() if k in expected} == expected


def test_kernel_specifiers(tmp_path: Path) -> None:
    kver = "13.0.8-5.10.0-1057-oem"     # taken from reporter of #1638
    token = "MySystemImage"
    roothash = "67e893261799236dcf20529115ba9fae4fd7c2269e1e658d42269503e5760d38"
    boot_count = "3"

    def test_expand_kernel_specifiers(text: str) -> str:
        return expand_kernel_specifiers(
            text,
            kver=kver,
            token=token,
            roothash=roothash,
            boot_count=boot_count,
        )

    assert test_expand_kernel_specifiers("&&") == "&"
    assert test_expand_kernel_specifiers("&k") == kver
    assert test_expand_kernel_specifiers("&e") == token
    assert test_expand_kernel_specifiers("&h") == roothash
    assert test_expand_kernel_specifiers("&c") == boot_count

    assert test_expand_kernel_specifiers("Image_1.0.3") == "Image_1.0.3"
    assert test_expand_kernel_specifiers("Image~&c+&h-&k-&e") == f"Image~{boot_count}+{roothash}-{kver}-{token}"


def test_output_id_version(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """
        [Output]
        ImageId=output
        ImageVersion=1.2.3
        """
    )

    with chdir(d):
        _, [config] = parse_config()

    assert config.output == "output_1.2.3"


def test_deterministic() -> None:
    assert Config.default() == Config.default()


def test_environment(tmp_path: Path) -> None:
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Config]
        PassEnvironment=PassThisEnv

        [Content]
        Environment=TestValue2=300
                    TestValue3=400
                    PassThisEnv=abc
        EnvironmentFiles=other.env
        """
    )

    (d / "mkosi.env").write_text(
        """\
        TestValue1=90
        TestValue4=99
        """
    )

    (d / "other.env").write_text(
        """\
        TestValue1=100
        TestValue2=200
        """
    )

    (d / "mkosi.images").mkdir()
    (d / "mkosi.images/sub.conf").touch()

    with chdir(d):
        _, [sub, config] = parse_config()

        expected = {
            "TestValue1": "100", # from other.env
            "TestValue2": "300", # from mkosi.conf
            "TestValue3": "400", # from mkosi.conf
            "TestValue4": "99", # from mkosi.env
        }

        # Only check values for keys from expected, as config.environment contains other items as well
        assert {k: config.environment[k] for k in expected.keys()} == expected

        assert config.environment_files == [Path.cwd() / "mkosi.env", Path.cwd() / "other.env"]

        assert sub.environment["PassThisEnv"] == "abc"
        assert "TestValue2" not in sub.environment
