# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.config import Compression, OutputFormat, parse_config, parse_ini
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

    with chdir(tmp_path):
        _, [config] = parse_config()

    assert config.distribution == Distribution.ubuntu
    assert config.architecture == Architecture.arm64
    assert config.packages == ["abc"]
    assert config.output_format == OutputFormat.cpio
    assert config.image_id == "base"

    with chdir(tmp_path):
        _, [config] = parse_config(["--distribution", "fedora", "--architecture", "x86-64"])

    # mkosi.conf sets a default distribution, so the CLI should take priority.
    assert config.distribution == Distribution.fedora
    # mkosi.conf sets overrides the architecture, so whatever is specified on the CLI should be ignored.
    assert config.architecture == Architecture.arm64

    d = d / "mkosi.conf.d"
    d.mkdir()

    (d / "d1.conf").write_text(
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

    with chdir(tmp_path):
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

    (tmp_path / "mkosi.version").write_text("1.2.3")

    (d / "d2.conf").write_text(
        """\
        [Content]
        Packages=
        """
    )

    with chdir(tmp_path):
        _, [config] = parse_config()

    # Test that empty string resets the list.
    assert config.packages == []
    # mkosi.version should only be used if no version is set explicitly.
    assert config.image_version == "0"

    (d / "d1.conf").unlink()

    with chdir(tmp_path):
        _, [config] = parse_config()

    # ImageVersion= is not set explicitly anymore, so now the version from mkosi.version should be used.
    assert config.image_version == "1.2.3"
