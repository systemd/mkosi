# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import contextlib
import itertools
import logging
import operator
import os
import tempfile
from pathlib import Path
from typing import cast

import barrage.assertions as Assert

import mkosi.resources
from mkosi import expand_kernel_specifiers
from mkosi.config import (
    Architecture,
    ArtifactOutput,
    Compression,
    Config,
    ConfigFeature,
    ConfigTree,
    OutputFormat,
    Verb,
    config_parse_bytes,
    in_box,
    parse_config,
    parse_ini,
)
from mkosi.distribution import Distribution, detect_distribution
from mkosi.util import chdir, resource_path


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def tmp_dir(stack: contextlib.AsyncExitStack) -> Path:
    return Path(stack.enter_context(tempfile.TemporaryDirectory()))


async def test_compression_enum_creation() -> None:
    Assert.eq(Compression["none"], Compression.none)
    Assert.eq(Compression["zstd"], Compression.zstd)
    Assert.eq(Compression["zst"], Compression.zstd)
    Assert.eq(Compression["xz"], Compression.xz)
    Assert.eq(Compression["bz2"], Compression.bz2)
    Assert.eq(Compression["gz"], Compression.gz)
    Assert.eq(Compression["lz4"], Compression.lz4)
    Assert.eq(Compression["lzma"], Compression.lzma)


async def test_compression_enum_bool() -> None:
    Assert.false(bool(Compression.none))
    Assert.true(bool(Compression.zstd))
    Assert.true(bool(Compression.xz))
    Assert.true(bool(Compression.bz2))
    Assert.true(bool(Compression.gz))
    Assert.true(bool(Compression.lz4))
    Assert.true(bool(Compression.lzma))


async def test_compression_enum_str() -> None:
    Assert.eq(str(Compression.none), "none")
    Assert.eq(str(Compression.zstd), "zstd")
    Assert.eq(str(Compression.zst), "zstd")
    Assert.eq(str(Compression.xz), "xz")
    Assert.eq(str(Compression.bz2), "bz2")
    Assert.eq(str(Compression.gz), "gz")
    Assert.eq(str(Compression.lz4), "lz4")
    Assert.eq(str(Compression.lzma), "lzma")


async def test_parse_ini(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    p = tmp_path / "ini"
    p.write_text(
        """\
        [MySection]
        Value=abc
        Other=def
        ALLCAPS=txt

        # Comment
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

    Assert.eq(next(g), ("MySection", "Value", "abc"))
    Assert.eq(next(g), ("MySection", "Other", "def"))
    Assert.eq(next(g), ("MySection", "ALLCAPS", "txt"))
    Assert.eq(next(g), ("MySection", "", ""))
    Assert.eq(next(g), ("EmptySection", "", ""))
    Assert.eq(next(g), ("AnotherSection", "EmptyValue", ""))
    Assert.eq(next(g), ("AnotherSection", "Multiline", "abc\ndef\nqed\nord"))


async def test_parse_config(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Distribution]
        Distribution=ubuntu
        Architecture=arm64
        Repositories=epel,epel-next

        [Config]
        Profiles=abc

        [Build]
        Environment=MY_KEY=MY_VALUE

        [Output]
        Format=cpio
        ImageId=base

        [Runtime]
        Credentials=my.cred=my.value
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.distribution, Distribution.ubuntu)
    Assert.eq(config.architecture, Architecture.arm64)
    Assert.eq(config.profiles, ["abc"])
    Assert.eq(config.output_format, OutputFormat.cpio)
    Assert.eq(config.image_id, "base")

    with chdir(d):
        _, _, [config] = parse_config(
            [
                "--distribution", "fedora",
                "--environment", "MY_KEY=CLI_VALUE",
                "--credential", "my.cred=cli.value",
                "--repositories", "universe",
            ]
        )  # fmt: skip

    # Values from the CLI should take priority.
    Assert.eq(config.distribution, Distribution.fedora)
    Assert.eq(config.environment["MY_KEY"], "CLI_VALUE")
    Assert.true(any(c.name == "my.cred" and c.value == "cli.value" for c in config.credentials))
    Assert.eq(config.repositories, ["epel", "epel-next", "universe"])

    with chdir(d):
        _, _, [config] = parse_config(
            [
                "--distribution", "",
                "--environment", "",
                "--credential", "",
                "--repositories", "",
            ]
        )  # fmt: skip

    # Empty values on the CLIs resets non-collection based settings to their defaults and collection
    # based settings to empty collections.
    Assert.not_in("MY_KEY", config.environment)
    Assert.false(any(c.name == "my.cred" for c in config.credentials))
    Assert.eq(config.repositories, [])

    (d / "mkosi.conf.d").mkdir()
    (d / "mkosi.conf.d/d1.conf").write_text(
        """\
        [Distribution]
        Distribution=debian

        [Config]
        Profiles=qed
                 def

        [Output]
        ImageId=00-dropin
        ImageVersion=0
        @Output=abc
        """
    )

    with chdir(d):
        _, _, [config] = parse_config(["--profile", "last"])

    # Setting a value explicitly in a dropin should override the default from mkosi.conf.
    Assert.eq(config.distribution, Distribution.debian)
    # Lists should be merged by appending the new values to the existing values. Any values from the CLI
    # should be appended to the values from the configuration files.
    Assert.eq(config.profiles, ["abc", "qed", "def", "last"])
    Assert.eq(config.output_format, OutputFormat.cpio)
    Assert.eq(config.image_id, "00-dropin")
    Assert.eq(config.image_version, "0")
    # '@' specifier should be automatically dropped.
    Assert.eq(config.output, "abc")

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
        _, _, [config] = parse_config()

    # Test that empty assignment resets settings.
    Assert.eq(config.packages, [])
    Assert.none(config.image_id)
    # mkosi.version should only be used if no version is set explicitly.
    Assert.eq(config.image_version, "0")

    (d / "mkosi.conf.d/d1.conf").unlink()

    with chdir(d):
        _, _, [config] = parse_config()

    # ImageVersion= is not set explicitly anymore, so now the version from mkosi.version should be used.
    Assert.eq(config.image_version, "1.2.3")

    (d / "abc").mkdir()
    (d / "abc/mkosi.conf").write_text(
        """\
        [Content]
        BuildPackages=abc

        [Runtime]
        CXL=yes
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
        _, _, [config] = parse_config()
        Assert.false(config.cxl)
        Assert.eq(config.split_artifacts, ArtifactOutput.compat_no())

        # Passing the directory should include both the main config file and the dropin.
        _, _, [config] = parse_config(["--include", os.fspath(d / "abc")] * 2)
        Assert.true(config.cxl)
        Assert.eq(config.split_artifacts, ArtifactOutput.compat_yes())
        # The same extra config should not be parsed more than once.
        Assert.eq(config.build_packages, ["abc"])

        # Passing the main config file should not include the dropin.
        _, _, [config] = parse_config(["--include", os.fspath(d / "abc/mkosi.conf")])
        Assert.true(config.cxl)
        Assert.eq(config.split_artifacts, ArtifactOutput.compat_no())

    (d / "mkosi.images").mkdir()

    (d / "mkosi.images/one.conf").write_text(
        """\
        [Content]
        Packages=one
        """
    )

    (d / "mkosi.images/two").mkdir()
    (d / "mkosi.images/two/mkosi.skeleton").mkdir()
    (d / "mkosi.images/two/mkosi.conf").write_text(
        """
        [Content]
        Packages=two

        [Output]
        ImageVersion=4.5.6
        """
    )

    with chdir(d):
        _, _, [one, two, config] = parse_config(
            ["--package", "qed", "--build-package", "def", "--repositories", "cli"]
        )

    # Universal settings should always come from the main image.
    Assert.eq(one.distribution, config.distribution)
    Assert.eq(two.distribution, config.distribution)
    Assert.eq(one.release, config.release)
    Assert.eq(two.release, config.release)

    # Non-universal settings should not be passed to the subimages.
    Assert.eq(one.packages, ["one"])
    Assert.eq(two.packages, ["two"])
    Assert.eq(one.build_packages, [])
    Assert.eq(two.build_packages, [])

    # But should apply to the main image of course.
    Assert.eq(config.packages, ["qed"])
    Assert.eq(config.build_packages, ["def"])

    # Inherited settings should be passed down to subimages but overridable by subimages.
    Assert.eq(one.image_version, "1.2.3")
    Assert.eq(two.image_version, "4.5.6")

    # Default values from subimages for universal settings should not be picked up.
    Assert.eq(len(one.sandbox_trees), 0)
    Assert.eq(len(two.sandbox_trees), 0)

    with chdir(d):
        _, _, [one, two, config] = parse_config(["--image-version", "7.8.9"])

    # Inherited settings specified on the CLI should not override subimages that configure the setting
    # explicitly.
    Assert.eq(config.image_version, "7.8.9")
    Assert.eq(one.image_version, "7.8.9")
    Assert.eq(two.image_version, "4.5.6")


async def test_parse_includes_once(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Content]
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
        _, _, [config] = parse_config(["--include", "abc.conf", "--include", "abc.conf"])
        Assert.eq(config.build_packages, ["abc", "def"])

    (d / "mkosi.images").mkdir()

    for n in ("one", "two"):
        (d / "mkosi.images" / f"{n}.conf").write_text(
            """\
            [Config]
            Include=abc.conf
            """
        )

    with chdir(d):
        _, _, [one, two, config] = parse_config([])
        Assert.eq(one.build_packages, ["def"])
        Assert.eq(two.build_packages, ["def"])


async def test_profiles(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.profiles").mkdir()
    (d / "mkosi.profiles/profile.conf").write_text(
        """\
        [Distribution]
        Distribution=fedora

        [Runtime]
        KVM=yes
        """
    )

    (d / "mkosi.conf").write_text(
        """\
        [Config]
        Profiles=profile
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
        _, _, [config] = parse_config()

    Assert.eq(config.profiles, ["profile"])
    # The profile should override mkosi.conf.d/
    Assert.eq(config.distribution, Distribution.fedora)
    Assert.eq(config.kvm, ConfigFeature.enabled)

    (d / "mkosi.conf").unlink()

    with chdir(d):
        _, _, [config] = parse_config(["--profile", "profile"])

    Assert.eq(config.profiles, ["profile"])
    # The profile should override mkosi.conf.d/
    Assert.eq(config.distribution, Distribution.fedora)
    Assert.eq(config.kvm, ConfigFeature.enabled)

    (d / "mkosi.conf").write_text(
        """\
        [Config]
        Profiles=profile,abc
        """
    )

    (d / "mkosi.profiles/abc.conf").write_text(
        """\
        [Match]
        Profiles=abc

        [Distribution]
        Distribution=opensuse
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.profiles, ["profile", "abc"])
    Assert.eq(config.distribution, Distribution.opensuse)

    # Check that mkosi.profiles/ is parsed in subimages as well.
    (d / "mkosi.images/subimage/mkosi.profiles").mkdir(parents=True)
    (d / "mkosi.images/subimage/mkosi.profiles/abc.conf").write_text(
        """
        [Build]
        Environment=Image=%I
        """
    )

    with chdir(d):
        _, _, [subimage, config] = parse_config()

    Assert.eq(subimage.environment["Image"], "subimage")


async def test_override_default(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Build]
        Environment=MY_KEY=MY_VALUE
        ToolsTree=yes
        """
    )

    with chdir(d):
        _, _, [config] = parse_config(["--tools-tree", "", "--environment", ""])

    Assert.none(config.tools_tree)
    Assert.not_in("MY_KEY", config.environment)

    (d / "mkosi.tools.conf").touch()

    (d / "mkosi.local.conf").write_text(
        """\
        [Build]
        ToolsTree=
        """
    )

    with chdir(d):
        _, _, [config] = parse_config([])

    Assert.none(config.tools_tree)


async def test_local_config(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.local.conf").write_text(
        """\
        [Distribution]
        Distribution=debian

        [Content]
        WithTests=yes
        Environment=FOO=override
        Environment=BAZ=normal
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.distribution, Distribution.debian)

    (d / "mkosi.conf").write_text(
        """\
        [Distribution]
        Distribution=fedora

        [Content]
        WithTests=no
        Environment=FOO=normal
        Environment=BAR=normal
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    # Local config should take precedence over non-local config.
    Assert.eq(config.distribution, Distribution.debian)
    Assert.true(config.with_tests)

    with chdir(d):
        _, _, [config] = parse_config(["--distribution", "fedora", "-T"])

    Assert.eq(config.distribution, Distribution.fedora)
    Assert.false(config.with_tests)

    (d / "mkosi.local/mkosi.conf.d").mkdir(parents=True)
    (d / "mkosi.local/mkosi.conf.d/10-test.conf").write_text(
        """\
        [Content]
        Environment=BAR=override
        Environment=BAZ=override
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.environment, {"FOO": "override", "BAR": "override", "BAZ": "override"})


async def test_parse_load_verb(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    with chdir(tmp_path):
        Assert.eq(parse_config(["build"])[0].verb, Verb.build)
        Assert.eq(parse_config(["clean"])[0].verb, Verb.clean)
        Assert.eq(parse_config(["genkey"])[0].verb, Verb.genkey)
        Assert.eq(parse_config(["bump"])[0].verb, Verb.bump)
        Assert.eq(parse_config(["serve"])[0].verb, Verb.serve)
        Assert.eq(parse_config(["build"])[0].verb, Verb.build)
        Assert.eq(parse_config(["shell"])[0].verb, Verb.shell)
        Assert.eq(parse_config(["boot"])[0].verb, Verb.boot)
        Assert.eq(parse_config(["qemu"])[0].verb, Verb.qemu)
        Assert.eq(parse_config(["vm"])[0].verb, Verb.vm)
        Assert.eq(parse_config(["journalctl"])[0].verb, Verb.journalctl)
        Assert.eq(parse_config(["coredumpctl"])[0].verb, Verb.coredumpctl)
        with Assert.raises(SystemExit):
            parse_config(["invalid"])


async def test_os_distribution(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    with chdir(tmp_path):
        for dist in Distribution:
            _, _, [config] = parse_config(["-d", dist.value])
            Assert.eq(config.distribution, dist)

        with Assert.raises((argparse.ArgumentError, SystemExit)):  # type: ignore[arg-type]
            parse_config(["-d", "invalidDistro"])
        with Assert.raises((argparse.ArgumentError, SystemExit)):  # type: ignore[arg-type]
            parse_config(["-d"])

        for dist in Distribution:
            Path("mkosi.conf").write_text(f"[Distribution]\nDistribution={dist}")
            _, _, [config] = parse_config()
            Assert.eq(config.distribution, dist)


async def test_parse_config_files_filter(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    with chdir(tmp_path):
        confd = Path("mkosi.conf.d")
        confd.mkdir()

        (confd / "10-file.conf").write_text("[Content]\nPackages=yes")
        (confd / "20-file.noconf").write_text("[Content]\nPackages=nope")

        _, _, [config] = parse_config()
        Assert.eq(config.packages, ["yes"])


async def test_compression(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    with chdir(tmp_path):
        _, _, [config] = parse_config(["--format", "disk", "--compress-output", "False"])
        Assert.eq(config.compress_output, Compression.none)


async def test_match_only(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
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

        _, _, [config] = parse_config(["--format", "tar"])
        Assert.ne(config.image_id, "abcde")


async def test_match_multiple(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
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
        _, _, [config] = parse_config(["--format", "tar", "--architecture", "s390x"])
        Assert.ne(config.image_id, "abcde")

        # Only a single section is matched, so image ID should not be "abcde".
        _, _, [config] = parse_config(["--format", "disk", "--architecture", "s390x"])
        Assert.ne(config.image_id, "abcde")

        # Both sections are matched, so image ID should be "abcde".
        _, _, [config] = parse_config(["--format", "disk", "--architecture", "x86-64"])
        Assert.eq(config.image_id, "abcde")

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
        _, _, [config] = parse_config(["--format", "tar", "--architecture", "s390x"])
        Assert.ne(config.image_id, "abcde")

        # The first section is matched, so image ID should be "abcde".
        _, _, [config] = parse_config(["--format", "disk", "--architecture", "x86-64"])
        Assert.eq(config.image_id, "abcde")

        # The second section is matched, so image ID should be "abcde".
        _, _, [config] = parse_config(["--format", "directory", "--architecture", "arm64"])
        Assert.eq(config.image_id, "abcde")

        # Parts of all section are matched, but none is matched fully, so image ID should not be "abcde".
        _, _, [config] = parse_config(["--format", "disk", "--architecture", "arm64"])
        Assert.ne(config.image_id, "abcde")

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
        _, _, [config] = parse_config(["--format", "disk"])
        Assert.eq(config.image_id, "abcde")

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
        _, _, [config] = parse_config(["--format", "disk", "--architecture=arm64"])
        Assert.ne(config.image_id, "abcde")

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
        _, _, [config] = parse_config(["--format", "disk", "--architecture=arm64"])
        Assert.eq(config.image_id, "abcde")

        # Match section matches, but no TriggerMatch section matches
        _, _, [config] = parse_config(["--format", "disk", "--architecture=s390x"])
        Assert.ne(config.image_id, "abcde")

        # Second TriggerMatch section matches, but the Match section does not
        _, _, [config] = parse_config(["--format", "tar", "--architecture=x86-64"])
        Assert.ne(config.image_id, "abcde")


async def test_match_empty(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    with chdir(tmp_path):
        Path("mkosi.conf").write_text(
            """\
            [Match]
            Profiles=

            [Build]
            Environment=ABC=QED
            """
        )

        _, _, [config] = parse_config([])

        Assert.eq(config.environment.get("ABC"), "QED")

        _, _, [config] = parse_config(["--profile", "profile"])

        Assert.none(config.environment.get("ABC"))


async def test_match_distribution(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    for dist1, dist2 in itertools.combinations_with_replacement(
        [Distribution.debian, Distribution.opensuse], 2
    ):
        with chdir(tmp_path):
            parent = Path("mkosi.conf")
            parent.write_text(
                f"""\
                [Distribution]
                Distribution={dist1}
                """
            )

            confd = Path("mkosi.conf.d")
            if not confd.exists():
                confd.mkdir()

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

            _, _, [conf] = parse_config()
            Assert.in_("testpkg1", conf.packages)
            if dist1 == dist2:
                Assert.in_("testpkg2", conf.packages)
            else:
                Assert.not_in("testpkg2", conf.packages)
            Assert.in_("testpkg3", conf.packages)


async def test_match_release(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    for release1, release2 in itertools.combinations_with_replacement([36, 37], 2):
        with chdir(tmp_path):
            parent = Path("mkosi.conf")
            parent.write_text(
                f"""\
                [Distribution]
                Distribution=fedora
                Release={release1}
                """
            )

            confd = Path("mkosi.conf.d")
            if not confd.exists():
                confd.mkdir()

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

            _, _, [conf] = parse_config()
            Assert.in_("testpkg1", conf.packages)
            if release1 == release2:
                Assert.in_("testpkg2", conf.packages)
            else:
                Assert.not_in("testpkg2", conf.packages)
            Assert.in_("testpkg3", conf.packages)


async def test_match_build_sources(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
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
        _, _, [config] = parse_config(["--build-sources", ".:kernel"])

    Assert.eq(config.output, "abc")


async def test_match_repositories(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
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
        _, _, [config] = parse_config(["--repositories", "epel,epel-next"])

    Assert.eq(config.output, "qed")


async def test_match_architecture(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Match]
        Architecture=uefi

        [Content]
        Output=qed
        """
    )

    with chdir(d):
        _, _, [config] = parse_config(["--architecture", "arm64"])

    Assert.eq(config.output, "qed")


async def test_match_imageid(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    for image1, image2 in itertools.combinations_with_replacement(["image_a", "image_b"], 2):
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

            confd = Path("mkosi.conf.d")
            if not confd.exists():
                confd.mkdir()

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

            _, _, [conf] = parse_config()
            Assert.in_("testpkg1", conf.packages)
            if image1 == image2:
                Assert.in_("testpkg2", conf.packages)
            else:
                Assert.not_in("testpkg2", conf.packages)
            Assert.in_("testpkg3", conf.packages)
            Assert.in_("testpkg4", conf.packages)


async def test_match_imageversion(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    for op, version in itertools.product(
        ["", "==", "<", ">", "<=", ">="],
        [122, 123],
    ):
        opfunc = {
            "==": operator.eq,
            "!=": operator.ne,
            "<": operator.lt,
            "<=": operator.le,
            ">": operator.gt,
            ">=": operator.ge,
        }.get(op, operator.eq)

        with chdir(tmp_path):
            parent = Path("mkosi.conf")
            parent.write_text(
                """\
                [Output]
                ImageId=testimage
                ImageVersion=123
                """
            )

            confd = Path("mkosi.conf.d")
            if not confd.exists():
                confd.mkdir()
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

            _, _, [conf] = parse_config()
            Assert.eq(("testpkg1" in conf.packages), opfunc(123, version))
            Assert.eq(("testpkg2" in conf.packages), opfunc(123, version))
            Assert.not_in("testpkg3", conf.packages)


async def test_match_environment(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
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
        _, _, [conf] = parse_config(["--environment", "MYENV=abc"])
        Assert.eq(conf.image_id, "matched")
        _, _, [conf] = parse_config(["--environment", "MYENV=bad"])
        Assert.ne(conf.image_id, "matched")
        _, _, [conf] = parse_config(["--environment", "MYEN=abc"])
        Assert.ne(conf.image_id, "matched")
        _, _, [conf] = parse_config(["--environment", "MYEN=bad"])
        Assert.ne(conf.image_id, "matched")

    (d / "mkosi.conf").write_text(
        """\
        [Match]
        Environment=MYENV

        [Content]
        ImageId=matched
        """
    )

    with chdir(d):
        _, _, [conf] = parse_config(["--environment", "MYENV=abc"])
        Assert.eq(conf.image_id, "matched")
        _, _, [conf] = parse_config(["--environment", "MYENV=bad"])
        Assert.eq(conf.image_id, "matched")
        _, _, [conf] = parse_config(["--environment", "MYEN=abc"])
        Assert.ne(conf.image_id, "matched")


async def test_paths_with_default_factory(stack: contextlib.AsyncExitStack) -> None:
    """
    If both paths= and default_factory= are defined, default_factory= should not
    be used when at least one of the files/directories from paths= has been found.
    """

    tmp_path = tmp_dir(stack)
    with chdir(tmp_path):
        Path("mkosi.sandbox.tar").touch()
        _, _, [config] = parse_config()

        Assert.eq(
            config.sandbox_trees,
            [
                ConfigTree(Path.cwd() / "mkosi.sandbox.tar", None),
            ],
        )


async def test_glob_expansion(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "script_a.sh").touch()
    (d / "script_b.sh").touch()
    (d / "script_c.sh").touch()
    (d / "other.py").touch()

    # Glob patterns should be expanded and results should be sorted.
    (d / "mkosi.conf").write_text(
        f"""\
        [Content]
        PrepareScripts={d}/script_*.sh
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.prepare_scripts, [d / "script_a.sh", d / "script_b.sh", d / "script_c.sh"])

    # Glob patterns that match nothing should result in an empty list.
    (d / "mkosi.conf").write_text(
        f"""\
        [Content]
        PrepareScripts={d}/nonexistent_*.sh
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.prepare_scripts, [])

    # Non-glob paths should be ordered before glob results when listed first.
    (d / "mkosi.conf").write_text(
        f"""\
        [Content]
        PrepareScripts={d}/other.py,{d}/script_*.sh
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(
        config.prepare_scripts,
        [
            d / "other.py",
            d / "script_a.sh",
            d / "script_b.sh",
            d / "script_c.sh",
        ],
    )

    # Glob expansion should work with other script options too.
    (d / "mkosi.conf").write_text(
        f"""\
        [Content]
        BuildScripts={d}/script_*.sh
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.build_scripts, [d / "script_a.sh", d / "script_b.sh", d / "script_c.sh"])


async def test_wrong_section_warning(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    for sections, args, warning_count in [
        (["Output"], [], 0),
        (["Content"], [], 1),
        (["Content", "Output"], [], 1),
        (["Output", "Content"], [], 1),
        (["Output", "Content", "Distribution"], [], 2),
        (["Content"], ["--image-id=testimage"], 1),
    ]:
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

            handler = _ListHandler()
            logger = logging.getLogger()
            prev_level = logger.level
            logger.addHandler(handler)
            logger.setLevel(logging.WARNING)
            try:
                # Parse the config, with --image-id sometimes given on the command line
                parse_config(args)
            finally:
                logger.removeHandler(handler)
                logger.setLevel(prev_level)

            Assert.eq(len(handler.records), warning_count)


async def test_config_parse_bytes() -> None:
    Assert.none(config_parse_bytes(None))
    Assert.eq(config_parse_bytes("1"), 4096)
    Assert.eq(config_parse_bytes("8000"), 8192)
    Assert.eq(config_parse_bytes("8K"), 8192)
    Assert.eq(config_parse_bytes("4097"), 8192)
    Assert.eq(config_parse_bytes("1M"), 1024**2)
    Assert.eq(config_parse_bytes("1.9M"), 1994752)
    Assert.eq(config_parse_bytes("1G"), 1024**3)
    Assert.eq(config_parse_bytes("7.3G"), 7838318592)

    with Assert.raises(SystemExit):
        config_parse_bytes("-1")
    with Assert.raises(SystemExit):
        config_parse_bytes("-2K")
    with Assert.raises(SystemExit):
        config_parse_bytes("-3M")
    with Assert.raises(SystemExit):
        config_parse_bytes("-4G")


async def test_specifiers(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
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

        [Build]
        Environment=Distribution=%d
                    Release=%r
                    Architecture=%a
                    Image=%I
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
        [Build]
        Environment=ConfigAbcDirectory=%D
                    ConfigAbcConfdir=%C
                    ConfigAbcPwd=%P
        """
    )
    (d / "mkosi.conf.d/qed").mkdir()
    (d / "mkosi.conf.d/qed/mkosi.conf").write_text(
        """
        [Build]
        Environment=ConfigQedDirectory=%D
                    ConfigQedConfdir=%C
                    ConfigQedPwd=%P
        """
    )

    (d / "mkosi.images").mkdir()
    (d / "mkosi.images/subimage.conf").write_text(
        """
        [Build]
        Environment=Image=%I
        """
    )

    with chdir(d):
        _, _, [subimage, config] = parse_config()

        expected = {
            "Distribution": "ubuntu",
            "Release": "lunar",
            "Architecture": "arm64",
            "Image": "main",
            "ImageId": "my-image-id",
            "ImageVersion": "1.2.3",
            "OutputDirectory": os.fspath(Path.cwd() / "abcde"),
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

        Assert.eq({k: v for k, v in config.environment.items() if k in expected}, expected)

        Assert.eq(subimage.environment["Image"], "subimage")


async def test_kernel_specifiers() -> None:
    kver = "13.0.8-5.10.0-1057-oem"  # taken from reporter of #1638
    token = "MySystemImage"
    roothash = "67e893261799236dcf20529115ba9fae4fd7c2269e1e658d42269503e5760d38"

    def test_expand_kernel_specifiers(text: str) -> str:
        return expand_kernel_specifiers(
            text,
            kver=kver,
            token=token,
            roothash=roothash,
        )

    Assert.eq(test_expand_kernel_specifiers("&&"), "&")
    Assert.eq(test_expand_kernel_specifiers("&k"), kver)
    Assert.eq(test_expand_kernel_specifiers("&e"), token)
    Assert.eq(test_expand_kernel_specifiers("&h"), roothash)

    Assert.eq(test_expand_kernel_specifiers("Image_1.0.3"), "Image_1.0.3")
    Assert.eq(test_expand_kernel_specifiers("Image+&h-&k-&e"), f"Image+{roothash}-{kver}-{token}")


async def test_output_id_version(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """
        [Output]
        ImageId=output
        ImageVersion=1.2.3
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

    Assert.eq(config.output, "output_1.2.3")


async def test_deterministic() -> None:
    Assert.eq(Config.default(), Config.default())


async def test_environment(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Config]
        PassEnvironment=PassThisEnv

        [Build]
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
        _, _, [sub, config] = parse_config()

        expected = {
            "TestValue1": "100",  # from other.env
            "TestValue2": "300",  # from mkosi.conf
            "TestValue3": "400",  # from mkosi.conf
            "TestValue4": "99",  # from mkosi.env
        }

        # Only check values for keys from expected, as config.environment contains other items as well
        Assert.eq({k: config.finalize_environment()[k] for k in expected.keys()}, expected)

        Assert.eq(config.environment_files, [Path.cwd() / "mkosi.env", Path.cwd() / "other.env"])

        Assert.eq(sub.environment["PassThisEnv"], "abc")
        Assert.not_in("TestValue2", sub.environment)


async def test_proxy(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    # Verify environment variables are set correctly when GIT_CONFIG_COUNT is not set
    (d / "mkosi.conf").write_text(
        """\
        [Build]
        ProxyUrl=http://proxy:8080
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

        expected = {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "http.proxy",
            "GIT_CONFIG_VALUE_0": "http://proxy:8080",
            "GIT_CONFIG_KEY_1": "https.proxy",
            "GIT_CONFIG_VALUE_1": "http://proxy:8080",
        }

        # Only check values for keys from expected, as config.environment contains other items as well
        Assert.eq({k: config.finalize_environment()[k] for k in expected.keys()}, expected)

    (d / "mkosi.conf").write_text(
        """\
        [Build]
        ProxyUrl=http://proxy:8080
        Environment=GIT_CONFIG_COUNT=1
                    GIT_CONFIG_KEY_0=user.name
                    GIT_CONFIG_VALUE_0=bob
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()

        expected = {
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "user.name",
            "GIT_CONFIG_VALUE_0": "bob",
            "GIT_CONFIG_KEY_1": "http.proxy",
            "GIT_CONFIG_VALUE_1": "http://proxy:8080",
            "GIT_CONFIG_KEY_2": "https.proxy",
            "GIT_CONFIG_VALUE_2": "http://proxy:8080",
        }

        # Only check values for keys from expected, as config.environment contains other items as well
        Assert.eq({k: config.finalize_environment()[k] for k in expected.keys()}, expected)


async def test_mkosi_version_executable(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    version = d / "mkosi.version"
    version.write_text("#!/bin/sh\necho '1.2.3'\n")

    with chdir(d):
        with Assert.raises(SystemExit) as error:
            _, _, [config] = parse_config()

        Assert.is_(error.exception.__class__, SystemExit)
        Assert.ne(error.exception.code, 0)

    version.chmod(0o755)

    with chdir(d):
        _, _, [config] = parse_config()
        Assert.eq(config.image_version, "1.2.3")


async def test_split_artifacts(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """
        [Output]
        SplitArtifacts=uki
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()
        Assert.eq(config.split_artifacts, [ArtifactOutput.uki])

    (d / "mkosi.conf").write_text(
        """
        [Output]
        SplitArtifacts=uki
        SplitArtifacts=kernel
        SplitArtifacts=initrd
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()
        Assert.eq(
            config.split_artifacts,
            [
                ArtifactOutput.uki,
                ArtifactOutput.kernel,
                ArtifactOutput.initrd,
            ],
        )


async def test_split_artifacts_compat(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    with chdir(d):
        _, _, [config] = parse_config()
        Assert.eq(config.split_artifacts, ArtifactOutput.compat_no())

    (d / "mkosi.conf").write_text(
        """
        [Output]
        SplitArtifacts=yes
        """
    )

    with chdir(d):
        _, _, [config] = parse_config()
        Assert.eq(config.split_artifacts, ArtifactOutput.compat_yes())


async def test_cli_collection_reset(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """
        [Content]
        Packages=abc
        """
    )

    with chdir(d):
        _, _, [config] = parse_config(["--package", ""])
        Assert.eq(config.packages, [])

        _, _, [config] = parse_config(["--package", "", "--package", "foo"])
        Assert.eq(config.packages, ["foo"])

        _, _, [config] = parse_config(["--package", "foo", "--package", "", "--package", "bar"])
        Assert.eq(config.packages, ["bar"])

        _, _, [config] = parse_config(["--package", "foo", "--package", ""])
        Assert.eq(config.packages, [])


async def test_tools(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path
    argv = ["--tools-tree=default"]

    if in_box():
        Assert.skip("Cannot run test_tools() test within mkosi box environment")

    with resource_path(mkosi.resources) as resources, chdir(d):
        _, tools, _ = parse_config(argv, resources=resources)
        Assert.not_none(tools)
        tools = cast(Config, tools)
        host = detect_distribution()[0]
        if isinstance(host, Distribution):
            Assert.eq(
                tools.distribution,
                (host.installer.default_tools_tree_distribution() or tools.distribution),
            )

        (d / "mkosi.tools.conf").write_text(
            f"""
            [Content]
            PackageDirectories={d}
            """
        )

        _, tools, _ = parse_config(argv, resources=resources)
        Assert.not_none(tools)
        tools = cast(Config, tools)
        Assert.eq(tools.package_directories, [Path(d)])

        _, tools, _ = parse_config(
            argv + ["--tools-tree-distribution=arch", "--tools-tree-package-directory=/tmp"],
            resources=resources,
        )
        Assert.not_none(tools)
        tools = cast(Config, tools)
        Assert.eq(tools.distribution, Distribution.arch)
        Assert.eq(tools.package_directories, [Path(d), Path("/tmp")])

        _, tools, _ = parse_config(argv + ["--tools-tree-package-directory="], resources=resources)
        Assert.not_none(tools)
        tools = cast(Config, tools)
        Assert.eq(tools.package_directories, [])

        (d / "mkosi.conf").write_text(
            """
            [Build]
            ToolsTreeDistribution=arch
            """
        )

        _, tools, _ = parse_config(argv, resources=resources)
        Assert.not_none(tools)
        tools = cast(Config, tools)
        Assert.eq(tools.distribution, Distribution.arch)


async def test_subdir(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    with chdir(d):
        (d / "mkosi").mkdir()
        (d / "mkosi/mkosi.conf").write_text(
            """
            [Output]
            Output=qed
            """
        )

        _, _, [config] = parse_config()
        Assert.eq(config.output, "qed")

        os.chdir(d)

        (d / "mkosi.conf").write_text(
            """
            [Output]
            Output=abc
            """
        )

        _, _, [config] = parse_config()
        Assert.eq(config.output, "abc")


async def test_assert(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    with chdir(d):
        (d / "mkosi.conf").write_text(
            """
            [Assert]
            ImageId=abcde
            """
        )

        with Assert.raises(SystemExit):
            parse_config()

        # Does not raise, i.e. parses successfully, but we don't care for the content.
        parse_config(["--image-id", "abcde"])

        (d / "mkosi.conf").write_text(
            """
            [Assert]
            ImageId=abcde

            [Assert]
            Environment=ABC=QED
            """
        )

        with Assert.raises(SystemExit):
            parse_config([])
        with Assert.raises(SystemExit):
            parse_config(["--image-id", "abcde"])
        with Assert.raises(SystemExit):
            parse_config(["--environment", "ABC=QED"])

        parse_config(["--image-id", "abcde", "--environment", "ABC=QED"])

        (d / "mkosi.conf").write_text(
            """
            [TriggerAssert]
            ImageId=abcde

            [TriggerAssert]
            Environment=ABC=QED
            """
        )

        with Assert.raises(SystemExit):
            parse_config()

        parse_config(["--image-id", "abcde"])
        parse_config(["--environment", "ABC=QED"])

        (d / "mkosi.conf").write_text(
            """
            [Assert]
            ImageId=abcde

            [TriggerAssert]
            Environment=ABC=QED

            [TriggerAssert]
            Environment=DEF=QEE
            """
        )

        with Assert.raises(SystemExit):
            parse_config()

        parse_config(["--image-id", "abcde", "--environment", "ABC=QED"])
        parse_config(["--image-id", "abcde", "--environment", "DEF=QEE"])


async def test_initrd_packages(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "mkosi.conf").write_text(
        """\
        [Content]
        InitrdPackages=package1
        InitrdPackages=package2

        [Content]
        Bootable=yes
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [initrd, _] = parse_config(resources=resources)

    Assert.in_("package1", initrd.packages)
    Assert.in_("package2", initrd.packages)

    # Make sure the InitrdPackages= are also picked up when a subimage is defined.
    (d / "mkosi.images").mkdir()
    (d / "mkosi.images/subimage.conf").touch()

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [_, initrd, _] = parse_config(resources=resources)

    Assert.in_("package1", initrd.packages)
    Assert.in_("package2", initrd.packages)


async def test_config_default_initrds(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    # Default initrd should be built when Bootable=yes and the image format supports it.
    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Bootable=yes
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [initrd, main] = parse_config(resources=resources)

    Assert.eq(len(main.initrds), 1)
    Assert.eq(initrd.image, "default-initrd")

    # Default initrd should not be built when Bootable=disabled.
    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Bootable=disabled
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.false(config.initrds)

    # Default initrd should not be built for UKI output format.
    (d / "mkosi.conf").write_text(
        """\
        [Output]
        Format=uki

        [Content]
        Bootable=yes
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.false(config.initrds)

    # Default initrd should not be built for ESP output format.
    (d / "mkosi.conf").write_text(
        """\
        [Output]
        Format=esp

        [Content]
        Bootable=yes
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.false(config.initrds)

    # Default initrd should not be built when Bootable=auto and output is cpio.
    (d / "mkosi.conf").write_text(
        """\
        [Output]
        Format=cpio
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.false(config.initrds)

    # Default initrd should not be built when Bootable=auto and output is a sysext image.
    (d / "mkosi.conf").write_text(
        """\
        [Output]
        Format=sysext
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.false(config.initrds)

    # Default initrd should not be built when Overlay=yes.
    (d / "mkosi.conf").write_text(
        """\
        [Output]
        Overlay=yes
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.false(config.initrds)


async def test_initrds_default_value(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    # The "default" special value should explicitly request the default initrd.
    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Bootable=yes
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [initrd, main] = parse_config(resources=resources)

    Assert.eq(len(main.initrds), 1)
    Assert.eq(initrd.image, "default-initrd")

    (d / "myinitrd.cpio").touch()

    # When a custom initrd is specified along with "default", both should be included.
    (d / "mkosi.conf").write_text(
        f"""\
        [Content]
        Bootable=yes
        Initrds={d / "myinitrd.cpio"}
        Initrds=default
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [initrd, main] = parse_config(resources=resources)

    # The main image should have two initrds: the custom one and the default one (resolved path).
    Assert.eq(len(main.initrds), 2)
    Assert.eq(main.initrds[0], d / "myinitrd.cpio")
    # Second initrd should be the resolved path from the default initrd image.
    Assert.eq(initrd.image, "default-initrd")

    # When only "default" is specified, the default initrd should be built.
    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Bootable=yes
        Initrds=default
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [initrd, main] = parse_config(resources=resources)

    Assert.eq(len(main.initrds), 1)
    Assert.eq(initrd.image, "default-initrd")


async def test_initrds_empty_resets(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    # An empty value for Initrds= should disable the default initrd.
    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Bootable=yes
        Initrds=
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    # Empty string should reset to empty, not to default.
    Assert.false(config.initrds)

    # Make sure dropin can override with empty to disable default initrd.
    (d / "mkosi.conf").write_text(
        """\
        [Content]
        Bootable=yes
        """
    )

    (d / "mkosi.conf.d").mkdir()
    (d / "mkosi.conf.d/no-initrd.conf").write_text(
        """\
        [Content]
        Initrds=
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.false(config.initrds)


async def test_initrds_custom_only(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "myinitrd.cpio").touch()

    # When only a custom initrd is specified (no "default"), only that initrd should be used.
    (d / "mkosi.conf").write_text(
        f"""\
        [Content]
        Bootable=yes
        Initrds={d / "myinitrd.cpio"}
        """
    )

    with chdir(d), resource_path(mkosi.resources) as resources:
        _, _, [config] = parse_config(resources=resources)

    Assert.eq(len(config.initrds), 1)
    Assert.eq(config.initrds[0], d / "myinitrd.cpio")


async def test_history_empty_list(stack: contextlib.AsyncExitStack) -> None:
    tmp_path = tmp_dir(stack)
    d = tmp_path

    (d / "packages").mkdir()

    (d / "mkosi.conf").write_text(
        """\
        [Build]
        History=yes

        [Content]
        PackageDirectories=packages
        """
    )

    with chdir(d):
        _, _, [main] = parse_config(["--package-directory=", "build"])

    Assert.true((d / ".mkosi-private/history/latest.json").exists())
    Assert.eq(main.package_directories, [])

    with chdir(d):
        _, _, [main] = parse_config(["summary"])

    Assert.eq(main.package_directories, [])
