# SPDX-License-Identifier: LGPL-2.1-or-later

import itertools

import barrage.assertions as Assert

from mkosi.versioncomp import GenericVersion


def RPMVERCMP(a: str, b: str, expected: int) -> None:
    Assert.eq(
        (GenericVersion(a) > GenericVersion(b)) - (GenericVersion(a) < GenericVersion(b)),
        expected,
    )


async def test_conversion() -> None:
    Assert.lt(GenericVersion("1"), 2)
    Assert.lt(GenericVersion("1"), "2")
    Assert.gt(GenericVersion("2"), 1)
    Assert.gt(GenericVersion("2"), "1")
    Assert.eq(GenericVersion("1"), "1")


async def test_generic_version_systemd() -> None:
    """Same as the first block of systemd/test/test-compare-versions.sh"""
    Assert.lt(GenericVersion("1"), GenericVersion("2"))
    Assert.le(GenericVersion("1"), GenericVersion("2"))
    Assert.ne(GenericVersion("1"), GenericVersion("2"))
    Assert.false(GenericVersion("1") > GenericVersion("2"))
    Assert.false(GenericVersion("1") == GenericVersion("2"))
    Assert.false(GenericVersion("1") >= GenericVersion("2"))
    Assert.eq(GenericVersion.compare_versions("1", "2"), -1)
    Assert.eq(GenericVersion.compare_versions("2", "2"), 0)
    Assert.eq(GenericVersion.compare_versions("2", "1"), 1)


async def test_generic_version_spec() -> None:
    """Examples from the uapi group version format spec"""
    Assert.eq(GenericVersion("11"), GenericVersion("11"))
    Assert.eq(GenericVersion("systemd-123"), GenericVersion("systemd-123"))
    Assert.lt(GenericVersion("bar-123"), GenericVersion("foo-123"))
    Assert.gt(GenericVersion("123a"), GenericVersion("123"))
    Assert.gt(GenericVersion("123.a"), GenericVersion("123"))
    Assert.lt(GenericVersion("123.a"), GenericVersion("123.b"))
    Assert.gt(GenericVersion("123a"), GenericVersion("123.a"))
    Assert.eq(GenericVersion("11α"), GenericVersion("11β"))
    Assert.lt(GenericVersion("A"), GenericVersion("a"))
    Assert.lt(GenericVersion(""), GenericVersion("0"))
    Assert.gt(GenericVersion("0."), GenericVersion("0"))
    Assert.gt(GenericVersion("0.0"), GenericVersion("0"))
    Assert.gt(GenericVersion("0"), GenericVersion("~"))
    Assert.gt(GenericVersion(""), GenericVersion("~"))
    Assert.eq(GenericVersion("1_"), GenericVersion("1"))
    Assert.eq(GenericVersion("_1"), GenericVersion("1"))
    Assert.lt(GenericVersion("1_"), GenericVersion("1.2"))
    Assert.gt(GenericVersion("1_2_3"), GenericVersion("1.3.3"))
    Assert.eq(GenericVersion("1+"), GenericVersion("1"))
    Assert.eq(GenericVersion("+1"), GenericVersion("1"))
    Assert.lt(GenericVersion("1+"), GenericVersion("1.2"))
    Assert.gt(GenericVersion("1+2+3"), GenericVersion("1.3.3"))


async def test_generic_version_strverscmp_improved_doc() -> None:
    """Example from the doc string of strverscmp_improved.

    strverscmp_improved can be found in systemd/src/fundamental/string-util-fundamental.c
    """
    versions = enumerate(
        [
            GenericVersion("122.1"),
            GenericVersion("123~rc1-1"),
            GenericVersion("123"),
            GenericVersion("123-a"),
            GenericVersion("123-a.1"),
            GenericVersion("123-1"),
            GenericVersion("123-1.1"),
            GenericVersion("123^post1"),
            GenericVersion("123.a-1"),
            GenericVersion("123.1-1"),
            GenericVersion("123a-1"),
            GenericVersion("124-1"),
        ],
    )
    for s1, s2 in itertools.combinations_with_replacement(versions, 2):
        i1, v1 = s1
        i2, v2 = s2
        Assert.eq(v1 == v2, i1 == i2)
        Assert.eq(v1 < v2, i1 < i2)
        Assert.eq(v1 <= v2, i1 <= i2)
        Assert.eq(v1 > v2, i1 > i2)
        Assert.eq(v1 >= v2, i1 >= i2)
        Assert.eq(v1 != v2, i1 != i2)


async def test_generic_version_rpmvercmp() -> None:
    EQUAL = 0
    RIGHT_SMALLER = 1
    LEFT_SMALLER = -1

    # Tests copied from rpm's rpmio test suite, under the LGPL license:
    # https://github.com/rpm-software-management/rpm/blob/master/tests/rpmvercmp.at.
    # The original form is retained as much as possible for easy comparisons and updates.

    RPMVERCMP("1.0", "1.0", EQUAL)
    RPMVERCMP("1.0", "2.0", LEFT_SMALLER)
    RPMVERCMP("2.0", "1.0", RIGHT_SMALLER)

    RPMVERCMP("2.0.1", "2.0.1", EQUAL)
    RPMVERCMP("2.0", "2.0.1", LEFT_SMALLER)
    RPMVERCMP("2.0.1", "2.0", RIGHT_SMALLER)

    RPMVERCMP("2.0.1a", "2.0.1a", EQUAL)
    RPMVERCMP("2.0.1a", "2.0.1", RIGHT_SMALLER)
    RPMVERCMP("2.0.1", "2.0.1a", LEFT_SMALLER)

    RPMVERCMP("5.5p1", "5.5p1", EQUAL)
    RPMVERCMP("5.5p1", "5.5p2", LEFT_SMALLER)
    RPMVERCMP("5.5p2", "5.5p1", RIGHT_SMALLER)

    RPMVERCMP("5.5p10", "5.5p10", EQUAL)
    RPMVERCMP("5.5p1", "5.5p10", LEFT_SMALLER)
    RPMVERCMP("5.5p10", "5.5p1", RIGHT_SMALLER)

    RPMVERCMP("10xyz", "10.1xyz", RIGHT_SMALLER)  # Note: this is reversed from rpm's vercmp */
    RPMVERCMP("10.1xyz", "10xyz", LEFT_SMALLER)  # Note: this is reversed from rpm's vercmp */

    RPMVERCMP("xyz10", "xyz10", EQUAL)
    RPMVERCMP("xyz10", "xyz10.1", LEFT_SMALLER)
    RPMVERCMP("xyz10.1", "xyz10", RIGHT_SMALLER)

    RPMVERCMP("xyz.4", "xyz.4", EQUAL)
    RPMVERCMP("xyz.4", "8", LEFT_SMALLER)
    RPMVERCMP("8", "xyz.4", RIGHT_SMALLER)
    RPMVERCMP("xyz.4", "2", LEFT_SMALLER)
    RPMVERCMP("2", "xyz.4", RIGHT_SMALLER)

    RPMVERCMP("5.5p2", "5.6p1", LEFT_SMALLER)
    RPMVERCMP("5.6p1", "5.5p2", RIGHT_SMALLER)

    RPMVERCMP("5.6p1", "6.5p1", LEFT_SMALLER)
    RPMVERCMP("6.5p1", "5.6p1", RIGHT_SMALLER)

    RPMVERCMP("6.0.rc1", "6.0", RIGHT_SMALLER)
    RPMVERCMP("6.0", "6.0.rc1", LEFT_SMALLER)

    RPMVERCMP("10b2", "10a1", RIGHT_SMALLER)
    RPMVERCMP("10a2", "10b2", LEFT_SMALLER)

    RPMVERCMP("1.0aa", "1.0aa", EQUAL)
    RPMVERCMP("1.0a", "1.0aa", LEFT_SMALLER)
    RPMVERCMP("1.0aa", "1.0a", RIGHT_SMALLER)

    RPMVERCMP("10.0001", "10.0001", EQUAL)
    RPMVERCMP("10.0001", "10.1", EQUAL)
    RPMVERCMP("10.1", "10.0001", EQUAL)
    RPMVERCMP("10.0001", "10.0039", LEFT_SMALLER)
    RPMVERCMP("10.0039", "10.0001", RIGHT_SMALLER)

    RPMVERCMP("4.999.9", "5.0", LEFT_SMALLER)
    RPMVERCMP("5.0", "4.999.9", RIGHT_SMALLER)

    RPMVERCMP("20101121", "20101121", EQUAL)
    RPMVERCMP("20101121", "20101122", LEFT_SMALLER)
    RPMVERCMP("20101122", "20101121", RIGHT_SMALLER)

    RPMVERCMP("2_0", "2_0", EQUAL)
    RPMVERCMP("2.0", "2_0", LEFT_SMALLER)  # Note: in rpm those compare equal
    RPMVERCMP("2_0", "2.0", RIGHT_SMALLER)  # Note: in rpm those compare equal

    # RhBug:178798 case */
    RPMVERCMP("a", "a", EQUAL)
    RPMVERCMP("a+", "a+", EQUAL)
    RPMVERCMP("a+", "a_", EQUAL)
    RPMVERCMP("a_", "a+", EQUAL)
    RPMVERCMP("+a", "+a", EQUAL)
    RPMVERCMP("+a", "_a", EQUAL)
    RPMVERCMP("_a", "+a", EQUAL)
    RPMVERCMP("+_", "+_", EQUAL)
    RPMVERCMP("_+", "+_", EQUAL)
    RPMVERCMP("_+", "_+", EQUAL)
    RPMVERCMP("+", "_", EQUAL)
    RPMVERCMP("_", "+", EQUAL)

    # Basic testcases for tilde sorting
    RPMVERCMP("1.0~rc1", "1.0~rc1", EQUAL)
    RPMVERCMP("1.0~rc1", "1.0", LEFT_SMALLER)
    RPMVERCMP("1.0", "1.0~rc1", RIGHT_SMALLER)
    RPMVERCMP("1.0~rc1", "1.0~rc2", LEFT_SMALLER)
    RPMVERCMP("1.0~rc2", "1.0~rc1", RIGHT_SMALLER)
    RPMVERCMP("1.0~rc1~git123", "1.0~rc1~git123", EQUAL)
    RPMVERCMP("1.0~rc1~git123", "1.0~rc1", LEFT_SMALLER)
    RPMVERCMP("1.0~rc1", "1.0~rc1~git123", RIGHT_SMALLER)

    # Basic testcases for caret sorting
    RPMVERCMP("1.0^", "1.0^", EQUAL)
    RPMVERCMP("1.0^", "1.0", RIGHT_SMALLER)
    RPMVERCMP("1.0", "1.0^", LEFT_SMALLER)
    RPMVERCMP("1.0^git1", "1.0^git1", EQUAL)
    RPMVERCMP("1.0^git1", "1.0", RIGHT_SMALLER)
    RPMVERCMP("1.0", "1.0^git1", LEFT_SMALLER)
    RPMVERCMP("1.0^git1", "1.0^git2", LEFT_SMALLER)
    RPMVERCMP("1.0^git2", "1.0^git1", RIGHT_SMALLER)
    RPMVERCMP("1.0^git1", "1.01", LEFT_SMALLER)
    RPMVERCMP("1.01", "1.0^git1", RIGHT_SMALLER)
    RPMVERCMP("1.0^20160101", "1.0^20160101", EQUAL)
    RPMVERCMP("1.0^20160101", "1.0.1", LEFT_SMALLER)
    RPMVERCMP("1.0.1", "1.0^20160101", RIGHT_SMALLER)
    RPMVERCMP("1.0^20160101^git1", "1.0^20160101^git1", EQUAL)
    RPMVERCMP("1.0^20160102", "1.0^20160101^git1", RIGHT_SMALLER)
    RPMVERCMP("1.0^20160101^git1", "1.0^20160102", LEFT_SMALLER)

    # Basic testcases for tilde and caret sorting */
    RPMVERCMP("1.0~rc1^git1", "1.0~rc1^git1", EQUAL)
    RPMVERCMP("1.0~rc1^git1", "1.0~rc1", RIGHT_SMALLER)
    RPMVERCMP("1.0~rc1", "1.0~rc1^git1", LEFT_SMALLER)
    RPMVERCMP("1.0^git1~pre", "1.0^git1~pre", EQUAL)
    RPMVERCMP("1.0^git1", "1.0^git1~pre", RIGHT_SMALLER)
    RPMVERCMP("1.0^git1~pre", "1.0^git1", LEFT_SMALLER)

    # These are included here to document current, arguably buggy behaviors
    # for reference purposes and for easy checking against unintended
    # behavior changes. */
    print("/* RPM version comparison oddities */")
    # RhBug:811992 case
    RPMVERCMP("1b.fc17", "1b.fc17", EQUAL)
    RPMVERCMP("1b.fc17", "1.fc17", RIGHT_SMALLER)  # Note: this is reversed from rpm's vercmp, WAT! */
    RPMVERCMP("1.fc17", "1b.fc17", LEFT_SMALLER)
    RPMVERCMP("1g.fc17", "1g.fc17", EQUAL)
    RPMVERCMP("1g.fc17", "1.fc17", RIGHT_SMALLER)
    RPMVERCMP("1.fc17", "1g.fc17", LEFT_SMALLER)

    # Non-ascii characters are considered equal so these are all the same, eh… */
    RPMVERCMP("1.1.α", "1.1.α", EQUAL)
    RPMVERCMP("1.1.α", "1.1.β", EQUAL)
    RPMVERCMP("1.1.β", "1.1.α", EQUAL)
    RPMVERCMP("1.1.αα", "1.1.α", EQUAL)
    RPMVERCMP("1.1.α", "1.1.ββ", EQUAL)
    RPMVERCMP("1.1.ββ", "1.1.αα", EQUAL)
