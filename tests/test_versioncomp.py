# SPDX-License-Identifier: LGPL-2.1-or-later

import itertools

import pytest

from mkosi.versioncomp import GenericVersion


def test_conversion() -> None:
    assert GenericVersion("1") < 2
    assert GenericVersion("1") < "2"
    assert GenericVersion("2") > 1
    assert GenericVersion("2") > "1"
    assert GenericVersion("1") == "1"


def test_generic_version_systemd() -> None:
    """Same as the first block of systemd/test/test-compare-versions.sh"""
    assert GenericVersion("1") < GenericVersion("2")
    assert GenericVersion("1") <= GenericVersion("2")
    assert GenericVersion("1") != GenericVersion("2")
    assert not (GenericVersion("1") > GenericVersion("2"))
    assert not (GenericVersion("1") == GenericVersion("2"))
    assert not (GenericVersion("1") >= GenericVersion("2"))
    assert GenericVersion.compare_versions("1", "2") == -1
    assert GenericVersion.compare_versions("2", "2") == 0
    assert GenericVersion.compare_versions("2", "1") == 1


def test_generic_version_spec() -> None:
    """Examples from the uapi group version format spec"""
    assert GenericVersion("11") == GenericVersion("11")
    assert GenericVersion("systemd-123") == GenericVersion("systemd-123")
    assert GenericVersion("bar-123") < GenericVersion("foo-123")
    assert GenericVersion("123a") > GenericVersion("123")
    assert GenericVersion("123.a") > GenericVersion("123")
    assert GenericVersion("123.a") < GenericVersion("123.b")
    assert GenericVersion("123a") > GenericVersion("123.a")
    assert GenericVersion("11α") == GenericVersion("11β")
    assert GenericVersion("A") < GenericVersion("a")
    assert GenericVersion("") < GenericVersion("0")
    assert GenericVersion("0.") > GenericVersion("0")
    assert GenericVersion("0.0") > GenericVersion("0")
    assert GenericVersion("0") > GenericVersion("~")
    assert GenericVersion("") > GenericVersion("~")
    assert GenericVersion("1_") == GenericVersion("1")
    assert GenericVersion("_1") == GenericVersion("1")
    assert GenericVersion("1_") < GenericVersion("1.2")
    assert GenericVersion("1_2_3") > GenericVersion("1.3.3")
    assert GenericVersion("1+") == GenericVersion("1")
    assert GenericVersion("+1") == GenericVersion("1")
    assert GenericVersion("1+") < GenericVersion("1.2")
    assert GenericVersion("1+2+3") > GenericVersion("1.3.3")


@pytest.mark.parametrize(
    "s1,s2",
    itertools.combinations_with_replacement(
        enumerate(
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
        ),
        2,
    ),
)
def test_generic_version_strverscmp_improved_doc(
    s1: tuple[int, GenericVersion],
    s2: tuple[int, GenericVersion],
) -> None:
    """Example from the doc string of strverscmp_improved.

    strverscmp_improved can be found in systemd/src/fundamental/string-util-fundamental.c
    """
    i1, v1 = s1
    i2, v2 = s2
    assert (v1 == v2) == (i1 == i2)
    assert (v1 < v2) == (i1 < i2)
    assert (v1 <= v2) == (i1 <= i2)
    assert (v1 > v2) == (i1 > i2)
    assert (v1 >= v2) == (i1 >= i2)
    assert (v1 != v2) == (i1 != i2)


def RPMVERCMP(a: str, b: str, expected: int) -> None:
    assert (GenericVersion(a) > GenericVersion(b)) - (GenericVersion(a) < GenericVersion(b)) == expected


def test_generic_version_rpmvercmp() -> None:
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
