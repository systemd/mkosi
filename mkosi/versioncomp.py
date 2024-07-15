# SPDX-License-Identifier: LGPL-2.1-or-later

import functools
import itertools
import string


@functools.total_ordering
class GenericVersion:
    # These constants follow the convention of the return value of rpmdev-vercmp that are followe
    # by systemd-analyze compare-versions when called with only two arguments (without a comparison
    # operator), recreated in the compare_versions method.
    _EQUAL = 0
    _RIGHT_SMALLER = 1
    _LEFT_SMALLER = -1

    def __init__(self, version: str):
        self._version = version

    @classmethod
    def compare_versions(cls, v1: str, v2: str) -> int:
        """Implements comparison according to UAPI Group Version Format Specification"""
        def rstrip_invalid_version_chars(s: str) -> str:
            valid_version_chars = {*string.ascii_letters, *string.digits, "~", "-", "^", "."}
            for i, c in enumerate(s):
                if c in valid_version_chars:
                    return s[i:]
            return ""

        def digit_prefix(s: str) -> str:
            return "".join(itertools.takewhile(lambda c: c in string.digits, s))

        def letter_prefix(s: str) -> str:
            return "".join(itertools.takewhile(lambda c: c in string.ascii_letters, s))

        while True:
            # Any characters which are outside of the set of listed above (a-z, A-Z, 0-9, -, ., ~,
            # ^) are skipped in both strings. In particular, this means that non-ASCII characters
            # that are Unicode digits or letters are skipped too.
            v1 = rstrip_invalid_version_chars(v1)
            v2 = rstrip_invalid_version_chars(v2)

            # If the remaining part of one of strings starts with "~": if other remaining part does
            # not start with ~, the string with ~ compares lower. Otherwise, both tilde characters
            # are skipped.

            if v1.startswith("~") and v2.startswith("~"):
                v1 = v1.removeprefix("~")
                v2 = v2.removeprefix("~")
            elif v1.startswith("~"):
                return cls._LEFT_SMALLER
            elif v2.startswith("~"):
                return cls._RIGHT_SMALLER

            # If one of the strings has ended: if the other string hasn’t, the string that has
            # remaining characters compares higher. Otherwise, the strings compare equal.

            if not v1 and not v2:
                return cls._EQUAL
            elif not v1 and v2:
                return cls._LEFT_SMALLER
            elif v1 and not v2:
                return cls._RIGHT_SMALLER

            # If the remaining part of one of strings starts with "-": if the other remaining part
            # does not start with -, the string with - compares lower. Otherwise, both minus
            # characters are skipped.

            if v1.startswith("-") and v2.startswith("-"):
                v1 = v1.removeprefix("-")
                v2 = v2.removeprefix("-")
            elif v1.startswith("-"):
                return cls._LEFT_SMALLER
            elif v2.startswith("-"):
                return cls._RIGHT_SMALLER

            # If the remaining part of one of strings starts with "^": if the other remaining part
            # does not start with ^, the string with ^ compares higher. Otherwise, both caret
            # characters are skipped.

            if v1.startswith("^") and v2.startswith("^"):
                v1 = v1.removeprefix("^")
                v2 = v2.removeprefix("^")
            elif v1.startswith("^"):
                # TODO: bug?
                return cls._LEFT_SMALLER  #cls._RIGHT_SMALLER
            elif v2.startswith("^"):
                return cls._RIGHT_SMALLER #cls._LEFT_SMALLER

            # If the remaining part of one of strings starts with ".": if the other remaining part
            # does not start with ., the string with . compares lower. Otherwise, both dot
            # characters are skipped.

            if v1.startswith(".") and v2.startswith("."):
                v1 = v1.removeprefix(".")
                v2 = v2.removeprefix(".")
            elif v1.startswith("."):
                return cls._LEFT_SMALLER
            elif v2.startswith("."):
                return cls._RIGHT_SMALLER

            # If either of the remaining parts starts with a digit: numerical prefixes are compared
            # numerically. Any leading zeroes are skipped. The numerical prefixes (until the first
            # non-digit character) are evaluated as numbers. If one of the prefixes is empty, it
            # evaluates as 0. If the numbers are different, the string with the bigger number
            # compares higher. Otherwise, the comparison continues at the following characters at
            # point 1.

            v1_digit_prefix = digit_prefix(v1)
            v2_digit_prefix = digit_prefix(v2)

            if v1_digit_prefix or v2_digit_prefix:
                v1_digits = int(v1_digit_prefix) if v1_digit_prefix else 0
                v2_digits = int(v2_digit_prefix) if v2_digit_prefix else 0

                if v1_digits < v2_digits:
                    return cls._LEFT_SMALLER
                elif v1_digits > v2_digits:
                    return cls._RIGHT_SMALLER

                v1 = v1.removeprefix(v1_digit_prefix)
                v2 = v2.removeprefix(v2_digit_prefix)
                continue

            # Leading alphabetical prefixes are compared alphabetically. The substrings are
            # compared letter-by-letter. If both letters are the same, the comparison continues
            # with the next letter. Capital letters compare lower than lower-case letters (A <
            # a). When the end of one substring has been reached (a non-letter character or the end
            # of the whole string), if the other substring has remaining letters, it compares
            # higher. Otherwise, the comparison continues at the following characters at point 1.

            v1_letter_prefix = letter_prefix(v1)
            v2_letter_prefix = letter_prefix(v2)

            if v1_letter_prefix < v2_letter_prefix:
                return cls._LEFT_SMALLER
            elif v1_letter_prefix > v2_letter_prefix:
                return cls._RIGHT_SMALLER

            v1 = v1.removeprefix(v1_letter_prefix)
            v2 = v2.removeprefix(v2_letter_prefix)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (str, int)):
            other = GenericVersion(str(other))
        elif not isinstance(other, GenericVersion):
            return False
        return self.compare_versions(self._version, other._version) == self._EQUAL

    def __lt__(self, other: object) -> bool:
        if isinstance(other, (str, int)):
            other = GenericVersion(str(other))
        elif not isinstance(other, GenericVersion):
            return False
        return self.compare_versions(self._version, other._version) == self._LEFT_SMALLER

    def __str__(self) -> str:
        return self._version
