# SPDX-License-Identifier: LGPL-2.1+

import pytest

import mkosi


def test_parse_bytes() -> None:
    assert mkosi.parse_bytes(None) == 0
    assert mkosi.parse_bytes("1") == 512
    assert mkosi.parse_bytes("1000") == 1024
    assert mkosi.parse_bytes("1K") == 1024
    assert mkosi.parse_bytes("1025") == 1536
    assert mkosi.parse_bytes("1M") == 1024**2
    assert mkosi.parse_bytes("1.9M") == 1992704
    assert mkosi.parse_bytes("1G") == 1024**3
    assert mkosi.parse_bytes("7.3G") == 7838315520

    with pytest.raises(ValueError):
        mkosi.parse_bytes("-1")
    with pytest.raises(ValueError):
        mkosi.parse_bytes("-2K")
    with pytest.raises(ValueError):
        mkosi.parse_bytes("-3M")
    with pytest.raises(ValueError):
        mkosi.parse_bytes("-4G")
