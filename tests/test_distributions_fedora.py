# SPDX-License-Identifier: LGPL-2.1+

import pytest

from mkosi.distributions.fedora import fedora_release_cmp


def test_fedora_release_cmp() -> None:
    assert fedora_release_cmp("rawhide", "rawhide") == 0
    assert fedora_release_cmp("32", "32") == 0
    assert fedora_release_cmp("33", "32") > 0
    assert fedora_release_cmp("30", "31") < 0
    assert fedora_release_cmp("-1", "-2") > 0
    assert fedora_release_cmp("1", "-2") > 0
    with pytest.raises(ValueError):
        fedora_release_cmp("literal", "rawhide")
