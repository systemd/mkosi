# SPDX-License-Identifier: LGPL-2.1+

from mkosi.util import Distribution, PackageType


def test_distribution() -> None:
    assert Distribution.fedora.package_type == PackageType.rpm
    assert Distribution.fedora is Distribution.fedora
    assert Distribution.fedora.package_type is not Distribution.debian.package_type
    assert str(Distribution.fedora) == "fedora"


