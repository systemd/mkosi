# SPDX-License-Identifier: LGPL-2.1+

from mkosi.backend import PackageType, Distribution


def test_distribution():
    assert Distribution.fedora.package_type == PackageType.rpm
    assert Distribution.fedora is Distribution.fedora
    assert Distribution.fedora is not Distribution.debian
    assert str(Distribution.photon) == "photon"
