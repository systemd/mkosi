# SPDX-License-Identifier: LGPL-2.1+

import os

from mkosi.backend import PackageType, Distribution, set_umask


def test_distribution():
    assert Distribution.fedora.package_type == PackageType.rpm
    assert Distribution.fedora is Distribution.fedora
    assert Distribution.fedora is not Distribution.debian
    assert str(Distribution.photon) == "photon"


def test_set_umask():
    with set_umask(0o767):
        tmp1 = os.umask(0o777)
        with set_umask(0o757):
            tmp2 = os.umask(0o727)
        tmp3 = os.umask(0o727)

    assert tmp1 == 0o767
    assert tmp2 == 0o757
    assert tmp3 == 0o777
