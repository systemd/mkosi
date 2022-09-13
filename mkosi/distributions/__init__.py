# SPDX-License-Identifier: LGPL-2.1+

import enum
from pathlib import Path


class PackageType(enum.Enum):
    rpm = 1
    deb = 2
    pkg = 3
    ebuild = 5


class Distribution(enum.Enum):
    package_type: PackageType

    fedora = 0, PackageType.rpm
    debian = 1, PackageType.deb
    ubuntu = 2, PackageType.deb
    arch = 3, PackageType.pkg
    opensuse = 4, PackageType.rpm
    mageia = 5, PackageType.rpm
    centos = 6, PackageType.rpm
    centos_epel = 7, PackageType.rpm
    openmandriva = 10, PackageType.rpm
    rocky = 11, PackageType.rpm
    rocky_epel = 12, PackageType.rpm
    alma = 13, PackageType.rpm
    alma_epel = 14, PackageType.rpm
    gentoo = 15, PackageType.ebuild

    def __new__(cls, number: int, package_type: PackageType) -> Distribution:
        # This turns the list above into enum entries with .package_type attributes.
        # See https://docs.python.org/3.9/library/enum.html#when-to-use-new-vs-init
        # for an explanation.
        entry = object.__new__(cls)
        entry._value_ = number
        entry.package_type = package_type
        return entry

    def __str__(self) -> str:
        return self.name


def is_rpm_distribution(d: Distribution) -> bool:
    return d in (
        Distribution.fedora,
        Distribution.mageia,
        Distribution.centos,
        Distribution.centos_epel,
        Distribution.openmandriva,
        Distribution.rocky,
        Distribution.rocky_epel,
        Distribution.alma,
        Distribution.alma_epel
    )


def is_centos_variant(d: Distribution) -> bool:
    return d in (
        Distribution.centos,
        Distribution.centos_epel,
        Distribution.alma,
        Distribution.alma_epel,
        Distribution.rocky,
        Distribution.rocky_epel,
    )


def is_epel_variant(d: Distribution) -> bool:
    return d in (
        Distribution.centos_epel,
        Distribution.alma_epel,
        Distribution.rocky_epel,
    )
