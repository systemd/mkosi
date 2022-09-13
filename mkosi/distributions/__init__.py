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
    fedora = "fedora", PackageType.rpm
    debian = "debian", PackageType.deb
    ubuntu = "ubuntu", PackageType.deb
    arch = "arch", PackageType.pkg
    opensuse = "opensuse", PackageType.rpm
    mageia = "mageia", PackageType.rpm
    centos = "centos", PackageType.rpm
    centos_epel = "centos_epel", PackageType.rpm
    openmandriva = "openmandriva", PackageType.rpm
    rocky = "rocky", PackageType.rpm
    rocky_epel = "rocky_epel", PackageType.rpm
    alma = "alma", PackageType.rpm
    alma_epel = "alma_epel", PackageType.rpm
    gentoo = "gentoo", PackageType.ebuild

    def __new__(cls, name: str, package_type: PackageType) -> "Distribution":
        # This turns the list above into enum entries with .package_type attributes.
        # See https://docs.python.org/3.9/library/enum.html#when-to-use-new-vs-init
        # for an explanation.
        entry = object.__new__(cls)
        entry._value_ = name
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
