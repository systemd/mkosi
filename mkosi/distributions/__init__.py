# SPDX-License-Identifier: LGPL-2.1+

import enum
import importlib
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional, Type, cast

from mkosi.architecture import Architecture
from mkosi.log import die
from mkosi.util import StrEnum, read_os_release

if TYPE_CHECKING:
    from mkosi.state import MkosiState


class PackageType(StrEnum):
    rpm    = enum.auto()
    deb    = enum.auto()
    pkg    = enum.auto()
    ebuild = enum.auto()


class DistributionInstaller:
    @classmethod
    def setup(cls, state: "MkosiState") -> None:
        raise NotImplementedError()

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        raise NotImplementedError()

    @classmethod
    def install_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError()

    @classmethod
    def remove_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError()

    @classmethod
    def filesystem(cls) -> str:
        raise NotImplementedError()

    @staticmethod
    def architecture(arch: Architecture) -> str:
        raise NotImplementedError()

    @classmethod
    def package_type(cls) -> PackageType:
        raise NotImplementedError()


class Distribution(StrEnum):
    fedora       = enum.auto()
    debian       = enum.auto()
    ubuntu       = enum.auto()
    arch         = enum.auto()
    opensuse     = enum.auto()
    mageia       = enum.auto()
    centos       = enum.auto()
    openmandriva = enum.auto()
    rocky        = enum.auto()
    alma         = enum.auto()
    gentoo       = enum.auto()

    def is_centos_variant(self) -> bool:
        return self in (Distribution.centos, Distribution.alma, Distribution.rocky)

    def is_dnf_distribution(self) -> bool:
        return self in (
            Distribution.fedora,
            Distribution.mageia,
            Distribution.centos,
            Distribution.openmandriva,
            Distribution.rocky,
            Distribution.alma,
        )

    def is_apt_distribution(self) -> bool:
        return self in (Distribution.debian, Distribution.ubuntu)

    def setup(self, state: "MkosiState") -> None:
        return self.installer().setup(state)

    def install(self, state: "MkosiState") -> None:
        return self.installer().install(state)

    def install_packages(self, state: "MkosiState", packages: Sequence[str]) -> None:
        return self.installer().install_packages(state, packages)

    def remove_packages(self, state: "MkosiState", packages: Sequence[str]) -> None:
        return self.installer().remove_packages(state, packages)

    def filesystem(self) -> str:
        return self.installer().filesystem()

    def architecture(self, arch: Architecture) -> str:
        return self.installer().architecture(arch)

    def package_type(self) -> PackageType:
        return self.installer().package_type()

    def installer(self) -> Type[DistributionInstaller]:
        try:
            mod = importlib.import_module(f"mkosi.distributions.{self}")
            installer = getattr(mod, f"{str(self).title().replace('_','')}Installer")
            if not issubclass(installer, DistributionInstaller):
                die(f"Distribution installer for {self} is not a subclass of DistributionInstaller")
            return cast(Type[DistributionInstaller], installer)
        except (ImportError, AttributeError):
            die("No installer for this distribution.")


def detect_distribution() -> tuple[Optional[Distribution], Optional[str]]:
    try:
        os_release = read_os_release()
    except FileNotFoundError:
        return None, None

    dist_id = os_release.get("ID", "linux")
    dist_id_like = os_release.get("ID_LIKE", "").split()
    version = os_release.get("VERSION", None)
    version_id = os_release.get("VERSION_ID", None)
    version_codename = os_release.get("VERSION_CODENAME", None)
    extracted_codename = None

    if version:
        # extract Debian release codename
        m = re.search(r"\((.*?)\)", version)
        if m:
            extracted_codename = m.group(1)

    d: Optional[Distribution] = None
    for the_id in [dist_id, *dist_id_like]:
        d = Distribution.__members__.get(the_id, None)
        if d is not None:
            break

    if d in {Distribution.debian, Distribution.ubuntu} and (version_codename or extracted_codename):
        version_id = version_codename or extracted_codename

    return d, version_id
