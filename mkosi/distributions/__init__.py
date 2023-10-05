# SPDX-License-Identifier: LGPL-2.1+

import enum
import importlib
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional, cast

from mkosi.architecture import Architecture
from mkosi.util import StrEnum, read_os_release

if TYPE_CHECKING:
    from mkosi.state import MkosiState


class PackageType(StrEnum):
    none   = enum.auto()
    rpm    = enum.auto()
    deb    = enum.auto()
    pkg    = enum.auto()
    ebuild = enum.auto()


class DistributionInstaller:
    @classmethod
    def pretty_name(cls) -> str:
        raise NotImplementedError

    @classmethod
    def setup(cls, state: "MkosiState") -> None:
        raise NotImplementedError

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        raise NotImplementedError

    @classmethod
    def install_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def remove_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @staticmethod
    def architecture(arch: Architecture) -> str:
        return str(arch)

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.none

    @classmethod
    def default_release(cls) -> str:
        return ""

    @classmethod
    def default_tools_tree_distribution(cls) -> Optional["Distribution"]:
        return None

    @classmethod
    def tools_tree_repositories(cls) -> list[str]:
        return []

    @classmethod
    def tools_tree_packages(cls) -> list[str]:
        return []


class Distribution(StrEnum):
    # Please consult docs/distribution-policy.md and contact one
    # of the mkosi maintainers before implementing a new distribution.
    fedora       = enum.auto()
    debian       = enum.auto()
    ubuntu       = enum.auto()
    arch         = enum.auto()
    opensuse     = enum.auto()
    mageia       = enum.auto()
    centos       = enum.auto()
    rhel_ubi     = enum.auto()
    openmandriva = enum.auto()
    rocky        = enum.auto()
    alma         = enum.auto()
    gentoo       = enum.auto()
    custom       = enum.auto()

    def is_centos_variant(self) -> bool:
        return self in (Distribution.centos, Distribution.alma, Distribution.rocky)

    def is_dnf_distribution(self) -> bool:
        return self in (
            Distribution.fedora,
            Distribution.mageia,
            Distribution.centos,
            Distribution.rhel_ubi,
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

    def default_release(self) -> str:
        return self.installer().default_release()

    def default_tools_tree_distribution(self) -> Optional["Distribution"]:
        return self.installer().default_tools_tree_distribution()

    def tools_tree_repositories(self) -> list[str]:
        return self.installer().tools_tree_repositories()

    def tools_tree_packages(self) -> list[str]:
        return self.installer().tools_tree_packages()

    def installer(self) -> type[DistributionInstaller]:
        modname = str(self).replace('-', '_')
        mod = importlib.import_module(f"mkosi.distributions.{modname}")
        installer = getattr(mod, "Installer")
        assert issubclass(installer, DistributionInstaller)
        return cast(type[DistributionInstaller], installer)


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
