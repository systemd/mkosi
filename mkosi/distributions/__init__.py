# SPDX-License-Identifier: LGPL-2.1+

import enum
import importlib
import re
import urllib.parse
from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional, cast

from mkosi.util import StrEnum, read_os_release

if TYPE_CHECKING:
    from mkosi.config import Architecture, Config
    from mkosi.context import Context
    from mkosi.installer import PackageManager


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
    def package_manager(cls, config: "Config") -> type["PackageManager"]:
        raise NotImplementedError

    @classmethod
    def setup(cls, context: "Context") -> None:
        raise NotImplementedError

    @classmethod
    def install(cls, context: "Context") -> None:
        raise NotImplementedError

    @classmethod
    def install_packages(cls, context: "Context", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def remove_packages(cls, context: "Context", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def architecture(cls, arch: "Architecture") -> str:
        raise NotImplementedError

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
    def grub_prefix(cls) -> str:
        return "grub"

    @classmethod
    def createrepo(cls, context: "Context") -> None:
        raise NotImplementedError


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
    rhel         = enum.auto()
    rhel_ubi     = enum.auto()
    openmandriva = enum.auto()
    rocky        = enum.auto()
    alma         = enum.auto()
    custom       = enum.auto()

    def is_centos_variant(self) -> bool:
        return self in (
            Distribution.centos,
            Distribution.alma,
            Distribution.rocky,
            Distribution.rhel,
            Distribution.rhel_ubi,
        )

    def is_dnf_distribution(self) -> bool:
        return self in (
            Distribution.fedora,
            Distribution.mageia,
            Distribution.centos,
            Distribution.rhel,
            Distribution.rhel_ubi,
            Distribution.openmandriva,
            Distribution.rocky,
            Distribution.alma,
        )

    def is_apt_distribution(self) -> bool:
        return self in (Distribution.debian, Distribution.ubuntu)

    def pretty_name(self) -> str:
        return self.installer().pretty_name()

    def package_manager(self, config: "Config") -> type["PackageManager"]:
        return self.installer().package_manager(config)

    def setup(self, context: "Context") -> None:
        return self.installer().setup(context)

    def install(self, context: "Context") -> None:
        return self.installer().install(context)

    def install_packages(self, context: "Context", packages: Sequence[str]) -> None:
        return self.installer().install_packages(context, packages)

    def remove_packages(self, context: "Context", packages: Sequence[str]) -> None:
        return self.installer().remove_packages(context, packages)

    def filesystem(self) -> str:
        return self.installer().filesystem()

    def architecture(self, arch: "Architecture") -> str:
        return self.installer().architecture(arch)

    def package_type(self) -> PackageType:
        return self.installer().package_type()

    def default_release(self) -> str:
        return self.installer().default_release()

    def default_tools_tree_distribution(self) -> Optional["Distribution"]:
        return self.installer().default_tools_tree_distribution()

    def grub_prefix(self) -> str:
        return self.installer().grub_prefix()

    def createrepo(self, context: "Context") -> None:
        return self.installer().createrepo(context)

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


def join_mirror(mirror: str, link: str) -> str:
    # urljoin() behaves weirdly if the base does not end with a / or the path starts with a / so fix them up as needed.
    if not mirror.endswith("/"):
        mirror = f"{mirror}/"
    link = link.removeprefix("/")

    return urllib.parse.urljoin(mirror, link)
