# SPDX-License-Identifier: LGPL-2.1-or-later

import enum
import functools
import importlib
import urllib.parse
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

from mkosi.log import die
from mkosi.util import StrEnum, read_env_file
from mkosi.versioncomp import GenericVersion

if TYPE_CHECKING:
    from mkosi.config import Architecture, Config
    from mkosi.context import Context
    from mkosi.installer import PackageManager


class PackageType(StrEnum):
    none = enum.auto()
    rpm = enum.auto()
    deb = enum.auto()
    pkg = enum.auto()
    apk = enum.auto()


@functools.total_ordering
class DistributionRelease:
    def __init__(self, release: str, *, releasemap: Optional[dict[str, tuple[str, str]]] = None) -> None:
        self.releasemap = {} if releasemap is None else releasemap
        self._release = release

    def __str__(self) -> str:
        return self.releasemap.get(self._release, (None, self._release))[1]

    def __fspath__(self) -> str:
        return str(self)

    def __repr__(self) -> str:
        return f"DistributionRelease('{self._release}')"

    def major(self) -> str:
        return self._release.partition(".")[0]

    def minor(self) -> str:
        return self._release.partition(".")[1]

    def isnumeric(self) -> bool:
        return self._release.isdigit()

    def capitalize(self) -> str:
        return str(self).capitalize()

    def _construct_versions(self, other: object) -> tuple[GenericVersion, Optional[GenericVersion]]:
        v1 = GenericVersion(self.releasemap.get(self._release.lower(), (self._release.lower(),))[0])

        if isinstance(other, DistributionRelease):
            if self.releasemap == other.releasemap:
                v2 = GenericVersion(
                    other.releasemap.get(other._release.lower(), (other._release.lower(),))[0]
                )
            else:
                v2 = None
        elif isinstance(other, GenericVersion):
            v2 = GenericVersion(self.releasemap.get(str(other), (str(other),))[0])
        elif isinstance(other, (str, int)):
            v2 = GenericVersion(self.releasemap.get(str(other), (str(other),))[0])
        else:
            raise ValueError(f"{other} not a DistributionRelease, str or int")

        return v1, v2

    def __eq__(self, other: object) -> bool:
        v1, v2 = self._construct_versions(other)
        if v2 is None:
            return False
        return v1 == v2

    def __lt__(self, other: object) -> bool:
        v1, v2 = self._construct_versions(other)
        if v2 is None:
            return False
        return v1 < v2


class Distribution(StrEnum):
    # Please consult docs/distribution-policy.md and contact one
    # of the mkosi maintainers before implementing a new distribution.
    fedora = enum.auto()
    debian = enum.auto()
    kali = enum.auto()
    ubuntu = enum.auto()
    postmarketos = enum.auto()
    arch = enum.auto()
    opensuse = enum.auto()
    mageia = enum.auto()
    centos = enum.auto()
    rhel = enum.auto()
    rhel_ubi = enum.auto()
    openmandriva = enum.auto()
    rocky = enum.auto()
    alma = enum.auto()
    azure = enum.auto()
    custom = enum.auto()

    def is_centos_variant(self) -> bool:
        return self in (
            Distribution.centos,
            Distribution.alma,
            Distribution.rocky,
            Distribution.rhel,
            Distribution.rhel_ubi,
        )

    def is_apt_distribution(self) -> bool:
        return self in (Distribution.debian, Distribution.ubuntu, Distribution.kali)

    def is_rpm_distribution(self) -> bool:
        return self in (
            Distribution.azure,
            Distribution.fedora,
            Distribution.opensuse,
            Distribution.mageia,
            Distribution.centos,
            Distribution.rhel,
            Distribution.rhel_ubi,
            Distribution.openmandriva,
            Distribution.rocky,
            Distribution.alma,
        )

    @property
    def installer(self) -> type["DistributionInstaller"]:
        importlib.import_module(f"mkosi.distribution.{self.name}")
        return DistributionInstaller.registry[self]


class DistributionInstaller:
    _default_release = ""
    _releasemap: dict[str, tuple[str, str]] = {}
    registry: dict[Distribution, "type[DistributionInstaller]"] = {}

    def __init_subclass__(cls, distribution: Distribution):
        cls.registry[distribution] = cls

    @classmethod
    def pretty_name(cls) -> str:
        raise NotImplementedError

    @classmethod
    def package_manager(cls, config: "Config") -> type["PackageManager"]:
        raise NotImplementedError

    @classmethod
    def keyring(cls, context: "Context") -> None:
        pass

    @classmethod
    def setup(cls, context: "Context") -> None:
        raise NotImplementedError

    @classmethod
    def install(cls, context: "Context") -> None:
        raise NotImplementedError

    @classmethod
    def install_packages(
        cls,
        context: "Context",
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        return cls.package_manager(context.config).install(
            context,
            packages,
            apivfs=apivfs,
            allow_downgrade=allow_downgrade,
        )

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
    def default_release(cls) -> DistributionRelease:
        return DistributionRelease(cls._default_release, releasemap=cls._releasemap)

    @classmethod
    def parse_release(cls, release: str) -> DistributionRelease:
        return DistributionRelease(release, releasemap=cls._releasemap)

    @classmethod
    def default_tools_tree_distribution(cls) -> Optional[Distribution]:
        return None

    @classmethod
    def grub_prefix(cls) -> str:
        return "grub"

    @classmethod
    def latest_snapshot(cls, config: "Config") -> str:
        die(f"{cls.pretty_name()} does not support snapshots")

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        return False


def detect_distribution(
    root: Path = Path("/"),
) -> tuple[Union[Distribution, str, None], Optional[DistributionRelease]]:
    try:
        os_release = read_env_file(root / "etc/os-release")
    except FileNotFoundError:
        try:
            os_release = read_env_file(root / "usr/lib/os-release")
        except FileNotFoundError:
            return None, None

    dist_id = os_release.get("ID")
    dist_id_like = os_release.get("ID_LIKE", "").split()
    version_id = os_release.get("VERSION_ID", None) if dist_id != "opensuse-tumbleweed" else "tumbleweed"
    version_codename = os_release.get("VERSION_CODENAME", None)

    quirks = {
        "azurelinux": "azure",
    }

    d: Optional[Distribution] = None
    for the_id in [dist_id, *dist_id_like]:
        if not the_id:
            continue

        if the_id in Distribution.values() or the_id in quirks:
            d = Distribution(quirks.get(the_id, the_id))
            break

    if d and d.is_apt_distribution() and version_codename:
        version_id = version_codename

    if d and version_id:
        return d, d.installer.parse_release(version_id)

    return d, DistributionRelease(version_id) if version_id is not None else None


def join_mirror(mirror: str, link: str) -> str:
    # urljoin() behaves weirdly if the base does not end with a / or the path starts with a / so fix them up
    # as needed.
    if not mirror.endswith("/"):
        mirror = f"{mirror}/"
    link = link.removeprefix("/")

    return urllib.parse.urljoin(mirror, link)
