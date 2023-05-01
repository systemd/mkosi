# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mkosi.state import MkosiState


class DistributionInstaller:
    @classmethod
    def install(cls, state: "MkosiState") -> None:
        raise NotImplementedError

    @staticmethod
    def kernel_image(kver: str, architecture: str) -> Path:
        return Path("usr/lib/modules") / kver / "vmlinuz"

    @staticmethod
    def initrd_path(kver: str) -> Path:
        return Path("boot") / f"initramfs-{kver}.img"

    @classmethod
    def install_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def remove_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def filesystem(cls) -> str:
        raise NotImplementedError

    @classmethod
    def cache_path(cls) -> Optional[Path]:
        return None

    @classmethod
    def filesystem_options(cls, state: "MkosiState") -> dict[str, list[str]]:
        return {}

    @staticmethod
    def kernel_command_line(state: "MkosiState") -> list[str]:
        return []
