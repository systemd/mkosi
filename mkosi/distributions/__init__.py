# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mkosi.state import MkosiState


class DistributionInstaller:
    @classmethod
    def install(cls, state: "MkosiState") -> None:
        raise NotImplementedError

    @staticmethod
    def kernel_image(kver: str, architecture: str) -> Path:
        return Path("usr/lib/modules") / kver / "vmlinuz"

    @classmethod
    def install_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def install_package_files(cls, state: "MkosiState", dir: Path) -> None:
        raise NotImplementedError

    @classmethod
    def remove_packages(cls, state: "MkosiState", packages: Sequence[str]) -> None:
        raise NotImplementedError

    @classmethod
    def filesystem(cls) -> str:
        raise NotImplementedError

    @classmethod
    def filesystem_options(cls, state: "MkosiState") -> dict[str, list[str]]:
        return {}

    @staticmethod
    def kernel_command_line(state: "MkosiState") -> list[str]:
        return []
