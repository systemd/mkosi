# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mkosi.backend import MkosiState


class DistributionInstaller:
    needs_skeletons_after_bootstrap = False

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        raise NotImplementedError

    @staticmethod
    def kernel_image(name: str, architecture: str) -> Path:
        return Path("lib/modules") / name / "vmlinuz"

    @classmethod
    def cache_path(cls) -> list[str]:
        raise NotImplementedError

    @classmethod
    def remove_packages(cls, state: "MkosiState", remove: list[str]) -> None:
        raise NotImplementedError

    @classmethod
    def filesystem(cls) -> str:
        raise NotImplementedError
