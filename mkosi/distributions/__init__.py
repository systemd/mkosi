# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path
from typing import TYPE_CHECKING, List

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
    def cache_path(cls) -> List[str]:
        raise NotImplementedError

    @classmethod
    def remove_packages(cls, state: "MkosiState", remove: List[str]) -> None:
        raise NotImplementedError
