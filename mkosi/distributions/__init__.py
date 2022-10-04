# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from ..backend import MkosiState


class DistributionInstaller:
    @classmethod
    def install(cls, state: "MkosiState") -> None:
        raise NotImplementedError

    @staticmethod
    def kernel_image(name: str, architecture: str) -> Path:
        return Path("lib/modules") / name / "vmlinuz"

    @classmethod
    def cache_path(cls) -> List[str]:
        raise NotImplementedError
