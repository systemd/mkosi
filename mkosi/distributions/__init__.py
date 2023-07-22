# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from typing import TYPE_CHECKING

from mkosi.architecture import Architecture

if TYPE_CHECKING:
    from mkosi.state import MkosiState


class DistributionInstaller:
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
