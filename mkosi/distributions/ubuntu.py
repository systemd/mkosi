# SPDX-License-Identifier: LGPL-2.1+

from typing import Any

from .debian import DebianInstaller


class UbuntuInstaller(DebianInstaller):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
