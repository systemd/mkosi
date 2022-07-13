# SPDX-License-Identifier: LGPL-2.1+

from typing import AbstractSet, Any

from .debian import DebianInstaller


class UbuntuInstaller(DebianInstaller):
    # Ubuntu needs the 'universe' repo to install 'dracut'
    _repos_for_boot = {"universe"}
    _kernel_package = "linux-generic"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    def _updates_repo(self, repos: AbstractSet[str]) -> str:
        return f"deb http://archive.ubuntu.com/ubuntu {self.release}-updates {' '.join(repos)}"

    def _security_repo(self, repos: AbstractSet[str]) -> str:
        return f"deb http://archive.ubuntu.com/ubuntu {self.release}-security {' '.join(repos)}"
