# SPDX-License-Identifier: LGPL-2.1+


from typing import AbstractSet, ClassVar, Dict, FrozenSet, Optional

from .debian import DebianInstaller


class UbuntuInstaller(DebianInstaller):
    _default_release: ClassVar[str] = "jammy"
    _default_mirror: ClassVar[Dict[Optional[str], str]] = {
        "x86_64": "http://archive.ubuntu.com/ubuntu",
        "aarch64": "http://ports.ubuntu.com/",
    }

    # Ubuntu needs the 'universe' repo to install 'dracut'
    _repos_for_boot: ClassVar[FrozenSet[str]] = frozenset({"universe"})
    _kernel_package: ClassVar[str] = "linux-generic"

    def _updates_repo(self, repos: AbstractSet[str]) -> str:
        return f"deb http://archive.ubuntu.com/ubuntu {self.release}-updates {' '.join(repos)}"

    def _security_repo(self, repos: AbstractSet[str]) -> str:
        return f"deb http://archive.ubuntu.com/ubuntu {self.release}-security {' '.join(repos)}"
