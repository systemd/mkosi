# SPDX-License-Identifier: LGPL-2.1+

import platform
from typing import List, Optional, Set, cast

from mkosi.backend import CommandLineArguments
from mkosi.distributions.debian import Debian


class Ubuntu(Debian):
    _default_release = "focal"
    _kernel_package = "linux-generic"

    def __init__(
        self,
        args: CommandLineArguments,
        repositories: Optional[List[str]] = None,
        release: Optional[str] = None,
        mirror: Optional[str] = None,
        architecture: Optional[str] = None,
        packages: Optional[Set[str]] = None,
        build_packages: Optional[Set[str]] = None,
    ):
        super().__init__(args, repositories, release, mirror, architecture, packages, build_packages)

        # Ubuntu needs the 'universe' repo to install 'dracut'
        if self._args.bootable:
            self.repositories.append("universe")

    def __str__(self) -> str:
        return "Ubuntu"

    @property
    def mirror(self) -> str:
        if self._mirror is None:
            if platform.machine() == "aarch64":
                return "http://ports.ubuntu.com/"
            return "http://archive.ubuntu.com/ubuntu"
        return self._mirror

    def _fix_os_release(self, root: str) -> None:
        pass
