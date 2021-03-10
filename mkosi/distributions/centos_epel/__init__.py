# SPDX-License-Identifier: LGPL-2.1+

from typing import List, Optional, Set

from mkosi.backend import CommandLineArguments
from mkosi.distributions.centos import CentOS


class CentOS_EPEL(CentOS):
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

        if self._old:
            self._repositories.append("epel")
            self._packages.add("epel-release")
