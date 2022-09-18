# SPDX-License-Identifier: LGPL-2.1+

from typing import Set

from ..backend import MkosiState, add_packages
from .debian import DebianInstaller


class UbuntuInstaller(DebianInstaller):
    repositories_for_boot = {"universe"}

    @classmethod
    def add_default_kernel_package(cls, state: MkosiState, extra_packages: Set[str]) -> None:
        # use the global metapckage linux-generic if the user didn't pick one
        if ("linux-generic" not in extra_packages and
            not any(package.startswith("linux-image") for package in extra_packages)):
            add_packages(state.config, extra_packages, "linux-generic")

    @classmethod
    def add_apt_auxiliary_repos(cls, state: MkosiState, repos: Set[str]) -> None:
        if state.config.release in ("unstable", "sid"):
            return

        updates = f"deb {state.config.mirror} {state.config.release}-updates {' '.join(repos)}"
        state.root.joinpath(f"etc/apt/sources.list.d/{state.config.release}-updates.list").write_text(f"{updates}\n")

        # Security updates repos are never mirrored
        security = f"deb http://security.ubuntu.com/ubuntu/ {state.config.release}-security {' '.join(repos)}"

        state.root.joinpath(f"etc/apt/sources.list.d/{state.config.release}-security.list").write_text(f"{security}\n")

    @classmethod
    def fixup_resolved(cls, state: MkosiState, extra_packages: Set[str]) -> None:
        pass
