# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path
from typing import Tuple

from mkosi.backend import MkosiConfig
from mkosi.distributions.centos import CentosInstaller


class AlmaInstaller(CentosInstaller):
    @staticmethod
    def _gpg_locations(epel_release: int) -> Tuple[Path, str]:
        return (
            Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux"),
            "https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux"
        )

    @classmethod
    def _mirror_directory(cls) -> str:
        return "almalinux"

    @classmethod
    def _mirror_repo_url(cls, config: MkosiConfig, repo: str) -> str:
        return f"https://mirrors.almalinux.org/mirrorlist/{config.release}/{repo.lower()}"
