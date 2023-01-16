# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.distributions.centos import CentosInstaller


class AlmaInstaller(CentosInstaller):
    @staticmethod
    def _gpg_locations(epel_release: int) -> tuple[Path, str]:
        return (
            Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-$releasever"),
            "https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-$releasever",
        )

    @classmethod
    def _mirror_directory(cls) -> str:
        return "almalinux"

    @classmethod
    def _mirror_repo_url(cls, repo: str) -> str:
        return f"https://mirrors.almalinux.org/mirrorlist/$releasever/{repo.lower()}"
