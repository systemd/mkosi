# SPDX-License-Identifier: LGPL-2.1+

from mkosi.distributions.centos import CentosInstaller


class AlmaInstaller(CentosInstaller):
    @staticmethod
    def _gpgurl(release: int) -> str:
        return "https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-$releasever"

    @staticmethod
    def _extras_gpgurl(release: int) -> str:
        return "https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-$releasever"

    @classmethod
    def _mirror_directory(cls) -> str:
        return "almalinux"

    @classmethod
    def _mirror_repo_url(cls, repo: str) -> str:
        return f"https://mirrors.almalinux.org/mirrorlist/$releasever/{repo.lower()}"
