# SPDX-License-Identifier: LGPL-2.1+

from mkosi.distributions.centos import CentosInstaller


class RockyInstaller(CentosInstaller):
    @staticmethod
    def _gpgurl(release: int) -> str:
        keyname = "Rocky-$releasever" if release >= 9 else "rockyofficial"
        return f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-{keyname}"

    @staticmethod
    def _extras_gpgurl(release: int) -> str:
        keyname = "Rocky-$releasever" if release >= 9 else "rockyofficial"
        return f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-{keyname}"

    @classmethod
    def _mirror_directory(cls) -> str:
        return "rocky"

    @classmethod
    def _mirror_repo_url(cls, repo: str) -> str:
        return f"https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo={repo}-$releasever"
