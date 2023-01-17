# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.distributions.centos import CentosInstaller


class RockyInstaller(CentosInstaller):
    @staticmethod
    def _gpg_locations(epel_release: int) -> tuple[Path, str]:
        keyname = "Rocky-$releasever" if epel_release >= 9 else "rockyofficial"
        return (
             Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-{keyname}"),
             f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-{keyname}"
        )

    @staticmethod
    def _extras_gpg_locations(epel_release: int) -> tuple[Path, str]:
        keyname = "Rocky-$releasever" if epel_release >= 9 else "rockyofficial"
        return (
             Path(f"/etc/pki/rpm-gpg/RPM-GPG-KEY-{keyname}"),
             f"https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-{keyname}"
        )

    @classmethod
    def _mirror_directory(cls) -> str:
        return "rocky"

    @classmethod
    def _mirror_repo_url(cls, repo: str) -> str:
        return f"https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo={repo}-$releasever"
