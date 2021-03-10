# SPDX-License-Identifier: LGPL-2.1+

import os
from typing import List, Optional, Set

from mkosi import Repo, invoke_tdnf, setup_dnf
from mkosi.backend import DistributionInstaller, die


class Photon(DistributionInstaller):
    _default_release = "3.0"
    supported_boot_protocols = ["bios"]

    def __str__(self) -> str:
        return "Photon"

    @property
    def package_cache(self) -> List[str]:
        return ["var/cache/tdnf"]

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        release_url = "baseurl=https://dl.bintray.com/vmware/photon_release_$releasever_$basearch"
        updates_url = "baseurl=https://dl.bintray.com/vmware/photon_updates_$releasever_$basearch"
        gpgpath = "/etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY"

        setup_dnf(
            self._args,
            root,
            repos=[
                Repo("photon", f"VMware Photon OS {self._args.release} Release", release_url, gpgpath),
                Repo("photon-updates", f"VMware Photon OS {self._args.release} Updates", updates_url, gpgpath),
            ],
        )

        packages = {"minimal"}
        if not do_run_build_script and self._args.bootable:
            packages |= {"linux", "initramfs"}

        invoke_tdnf(
            self._args,
            root,
            self._args.repositories or ["photon", "photon-updates"],
            packages,
            os.path.exists(gpgpath),
            do_run_build_script,
        )

    def sanity_check(self) -> None:
        if "uefi" in self._args.boot_protocols:
            die(f"uefi boot not supported for Photon")

        if self._args.bootable:
            die("Sorry, --bootable is not supported on Photon")
