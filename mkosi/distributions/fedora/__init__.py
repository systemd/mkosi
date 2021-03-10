# SPDX-License-Identifier: LGPL-2.1+

import os
import platform
import urllib
from typing import List

from mkosi import Repo, check_if_url_exists, configure_dracut, invoke_dnf, setup_dnf
from mkosi.backend import (
    CommandLineArguments,
    DistributionInstaller,
    MkosiPrinter,
    warn,
)

FEDORA_KEYS_MAP = {
    "23": "34EC9CBA",
    "24": "81B46521",
    "25": "FDB19C98",
    "26": "64DAB85D",
    "27": "F5282EE4",
    "28": "9DB62FB1",
    "29": "429476B4",
    "30": "CFC659B9",
    "31": "3C3359C4",
    "32": "12C944D0",
    "33": "9570FF31",
    "34": "45719A39",
}


class Fedora(DistributionInstaller):
    _default_release = "34"
    supports_with_documentation = True

    def __str__(self) -> str:
        return "Fedora Linux"

    @property
    def package_cache(self) -> List[str]:
        return ["var/cache/dnf"]

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        if self.release == "rawhide":
            last = sorted(FEDORA_KEYS_MAP)[-1]
            warn(
                f"Assuming rawhide is version {last} — " + "You may specify otherwise with --release=rawhide-<version>"
            )
            self.releasever = last
        elif self.release.startswith("rawhide-"):
            self._release, self.releasever = self.release.split("-")
            MkosiPrinter.info(f"Fedora rawhide — release version: {self.releasever}")
        else:
            self.releasever = self.release

        arch = self.architecture or platform.machine()

        if self.mirror:
            baseurl = urllib.parse.urljoin(self.mirror, f"releases/{self.release}/Everything/$basearch/os/")
            media = urllib.parse.urljoin(baseurl.replace("$basearch", arch), "media.repo")
            if not check_if_url_exists(media):
                baseurl = urllib.parse.urljoin(self.mirror, f"development/{self.release}/Everything/$basearch/os/")

            release_url = f"baseurl={baseurl}"
            updates_url = f"baseurl={self.mirror}/updates/{self.release}/Everything/$basearch/"
        else:
            release_url = (
                f"metalink=https://mirrors.fedoraproject.org/metalink?" + f"repo=fedora-{self.release}&arch=$basearch"
            )
            updates_url = (
                f"metalink=https://mirrors.fedoraproject.org/metalink?"
                + f"repo=updates-released-f{self.release}&arch=$basearch"
            )

        if self.releasever in FEDORA_KEYS_MAP:
            gpgid = f"keys/{FEDORA_KEYS_MAP[self.releasever]}.txt"
        else:
            gpgid = "fedora.gpg"

        gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-{self.releasever}-{arch}"
        gpgurl = urllib.parse.urljoin("https://getfedora.org/static/", gpgid)

        setup_dnf(
            self._args,
            root,
            repos=[
                Repo("fedora", f"Fedora {self.release.capitalize()} - base", release_url, gpgpath, gpgurl),
                Repo("updates", f"Fedora {self.release.capitalize()} - updates", updates_url, gpgpath, gpgurl),
            ],
        )

        packages = {"fedora-release", "glibc-minimal-langpack", "systemd", *self.packages}
        if not do_run_build_script and self._args.bootable:
            packages |= {"kernel-core", "kernel-modules", "systemd-udev", "binutils", "dracut"}
            configure_dracut(self._args, root)
        if do_run_build_script:
            packages.update(self.build_packages)
        if not do_run_build_script and self._args.network_veth:
            packages.add("systemd-networkd")
        invoke_dnf(self._args, root, self.repositories or ["fedora", "updates"], packages, do_run_build_script)

        with open(os.path.join(root, "etc/locale.conf"), "w") as f:
            f.write("LANG=C.UTF-8\n")
