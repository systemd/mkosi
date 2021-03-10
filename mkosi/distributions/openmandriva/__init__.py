# SPDX-License-Identifier: LGPL-2.1+

import platform
import shutil
from typing import List, Optional, Set

from mkosi import (
    Repo,
    configure_dracut,
    disable_pam_securetty,
    dracut_configure_uefi_stub,
    invoke_dnf,
    setup_dnf,
)
from mkosi.backend import CommandLineArguments, DistributionInstaller, die


class OpenMandriva(DistributionInstaller):
    _default_release = "cooker"

    @property
    def package_cache(self) -> List[str]:
        return ["var/cache/dnf"]

    def configure_dracut(self, dracut_dir: str) -> None:
        dracut_configure_uefi_stub(dracut_dir)

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        release = self.release.strip("'")
        arch = self.architecture or platform.machine()

        if release[0].isdigit():
            release_model = "rock"
        elif release == "cooker":
            release_model = "cooker"
        else:
            release_model = release

        if self.mirror:
            baseurl = f"{self.mirror}/{release_model}/repository/{arch}/main"
            release_url = f"baseurl={baseurl}/release/"
            updates_url = f"baseurl={baseurl}/updates/"
        else:
            baseurl = f"http://mirrors.openmandriva.org/mirrors.php?platform={release_model}&arch={arch}&repo=main"
            release_url = f"mirrorlist={baseurl}&release=release"
            updates_url = f"mirrorlist={baseurl}&release=updates"

        gpgpath = "/etc/pki/rpm-gpg/RPM-GPG-KEY-OpenMandriva"

        setup_dnf(
            self._args,
            root,
            repos=[
                Repo("openmandriva", f"OpenMandriva {release_model} Main", release_url, gpgpath),
                Repo("updates", f"OpenMandriva {release_model} Main Updates", updates_url, gpgpath),
            ],
        )

        # well we may use basesystem here, but that pulls lot of stuff
        packages = {"basesystem-minimal", "systemd", *self.packages}
        if not do_run_build_script and self._args.bootable:
            packages |= {
                "kernel-release-server",
                "binutils",
                "systemd-boot",
                "dracut",
                "timezone",
                "systemd-cryptsetup",
            }
            configure_dracut(self._args, root)
        if self._args.network_veth:
            packages |= {"systemd-networkd"}
        if do_run_build_script:
            packages.update(self.build_packages)
        invoke_dnf(self._args, root, self.repositories or ["openmandriva", "updates"], packages, do_run_build_script)

        disable_pam_securetty(root)

    def tar_cmd(self, tar_root_dir: str) -> List[str]:
        if shutil.which("bsdtar"):
            cmd = ["bsdtar", "-C", tar_root_dir, "-c", "-J", "--xattrs", "-f", "-", "."]
        else:
            cmd = super().tar_cmd(tar_root_dir)
        return cmd

    def sanity_check(self) -> None:
        if shutil.which("bsdtar") and self._args.tar_strip_selinux_context:
            die("Sorry, bsdtar on OpenMandriva is incompatible with --tar-strip-selinux-context")
