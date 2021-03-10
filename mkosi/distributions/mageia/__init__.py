# SPDX-License-Identifier: LGPL-2.1+

import os
from typing import List, Optional, Set

from mkosi import (
    Repo,
    configure_dracut,
    disable_pam_securetty,
    dracut_configure_uefi_stub,
    invoke_dnf,
    setup_dnf,
)
from mkosi.backend import CommandLineArguments, DistributionInstaller, die, warn


class Mageia(DistributionInstaller):
    _default_release = "7"
    supports_with_documentation = True

    @property
    def package_cache(self) -> List[str]:
        return ["var/cache/dnf"]

    def configure_dracut(self, dracut_dir: str) -> None:
        dracut_configure_uefi_stub(dracut_dir)

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        if self.mirror:
            baseurl = f"{self.mirror}/distrib/{self.release}/x86_64/media/core/"
            release_url = f"baseurl={baseurl}/release/"
            updates_url = f"baseurl={baseurl}/updates/"
        else:
            baseurl = f"https://www.mageia.org/mirrorlist/?release={self.release}&arch=x86_64&section=core"
            release_url = f"mirrorlist={baseurl}&repo=release"
            updates_url = f"mirrorlist={baseurl}&repo=updates"

        gpgpath = "/etc/pki/rpm-gpg/RPM-GPG-KEY-Mageia"

        setup_dnf(
            self._args,
            root,
            repos=[
                Repo("mageia", f"Mageia {self.release} Core Release", release_url, gpgpath),
                Repo("updates", f"Mageia {self.release} Core Updates", updates_url, gpgpath),
            ],
        )

        packages = {"basesystem-minimal", *self.packages}
        if not do_run_build_script and self._args.bootable:
            packages |= {"kernel-server-latest", "binutils", "dracut"}

            configure_dracut(self._args, root)
            # Mageia ships /etc/50-mageia.conf that omits systemd from the initramfs and disables hostonly.
            # We override that again so our defaults get applied correctly on Mageia as well.
            with open(os.path.join(root, "etc/dracut.conf.d/51-mkosi-override-mageia.conf"), "w") as f:
                f.write("hostonly=no\n")
                f.write('omit_dracutmodules=""\n')
        if do_run_build_script:
            packages.update(self.build_packages)
        invoke_dnf(self._args, root, self.repositories or ["mageia", "updates"], packages, do_run_build_script)

        disable_pam_securetty(root)

    def sanity_check(self) -> None:
        if not self._args.with_unified_kernel_images and "uefi" in self._args.boot_protocols:
            die("Sorry, --without-unified-kernel-images is not supported in UEFI mode on this distro.")
