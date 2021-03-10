# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
from typing import List, Optional, Set

from mkosi import configure_dracut, mount_api_vfs
from mkosi.backend import (
    CommandLineArguments,
    DistributionInstaller,
    OutputFormat,
    die,
    install_grub,
    patch_file,
    run,
)


class OpenSuse(DistributionInstaller):
    _default_release = "tumbleweed"

    def __str__(self) -> str:
        return "openSUSE"

    @property
    def mirror(self) -> str:
        if self._mirror is None:
            return "http://download.opensuse.org"
        return self._mirror

    @property
    def package_cache(self) -> List[str]:
        return ["var/cache/zypp/packages"]

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        release = self.release.strip('"')

        # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy (14.x won't ever appear). For
        # anything else, let's default to Leap.
        if release.isdigit() or release == "tumbleweed":
            release_url = f"{self.mirror}/tumbleweed/repo/oss/"
            updates_url = f"{self.mirror}/update/tumbleweed/"
        elif release == "leap":
            release_url = f"{self.mirror}/distribution/leap/15.1/repo/oss/"
            updates_url = f"{self.mirror}/update/leap/15.1/oss/"
        elif release == "current":
            release_url = f"{self.mirror}/distribution/openSUSE-stable/repo/oss/"
            updates_url = f"{self.mirror}/update/openSUSE-current/"
        elif release == "stable":
            release_url = f"{self.mirror}/distribution/openSUSE-stable/repo/oss/"
            updates_url = f"{self.mirror}/update/openSUSE-stable/"
        else:
            release_url = f"{self.mirror}/distribution/leap/{release}/repo/oss/"
            updates_url = f"{self.mirror}/update/leap/{release}/oss/"

        # Configure the repositories: we need to enable packages caching here to make sure that the package cache
        # stays populated after "zypper install".
        run(["zypper", "--root", root, "addrepo", "-ck", release_url, "repo-oss"])
        run(["zypper", "--root", root, "addrepo", "-ck", updates_url, "repo-update"])

        if not self._args.with_docs:
            with open(os.path.join(root, "etc/zypp/zypp.conf"), "w") as f:
                f.write("rpm.install.excludedocs = yes\n")

        packages = {"systemd", *self.packages}

        if release.startswith("42."):
            packages.add("patterns-openSUSE-minimal_base")
        else:
            packages.add("patterns-base-minimal_base")

        if not do_run_build_script and self._args.bootable:
            packages.add("kernel-default")
            packages.add("dracut")
            packages.add("binutils")

            configure_dracut(self._args, root)

            if self._args.bios_partno is not None:
                packages.add("grub2")

        if not do_run_build_script and self._args.encrypt:
            packages.add("device-mapper")

        if self._args.output_format in (OutputFormat.subvolume, OutputFormat.gpt_btrfs):
            packages.add("btrfsprogs")

        if do_run_build_script:
            packages.update(self.build_packages)

        if not do_run_build_script and self._args.ssh:
            packages.update("openssh-server")

        cmdline = [
            "zypper",
            "--root",
            root,
            "--gpg-auto-import-keys",
            "install",
            "-y",
            "--no-recommends",
            "--download-in-advance",
            *packages,
        ]

        with mount_api_vfs(self._args, root):
            run(cmdline)

        # Disable packages caching in the image that was enabled previously to populate the package cache.
        run(["zypper", "--root", root, "modifyrepo", "-K", "repo-oss"])
        run(["zypper", "--root", root, "modifyrepo", "-K", "repo-update"])

        if self._args.password == "":
            shutil.copy2(os.path.join(root, "usr/etc/pam.d/common-auth"), os.path.join(root, "etc/pam.d/common-auth"))

            def jj(line: str) -> str:
                if "pam_unix.so" in line:
                    return f"{line.strip()} nullok"
                return line

            patch_file(os.path.join(root, "etc/pam.d/common-auth"), jj)

        if self._args.autologin:
            # copy now, patch later (in set_autologin())
            shutil.copy2(os.path.join(root, "usr/etc/pam.d/login"), os.path.join(root, "etc/pam.d/login"))

    def install_bootloader_bios(self, root: str, loopdev: str) -> None:
        install_grub(self._args, root, loopdev, "/usr/sbin/grub2")

    def sanity_check(self) -> None:
        if not self._args.with_unified_kernel_images and "uefi" in self._args.boot_protocols:
            die("Sorry, --without-unified-kernel-images is not supported in UEFI mode on this distro.")
