# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
from textwrap import dedent
from typing import List, Optional, Set

from mkosi.backend import (
    CommandLineArguments,
    DistributionInstaller,
    OutputFormat,
    die,
    nspawn_params_for_blockdev_access,
    run,
    run_workspace_command,
)


class Clear(DistributionInstaller):
    _default_release = "latest"

    def __str__(self) -> str:
        return "Clear Linux"

    @property
    def cache_path(self) -> str:
        # Clear has a release number that can be used, however the
        # cache is valid (and more efficient) across releases.
        return f"{self.__class__.__name__.lower()}"

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        if self.release == "latest":
            release = "clear"
        else:
            release = "clear/" + self.release

        packages = {"os-core-plus", *self.packages}
        if do_run_build_script:
            packages.update(self.build_packages)
        if not do_run_build_script and self._args.bootable:
            packages.add("kernel-native")
        if not do_run_build_script and self._args.ssh:
            packages.add("openssh-server")

        swupd_extract = shutil.which("swupd-extract")

        if swupd_extract is None:
            die(
                dedent(
                    """
                    Couldn't find swupd-extract program, download (or update it) it using:

                      go get -u github.com/clearlinux/mixer-tools/swupd-extract

                    and it will be installed by default in ~/go/bin/swupd-extract. Also
                    ensure that you have openssl program in your system.
                    """
                )
            )

        cmdline = [swupd_extract, "-output", root]
        if self.cache_path:
            cmdline += ["-state", self.cache_path]
        cmdline += [release, *packages]

        run(cmdline)

        os.symlink("../run/systemd/resolve/resolv.conf", os.path.join(root, "etc/resolv.conf"))

        # Clear Linux doesn't have a /etc/shadow at install time, it gets
        # created when the root first login. To set the password via
        # mkosi, create one.
        if not do_run_build_script and self._args.password is not None:
            shadow_file = os.path.join(root, "etc/shadow")
            with open(shadow_file, "w") as f:
                f.write("root::::::::")
            os.chmod(shadow_file, 0o400)
            # Password is already empty for root, so no need to reset it later.
            if self._args.password == "":
                self._args.password = None

    def install_bootloader_efi(self, root: str, loopdev: str) -> None:
        pass

    def install_bootloader_bios(self, root: str, loopdev: str) -> None:
        # clr-boot-manager uses blkid in the device backing "/" to
        # figure out uuid and related parameters.
        nspawn_params = nspawn_params_for_blockdev_access(self._args, loopdev)

        cmdline = ["/usr/bin/clr-boot-manager", "update", "-i"]
        run_workspace_command(self._args, root, cmdline, nspawn_params=nspawn_params)

    def sanity_check(self) -> None:
        # Remove once https://github.com/clearlinux/clr-boot-manager/pull/238 is merged and available.
        if self._args.output_format == OutputFormat.gpt_btrfs:
            die("Sorry, Clear Linux does not support btrfs")

        if "," in self._args.boot_protocols:
            die("Sorry, Clear Linux does not support hybrid BIOS/UEFI images")

        if self._args.bootable:
            die("Sorry, --bootable is not supported on this distro")
