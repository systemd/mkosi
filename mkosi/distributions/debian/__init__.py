# SPDX-License-Identifier: LGPL-2.1+
import os
from subprocess import PIPE
from typing import List, Optional, Set

from mkosi import (
    configure_dracut,
    debootstrap_knows_arg,
    disable_pam_securetty,
    dracut_configure_uefi_stub,
)
from mkosi.backend import (
    CommandLineArguments,
    DistributionInstaller,
    OutputFormat,
    die,
    install_grub,
    run,
    run_workspace_command,
)

# Debian calls their architectures differently, so when calling debootstrap we
# will have to map to their names
DEBIAN_ARCHITECTURES = {
    "x86_64": "amd64",
    "x86": "i386",
    "aarch64": "arm64",
    "armhfp": "armhf",
}


class Debian(DistributionInstaller):
    _default_release = "unstable"
    unit_name_ssh = "sshd"
    pam_device_prefix = "/dev"

    _kernel_package = "linux-image-amd64"

    def __init__(
        self,
        args: CommandLineArguments,
        repositories: Optional[List[str]] = None,
        release: Optional[str] = None,
        mirror: Optional[str] = None,
        architecture: Optional[str] = None,
        packages: Optional[Set[str]] = None,
        build_packages: Optional[Set[str]] = None,
    ):
        super().__init__(args, repositories, release, mirror, architecture, packages, build_packages)
        if not self._repositories:
            self._repositories = ["main"]

    @property
    def mirror(self) -> str:
        if self._mirror is None:
            return "http://deb.debian.org/debian"
        return self._mirror

    @property
    def package_cache(self) -> List[str]:
        return ["var/cache/apt/archives"]

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        cmdline = ["debootstrap", "--variant=minbase", "--merged-usr", f"--components={','.join(self.repositories)}"]

        if self.architecture is not None:
            debarch = DEBIAN_ARCHITECTURES.get(self.architecture)
            cmdline += [f"--arch={debarch}"]

        # Let's use --no-check-valid-until only if debootstrap knows it
        if debootstrap_knows_arg("--no-check-valid-until"):
            cmdline.append("--no-check-valid-until")

        # Either the image builds or it fails and we restart, we don't need safety fsyncs when bootstrapping
        # Add it before debootstrap, as the second stage already uses dpkg from the chroot
        dpkg_io_conf = os.path.join(root, "etc/dpkg/dpkg.cfg.d/unsafe_io")
        os.makedirs(os.path.dirname(dpkg_io_conf), mode=0o755, exist_ok=True)
        with open(dpkg_io_conf, "w") as f:
            f.write("force-unsafe-io\n")

        cmdline += [self.release, root, self.mirror]
        run(cmdline)

        # Install extra packages via the secondary APT run, because it is smarter and can deal better with any
        # conflicts. dbus and libpam-systemd are optional dependencies for systemd in debian so we include them
        # explicitly.
        extra_packages = {"systemd", "systemd-sysv", "dbus", "libpam-systemd"}
        extra_packages.update(self.packages)

        if do_run_build_script:
            extra_packages.update(self.build_packages)

        if not do_run_build_script and self._args.bootable:
            extra_packages.add("dracut")
            extra_packages.add("binutils")

            configure_dracut(self._args, root)

            extra_packages.add(self._kernel_package)

            if self._args.bios_partno:
                extra_packages.add("grub-pc")

            if self._args.output_format == OutputFormat.gpt_btrfs:
                extra_packages.add("btrfs-progs")

        if not do_run_build_script and self._args.ssh:
            extra_packages.add("openssh-server")

        # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
        # start. Let's install one that denies all daemon startups.
        # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
        # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
        # the admin.
        policyrcd = os.path.join(root, "usr/sbin/policy-rc.d")
        with open(policyrcd, "w") as f:
            f.write("#!/bin/sh\nexit 101\n")
        os.chmod(policyrcd, 0o755)

        doc_paths = [
            "/usr/share/locale",
            "/usr/share/doc",
            "/usr/share/man",
            "/usr/share/groff",
            "/usr/share/info",
            "/usr/share/lintian",
            "/usr/share/linda",
        ]
        if not self._args.with_docs:
            # Remove documentation installed by debootstrap
            cmdline = ["/bin/rm", "-rf"] + doc_paths
            run_workspace_command(self._args, root, cmdline)
            # Create dpkg.cfg to ignore documentation on new packages
            dpkg_conf = os.path.join(root, "etc/dpkg/dpkg.cfg.d/01_nodoc")
            with open(dpkg_conf, "w") as f:
                f.writelines(f"path-exclude {d}/*\n" for d in doc_paths)

        cmdline = ["/usr/bin/apt-get", "--assume-yes", "--no-install-recommends", "install", *extra_packages]
        env = {
            "DEBIAN_FRONTEND": "noninteractive",
            "DEBCONF_NONINTERACTIVE_SEEN": "true",
        }

        if not do_run_build_script and self._args.bootable and self._args.with_unified_kernel_images:
            # Disable dracut postinstall script for this apt-get run.
            env["INITRD"] = "No"
            self._fix_os_release(root)

        run_workspace_command(self._args, root, cmdline, network=True, env=env)
        os.unlink(policyrcd)
        os.unlink(dpkg_io_conf)
        # Debian still has pam_securetty module enabled
        disable_pam_securetty(root)

    def configure_dracut(self, dracut_dir: str) -> None:
        dracut_configure_uefi_stub(dracut_dir)

    def install_bootloader_bios(self, root: str, loopdev: str) -> None:
        install_grub(self._args, root, loopdev, "/usr/sbin/grub")

    def sanity_check(self) -> None:
        if not self._args.with_unified_kernel_images and "uefi" in self._args.boot_protocols:
            die("Sorry, --without-unified-kernel-images is not supported in UEFI mode on this distro.")

    def _fix_os_release(self, root: str) -> None:
        # systemd-boot won't boot unified kernel images generated without a BUILD_ID or VERSION_ID in
        # /etc/os-release.
        if self.release == "unstable":
            with open(os.path.join(root, "etc/os-release"), "a") as f:
                f.write("BUILD_ID=unstable\n")
