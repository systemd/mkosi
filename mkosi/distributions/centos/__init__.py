# SPDX-License-Identifier: LGPL-2.1+

import os
from typing import Dict, List, Optional, Set

from mkosi import Repo, configure_dracut, invoke_dnf_or_yum, setup_dnf
from mkosi.backend import (
    CommandLineArguments,
    DistributionInstaller,
    OutputFormat,
    die,
    nspawn_params_for_blockdev_access,
    patch_file,
    run_workspace_command,
    write_grub_config,
)


def install_centos_old(args: CommandLineArguments, root: str, epel_release: int) -> List[str]:
    # Repos for CentOS 7 and earlier

    gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-{args.release}"
    gpgurl = f"https://www.centos.org/keys/RPM-GPG-KEY-CentOS-{args.release}"
    epel_gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}"
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        release_url = f"baseurl={args.mirror}/centos/{args.release}/os/x86_64"
        updates_url = f"baseurl={args.mirror}/centos/{args.release}/updates/x86_64/"
        extras_url = f"baseurl={args.mirror}/centos/{args.release}/extras/x86_64/"
        centosplus_url = f"baseurl={args.mirror}/centos/{args.release}/centosplus/x86_64/"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/x86_64/"
    else:
        release_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=os"
        updates_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=updates"
        extras_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=extras"
        centosplus_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=centosplus"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=x86_64"

    setup_dnf(
        args,
        root,
        repos=[
            Repo("base", f"CentOS-{args.release} - Base", release_url, gpgpath, gpgurl),
            Repo("updates", f"CentOS-{args.release} - Updates", updates_url, gpgpath, gpgurl),
            Repo("extras", f"CentOS-{args.release} - Extras", extras_url, gpgpath, gpgurl),
            Repo("centosplus", f"CentOS-{args.release} - Plus", centosplus_url, gpgpath, gpgurl),
            Repo(
                "epel",
                f"name=Extra Packages for Enterprise Linux {epel_release} - $basearch",
                epel_url,
                epel_gpgpath,
                epel_gpgurl,
            ),
        ],
    )

    return ["base", "updates", "extras", "centosplus"]


def install_centos_new(args: CommandLineArguments, root: str, epel_release: int) -> List[str]:
    # Repos for CentOS 8 and later

    gpgpath = "/etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial"
    gpgurl = "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official"
    epel_gpgpath = f"/etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-{epel_release}"
    epel_gpgurl = f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{epel_release}"

    if args.mirror:
        appstream_url = f"baseurl={args.mirror}/centos/{args.release}/AppStream/x86_64/os"
        baseos_url = f"baseurl={args.mirror}/centos/{args.release}/BaseOS/x86_64/os"
        extras_url = f"baseurl={args.mirror}/centos/{args.release}/extras/x86_64/os"
        centosplus_url = f"baseurl={args.mirror}/centos/{args.release}/centosplus/x86_64/os"
        epel_url = f"baseurl={args.mirror}/epel/{epel_release}/Everything/x86_64"
    else:
        appstream_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=AppStream"
        baseos_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=BaseOS"
        extras_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=extras"
        centosplus_url = f"mirrorlist=http://mirrorlist.centos.org/?release={args.release}&arch=x86_64&repo=centosplus"
        epel_url = f"mirrorlist=https://mirrors.fedoraproject.org/mirrorlist?repo=epel-{epel_release}&arch=x86_64"

    setup_dnf(
        args,
        root,
        repos=[
            Repo("AppStream", f"CentOS-{args.release} - AppStream", appstream_url, gpgpath, gpgurl),
            Repo("BaseOS", f"CentOS-{args.release} - Base", baseos_url, gpgpath, gpgurl),
            Repo("extras", f"CentOS-{args.release} - Extras", extras_url, gpgpath, gpgurl),
            Repo("centosplus", f"CentOS-{args.release} - Plus", centosplus_url, gpgpath, gpgurl),
            Repo(
                "epel",
                f"name=Extra Packages for Enterprise Linux {epel_release} - $basearch",
                epel_url,
                epel_gpgpath,
                epel_gpgurl,
            ),
        ],
    )

    return ["AppStream", "BaseOS", "extras", "centosplus"]


class CentOS(DistributionInstaller):
    _default_release = "8"
    supports_with_documentation = True

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
        # CentOS 7 contains some very old versions of certain libraries
        # which require workarounds in different places.
        # Additionally the repositories have been changed between 7 and 8
        self._epel_release = int(self.release.split(".")[0])
        self._old = self._epel_release <= 7

    @property
    def package_cache(self) -> List[str]:
        # We mount both the YUM and the DNF cache in this case, as YUM might
        # just be redirected to DNF even if we invoke the former
        return ["var/cache/yum", "var/cache/dnf"]

    @property
    def mkfs_args(self) -> List[str]:
        # e2fsprogs in centos7 is too old and doesn't support this feature
        return ["-O", "^metadata_csum"] if self._old else []

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        if self._old:
            default_repos = install_centos_old(self._args, root, self._epel_release)
        else:
            default_repos = install_centos_new(self._args, root, self._epel_release)

        if not self._repositories:
            self._repositories = default_repos
        packages = {"centos-release", "systemd", *self.packages}
        if not do_run_build_script and self._args.bootable:
            packages |= {"kernel", "dracut", "binutils"}
            configure_dracut(self._args, root)
            if self._old:
                packages |= {
                    "grub2-efi",
                    "grub2-tools",
                    "grub2-efi-x64-modules",
                    "shim-x64",
                    "efibootmgr",
                    "efivar-libs",
                }
            else:
                # this does not exist on CentOS 7
                packages.add("systemd-udev")

        if do_run_build_script:
            packages.update(self.build_packages)

        if not do_run_build_script and "epel-release" in self.packages and self._args.network_veth:
            packages.add("systemd-networkd")

        invoke_dnf_or_yum(self._args, root, self.repositories, packages, do_run_build_script)

    def install_bootloader_efi(self, root: str, loopdev: str) -> None:
        if not self._old:
            return super().install_bootloader_efi(root, loopdev)

        nspawn_params = nspawn_params_for_blockdev_access(self._args, loopdev)

        # prepare EFI directory on ESP
        os.makedirs(os.path.join(root, "efi/EFI/centos"), exist_ok=True)

        # patch existing or create minimal GRUB_CMDLINE config
        write_grub_config(self._args, root)

        # generate grub2 efi boot config
        cmdline = ["/sbin/grub2-mkconfig", "-o", "/efi/EFI/centos/grub.cfg"]
        run_workspace_command(self._args, root, cmdline, nspawn_params=nspawn_params)

        # if /sys/firmware/efi is not present within systemd-nspawn the grub2-mkconfig makes false assumptions, let's fix this
        def _fix_grub(line: str) -> str:
            if "linux16" in line:
                return line.replace("linux16", "linuxefi")
            elif "initrd16" in line:
                return line.replace("initrd16", "initrdefi")
            return line

        patch_file(os.path.join(root, "efi/EFI/centos/grub.cfg"), _fix_grub)

    def sanity_check(self) -> None:
        epel_release = int(self.release.split(".")[0])

        if epel_release <= 8 and self._args.output_format == OutputFormat.gpt_btrfs:
            die(f"Sorry, CentOS {epel_release} does not support btrfs")

        if (
            epel_release <= 7
            and self._args.bootable
            and "uefi" in self._args.boot_protocols
            and self._args.with_unified_kernel_images
        ):
            die(
                f"Sorry, CentOS {epel_release} does not support unified kernel images. "
                "You must use --without-unified-kernel-images."
            )
