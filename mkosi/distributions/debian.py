# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
from pathlib import Path
from subprocess import PIPE
from typing import (
    AbstractSet,
    ClassVar,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Set,
    cast,
)

from ..backend import (
    Distribution,
    MkosiArgs,
    OutputFormat,
    PartitionIdentifier,
    PathString,
    add_packages,
    complete_step,
    disable_pam_securetty,
    install_skeleton_trees,
    run,
    run_workspace_command,
    unlink_try_hard,
)
from ..distributions import DistributionInstaller, configure_dracut


class DebianInstaller(DistributionInstaller):
    _default_release: ClassVar[str] = "testing"
    _default_mirror: ClassVar[Dict[Optional[str], str]] = {
        "x86_64": "http://deb.debian.org/debian"
    }

    _repos_for_boot: ClassVar[FrozenSet[str]] = frozenset()
    _kernel_package: ClassVar[str] = "linux-image-amd64"

    def hook_install_etc_locale(self, root: Path, cached: bool) -> None:
        # Debian/Ubuntu use a different path to store the locale so let's make sure that path is a symlink to
        # etc/locale.conf.
        try:
            root.joinpath("etc/default/locale").unlink()
        except FileNotFoundError:
            pass
        root.joinpath("etc/default/locale").symlink_to("../locale.conf")

    def which_cache_directory(self, root: Path) -> Path:
        return root / "var/cache/apt/archives"

    def hook_configure_dracut(self, packages: Set[str], root: Path) -> None:
        dracut_dir = root / "etc/dracut.conf.d"
        dracut_dir.joinpath("30-mkosi-uefi-stub.conf").write_text(
            "uefi_stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub\n"
        )

    def hook_prepare_tree(self, root: Path, do_run_build_script: bool, cached: bool) -> None:
        # Make sure kernel-install actually runs when needed by creating the machine-id subdirectory
        # under /boot. For "bios" on Debian/Ubuntu, it's required for grub to pick up the generated
        # initrd. For "linux", we need kernel-install to run so we can extract the generated initrd
        # from /boot later.
        if "bios" in self.boot_protocols:
            root.joinpath("boot", self.machine_id).mkdir(mode=0o700, exist_ok=True)

    def hook_rpmdb_fixup(self, root: Path) -> None:
        # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/
        # so it needs to be copied back in the right location, otherwise
        # the rpmdb will be broken. See: https://bugs.debian.org/1004863
        rpmdb_home = root / "root/.rpmdb"
        if rpmdb_home.exists():
            # Take into account the new location in F36
            rpmdb = root / "usr/lib/sysimage/rpm"
            if not rpmdb.exists():
                rpmdb = root / "var/lib/rpm"
            unlink_try_hard(rpmdb)
            shutil.move(cast(str, rpmdb_home), rpmdb)

    def hook_install(self, root: Path, *, do_run_build_script: bool) -> None:
        install_debian_or_ubuntu(self, root, do_run_build_script=do_run_build_script)

    def which_grub(self) -> str:
        return "/usr/sbin/grub"

    def which_kernel_image(self, kernel_version: str) -> Path:
        return Path(f"boot/vmlinuz-{kernel_version}")

    def hook_run_kernel_install(self, root: Path, do_run_build_script: bool, for_cache: bool, cached: bool) -> None:
        run_workspace_command(self, root, ["dpkg-reconfigure", "dracut"])

    def hook_remove_packages(self, root: Path) -> None:
        if self.remove_packages:
            with complete_step(f"Removing {len(self.packages)} packages…"):
                invoke_apt(self, False, root, "purge", ["--auto-remove", *self.remove_packages])

    def _updates_repo(self, repos: AbstractSet[str]) -> str:
        return f"deb http://deb.debian.org/debian {self.release}-updates {' '.join(repos)}"

    def _security_repo(self, repos: AbstractSet[str]) -> str:
        if self.release in ("stretch", "buster"):
            return f"deb http://security.debian.org/debian-security/ {self.release}/updates main"
        else:
            return f"deb https://security.debian.org/debian-security {self.release}-security main"


# Debian calls their architectures differently, so when calling debootstrap we
# will have to map to their names
DEBIAN_ARCHITECTURES = {
    "x86_64": "amd64",
    "x86": "i386",
    "aarch64": "arm64",
    "armhfp": "armhf",
}


def debootstrap_knows_arg(arg: str) -> bool:
    return bytes("invalid option", "UTF-8") not in run(["debootstrap", arg], stdout=PIPE, check=False).stdout


def invoke_apt(
    args: MkosiArgs,
    do_run_build_script: bool,
    root: Path,
    command: str,
    extra: Iterable[str],
) -> None:

    cmdline = ["/usr/bin/apt-get", "--assume-yes", command, *extra]
    env = dict(
        DEBIAN_FRONTEND="noninteractive",
        DEBCONF_NONINTERACTIVE_SEEN="true",
        INITRD="No",
    )

    run_workspace_command(args, root, cmdline, network=True, env=env)


def install_debian_or_ubuntu(args: DebianInstaller, root: Path, *, do_run_build_script: bool) -> None:
    # Either the image builds or it fails and we restart, we don't need safety fsyncs when bootstrapping
    # Add it before debootstrap, as the second stage already uses dpkg from the chroot
    dpkg_io_conf = root / "etc/dpkg/dpkg.cfg.d/unsafe_io"
    os.makedirs(dpkg_io_conf.parent, mode=0o755, exist_ok=True)
    dpkg_io_conf.write_text("force-unsafe-io\n")

    repos = set(args.repositories) or {"main"}
    if args.bootable:
        repos |= args._repos_for_boot

    # debootstrap fails if a base image is used with an already populated root, so skip it.
    if args.base_image is None:
        cmdline: List[PathString] = [
            "debootstrap",
            "--variant=minbase",
            "--include=ca-certificates",
            "--merged-usr",
            f"--components={','.join(repos)}",
        ]

        if args.architecture is not None:
            debarch = DEBIAN_ARCHITECTURES.get(args.architecture)
            cmdline += [f"--arch={debarch}"]

        # Let's use --no-check-valid-until only if debootstrap knows it
        if debootstrap_knows_arg("--no-check-valid-until"):
            cmdline += ["--no-check-valid-until"]

        assert args.mirror is not None
        cmdline += [args.release, root, args.mirror]
        run(cmdline)

    # Install extra packages via the secondary APT run, because it is smarter and can deal better with any
    # conflicts. dbus and libpam-systemd are optional dependencies for systemd in debian so we include them
    # explicitly.
    extra_packages: Set[str] = set()
    add_packages(args, extra_packages, "systemd", "systemd-sysv", "dbus", "libpam-systemd")
    extra_packages.update(args.packages)

    if do_run_build_script:
        extra_packages.update(args.build_packages)

    if not do_run_build_script and args.bootable:
        add_packages(args, extra_packages, "dracut")
        configure_dracut(args, extra_packages, root)

        add_packages(args, extra_packages, args._kernel_package)

        if args.get_partition(PartitionIdentifier.bios):
            add_packages(args, extra_packages, "grub-pc")

        if args.output_format == OutputFormat.gpt_btrfs:
            add_packages(args, extra_packages, "btrfs-progs")

    if not do_run_build_script and args.ssh:
        add_packages(args, extra_packages, "openssh-server")

    # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
    # start. Let's install one that denies all daemon startups.
    # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
    # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
    # the admin.
    policyrcd = root / "usr/sbin/policy-rc.d"
    policyrcd.write_text("#!/bin/sh\nexit 101\n")
    policyrcd.chmod(0o755)

    doc_paths = [
        "/usr/share/locale",
        "/usr/share/doc",
        "/usr/share/man",
        "/usr/share/groff",
        "/usr/share/info",
        "/usr/share/lintian",
        "/usr/share/linda",
    ]
    if not args.with_docs:
        # Remove documentation installed by debootstrap
        cmdline = ["/bin/rm", "-rf", *doc_paths]
        run_workspace_command(args, root, cmdline)
        # Create dpkg.cfg to ignore documentation on new packages
        dpkg_nodoc_conf = root / "etc/dpkg/dpkg.cfg.d/01_nodoc"
        with dpkg_nodoc_conf.open("w") as f:
            f.writelines(f"path-exclude {d}/*\n" for d in doc_paths)

    if not do_run_build_script and args.bootable and args.with_unified_kernel_images and args.base_image is None:
        # systemd-boot won't boot unified kernel images generated without a BUILD_ID or VERSION_ID in
        # /etc/os-release. Build one with the mtime of os-release if we don't find them.
        with root.joinpath("etc/os-release").open("r+") as f:
            os_release = f.read()
            if "VERSION_ID" not in os_release and "BUILD_ID" not in os_release:
                f.write(f"BUILD_ID=mkosi-{args.release}\n")

    if args.release not in ("testing", "unstable"):
        updates = args._updates_repo(repos)
        root.joinpath(f"etc/apt/sources.list.d/{args.release}-updates.list").write_text(f"{updates}\n")

        security = args._security_repo(repos)
        root.joinpath(f"etc/apt/sources.list.d/{args.release}-security.list").write_text(f"{security}\n")

    install_skeleton_trees(args, root, False, late=True)

    invoke_apt(args, do_run_build_script, root, "update", [])

    if args.bootable and not do_run_build_script and args.get_partition(PartitionIdentifier.esp):
        if run_workspace_command(args, root, ["apt-cache", "search", "--names-only", "^systemd-boot$"],
                                 capture_stdout=True).stdout.strip() != "":
            add_packages(args, extra_packages, "systemd-boot")

    invoke_apt(args, do_run_build_script, root, "install", ["--no-install-recommends", *extra_packages])

    policyrcd.unlink()
    dpkg_io_conf.unlink()
    if not args.with_docs and args.base_image is not None:
        # Don't ship dpkg config files in extensions, they belong with dpkg in the base image.
        dpkg_nodoc_conf.unlink() # type: ignore

    if args.base_image is None:
        # Debian still has pam_securetty module enabled, disable it in the base image.
        disable_pam_securetty(root)

    if args.distribution == Distribution.debian and "systemd" in extra_packages:
        # The default resolv.conf points to 127.0.0.1, and resolved is disabled, fix it in
        # the base image.
        root.joinpath("etc/resolv.conf").unlink()
        root.joinpath("etc/resolv.conf").symlink_to("../run/systemd/resolve/resolv.conf")
        run(["systemctl", "--root", root, "enable", "systemd-resolved"])
