# SPDX-License-Identifier: LGPL-2.1+

from __future__ import annotations

from pathlib import Path
from typing import Set

from ..backend import Distribution, MkosiArgs, PartitionIdentifier

DRACUT_SYSTEMD_EXTRAS = [
    "/usr/bin/systemd-repart",
    "/usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "/usr/lib/systemd/system/initrd-root-fs.target.wants/systemd-repart.service",
    "/usr/lib/systemd/system/initrd-usr-fs.target",
    "/usr/lib/systemd/system/sysinit.target.wants/veritysetup.target",
    "/usr/lib/systemd/system/systemd-repart.service",
    "/usr/lib/systemd/system/systemd-volatile-root.service",
    "/usr/lib/systemd/system/veritysetup.target",
    "/usr/lib/systemd/systemd-veritysetup",
    "/usr/lib/systemd/systemd-volatile-root",
    "/usr/bin/systemd-ask-password",
    "/usr/bin/systemd-tty-ask-password-agent"
]


def configure_dracut(args: MkosiArgs, packages: Set[str], root: Path) -> None:
    if "dracut" not in packages:
        return

    dracut_dir = root / "etc/dracut.conf.d"
    dracut_dir.mkdir(mode=0o755)

    dracut_dir.joinpath('30-mkosi-hostonly.conf').write_text(
        f'hostonly={"yes" if args.hostonly_initrd else "no"}\n'
        'hostonly_default_device=no\n'
    )

    dracut_dir.joinpath("30-mkosi-qemu.conf").write_text('add_dracutmodules+=" qemu "\n')

    with dracut_dir.joinpath("30-mkosi-systemd-extras.conf").open("w") as f:
        for extra in DRACUT_SYSTEMD_EXTRAS:
            f.write(f'install_optional_items+=" {extra} "\n')

    if args.hostonly_initrd:
        dracut_dir.joinpath("30-mkosi-filesystem.conf").write_text(
            f'filesystems+=" {(args.output_format.needed_kernel_module())} "\n'
        )

    if args.get_partition(PartitionIdentifier.esp):
        # These distros need uefi_stub configured explicitly for dracut to find the systemd-boot uefi stub.
        if args.distribution in (Distribution.ubuntu,
                                 Distribution.debian,
                                 Distribution.mageia,
                                 Distribution.openmandriva,
                                 Distribution.gentoo):
            dracut_dir.joinpath("30-mkosi-uefi-stub.conf").write_text(
                "uefi_stub=/usr/lib/systemd/boot/efi/linuxx64.efi.stub\n"
            )

        # efivarfs must be present in order to GPT root discovery work
        dracut_dir.joinpath("30-mkosi-efivarfs.conf").write_text(
            '[[ $(modinfo -k "$kernel" -F filename efivarfs 2>/dev/null) == /* ]] && add_drivers+=" efivarfs "\n'
        )


class DistributionInstaller(MkosiArgs):
    def hook_install_etc_locale(self, root: Path, cached: bool) -> None:
        pass

    def which_cache_directory(self, root: Path) -> Path:
        raise NotImplementedError

    def hook_configure_dracut(self, packages: Set[str], root: Path) -> None:
        pass

    def hook_prepare_tree(self, root: Path, do_run_build_script: bool, cached: bool) -> None:
        pass

    def hook_rpmdb_fixup(self, root: Path) -> None:
        pass

    def hook_install(self, root: Path, *, do_run_build_script: bool) -> None:
        pass

    def which_grub(self) -> str:
        return "grub"

    def which_kernel_image(self, kernel_version: str) -> Path:
        return Path("lib/modules") / kernel_version / "vmlinuz"

    def hook_run_kernel_install(self, root: Path, do_run_build_script: bool, for_cache: bool, cached: bool) -> None:
        pass

    def hook_remove_packages(self, root: Path) -> None:
        pass
