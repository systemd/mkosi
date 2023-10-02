# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.architecture import Architecture
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer.pacman import invoke_pacman, setup_pacman
from mkosi.log import die
from mkosi.state import MkosiState


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Arch Linux"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.pkg

    @classmethod
    def default_release(cls) -> str:
        return "rolling"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.arch

    @classmethod
    def tools_tree_packages(cls) -> list[str]:
        return [
            "archlinux-keyring",
            "base",
            "bash",
            "btrfs-progs",
            "bubblewrap",
            "ca-certificates",
            "coreutils",
            "cpio",
            "curl",
            "debian-archive-keyring",
            "dnf",
            "dosfstools",
            "e2fsprogs",
            "edk2-ovmf",
            "erofs-utils",
            "mtools",
            "openssh",
            "openssl",
            "pacman",
            "pesign",
            "python-cryptography",
            "qemu-base",
            "sbsigntools",
            "socat",
            "squashfs-tools",
            "strace",
            "swtpm",
            "systemd-ukify",
            "systemd",
            "tar",
            "util-linux",
            "virtiofsd",
            "xfsprogs",
            "xz",
            "zstd",
        ]

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        setup_pacman(state)

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_pacman(state, packages, apivfs=apivfs)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Arch Linux")

        return a

