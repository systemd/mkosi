# SPDX-License-Identifier: LGPL-2.1+

import shutil
from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import invoke_dnf, setup_dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die
from mkosi.state import MkosiState


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "OpenMandriva"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def default_release(cls) -> str:
        return "cooker"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.openmandriva

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        mirror = state.config.mirror or "http://mirror.openmandriva.org"

        gpgurls = (
            find_rpm_gpgkey(
                state,
                "RPM-GPG-KEY-OpenMandriva",
                "https://raw.githubusercontent.com/OpenMandrivaAssociation/openmandriva-repos/master/RPM-GPG-KEY-OpenMandriva",
            ),
        )

        repos = []

        if state.config.local_mirror:
            repos += [RpmRepository("main-release", f"baseurl={state.config.local_mirror}", gpgurls)]
        else:
            url = f"baseurl={join_mirror(mirror, '$releasever/repository/$basearch/main')}"
            repos += [
                RpmRepository("main-release", f"{url}/release", gpgurls),
                RpmRepository("main-updates", f"{url}/updates", gpgurls),
            ]

        setup_dnf(state, repos)

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(state, "install", packages, apivfs=apivfs)

        for d in state.root.glob("boot/vmlinuz-*"):
            kver = d.name.removeprefix("vmlinuz-")
            vmlinuz = state.root / "usr/lib/modules" / kver / "vmlinuz"
            # Openmandriva symlinks /usr/lib/modules/<kver>/vmlinuz to /boot/vmlinuz-<kver>, so get rid of the symlink
            # and put the actual vmlinuz in /usr/lib/modules/<kver>.
            if vmlinuz.is_symlink():
                vmlinuz.unlink()
            if not vmlinuz.exists():
                shutil.copy2(d, vmlinuz)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64  : "x86_64",
            Architecture.arm64   : "aarch64",
            Architecture.riscv64 : "riscv64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by OpenMandriva")

        return a
