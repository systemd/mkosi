# SPDX-License-Identifier: LGPL-2.1+

import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller, PackageType
from mkosi.installer.apt import invoke_apt, setup_apt
from mkosi.log import die
from mkosi.run import run
from mkosi.state import MkosiState


class DebianInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.deb

    @staticmethod
    def repositories(state: MkosiState, local: bool = True) -> list[str]:
        assert state.config.mirror

        archives = ("deb", "deb-src")
        components = ' '.join(("main", *state.config.repositories))

        if state.config.local_mirror and local:
            return [f"deb [trusted=yes] {state.config.local_mirror} {state.config.release} {components}"]

        repos = [
            f"{archive} {state.config.mirror} {state.config.release} {components}"
            for archive in archives
        ]

        # Debug repos are typically not mirrored.
        repos += [f"deb http://deb.debian.org/debian-debug {state.config.release}-debug {components}"]

        if state.config.release in ("unstable", "sid"):
            return repos

        repos += [
            f"{archive} {state.config.mirror} {state.config.release}-updates {components}"
            for archive in archives
        ]

        # Security updates repos are never mirrored
        repos += [
            f"{archive} http://security.debian.org/debian-security {state.config.release}-security {components}"
            for archive in archives
        ]

        return repos

    @classmethod
    def install(cls, state: MkosiState) -> None:
        # Instead of using debootstrap, we replicate its core functionality here. Because dpkg does not have
        # an option to delay running pre-install maintainer scripts when it installs a package, it's
        # impossible to use apt directly to bootstrap a Debian chroot since dpkg will try to run a maintainer
        # script which depends on some basic tool to be available in the chroot from a deb which hasn't been
        # unpacked yet, causing the script to fail. To avoid these issues, we have to extract all the
        # essential debs first, and only then run the maintainer scripts for them.

        # First, we set up merged usr.
        # This list is taken from https://salsa.debian.org/installer-team/debootstrap/-/blob/master/functions#L1369.
        subdirs = ["bin", "sbin", "lib"] + {
            "amd64"       : ["lib32", "lib64", "libx32"],
            "i386"        : ["lib64", "libx32"],
            "mips"        : ["lib32", "lib64"],
            "mipsel"      : ["lib32", "lib64"],
            "mips64el"    : ["lib32", "lib64", "libo32"],
            "loongarch64" : ["lib32", "lib64"],
            "powerpc"     : ["lib64"],
            "ppc64"       : ["lib32", "lib64"],
            "ppc64el"     : ["lib64"],
            "s390x"       : ["lib32"],
            "sparc"       : ["lib64"],
            "sparc64"     : ["lib32", "lib64"],
            "x32"         : ["lib32", "lib64", "libx32"],
        }.get(state.config.distribution.architecture(state.config.architecture), [])

        state.root.joinpath("usr").mkdir(mode=0o755, exist_ok=True)
        for d in subdirs:
            state.root.joinpath(d).symlink_to(f"usr/{d}")
            state.root.joinpath(f"usr/{d}").mkdir(mode=0o755, exist_ok=True)

        # Next, we invoke apt-get install to download all the essential packages. With DPkg::Pre-Install-Pkgs,
        # we specify a shell command that will receive the list of packages that will be installed on stdin.
        # By configuring Debug::pkgDpkgPm=1, apt-get install will not actually execute any dpkg commands, so
        # all it does is download the essential debs and tell us their full in the apt cache without actually
        # installing them.
        with tempfile.NamedTemporaryFile(mode="r") as f:
            cls.install_packages(state, [
                "-oDebug::pkgDPkgPm=1",
                f"-oDPkg::Pre-Install-Pkgs::=cat >{f.name}",
                "?essential", "?name(usr-is-merged)",
            ], apivfs=False)

            essential = f.read().strip().splitlines()

        # Now, extract the debs to the chroot by first extracting the sources tar file out of the deb and
        # then extracting the tar file into the chroot.

        for deb in essential:
            with tempfile.NamedTemporaryFile() as f:
                run(["dpkg-deb", "--fsys-tarfile", deb], stdout=f)
                run(["tar", "-C", state.root, "--keep-directory-symlink", "--extract", "--file", f.name])

        # Finally, run apt to properly install packages in the chroot without having to worry that maintainer
        # scripts won't find basic tools that they depend on.

        cls.install_packages(state, [Path(deb).name.partition("_")[0].removesuffix(".deb") for deb in essential])

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
        # start. Let's install one that denies all daemon startups.
        # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
        # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
        # the admin.
        policyrcd = state.root / "usr/sbin/policy-rc.d"
        policyrcd.write_text("#!/bin/sh\nexit 101\n")
        policyrcd.chmod(0o755)

        setup_apt(state, cls.repositories(state))
        invoke_apt(state, "apt-get", "update", apivfs=False)
        invoke_apt(state, "apt-get", "install", packages, apivfs=apivfs)
        install_apt_sources(state, cls.repositories(state, local=False))

        policyrcd.unlink()

        for d in state.root.glob("boot/vmlinuz-*"):
            kver = d.name.removeprefix("vmlinuz-")
            vmlinuz = state.root / "usr/lib/modules" / kver / "vmlinuz"
            if not vmlinuz.exists():
                shutil.copy2(d, vmlinuz)


    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_apt(state, "apt-get", "purge", packages)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.arm64       : "arm64",
            Architecture.arm         : "armhf",
            Architecture.alpha       : "alpha",
            Architecture.x86_64      : "amd64",
            Architecture.x86         : "i386",
            Architecture.ia64        : "ia64",
            Architecture.loongarch64 : "loongarch64",
            Architecture.mips64_le   : "mips64el",
            Architecture.mips_le     : "mipsel",
            Architecture.parisc      : "hppa",
            Architecture.ppc64_le    : "ppc64el",
            Architecture.ppc64       : "ppc64",
            Architecture.riscv64     : "riscv64",
            Architecture.s390x       : "s390x",
            Architecture.s390        : "s390",
        }.get(arch)

        if not a:
            die(f"Architecture {arch} is not supported by Debian")

        return a


def install_apt_sources(state: MkosiState, repos: Sequence[str]) -> None:
    if not state.root.joinpath("usr/bin/apt").exists():
        return

    sources = state.root / "etc/apt/sources.list"
    if not sources.exists():
        with sources.open("w") as f:
            for repo in repos:
                f.write(f"{repo}\n")
