# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

from mkosi.backend import MkosiState
from mkosi.distributions import DistributionInstaller
from mkosi.run import run, run_with_apivfs
from mkosi.types import _FILE, CompletedProcess, PathString


class DebianInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @staticmethod
    def kernel_image(name: str, architecture: str) -> Path:
        return Path(f"boot/vmlinuz-{name}")

    @staticmethod
    def initrd_path(kver: str) -> Path:
        return Path("boot") / f"initrd.img-{kver}"

    @staticmethod
    def repositories(state: MkosiState, local: bool = True) -> list[str]:
        repos = ' '.join(("main", *state.config.repositories))

        if state.config.local_mirror and local:
            return [f"deb [trusted=yes] {state.config.local_mirror} {state.config.release} {repos}"]

        main = f"deb {state.config.mirror} {state.config.release} {repos}"

        if state.config.release in ("unstable", "sid"):
            return [main]

        updates = f"deb {state.config.mirror} {state.config.release}-updates {repos}"

        # Security updates repos are never mirrored
        if state.config.release in ("stretch", "buster"):
            security = f"deb http://security.debian.org/debian-security {state.config.release}/updates {repos}"
        else:
            security = f"deb http://security.debian.org/debian-security {state.config.release}-security {repos}"

        return [main, updates, security]

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
        }.get(DEBIAN_ARCHITECTURES[state.config.architecture], [])

        state.root.joinpath("usr").mkdir(mode=0o755)
        for d in subdirs:
            state.root.joinpath(d).symlink_to(f"usr/{d}")
            state.root.joinpath(f"usr/{d}").mkdir(mode=0o755)

        # Next, we download the essential debs. We add usr-is-merged to assert the system is usr-merged
        # already and to prevent usrmerge from being installed and pulling in all its dependencies.
        setup_apt(state, cls.repositories(state))
        invoke_apt(state, "update")
        invoke_apt(state, "install", ["--download-only", "?essential", "?name(usr-is-merged)"])

        # Next, invoke apt install with an info fd to which it writes the debs it's operating on. However, by
        # passing "-oDebug::pkgDpkgPm=1", apt will not actually execute any dpkg commands, which turns the
        # install command into a noop that tells us the full paths to the essential debs and any dependencies
        # that apt would install in the apt cache.
        with tempfile.TemporaryFile(dir=state.workspace, mode="w+") as f:
            os.set_inheritable(f.fileno(), True)

            options = [
                "-oDebug::pkgDpkgPm=1",
                f"-oAPT::Keep-Fds::={f.fileno()}",
                f"-oDPkg::Tools::options::'cat >&$fd'::InfoFD={f.fileno()}",
                f"-oDpkg::Pre-Install-Pkgs::=cat >&{f.fileno()}",
                "?essential", "?name(usr-is-merged)",
            ]

            try:
                invoke_apt(state, "install", options, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                # By default, we run the command with stdout/stderr redirected to /dev/null because it
                # produces a lot of useless output. If it fails, let's rerun it with regular stdout/stderr so
                # we can debug the error.
                invoke_apt(state, "install", options)
                raise

            f.seek(0)
            essential = f.read().strip().splitlines()

        # Now, extract the debs to the chroot by first extracting the sources tar file out of the deb and
        # then extracting the tar file into the chroot.

        for deb in essential:
            with tempfile.NamedTemporaryFile(dir=state.workspace) as f:
                run(["dpkg-deb", "--fsys-tarfile", deb], stdout=f)
                run(["tar", "-C", state.root, "--keep-directory-symlink", "--extract", "--file", f.name])

        # Finally, run apt to properly install packages in the chroot without having to worry that maintainer
        # scripts won't find basic tools that they depend on.

        cls.install_packages(state, [Path(deb).name.partition("_")[0] for deb in essential])

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
        # start. Let's install one that denies all daemon startups.
        # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
        # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
        # the admin.
        policyrcd = state.root / "usr/sbin/policy-rc.d"
        policyrcd.write_text("#!/bin/sh\nexit 101\n")
        policyrcd.chmod(0o755)

        setup_apt(state, cls.repositories(state))
        invoke_apt(state, "update")
        invoke_apt(state, "install", packages)

        policyrcd.unlink()

        sources = state.root / "etc/apt/sources.list"
        if not sources.exists() and state.root.joinpath("usr/bin/apt").exists():
            with sources.open("w") as f:
                for repo in cls.repositories(state, local=False):
                    f.write(f"{repo}\n")

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_apt(state, "purge", packages)


# Debian calls their architectures differently, so when calling apt we will have to map to their names.
# uname -m -> dpkg --print-architecture
DEBIAN_ARCHITECTURES = {
    "aarch64": "arm64",
    "armhfp": "armhf",
    "armv7l": "armhf",
    "ia64": "ia64",
    "mips64": "mipsel",
    "m68k": "m68k",
    "parisc64": "hppa",
    "ppc64": "ppc64",
    "ppc64le": "ppc64el",
    "riscv64:": "riscv64",
    "s390x": "s390x",
    "x86": "i386",
    "x86_64": "amd64",
}


def setup_apt(state: MkosiState, repos: Sequence[str]) -> None:
    state.workspace.joinpath("apt").mkdir(exist_ok=True)
    state.workspace.joinpath("apt/apt.conf.d").mkdir(exist_ok=True)
    state.workspace.joinpath("apt/preferences.d").mkdir(exist_ok=True)
    state.workspace.joinpath("apt/log").mkdir(exist_ok=True)
    state.root.joinpath("var").mkdir(mode=0o755, exist_ok=True)
    state.root.joinpath("var/lib").mkdir(mode=0o755, exist_ok=True)
    state.root.joinpath("var/lib/dpkg").mkdir(mode=0o755, exist_ok=True)
    state.root.joinpath("var/lib/dpkg/status").touch()

    config = state.workspace / "apt/apt.conf"
    debarch = DEBIAN_ARCHITECTURES[state.config.architecture]

    config.write_text(
        dedent(
            f"""\
            APT::Architecture "{debarch}";
            APT::Immediate-Configure "off";
            APT::Install-Recommends "false";
            APT::Get::Assume-Yes "true";
            APT::Get::AutomaticRemove "true";
            APT::Sandbox::User "root";
            Dir::Cache "{state.cache}";
            Dir::State "{state.workspace / "apt"}";
            Dir::State::status "{state.root / "var/lib/dpkg/status"}";
            Dir::Etc "{state.workspace / "apt"}";
            Dir::Etc::trusted "/usr/share/keyrings/{state.config.release}-archive-keyring";
            Dir::Etc::trustedparts "/usr/share/keyrings";
            Dir::Log "{state.workspace / "apt/log"}";
            Dir::Bin::dpkg "{shutil.which("dpkg")}";
            DPkg::Options:: "--root={state.root}";
            DPkg::Options:: "--log={state.workspace / "apt/dpkg.log"}";
            DPkg::Options:: "--force-unsafe-io";
            Dpkg::Use-Pty "false";
            DPkg::Install::Recursive::Minimum "1000";
            pkgCacheGen::ForceEssential ",";
            """
        )
    )

    with state.workspace.joinpath("apt/sources.list").open("w") as f:
        for repo in repos:
            f.write(f"{repo}\n")


def invoke_apt(
    state: MkosiState,
    operation: str,
    extra: Sequence[str] = tuple(),
    stdout: _FILE = None,
    stderr: _FILE = None,
) -> CompletedProcess:
    env: dict[str, PathString] = dict(
        APT_CONFIG=state.workspace / "apt/apt.conf",
        DEBIAN_FRONTEND="noninteractive",
        DEBCONF_INTERACTIVE_SEEN="true",
        KERNEL_INSTALL_BYPASS="1",
        INITRD="No",
    )

    return run_with_apivfs(state, ["apt-get", operation, *extra], env=env, stdout=stdout, stderr=stderr)
