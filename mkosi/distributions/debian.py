# SPDX-License-Identifier: LGPL-2.1+

import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

from mkosi.backend import MkosiState
from mkosi.distributions import DistributionInstaller
from mkosi.install import install_skeleton_trees
from mkosi.run import run, run_with_apivfs
from mkosi.types import CompletedProcess, PathString


class DebianInstaller(DistributionInstaller):
    needs_skeletons_after_bootstrap = True

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
        repos = {"main", *state.config.repositories}

        cmdline: list[PathString] = [
            "debootstrap",
            "--variant=minbase",
            "--merged-usr",
            f"--cache-dir={state.cache}",
            f"--components={','.join(repos)}",
        ]

        debarch = DEBIAN_ARCHITECTURES[state.config.architecture]
        cmdline += [f"--arch={debarch}"]

        # Let's use --no-check-valid-until only if debootstrap knows it
        if debootstrap_knows_arg("--no-check-valid-until"):
            cmdline += ["--no-check-valid-until"]

        if not state.config.repository_key_check:
            cmdline += ["--no-check-gpg"]

        mirror = state.config.local_mirror or state.config.mirror
        assert mirror is not None
        cmdline += [state.config.release, state.root, mirror]

        # Pretend we're lxc so debootstrap skips its mknod check.
        run_with_apivfs(state, cmdline, env=dict(container="lxc", DPKG_FORCE="unsafe-io"))

        install_skeleton_trees(state, False, late=True)

        cls.install_packages(state, ["base-passwd"])

        # Ensure /efi exists so that the ESP is mounted there, and we never run dpkg -i on vfat
        state.root.joinpath("efi").mkdir(mode=0o755, exist_ok=True)

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


# Debian calls their architectures differently, so when calling debootstrap we
# will have to map to their names
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


def debootstrap_knows_arg(arg: str) -> bool:
    return bytes("invalid option", "UTF-8") not in run(["debootstrap", arg],
                                                       stdout=subprocess.PIPE, check=False).stdout


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
            Dir::Cache "{state.cache}";
            Dir::State "{state.workspace / "apt"}";
            Dir::State::status "{state.root / "var/lib/dpkg/status"}";
            Dir::Etc "{state.workspace / "apt"}";
            Dir::Etc::trusted "/usr/share/keyrings/{state.config.release}-archive-keyring";
            Dir::Etc::trustedparts "/usr/share/keyrings";
            Dir::Log "{state.workspace / "apt/log"}";
            Dir::Bin::dpkg "dpkg";
            DPkg::Path "{os.environ["PATH"]}";
            DPkg::Options:: "--root={state.root}";
            DPkg::Options:: "--log={state.workspace / "apt/dpkg.log"}";
            DPkg::Options:: "--force-unsafe-io";
            DPkg::Install::Recursive::Minimum "1000";
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
) -> CompletedProcess:
    env: dict[str, PathString] = dict(
        APT_CONFIG=state.workspace / "apt/apt.conf",
        DEBIAN_FRONTEND="noninteractive",
        DEBCONF_INTERACTIVE_SEEN="true",
        KERNEL_INSTALL_BYPASS="1",
        INITRD="No",
    )

    return run_with_apivfs(state, ["apt-get", operation, *extra], env=env)
