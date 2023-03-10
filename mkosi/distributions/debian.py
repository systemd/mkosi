# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path
from textwrap import dedent

from mkosi.backend import MkosiState, add_packages, disable_pam_securetty
from mkosi.distributions import DistributionInstaller
from mkosi.install import install_skeleton_trees, write_resource
from mkosi.run import run, run_with_apivfs
from mkosi.types import _FILE, CompletedProcess, PathString


class DebianInstaller(DistributionInstaller):
    needs_skeletons_after_bootstrap = True
    repositories_for_boot: set[str] = set()

    @classmethod
    def _add_default_kernel_package(cls, state: MkosiState, packages: list[str]) -> None:
        # Don't pull in a kernel if users specify one, but otherwise try to pick a default
        # one - try to infer from the architecture.
        if not any(package.startswith("linux-image") for package in packages):
            add_packages(state.config, packages, f"linux-image-{DEBIAN_KERNEL_ARCHITECTURES[state.config.architecture]}")

    @classmethod
    def _fixup_resolved(cls, state: MkosiState, packages: list[str]) -> None:
        if "systemd" in packages and "systemd-resolved" not in packages:
            # The default resolv.conf points to 127.0.0.1, and resolved is disabled, fix it in
            # the base image.
            state.root.joinpath("etc/resolv.conf").unlink(missing_ok=True)
            state.root.joinpath("etc/resolv.conf").symlink_to("../run/systemd/resolve/resolv.conf")

    @classmethod
    def cache_path(cls) -> list[str]:
        return ["var/cache/apt/archives"]

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @staticmethod
    def kernel_image(name: str, architecture: str) -> Path:
        return Path(f"boot/vmlinuz-{name}")

    @staticmethod
    def initrd_path(kver: str) -> Path:
        return Path("boot") / f"initrd.img-{kver}"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        # Either the image builds or it fails and we restart, we don't need safety fsyncs when bootstrapping
        # Add it before debootstrap, as the second stage already uses dpkg from the chroot
        dpkg_io_conf = state.root / "etc/dpkg/dpkg.cfg.d/unsafe_io"
        os.makedirs(dpkg_io_conf.parent, mode=0o755, exist_ok=True)
        dpkg_io_conf.write_text("force-unsafe-io\n")

        repos = {"main", *state.config.repositories}
        # Ubuntu needs the 'universe' repo to install 'dracut'
        if state.config.bootable:
            repos |= cls.repositories_for_boot

        # debootstrap fails if a base image is used with an already populated root, so skip it.
        if state.config.base_image is None:
            cmdline: list[PathString] = [
                "debootstrap",
                "--variant=minbase",
                "--include=ca-certificates",
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
            run_with_apivfs(state, cmdline, env=dict(container="lxc"))

        # Install extra packages via the secondary APT run, because it is smarter and can deal better with any
        # conflicts. dbus and libpam-systemd are optional dependencies for systemd in debian so we include them
        # explicitly.
        packages = state.config.packages.copy()
        add_packages(state.config, packages, "systemd", "systemd-sysv", "dbus", "libpam-systemd")

        if state.config.bootable:
            if not state.config.initrds:
                add_packages(state.config, packages, "dracut", "dracut-config-generic")
            cls._add_default_kernel_package(state, packages)

        if state.config.ssh:
            add_packages(state.config, packages, "openssh-server")

        # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
        # start. Let's install one that denies all daemon startups.
        # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
        # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
        # the admin.
        policyrcd = state.root / "usr/sbin/policy-rc.d"
        policyrcd.write_text("#!/bin/sh\nexit 101\n")
        policyrcd.chmod(0o755)

        doc_paths = [
            state.root / "usr/share/locale",
            state.root / "usr/share/doc",
            state.root / "usr/share/man",
            state.root / "usr/share/groff",
            state.root / "usr/share/info",
            state.root / "usr/share/lintian",
            state.root / "usr/share/linda",
        ]
        if not state.config.with_docs:
            # Remove documentation installed by debootstrap
            for d in doc_paths:
                try:
                    shutil.rmtree(d)
                except FileNotFoundError:
                    pass
            # Create dpkg.cfg to ignore documentation on new packages
            dpkg_nodoc_conf = state.root / "etc/dpkg/dpkg.cfg.d/01_nodoc"
            with dpkg_nodoc_conf.open("w") as f:
                f.writelines(f"path-exclude {d}/*\n" for d in doc_paths)

        if state.config.bootable and state.config.base_image is None:
            # systemd-boot won't boot unified kernel images generated without a BUILD_ID or VERSION_ID in
            # /etc/os-release. Build one with the mtime of os-release if we don't find them.
            with state.root.joinpath("etc/os-release").open("r+") as f:
                os_release = f.read()
                if "VERSION_ID" not in os_release and "BUILD_ID" not in os_release:
                    f.write(f"BUILD_ID=mkosi-{state.config.release}\n")

        if not state.config.local_mirror:
            cls._add_apt_auxiliary_repos(state, repos)
        else:
            # Add a single local offline repository, and then remove it after apt has ran
            state.root.joinpath("etc/apt/sources.list.d/mirror.list").write_text(f"deb [trusted=yes] {state.config.local_mirror} {state.config.release} main\n")

        install_skeleton_trees(state, False, late=True)

        invoke_apt(state, "get", "update", ["--assume-yes"])

        if state.config.bootable:
            # Ensure /efi exists so that the ESP is mounted there, and we never run dpkg -i on vfat
            state.root.joinpath("efi").mkdir(mode=0o755)

        if state.config.bootable:
            add_apt_package_if_exists(state, packages, "systemd-boot")

        # systemd-resolved was split into a separate package
        add_apt_package_if_exists(state, packages, "systemd-resolved")

        invoke_apt(state, "get", "install", ["--assume-yes", "--no-install-recommends", *packages])

        # Now clean up and add the real repositories, so that the image is ready
        if state.config.local_mirror:
            main_repo = f"deb {state.config.mirror} {state.config.release} {' '.join(repos)}\n"
            state.root.joinpath("etc/apt/sources.list").write_text(main_repo)
            state.root.joinpath("etc/apt/sources.list.d/mirror.list").unlink()
            cls._add_apt_auxiliary_repos(state, repos)

        policyrcd.unlink()
        dpkg_io_conf.unlink()
        if not state.config.with_docs and state.config.base_image is not None:
            # Don't ship dpkg config files in extensions, they belong with dpkg in the base image.
            dpkg_nodoc_conf.unlink() # type: ignore

        if state.config.base_image is None:
            # Debian still has pam_securetty module enabled, disable it in the base image.
            disable_pam_securetty(state.root)

        cls._fixup_resolved(state, packages)

        # Debian/Ubuntu use a different path to store the locale so let's make sure that path is a symlink to
        # etc/locale.conf.
        state.root.joinpath("etc/default/locale").unlink(missing_ok=True)
        state.root.joinpath("etc/default/locale").symlink_to("../locale.conf")

        # Don't enable any services by default.
        presetdir = state.root / "etc/systemd/system-preset"
        presetdir.mkdir(exist_ok=True, mode=0o755)
        presetdir.joinpath("99-mkosi-disable.preset").write_text("disable *")

        if state.config.bootable and not state.config.initrds:
            write_resource(state.root / "etc/kernel/install.d/50-mkosi-dpkg-reconfigure-dracut.install",
                           "mkosi.resources", "dpkg-reconfigure-dracut.install", executable=True)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_apt(state, "get", "install", ["--assume-yes", "--no-install-recommends", *packages])

    @classmethod
    def _add_apt_auxiliary_repos(cls, state: MkosiState, repos: set[str]) -> None:
        if state.config.release in ("unstable", "sid"):
            return

        updates = f"deb {state.config.mirror} {state.config.release}-updates {' '.join(repos)}"
        state.root.joinpath(f"etc/apt/sources.list.d/{state.config.release}-updates.list").write_text(f"{updates}\n")

        # Security updates repos are never mirrored
        if state.config.release in ("stretch", "buster"):
            security = f"deb http://security.debian.org/debian-security/ {state.config.release}/updates main"
        else:
            security = f"deb https://security.debian.org/debian-security {state.config.release}-security main"

        state.root.joinpath(f"etc/apt/sources.list.d/{state.config.release}-security.list").write_text(f"{security}\n")

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_apt(state, "get", "purge", ["--assume-yes", "--auto-remove", *packages])


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

# And the kernel package names have yet another format, so adjust accordingly
# uname -m -> linux-image-$arch
DEBIAN_KERNEL_ARCHITECTURES = {
    "aarch64": "arm64",
    "armhfp": "armmp",
    "alpha": "alpha-generic",
    "ia64": "itanium",
    "m68k": "m68k",
    "parisc64": "parisc64",
    "ppc": "powerpc",
    "ppc64": "powerpc64",
    "ppc64le": "powerpc64le",
    "riscv64:": "riscv64",
    "s390x": "s390x",
    "x86": "i386",
    "x86_64": "amd64",
}


def debootstrap_knows_arg(arg: str) -> bool:
    return bytes("invalid option", "UTF-8") not in run(["debootstrap", arg],
                                                       stdout=subprocess.PIPE, check=False).stdout


def invoke_apt(
    state: MkosiState,
    subcommand: str,
    operation: str,
    extra: Iterable[str],
    stdout: _FILE = None,
) -> CompletedProcess:

    state.workspace.joinpath("apt").mkdir(exist_ok=True)
    state.workspace.joinpath("apt/log").mkdir(exist_ok=True)
    state.root.joinpath("var/lib/dpkg").mkdir(exist_ok=True)
    state.root.joinpath("var/lib/dpkg/status").touch()

    config_file = state.workspace / "apt/apt.conf"
    debarch = DEBIAN_ARCHITECTURES[state.config.architecture]

    config_file.write_text(
        dedent(
            f"""\
            APT::Architecture "{debarch}";
            APT::Immediate-Configure "off";
            Dir::Cache "{state.cache}";
            Dir::State "{state.workspace / "apt"}";
            Dir::State::status "{state.root / "var/lib/dpkg/status"}";
            Dir::Etc "{state.root / "etc/apt"}";
            Dir::Log "{state.workspace / "apt/log"}";
            Dir::Bin::dpkg "dpkg";
            DPkg::Path "{os.environ["PATH"]}";
            DPkg::Options:: "--root={state.root}";
            DPkg::Options:: "--log={state.workspace / "apt/dpkg.log"}";
            DPkg::Install::Recursive::Minimum "1000";
            """
        )
    )

    cmdline = [
        f"/usr/bin/apt-{subcommand}",
        operation,
        *extra,
    ]
    env: dict[str, PathString] = dict(
        APT_CONFIG=config_file,
        DEBIAN_FRONTEND="noninteractive",
        DEBCONF_INTERACTIVE_SEEN="true",
        INITRD="No",
    )

    return run_with_apivfs(state, cmdline, stdout=stdout, env=env)


def add_apt_package_if_exists(state: MkosiState, packages: list[str], package: str) -> None:
    if invoke_apt(state, "cache", "search", ["--names-only", f"^{package}$"], stdout=subprocess.PIPE).stdout.strip():
        add_packages(state.config, packages, package)
