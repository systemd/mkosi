# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import subprocess
from pathlib import Path
from subprocess import PIPE
from typing import TYPE_CHECKING, Any, Iterable, Iterator, List, Set

from ..backend import (
    MkosiState,
    OutputFormat,
    PartitionIdentifier,
    PathString,
    add_packages,
    complete_step,
    disable_pam_securetty,
    run,
    run_workspace_command,
)
from ..install import install_skeleton_trees, write_resource
from ..mount import mount_api_vfs, mount_bind
from . import DistributionInstaller

if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[Any]
else:
    CompletedProcess = subprocess.CompletedProcess


class DebianInstaller(DistributionInstaller):
    needs_skeletons_after_bootstrap = True
    repositories_for_boot: Set[str] = set()

    @classmethod
    def add_default_kernel_package(cls, state: MkosiState, extra_packages: Set[str]) -> None:
        # Don't pull in a kernel if users specify one, but otherwise try to pick a default
        # one - try to infer from the architecture.
        if not any(package.startswith("linux-image") for package in extra_packages):
            add_packages(state.config, extra_packages, f"linux-image-{DEBIAN_KERNEL_ARCHITECTURES[state.config.architecture]}")

    @classmethod
    def fixup_resolved(cls, state: MkosiState, extra_packages: Set[str]) -> None:
        if "systemd" in extra_packages and "systemd-resolved" not in extra_packages:
            # The default resolv.conf points to 127.0.0.1, and resolved is disabled, fix it in
            # the base image.
            # TODO: use missing_ok=True when we drop Python << 3.8
            if state.root.joinpath("etc/resolv.conf").exists():
                state.root.joinpath("etc/resolv.conf").unlink()
            state.root.joinpath("etc/resolv.conf").symlink_to("../run/systemd/resolve/resolv.conf")
            run(["systemctl", "--root", state.root, "enable", "systemd-resolved"])

    @classmethod
    def cache_path(cls) -> List[str]:
        return ["var/cache/apt/archives"]

    @staticmethod
    def kernel_image(name: str) -> Path:
        return Path("lib/modules") / name / "vmlinuz"

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        # Either the image builds or it fails and we restart, we don't need safety fsyncs when bootstrapping
        # Add it before debootstrap, as the second stage already uses dpkg from the chroot
        dpkg_io_conf = state.root / "etc/dpkg/dpkg.cfg.d/unsafe_io"
        os.makedirs(dpkg_io_conf.parent, mode=0o755, exist_ok=True)
        dpkg_io_conf.write_text("force-unsafe-io\n")

        repos = set(state.config.repositories) or {"main"}
        # Ubuntu needs the 'universe' repo to install 'dracut'
        if state.config.bootable:
            repos |= cls.repositories_for_boot

        # debootstrap fails if a base image is used with an already populated root, so skip it.
        if state.config.base_image is None:
            cmdline: List[PathString] = [
                "debootstrap",
                "--variant=minbase",
                "--include=ca-certificates",
                "--merged-usr",
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
            run(cmdline)

        # Install extra packages via the secondary APT run, because it is smarter and can deal better with any
        # conflicts. dbus and libpam-systemd are optional dependencies for systemd in debian so we include them
        # explicitly.
        extra_packages: Set[str] = set()
        add_packages(state.config, extra_packages, "systemd", "systemd-sysv", "dbus", "libpam-systemd")
        extra_packages.update(state.config.packages)

        if state.do_run_build_script:
            extra_packages.update(state.config.build_packages)

        if not state.do_run_build_script and state.config.bootable:
            add_packages(state.config, extra_packages, "dracut")
            cls.add_default_kernel_package(state, extra_packages)

            if state.config.output_format == OutputFormat.gpt_btrfs:
                add_packages(state.config, extra_packages, "btrfs-progs")

        if not state.do_run_build_script and state.config.ssh:
            add_packages(state.config, extra_packages, "openssh-server")

        # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
        # start. Let's install one that denies all daemon startups.
        # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
        # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
        # the admin.
        policyrcd = state.root / "usr/sbin/policy-rc.d"
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
        if not state.config.with_docs:
            # Remove documentation installed by debootstrap
            cmdline = ["/bin/rm", "-rf", *doc_paths]
            run_workspace_command(state, cmdline)
            # Create dpkg.cfg to ignore documentation on new packages
            dpkg_nodoc_conf = state.root / "etc/dpkg/dpkg.cfg.d/01_nodoc"
            with dpkg_nodoc_conf.open("w") as f:
                f.writelines(f"path-exclude {d}/*\n" for d in doc_paths)

        if not state.do_run_build_script and state.config.bootable and state.config.with_unified_kernel_images and state.config.base_image is None:
            # systemd-boot won't boot unified kernel images generated without a BUILD_ID or VERSION_ID in
            # /etc/os-release. Build one with the mtime of os-release if we don't find them.
            with state.root.joinpath("etc/os-release").open("r+") as f:
                os_release = f.read()
                if "VERSION_ID" not in os_release and "BUILD_ID" not in os_release:
                    f.write(f"BUILD_ID=mkosi-{state.config.release}\n")

        if not state.config.local_mirror:
            cls.add_apt_auxiliary_repos(state, repos)
        else:
            # Add a single local offline repository, and then remove it after apt has ran
            state.root.joinpath("etc/apt/sources.list.d/mirror.list").write_text(f"deb [trusted=yes] {state.config.local_mirror} {state.config.release} main\n")

        install_skeleton_trees(state, False, late=True)

        invoke_apt(state, "get", "update", ["--assume-yes"])

        if state.config.bootable and not state.do_run_build_script and state.get_partition(PartitionIdentifier.esp):
            add_apt_package_if_exists(state, extra_packages, "systemd-boot")

        # systemd-resolved was split into a separate package
        add_apt_package_if_exists(state, extra_packages, "systemd-resolved")

        invoke_apt(state, "get", "install", ["--assume-yes", "--no-install-recommends", *extra_packages])

        # Now clean up and add the real repositories, so that the image is ready
        if state.config.local_mirror:
            main_repo = f"deb {state.config.mirror} {state.config.release} {' '.join(repos)}\n"
            state.root.joinpath("etc/apt/sources.list").write_text(main_repo)
            state.root.joinpath("etc/apt/sources.list.d/mirror.list").unlink()
            cls.add_apt_auxiliary_repos(state, repos)

        policyrcd.unlink()
        dpkg_io_conf.unlink()
        if not state.config.with_docs and state.config.base_image is not None:
            # Don't ship dpkg config files in extensions, they belong with dpkg in the base image.
            dpkg_nodoc_conf.unlink() # type: ignore

        if state.config.base_image is None:
            # Debian still has pam_securetty module enabled, disable it in the base image.
            disable_pam_securetty(state.root)

        cls.fixup_resolved(state, extra_packages)

        write_resource(state.root / "etc/kernel/install.d/50-mkosi-dpkg-reconfigure-dracut.install",
                       "mkosi.resources", "dpkg-reconfigure-dracut.install", executable=True)

        # Debian/Ubuntu use a different path to store the locale so let's make sure that path is a symlink to
        # etc/locale.conf.
        try:
            state.root.joinpath("etc/default/locale").unlink()
        except FileNotFoundError:
            pass
        state.root.joinpath("etc/default/locale").symlink_to("../locale.conf")

    @classmethod
    def add_apt_auxiliary_repos(cls, state: MkosiState, repos: Set[str]) -> None:
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
    def remove_packages(cls, state: MkosiState, remove: List[str]) -> None:
        invoke_apt(state, "get", "purge", ["--assume-yes", "--auto-remove", *remove])


# Debian calls their architectures differently, so when calling debootstrap we
# will have to map to their names
DEBIAN_ARCHITECTURES = {
    "x86_64": "amd64",
    "x86": "i386",
    "aarch64": "arm64",
    "armhfp": "armhf",
}

# And the kernel package names have yet another format, so adjust accordingly
DEBIAN_KERNEL_ARCHITECTURES = {
    "x86_64": "amd64",
    "x86": "i386",
    "aarch64": "arm64",
    "armhfp": "armmp",
    "alpha": "alpha-generic",
    "ia64": "itanium",
    "ppc": "powerpc",
    "ppc64": "powerpc64",
    "ppc64le": "powerpc64le",
    "s390x": "s390x",
}

def debootstrap_knows_arg(arg: str) -> bool:
    return bytes("invalid option", "UTF-8") not in run(["debootstrap", arg], stdout=PIPE, check=False).stdout


@contextlib.contextmanager
def mount_apt_local_mirror(state: MkosiState) -> Iterator[None]:
    # Ensure apt inside the image can see the local mirror outside of it
    mirror = state.config.local_mirror or state.config.mirror
    if not mirror or not mirror.startswith("file:"):
        yield
        return

    # Strip leading '/' as Path() does not behave well when concatenating
    mirror_dir = mirror[5:].lstrip("/")

    with complete_step("Mounting apt local mirror…", "Unmounting apt local mirror…"):
        with mount_bind(Path("/") / mirror_dir, state.root / mirror_dir):
            yield


def invoke_apt(
    state: MkosiState,
    subcommand: str,
    operation: str,
    extra: Iterable[str],
    **kwargs: Any,
) -> CompletedProcess:

    debarch = DEBIAN_ARCHITECTURES[state.config.architecture]

    cmdline = [
        f"/usr/bin/apt-{subcommand}",
        "-o", f"Dir={state.root}",
        "-o", f"DPkg::Chroot-Directory={state.root}",
        "-o", f"APT::Architecture={debarch}",
        "-o", "dpkg::install::recursive::minimum=1000",
        operation,
        *extra,
    ]
    env = dict(
        DEBIAN_FRONTEND="noninteractive",
        DEBCONF_NONINTERACTIVE_SEEN="true",
        INITRD="No",
    )

    # Overmount /etc/apt on the host with an empty directory, so that apt doesn't parse any configuration
    # from it.
    with mount_bind(state.workspace / "apt", Path("/") / "etc/apt"), mount_apt_local_mirror(state), mount_api_vfs(state.root):
        return run(cmdline, env=env, text=True, **kwargs)


def add_apt_package_if_exists(state: MkosiState, extra_packages: Set[str], package: str) -> None:
    if invoke_apt(state, "cache", "search", ["--names-only", f"^{package}$"], stdout=PIPE).stdout.strip() != "":
        add_packages(state.config, extra_packages, package)
