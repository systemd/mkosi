# SPDX-License-Identifier: LGPL-2.1+

import argparse
import base64
import contextlib
import crypt
import dataclasses
import datetime
import errno
import hashlib
import http.server
import itertools
import json
import os
import platform
import resource
import shutil
import string
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from textwrap import dedent
from typing import Callable, ContextManager, Optional, TextIO, TypeVar, Union, cast

from mkosi.backend import (
    Compression,
    Distribution,
    ManifestFormat,
    MkosiConfig,
    MkosiState,
    OutputFormat,
    Verb,
    current_user_uid_gid,
    flatten,
    format_rlimit,
    is_dnf_distribution,
    patch_file,
    set_umask,
    tmp_dir,
)
from mkosi.install import add_dropin_config_from_resource, copy_path, flock
from mkosi.log import ARG_DEBUG, MkosiPrinter, die, warn
from mkosi.manifest import GenericVersion, Manifest
from mkosi.mounts import dissect_and_mount, mount_overlay, scandir_recursive
from mkosi.pager import page
from mkosi.remove import unlink_try_hard
from mkosi.run import (
    become_root,
    fork_and_wait,
    init_mount_namespace,
    run,
    run_workspace_command,
    spawn,
)
from mkosi.types import PathString

complete_step = MkosiPrinter.complete_step
color_error = MkosiPrinter.color_error

MKOSI_COMMANDS_NEED_BUILD = (Verb.shell, Verb.boot, Verb.qemu, Verb.serve)
MKOSI_COMMANDS_SUDO = (Verb.shell, Verb.boot)
MKOSI_COMMANDS_CMDLINE = (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.ssh)


T = TypeVar("T")


def list_to_string(seq: Iterator[str]) -> str:
    """Print contents of a list to a comma-separated string

    ['a', "b", 11] → "'a', 'b', 11"
    """
    return str(list(seq))[1:-1]


# EFI has its own conventions too
EFI_ARCHITECTURES = {
    "x86_64": "x64",
    "x86": "ia32",
    "aarch64": "aa64",
    "armhfp": "arm",
    "riscv64:": "riscv64",
}


def format_bytes(num_bytes: int) -> str:
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes/1024**3 :0.1f}G"
    if num_bytes >= 1024 * 1024:
        return f"{num_bytes/1024**2 :0.1f}M"
    if num_bytes >= 1024:
        return f"{num_bytes/1024 :0.1f}K"

    return f"{num_bytes}B"


def btrfs_subvol_create(path: Path, mode: int = 0o755) -> None:
    with set_umask(~mode & 0o7777):
        run(["btrfs", "subvol", "create", path])


@contextlib.contextmanager
def mount_image(state: MkosiState) -> Iterator[None]:
    with complete_step("Mounting image…", "Unmounting image…"), contextlib.ExitStack() as stack:

        if state.config.base_trees and state.config.overlay:
            bases = []
            state.workspace.joinpath("bases").mkdir(exist_ok=True)

            for path in state.config.base_trees:
                d = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=state.workspace / "base", prefix=path.name)))
                d.rmdir() # We need the random name, but we want to create the directory ourselves

                if path.is_dir():
                    bases += [path]
                elif path.suffix == ".tar":
                    shutil.unpack_archive(path, d)
                    bases += [d]
                elif path.suffix == ".raw":
                    stack.enter_context(dissect_and_mount(path, d))
                    bases += [d]
                else:
                    die(f"Unsupported base tree source {path}")

            stack.enter_context(mount_overlay(bases, state.root, state.workdir, state.root, read_only=False))

        yield


def prepare_tree_root(state: MkosiState) -> None:
    if state.config.output_format == OutputFormat.subvolume:
        with complete_step("Setting up OS tree root…"):
            btrfs_subvol_create(state.root)


def clean_paths(
        root: Path,
        globs: Sequence[str],
        tool: str,
        always: bool) -> None:
    """Remove globs under root if always or if tool is not found under root."""

    toolp = root / tool.lstrip('/')
    cond = always or not os.access(toolp, os.F_OK, follow_symlinks=False)

    paths = flatten(root.glob(glob.lstrip('/')) for glob in globs)

    if not cond or not paths:
        return

    with complete_step(f"Cleaning {toolp.name} metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_dnf_metadata(root: Path, always: bool) -> None:
    """Remove dnf metadata if /bin/dnf is not present in the image

    If dnf is not installed, there doesn't seem to be much use in keeping the
    dnf metadata, since it's not usable from within the image anyway.
    """
    paths = [
        "/var/lib/dnf",
        "/var/log/dnf.*",
        "/var/log/hawkey.*",
        "/var/cache/dnf",
    ]

    clean_paths(root, paths, tool='/bin/dnf', always=always)


def clean_yum_metadata(root: Path, always: bool) -> None:
    """Remove yum metadata if /bin/yum is not present in the image"""
    paths = [
        "/var/lib/yum",
        "/var/log/yum.*",
        "/var/cache/yum",
    ]

    clean_paths(root, paths, tool='/bin/yum', always=always)


def clean_zypper_metadata(root: Path, always: bool) -> None:
    """Remove zypper metadata if /usr/bin/zypper is not present in the image"""
    paths = [
        "/var/lib/zypp",
        "/var/log/zypp",
        "/var/cache/zypp",
    ]

    clean_paths(root, paths, tool='/usr/bin/zypper', always=always)


def clean_rpm_metadata(root: Path, always: bool) -> None:
    """Remove rpm metadata if /bin/rpm is not present in the image"""
    paths = [
        "/var/lib/rpm",
        "/usr/lib/sysimage/rpm",
    ]

    clean_paths(root, paths, tool='/bin/rpm', always=always)


def clean_apt_metadata(root: Path, always: bool) -> None:
    """Remove apt metadata if /usr/bin/apt is not present in the image"""
    paths = [
        "/var/lib/apt",
        "/var/log/apt",
        "/var/cache/apt",
    ]

    clean_paths(root, paths, tool='/usr/bin/apt', always=always)


def clean_dpkg_metadata(root: Path, always: bool) -> None:
    """Remove dpkg metadata if /usr/bin/dpkg is not present in the image"""
    paths = [
        "/var/lib/dpkg",
        "/var/log/dpkg.log",
    ]

    clean_paths(root, paths, tool='/usr/bin/dpkg', always=always)


def clean_pacman_metadata(root: Path, always: bool) -> None:
    """Remove pacman metadata if /usr/bin/pacman is not present in the image"""
    paths = [
        "/var/lib/pacman",
        "/var/cache/pacman",
        "/var/log/pacman.log"
    ]

    clean_paths(root, paths, tool='/usr/bin/pacman', always=always)


def clean_package_manager_metadata(state: MkosiState) -> None:
    """Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if the
    package manager is present in the image.
    """

    assert state.config.clean_package_metadata in (False, True, None)
    if state.config.clean_package_metadata is False or state.for_cache:
        return

    # we try then all: metadata will only be touched if any of them are in the
    # final image
    always = state.config.clean_package_metadata is True
    clean_dnf_metadata(state.root, always=always)
    clean_yum_metadata(state.root, always=always)
    clean_rpm_metadata(state.root, always=always)
    clean_apt_metadata(state.root, always=always)
    clean_dpkg_metadata(state.root, always=always)
    clean_pacman_metadata(state.root, always=always)
    clean_zypper_metadata(state.root, always=always)
    # FIXME: implement cleanup for other package managers: swupd


def remove_files(state: MkosiState) -> None:
    """Remove files based on user-specified patterns"""

    if not state.config.remove_files or state.for_cache:
        return

    with complete_step("Removing files…"):
        for pattern in state.config.remove_files:
            for p in state.root.glob(pattern.lstrip("/")):
                unlink_try_hard(p)


def install_distribution(state: MkosiState, cached: bool) -> None:
    if cached:
        return

    if state.config.base_trees:
        if not state.config.packages:
            return

        with complete_step(f"Installing extra packages for {str(state.config.distribution).capitalize()}"):
            state.installer.install_packages(state, state.config.packages)
    else:
        with complete_step(f"Installing {str(state.config.distribution).capitalize()}"):
            state.installer.install(state)

            # Ensure /efi exists so that the ESP is mounted there, as recommended by
            # https://0pointer.net/blog/linux-boot-partitions.html. Use the most restrictive access mode we
            # can without tripping up mkfs tools since this directory is only meant to be overmounted and
            # should not be read from or written to.
            state.root.joinpath("efi").mkdir(mode=0o500, exist_ok=True)

            if state.config.packages:
                state.installer.install_packages(state, state.config.packages)


def install_build_packages(state: MkosiState, cached: bool) -> None:
    if state.config.build_script is None or cached:
        return

    with mount_build_overlay(state):
        state.installer.install_packages(state, state.config.build_packages)

        # Create a few necessary mount points inside the build overlay for later.
        state.root.joinpath("work").mkdir(mode=0o755)
        state.root.joinpath("work/src").mkdir(mode=0o755)
        state.root.joinpath("work/dest").mkdir(mode=0o755)
        state.root.joinpath("work/build-script").touch(mode=0o755)
        state.root.joinpath("work/build").mkdir(mode=0o755)


def remove_packages(state: MkosiState) -> None:
    """Remove packages listed in config.remove_packages"""

    if not state.config.remove_packages or state.for_cache:
        return

    with complete_step(f"Removing {len(state.config.packages)} packages…"):
        try:
            state.installer.remove_packages(state, state.config.remove_packages)
        except NotImplementedError:
            die(f"Removing packages is not supported for {state.config.distribution}")


def reset_machine_id(state: MkosiState) -> None:
    """Make /etc/machine-id an empty file.

    This way, on the next boot is either initialized and committed (if /etc is
    writable) or the image runs with a transient machine ID, that changes on
    each boot (if the image is read-only).
    """

    if state.for_cache:
        return

    with complete_step("Resetting machine ID"):
        machine_id = state.root / "etc/machine-id"
        machine_id.unlink(missing_ok=True)
        machine_id.write_text("uninitialized\n")


def reset_random_seed(root: Path) -> None:
    """Remove random seed file, so that it is initialized on first boot"""
    random_seed = root / "var/lib/systemd/random-seed"
    if not random_seed.exists():
        return

    with complete_step("Removing random seed"):
        random_seed.unlink()


def configure_root_password(state: MkosiState) -> None:
    "Set the root account password, or just delete it so it's easy to log in"

    if state.for_cache:
        return

    if state.config.password == "":
        with complete_step("Deleting root password"):

            def delete_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", ""] + line.split(":")[2:])
                return line

            patch_file(state.root / "etc/passwd", delete_root_pw)
    elif state.config.password:
        with complete_step("Setting root password"):
            if state.config.password_is_hashed:
                password = state.config.password
            else:
                password = crypt.crypt(state.config.password, crypt.mksalt(crypt.METHOD_SHA512))

            def set_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", password] + line.split(":")[2:])
                return line

            shadow = state.root / "etc/shadow"
            try:
                patch_file(shadow, set_root_pw)
            except FileNotFoundError:
                shadow.write_text(f"root:{password}:0:0:99999:7:::\n")


def configure_autologin(state: MkosiState) -> None:
    if not state.config.autologin or state.for_cache:
        return

    with complete_step("Setting up autologin…"):
        add_dropin_config_from_resource(state.root, "console-getty.service", "autologin",
                                        "mkosi.resources", "console_getty_autologin.conf")
        add_dropin_config_from_resource(state.root, "serial-getty@ttyS0.service", "autologin",
                                        "mkosi.resources", "serial_getty_autologin.conf")
        add_dropin_config_from_resource(state.root, "serial-getty@hvc0.service", "autologin",
                                        "mkosi.resources", "serial_getty_autologin.conf")
        add_dropin_config_from_resource(state.root, "getty@tty1.service", "autologin",
                                        "mkosi.resources", "getty_autologin.conf")



def mount_build_overlay(state: MkosiState, read_only: bool = False) -> ContextManager[Path]:
    return mount_overlay([state.root], state.build_overlay, state.workdir, state.root, read_only)


def run_prepare_script(state: MkosiState, cached: bool, build: bool) -> None:
    if state.config.prepare_script is None:
        return
    if cached:
        return
    if build and state.config.build_script is None:
        return

    bwrap: list[PathString] = [
        "--bind", state.config.build_sources, "/root/src",
        "--bind", state.config.prepare_script, "/root/prepare",
        "--chdir", "/root/src",
    ]

    def clean() -> None:
        srcdir = state.root / "root/src"
        if srcdir.exists():
            srcdir.rmdir()

        state.root.joinpath("root/prepare").unlink()

    if build:
        with complete_step("Running prepare script in build overlay…"), mount_build_overlay(state):
            run_workspace_command(
                state,
                ["/root/prepare", "build"],
                network=True,
                bwrap_params=bwrap,
                env=dict(SRCDIR="/root/src"),
            )
            clean()
    else:
        with complete_step("Running prepare script…"):
            run_workspace_command(
                state,
                ["/root/prepare", "final"],
                network=True,
                bwrap_params=bwrap,
                env=dict(SRCDIR="/root/src"),
            )
            clean()


def run_postinst_script(state: MkosiState) -> None:
    if state.config.postinst_script is None:
        return
    if state.for_cache:
        return

    with complete_step("Running postinstall script…"):
        bwrap: list[PathString] = [
            "--bind", state.config.postinst_script, "/root/postinst",
        ]

        run_workspace_command(state, ["/root/postinst", "final"], bwrap_params=bwrap,
                              network=state.config.with_network)

        state.root.joinpath("root/postinst").unlink()


def run_finalize_script(state: MkosiState) -> None:
    if state.config.finalize_script is None:
        return
    if state.for_cache:
        return

    with complete_step("Running finalize script…"):
        run([state.config.finalize_script],
            env={**state.environment, "BUILDROOT": str(state.root), "OUTPUTDIR": str(state.config.output_dir or Path.cwd())})


def install_boot_loader(state: MkosiState) -> None:
    if state.for_cache or state.config.bootable is False:
        return

    if state.config.output_format == OutputFormat.cpio and state.config.bootable is None:
        return

    directory = state.root / "usr/lib/systemd/boot/efi"
    if not directory.exists() or not any(directory.iterdir()):
        if state.config.bootable is True:
            die("A bootable image was requested but systemd-boot was not found at "
                f"{directory.relative_to(state.root)}")
        return

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        with complete_step("Signing systemd-boot binaries…"):
            for f in itertools.chain(directory.glob('*.efi'), directory.glob('*.EFI')):
                run(["sbsign",
                     "--key", state.config.secure_boot_key,
                     "--cert", state.config.secure_boot_certificate,
                     "--output", f"{f}.signed",
                     f])

    with complete_step("Installing boot loader…"):
        run(["bootctl", "install", "--root", state.root], env={"SYSTEMD_ESP_PATH": "/boot"})

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        with complete_step("Setting up secure boot auto-enrollment…"):
            keys = state.root / "boot/loader/keys/auto"
            keys.mkdir(parents=True, exist_ok=True)

            # sbsiglist expects a DER certificate.
            run(["openssl",
                 "x509",
                 "-outform", "DER",
                 "-in", state.config.secure_boot_certificate,
                 "-out", state.workspace / "mkosi.der"])
            run(["sbsiglist",
                 "--owner", str(uuid.uuid4()),
                 "--type", "x509",
                 "--output", state.workspace / "mkosi.esl",
                 state.workspace / "mkosi.der"])

            # We reuse the key for all secure boot databases to keep things simple.
            for db in ["PK", "KEK", "db"]:
                run(["sbvarsign",
                     "--attr",
                         "NON_VOLATILE,BOOTSERVICE_ACCESS,RUNTIME_ACCESS,TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
                     "--key", state.config.secure_boot_key,
                     "--cert", state.config.secure_boot_certificate,
                     "--output", keys / f"{db}.auth",
                     db,
                     state.workspace / "mkosi.esl"])


def install_base_trees(state: MkosiState, cached: bool) -> None:
    if not state.config.base_trees or cached or state.config.overlay:
        return

    with complete_step("Copying in base trees…"):
        for path in state.config.base_trees:

            if path.is_dir():
                copy_path(path, state.root)
            elif path.suffix == ".tar":
                shutil.unpack_archive(path, state.root)
            elif path.suffix == ".raw":
                run(["systemd-dissect", "--copy-from", path, "/", state.root])
            else:
                die(f"Unsupported base tree source {path}")

            if path.is_dir():
                copy_path(path, state.root)
            else:
                shutil.unpack_archive(path, state.root)


def install_skeleton_trees(state: MkosiState, cached: bool) -> None:
    if not state.config.skeleton_trees or cached:
        return

    with complete_step("Copying in skeleton file trees…"):
        for source, target in state.config.skeleton_trees:
            t = state.root
            if target:
                t = state.root / target.relative_to("/")

            t.mkdir(mode=0o755, parents=True, exist_ok=True)
            if source.is_dir():
                copy_path(source, t, preserve_owner=False)
            else:
                shutil.unpack_archive(source, t)


def install_extra_trees(state: MkosiState) -> None:
    if not state.config.extra_trees:
        return

    if state.for_cache:
        return

    with complete_step("Copying in extra file trees…"):
        for source, target in state.config.extra_trees:
            t = state.root
            if target:
                t = state.root / target.relative_to("/")

            t.mkdir(mode=0o755, parents=True, exist_ok=True)

            if source.is_dir():
                copy_path(source, t, preserve_owner=False)
            else:
                shutil.unpack_archive(source, t)


def install_build_dest(state: MkosiState) -> None:
    if state.for_cache:
        return

    if state.config.build_script is None:
        return

    with complete_step("Copying in build tree…"):
        # The build is executed as a regular user, so we don't want to copy ownership in this scenario.
        copy_path(install_dir(state), state.root, preserve_owner=False)


def xz_binary() -> str:
    return "pxz" if shutil.which("pxz") else "xz"


def compressor_command(compression: Compression, src: Path) -> list[PathString]:
    """Returns a command suitable for compressing archives."""

    if compression == Compression.xz:
        return [xz_binary(), "--check=crc32", "--lzma2=dict=1MiB", "-T0", src]
    elif compression == Compression.zst:
        return ["zstd", "-q", "-T0", "--rm", src]
    else:
        die(f"Unknown compression {compression}")


def tar_binary() -> str:
    # Some distros (Mandriva) install BSD tar as "tar", hence prefer
    # "gtar" if it exists, which should be GNU tar wherever it exists.
    # We are interested in exposing same behaviour everywhere hence
    # it's preferable to use the same implementation of tar
    # everywhere. In particular given the limited/different SELinux
    # support in BSD tar and the different command line syntax
    # compared to GNU tar.
    return "gtar" if shutil.which("gtar") else "tar"


def make_tar(state: MkosiState) -> None:
    if state.config.output_format != OutputFormat.tar:
        return
    if state.for_cache:
        return

    cmd: list[PathString] = [tar_binary(), "-C", state.root, "-c", "--xattrs", "--xattrs-include=*"]
    if state.config.tar_strip_selinux_context:
        cmd += ["--xattrs-exclude=security.selinux"]

    cmd += [".", "-f", state.staging / state.config.output.name]

    with complete_step("Creating archive…"):
        run(cmd)


def find_files(dir: Path, root: Path) -> Iterator[Path]:
    """Generate a list of all filepaths in directory @dir relative to @root"""
    yield from scandir_recursive(dir,
                                 lambda entry: Path(entry.path).relative_to(root))


def make_initrd(state: MkosiState) -> None:
    if state.config.output_format != OutputFormat.cpio:
        return
    if state.for_cache:
        return

    make_cpio(state.root, find_files(state.root, state.root), state.staging / state.config.output.name)


def make_cpio(root: Path, files: Iterator[Path], output: Path) -> None:
    with complete_step("Creating archive…"):
        cmd: list[PathString] = [
            "cpio", "-o", "--reproducible", "--null", "-H", "newc", "--quiet", "-D", root, "-O", output
        ]

        with spawn(cmd, stdin=subprocess.PIPE, text=True) as cpio:
            #  https://github.com/python/mypy/issues/10583
            assert cpio.stdin is not None

            for file in files:
                cpio.stdin.write(os.fspath(file))
                cpio.stdin.write("\0")
            cpio.stdin.close()


def make_directory(state: MkosiState) -> None:
    if state.config.output_format != OutputFormat.directory or state.for_cache:
        return

    os.rename(state.root, state.staging / state.config.output.name)


def gen_kernel_images(state: MkosiState) -> Iterator[tuple[str, Path]]:
    if not state.root.joinpath("usr/lib/modules").exists():
        return

    for kver in sorted(
        (k for k in state.root.joinpath("usr/lib/modules").iterdir() if k.is_dir()),
        key=lambda k: GenericVersion(k.name),
        reverse=True
    ):
        kimg = Path("usr/lib/modules") / kver.name / "vmlinuz"
        if not kimg.exists():
            kimg = state.installer.kernel_image(kver.name, state.config.architecture)

        yield kver.name, kimg


def gen_kernel_modules_initrd(state: MkosiState, kver: str) -> Path:
    kmods = state.workspace / f"initramfs-kernel-modules-{kver}.img"

    def files() -> Iterator[Path]:
        yield state.root.joinpath("usr/lib/modules").relative_to(state.root)
        yield state.root.joinpath("usr/lib/modules").joinpath(kver).relative_to(state.root)
        for p in find_files(state.root / "usr/lib/modules" / kver, state.root):
            if p.name != "vmlinuz":
                yield p

    with complete_step(f"Generating kernel modules initrd for kernel {kver}"):
        make_cpio(state.root, files(), kmods)

    return kmods


def install_unified_kernel(state: MkosiState, roothash: Optional[str]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if state.for_cache or state.config.bootable is False:
        return

    for kver, kimg in gen_kernel_images(state):
        copy_path(state.root / kimg, state.staging / state.config.output_split_kernel.name)
        break

    if state.config.output_format == OutputFormat.cpio and state.config.bootable is None:
        return

    for kver, kimg in gen_kernel_images(state):
        with complete_step(f"Generating unified kernel image for {kimg}"):
            image_id = state.config.image_id or f"mkosi-{state.config.distribution}"

            # See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/#boot-counting
            boot_count = ""
            if state.root.joinpath("etc/kernel/tries").exists():
                boot_count = f'+{state.root.joinpath("etc/kernel/tries").read_text().strip()}'

            if state.config.image_version:
                boot_binary = state.root / f"boot/EFI/Linux/{image_id}_{state.config.image_version}{boot_count}.efi"
            elif roothash:
                _, _, h = roothash.partition("=")
                boot_binary = state.root / f"boot/EFI/Linux/{image_id}-{kver}-{h}{boot_count}.efi"
            else:
                boot_binary = state.root / f"boot/EFI/Linux/{image_id}-{kver}{boot_count}.efi"

            if state.root.joinpath("etc/kernel/cmdline").exists():
                cmdline = [state.root.joinpath("etc/kernel/cmdline").read_text().strip()]
            elif state.root.joinpath("/usr/lib/kernel/cmdline").exists():
                cmdline = [state.root.joinpath("usr/lib/kernel/cmdline").read_text().strip()]
            else:
                cmdline = []

            cmdline += state.installer.kernel_command_line(state)

            if roothash:
                cmdline += [roothash]

            cmdline += state.config.kernel_command_line

            # Older versions of systemd-stub expect the cmdline section to be null terminated. We can't embed
            # nul terminators in argv so let's communicate the cmdline via a file instead.
            state.workspace.joinpath("cmdline").write_text(f"{' '.join(cmdline).strip()}\x00")

            stub = state.root / f"lib/systemd/boot/efi/linux{EFI_ARCHITECTURES[state.config.architecture]}.efi.stub"
            if not stub.exists():
                die(f"sd-stub not found at /{stub.relative_to(state.root)} in the image")

            cmd: list[PathString] = [
                shutil.which("ukify") or "/usr/lib/systemd/ukify",
                "--cmdline", f"@{state.workspace / 'cmdline'}",
                "--os-release", f"@{state.root / 'usr/lib/os-release'}",
                "--stub", stub,
                "--output", boot_binary,
                "--efi-arch", EFI_ARCHITECTURES[state.config.architecture],
            ]

            for p in state.config.extra_search_paths:
                cmd += ["--tools", p]

            if state.config.secure_boot:
                assert state.config.secure_boot_key
                assert state.config.secure_boot_certificate

                cmd += [
                    "--secureboot-private-key", state.config.secure_boot_key,
                    "--secureboot-certificate", state.config.secure_boot_certificate,
                ]

                if state.config.sign_expected_pcr:
                    cmd += [
                        "--pcr-private-key", state.config.secure_boot_key,
                        "--pcr-banks", "sha1,sha256",
                    ]

            if state.config.initrds:
                initrds = state.config.initrds + [gen_kernel_modules_initrd(state, kver)]
            else:
                initrd = state.root / state.installer.initrd_path(kver)
                if not initrd.exists():
                    die(f"Initrd not found at {initrd}")

                initrds = [initrd]

            cmd += [state.root / kimg] + initrds

            run(cmd)

            if not state.staging.joinpath(state.config.output_split_uki.name).exists():
                copy_path(boot_binary, state.staging / state.config.output_split_uki.name)

    if state.config.bootable is True and not state.staging.joinpath(state.config.output_split_uki.name).exists():
        die("A bootable image was requested but no kernel was found")


def compress_output(config: MkosiConfig, src: Path, uid: int, gid: int) -> None:
    if not src.is_file():
        return

    if config.compress_output == Compression.none:
        # If we shan't compress, then at least make the output file sparse
        with complete_step(f"Digging holes into output file {src}…"):
            run(["fallocate", "--dig-holes", src], user=uid, group=gid)
    else:
        with complete_step(f"Compressing output file {src}…"):
            run(compressor_command(config.compress_output, src), user=uid, group=gid)


def copy_nspawn_settings(state: MkosiState) -> None:
    if state.config.nspawn_settings is None:
        return None

    with complete_step("Copying nspawn settings file…"):
        copy_path(state.config.nspawn_settings, state.staging / state.config.output_nspawn_settings.name)


def hash_file(of: TextIO, path: Path) -> None:
    bs = 16 * 1024**2
    h = hashlib.sha256()

    with path.open("rb") as sf:
        while (buf := sf.read(bs)):
            h.update(buf)

    of.write(h.hexdigest() + " *" + path.name + "\n")


def calculate_sha256sum(state: MkosiState) -> None:
    if state.config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        return None

    if not state.config.checksum:
        return None

    with complete_step("Calculating SHA256SUMS…"):
        with open(state.workspace / state.config.output_checksum.name, "w") as f:
            for p in state.staging.iterdir():
                hash_file(f, p)

        os.rename(state.workspace / state.config.output_checksum.name, state.staging / state.config.output_checksum.name)


def calculate_signature(state: MkosiState) -> None:
    if not state.config.sign:
        return None

    with complete_step("Signing SHA256SUMS…"):
        cmdline: list[PathString] = [
            "gpg",
            "--detach-sign",
            "-o", state.staging / state.config.output_signature.name,
            state.staging / state.config.output_checksum.name,
        ]

        if state.config.key is not None:
            cmdline += ["--default-key", state.config.key]

        run(cmdline)


def acl_toggle_remove(config: MkosiConfig, root: Path, uid: int, *, allow: bool) -> None:
    if not config.acl:
        return

    ret = run(["setfacl",
               "--physical",
               "--modify" if allow else "--remove",
               f"user:{uid}:rwx" if allow else f"user:{uid}",
               "-"],
              check=False,
              text=True,
              # Supply files via stdin so we don't clutter --debug run output too much
              input="\n".join([str(root),
                               *(e.path for e in cast(Iterator[os.DirEntry[str]], scandir_recursive(root)) if e.is_dir())])
    )
    if ret.returncode != 0:
        warn("Failed to set ACLs, you'll need root privileges to remove some generated files/directories")


def save_cache(state: MkosiState) -> None:
    final, build = cache_tree_paths(state.config)

    with complete_step("Installing cache copies"):
        unlink_try_hard(final)
        shutil.move(state.root, final)
        acl_toggle_remove(state.config, final, state.uid, allow=True)

        if state.config.build_script:
            unlink_try_hard(build)
            shutil.move(state.build_overlay, build)
            acl_toggle_remove(state.config, build, state.uid, allow=True)


def dir_size(path: PathString) -> int:
    dir_sum = 0
    for entry in os.scandir(path):
        if entry.is_symlink():
            # We can ignore symlinks because they either point into our tree,
            # in which case we'll include the size of target directory anyway,
            # or outside, in which case we don't need to.
            continue
        elif entry.is_file():
            dir_sum += entry.stat().st_blocks * 512
        elif entry.is_dir():
            dir_sum += dir_size(entry.path)
    return dir_sum


def save_manifest(state: MkosiState, manifest: Manifest) -> None:
    if manifest.has_data():
        if ManifestFormat.json in state.config.manifest_format:
            with complete_step(f"Saving manifest {state.config.output_manifest.name}"):
                with open(state.staging / state.config.output_manifest.name, 'w') as f:
                    manifest.write_json(f)

        if ManifestFormat.changelog in state.config.manifest_format:
            with complete_step(f"Saving report {state.config.output_changelog.name}"):
                with open(state.staging / state.config.output_changelog.name, 'w') as f:
                    manifest.write_package_report(f)


def print_output_size(config: MkosiConfig) -> None:
    if not config.output_compressed.exists():
        return

    if config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        MkosiPrinter.print_step("Resulting image size is " + format_bytes(dir_size(config.output)) + ".")
    else:
        st = os.stat(config.output_compressed)
        size = format_bytes(st.st_size)
        space = format_bytes(st.st_blocks * 512)
        MkosiPrinter.print_step(f"Resulting image size is {size}, consumes {space}.")


def empty_directory(path: Path) -> None:
    try:
        for f in os.listdir(path):
            unlink_try_hard(path / f)
    except FileNotFoundError:
        pass


def unlink_output(config: MkosiConfig) -> None:
    with complete_step("Removing output files…"):
        if config.output.parent.exists():
            for p in config.output.parent.iterdir():
                if p.name.startswith(config.output.name) and "cache" not in p.name:
                    unlink_try_hard(p)
        unlink_try_hard(Path(f"{config.output}.manifest"))
        unlink_try_hard(Path(f"{config.output}.changelog"))

        if config.checksum:
            unlink_try_hard(config.output_checksum)

        if config.sign:
            unlink_try_hard(config.output_signature)

        if config.output_split_kernel.parent.exists():
            for p in config.output_split_kernel.parent.iterdir():
                if p.name.startswith(config.output_split_kernel.name):
                    unlink_try_hard(p)
        unlink_try_hard(config.output_split_kernel)

        if config.output_split_uki.parent.exists():
            for p in config.output_split_uki.parent.iterdir():
                if p.name.startswith(config.output_split_uki.name):
                    unlink_try_hard(p)
        unlink_try_hard(config.output_split_uki)

        if config.nspawn_settings is not None:
            unlink_try_hard(config.output_nspawn_settings)

    if config.ssh and config.output_sshkey is not None:
        unlink_try_hard(config.output_sshkey)

    # We remove any cached images if either the user used --force
    # twice, or he/she called "clean" with it passed once. Let's also
    # remove the downloaded package cache if the user specified one
    # additional "--force".

    if config.verb == Verb.clean:
        remove_build_cache = config.force > 0
        remove_package_cache = config.force > 1
    else:
        remove_build_cache = config.force > 1
        remove_package_cache = config.force > 2

    if remove_build_cache:
        with complete_step("Removing incremental cache files…"):
            for p in cache_tree_paths(config):
                unlink_try_hard(p)

        if config.build_dir is not None:
            with complete_step("Clearing out build directory…"):
                empty_directory(config.build_dir)

        if config.install_dir is not None:
            with complete_step("Clearing out install directory…"):
                empty_directory(config.install_dir)

    if remove_package_cache:
        if config.cache_dir is not None:
            with complete_step("Clearing out package cache…"):
                empty_directory(config.cache_dir)


def require_private_file(name: Path, description: str) -> None:
    mode = os.stat(name).st_mode & 0o777
    if mode & 0o007:
        warn(dedent(f"""\
            Permissions of '{name}' of '{mode:04o}' are too open.
            When creating {description} files use an access mode that restricts access to the owner only.
        """))


def find_password(args: argparse.Namespace) -> None:
    if args.password is not None:
        return

    try:
        pwfile = Path("mkosi.rootpw")
        require_private_file(pwfile, "root password")

        args.password = pwfile.read_text().strip()

    except FileNotFoundError:
        pass


def find_image_version(args: argparse.Namespace) -> None:
    if args.image_version is not None:
        return

    try:
        with open("mkosi.version") as f:
            args.image_version = f.read().strip()
    except FileNotFoundError:
        pass


def load_credentials(args: argparse.Namespace) -> dict[str, str]:
    creds = {}

    d = Path("mkosi.credentials")
    if d.is_dir():
        for e in d.iterdir():
            if os.access(e, os.X_OK):
                creds[e.name] = run([e], text=True, stdout=subprocess.PIPE, env=os.environ).stdout
            else:
                creds[e.name] = e.read_text()

    for s in args.credentials:
        key, _, value = s.partition("=")
        creds[key] = value

    if "firstboot.timezone" not in creds:
        tz = run(
            ["timedatectl", "show", "-p", "Timezone", "--value"],
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        creds["firstboot.timezone"] = tz

    if "firstboot.locale" not in creds:
        creds["firstboot.locale"] = "C.UTF-8"

    if "firstboot.hostname" not in creds:
        creds["firstboot.hostname"] = machine_name(args)

    if args.ssh and "ssh.authorized_keys.root" not in creds and "SSH_AUTH_SOCK" in os.environ:
        key = run(
            ["ssh-add", "-L"],
            text=True,
            stdout=subprocess.PIPE,
            env=os.environ,
        ).stdout.strip()
        creds["ssh.authorized_keys.root"] = key

    return creds


def load_kernel_command_line_extra(args: argparse.Namespace) -> list[str]:
    columns, lines = shutil.get_terminal_size()

    cmdline = [
        f"systemd.tty.term.hvc0={os.getenv('TERM', 'vt220')}",
        f"systemd.tty.columns.hvc0={columns}",
        f"systemd.tty.rows.hvc0={lines}",
        f"systemd.tty.term.ttyS0={os.getenv('TERM', 'vt220')}",
        f"systemd.tty.columns.ttyS0={columns}",
        f"systemd.tty.rows.ttyS0={lines}",
        "console=hvc0",
    ]

    if args.output_format == OutputFormat.cpio:
        cmdline += ["rd.systemd.unit=default.target"]

    for s in args.kernel_command_line_extra:
        key, sep, value = s.partition("=")
        if " " in value:
            value = f'"{value}"'
        cmdline += [key if not sep else f"{key}={value}"]

    return cmdline


def load_args(args: argparse.Namespace) -> MkosiConfig:
    ARG_DEBUG.update(args.debug)

    find_image_version(args)

    args.extra_search_paths = expand_paths(args.extra_search_paths)

    if args.cmdline and args.verb not in MKOSI_COMMANDS_CMDLINE:
        die(f"Parameters after verb are only accepted for {list_to_string(verb.name for verb in MKOSI_COMMANDS_CMDLINE)}.")

    if args.verb == Verb.qemu and args.output_format in (
        OutputFormat.directory,
        OutputFormat.subvolume,
        OutputFormat.tar,
    ):
        die("Directory, subvolume, tar, cpio, and plain squashfs images cannot be booted in qemu.")

    if shutil.which("bsdtar") and args.distribution == Distribution.openmandriva and args.tar_strip_selinux_context:
        die("Sorry, bsdtar on OpenMandriva is incompatible with --tar-strip-selinux-context")

    if args.cache_dir:
        args.cache_dir = args.cache_dir / f"{args.distribution}~{args.release}"
    if args.build_dir:
        args.build_dir = args.build_dir / f"{args.distribution}~{args.release}"
    if args.output_dir:
        args.output_dir = args.output_dir / f"{args.distribution}~{args.release}"

    if args.mirror is None:
        if args.distribution in (Distribution.fedora, Distribution.centos):
            args.mirror = None
        elif args.distribution == Distribution.debian:
            args.mirror = "http://deb.debian.org/debian"
        elif args.distribution == Distribution.ubuntu:
            if args.architecture == "x86" or args.architecture == "x86_64":
                args.mirror = "http://archive.ubuntu.com/ubuntu"
            else:
                args.mirror = "http://ports.ubuntu.com"
        elif args.distribution == Distribution.arch:
            if args.architecture == "aarch64":
                args.mirror = "http://mirror.archlinuxarm.org"
            else:
                args.mirror = "https://geo.mirror.pkgbuild.com"
        elif args.distribution == Distribution.opensuse:
            args.mirror = "https://download.opensuse.org"
        elif args.distribution == Distribution.rocky:
            args.mirror = None
        elif args.distribution == Distribution.alma:
            args.mirror = None

    if args.sign:
        args.checksum = True

    if args.compress_output is None:
        args.compress_output = Compression.zst if args.output_format == OutputFormat.cpio else Compression.none

    if args.output is None:
        iid = args.image_id if args.image_id is not None else "image"
        prefix = f"{iid}_{args.image_version}" if args.image_version is not None else iid

        if args.output_format == OutputFormat.disk:
            output = f"{prefix}.raw"
        elif args.output_format == OutputFormat.tar:
            output = f"{prefix}.tar"
        elif args.output_format == OutputFormat.cpio:
            output = f"{prefix}.cpio"
        else:
            output = prefix
        args.output = Path(output)

    if args.output_dir is not None:
        if "/" not in str(args.output):
            args.output = args.output_dir / args.output
        else:
            warn("Ignoring configured output directory as output file is a qualified path.")

    args.output = args.output.absolute()

    if args.environment:
        env = {}
        for s in args.environment:
            key, _, value = s.partition("=")
            value = value or os.getenv(key, "")
            env[key] = value
        args.environment = env
    else:
        args.environment = {}

    args.credentials = load_credentials(args)
    args.kernel_command_line_extra = load_kernel_command_line_extra(args)

    if args.secure_boot and args.verb != Verb.genkey:
        if args.secure_boot_key is None:
            die("UEFI SecureBoot enabled, but couldn't find private key.",
                hint="Consider placing it in mkosi.secure-boot.key")

        if args.secure_boot_certificate is None:
            die("UEFI SecureBoot enabled, but couldn't find certificate.",
                hint="Consider placing it in mkosi.secure-boot.crt")

    if args.sign_expected_pcr is True and not shutil.which("systemd-measure"):
        die("Couldn't find systemd-measure needed for the --sign-expected-pcr option.")

    if args.sign_expected_pcr is None:
        args.sign_expected_pcr = bool(shutil.which("systemd-measure"))

    # Resolve passwords late so we can accurately determine whether a build is needed
    find_password(args)

    if args.verb in (Verb.shell, Verb.boot):
        opname = "acquire shell" if args.verb == Verb.shell else "boot"
        if args.output_format in (OutputFormat.tar, OutputFormat.cpio):
            die(f"Sorry, can't {opname} with a {args.output_format} archive.")
        if args.compress_output != Compression.none:
            die(f"Sorry, can't {opname} with a compressed image.")

    if args.repo_dirs and not (is_dnf_distribution(args.distribution) or args.distribution == Distribution.arch):
        die("--repo-dir is only supported on DNF based distributions and Arch")

    if args.qemu_kvm is True and not qemu_check_kvm_support():
        die("Sorry, the host machine does not support KVM acceleration.")

    if args.qemu_kvm is None:
        args.qemu_kvm = qemu_check_kvm_support()

    if args.repositories and not is_dnf_distribution(args.distribution) and args.distribution not in (Distribution.debian, Distribution.ubuntu):
        die("Sorry, the --repositories option is only supported on DNF/Debian based distributions")

    if args.initrds:
        args.initrds = [p.absolute() for p in args.initrds]
        for p in args.initrds:
            if not p.exists():
                die(f"Initrd {p} not found")
            if not p.is_file():
                die(f"Initrd {p} is not a file")

    if args.overlay and not args.base_trees:
        die("--overlay can only be used with --base-tree")

    # For unprivileged builds we need the userxattr OverlayFS mount option, which is only available in Linux v5.11 and later.
    with prepend_to_environ_path(args.extra_search_paths):
        if (args.build_script is not None or args.base_trees) and GenericVersion(platform.release()) < GenericVersion("5.11") and os.geteuid() != 0:
            die("This unprivileged build configuration requires at least Linux v5.11")

    return MkosiConfig(**vars(args))


def cache_tree_paths(config: MkosiConfig) -> tuple[Path, Path]:

    # If the image ID is specified, use cache file names that are independent of the image versions, so that
    # rebuilding and bumping versions is cheap and reuses previous versions if cached.
    if config.image_id is not None and config.output_dir:
        prefix = config.output_dir / config.image_id
    elif config.image_id:
        prefix = Path(config.image_id)
    # Otherwise, derive the cache file names directly from the output file names.
    else:
        prefix = config.output

    return (Path(f"{prefix}.cache"), Path(f"{prefix}.build.cache"))


def check_tree_input(path: Optional[Path]) -> None:
    # Each path may be a directory or a tarball.
    # Open the file or directory to simulate an access check.
    # If that fails, an exception will be thrown.
    if not path:
        return

    os.open(path, os.R_OK)


def check_source_target_input(tree: tuple[Path, Optional[Path]]) -> None:
    source, _ = tree
    os.open(source, os.R_OK)


def check_script_input(path: Optional[Path]) -> None:
    if not path:
        return

    os.open(path, os.R_OK)
    if not path.is_file():
        raise OSError(errno.ENOENT, 'Not a normal file')
    if not os.access(path, os.X_OK):
        raise OSError(errno.ENOENT, 'Not executable')
    return None


def check_inputs(config: MkosiConfig) -> None:
    try:
        for base in config.base_trees:
            check_tree_input(base)

        for tree in (config.skeleton_trees,
                     config.extra_trees):
            for item in tree:
                check_source_target_input(item)

        for path in (config.build_script,
                     config.prepare_script,
                     config.postinst_script,
                     config.finalize_script):
            check_script_input(path)
    except OSError as e:
        die(f'{e.filename} {e.strerror}')


def check_outputs(config: MkosiConfig) -> None:
    for f in (
        config.output,
        config.output_checksum if config.checksum else None,
        config.output_signature if config.sign else None,
        config.output_nspawn_settings if config.nspawn_settings is not None else None,
        config.output_sshkey if config.ssh else None,
    ):
        if f and f.exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def yes_no(b: Optional[bool]) -> str:
    return "yes" if b else "no"


def yes_no_auto(b: Optional[bool]) -> str:
    return "auto" if b is None else yes_no(b)


def none_to_na(s: Optional[T]) -> Union[T, str]:
    return "n/a" if s is None else s


def none_to_none(s: Optional[T]) -> Union[T, str]:
    return "none" if s is None else s


def none_to_default(s: Optional[T]) -> Union[T, str]:
    return "default" if s is None else s


def path_or_none(
        path: Optional[Path],
        checker: Optional[Callable[[Optional[Path]], None]] = None,
) -> Union[Optional[Path], str]:
    try:
        if checker:
            checker(path)
    except OSError as e:
        return f'{color_error(path)} ({e.strerror})'
    else:
        return path


def line_join_list(
        array: Sequence[PathString],
        checker: Optional[Callable[[Optional[Path]], None]] = None,
) -> str:
    if not array:
        return "none"

    items = (str(path_or_none(cast(Path, item), checker=checker)) for item in array)
    return "\n                            ".join(items)


def line_join_source_target_list(array: Sequence[tuple[Path, Optional[Path]]]) -> str:
    if not array:
        return "none"

    items = [f"{source}:{target}" if target else f"{source}" for source, target in array]
    return "\n                            ".join(items)


def print_summary(config: MkosiConfig) -> None:
    b = MkosiPrinter.bold
    e = MkosiPrinter.reset
    bold: Callable[..., str] = lambda s: f"{b}{s}{e}"

    maniformats = (" ".join(i.name for i in config.manifest_format)) or "(none)"
    env = [f"{k}={v}" for k, v in config.environment.items()]

    summary = f"""\
{bold("COMMANDS")}:
                      verb: {bold(config.verb)}
                   cmdline: {bold(" ".join(config.cmdline))}

{bold("DISTRIBUTION")}
              Distribution: {bold(config.distribution.name)}
                   Release: {bold(none_to_na(config.release))}
              Architecture: {config.architecture}
                    Mirror: {none_to_default(config.mirror)}
      Local Mirror (build): {none_to_none(config.local_mirror)}
  Repo Signature/Key check: {yes_no(config.repository_key_check)}
              Repositories: {",".join(config.repositories)}
                   Initrds: {",".join(os.fspath(p) for p in config.initrds)}

{bold("OUTPUT")}:
                  Image ID: {config.image_id}
             Image Version: {config.image_version}
             Output Format: {config.output_format.name}
          Manifest Formats: {maniformats}
          Output Directory: {none_to_default(config.output_dir)}
       Workspace Directory: {none_to_default(config.workspace_dir)}
                    Output: {bold(config.output_compressed)}
           Output Checksum: {none_to_na(config.output_checksum if config.checksum else None)}
          Output Signature: {none_to_na(config.output_signature if config.sign else None)}
    Output nspawn Settings: {none_to_na(config.output_nspawn_settings if config.nspawn_settings is not None else None)}
               Incremental: {yes_no(config.incremental)}
               Compression: {config.compress_output.name}
       Kernel Command Line: {" ".join(config.kernel_command_line)}
           UEFI SecureBoot: {yes_no(config.secure_boot)}
       SecureBoot Sign Key: {none_to_none(config.secure_boot_key)}
    SecureBoot Certificate: {none_to_none(config.secure_boot_certificate)}

{bold("CONTENT")}:
                  Packages: {line_join_list(config.packages)}
        With Documentation: {yes_no(config.with_docs)}
             Package Cache: {none_to_none(config.cache_dir)}
               Extra Trees: {line_join_source_target_list(config.extra_trees)}
    Clean Package Metadata: {yes_no_auto(config.clean_package_metadata)}
              Remove Files: {line_join_list(config.remove_files)}
           Remove Packages: {line_join_list(config.remove_packages)}
             Build Sources: {config.build_sources}
           Build Directory: {none_to_none(config.build_dir)}
         Install Directory: {none_to_none(config.install_dir)}
            Build Packages: {line_join_list(config.build_packages)}
              Build Script: {path_or_none(config.build_script, check_script_input)}
 Run Tests in Build Script: {yes_no(config.with_tests)}
        Postinstall Script: {path_or_none(config.postinst_script, check_script_input)}
            Prepare Script: {path_or_none(config.prepare_script, check_script_input)}
           Finalize Script: {path_or_none(config.finalize_script, check_script_input)}
        Script Environment: {line_join_list(env)}
      Scripts with network: {yes_no(config.with_network)}
           nspawn Settings: {none_to_none(config.nspawn_settings)}
                  Password: {("(default)" if config.password is None else "(set)")}
                 Autologin: {yes_no(config.autologin)}

{bold("HOST CONFIGURATION")}:
        Extra search paths: {line_join_list(config.extra_search_paths)}
      QEMU Extra Arguments: {line_join_list(config.qemu_args)}
    """

    if config.output_format == OutputFormat.disk:
        summary += f"""\

{bold("VALIDATION")}:
                  Checksum: {yes_no(config.checksum)}
                      Sign: {yes_no(config.sign)}
                   GPG Key: ({"default" if config.key is None else config.key})
        """

    page(summary, config.pager)


def make_output_dir(state: MkosiState) -> None:
    """Create the output directory if set and not existing yet"""
    if state.config.output_dir is None:
        return

    run(["mkdir", "-p", state.config.output_dir], user=state.uid, group=state.gid)


def make_build_dir(state: MkosiState) -> None:
    """Create the build directory if set and not existing yet"""
    if state.config.build_dir is None:
        return

    run(["mkdir", "-p", state.config.build_dir], user=state.uid, group=state.gid)


def make_cache_dir(state: MkosiState) -> None:
    # If no cache directory is configured, it'll be located in the workspace which is owned by root in the
    # userns so we have to run as the same user.
    run(["mkdir", "-p", state.cache],
        user=state.uid if state.config.cache_dir else 0,
        group=state.gid if state.config.cache_dir else 0)


def make_install_dir(state: MkosiState) -> None:
    # If no install directory is configured, it'll be located in the workspace which is owned by root in the
    # userns so we have to run as the same user.
    run(["mkdir", "-p", install_dir(state)],
        user=state.uid if state.config.install_dir else 0,
        group=state.gid if state.config.install_dir else 0)
    # Make sure the install dir is always owned by the user running mkosi since the build will be running as
    # the same user and needs to be able to write files here.
    os.chown(install_dir(state), state.uid, state.gid)


def configure_ssh(state: MkosiState) -> None:
    if state.for_cache or not state.config.ssh:
        return

    state.root.joinpath("etc/systemd/system/ssh.socket").write_text(
        dedent(
            """\
            [Unit]
            Description=Mkosi SSH Server VSock Socket
            ConditionVirtualization=!container
            Wants=sshd-keygen.target

            [Socket]
            ListenStream=vsock::22
            Accept=yes

            [Install]
            WantedBy=sockets.target
            """
        )
    )

    state.root.joinpath("etc/systemd/system/ssh@.service").write_text(
        dedent(
            """\
            [Unit]
            Description=Mkosi SSH Server
            After=sshd-keygen.target

            [Service]
            # We disable PAM because of an openssh-server bug where it sets PAM_RHOST=UNKNOWN when -i is used
            # causing a very slow reverse DNS lookup by pam.
            ExecStart=sshd -i -o UsePAM=no
            StandardInput=socket
            RuntimeDirectoryPreserve=yes
            # ssh always exits with 255 even on normal disconnect, so let's mark that as success so we don't
            # get noisy logs about SSH service failures.
            SuccessExitStatus=255
            """
        )
    )

    presetdir = state.root / "etc/systemd/system-preset"
    presetdir.mkdir(exist_ok=True, mode=0o755)
    presetdir.joinpath("80-mkosi-ssh.preset").write_text("enable ssh.socket")


def configure_initrd(state: MkosiState) -> None:
    if state.for_cache or not state.config.output_format == OutputFormat.cpio:
        return

    if not state.root.joinpath("init").exists():
        state.root.joinpath("init").symlink_to("/usr/lib/systemd/systemd")

    if not state.root.joinpath("etc/initrd-release").exists():
        state.root.joinpath("etc/initrd-release").symlink_to("/etc/os-release")


def run_kernel_install(state: MkosiState, cached: bool) -> None:
    if not state.config.cache_initrd and state.for_cache:
        return

    if state.config.cache_initrd and cached:
        return

    if state.config.initrds:
        return

    if state.config.bootable is False:
        return

    if state.config.bootable is None and state.config.output_format == OutputFormat.cpio:
        return

    # CentOS Stream 8 has an old version of kernel-install that unconditionally writes initrds to
    # /boot/<machine-id>/<kver>, so let's detect that and move them to the correct location.

    if (p := state.root / "etc/machine-id").exists():
        machine_id = p.read_text().strip()
    else:
        machine_id = None

    # kernel-install on Debian/Ubuntu does not rebuild the dracut initrd, so we do it manually here.
    if (state.root.joinpath("usr/bin/dracut").exists() and
        state.config.distribution in (Distribution.ubuntu, Distribution.debian) and
        not state.root.joinpath("usr/lib/kernel/install.d/50-dracut.install").exists() and
        not state.root.joinpath("etc/kernel/install.d/50-dracut.install").exists()):
        with complete_step("Running dpkg-reconfigure dracut…"):
            run_workspace_command(state, ["dpkg-reconfigure", "dracut"], env=dict(hostonly_l="no"))
            return

    with complete_step("Running kernel-install…"):
        for kver, kimg in gen_kernel_images(state):
            cmd: list[PathString] = ["kernel-install", "add", kver, Path("/") / kimg]

            if ARG_DEBUG:
                cmd.insert(1, "--verbose")

            # Make dracut think --no-host-only was passed via the CLI.
            run_workspace_command(state, cmd, env=dict(hostonly_l="no"))

            if machine_id and (p := state.root / "boot" / machine_id / kver / "initrd").exists():
                shutil.move(p, state.root / state.installer.initrd_path(kver))

    if machine_id and (p := state.root / "boot" / machine_id).exists():
        shutil.rmtree(p)


def run_sysusers(state: MkosiState) -> None:
    if state.for_cache:
        return

    with complete_step("Generating system users"):
        run(["systemd-sysusers", "--root", state.root])


def run_preset_all(state: MkosiState) -> None:
    if state.for_cache:
        return

    with complete_step("Applying presets…"):
        run(["systemctl", "--root", state.root, "preset-all"])


def run_selinux_relabel(state: MkosiState) -> None:
    if state.for_cache:
        return

    selinux = state.root / "etc/selinux/config"
    if not selinux.exists():
        return

    policy = run(["sh", "-c", f". {selinux} && echo $SELINUXTYPE"], text=True, stdout=subprocess.PIPE).stdout.strip()
    if not policy:
        return

    fc = Path('/etc/selinux') / policy / 'contexts/files/file_contexts'

    # We want to be able to relabel the underlying APIVFS mountpoints, so mount root non-recursive to a
    # temporary location so that the underlying mountpoints become visible.
    cmd = f"mkdir /tmp/relabel && mount --bind / /tmp/relabel && exec setfiles -m -r /tmp/relabel -F {fc} /tmp/relabel || exit $?"

    with complete_step(f"Relabeling files using {policy} policy"):
        run_workspace_command(state, ["sh", "-c", cmd])


def reuse_cache_tree(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    final, build = cache_tree_paths(state.config)
    if not final.exists() or (state.config.build_script and not build.exists()):
        return False
    if state.for_cache and final.exists() and (not state.config.build_script or build.exists()):
        return True

    with complete_step("Copying cached trees"):
        copy_path(final, state.root)
        acl_toggle_remove(state.config, state.root, state.uid, allow=False)
        if state.config.build_script:
            state.build_overlay.rmdir()
            state.build_overlay.symlink_to(build)

    return True


def invoke_repart(state: MkosiState, skip: Sequence[str] = [], split: bool = False) -> Optional[str]:
    if not state.config.output_format == OutputFormat.disk or state.for_cache:
        return None

    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--root", state.root,
        state.staging / state.config.output.name,
    ]

    if not state.staging.joinpath(state.config.output.name).exists():
        cmdline += ["--empty=create"]
    if state.config.passphrase:
        cmdline += ["--key-file", state.config.passphrase]
    if state.config.secure_boot_key:
        cmdline += ["--private-key", state.config.secure_boot_key]
    if state.config.secure_boot_certificate:
        cmdline += ["--certificate", state.config.secure_boot_certificate]
    if skip:
        cmdline += ["--defer-partitions", ",".join(skip)]
    if split and state.config.split_artifacts:
        cmdline += ["--split=yes"]

    if state.config.repart_dirs:
        for d in state.config.repart_dirs:
            cmdline += ["--definitions", d]
    else:
        definitions = state.workspace / "repart-definitions"
        if not definitions.exists():
            definitions.mkdir()
            bootdir = state.root.joinpath("boot/EFI/BOOT")

            # If Bootable=auto and we have at least one UKI and a bootloader, let's generate an ESP partition.
            add = (state.config.bootable is True or
                  (state.config.bootable is None and
                   bootdir.exists() and
                   any(bootdir.iterdir()) and
                   any(gen_kernel_images(state))))

            if add:
                definitions.joinpath("00-esp.conf").write_text(
                    dedent(
                        """\
                        [Partition]
                        Type=esp
                        Format=vfat
                        CopyFiles=/boot:/
                        SizeMinBytes=1024M
                        SizeMaxBytes=1024M
                        """
                    )
                )

            definitions.joinpath("10-root.conf").write_text(
                dedent(
                    f"""\
                    [Partition]
                    Type=root
                    Format={state.installer.filesystem()}
                    CopyFiles=/
                    Minimize=guess
                    """
                )
            )

        cmdline += ["--definitions", definitions]

    env = dict(TMPDIR=str(state.workspace))
    for fs, options in state.installer.filesystem_options(state).items():
        env[f"SYSTEMD_REPART_MKFS_OPTIONS_{fs.upper()}"] = " ".join(options)

    with complete_step("Generating disk image"):
        output = json.loads(run(cmdline, stdout=subprocess.PIPE, env=env).stdout)

    roothash = usrhash = None
    for p in output:
        if (h := p.get("roothash")) is None:
            continue

        if not (p["type"].startswith("usr") or p["type"].startswith("root")):
            die(f"Found roothash property on unexpected partition type {p['type']}")

        # When there's multiple verity enabled root or usr partitions, the first one wins.
        if p["type"].startswith("usr"):
            usrhash = usrhash or h
        else:
            roothash = roothash or h

    return f"roothash={roothash}" if roothash else f"usrhash={usrhash}" if usrhash else None


def build_image(state: MkosiState, *, manifest: Optional[Manifest] = None) -> None:
    with mount_image(state):
        cached = reuse_cache_tree(state)
        install_base_trees(state, cached)
        install_skeleton_trees(state, cached)
        install_distribution(state, cached)
        run_prepare_script(state, cached, build=False)
        install_build_packages(state, cached)
        run_prepare_script(state, cached, build=True)
        configure_root_password(state)
        configure_autologin(state)
        configure_initrd(state)
        run_build_script(state)
        install_build_dest(state)
        install_extra_trees(state)
        run_kernel_install(state, cached)
        install_boot_loader(state)
        configure_ssh(state)
        run_postinst_script(state)
        run_sysusers(state)
        run_preset_all(state)
        remove_packages(state)

        if manifest:
            with complete_step("Recording packages in manifest…"):
                manifest.record_packages(state.root)

        clean_package_manager_metadata(state)
        remove_files(state)
        reset_machine_id(state)
        reset_random_seed(state.root)
        run_finalize_script(state)
        run_selinux_relabel(state)

    roothash = invoke_repart(state, skip=("esp", "xbootldr"))
    install_unified_kernel(state, roothash)
    invoke_repart(state, split=True)

    make_tar(state)
    make_initrd(state)
    make_directory(state)


def one_zero(b: bool) -> str:
    return "1" if b else "0"


def install_dir(state: MkosiState) -> Path:
    return state.config.install_dir or state.workspace / "dest"


def run_build_script(state: MkosiState) -> None:
    if state.config.build_script is None or state.for_cache:
        return

    # Make sure that if mkosi.installdir/ is used, any leftover files from a previous run are removed.
    if state.config.install_dir:
        empty_directory(state.config.install_dir)

    with complete_step("Running build script…"), mount_build_overlay(state, read_only=True):
        bwrap: list[PathString] = [
            "--bind", state.config.build_sources, "/work/src",
            "--bind", state.config.build_script, "/work/build-script",
            "--bind", install_dir(state), "/work/dest",
            "--chdir", "/work/src",
        ]

        env = dict(
            WITH_DOCS=one_zero(state.config.with_docs),
            WITH_TESTS=one_zero(state.config.with_tests),
            WITH_NETWORK=one_zero(state.config.with_network),
            SRCDIR="/work/src",
            DESTDIR="/work/dest",
        )

        if state.config.build_dir is not None:
            bwrap += ["--bind", state.config.build_dir, "/work/build"]
            env |= dict(BUILDDIR="/work/build")

        cmd = ["setpriv", f"--reuid={state.uid}", f"--regid={state.gid}", "--clear-groups", "/work/build-script"]
        # When we're building the image because it's required for another verb, any passed arguments are
        # most likely intended for the target verb, and not for "build", so don't add them in that case.
        if state.config.verb == Verb.build:
            cmd += state.config.cmdline

        # build-script output goes to stdout so we can run language servers from within mkosi
        # build-scripts. See https://github.com/systemd/mkosi/pull/566 for more information.
        run_workspace_command(state, cmd, network=state.config.with_network, bwrap_params=bwrap,
                              stdout=sys.stdout, env=env)


def need_cache_tree(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    if state.config.force > 1:
        return True

    final, build = cache_tree_paths(state.config)

    return not final.exists() or (state.config.build_script is not None and not build.exists())


def build_stuff(uid: int, gid: int, config: MkosiConfig) -> None:
    workspace = tempfile.TemporaryDirectory(dir=config.workspace_dir or Path.cwd(), prefix=".mkosi.tmp")
    workspace_dir = Path(workspace.name)
    cache = config.cache_dir or workspace_dir / "cache"

    state = MkosiState(
        uid=uid,
        gid=gid,
        config=config,
        workspace=workspace_dir,
        cache=cache,
        for_cache=False,
    )

    manifest = Manifest(config)

    make_output_dir(state)
    make_cache_dir(state)
    make_install_dir(state)
    make_build_dir(state)

    # Make sure tmpfiles' aging doesn't interfere with our workspace
    # while we are working on it.
    with flock(workspace_dir), workspace:
        # If caching is requested, then make sure we have cache trees around we can make use of
        if need_cache_tree(state):
            with complete_step("Building cache image"):
                state = dataclasses.replace(state, for_cache=True)
                build_image(state)
                save_cache(state)

        with complete_step("Building image"):
            state = dataclasses.replace(state, for_cache=False)
            build_image(state, manifest=manifest)

        copy_nspawn_settings(state)
        calculate_sha256sum(state)
        calculate_signature(state)
        save_manifest(state, manifest)

        if state.config.cache_dir:
            acl_toggle_remove(state.config, state.config.cache_dir, state.uid, allow=True)

        for p in state.config.output_paths():
            if state.staging.joinpath(p.name).exists():
                shutil.move(state.staging / p.name, p)
                if p != state.config.output or state.config.output_format != OutputFormat.directory:
                    os.chown(p, state.uid, state.gid)
                else:
                    acl_toggle_remove(state.config, p, uid, allow=True)
                if p == state.config.output:
                    compress_output(state.config, p, uid=state.uid, gid=state.gid)

        for p in state.staging.iterdir():
            shutil.move(p, state.config.output.parent / p.name)
            os.chown(state.config.output.parent / p.name, state.uid, state.gid)
            if p.name.startswith(state.config.output.name):
                compress_output(state.config, p, uid=state.uid, gid=state.gid)

    print_output_size(config)


def check_root() -> None:
    if os.getuid() != 0:
        die("Must be invoked as root.")


def machine_name(config: Union[MkosiConfig, argparse.Namespace]) -> str:
    return config.image_id or config.output.with_suffix("").name.partition("_")[0]


def machine_cid(config: MkosiConfig) -> int:
    cid = int.from_bytes(hashlib.sha256(machine_name(config).encode()).digest()[:4], byteorder='little')
    # Make sure we don't return any of the well-known CIDs.
    return max(3, min(cid, 0xFFFFFFFF - 1))


def nspawn_knows_arg(arg: str) -> bool:
    # Specify some extra incompatible options so nspawn doesn't try to boot a container in the current
    # directory if it has a compatible layout.
    c = run(["systemd-nspawn", arg,
             "--directory", "/dev/null",
             "--image", "/dev/null"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            text=True)
    return "unrecognized option" not in c.stderr


def run_shell(config: MkosiConfig) -> None:
    cmdline: list[PathString] = ["systemd-nspawn", "--quiet"]

    if config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        cmdline += ["--directory", config.output]

        owner = os.stat(config.output).st_uid
        if owner != 0:
            cmdline += [f"--private-users={str(owner)}"]
    else:
        cmdline += ["--image", config.output]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings is not None:
        cmdline += ["--settings=trusted"]

    if config.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += [f"--rlimit=RLIMIT_CORE={format_rlimit(resource.RLIMIT_CORE)}"]

        # Redirecting output correctly when not running directly from the terminal.
        console_arg = f"--console={'interactive' if sys.stdout.isatty() else 'pipe'}"
        if nspawn_knows_arg(console_arg):
            cmdline += [console_arg]

    if config.ephemeral:
        cmdline += ["--ephemeral"]

    cmdline += ["--machine", machine_name(config)]
    cmdline += [f"--bind={config.build_sources}:/root/src", "--chdir=/root/src"]

    for k, v in config.credentials.items():
        cmdline += [f"--set-credential={k}:{v}"]

    if config.verb == Verb.boot:
        # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
        cmdline += config.cmdline
        # kernel cmdline config of the form systemd.xxx= get interpreted by systemd when running in nspawn as
        # well.
        cmdline += config.kernel_command_line
        cmdline += config.kernel_command_line_extra
    elif config.cmdline:
        cmdline += ["--"]
        cmdline += config.cmdline

    uid, _ = current_user_uid_gid()

    if config.output_format == OutputFormat.directory:
        acl_toggle_remove(config, config.output, uid, allow=False)

    try:
        run(cmdline, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False)
    finally:
        if config.output_format == OutputFormat.directory:
            acl_toggle_remove(config, config.output, uid, allow=True)


def find_qemu_binary(config: MkosiConfig) -> str:
    binaries = ["qemu", "qemu-kvm", f"qemu-system-{config.architecture}"]
    for binary in binaries:
        if shutil.which(binary) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_qemu_firmware(config: MkosiConfig) -> tuple[Path, bool]:
    FIRMWARE_LOCATIONS = {
        "x86_64": ["/usr/share/ovmf/x64/OVMF_CODE.secboot.fd"],
        "i386": [
            "/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd",
            "/usr/share/OVMF/OVMF32_CODE_4M.secboot.fd"
        ],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = {
        "x86_64": [
            "/usr/share/ovmf/ovmf_code_x64.bin",
            "/usr/share/ovmf/x64/OVMF_CODE.fd",
            "/usr/share/qemu/ovmf-x86_64.bin",
        ],
        "i386": ["/usr/share/ovmf/ovmf_code_ia32.bin", "/usr/share/edk2/ovmf-ia32/OVMF_CODE.fd"],
        "aarch64": ["/usr/share/AAVMF/AAVMF_CODE.fd"],
        "armhfp": ["/usr/share/AAVMF/AAVMF32_CODE.fd"],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            warn("Couldn't find OVMF firmware blob with secure boot support, "
                 "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    # If we can't find an architecture specific path, fall back to some generic paths that might also work.

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.secboot.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.secboot.fd",
        "/usr/share/ovmf/OVMF.secboot.fd",
        "/usr/share/OVMF/OVMF_CODE.secboot.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            warn("Couldn't find OVMF firmware blob with secure boot support, "
                 "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    die("Couldn't find OVMF UEFI firmware blob.")


def find_ovmf_vars(config: MkosiConfig) -> Path:
    OVMF_VARS_LOCATIONS = []

    if config.architecture == "x86_64":
        OVMF_VARS_LOCATIONS += ["/usr/share/ovmf/x64/OVMF_VARS.fd"]
    elif config.architecture == "i386":
        OVMF_VARS_LOCATIONS += [
            "/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd",
            "/usr/share/OVMF/OVMF32_VARS_4M.fd",
        ]
    elif config.architecture == "armhfp":
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF32_VARS.fd"]
    elif config.architecture == "aarch64":
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF_VARS.fd"]

    OVMF_VARS_LOCATIONS += ["/usr/share/edk2/ovmf/OVMF_VARS.fd",
                            "/usr/share/edk2-ovmf/OVMF_VARS.fd",  # GENTOO:
                            "/usr/share/qemu/OVMF_VARS.fd",
                            "/usr/share/ovmf/OVMF_VARS.fd",
                            "/usr/share/OVMF/OVMF_VARS.fd"]

    for location in OVMF_VARS_LOCATIONS:
        if os.path.exists(location):
            return Path(location)

    die("Couldn't find OVMF UEFI variables file.")


def qemu_check_kvm_support() -> bool:
    kvm = Path("/dev/kvm")
    if not kvm.is_char_device():
        return False
    # some CI runners may present a non-working KVM device
    try:
        with kvm.open("r+b"):
            return True
    except OSError:
        return False


@contextlib.contextmanager
def start_swtpm() -> Iterator[Optional[Path]]:

    if not shutil.which("swtpm"):
        yield None
        return

    with tempfile.TemporaryDirectory() as swtpm_state:
        swtpm_sock = Path(swtpm_state) / Path("sock")

        cmd = ["swtpm",
               "socket",
               "--tpm2",
               "--tpmstate", f"dir={swtpm_state}",
               "--ctrl", f"type=unixio,path={swtpm_sock}",
         ]

        swtpm_proc = spawn(cmd)

        try:
            yield swtpm_sock
        finally:
            swtpm_proc.wait()


def run_qemu(config: MkosiConfig) -> None:
    accel = "kvm" if config.qemu_kvm else "tcg"

    firmware, fw_supports_sb = find_qemu_firmware(config)
    smm = "on" if fw_supports_sb else "off"

    if config.architecture == "aarch64":
        machine = f"type=virt,accel={accel}"
    else:
        machine = f"type=q35,accel={accel},smm={smm}"

    cmdline: list[PathString] = [
        find_qemu_binary(config),
        "-machine", machine,
        "-smp", config.qemu_smp,
        "-m", config.qemu_mem,
        "-object", "rng-random,filename=/dev/urandom,id=rng0",
        "-device", "virtio-rng-pci,rng=rng0,id=rng-device0",
        "-nic", "user,model=virtio-net-pci",
    ]

    try:
        os.open("/dev/vhost-vsock", os.R_OK|os.W_OK)
        cmdline += ["-device", f"vhost-vsock-pci,guest-cid={machine_cid(config)}"]
    except OSError as e:
        if e.errno == errno.ENOENT:
            warn("/dev/vhost-vsock not found. Not adding a vsock device to the virtual machine.")
        elif e.errno in (errno.EPERM, errno.EACCES):
            warn("Permission denied to access /dev/vhost-vsock. Not adding a vsock device to the virtual machine.")

    cmdline += ["-cpu", "max"]

    if config.qemu_gui:
        cmdline += ["-vga", "virtio"]
    else:
        # -nodefaults removes the default CDROM device which avoids an error message during boot
        # -serial mon:stdio adds back the serial device removed by -nodefaults.
        cmdline += [
            "-nographic",
            "-nodefaults",
            "-chardev", "stdio,mux=on,id=console,signal=off",
            # Use virtconsole which appears as /dev/hvc0 in the guest on which a getty is automatically
            # by spawned by systemd without needing a console= cmdline argument.
            "-device", "virtio-serial",
            "-device", "virtconsole,chardev=console",
            "-mon", "console",
            # EDK2 doesn't support virtio-serial, so add a regular serial console as well to get bootloader
            # output.
            "-serial", "chardev:console",
        ]

    for k, v in config.credentials.items():
        cmdline += ["-smbios", f"type=11,value=io.systemd.credential.binary:{k}={base64.b64encode(v.encode()).decode()}"]
    cmdline += ["-smbios", f"type=11,value=io.systemd.stub.kernel-cmdline-extra={' '.join(config.kernel_command_line_extra)}"]

    cmdline += ["-drive", f"if=pflash,format=raw,readonly=on,file={firmware}"]

    with contextlib.ExitStack() as stack:
        if fw_supports_sb:
            ovmf_vars = stack.enter_context(tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=tmp_dir()))
            copy_path(find_ovmf_vars(config), Path(ovmf_vars.name))
            cmdline += [
                "-global", "ICH9-LPC.disable_s3=1",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-drive", f"file={ovmf_vars.name},if=pflash,format=raw",
            ]

        if config.ephemeral:
            f = stack.enter_context(tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=config.output.parent))
            fname = Path(f.name)

            # So on one hand we want CoW off, since this stuff will
            # have a lot of random write accesses. On the other we
            # want the copy to be snappy, hence we do want CoW. Let's
            # ask for both, and let the kernel figure things out:
            # let's turn off CoW on the file, but start with a CoW
            # copy. On btrfs that works: the initial copy is made as
            # CoW but later changes do not result in CoW anymore.

            run(["chattr", "+C", fname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            copy_path(config.output_compressed, fname)
        else:
            fname = config.output_compressed

        # Debian images fail to boot with virtio-scsi, see: https://github.com/systemd/mkosi/issues/725
        if config.output_format == OutputFormat.cpio:
            kernel = (config.output_dir or Path.cwd()) / config.output_split_kernel
            if not kernel.exists() and "-kernel" not in config.cmdline:
                die("No kernel found, please install a kernel in the cpio or provide a -kernel argument to mkosi qemu")
            cmdline += ["-kernel", kernel,
                        "-initrd", fname,
                        "-append", " ".join(config.kernel_command_line + config.kernel_command_line_extra)]
        if config.distribution == Distribution.debian:
            cmdline += ["-drive", f"if=virtio,id=hd,file={fname},format=raw"]
        else:
            cmdline += ["-drive", f"if=none,id=hd,file={fname},format=raw",
                        "-device", "virtio-scsi-pci,id=scsi",
                        "-device", "scsi-hd,drive=hd,bootindex=1"]

        swtpm_socket = stack.enter_context(start_swtpm())
        if swtpm_socket is not None:
            cmdline += ["-chardev", f"socket,id=chrtpm,path={swtpm_socket}",
                        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm"]

            if config.architecture == "x86_64":
                cmdline += ["-device", "tpm-tis,tpmdev=tpm0"]
            elif config.architecture == "aarch64":
                cmdline += ["-device", "tpm-tis-device,tpmdev=tpm0"]

        cmdline += config.qemu_args
        cmdline += config.cmdline

        run(cmdline, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False)


def run_ssh(config: MkosiConfig) -> None:
    cmd = [
        "ssh",
        # Silence known hosts file errors/warnings.
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "LogLevel=ERROR",
        "-o", f"ProxyCommand=socat - VSOCK-CONNECT:{machine_cid(config)}:%p",
        "root@mkosi",
    ]

    cmd += config.cmdline

    run(cmd, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False)


def run_serve(config: MkosiConfig) -> None:
    """Serve the output directory via a tiny embedded HTTP server"""

    port = 8081

    if config.output_dir is not None:
        os.chdir(config.output_dir)

    with http.server.HTTPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Serving HTTP on port {port}: http://localhost:{port}/")
        httpd.serve_forever()


def generate_secure_boot_key(config: MkosiConfig) -> None:
    """Generate secure boot keys using openssl"""

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(config.secure_boot_valid_days))
    cn = expand_specifier(config.secure_boot_common_name)

    for f in (config.secure_boot_key, config.secure_boot_certificate):
        if f and not config.force:
            die(f"{f} already exists",
                hint=("To generate new secure boot keys, "
                      f"first remove {config.secure_boot_key} {config.secure_boot_certificate}"))

    MkosiPrinter.print_step(f"Generating secure boot keys rsa:{keylength} for CN {cn!r}.")
    MkosiPrinter.info(
        dedent(
            f"""
            The keys will expire in {config.secure_boot_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    key = config.secure_boot_key or "mkosi.secure-boot.key"
    crt = config.secure_boot_certificate or "mkosi.secure-boot.crt"

    cmd: list[PathString] = [
        "openssl", "req",
        "-new",
        "-x509",
        "-newkey", f"rsa:{keylength}",
        "-keyout", key,
        "-out", crt,
        "-days", str(config.secure_boot_valid_days),
        "-subj", f"/CN={cn}/",
        "-nodes",
    ]
    run(cmd)


def bump_image_version(config: MkosiConfig) -> None:
    """Write current image version plus one to mkosi.version"""

    if config.image_version is None or config.image_version == "":
        print("No version configured so far, starting with version 1.")
        new_version = "1"
    else:
        v = config.image_version.split(".")

        try:
            m = int(v[-1])
        except ValueError:
            new_version = config.image_version + ".2"
            print(
                f"Last component of current version is not a decimal integer, appending '.2', bumping '{config.image_version}' → '{new_version}'."
            )
        else:
            new_version = ".".join(v[:-1] + [str(m + 1)])
            print(f"Increasing last component of version by one, bumping '{config.image_version}' → '{new_version}'.")

    Path("mkosi.version").write_text(new_version + "\n")


def expand_paths(paths: Sequence[str]) -> list[Path]:
    if not paths:
        return []

    environ = os.environ.copy()
    # Add a fake SUDO_HOME variable to allow non-root users specify
    # paths in their home when using mkosi via sudo.
    sudo_user = os.getenv("SUDO_USER")
    if sudo_user and "SUDO_HOME" not in environ:
        environ["SUDO_HOME"] = os.path.expanduser(f"~{sudo_user}")

    # No os.path.expandvars because it treats unset variables as empty.
    expanded = []
    for path in paths:
        if not sudo_user:
            path = os.path.expanduser(path)
        try:
            expanded += [Path(string.Template(str(path)).substitute(environ))]
        except KeyError:
            # Skip path if it uses a variable not defined.
            pass
    return expanded


@contextlib.contextmanager
def prepend_to_environ_path(paths: Sequence[Path]) -> Iterator[None]:
    if not paths:
        yield
        return

    with tempfile.TemporaryDirectory(prefix="mkosi.path", dir=tmp_dir()) as d:

        for path in paths:
            if not path.is_dir():
                Path(d).joinpath(path.name).symlink_to(path.absolute())

        paths = [Path(d), *paths]

        news = [os.fspath(path) for path in paths if path.is_dir()]
        olds = os.getenv("PATH", "").split(":")
        os.environ["PATH"] = ":".join(news + olds)

        yield


def expand_specifier(s: str) -> str:
    user = os.getenv("SUDO_USER") or os.getenv("USER")
    assert user is not None
    return s.replace("%u", user)


def needs_build(config: Union[argparse.Namespace, MkosiConfig]) -> bool:
    return config.verb == Verb.build or (config.verb in MKOSI_COMMANDS_NEED_BUILD and (not config.output_compressed.exists() or config.force > 0))


def run_verb(config: MkosiConfig) -> None:
    with prepend_to_environ_path(config.extra_search_paths):
        if config.verb == Verb.genkey:
            return generate_secure_boot_key(config)

        if config.verb == Verb.bump:
            return bump_image_version(config)

        if config.verb == Verb.summary:
            return print_summary(config)

        if config.verb in MKOSI_COMMANDS_SUDO:
            check_root()

        if config.verb == Verb.build:
            check_inputs(config)

            if not config.force:
                check_outputs(config)

        if needs_build(config) or config.verb == Verb.clean:
            def target() -> None:
                if os.getuid() != 0:
                    become_root()
                unlink_output(config)

            fork_and_wait(target)

        if needs_build(config):
            def target() -> None:
                # Get the user UID/GID either on the host or in the user namespace running the build
                uid, gid = become_root() if os.getuid() != 0 else current_user_uid_gid()
                init_mount_namespace()
                build_stuff(uid, gid, config)

            # We only want to run the build in a user namespace but not the following steps. Since we can't
            # rejoin the parent user namespace after unsharing from it, let's run the build in a fork so that
            # the main process does not leave its user namespace.
            fork_and_wait(target)

            if config.auto_bump:
                bump_image_version(config)

        if config.verb in (Verb.shell, Verb.boot):
            run_shell(config)

        if config.verb == Verb.qemu:
            run_qemu(config)

        if config.verb == Verb.ssh:
            run_ssh(config)

        if config.verb == Verb.serve:
            run_serve(config)
