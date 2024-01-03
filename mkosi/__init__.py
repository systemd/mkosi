# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import dataclasses
import datetime
import hashlib
import io
import itertools
import json
import logging
import os
import resource
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Optional, TextIO, Union, cast

import mkosi.resources
from mkosi.archive import extract_tar, make_cpio, make_tar
from mkosi.bubblewrap import bwrap, chroot_cmd
from mkosi.burn import run_burn
from mkosi.config import (
    Args,
    BiosBootloader,
    Bootloader,
    Compression,
    Config,
    ConfigFeature,
    DocFormat,
    JsonEncoder,
    ManifestFormat,
    OutputFormat,
    SecureBootSignTool,
    ShimBootloader,
    Verb,
    __version__,
    format_bytes,
    format_tree,
    parse_config,
    summary,
    yes_no,
)
from mkosi.context import Context
from mkosi.distributions import Distribution
from mkosi.installer import clean_package_manager_metadata, package_manager_scripts
from mkosi.kmod import gen_required_kernel_modules, process_kernel_modules
from mkosi.log import ARG_DEBUG, complete_step, die, log_notice, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import mount_overlay, mount_usr
from mkosi.pager import page
from mkosi.partition import Partition, finalize_root, finalize_roothash
from mkosi.qemu import KernelType, QemuDeviceNode, copy_ephemeral, run_qemu, run_ssh
from mkosi.run import become_root, find_binary, fork_and_wait, init_mount_namespace, run
from mkosi.tree import copy_tree, move_tree, rmtree
from mkosi.types import PathString
from mkosi.util import (
    INVOKING_USER,
    chdir,
    flatten,
    format_rlimit,
    make_executable,
    one_zero,
    read_env_file,
    read_os_release,
    resource_path,
    round_up,
    scopedenv,
    try_import,
    umask,
)
from mkosi.versioncomp import GenericVersion

MKOSI_AS_CALLER = (
    "setpriv",
    f"--reuid={INVOKING_USER.uid}",
    f"--regid={INVOKING_USER.gid}",
    "--clear-groups",
)

@contextlib.contextmanager
def mount_base_trees(context: Context) -> Iterator[None]:
    if not context.config.base_trees or not context.config.overlay:
        yield
        return

    with complete_step("Mounting base trees…"), contextlib.ExitStack() as stack:
        bases = []
        (context.workspace / "bases").mkdir(exist_ok=True)

        for path in context.config.base_trees:
            d = context.workspace / f"bases/{path.name}-{uuid.uuid4().hex}"

            if path.is_dir():
                bases += [path]
            elif path.suffix == ".tar":
                extract_tar(context, path, d)
                bases += [d]
            elif path.suffix == ".raw":
                bwrap(context, ["systemd-dissect", "-M", path, d])
                stack.callback(lambda: bwrap(context, ["systemd-dissect", "-U", d]))
                bases += [d]
            else:
                die(f"Unsupported base tree source {path}")

        stack.enter_context(mount_overlay(bases, context.root, context.root))

        yield


def remove_files(context: Context) -> None:
    """Remove files based on user-specified patterns"""

    if not context.config.remove_files:
        return

    with complete_step("Removing files…"):
        for pattern in context.config.remove_files:
            for p in context.root.glob(pattern.lstrip("/")):
                rmtree(p)


def install_distribution(context: Context) -> None:
    if context.config.base_trees:
        if not context.config.packages:
            return

        with complete_step(f"Installing extra packages for {str(context.config.distribution).capitalize()}"):
            context.config.distribution.install_packages(context, context.config.packages)
    else:
        with complete_step(f"Installing {str(context.config.distribution).capitalize()}"):
            context.config.distribution.install(context)

            if not context.config.overlay:
                if not (context.root / "etc/machine-id").exists():
                    # Uninitialized means we want it to get initialized on first boot.
                    with umask(~0o444):
                        (context.root / "etc/machine-id").write_text("uninitialized\n")

                # Ensure /efi exists so that the ESP is mounted there, as recommended by
                # https://0pointer.net/blog/linux-boot-partitions.html. Use the most restrictive access mode we
                # can without tripping up mkfs tools since this directory is only meant to be overmounted and
                # should not be read from or written to.
                with umask(~0o500):
                    (context.root / "efi").mkdir(exist_ok=True)

            if context.config.packages:
                context.config.distribution.install_packages(context, context.config.packages)

    for f in ("var/lib/systemd/random-seed",
              "var/lib/systemd/credential.secret",
              "etc/machine-info",
              "var/lib/dbus/machine-id"):
        # Using missing_ok=True still causes an OSError if the mount is read-only even if the
        # file doesn't exist so do an explicit exists() check first.
        if (context.root / f).exists():
            (context.root / f).unlink()


def install_build_packages(context: Context) -> None:
    if not context.config.build_scripts or not context.config.build_packages:
        return

    # TODO: move to parenthesised context managers once on 3.10
    pd = str(context.config.distribution).capitalize()
    with complete_step(f"Installing build packages for {pd}"), mount_build_overlay(context):
        context.config.distribution.install_packages(context, context.config.build_packages)


def remove_packages(context: Context) -> None:
    """Remove packages listed in config.remove_packages"""

    if not context.config.remove_packages:
        return

    with complete_step(f"Removing {len(context.config.remove_packages)} packages…"):
        try:
            context.config.distribution.remove_packages(context, context.config.remove_packages)
        except NotImplementedError:
            die(f"Removing packages is not supported for {context.config.distribution}")


def check_root_populated(context: Context) -> None:
    """Check that the root was populated by looking for a os-release file."""
    osrelease = context.root / "usr/lib/os-release"
    if not osrelease.exists():
        die(
            f"{osrelease} not found.",
            hint=(
                "The root must be populated by the distribution, or from base trees, "
                "skeleton trees, and prepare scripts."
            )
        )


def configure_os_release(context: Context) -> None:
    """Write IMAGE_ID and IMAGE_VERSION to /usr/lib/os-release in the image."""
    if not context.config.image_id and not context.config.image_version:
        return

    if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
        return

    for candidate in ["usr/lib/os-release", "etc/os-release", "usr/lib/initrd-release", "etc/initrd-release"]:
        osrelease = context.root / candidate
        # at this point we know we will either change or add to the file
        newosrelease = osrelease.with_suffix(".new")

        if not osrelease.is_file() or osrelease.is_symlink():
            continue

        image_id_written = image_version_written = False
        with osrelease.open("r") as old, newosrelease.open("w") as new:
            # fix existing values
            for line in old.readlines():
                if context.config.image_id and line.startswith("IMAGE_ID="):
                    new.write(f'IMAGE_ID="{context.config.image_id}"\n')
                    image_id_written = True
                elif context.config.image_version and line.startswith("IMAGE_VERSION="):
                    new.write(f'IMAGE_VERSION="{context.config.image_version}"\n')
                    image_version_written = True
                else:
                    new.write(line)

            # append if they were missing
            if context.config.image_id and not image_id_written:
                new.write(f'IMAGE_ID="{context.config.image_id}"\n')
            if context.config.image_version and not image_version_written:
                new.write(f'IMAGE_VERSION="{context.config.image_version}"\n')

        newosrelease.rename(osrelease)


def configure_extension_release(context: Context) -> None:
    if context.config.output_format not in (OutputFormat.sysext, OutputFormat.confext):
        return

    prefix = "SYSEXT" if context.config.output_format == OutputFormat.sysext else "CONFEXT"
    d = "usr/lib" if context.config.output_format == OutputFormat.sysext else "etc"
    p = context.root / d / f"extension-release.d/extension-release.{context.config.output}"
    p.parent.mkdir(parents=True, exist_ok=True)

    osrelease = read_os_release(context.root)
    extrelease = read_env_file(p) if p.exists() else {}
    new = p.with_suffix(".new")

    with new.open() as f:
        for k, v in extrelease.items():
            f.write(f"{k}={v}\n")

        if "ID" not in extrelease:
            f.write(f"ID={osrelease.get('ID', '_any')}\n")

        if "VERSION_ID" not in extrelease and (version := osrelease.get("VERSION_ID")):
            f.write(f"VERSION_ID={version}\n")

        if f"{prefix}_ID" not in extrelease and context.config.image_id:
            f.write(f"{prefix}_ID={context.config.image_id}\n")

        if f"{prefix}_VERSION_ID" not in extrelease and context.config.image_version:
            f.write(f"{prefix}_VERSION_ID={context.config.image_version}\n")

        if f"{prefix}_SCOPE" not in extrelease:
            f.write(f"{prefix}_SCOPE=initrd system portable\n")

        if "ARCHITECTURE" not in extrelease:
            f.write(f"ARCHITECTURE={context.config.architecture}\n")

    new.rename(p)


def configure_autologin_service(context: Context, service: str, extra: str) -> None:
    dropin = context.root / f"usr/lib/systemd/system/{service}.d/autologin.conf"
    with umask(~0o755):
        dropin.parent.mkdir(parents=True, exist_ok=True)
    with umask(~0o644):
        dropin.write_text(
            textwrap.dedent(
                f"""\
                [Service]
                ExecStart=
                ExecStart=-agetty -o '-f -p -- \\\\u' --autologin root {extra} $TERM
                StandardInput=tty
                StandardOutput=tty
                """
            )
        )


def configure_autologin(context: Context) -> None:
    if not context.config.autologin:
        return

    with complete_step("Setting up autologin…"):
        configure_autologin_service(context, "console-getty.service",
                                    "--noclear --keep-baud console 115200,38400,9600")
        configure_autologin_service(context, "getty@tty1.service",
                                    "--noclear -")
        configure_autologin_service(context, "serial-getty@ttyS0.service",
                                    "--keep-baud 115200,57600,38400,9600 -")

        if context.config.architecture.default_serial_tty() != "ttyS0":
            configure_autologin_service(context,
                                        f"serial-getty@{context.config.architecture.default_serial_tty()}.service",
                                        "--keep-baud 115200,57600,38400,9600 -")


@contextlib.contextmanager
def mount_cache_overlay(context: Context) -> Iterator[None]:
    if not context.config.incremental or not any(context.root.iterdir()):
        yield
        return

    d = context.workspace / "cache-overlay"
    with umask(~0o755):
        d.mkdir(exist_ok=True)

    with mount_overlay([context.root], d, context.root):
        yield


@contextlib.contextmanager
def mount_build_overlay(context: Context, volatile: bool = False) -> Iterator[Path]:
    d = context.workspace / "build-overlay"
    if not d.is_symlink():
        with umask(~0o755):
            d.mkdir(exist_ok=True)

    with contextlib.ExitStack() as stack:
        lower = [context.root]

        if volatile:
            lower += [d]
            upper = None
        else:
            upper = d

        stack.enter_context(mount_overlay(lower, upper, context.root))

        yield context.root


@contextlib.contextmanager
def finalize_source_mounts(config: Config) -> Iterator[list[PathString]]:
    with contextlib.ExitStack() as stack:
        mounts = [
            (stack.enter_context(mount_overlay([source])) if config.build_sources_ephemeral else source, target)
            for source, target
            in [(Path.cwd(), Path.cwd())] + [t.with_prefix(Path.cwd()) for t in config.build_sources]
        ]

        yield flatten(["--bind", src, target] for src, target in sorted(set(mounts), key=lambda s: s[1]))


def script_maybe_chroot(script: Path, mountpoint: str) -> list[str]:
    return ["mkosi-chroot", mountpoint] if script.suffix == ".chroot" else [os.fspath(script)]


@contextlib.contextmanager
def finalize_scripts(scripts: Mapping[str, Sequence[PathString]] = {}) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mkosi-scripts") as d:
        for name, script in scripts.items():
            # Make sure we don't end up in a recursive loop when we name a script after the binary it execs
            # by removing the scripts directory from the PATH when we execute a script.
            (Path(d) / name).write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    DIR="$(cd "$(dirname "$0")" && pwd)"
                    PATH="$(echo "$PATH" | tr ':' '\\n' | grep -v "$DIR" | tr '\\n' ':')"
                    export PATH
                    if [ $# -gt 0 ]; then
                        exec {shlex.join(str(s) for s in script)} "$@"
                    else
                        exec {shlex.join(str(s) for s in script)} sh -i
                    fi
                    """
                )
            )

            make_executable(Path(d) / name)
            os.utime(Path(d) / name, (0, 0))

        yield Path(d)


def finalize_host_scripts(
    context: Context,
    helpers: dict[str, Sequence[PathString]],  # FIXME: change dict to Mapping when PyRight is fixed
) -> contextlib.AbstractContextManager[Path]:
    scripts: dict[str, Sequence[PathString]] = {}
    if find_binary("git"):
        scripts["git"] = ("git", "-c", "safe.directory=*")
    if find_binary("useradd"):
        scripts["useradd"] = ("useradd", "--root", context.root)
    return finalize_scripts(scripts | helpers | package_manager_scripts(context))


def finalize_chroot_scripts(context: Context) -> contextlib.AbstractContextManager[Path]:
    git = {"git": ("git", "-c", "safe.directory=*")} if find_binary("git", root=context.root) else {}
    return finalize_scripts(git)


def run_prepare_scripts(context: Context, build: bool) -> None:
    if not context.config.prepare_scripts:
        return
    if build and not context.config.build_scripts:
        return

    env = dict(
        ARCHITECTURE=str(context.config.architecture),
        BUILDROOT=str(context.root),
        CHROOT_SCRIPT="/work/prepare",
        CHROOT_SRCDIR="/work/src",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        SCRIPT="/work/prepare",
        SRCDIR=str(Path.cwd()),
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
    )

    with contextlib.ExitStack() as stack:
        if build:
            stack.enter_context(mount_build_overlay(context))
            step_msg = "Running prepare script {} in build overlay…"
            arg = "build"
        else:
            step_msg = "Running prepare script {}…"
            arg = "final"

        sources = stack.enter_context(finalize_source_mounts(context.config))
        cd = stack.enter_context(finalize_chroot_scripts(context))

        for script in context.config.prepare_scripts:
            helpers = {
                "mkosi-chroot": chroot_cmd(
                    context.root,
                    resolve=True,
                    options=[
                        "--bind", script, "/work/prepare",
                        "--bind", Path.cwd(), "/work/src",
                        "--bind", cd, "/work/scripts",
                        "--chdir", "/work/src",
                        "--setenv", "SRCDIR", "/work/src",
                        "--setenv", "BUILDROOT", "/",
                    ],
                ),
                "mkosi-as-caller" : MKOSI_AS_CALLER,
            }

            hd = stack.enter_context(finalize_host_scripts(context, helpers))

            with complete_step(step_msg.format(script)):
                bwrap(
                    context,
                    script_maybe_chroot(script, "/work/prepare") + [arg],
                    network=True,
                    options=sources + ["--ro-bind", script, script],
                    scripts=hd,
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                )


def run_build_scripts(context: Context) -> None:
    if not context.config.build_scripts:
        return

    env = dict(
        ARCHITECTURE=str(context.config.architecture),
        BUILDROOT=str(context.root),
        CHROOT_DESTDIR="/work/dest",
        CHROOT_OUTPUTDIR="/work/out",
        CHROOT_SCRIPT="/work/build-script",
        CHROOT_SRCDIR="/work/src",
        DESTDIR=str(context.install_dir),
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        OUTPUTDIR=str(context.staging),
        SCRIPT="/work/build-script",
        SRCDIR=str(Path.cwd()),
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
    )

    if context.config.build_dir is not None:
        env |= dict(
            BUILDDIR=str(context.config.build_dir),
            CHROOT_BUILDDIR="/work/build",
        )

    with (
        mount_build_overlay(context, volatile=True),
        finalize_chroot_scripts(context) as cd,
        finalize_source_mounts(context.config) as sources,
    ):
        for script in context.config.build_scripts:
            helpers = {
                "mkosi-chroot": chroot_cmd(
                    context.root,
                    resolve=context.config.with_network,
                    options=[
                        "--bind", script, "/work/build-script",
                        "--bind", context.install_dir, "/work/dest",
                        "--bind", context.staging, "/work/out",
                        "--bind", Path.cwd(), "/work/src",
                        "--bind", cd, "/work/scripts",
                        *([
                            "--bind", os.fspath(context.config.build_dir), "/work/build"]
                            if context.config.build_dir
                            else []
                        ),
                        "--chdir", "/work/src",
                        "--setenv", "SRCDIR", "/work/src",
                        "--setenv", "DESTDIR", "/work/dest",
                        "--setenv", "OUTPUTDIR", "/work/out",
                        "--setenv", "BUILDROOT", "/",
                        *(["--setenv", "BUILDDIR", "/work/build"] if context.config.build_dir else []),
                    ],
                ),
                "mkosi-as-caller" : MKOSI_AS_CALLER,
            }

            cmdline = context.args.cmdline if context.args.verb == Verb.build else []

            with (
                finalize_host_scripts(context, helpers) as hd,
                complete_step(f"Running build script {script}…"),
            ):
                bwrap(
                    context,
                    script_maybe_chroot(script, "/work/build-script") + cmdline,
                    network=context.config.with_network,
                    options=sources + ["--ro-bind", script, script],
                    scripts=hd,
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                )


def run_postinst_scripts(context: Context) -> None:
    if not context.config.postinst_scripts:
        return

    env = dict(
        ARCHITECTURE=str(context.config.architecture),
        BUILDROOT=str(context.root),
        CHROOT_OUTPUTDIR="/work/out",
        CHROOT_SCRIPT="/work/postinst",
        CHROOT_SRCDIR="/work/src",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        OUTPUTDIR=str(context.staging),
        SCRIPT="/work/postinst",
        SRCDIR=str(Path.cwd()),
    )

    with (
        finalize_chroot_scripts(context) as cd,
        finalize_source_mounts(context.config) as sources,
    ):
        for script in context.config.postinst_scripts:
            helpers = {
                "mkosi-chroot": chroot_cmd(
                    context.root,
                    resolve=context.config.with_network,
                    options=[
                        "--bind", script, "/work/postinst",
                        "--bind", context.staging, "/work/out",
                        "--bind", Path.cwd(), "/work/src",
                        "--bind", cd, "/work/scripts",
                        "--chdir", "/work/src",
                        "--setenv", "SRCDIR", "/work/src",
                        "--setenv", "OUTPUTDIR", "/work/out",
                        "--setenv", "BUILDROOT", "/",
                    ],
                ),
                "mkosi-as-caller" : MKOSI_AS_CALLER,
            }

            with (
                finalize_host_scripts(context, helpers) as hd,
                complete_step(f"Running postinstall script {script}…"),
            ):
                bwrap(
                    context,
                    script_maybe_chroot(script, "/work/postinst") + ["final"],
                    network=context.config.with_network,
                    options=sources + ["--ro-bind", script, script],
                    scripts=hd,
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                )


def run_finalize_scripts(context: Context) -> None:
    if not context.config.finalize_scripts:
        return

    env = dict(
        ARCHITECTURE=str(context.config.architecture),
        BUILDROOT=str(context.root),
        CHROOT_OUTPUTDIR="/work/out",
        CHROOT_SCRIPT="/work/finalize",
        CHROOT_SRCDIR="/work/src",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        OUTPUTDIR=str(context.staging),
        SCRIPT="/work/finalize",
        SRCDIR=str(Path.cwd()),
    )

    with (
        finalize_chroot_scripts(context) as cd,
        finalize_source_mounts(context.config) as sources,
    ):
        for script in context.config.finalize_scripts:
            helpers = {
                "mkosi-chroot": chroot_cmd(
                    context.root,
                    resolve=context.config.with_network,
                    options=[
                        "--bind", script, "/work/finalize",
                        "--bind", context.staging, "/work/out",
                        "--bind", Path.cwd(), "/work/src",
                        "--bind", cd, "/work/scripts",
                        "--chdir", "/work/src",
                        "--setenv", "SRCDIR", "/work/src",
                        "--setenv", "OUTPUTDIR", "/work/out",
                        "--setenv", "BUILDROOT", "/",
                    ],
                ),
                "mkosi-as-caller" : MKOSI_AS_CALLER,
            }

            with (
                finalize_host_scripts(context, helpers) as hd,
                complete_step(f"Running finalize script {script}…"),
            ):
                bwrap(
                    context,
                    script_maybe_chroot(script, "/work/finalize"),
                    network=context.config.with_network,
                    options=sources + ["--ro-bind", script, script],
                    scripts=hd,
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                )


def certificate_common_name(context: Context, certificate: Path) -> str:
    output = bwrap(
        context,
        [
            "openssl",
            "x509",
            "-noout",
            "-subject",
            "-nameopt", "multiline",
            "-in", certificate,
        ],
        stdout=subprocess.PIPE,
    ).stdout

    for line in output.splitlines():
        if not line.strip().startswith("commonName"):
            continue

        _, sep, value = line.partition("=")
        if not sep:
            die("Missing '=' delimiter in openssl output")

        return value.strip()

    die(f"Certificate {certificate} is missing Common Name")


def pesign_prepare(context: Context) -> None:
    assert context.config.secure_boot_key
    assert context.config.secure_boot_certificate

    if (context.workspace / "pesign").exists():
        return

    (context.workspace / "pesign").mkdir()

    # pesign takes a certificate directory and a certificate common name as input arguments, so we have
    # to transform our input key and cert into that format. Adapted from
    # https://www.mankier.com/1/pesign#Examples-Signing_with_the_certificate_and_private_key_in_individual_files
    bwrap(
        context,
        [
            "openssl",
            "pkcs12",
            "-export",
            # Arcane incantation to create a pkcs12 certificate without a password.
            "-keypbe", "NONE",
            "-certpbe", "NONE",
            "-nomaciter",
            "-passout", "pass:",
            "-out", context.workspace / "secure-boot.p12",
            "-inkey", context.config.secure_boot_key,
            "-in", context.config.secure_boot_certificate,
        ],
    )

    bwrap(
        context,
        [
            "pk12util",
            "-K", "",
            "-W", "",
            "-i", context.workspace / "secure-boot.p12",
            "-d", context.workspace / "pesign",
        ],
    )


def efi_boot_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    assert arch
    return Path(f"efi/EFI/BOOT/BOOT{arch.upper()}.EFI")


def shim_second_stage_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    assert arch
    if context.config.distribution == Distribution.opensuse:
        return Path("efi/EFI/BOOT/grub.EFI")
    else:
        return Path(f"efi/EFI/BOOT/grub{arch}.EFI")


def sign_efi_binary(context: Context, input: Path, output: Path) -> None:
    assert context.config.secure_boot_key
    assert context.config.secure_boot_certificate

    if (
        context.config.secure_boot_sign_tool == SecureBootSignTool.sbsign or
        context.config.secure_boot_sign_tool == SecureBootSignTool.auto and
        shutil.which("sbsign") is not None
    ):
        bwrap(
            context,
            [
                "sbsign",
                "--key", context.config.secure_boot_key,
                "--cert", context.config.secure_boot_certificate,
                "--output", output,
                input,
            ],
        )
    elif (
        context.config.secure_boot_sign_tool == SecureBootSignTool.pesign or
        context.config.secure_boot_sign_tool == SecureBootSignTool.auto and
        shutil.which("pesign") is not None
    ):
        pesign_prepare(context)
        bwrap(
            context,
            [
                "pesign",
                "--certdir", context.workspace / "pesign",
                "--certificate", certificate_common_name(context, context.config.secure_boot_certificate),
                "--sign",
                "--force",
                "--in", input,
                "--out", output,
            ],
        )
    else:
        die("One of sbsign or pesign is required to use SecureBoot=")


def install_systemd_boot(context: Context) -> None:
    if not want_efi(context.config):
        return

    if context.config.bootloader != Bootloader.systemd_boot:
        return

    if not any(gen_kernel_images(context)) and context.config.bootable == ConfigFeature.auto:
        return

    if not shutil.which("bootctl"):
        if context.config.bootable == ConfigFeature.enabled:
            die("An EFI bootable image with systemd-boot was requested but bootctl was not found")
        return

    directory = context.root / "usr/lib/systemd/boot/efi"
    if not directory.exists() or not any(directory.iterdir()):
        if context.config.bootable == ConfigFeature.enabled:
            die("A EFI bootable image with systemd-boot was requested but systemd-boot was not found at "
                f"{directory.relative_to(context.root)}")
        return

    if context.config.secure_boot:
        with complete_step("Signing systemd-boot binaries…"):
            for input in itertools.chain(directory.glob('*.efi'), directory.glob('*.EFI')):
                output = directory / f"{input}.signed"
                sign_efi_binary(context, input, output)

    with complete_step("Installing systemd-boot…"):
        bwrap(
            context,
            ["bootctl", "install", "--root", context.root, "--all-architectures", "--no-variables"],
            env={"SYSTEMD_ESP_PATH": "/efi"},
        )

        if context.config.shim_bootloader != ShimBootloader.none:
            shutil.copy2(
                context.root / f"efi/EFI/systemd/systemd-boot{context.config.architecture.to_efi()}.efi",
                context.root / shim_second_stage_binary(context),
            )

    if context.config.secure_boot and context.config.secure_boot_auto_enroll:
        assert context.config.secure_boot_key
        assert context.config.secure_boot_certificate

        with complete_step("Setting up secure boot auto-enrollment…"):
            keys = context.root / "efi/loader/keys/auto"
            with umask(~0o700):
                keys.mkdir(parents=True, exist_ok=True)

            # sbsiglist expects a DER certificate.
            bwrap(
                context,
                [
                    "openssl",
                    "x509",
                    "-outform", "DER",
                    "-in", context.config.secure_boot_certificate,
                    "-out", context.workspace / "mkosi.der",
                ],
            )

            bwrap(
                context,
                [
                    "sbsiglist",
                    "--owner", str(uuid.uuid4()),
                    "--type", "x509",
                    "--output", context.workspace / "mkosi.esl",
                    context.workspace / "mkosi.der",
                ],
            )

            # We reuse the key for all secure boot databases to keep things simple.
            for db in ["PK", "KEK", "db"]:
                bwrap(
                    context,
                    [
                        "sbvarsign",
                        "--attr",
                            "NON_VOLATILE,BOOTSERVICE_ACCESS,RUNTIME_ACCESS,TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
                        "--key", context.config.secure_boot_key,
                        "--cert", context.config.secure_boot_certificate,
                        "--output", keys / f"{db}.auth",
                        db,
                        context.workspace / "mkosi.esl",
                    ],
                )


def find_and_install_shim_binary(
    context: Context,
    name: str,
    signed: Sequence[str],
    unsigned: Sequence[str],
    output: Path,
) -> None:
    if context.config.shim_bootloader == ShimBootloader.signed:
        for pattern in signed:
            for p in context.root.glob(pattern):
                if p.is_symlink() and p.readlink().is_absolute():
                    logging.warning(f"Ignoring signed {name} EFI binary which is an absolute path to {p.readlink()}")
                    continue

                rel = p.relative_to(context.root)
                log_step(f"Installing signed {name} EFI binary from /{rel} to /{output}")
                shutil.copy2(p, context.root / output)
                return

        if context.config.bootable == ConfigFeature.enabled:
            die(f"Couldn't find signed {name} EFI binary installed in the image")
    else:
        for pattern in unsigned:
            for p in context.root.glob(pattern):
                if p.is_symlink() and p.readlink().is_absolute():
                    logging.warning(f"Ignoring unsigned {name} EFI binary which is an absolute path to {p.readlink()}")
                    continue

                rel = p.relative_to(context.root)
                if context.config.secure_boot:
                    log_step(f"Signing and installing unsigned {name} EFI binary from /{rel} to /{output}")
                    sign_efi_binary(context, p, context.root / output)
                else:
                    log_step(f"Installing unsigned {name} EFI binary /{rel} to /{output}")
                    shutil.copy2(p, context.root / output)

                return

        if context.config.bootable == ConfigFeature.enabled:
            die(f"Couldn't find unsigned {name} EFI binary installed in the image")


def install_shim(context: Context) -> None:
    if not want_efi(context.config):
        return

    if context.config.shim_bootloader == ShimBootloader.none:
        return

    if not any(gen_kernel_images(context)) and context.config.bootable == ConfigFeature.auto:
        return

    dst = efi_boot_binary(context)
    with umask(~0o700):
        (context.root / dst).parent.mkdir(parents=True, exist_ok=True)

    arch = context.config.architecture.to_efi()

    signed = [
        f"usr/lib/shim/shim{arch}.efi.signed.latest", # Ubuntu
        f"usr/lib/shim/shim{arch}.efi.signed", # Debian
        f"boot/efi/EFI/*/shim{arch}.efi", # Fedora/CentOS
        "usr/share/efi/*/shim.efi", # OpenSUSE
    ]

    unsigned = [
        f"usr/lib/shim/shim{arch}.efi", # Debian/Ubuntu
        f"usr/share/shim/*/*/shim{arch}.efi", # Fedora/CentOS
        f"usr/share/shim/shim{arch}.efi", # Arch
    ]

    find_and_install_shim_binary(context, "shim", signed, unsigned, dst)

    signed = [
        f"usr/lib/shim/mm{arch}.efi.signed", # Debian
        f"usr/lib/shim/mm{arch}.efi", # Ubuntu
        f"boot/efi/EFI/*/mm{arch}.efi", # Fedora/CentOS
        "usr/share/efi/*/MokManager.efi", # OpenSUSE
    ]

    unsigned = [
        f"usr/lib/shim/mm{arch}.efi", # Debian/Ubuntu
        f"usr/share/shim/*/*/mm{arch}.efi", # Fedora/CentOS
        f"usr/share/shim/mm{arch}.efi", # Arch
    ]

    find_and_install_shim_binary(context, "mok", signed, unsigned, dst.parent)


def find_grub_bios_directory(context: Context) -> Optional[Path]:
    for d in ("usr/lib/grub/i386-pc", "usr/share/grub2/i386-pc"):
        if (p := context.root / d).exists() and any(p.iterdir()):
            return p

    return None


def find_grub_binary(context: Context, binary: str) -> Optional[Path]:
    assert "grub" in binary and "grub2" not in binary
    return find_binary(binary, root=context.root) or find_binary(binary.replace("grub", "grub2"), root=context.root)


def find_grub_prefix(context: Context) -> Optional[str]:
    path = find_grub_binary(context, "grub-mkimage")
    if path is None:
        return None

    return "grub2" if "grub2" in os.fspath(path) else "grub"


def want_grub_efi(context: Context) -> bool:
    if context.config.bootable == ConfigFeature.disabled:
        return False

    if context.config.bootloader != Bootloader.grub:
        return False

    if context.config.overlay or context.config.output_format.is_extension_image():
        return False

    if not any((context.root / "efi").rglob("grub*.efi")):
        if context.config.bootable == ConfigFeature.enabled:
            die("A bootable EFI image with grub was requested but grub for EFI is not installed in /efi")

        return False

    return True


def want_grub_bios(context: Context, partitions: Sequence[Partition] = ()) -> bool:
    if context.config.bootable == ConfigFeature.disabled:
        return False

    if context.config.output_format != OutputFormat.disk:
        return False

    if context.config.bios_bootloader != BiosBootloader.grub:
        return False

    if context.config.overlay:
        return False

    have = find_grub_bios_directory(context) is not None
    if not have and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but grub for BIOS is not installed")

    bios = any(p.type == Partition.GRUB_BOOT_PARTITION_UUID for p in partitions)
    if partitions and not bios and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no BIOS Boot Partition was configured")

    esp = any(p.type == "esp" for p in partitions)
    if partitions and not esp and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no ESP partition was configured")

    root = any(p.type.startswith("root") or p.type.startswith("usr") for p in partitions)
    if partitions and not root and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no root or usr partition was configured")

    installed = True

    for binary in ("grub-mkimage", "grub-bios-setup"):
        path = find_grub_binary(context, binary)
        if path is not None:
            continue

        if context.config.bootable == ConfigFeature.enabled:
            die(f"A BIOS bootable image with grub was requested but {binary} was not found")

        installed = False

    return (have and bios and esp and root and installed) if partitions else have


def prepare_grub_config(context: Context) -> Optional[Path]:
    prefix = find_grub_prefix(context)
    if not prefix:
        return None

    config = context.root / "efi" / prefix / "grub.cfg"
    with umask(~0o700):
        config.parent.mkdir(exist_ok=True)

    # For some unknown reason, if we don't set the timeout to zero, grub never leaves its menu, so we default
    # to a zero timeout, but only if the config file hasn't been provided by the user.
    if not config.exists():
        with umask(~0o600), config.open("w") as f:
            f.write("set timeout=0\n")

    return config


def prepare_grub_efi(context: Context) -> None:
    if not want_grub_efi(context):
        return

    prefix = find_grub_prefix(context)
    assert prefix

    # Signed EFI grub shipped by distributions reads its configuration from /EFI/<distribution>/grub.cfg in
    # the ESP so let's put a shim there to redirect to the actual configuration file.
    earlyconfig = context.root / "efi/EFI" / context.config.distribution.name / "grub.cfg"
    with umask(~0o700):
        earlyconfig.parent.mkdir(parents=True, exist_ok=True)

    # Read the actual config file from the root of the ESP.
    earlyconfig.write_text(f"configfile /{prefix}/grub.cfg\n")

    config = prepare_grub_config(context)
    assert config

    with config.open("a") as f:
        f.write('if [ "${grub_platform}" == "efi" ]; then\n')

        for uki in (context.root / "boot/EFI/Linux").glob("*.efi"):
            f.write(
                textwrap.dedent(
                    f"""\
                    menuentry "{uki.stem}" {{
                        chainloader /{uki.relative_to(context.root / "boot")}
                    }}
                    """
                )
            )

        f.write("fi\n")


def prepare_grub_bios(context: Context, partitions: Sequence[Partition]) -> None:
    if not want_grub_bios(context, partitions):
        return

    config = prepare_grub_config(context)
    assert config

    root = finalize_root(partitions)
    assert root

    token = find_entry_token(context)

    dst = context.root / "boot" / token
    with umask(~0o700):
        dst.mkdir(exist_ok=True)

    with config.open("a") as f:
        f.write('if [ "${grub_platform}" == "pc" ]; then\n')

        for kver, kimg in gen_kernel_images(context):
            kdst = dst / kver
            with umask(~0o700):
                kdst.mkdir(exist_ok=True)

            microcode = build_microcode_initrd(context)
            kmods = build_kernel_modules_initrd(context, kver)

            with umask(~0o600):
                kimg = Path(shutil.copy2(context.root / kimg, kdst / "vmlinuz"))
                initrds = [Path(shutil.copy2(microcode, kdst / "microcode"))] if microcode else []
                initrds += [
                    Path(shutil.copy2(initrd, dst / initrd.name))
                    for initrd in (context.config.initrds or [build_initrd(context)])
                ]
                initrds += [Path(shutil.copy2(kmods, kdst / "kmods"))]

                image = Path("/") / kimg.relative_to(context.root / "boot")
                cmdline = " ".join(context.config.kernel_command_line)
                initrds = " ".join(
                    [os.fspath(Path("/") / initrd.relative_to(context.root / "boot")) for initrd in initrds]
                )

                f.write(
                    textwrap.dedent(
                        f"""\
                        menuentry "{token}-{kver}" {{
                            linux {image} {root} {cmdline}
                            initrd {initrds}
                        }}
                        """
                    )
                )

        f.write('fi\n')

    # grub-install insists on opening the root partition device to probe it's filesystem which requires root
    # so we're forced to reimplement its functionality. Luckily that's pretty simple, run grub-mkimage to
    # generate the required core.img and copy the relevant files to the ESP.

    mkimage = find_grub_binary(context, "grub-mkimage")
    assert mkimage

    directory = find_grub_bios_directory(context)
    assert directory

    prefix = find_grub_prefix(context)
    assert prefix

    dst = context.root / "efi" / prefix / "i386-pc"
    dst.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", prefix="grub-early-config") as earlyconfig:
        earlyconfig.write(
            textwrap.dedent(
                f"""\
                search --no-floppy --set=root --file /{prefix}/grub.cfg
                set prefix=($root)/{prefix}
                """
            )
        )

        earlyconfig.flush()

        bwrap(
            context,
            [
                mkimage,
                "--directory", directory,
                "--config", earlyconfig.name,
                "--prefix", f"/{prefix}",
                "--output", dst / "core.img",
                "--format", "i386-pc",
                *(["--verbose"] if ARG_DEBUG.get() else []),
                # Modules required to find and read from the XBOOTLDR partition which has all the other modules.
                "fat",
                "part_gpt",
                "biosdisk",
                "search",
                "search_fs_file",
            ],
            options=["--bind", context.root / "usr", "/usr"],
        )

    for p in directory.glob("*.mod"):
        shutil.copy2(p, dst)

    for p in directory.glob("*.lst"):
        shutil.copy2(p, dst)

    shutil.copy2(directory / "modinfo.sh", dst)
    shutil.copy2(directory / "boot.img", dst)

    dst = context.root / "efi" / prefix / "fonts"
    with umask(~0o700):
        dst.mkdir(exist_ok=True)

    for prefix in ("grub", "grub2"):
        unicode = context.root / "usr/share" / prefix / "unicode.pf2"
        if unicode.exists():
            shutil.copy2(unicode, dst)


def install_grub_bios(context: Context, partitions: Sequence[Partition]) -> None:
    if not want_grub_bios(context, partitions):
        return

    setup = find_grub_binary(context, "grub-bios-setup")
    assert setup

    prefix = find_grub_prefix(context)
    assert prefix

    # grub-bios-setup insists on being able to open the root device that --directory is located on, which
    # needs root privileges. However, it only uses the root device when it is unable to embed itself in the
    # bios boot partition. To make installation work unprivileged, we trick grub to think that the root
    # device is our image by mounting over its /proc/self/mountinfo file (where it gets its information from)
    # with our own file correlating the root directory to our image file.
    mountinfo = context.workspace / "mountinfo"
    mountinfo.write_text(f"1 0 1:1 / / - fat {context.staging / context.config.output_with_format}\n")

    with complete_step("Installing grub boot loader…"):
        # We don't setup the mountinfo bind mount with bwrap because we need to know the child process pid to
        # be able to do the mount and we don't know the pid beforehand.
        bwrap(
            context,
            [
                "sh", "-c", f"mount --bind {mountinfo} /proc/$$/mountinfo && exec $0 \"$@\"",
                setup,
                "--directory", context.root / "efi" / prefix / "i386-pc",
                *(["--verbose"] if ARG_DEBUG.get() else []),
                context.staging / context.config.output_with_format,
            ],
            options=["--bind", context.root / "usr", "/usr"],
        )


def install_tree(
    context: Context,
    src: Path,
    dst: Path,
    target: Optional[Path] = None,
    *,
    preserve_owner: bool = True,
) -> None:
    t = dst
    if target:
        t = dst / target.relative_to("/")

    with umask(~0o755):
        t.parent.mkdir(parents=True, exist_ok=True)

    if src.is_dir() or (src.is_file() and target):
        copy_tree(src, t, preserve_owner=preserve_owner, use_subvolumes=context.config.use_subvolumes)
    elif src.suffix == ".tar":
        extract_tar(context, src, t)
    elif src.suffix == ".raw":
        run(["systemd-dissect", "--copy-from", src, "/", t])
    else:
        # If we get an unknown file without a target, we just copy it into /.
        copy_tree(src, t, preserve_owner=preserve_owner, use_subvolumes=context.config.use_subvolumes)


def install_base_trees(context: Context) -> None:
    if not context.config.base_trees or context.config.overlay:
        return

    with complete_step("Copying in base trees…"):
        for path in context.config.base_trees:
            install_tree(context, path, context.root)


def install_skeleton_trees(context: Context) -> None:
    if not context.config.skeleton_trees:
        return

    with complete_step("Copying in skeleton file trees…"):
        for tree in context.config.skeleton_trees:
            install_tree(context, tree.source, context.root, tree.target, preserve_owner=False)


def install_package_manager_trees(context: Context) -> None:
    # Ensure /etc exists in the package manager tree
    (context.pkgmngr / "etc").mkdir(exist_ok=True)

    # Required to be able to access certificates in the sandbox when running from nix.
    if Path("/etc/static").is_symlink():
        (context.pkgmngr / "etc/static").symlink_to(Path("/etc/static").readlink())

    if not context.config.package_manager_trees:
        return

    with complete_step("Copying in package manager file trees…"):
        for tree in context.config.package_manager_trees:
            install_tree(context, tree.source, context.workspace / "pkgmngr", tree.target, preserve_owner=False)


def install_extra_trees(context: Context) -> None:
    if not context.config.extra_trees:
        return

    with complete_step("Copying in extra file trees…"):
        for tree in context.config.extra_trees:
            install_tree(context, tree.source, context.root, tree.target, preserve_owner=False)


def install_build_dest(context: Context) -> None:
    if not any(context.install_dir.iterdir()):
        return

    with complete_step("Copying in build tree…"):
        copy_tree(context.install_dir, context.root, use_subvolumes=context.config.use_subvolumes)


def gzip_binary() -> str:
    return "pigz" if shutil.which("pigz") else "gzip"


def gen_kernel_images(context: Context) -> Iterator[tuple[str, Path]]:
    if not (context.root / "usr/lib/modules").exists():
        return

    for kver in sorted(
        (k for k in (context.root / "usr/lib/modules").iterdir() if k.is_dir()),
        key=lambda k: GenericVersion(k.name),
        reverse=True
    ):
        # Make sure we look for anything that remotely resembles vmlinuz, as
        # the arch specific install scripts in the kernel source tree sometimes
        # do weird stuff. But let's make sure we're not returning UKIs as the
        # UKI on Fedora is named vmlinuz-virt.efi.
        for kimg in kver.glob("vmlinuz*"):
            if KernelType.identify(kimg) != KernelType.uki:
                yield kver.name, kimg
                break


def build_initrd(context: Context) -> Path:
    if context.config.distribution == Distribution.custom:
        die("Building a default initrd is not supported for custom distributions")

    # Default values are assigned via the parser so we go via the argument parser to construct
    # the config for the initrd.

    if context.config.root_password:
        password, hashed = context.config.root_password
        rootpwopt = f"hashed:{password}" if hashed else password
    else:
        rootpwopt = None

    cmdline = [
        "--directory", "",
        "--distribution", str(context.config.distribution),
        "--release", context.config.release,
        "--architecture", str(context.config.architecture),
        *(["--mirror", context.config.mirror] if context.config.mirror else []),
        "--repository-key-check", str(context.config.repository_key_check),
        "--repositories", ",".join(context.config.repositories),
        "--package-manager-tree", ",".join(format_tree(t) for t in context.config.package_manager_trees),
        # Note that when compress_output == Compression.none == 0 we don't pass --compress-output which means the
        # default compression will get picked. This is exactly what we want so that initrds are always compressed.
        *(["--compress-output", str(context.config.compress_output)] if context.config.compress_output else []),
        "--with-network", str(context.config.with_network),
        "--cache-only", str(context.config.cache_only),
        "--output-dir", str(context.workspace / "initrd"),
        *(["--workspace-dir", str(context.config.workspace_dir)] if context.config.workspace_dir else []),
        "--cache-dir", str(context.cache_dir),
        *(["--local-mirror", str(context.config.local_mirror)] if context.config.local_mirror else []),
        "--incremental", str(context.config.incremental),
        "--acl", str(context.config.acl),
        *flatten(["--package", package] for package in context.config.initrd_packages),
        "--output", f"{context.config.output}-initrd",
        *(["--image-id", context.config.image_id] if context.config.image_id else []),
        *(["--image-version", context.config.image_version] if context.config.image_version else []),
        *(
            ["--source-date-epoch", str(context.config.source_date_epoch)]
            if context.config.source_date_epoch is not None else
            []
        ),
        *(["--locale", context.config.locale] if context.config.locale else []),
        *(["--locale-messages", context.config.locale_messages] if context.config.locale_messages else []),
        *(["--keymap", context.config.keymap] if context.config.keymap else []),
        *(["--timezone", context.config.timezone] if context.config.timezone else []),
        *(["--hostname", context.config.hostname] if context.config.hostname else []),
        *(["--root-password", rootpwopt] if rootpwopt else []),
        *([f"--environment={k}='{v}'" for k, v in context.config.environment.items()]),
        *(["--tools-tree", str(context.config.tools_tree)] if context.config.tools_tree else []),
        *(["-f"] * context.args.force),
    ]

    with resource_path(mkosi.resources) as r:
        cmdline += ["--include", os.fspath(r / "mkosi-initrd")]

        for include in context.config.initrd_include:
            cmdline += ["--include", os.fspath(include)]

        args, [config] = parse_config(cmdline + ["build"])

        config = dataclasses.replace(config, image="default-initrd")
        assert config.output_dir

        config.output_dir.mkdir(exist_ok=True)

        if (config.output_dir / config.output).exists():
            return config.output_dir / config.output

        with complete_step("Building default initrd"):
            build_image(args, config)

    return config.output_dir / config.output


def build_microcode_initrd(context: Context) -> Optional[Path]:
    microcode = context.workspace / "initrd-microcode.img"
    if microcode.exists():
        return microcode

    amd = context.root / "usr/lib/firmware/amd-ucode"
    intel = context.root / "usr/lib/firmware/intel-ucode"

    if not amd.exists() and not intel.exists():
        return None

    root = context.workspace / "initrd-microcode-root"
    destdir = root / "kernel/x86/microcode"

    with umask(~0o755):
        destdir.mkdir(parents=True, exist_ok=True)

    if amd.exists():
        with (destdir / "AuthenticAMD.bin").open("wb") as f:
            for p in amd.iterdir():
                f.write(p.read_bytes())

    if intel.exists():
        with (destdir / "GenuineIntel.bin").open("wb") as f:
            for p in intel.iterdir():
                f.write(p.read_bytes())

    make_cpio(context, root, microcode)

    return microcode


def build_kernel_modules_initrd(context: Context, kver: str) -> Path:
    kmods = context.workspace / f"initrd-kernel-modules-{kver}.img"
    if kmods.exists():
        return kmods

    make_cpio(
        context, context.root, kmods,
        gen_required_kernel_modules(
            context.root, kver,
            context.config.kernel_modules_initrd_include,
            context.config.kernel_modules_initrd_exclude,
            context.config.kernel_modules_initrd_include_host,
        )
    )

    # Debian/Ubuntu do not compress their kernel modules, so we compress the initramfs instead. Note that
    # this is not ideal since the compressed kernel modules will all be decompressed on boot which
    # requires significant memory.
    if context.config.distribution.is_apt_distribution():
        maybe_compress(context, Compression.zstd, kmods, kmods)

    return kmods


def join_initrds(initrds: Sequence[Path], output: Path) -> Path:
    assert initrds

    if len(initrds) == 1:
        copy_tree(initrds[0], output)
        return output

    seq = io.BytesIO()
    for p in initrds:
        initrd = p.read_bytes()
        n = len(initrd)
        padding = b'\0' * (round_up(n, 4) - n)  # pad to 32 bit alignment
        seq.write(initrd)
        seq.write(padding)

    output.write_bytes(seq.getbuffer())
    return output


def python_binary(config: Config) -> str:
    # If there's no tools tree, prefer the interpreter from MKOSI_INTERPRETER. If there is a tools
    # tree, just use the default python3 interpreter.
    return "python3" if config.tools_tree else os.getenv("MKOSI_INTERPRETER", "python3")


def extract_pe_section(context: Context, binary: Path, section: str, output: Path) -> None:
    # When using a tools tree, we want to use the pefile module from the tools tree instead of requiring that
    # python-pefile is installed on the host. So we execute python as a subprocess to make sure we load
    # pefile from the tools tree if one is used.

    # TODO: Use ignore_padding=True instead of length once we can depend on a newer pefile.
    pefile = textwrap.dedent(
        f"""\
        import pefile
        from pathlib import Path
        pe = pefile.PE("{binary}", fast_load=True)
        section = {{s.Name.decode().strip("\\0"): s for s in pe.sections}}["{section}"]
        Path("{output}").write_bytes(section.get_data(length=section.Misc_VirtualSize))
        """
    )

    bwrap(context, [python_binary(context.config)], input=pefile)


def build_uki(
    context: Context,
    stub: Path,
    kver: str,
    kimg: Path,
    initrds: Sequence[Path],
    cmdline: Sequence[str],
    output: Path,
    roothash: Optional[str] = None,
) -> None:
    cmdline = list(cmdline)

    if roothash:
        cmdline += [roothash]

    cmdline += context.config.kernel_command_line

    # Older versions of systemd-stub expect the cmdline section to be null terminated. We can't embed
    # nul terminators in argv so let's communicate the cmdline via a file instead.
    (context.workspace / "cmdline").write_text(f"{' '.join(cmdline).strip()}\x00")

    if not (arch := context.config.architecture.to_efi()):
        die(f"Architecture {context.config.architecture} does not support UEFI")

    cmd: list[PathString] = [
        shutil.which("ukify") or "/usr/lib/systemd/ukify",
        "--cmdline", f"@{context.workspace / 'cmdline'}",
        "--os-release", f"@{context.root / 'usr/lib/os-release'}",
        "--stub", stub,
        "--output", output,
        "--efi-arch", arch,
        "--uname", kver,
    ]

    if not context.config.tools_tree:
        for p in context.config.extra_search_paths:
            cmd += ["--tools", p]

    if context.config.secure_boot:
        assert context.config.secure_boot_key
        assert context.config.secure_boot_certificate

        cmd += ["--sign-kernel"]

        if context.config.secure_boot_sign_tool != SecureBootSignTool.pesign:
            cmd += [
                "--signtool", "sbsign",
                "--secureboot-private-key",
                context.config.secure_boot_key,
                "--secureboot-certificate",
                context.config.secure_boot_certificate,
            ]
        else:
            pesign_prepare(context)
            cmd += [
                "--signtool", "pesign",
                "--secureboot-certificate-dir",
                context.workspace / "pesign",
                "--secureboot-certificate-name",
                certificate_common_name(context, context.config.secure_boot_certificate),
            ]

        sign_expected_pcr = (context.config.sign_expected_pcr == ConfigFeature.enabled or
                            (context.config.sign_expected_pcr == ConfigFeature.auto and
                                shutil.which("systemd-measure") is not None))

        if sign_expected_pcr:
            cmd += [
                "--pcr-private-key", context.config.secure_boot_key,
                "--pcr-banks", "sha1,sha256",
            ]

    cmd += ["build", "--linux", kimg]

    for initrd in initrds:
        cmd += ["--initrd", initrd]

    with complete_step(f"Generating unified kernel image for kernel version {kver}"):
        bwrap(context, cmd)


def want_efi(config: Config) -> bool:
    # Do we want to make the image bootable on EFI firmware?
    # Note that this returns True also in the case where autodetection might later
    # cause the system to not be made bootable on EFI firmware after the filesystem
    # has been populated.

    if config.output_format in (OutputFormat.uki, OutputFormat.esp):
        return True

    if config.bootable == ConfigFeature.disabled:
        return False

    if config.bootloader == Bootloader.none:
        return False

    if (
        (config.output_format == OutputFormat.cpio or config.output_format.is_extension_image() or config.overlay)
        and config.bootable == ConfigFeature.auto
    ):
        return False

    if config.architecture.to_efi() is None:
        if config.bootable == ConfigFeature.enabled:
            die(f"Cannot make image bootable on UEFI on {config.architecture} architecture")

        return False

    return True


def find_entry_token(context: Context) -> str:
    if (
        "--version" not in run(["kernel-install", "--help"], stdout=subprocess.PIPE).stdout or
        systemd_tool_version("kernel-install") < "255.1"
    ):
        return context.config.image_id or context.config.distribution.name

    output = json.loads(bwrap(context, ["kernel-install", "--root", context.root, "--json=pretty", "inspect"],
                        stdout=subprocess.PIPE).stdout)
    logging.debug(json.dumps(output, indent=4))
    return cast(str, output["EntryToken"])


def install_uki(context: Context, partitions: Sequence[Partition]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if not want_efi(context.config) or context.config.output_format in (OutputFormat.uki, OutputFormat.esp):
        return

    arch = context.config.architecture.to_efi()
    stub = context.root / f"usr/lib/systemd/boot/efi/linux{arch}.efi.stub"
    if not stub.exists() and context.config.bootable == ConfigFeature.auto:
        return

    roothash = finalize_roothash(partitions)

    for kver, kimg in gen_kernel_images(context):
        # See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/#boot-counting
        boot_count = ""
        if (context.root / "etc/kernel/tries").exists():
            boot_count = f'+{(context.root / "etc/kernel/tries").read_text().strip()}'

        if context.config.bootloader == Bootloader.uki:
            if context.config.shim_bootloader != ShimBootloader.none:
                boot_binary = context.root / shim_second_stage_binary(context)
            else:
                boot_binary = context.root / efi_boot_binary(context)
        else:
            token = find_entry_token(context)
            if roothash:
                _, _, h = roothash.partition("=")
                boot_binary = context.root / f"boot/EFI/Linux/{token}-{kver}-{h}{boot_count}.efi"
            else:
                boot_binary = context.root / f"boot/EFI/Linux/{token}-{kver}{boot_count}.efi"

        microcode = build_microcode_initrd(context)

        initrds = [microcode] if microcode else []
        initrds += context.config.initrds or [build_initrd(context)]

        if context.config.kernel_modules_initrd:
            initrds += [build_kernel_modules_initrd(context, kver)]

        # Make sure the parent directory where we'll be writing the UKI exists.
        with umask(~0o700):
            boot_binary.parent.mkdir(parents=True, exist_ok=True)

        if (context.root / "etc/kernel/cmdline").exists():
            cmdline = [(context.root / "etc/kernel/cmdline").read_text().strip()]
        elif (context.root / "usr/lib/kernel/cmdline").exists():
            cmdline = [(context.root / "usr/lib/kernel/cmdline").read_text().strip()]
        else:
            cmdline = []

        build_uki(context, stub, kver, context.root / kimg, initrds, cmdline, boot_binary, roothash=roothash)

        if not (context.staging / context.config.output_split_initrd).exists():
            # Extract the combined initrds from the UKI so we can use it to direct kernel boot with qemu
            # if needed.
            extract_pe_section(context, boot_binary, ".initrd", context.staging / context.config.output_split_initrd)

        if not (context.staging / context.config.output_split_uki).exists():
            shutil.copy(boot_binary, context.staging / context.config.output_split_uki)

            # ukify will have signed the kernel image as well. Let's make sure we put the signed kernel
            # image in the output directory instead of the unsigned one by reading it from the UKI.
            extract_pe_section(context, boot_binary, ".linux", context.staging / context.config.output_split_kernel)

        print_output_size(boot_binary)

        if context.config.bootloader == Bootloader.uki:
            break

    if (
        context.config.bootable == ConfigFeature.enabled and
        not (context.staging / context.config.output_split_uki).exists()
    ):
        die("A bootable image was requested but no kernel was found")


def make_uki(context: Context, stub: Path, kver: str, kimg: Path, output: Path) -> None:
    microcode = build_microcode_initrd(context)
    make_cpio(context, context.root, context.workspace / "initrd")
    maybe_compress(context, context.config.compress_output, context.workspace / "initrd", context.workspace / "initrd")

    initrds = [microcode] if microcode else []
    initrds += [context.workspace / "initrd"]

    build_uki(context, stub, kver, kimg, initrds, [], output)
    extract_pe_section(context, output, ".linux", context.staging / context.config.output_split_kernel)
    extract_pe_section(context, output, ".initrd", context.staging / context.config.output_split_initrd)


def compressor_command(compression: Compression) -> list[PathString]:
    """Returns a command suitable for compressing archives."""

    if compression == Compression.gz:
        return [gzip_binary(), "--fast", "--stdout", "-"]
    elif compression == Compression.xz:
        return ["xz", "--check=crc32", "--fast", "-T0", "--stdout", "-"]
    elif compression == Compression.zstd:
        return ["zstd", "-q", "-T0", "--stdout", "-"]
    else:
        die(f"Unknown compression {compression}")


def maybe_compress(context: Context, compression: Compression, src: Path, dst: Optional[Path] = None) -> None:
    if not compression or src.is_dir():
        if dst:
            move_tree(src, dst, use_subvolumes=context.config.use_subvolumes)
        return

    if not dst:
        dst = src.parent / f"{src.name}.{compression}"

    with complete_step(f"Compressing {src} with {compression}"):
        with src.open("rb") as i:
            src.unlink() # if src == dst, make sure dst doesn't truncate the src file but creates a new file.

            with dst.open("wb") as o:
                bwrap(context, compressor_command(compression), stdin=i, stdout=o)


def copy_vmlinuz(context: Context) -> None:
    if (context.staging / context.config.output_split_kernel).exists():
        return

    for _, kimg in gen_kernel_images(context):
        shutil.copy(context.root / kimg, context.staging / context.config.output_split_kernel)
        break


def copy_initrd(context: Context) -> None:
    if (context.staging / context.config.output_split_initrd).exists():
        return

    if context.config.bootable == ConfigFeature.disabled:
        return

    if context.config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        return

    for kver, _ in gen_kernel_images(context):
        microcode = build_microcode_initrd(context)
        initrds = [microcode] if microcode else []
        initrds += context.config.initrds or [build_initrd(context)]
        if context.config.kernel_modules_initrd:
            kver = next(gen_kernel_images(context))[0]
            initrds += [build_kernel_modules_initrd(context, kver)]
        join_initrds(initrds, context.staging / context.config.output_split_initrd)
        break


def hash_file(of: TextIO, path: Path) -> None:
    bs = 16 * 1024**2
    h = hashlib.sha256()

    with path.open("rb") as sf:
        while (buf := sf.read(bs)):
            h.update(buf)

    of.write(h.hexdigest() + " *" + path.name + "\n")


def calculate_sha256sum(context: Context) -> None:
    if context.config.output_format == OutputFormat.directory:
        return None

    if not context.config.checksum:
        return None

    with complete_step("Calculating SHA256SUMS…"):
        with open(context.workspace / context.config.output_checksum, "w") as f:
            for p in context.staging.iterdir():
                hash_file(f, p)

        (context.workspace / context.config.output_checksum).rename(context.staging / context.config.output_checksum)


def calculate_signature(context: Context) -> None:
    if not context.config.sign:
        return None

    with complete_step("Signing SHA256SUMS…"):
        cmdline: list[PathString] = ["gpg", "--detach-sign"]

        # Need to specify key before file to sign
        if context.config.key is not None:
            cmdline += ["--default-key", context.config.key]

        cmdline += [
            "--output", context.staging / context.config.output_signature,
            context.staging / context.config.output_checksum,
        ]

        # Set the path of the keyring to use based on the environment if possible and fallback to the default
        # path. Without this the keyring for the root user will instead be used which will fail for a
        # non-root build.
        env = dict(GNUPGHOME=os.environ.get("GNUPGHOME", os.fspath(Path(os.environ["HOME"]) / ".gnupg")))
        if sys.stderr.isatty():
            env |= dict(GPGTTY=os.ttyname(sys.stderr.fileno()))

        # Do not output warnings about keyring permissions
        bwrap(context, cmdline, stderr=subprocess.DEVNULL, env=env)


def dir_size(path: Union[Path, os.DirEntry[str]]) -> int:
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
            dir_sum += dir_size(entry)
    return dir_sum


def save_manifest(context: Context, manifest: Optional[Manifest]) -> None:
    if not manifest:
        return

    if manifest.has_data():
        if ManifestFormat.json in context.config.manifest_format:
            with complete_step(f"Saving manifest {context.config.output_manifest}"):
                with open(context.staging / context.config.output_manifest, 'w') as f:
                    manifest.write_json(f)

        if ManifestFormat.changelog in context.config.manifest_format:
            with complete_step(f"Saving report {context.config.output_changelog}"):
                with open(context.staging / context.config.output_changelog, 'w') as f:
                    manifest.write_package_report(f)


def print_output_size(path: Path) -> None:
    if path.is_dir():
        log_step(f"{path} size is " + format_bytes(dir_size(path)) + ".")
    else:
        size = format_bytes(path.stat().st_size)
        space = format_bytes(path.stat().st_blocks * 512)
        log_step(f"{path} size is {size}, consumes {space}.")


def empty_directory(path: Path) -> None:
    try:
        rmtree(*path.iterdir())
    except FileNotFoundError:
        pass


def unlink_output(args: Args, config: Config) -> None:
    # We remove any cached images if either the user used --force twice, or he/she called "clean" with it
    # passed once. Let's also remove the downloaded package cache if the user specified one additional
    # "--force".

    if args.verb == Verb.clean:
        remove_build_cache = args.force > 0
        remove_package_cache = args.force > 1
    else:
        remove_build_cache = args.force > 1
        remove_package_cache = args.force > 2

    with complete_step("Removing output files…"):
        if config.output_dir_or_cwd().exists():
            for p in config.output_dir_or_cwd().iterdir():
                if p.name.startswith(config.output):
                    rmtree(p)

    if remove_build_cache:
        if config.cache_dir:
            for p in cache_tree_paths(config):
                if p.exists():
                    with complete_step(f"Removing cache entry {p}…"):
                        rmtree(p)

        if config.build_dir and config.build_dir.exists() and any(config.build_dir.iterdir()):
            with complete_step("Clearing out build directory…"):
                empty_directory(config.build_dir)

    if remove_package_cache:
        if config.cache_dir and config.cache_dir.exists() and any(config.cache_dir.iterdir()):
            with complete_step("Clearing out package cache…"):
                rmtree(*(
                    config.cache_dir / p / d
                    for p in ("cache", "lib")
                    for d in ("apt", "dnf", "libdnf5", "pacman", "zypp")
                ))


def cache_tree_paths(config: Config) -> tuple[Path, Path, Path]:
    fragments = [config.distribution, config.release, config.architecture]

    if config.image:
        fragments += [config.image]

    key = '~'.join(str(s) for s in fragments)

    assert config.cache_dir
    return (
        config.cache_dir / f"{key}.cache",
        config.cache_dir / f"{key}.build.cache",
        config.cache_dir / f"{key}.manifest",
    )


def check_inputs(config: Config) -> None:
    """
    Make sure all the inputs exist that aren't checked during config parsing because they might be created by an
    earlier build.
    """
    for base in config.base_trees:
        if not base.exists():
            die(f"Base tree {base} not found")

    if config.tools_tree and not config.tools_tree.exists():
        die(f"Tools tree {config.tools_tree} not found")

    for name, trees in (("Skeleton", config.skeleton_trees),
                        ("Package manager", config.package_manager_trees),
                        ("Extra", config.extra_trees)):
        for tree in trees:
            if not tree.source.exists():
                die(f"{name} tree {tree.source} not found")

    if config.bootable != ConfigFeature.disabled:
        for p in config.initrds:
            if not p.exists():
                die(f"Initrd {p} not found")
            if not p.is_file():
                die(f"Initrd {p} is not a file")


def check_outputs(config: Config) -> None:
    for f in (
        config.output_with_compression,
        config.output_checksum if config.checksum else None,
        config.output_signature if config.sign else None,
    ):
        if f and (config.output_dir_or_cwd() / f).exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def systemd_tool_version(tool: PathString) -> GenericVersion:
    return GenericVersion(run([tool, "--version"], stdout=subprocess.PIPE).stdout.split()[2].strip("()"))


def check_tool(*tools: PathString, reason: str, hint: Optional[str] = None) -> Path:
    tool = find_binary(*tools)
    if not tool:
        die(f"Could not find '{tools[0]}' which is required to {reason}.", hint=hint)

    return tool


def check_systemd_tool(*tools: PathString, version: str, reason: str, hint: Optional[str] = None) -> None:
    tool = check_tool(*tools, reason=reason, hint=hint)

    v = systemd_tool_version(tool)
    if v < version:
        die(f"Found '{tool}' with version {v} but version {version} or newer is required to {reason}.",
            hint=f"Use ToolsTree=default to get a newer version of '{tools[0]}'.")


def check_tools(verb: Verb, config: Config) -> None:
    if verb == Verb.build:
        if want_efi(config):
            check_systemd_tool(
                "ukify", "/usr/lib/systemd/ukify",
                version="254",
                reason="build bootable images",
                hint="Use ToolsTree=default to download most required tools including ukify automatically or use "
                     "Bootable=no to create a non-bootable image which doesn't require ukify",
            )

        if config.output_format in (OutputFormat.disk, OutputFormat.esp):
            check_systemd_tool("systemd-repart", version="254", reason="build disk images")

        if config.selinux_relabel == ConfigFeature.enabled:
            check_tool("setfiles", reason="relabel files")

    if verb == Verb.boot:
        check_systemd_tool("systemd-nspawn", version="254", reason="boot images")


def configure_ssh(context: Context) -> None:
    if not context.config.ssh:
        return

    unitdir = context.root / "usr/lib/systemd/system"
    with umask(~0o755):
        unitdir.mkdir(parents=True, exist_ok=True)

    with umask(~0o644):
        (unitdir / "ssh.socket").write_text(
            textwrap.dedent(
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

        (unitdir / "ssh@.service").write_text(
            textwrap.dedent(
                """\
                [Unit]
                Description=Mkosi SSH Server
                After=sshd-keygen.target

                [Service]
                # We disable PAM because of an openssh-server bug where it sets PAM_RHOST=UNKNOWN when -i is
                # used causing a very slow reverse DNS lookup by pam.
                ExecStart=sshd -i -o UsePAM=no
                StandardInput=socket
                RuntimeDirectoryPreserve=yes
                RuntimeDirectory=sshd
                # ssh always exits with 255 even on normal disconnect, so let's mark that as success so we
                # don't get noisy logs about SSH service failures.
                SuccessExitStatus=255
                """
            )
        )

    preset = context.root / "usr/lib/systemd/system-preset/80-mkosi-ssh.preset"
    with umask(~0o755):
        preset.parent.mkdir(parents=True, exist_ok=True)
    with umask(~0o644):
        preset.write_text("enable ssh.socket\n")


def configure_initrd(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    if (
        not (context.root / "init").exists() and
        not (context.root / "init").is_symlink() and
        (context.root / "usr/lib/systemd/systemd").exists()
    ):
        (context.root / "init").symlink_to("/usr/lib/systemd/systemd")

    if not context.config.make_initrd:
        return

    if not (context.root / "etc/initrd-release").exists() and not (context.root / "etc/initrd-release").is_symlink():
        (context.root / "etc/initrd-release").symlink_to("/etc/os-release")


def configure_clock(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    with umask(~0o644):
        (context.root / "usr/lib/clock-epoch").touch()


def run_depmod(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    for kver, _ in gen_kernel_images(context):
        process_kernel_modules(
            context.root, kver,
            context.config.kernel_modules_include,
            context.config.kernel_modules_exclude,
            context.config.kernel_modules_include_host,
        )

        with complete_step(f"Running depmod for {kver}"):
            bwrap(context, ["depmod", "--all", "--basedir", context.root, kver])


def run_sysusers(context: Context) -> None:
    if not shutil.which("systemd-sysusers"):
        logging.info("systemd-sysusers is not installed, not generating system users")
        return

    with complete_step("Generating system users"):
        bwrap(context, ["systemd-sysusers", "--root", context.root])


def run_preset(context: Context) -> None:
    if not shutil.which("systemctl"):
        logging.info("systemctl is not installed, not applying presets")
        return

    with complete_step("Applying presets…"):
        bwrap(context, ["systemctl", "--root", context.root, "preset-all"])
        bwrap(context, ["systemctl", "--root", context.root, "--global", "preset-all"])


def run_hwdb(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    if not shutil.which("systemd-hwdb"):
        logging.info("systemd-hwdb is not installed, not generating hwdb")
        return

    with complete_step("Generating hardware database"):
        bwrap(context, ["systemd-hwdb", "--root", context.root, "--usr", "--strict", "update"])

    # Remove any existing hwdb in /etc in favor of the one we just put in /usr.
    (context.root / "etc/udev/hwdb.bin").unlink(missing_ok=True)


def run_firstboot(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    password, hashed = context.config.root_password or (None, False)
    pwopt = "--root-password-hashed" if hashed else "--root-password"
    pwcred = "passwd.hashed-password.root" if hashed else "passwd.plaintext-password.root"

    settings = (
        ("--locale",          "firstboot.locale",          context.config.locale),
        ("--locale-messages", "firstboot.locale-messages", context.config.locale_messages),
        ("--keymap",          "firstboot.keymap",          context.config.keymap),
        ("--timezone",        "firstboot.timezone",        context.config.timezone),
        ("--hostname",        None,                        context.config.hostname),
        (pwopt,               pwcred,                      password),
        ("--root-shell",      "passwd.shell.root",         context.config.root_shell),
    )

    options = []
    creds = []

    for option, cred, value in settings:
        # Check for None as password might be the empty string
        if value is None:
            continue

        options += [option, value]

        if cred:
            creds += [(cred, value)]

    if not options and not creds:
        return

    with complete_step("Applying first boot settings"):
        bwrap(context, ["systemd-firstboot", "--root", context.root, "--force", *options])

        # Initrds generally don't ship with only /usr so there's not much point in putting the credentials in
        # /usr/lib/credstore.
        if context.config.output_format != OutputFormat.cpio or not context.config.make_initrd:
            with umask(~0o755):
                (context.root / "usr/lib/credstore").mkdir(exist_ok=True)

            for cred, value in creds:
                with umask(~0o600 if "password" in cred else ~0o644):
                    (context.root / "usr/lib/credstore" / cred).write_text(value)


def run_selinux_relabel(context: Context) -> None:
    if context.config.selinux_relabel == ConfigFeature.disabled:
        return

    selinux = context.root / "etc/selinux/config"
    if not selinux.exists():
        if context.config.selinux_relabel == ConfigFeature.enabled:
            die("SELinux relabel is requested but could not find selinux config at /etc/selinux/config")
        return

    policy = bwrap(context, ["sh", "-c", f". {selinux} && echo $SELINUXTYPE"], stdout=subprocess.PIPE).stdout.strip()
    if not policy:
        if context.config.selinux_relabel == ConfigFeature.enabled:
            die("SELinux relabel is requested but no selinux policy is configured in /etc/selinux/config")
        return

    if not shutil.which("setfiles"):
        logging.info("setfiles is not installed, not relabeling files")
        return

    fc = context.root / "etc/selinux" / policy / "contexts/files/file_contexts"
    binpolicydir = context.root / "etc/selinux" / policy / "policy"

    try:
        # The policy file is named policy.XX where XX is the policy version that indicates what features are
        # available. It's not expected for there to be more than one file in this directory.
        binpolicy = next(binpolicydir.iterdir())
    except StopIteration:
        die(f"SELinux binary policy not found in {binpolicydir}")

    with complete_step(f"Relabeling files using {policy} policy"):
        bwrap(context, ["setfiles", "-mFr", context.root, "-c", binpolicy, fc, context.root],
              check=context.config.selinux_relabel == ConfigFeature.enabled)


def need_build_overlay(config: Config) -> bool:
    return bool(config.build_scripts and (config.build_packages or config.prepare_scripts))


def save_cache(context: Context) -> None:
    if not context.config.incremental:
        return

    final, build, manifest = cache_tree_paths(context.config)

    with complete_step("Installing cache copies"):
        rmtree(final)

        # We only use the cache-overlay directory for caching if we have a base tree, otherwise we just
        # cache the root directory.
        if (context.workspace / "cache-overlay").exists():
            move_tree(context.workspace / "cache-overlay", final, use_subvolumes=context.config.use_subvolumes)
        else:
            move_tree(context.root, final, use_subvolumes=context.config.use_subvolumes)

        if need_build_overlay(context.config) and (context.workspace / "build-overlay").exists():
            rmtree(build)
            move_tree(context.workspace / "build-overlay", build, use_subvolumes=context.config.use_subvolumes)

        manifest.write_text(
            json.dumps(
                context.config.cache_manifest(),
                cls=JsonEncoder,
                indent=4,
                sort_keys=True,
            )
        )


def reuse_cache(context: Context) -> bool:
    if not context.config.incremental:
        return False

    final, build, manifest = cache_tree_paths(context.config)
    if not final.exists() or (need_build_overlay(context.config) and not build.exists()):
        return False

    if manifest.exists():
        prev = json.loads(manifest.read_text())
        if prev != json.loads(json.dumps(context.config.cache_manifest(), cls=JsonEncoder)):
            return False
    else:
        return False

    # Either we're running as root and the cache is owned by root or we're running unprivileged inside a user
    # namespace and we'll think the cache is owned by root. However, if we're running as root and the cache was
    # generated by an unprivileged build, the cache will not be owned by root and we should not use it.
    for p in (final, build):
        if p.exists() and p.stat().st_uid != 0:
            return False

    with complete_step("Copying cached trees"):
        copy_tree(final, context.root, use_subvolumes=context.config.use_subvolumes)
        if need_build_overlay(context.config):
            (context.workspace / "build-overlay").symlink_to(build)

    return True


def save_uki_components(context: Context) -> tuple[Optional[Path], Optional[str], Optional[Path]]:
    if context.config.output_format not in (OutputFormat.uki, OutputFormat.esp):
        return None, None, None

    try:
        kver, kimg = next(gen_kernel_images(context))
    except StopIteration:
        die("A kernel must be installed in the image to build a UKI")

    kimg = shutil.copy2(context.root / kimg, context.workspace)

    if not (arch := context.config.architecture.to_efi()):
        die(f"Architecture {context.config.architecture} does not support UEFI")

    stub = context.root / f"usr/lib/systemd/boot/efi/linux{arch}.efi.stub"
    if not stub.exists():
        die(f"sd-stub not found at /{stub.relative_to(context.root)} in the image")

    stub = shutil.copy2(stub, context.workspace)

    return stub, kver, kimg


def make_image(
    context: Context,
    msg: str,
    skip: Sequence[str] = [],
    split: bool = False,
    root: Optional[Path] = None,
    definitions: Sequence[Path] = [],
) -> list[Partition]:
    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--no-pager",
        f"--offline={yes_no(context.config.repart_offline)}",
        "--seed", str(context.config.seed) if context.config.seed else "random",
        context.staging / context.config.output_with_format,
    ]

    if root:
        cmdline += ["--root", root]
    if not context.config.architecture.is_native():
        cmdline += ["--architecture", str(context.config.architecture)]
    if not (context.staging / context.config.output_with_format).exists():
        cmdline += ["--empty=create"]
    if context.config.passphrase:
        cmdline += ["--key-file", context.config.passphrase]
    if context.config.verity_key:
        cmdline += ["--private-key", context.config.verity_key]
    if context.config.verity_certificate:
        cmdline += ["--certificate", context.config.verity_certificate]
    if skip:
        cmdline += ["--defer-partitions", ",".join(skip)]
    if split:
        cmdline += ["--split=yes"]
    if context.config.sector_size:
        cmdline += ["--sector-size", str(context.config.sector_size)]

    for d in definitions:
        cmdline += ["--definitions", d]

    env = {
        option: value
        for option, value in context.config.environment.items()
        if option.startswith("SYSTEMD_REPART_MKFS_OPTIONS_") or option == "SOURCE_DATE_EPOCH"
    }

    with complete_step(msg):
        output = json.loads(
            bwrap(context, cmdline, devices=not context.config.repart_offline, stdout=subprocess.PIPE, env=env).stdout
        )

    logging.debug(json.dumps(output, indent=4))

    partitions = [Partition.from_dict(d) for d in output]

    if split:
        for p in partitions:
            if p.split_path:
                maybe_compress(context, context.config.compress_output, p.split_path)

    return partitions


def make_disk(
    context: Context,
    msg: str,
    skip: Sequence[str] = [],
    split: bool = False,
) -> list[Partition]:
    if context.config.output_format != OutputFormat.disk:
        return []

    if context.config.repart_dirs:
        definitions = context.config.repart_dirs
    else:
        defaults = context.workspace / "repart-definitions"
        if not defaults.exists():
            defaults.mkdir()
            if (arch := context.config.architecture.to_efi()):
                bootloader = context.root / f"efi/EFI/BOOT/BOOT{arch.upper()}.EFI"
            else:
                bootloader = None

            esp = (
                context.config.bootable == ConfigFeature.enabled or
                (context.config.bootable == ConfigFeature.auto and bootloader and bootloader.exists())
            )
            bios = (context.config.bootable != ConfigFeature.disabled and want_grub_bios(context))

            if esp or bios:
                # Even if we're doing BIOS, let's still use the ESP to store the kernels, initrds and grub
                # modules. We cant use UKIs so we have to put each kernel and initrd on the ESP twice, so
                # let's make the ESP twice as big in that case.
                (defaults / "00-esp.conf").write_text(
                    textwrap.dedent(
                        f"""\
                        [Partition]
                        Type=esp
                        Format=vfat
                        CopyFiles=/boot:/
                        CopyFiles=/efi:/
                        SizeMinBytes={"1G" if bios else "512M"}
                        SizeMaxBytes={"1G" if bios else "512M"}
                        """
                    )
                )

            # If grub for BIOS is installed, let's add a BIOS boot partition onto which we can install grub.
            if bios:
                (defaults / "05-bios.conf").write_text(
                    textwrap.dedent(
                        f"""\
                        [Partition]
                        Type={Partition.GRUB_BOOT_PARTITION_UUID}
                        SizeMinBytes=1M
                        SizeMaxBytes=1M
                        """
                    )
                )

            (defaults / "10-root.conf").write_text(
                textwrap.dedent(
                    f"""\
                    [Partition]
                    Type=root
                    Format={context.config.distribution.filesystem()}
                    CopyFiles=/
                    Minimize=guess
                    """
                )
            )

        definitions = [defaults]

    return make_image(context, msg=msg, skip=skip, split=split, root=context.root, definitions=definitions)


def make_esp(context: Context, uki: Path) -> list[Partition]:
    if not (arch := context.config.architecture.to_efi()):
        die(f"Architecture {context.config.architecture} does not support UEFI")

    definitions = context.workspace / "esp-definitions"
    definitions.mkdir(exist_ok=True)

    # Use a minimum of 36MB or 260MB depending on sector size because otherwise the generated FAT filesystem will have
    # too few clusters to be considered a FAT32 filesystem by OVMF which will refuse to boot from it.
    # See https://superuser.com/questions/1702331/what-is-the-minimum-size-of-a-4k-native-partition-when-formatted-with-fat32/1717643#1717643
    if context.config.sector_size == 512:
        m = 36
    # TODO: Figure out minimum size for 2K sector size
    else:
        m = 260

    # Always reserve 10MB for filesystem metadata.
    size = max(uki.stat().st_size, (m - 10) * 1024**2) + 10 * 1024**2

    # TODO: Remove the extra 4096 for the max size once https://github.com/systemd/systemd/pull/29954 is in a stable
    # release.
    (definitions / "00-esp.conf").write_text(
        textwrap.dedent(
            f"""\
            [Partition]
            Type=esp
            Format=vfat
            CopyFiles={uki}:/EFI/BOOT/BOOT{arch.upper()}.EFI
            SizeMinBytes={size}
            SizeMaxBytes={size + 4096}
            """
        )
    )

    return make_image(context, msg="Generating ESP image", definitions=[definitions])


def make_extension_image(context: Context, output: Path) -> None:
    cmdline: list[PathString] = [
        "systemd-repart",
        "--root", context.root,
        "--dry-run=no",
        "--no-pager",
        f"--offline={yes_no(context.config.repart_offline)}",
        "--seed", str(context.config.seed) if context.config.seed else "random",
        "--empty=create",
        "--size=auto",
        output,
    ]

    if not context.config.architecture.is_native():
        cmdline += ["--architecture", str(context.config.architecture)]
    if context.config.passphrase:
        cmdline += ["--key-file", context.config.passphrase]
    if context.config.verity_key:
        cmdline += ["--private-key", context.config.verity_key]
    if context.config.verity_certificate:
        cmdline += ["--certificate", context.config.verity_certificate]
    if context.config.sector_size:
        cmdline += ["--sector-size", str(context.config.sector_size)]

    env = {
        option: value
        for option, value in context.config.environment.items()
        if option.startswith("SYSTEMD_REPART_MKFS_OPTIONS_") or option == "SOURCE_DATE_EPOCH"
    }

    with (
        resource_path(mkosi.resources) as r,
        complete_step(f"Building {context.config.output_format} extension image")
    ):
        bwrap(
            context,
            cmdline + ["--definitions", r / f"repart/definitions/{context.config.output_format}.repart.d"],
            devices=not context.config.repart_offline,
            env=env,
        )


def finalize_staging(context: Context) -> None:
    # Our output unlinking logic removes everything prefixed with the name of the image, so let's make
    # sure that everything we put into the output directory is prefixed with the name of the output.
    for f in context.staging.iterdir():
        # Skip the symlink we create without the version that points to the output with the version.
        if f.name.startswith(context.config.output) and f.is_symlink():
            continue

        name = f.name
        if not name.startswith(context.config.output):
            name = f"{context.config.output}-{name}"
        if name != f.name:
            f.rename(context.staging / name)

    for f in context.staging.iterdir():
        # Make sure all build outputs that are not directories are owned by the user running mkosi.
        if not f.is_dir():
            os.chown(f, INVOKING_USER.uid, INVOKING_USER.gid, follow_symlinks=False)
        move_tree(f, context.config.output_dir_or_cwd(), use_subvolumes=context.config.use_subvolumes)


def normalize_mtime(root: Path, mtime: Optional[int], directory: Optional[Path] = None) -> None:
    if mtime is None:
        return

    directory = directory or Path("")

    with complete_step(f"Normalizing modification times of /{directory}"):
        os.utime(root / directory, (mtime, mtime), follow_symlinks=False)
        for p in (root / directory).rglob("*"):
            os.utime(p, (mtime, mtime), follow_symlinks=False)


@contextlib.contextmanager
def setup_workspace(args: Args, config: Config) -> Iterator[Path]:
    with contextlib.ExitStack() as stack:
        workspace = Path(tempfile.mkdtemp(dir=config.workspace_dir_or_default(), prefix="mkosi-workspace"))
        stack.callback(lambda: rmtree(workspace))

        with scopedenv({"TMPDIR" : os.fspath(workspace)}):
            try:
                yield Path(workspace)
            except BaseException:
                if args.debug_workspace:
                    stack.pop_all()
                    log_notice(f"Workspace: {workspace}")
                    workspace.chmod(0o755)

                raise


def build_image(args: Args, config: Config) -> None:
    manifest = Manifest(config) if config.manifest_format else None

    with setup_workspace(args, config) as workspace:
        context = Context(args, config, workspace)
        install_package_manager_trees(context)

        with mount_base_trees(context):
            install_base_trees(context)
            install_skeleton_trees(context)
            cached = reuse_cache(context)

            context.config.distribution.setup(context)

            if not cached:
                with mount_cache_overlay(context):
                    install_distribution(context)
                    run_prepare_scripts(context, build=False)
                    install_build_packages(context)
                    run_prepare_scripts(context, build=True)

                save_cache(context)
                reuse_cache(context)

            check_root_populated(context)
            run_build_scripts(context)

            if context.config.output_format == OutputFormat.none:
                # Touch an empty file to indicate the image was built.
                (context.staging / context.config.output).touch()
                finalize_staging(context)
                return

            install_build_dest(context)
            install_extra_trees(context)
            run_postinst_scripts(context)

            configure_autologin(context)
            configure_os_release(context)
            configure_initrd(context)
            configure_ssh(context)
            configure_clock(context)

            install_systemd_boot(context)
            install_shim(context)
            run_sysusers(context)
            run_preset(context)
            run_depmod(context)
            run_firstboot(context)
            run_hwdb(context)

            # These might be removed by the next steps,
            # so let's save them for later if needed.
            stub, kver, kimg = save_uki_components(context)

            remove_packages(context)

            if manifest:
                with complete_step("Recording packages in manifest…"):
                    manifest.record_packages(context.root)

            clean_package_manager_metadata(context)
            remove_files(context)
            run_selinux_relabel(context)
            run_finalize_scripts(context)

        normalize_mtime(context.root, context.config.source_date_epoch)
        partitions = make_disk(context, skip=("esp", "xbootldr"), msg="Generating disk image")
        install_uki(context, partitions)
        prepare_grub_efi(context)
        prepare_grub_bios(context, partitions)
        normalize_mtime(context.root, context.config.source_date_epoch, directory=Path("boot"))
        normalize_mtime(context.root, context.config.source_date_epoch, directory=Path("efi"))
        partitions = make_disk(context, msg="Formatting ESP/XBOOTLDR partitions")
        install_grub_bios(context, partitions)

        if context.config.split_artifacts:
            make_disk(context, split=True, msg="Extracting partitions")

        copy_vmlinuz(context)
        copy_initrd(context)

        if context.config.output_format == OutputFormat.tar:
            make_tar(context, context.root, context.staging / context.config.output_with_format)
        elif context.config.output_format == OutputFormat.cpio:
            make_cpio(context, context.root, context.staging / context.config.output_with_format)
        elif context.config.output_format == OutputFormat.uki:
            assert stub and kver and kimg
            make_uki(context, stub, kver, kimg, context.staging / context.config.output_with_format)
        elif context.config.output_format == OutputFormat.esp:
            assert stub and kver and kimg
            make_uki(context, stub, kver, kimg, context.staging / context.config.output_split_uki)
            make_esp(context, context.staging / context.config.output_split_uki)
        elif context.config.output_format.is_extension_image():
            make_extension_image(context, context.staging / context.config.output_with_format)
        elif context.config.output_format == OutputFormat.directory:
            context.root.rename(context.staging / context.config.output_with_format)

        if config.output_format not in (OutputFormat.uki, OutputFormat.esp):
            maybe_compress(context, context.config.compress_output,
                           context.staging / context.config.output_with_format,
                           context.staging / context.config.output_with_compression)

        calculate_sha256sum(context)
        calculate_signature(context)
        save_manifest(context, manifest)

        output_base = context.staging / context.config.output
        if not output_base.exists() or output_base.is_symlink():
            output_base.unlink(missing_ok=True)
            output_base.symlink_to(context.config.output_with_compression)

        finalize_staging(context)

    print_output_size(config.output_dir_or_cwd() / config.output)


def setfacl(root: Path, uid: int, allow: bool) -> None:
    run(["setfacl",
         "--physical",
         "--modify" if allow else "--remove",
         f"user:{uid}:rwx" if allow else f"user:{uid}",
         "-"],
         # Supply files via stdin so we don't clutter --debug run output too much
         input="\n".join([str(root), *(os.fspath(p) for p in root.rglob("*") if p.is_dir())]),
    )


@contextlib.contextmanager
def acl_maybe_toggle(config: Config, root: Path, uid: int, *, always: bool) -> Iterator[None]:
    if not config.acl:
        yield
        return

    # getfacl complains about absolute paths so make sure we pass a relative one.
    if root.exists():
        has_acl = f"user:{uid}:rwx" in run(["getfacl", "-n", root.relative_to(Path.cwd())],
                                           stdout=subprocess.PIPE).stdout

        if not has_acl and not always:
            yield
            return
    else:
        has_acl = False

    try:
        if has_acl:
            with complete_step(f"Removing ACLs from {root}"):
                setfacl(root, uid, allow=False)

        yield
    finally:
        if has_acl or always:
            with complete_step(f"Adding ACLs to {root}"):
                setfacl(root, uid, allow=True)


@contextlib.contextmanager
def acl_toggle_build(config: Config, uid: int) -> Iterator[None]:
    if not config.acl:
        yield
        return

    extras = [t.source for t in config.extra_trees]
    skeletons = [t.source for t in config.skeleton_trees]

    with contextlib.ExitStack() as stack:
        for p in (*config.base_trees, *extras, *skeletons):
            if p and p.is_dir():
                stack.enter_context(acl_maybe_toggle(config, p, uid, always=False))

        for p in (config.cache_dir, config.build_dir):
            if p:
                stack.enter_context(acl_maybe_toggle(config, p, uid, always=True))

        if config.output_format == OutputFormat.directory:
            stack.enter_context(acl_maybe_toggle(config, config.output_dir_or_cwd() / config.output, uid, always=True))

        yield


@contextlib.contextmanager
def acl_toggle_boot(config: Config, uid: int) -> Iterator[None]:
    if not config.acl or config.output_format != OutputFormat.directory:
        yield
        return

    with acl_maybe_toggle(config, config.output_dir_or_cwd() / config.output, uid, always=False):
        yield


def run_shell(args: Args, config: Config) -> None:
    cmdline: list[PathString] = ["systemd-nspawn", "--quiet"]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings:
        cmdline += ["--settings=trusted"]

    if args.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += [
            f"--rlimit=RLIMIT_CORE={format_rlimit(resource.RLIMIT_CORE)}",
            "--console=autopipe",
        ]

    # Underscores are not allowed in machine names so replace them with hyphens.
    name = config.name().replace("_", "-")
    cmdline += ["--machine", name]

    for k, v in config.credentials.items():
        cmdline += [f"--set-credential={k}:{v}"]

    with contextlib.ExitStack() as stack:
        if config.nspawn_settings:
            copy_tree(config.nspawn_settings, config.output_dir_or_cwd() / f"{name}.nspawn")
            stack.callback(lambda: rmtree(config.output_dir_or_cwd() / f"{name}.nspawn"))

        if config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = config.output_dir_or_cwd() / config.output

        if config.output_format == OutputFormat.disk and args.verb == Verb.boot:
            run(["systemd-repart",
                 "--image", fname,
                 *([f"--size={config.runtime_size}"] if config.runtime_size else []),
                 "--no-pager",
                 "--dry-run=no",
                 "--offline=no",
                 fname],
                 stdin=sys.stdin)

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]

            owner = os.stat(fname).st_uid
            if owner != 0:
                cmdline += [f"--private-users={str(owner)}"]
        else:
            cmdline += ["--image", fname]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or tree.source.name)
            # We add norbind because very often RuntimeTrees= will be used to mount the source directory into the
            # container and the output directory from which we're running will very likely be a subdirectory of the
            # source directory which would mean we'd be mounting the container root directory as a subdirectory in
            # itself which tends to lead to all kinds of weird issues, which we avoid by not doing a recursive mount
            # which means the container root directory mounts will be skipped.
            cmdline += ["--bind", f"{tree.source}:{target}:norbind,rootidmap"]

        if args.verb == Verb.boot:
            # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
            cmdline += args.cmdline
            # kernel cmdline config of the form systemd.xxx= get interpreted by systemd when running in nspawn as
            # well.
            cmdline += config.kernel_command_line
            cmdline += config.kernel_command_line_extra
        elif args.cmdline:
            cmdline += ["--"]
            cmdline += args.cmdline

        run(cmdline, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False)


def run_systemd_tool(tool: str, args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        die(f"{config.output_format} images cannot be inspected with {tool}")

    if (tool_path := find_binary(tool)) is None:
        die(f"Failed to find {tool}")

    if config.ephemeral:
        die(f"Images booted in ephemeral mode cannot be inspected with {tool}")

    image_arg_name = "root" if config.output_format == OutputFormat.directory else "image"
    run(
        [
            tool_path,
            f"--{image_arg_name}={config.output_dir_or_cwd() / config.output}",
            *args.cmdline
        ],
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ,
        log=False
    )


def run_journalctl(args: Args, config: Config) -> None:
    run_systemd_tool("journalctl", args, config)


def run_coredumpctl(args: Args, config: Config) -> None:
    run_systemd_tool("coredumpctl", args, config)


def run_serve(config: Config) -> None:
    """Serve the output directory via a tiny HTTP server"""

    port = "8081"

    with chdir(config.output_dir_or_cwd()):
        run([python_binary(config), "-m", "http.server", port],
            user=INVOKING_USER.uid, group=INVOKING_USER.gid, stdin=sys.stdin, stdout=sys.stdout)


def generate_key_cert_pair(args: Args) -> None:
    """Generate a private key and accompanying X509 certificate using openssl"""

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(args.genkey_valid_days))
    cn = expand_specifier(args.genkey_common_name)

    for f in ("mkosi.key", "mkosi.crt"):
        if Path(f).exists() and not args.force:
            die(f"{f} already exists",
                hint=("To generate new keys, first remove mkosi.key and mkosi.crt"))

    log_step(f"Generating keys rsa:{keylength} for CN {cn!r}.")
    logging.info(
        textwrap.dedent(
            f"""
            The keys will expire in {args.genkey_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey", f"rsa:{keylength}",
            "-keyout", "mkosi.key",
            "-out", "mkosi.crt",
            "-days", str(args.genkey_valid_days),
            "-subj", f"/CN={cn}/",
            "-nodes"
        ],
        env=dict(OPENSSL_CONF="/dev/null"),
    )


def bump_image_version() -> None:
    """Write current image version plus one to mkosi.version"""
    version = Path("mkosi.version").read_text().strip()
    v = version.split(".")

    try:
        m = int(v[-1])
    except ValueError:
        new_version = version + ".2"
        logging.info(
            "Last component of current version is not a decimal integer, "
            f"appending '.2', bumping '{version}' → '{new_version}'."
        )
    else:
        new_version = ".".join(v[:-1] + [str(m + 1)])
        logging.info(f"Increasing last component of version by one, bumping '{version}' → '{new_version}'.")

    Path("mkosi.version").write_text(f"{new_version}\n")
    os.chown("mkosi.version", INVOKING_USER.uid, INVOKING_USER.gid)


def show_docs(args: Args) -> None:
    if args.doc_format == DocFormat.auto:
        formats = [DocFormat.man, DocFormat.pandoc, DocFormat.markdown, DocFormat.system]
    else:
        formats = [args.doc_format]

    while formats:
        form = formats.pop(0)
        try:
            with resource_path(mkosi.resources) as r:
                if form == DocFormat.man:
                    man = r / "mkosi.1"
                    if not man.exists():
                        raise FileNotFoundError()
                    run(["man", "--local-file", man])
                    return
                elif form == DocFormat.pandoc:
                    if not shutil.which("pandoc"):
                        logging.error("pandoc is not available")
                    mdr = r / "mkosi.md"
                    pandoc = run(["pandoc", "-t", "man", "-s", mdr], stdout=subprocess.PIPE)
                    run(["man", "--local-file", "-"], input=pandoc.stdout)
                    return
                elif form == DocFormat.markdown:
                    md = (r / "mkosi.md").read_text()
                    page(md, args.pager)
                    return
                elif form == DocFormat.system:
                    run(["man", "mkosi"])
                    return
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            if not formats:
                if isinstance(e, FileNotFoundError):
                    die("The mkosi package does not contain the man page.")
                raise e


def expand_specifier(s: str) -> str:
    return s.replace("%u", INVOKING_USER.name())


def needs_build(args: Args, config: Config) -> bool:
    return (
        args.verb.needs_build() and
        (args.force > 0 or not (config.output_dir_or_cwd() / config.output_with_compression).exists())
    )


@contextlib.contextmanager
def prepend_to_environ_path(config: Config) -> Iterator[None]:
    if config.tools_tree or not config.extra_search_paths:
        yield
        return

    with tempfile.TemporaryDirectory(prefix="mkosi.path") as d:

        for path in config.extra_search_paths:
            if not path.is_dir():
                (Path(d) / path.name).symlink_to(path.absolute())

        news = [os.fspath(path) for path in [Path(d), *config.extra_search_paths] if path.is_dir()]
        olds = os.getenv("PATH", "").split(":")
        os.environ["PATH"] = ":".join(news + olds)

        try:
            yield
        finally:
            os.environ["PATH"] = ":".join(olds)


def finalize_tools(args: Args, images: Sequence[Config]) -> Sequence[Config]:
    new = []

    for config in images:
        if not config.tools_tree or config.tools_tree.name != "default":
            new.append(config)
            continue

        distribution = config.tools_tree_distribution or config.distribution.default_tools_tree_distribution()
        if not distribution:
            die(f"{config.distribution} does not have a default tools tree distribution",
                hint="use ToolsTreeDistribution= to set one explicitly")

        release = config.tools_tree_release or distribution.default_release()
        mirror = (
            config.tools_tree_mirror or
            (config.mirror if config.mirror and config.distribution == distribution else None)
        )

        cmdline = [
            "--directory", "",
            "--distribution", str(distribution),
            *(["--release", release] if release else []),
            *(["--mirror", mirror] if mirror else []),
            "--repository-key-check", str(config.repository_key_check),
            "--cache-only", str(config.cache_only),
            *(["--output-dir", str(config.output_dir)] if config.output_dir else []),
            *(["--workspace-dir", str(config.workspace_dir)] if config.workspace_dir else []),
            *(["--cache-dir", str(config.cache_dir)] if config.cache_dir else []),
            "--incremental", str(config.incremental),
            "--acl", str(config.acl),
            *([f"--package={package}" for package in config.tools_tree_packages]),
            "--output", f"{distribution}-tools",
            *(["--source-date-epoch", str(config.source_date_epoch)] if config.source_date_epoch is not None else []),
            *([f"--environment={k}='{v}'" for k, v in config.environment.items()]),
            *([f"--extra-search-path={p}" for p in config.extra_search_paths]),
            *(["-f"] * args.force),
        ]

        with resource_path(mkosi.resources) as r:
            _, [tools] = parse_config(cmdline + ["--include", os.fspath(r / "mkosi-tools"), "build"])

        tools = dataclasses.replace(tools, image=f"{distribution}-tools")

        if tools not in new:
            new.append(tools)

        new.append(dataclasses.replace(config, tools_tree=tools.output_dir_or_cwd() / tools.output))

    return new


def check_workspace_directory(config: Config) -> None:
    wd = config.workspace_dir_or_default()

    if wd.is_relative_to(Path.cwd()):
        die(f"The workspace directory ({wd}) cannot be located in the current working directory ({Path.cwd()})",
            hint="Use WorkspaceDirectory= to configure a different workspace directory")

    for tree in config.build_sources:
        if wd.is_relative_to(tree.source):
            die(f"The workspace directory ({wd}) cannot be a subdirectory of any source directory ({tree.source})",
                hint="Use WorkspaceDirectory= to configure a different workspace directory")


def run_verb(args: Args, images: Sequence[Config]) -> None:
    if args.verb.needs_root() and os.getuid() != 0:
        die(f"Must be root to run the {args.verb} command")

    if args.verb == Verb.documentation:
        return show_docs(args)

    if args.verb == Verb.genkey:
        return generate_key_cert_pair(args)

    if all(config == Config.default() for config in images):
        die("No configuration found",
            hint="Make sure you're running mkosi from a directory with configuration files")

    if args.verb == Verb.bump:
        return bump_image_version()

    if args.verb == Verb.summary:
        if args.json:
            text = json.dumps(
                {"Images": [config.to_dict() for config in images]},
                cls=JsonEncoder,
                indent=4,
                sort_keys=True
            )
        else:
            text = "\n".join(summary(config) for config in images)

        page(text, args.pager)
        return

    for config in images:
        if not config.minimum_version or config.minimum_version <= __version__:
            continue

        die(f"mkosi {config.minimum_version} or newer is required to build this configuration (found {__version__})")

    for config in images:
        if not config.repart_offline and os.getuid() != 0:
            die(f"Must be root to build {config.name()} image configured with RepartOffline=no")

    for config in images:
        check_workspace_directory(config)

    images = finalize_tools(args, images)
    last = images[-1]

    if args.verb in (Verb.shell, Verb.boot):
        opname = "acquire shell in" if args.verb == Verb.shell else "boot"
        if last.output_format in (OutputFormat.tar, OutputFormat.cpio):
            die(f"Sorry, can't {opname} a {last.output_format} archive.")
        if last.output_format.use_outer_compression() and last.compress_output:
            die(f"Sorry, can't {opname} a compressed image.")

    if (
        args.verb in (Verb.journalctl, Verb.coredumpctl)
        and last.output_format == OutputFormat.disk
        and os.getuid() != 0
    ):
        die(f"Must be root to run the {args.verb} command")

    for config in images:
        if args.verb == Verb.build and not args.force:
            check_outputs(config)

    # Because we overmount /usr when using a tools tree, we need to make sure we load all python modules we
    # might end up using before overmounting /usr. Any modules that might be dynamically loaded during
    # execution are forcibly loaded early here.
    try_import("importlib.readers")
    try_import("importlib.resources.readers")
    for config in images:
        try_import(f"mkosi.distributions.{config.distribution}")

    # After we unshare the user namespace, we might not have access to /dev/kvm or related device nodes anymore as
    # access to these might be gated behind the kvm group and we won't be part of the kvm group anymore after unsharing
    # the user namespace. To get around this, open all those device nodes now while we still can so we can pass them as
    # file descriptors to qemu later. Note that we can't pass the kvm file descriptor to qemu until
    # https://gitlab.com/qemu-project/qemu/-/issues/1936 is resolved.
    qemu_device_fds = {
        d: d.open()
        for d in QemuDeviceNode
        if args.verb == Verb.qemu and d.feature(last) != ConfigFeature.disabled and d.available(log=True)
    }

    # First, process all directory removals because otherwise if different images share directories a later
    # image build could end up deleting the output generated by an earlier image build.

    for config in images:
        if not needs_build(args, config) and args.verb != Verb.clean:
            continue

        def target() -> None:
            become_root()
            unlink_output(args, config)

        fork_and_wait(target)

    if args.verb == Verb.clean:
        return

    build = False

    for config in images:
        check_inputs(config)

        if not needs_build(args, config):
            continue

        def target() -> None:
            become_root()
            init_mount_namespace()

            # For extra safety when running as root, remount a bunch of stuff read-only.
            for d in ("/usr", "/etc", "/opt", "/srv", "/boot", "/efi", "/media", "/mnt"):
                if Path(d).exists():
                    run(["mount", "--rbind", d, d, "--options", "ro"])

            with (
                complete_step(f"Building {config.name()} image"),
                mount_usr(config.tools_tree),
                prepend_to_environ_path(config),
            ):
                # After tools have been mounted, check if we have what we need
                check_tools(Verb.build, config)

                # Create these as the invoking user to make sure they're owned by the user running mkosi.
                for p in (
                    config.output_dir,
                    config.cache_dir,
                    config.build_dir,
                    config.workspace_dir,
                ):
                    if p:
                        run(["mkdir", "--parents", p], user=INVOKING_USER.uid, group=INVOKING_USER.gid)

                with acl_toggle_build(config, INVOKING_USER.uid):
                    build_image(args, config)

        fork_and_wait(target)

        build = True

    if build and args.auto_bump:
        bump_image_version()

    if args.verb == Verb.build:
        return

    if last.tools_tree and args.verb != Verb.ssh:
        become_root()

    with contextlib.ExitStack() as stack:
        if os.getuid() == 0 and args.verb != Verb.ssh:
            init_mount_namespace()
            stack.enter_context(mount_usr(last.tools_tree, umount=False))

        stack.enter_context(prepend_to_environ_path(last))

        check_tools(args.verb, last)

        with prepend_to_environ_path(last):
            if args.verb in (Verb.shell, Verb.boot):
                with acl_toggle_boot(last, INVOKING_USER.uid):
                    run_shell(args, last)

            if args.verb == Verb.qemu:
                run_qemu(args, last, qemu_device_fds)

            if args.verb == Verb.ssh:
                run_ssh(args, last)

            if args.verb == Verb.serve:
                run_serve(last)

            if args.verb == Verb.journalctl:
                run_journalctl(args, last)

            if args.verb == Verb.coredumpctl:
                run_coredumpctl(args, last)

            if args.verb == Verb.burn:
                run_burn(args, last)
