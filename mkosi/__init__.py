# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import dataclasses
import datetime
import hashlib
import importlib.resources
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
from typing import Optional, TextIO, Union

from mkosi.archive import extract_tar, make_cpio, make_tar
from mkosi.config import (
    BiosBootloader,
    Bootloader,
    Compression,
    ConfigFeature,
    DocFormat,
    ManifestFormat,
    MkosiArgs,
    MkosiConfig,
    MkosiJsonEncoder,
    OutputFormat,
    SecureBootSignTool,
    Verb,
    format_bytes,
    format_source_target,
    parse_config,
    summary,
)
from mkosi.distributions import Distribution
from mkosi.installer import clean_package_manager_metadata, package_manager_scripts
from mkosi.kmod import gen_required_kernel_modules, process_kernel_modules
from mkosi.log import ARG_DEBUG, complete_step, die, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import mount, mount_overlay, mount_passwd, mount_usr
from mkosi.pager import page
from mkosi.partition import Partition, finalize_root, finalize_roothash
from mkosi.qemu import QemuDeviceNode, copy_ephemeral, run_qemu, run_ssh
from mkosi.run import (
    become_root,
    bwrap,
    chroot_cmd,
    find_binary,
    init_mount_namespace,
    run,
)
from mkosi.state import MkosiState
from mkosi.tree import copy_tree, install_tree, move_tree, rmtree
from mkosi.types import _FILE, CompletedProcess, PathString
from mkosi.util import (
    INVOKING_USER,
    chdir,
    flatten,
    format_rlimit,
    make_executable,
    one_zero,
    scopedenv,
    try_import,
    umask,
)
from mkosi.versioncomp import GenericVersion

MINIMUM_SYSTEMD_VERSION = GenericVersion("254")


@contextlib.contextmanager
def mount_base_trees(state: MkosiState) -> Iterator[None]:
    if not state.config.base_trees or not state.config.overlay:
        yield
        return

    with complete_step("Mounting base trees…"), contextlib.ExitStack() as stack:
        bases = []
        (state.workspace / "bases").mkdir(exist_ok=True)

        for path in state.config.base_trees:
            d = state.workspace / f"bases/{path.name}-{uuid.uuid4().hex}"

            if path.is_dir():
                bases += [path]
            elif path.suffix == ".tar":
                extract_tar(path, d)
                bases += [d]
            elif path.suffix == ".raw":
                run(["systemd-dissect", "-M", path, d])
                stack.callback(lambda: run(["systemd-dissect", "-U", d]))
                bases += [d]
            else:
                die(f"Unsupported base tree source {path}")

        stack.enter_context(mount_overlay(bases, state.root, state.root))

        yield


def remove_files(state: MkosiState) -> None:
    """Remove files based on user-specified patterns"""

    if not state.config.remove_files:
        return

    with complete_step("Removing files…"):
        for pattern in state.config.remove_files:
            for p in state.root.glob(pattern.lstrip("/")):
                rmtree(p)


def install_distribution(state: MkosiState) -> None:
    if state.config.base_trees:
        if not state.config.packages:
            return

        with complete_step(f"Installing extra packages for {str(state.config.distribution).capitalize()}"):
            state.config.distribution.install_packages(state, state.config.packages)
    else:
        with complete_step(f"Installing {str(state.config.distribution).capitalize()}"):
            state.config.distribution.install(state)

            if not (state.root / "etc/machine-id").exists():
                # Uninitialized means we want it to get initialized on first boot.
                with umask(~0o444):
                    (state.root / "etc/machine-id").write_text("uninitialized\n")

            # Ensure /efi exists so that the ESP is mounted there, as recommended by
            # https://0pointer.net/blog/linux-boot-partitions.html. Use the most restrictive access mode we
            # can without tripping up mkfs tools since this directory is only meant to be overmounted and
            # should not be read from or written to.
            with umask(~0o500):
                (state.root / "efi").mkdir(exist_ok=True)

            # Some distributions install EFI binaries directly to /boot/efi. Let's redirect them to /efi
            # instead.
            rmtree(state.root / "boot/efi")
            (state.root / "boot").mkdir(exist_ok=True)
            (state.root / "boot/efi").symlink_to("../efi")

            if state.config.packages:
                state.config.distribution.install_packages(state, state.config.packages)

    for f in ("var/lib/systemd/random-seed",
              "var/lib/systemd/credential.secret",
              "etc/machine-info",
              "var/lib/dbus/machine-id"):
        # Using missing_ok=True still causes an OSError if the mount is read-only even if the
        # file doesn't exist so do an explicit exists() check first.
        if (state.root / f).exists():
            (state.root / f).unlink()


def install_build_packages(state: MkosiState) -> None:
    if not state.config.build_scripts or not state.config.build_packages:
        return

    # TODO: move to parenthesised context managers once on 3.10
    pd = str(state.config.distribution).capitalize()
    with complete_step(f"Installing build packages for {pd}"), mount_build_overlay(state):
        state.config.distribution.install_packages(state, state.config.build_packages)


def remove_packages(state: MkosiState) -> None:
    """Remove packages listed in config.remove_packages"""

    if not state.config.remove_packages:
        return

    with complete_step(f"Removing {len(state.config.packages)} packages…"):
        try:
            state.config.distribution.remove_packages(state, state.config.remove_packages)
        except NotImplementedError:
            die(f"Removing packages is not supported for {state.config.distribution}")


def check_root_populated(state: MkosiState) -> None:
    """Check that the root was populated by looking for a os-release file."""
    osrelease = state.root / "usr/lib/os-release"
    if not osrelease.exists():
        die(
            f"{osrelease} not found.",
            hint=(
                "The root must be populated by the distribution, or from base trees, "
                "skeleton trees, and prepare scripts."
            )
        )


def configure_os_release(state: MkosiState) -> None:
    """Write IMAGE_ID and IMAGE_VERSION to /usr/lib/os-release in the image."""
    if not state.config.image_id and not state.config.image_version:
        return

    for candidate in ["usr/lib/os-release", "etc/os-release", "usr/lib/initrd-release", "etc/initrd-release"]:
        osrelease = state.root / candidate
        # at this point we know we will either change or add to the file
        newosrelease = osrelease.with_suffix(".new")

        if not osrelease.is_file() or osrelease.is_symlink():
            continue

        image_id_written = image_version_written = False
        with osrelease.open("r") as old, newosrelease.open("w") as new:
            # fix existing values
            for line in old.readlines():
                if state.config.image_id and line.startswith("IMAGE_ID="):
                    new.write(f'IMAGE_ID="{state.config.image_id}"\n')
                    image_id_written = True
                elif state.config.image_version and line.startswith("IMAGE_VERSION="):
                    new.write(f'IMAGE_VERSION="{state.config.image_version}"\n')
                    image_version_written = True
                else:
                    new.write(line)

            # append if they were missing
            if state.config.image_id and not image_id_written:
                new.write(f'IMAGE_ID="{state.config.image_id}"\n')
            if state.config.image_version and not image_version_written:
                new.write(f'IMAGE_VERSION="{state.config.image_version}"\n')

        newosrelease.rename(osrelease)


def configure_autologin(state: MkosiState) -> None:
    if not state.config.autologin:
        return

    with complete_step("Setting up autologin…"):
        dropin = state.root / "usr/lib/systemd/system/console-getty.service.d/autologin.conf"
        with umask(~0o755):
            dropin.parent.mkdir(parents=True, exist_ok=True)
        with umask(~0o644):
            dropin.write_text(
                """\
                [Service]
                ExecStart=
                ExecStart=-/sbin/agetty -o '-f -p -- \\\\u' --autologin root --noclear --keep-baud console 115200,38400,9600 $TERM
                StandardInput=tty
                StandardOutput=tty
                """  # noqa: E501
            )

        dropin = state.root / "usr/lib/systemd/system/getty@tty1.service.d/autologin.conf"
        with umask(~0o755):
            dropin.parent.mkdir(parents=True, exist_ok=True)
        with umask(~0o644):
            dropin.write_text(
                """\
                [Service]
                ExecStart=
                ExecStart=-/sbin/agetty -o '-f -p -- \\\\u' --autologin root --noclear - $TERM
                StandardInput=tty
                StandardOutput=tty
                """
            )

        dropin = state.root / "usr/lib/systemd/system/serial-getty@ttyS0.service.d/autologin.conf"
        with umask(~0o755):
            dropin.parent.mkdir(parents=True, exist_ok=True)
        with umask(~0o644):
            dropin.write_text(
                """\
                [Service]
                ExecStart=
                ExecStart=-/sbin/agetty -o '-f -p -- \\\\u' --autologin root --keep-baud 115200,57600,38400,9600 - $TERM
                StandardInput=tty
                StandardOutput=tty
                """  # noqa: E501
            )


@contextlib.contextmanager
def mount_cache_overlay(state: MkosiState) -> Iterator[None]:
    if not state.config.incremental or not any(state.root.iterdir()):
        yield
        return

    d = state.workspace / "cache-overlay"
    with umask(~0o755):
        d.mkdir(exist_ok=True)

    with mount_overlay([state.root], d, state.root):
        yield


def mount_build_overlay(state: MkosiState) -> contextlib.AbstractContextManager[Path]:
    d = state.workspace / "build-overlay"
    if not d.is_symlink():
        with umask(~0o755):
            d.mkdir(exist_ok=True)
    return mount_overlay([state.root], state.workspace / "build-overlay", state.root)


@contextlib.contextmanager
def mount_volatile_overlay(state: MkosiState) -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as d:
        Path(d).chmod(0o755)

        with mount_overlay([state.root], Path(d), state.root) as p:
            yield p


def finalize_mounts(config: MkosiConfig) -> list[PathString]:
    sources = [
        (src, Path.cwd() / (str(target).lstrip("/") if target else "."))
        for src, target
        in ((Path.cwd(), None), *config.build_sources)
    ]

    # bwrap() mounts /home and /var read-only during execution. So let's add the bind mount options for the
    # directories that could be in /home or /var that we do need to be writable.
    sources += [(d, d) for d in (config.workspace_dir, config.cache_dir, config.output_dir, config.build_dir) if d]

    return flatten(["--bind", src, target] for src, target in sorted(set(sources), key=lambda s: s[1]))


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
                    exec {shlex.join(str(s) for s in script)} "$@"
                    """
                )
            )

            make_executable(Path(d) / name)

        yield Path(d)


def finalize_host_scripts(state: MkosiState, chroot: Sequence[PathString]) -> contextlib.AbstractContextManager[Path]:
    git = {"git": ("git", "-c", "safe.directory=*")} if find_binary("git") else {}
    return finalize_scripts(git | {"mkosi-chroot": chroot} | package_manager_scripts(state))


def finalize_chroot_scripts(state: MkosiState) -> contextlib.AbstractContextManager[Path]:
    git = {"git": ("git", "-c", "safe.directory=*")} if find_binary("git", state.root) else {}
    return finalize_scripts(git)


def run_prepare_scripts(state: MkosiState, build: bool) -> None:
    if not state.config.prepare_scripts:
        return
    if build and not state.config.build_scripts:
        return

    env = dict(
        BUILDROOT=str(state.root),
        CHROOT_SCRIPT="/work/prepare",
        CHROOT_SRCDIR="/work/src",
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_UID=str(INVOKING_USER.uid),
        SCRIPT="/work/prepare",
        SRCDIR=str(Path.cwd()),
        WITH_DOCS=one_zero(state.config.with_docs),
        WITH_NETWORK=one_zero(state.config.with_network),
        WITH_TESTS=one_zero(state.config.with_tests),
    )

    with contextlib.ExitStack() as stack:
        if build:
            stack.enter_context(mount_build_overlay(state))
            step_msg = "Running prepare script {} in build overlay…"
            arg = "build"
        else:
            step_msg = "Running prepare script {}…"
            arg = "final"

        d = stack.enter_context(finalize_chroot_scripts(state))

        for script in state.config.prepare_scripts:
            chroot: list[PathString] = chroot_cmd(
                state.root,
                options=[
                    "--bind", script, "/work/prepare",
                    "--bind", Path.cwd(), "/work/src",
                    "--bind", d, "/work/scripts",
                    "--chdir", "/work/src",
                    "--setenv", "SRCDIR", "/work/src",
                    "--setenv", "BUILDROOT", "/",
                ],
            )

            d = stack.enter_context(finalize_host_scripts(state, chroot))

            with complete_step(step_msg.format(script)):
                bwrap(
                    script_maybe_chroot(script, "/work/prepare") + [arg],
                    network=True,
                    readonly=True,
                    options=finalize_mounts(state.config),
                    scripts=d,
                    env=env | state.config.environment,
                    stdin=sys.stdin,
                )


def run_build_scripts(state: MkosiState) -> None:
    if not state.config.build_scripts:
        return

    env = dict(
        BUILDROOT=str(state.root),
        CHROOT_DESTDIR="/work/dest",
        CHROOT_OUTPUTDIR="/work/out",
        CHROOT_SCRIPT="/work/build-script",
        CHROOT_SRCDIR="/work/src",
        DESTDIR=str(state.install_dir),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_UID=str(INVOKING_USER.uid),
        OUTPUTDIR=str(state.staging),
        SCRIPT="/work/build-script",
        SRCDIR=str(Path.cwd()),
        WITH_DOCS=one_zero(state.config.with_docs),
        WITH_NETWORK=one_zero(state.config.with_network),
        WITH_TESTS=one_zero(state.config.with_tests),
    )

    if state.config.build_dir is not None:
        env |= dict(
            BUILDDIR=str(state.config.build_dir),
            CHROOT_BUILDDIR="/work/build",
        )

    with (
        mount_build_overlay(state),\
        mount_passwd(state.root),\
        mount_volatile_overlay(state),\
        finalize_chroot_scripts(state) as d\
    ):
        for script in state.config.build_scripts:
            chroot = chroot_cmd(
                state.root,
                options=[
                    "--bind", script, "/work/build-script",
                    "--bind", state.install_dir, "/work/dest",
                    "--bind", state.staging, "/work/out",
                    "--bind", Path.cwd(), "/work/src",
                    "--bind", d, "/work/scripts",
                    *(["--bind", str(state.config.build_dir), "/work/build"] if state.config.build_dir else []),
                    "--chdir", "/work/src",
                    "--setenv", "SRCDIR", "/work/src",
                    "--setenv", "DESTDIR", "/work/dest",
                    "--setenv", "OUTPUTDIR", "/work/out",
                    "--setenv", "BUILDROOT", "/",
                    *(["--setenv", "BUILDDIR", "/work/build"] if state.config.build_dir else []),
                ],
            )

            cmdline = state.args.cmdline if state.args.verb == Verb.build else []

            with (
                finalize_host_scripts(state, chroot) as d,\
                complete_step(f"Running build script {script}…")\
            ):
                bwrap(
                    script_maybe_chroot(script, "/work/build-script") + cmdline,
                    network=state.config.with_network,
                    readonly=True,
                    options=finalize_mounts(state.config),
                    scripts=d,
                    env=env | state.config.environment,
                    stdin=sys.stdin,
                )


def run_postinst_scripts(state: MkosiState) -> None:
    if not state.config.postinst_scripts:
        return

    env = dict(
        BUILDROOT=str(state.root),
        CHROOT_OUTPUTDIR="/work/out",
        CHROOT_SCRIPT="/work/postinst",
        CHROOT_SRCDIR="/work/src",
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_UID=str(INVOKING_USER.uid),
        OUTPUTDIR=str(state.staging),
        SCRIPT="/work/postinst",
        SRCDIR=str(Path.cwd()),
    )

    for script in state.config.postinst_scripts:
        with finalize_chroot_scripts(state) as d:
            chroot = chroot_cmd(
                state.root,
                options=[
                    "--bind", script, "/work/postinst",
                    "--bind", state.staging, "/work/out",
                    "--bind", Path.cwd(), "/work/src",
                    "--bind", d, "/work/scripts",
                    "--chdir", "/work/src",
                    "--setenv", "SRCDIR", "/work/src",
                    "--setenv", "OUTPUTDIR", "/work/out",
                    "--setenv", "BUILDROOT", "/",
                ],
            )

            with (
                finalize_host_scripts(state, chroot) as d,\
                complete_step(f"Running postinstall script {script}…")\
            ):
                bwrap(
                    script_maybe_chroot(script, "/work/postinst") + ["final"],
                    network=state.config.with_network,
                    readonly=True,
                    options=finalize_mounts(state.config),
                    scripts=d,
                    env=env | state.config.environment,
                    stdin=sys.stdin,
                )


def run_finalize_scripts(state: MkosiState) -> None:
    if not state.config.finalize_scripts:
        return

    env = dict(
        BUILDROOT=str(state.root),
        CHROOT_OUTPUTDIR="/work/out",
        CHROOT_SCRIPT="/work/finalize",
        CHROOT_SRCDIR="/work/src",
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_UID=str(INVOKING_USER.uid),
        OUTPUTDIR=str(state.staging),
        SCRIPT="/work/finalize",
        SRCDIR=str(Path.cwd()),
    )

    for script in state.config.finalize_scripts:
        with finalize_chroot_scripts(state) as d:
            chroot = chroot_cmd(
                state.root,
                options=[
                    "--bind", script, "/work/finalize",
                    "--bind", state.staging, "/work/out",
                    "--bind", Path.cwd(), "/work/src",
                    "--bind", d, "/work/scripts",
                    "--chdir", "/work/src",
                    "--setenv", "SRCDIR", "/work/src",
                    "--setenv", "OUTPUTDIR", "/work/out",
                    "--setenv", "BUILDROOT", "/",
                ],
            )

            with (
                finalize_host_scripts(state, chroot) as d,\
                complete_step(f"Running finalize script {script}…")\
            ):
                bwrap(
                    script_maybe_chroot(script, "/work/finalize"),
                    network=state.config.with_network,
                    readonly=True,
                    options=finalize_mounts(state.config),
                    scripts=d,
                    env=env | state.config.environment,
                    stdin=sys.stdin,
                )


def run_openssl(args: Sequence[PathString], stdout: _FILE = None) -> CompletedProcess:
    with tempfile.NamedTemporaryFile(prefix="mkosi-openssl.cnf") as config:
        return run(["openssl", *args], stdout=stdout, env=dict(OPENSSL_CONF=config.name))


def certificate_common_name(certificate: Path) -> str:
    output = run_openssl([
        "x509",
        "-noout",
        "-subject",
        "-nameopt", "multiline",
        "-in", certificate,
    ], stdout=subprocess.PIPE).stdout

    for line in output.splitlines():
        if not line.strip().startswith("commonName"):
            continue

        _, sep, value = line.partition("=")
        if not sep:
            die("Missing '=' delimiter in openssl output")

        return value.strip()

    die(f"Certificate {certificate} is missing Common Name")


def pesign_prepare(state: MkosiState) -> None:
    assert state.config.secure_boot_key
    assert state.config.secure_boot_certificate

    if (state.workspace / "pesign").exists():
        return

    (state.workspace / "pesign").mkdir()

    # pesign takes a certificate directory and a certificate common name as input arguments, so we have
    # to transform our input key and cert into that format. Adapted from
    # https://www.mankier.com/1/pesign#Examples-Signing_with_the_certificate_and_private_key_in_individual_files
    run(["openssl",
         "pkcs12",
         "-export",
         # Arcane incantation to create a pkcs12 certificate without a password.
         "-keypbe", "NONE",
         "-certpbe", "NONE",
         "-nomaciter",
         "-passout", "pass:",
         "-out", state.workspace / "secure-boot.p12",
         "-inkey", state.config.secure_boot_key,
         "-in", state.config.secure_boot_certificate])

    run(["pk12util",
         "-K", "",
         "-W", "",
         "-i", state.workspace / "secure-boot.p12",
         "-d", state.workspace / "pesign"])


def install_systemd_boot(state: MkosiState) -> None:
    if state.config.bootable == ConfigFeature.disabled:
        return

    if state.config.bootloader != Bootloader.systemd_boot:
        return

    if state.config.output_format == OutputFormat.cpio and state.config.bootable == ConfigFeature.auto:
        return

    if state.config.architecture.to_efi() is None and state.config.bootable == ConfigFeature.auto:
        return

    if not any(gen_kernel_images(state)) and state.config.bootable == ConfigFeature.auto:
        return

    if not shutil.which("bootctl"):
        if state.config.bootable == ConfigFeature.enabled:
            die("An EFI bootable image with systemd-boot was requested but bootctl was not found")
        return

    directory = state.root / "usr/lib/systemd/boot/efi"
    if not directory.exists() or not any(directory.iterdir()):
        if state.config.bootable == ConfigFeature.enabled:
            die("A EFI bootable image with systemd-boot was requested but systemd-boot was not found at "
                f"{directory.relative_to(state.root)}")
        return

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        with complete_step("Signing systemd-boot binaries…"):
            for input in itertools.chain(directory.glob('*.efi'), directory.glob('*.EFI')):
                output = directory / f"{input}.signed"

                if (state.config.secure_boot_sign_tool == SecureBootSignTool.sbsign or
                    state.config.secure_boot_sign_tool == SecureBootSignTool.auto and
                    shutil.which("sbsign") is not None):
                    run(["sbsign",
                         "--key", state.config.secure_boot_key,
                         "--cert", state.config.secure_boot_certificate,
                         "--output", output,
                         input])
                elif (state.config.secure_boot_sign_tool == SecureBootSignTool.pesign or
                      state.config.secure_boot_sign_tool == SecureBootSignTool.auto and
                      shutil.which("pesign") is not None):
                    pesign_prepare(state)
                    run(["pesign",
                         "--certdir", state.workspace / "pesign",
                         "--certificate", certificate_common_name(state.config.secure_boot_certificate),
                         "--sign",
                         "--force",
                         "--in", input,
                         "--out", output])
                else:
                    die("One of sbsign or pesign is required to use SecureBoot=")

    with complete_step("Installing boot loader…"):
        run(["bootctl", "install", "--root", state.root, "--all-architectures", "--no-variables"],
            env={"SYSTEMD_ESP_PATH": "/efi"})

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        with complete_step("Setting up secure boot auto-enrollment…"):
            keys = state.root / "efi/loader/keys/auto"
            with umask(~0o700):
                keys.mkdir(parents=True, exist_ok=True)

            # sbsiglist expects a DER certificate.
            run_openssl(["x509",
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


def find_grub_bios_directory(state: MkosiState) -> Optional[Path]:
    for d in ("usr/lib/grub/i386-pc", "usr/share/grub2/i386-pc"):
        if (p := state.root / d).exists() and any(p.iterdir()):
            return p

    return None


def find_grub_binary(state: MkosiState, binary: str) -> Optional[Path]:
    assert "grub" in binary and "grub2" not in binary
    return find_binary(binary, state.root) or find_binary(binary.replace("grub", "grub2"), state.root)


def find_grub_prefix(state: MkosiState) -> Optional[str]:
    path = find_grub_binary(state, "grub-mkimage")
    if path is None:
        return None

    return "grub2" if "grub2" in os.fspath(path) else "grub"


def want_grub_efi(state: MkosiState) -> bool:
    if state.config.bootable == ConfigFeature.disabled:
        return False

    if state.config.bootloader != Bootloader.grub:
        return False

    if not any((state.root / "efi").rglob("grub*.efi")):
        if state.config.bootable == ConfigFeature.enabled:
            die("A bootable EFI image with grub was requested but grub for EFI is not installed in /efi")

        return False

    return True


def want_grub_bios(state: MkosiState, partitions: Sequence[Partition] = ()) -> bool:
    if state.config.bootable == ConfigFeature.disabled:
        return False

    if state.config.output_format != OutputFormat.disk:
        return False

    if state.config.bios_bootloader != BiosBootloader.grub:
        return False

    have = find_grub_bios_directory(state) is not None
    if not have and state.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but grub for BIOS is not installed")

    bios = any(p.type == Partition.GRUB_BOOT_PARTITION_UUID for p in partitions)
    if partitions and not bios and state.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no BIOS Boot Partition was configured")

    esp = any(p.type == "esp" for p in partitions)
    if partitions and not esp and state.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no ESP partition was configured")

    root = any(p.type.startswith("root") or p.type.startswith("usr") for p in partitions)
    if partitions and not root and state.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no root or usr partition was configured")

    installed = True

    for binary in ("grub-mkimage", "grub-bios-setup"):
        path = find_grub_binary(state, binary)
        if path is not None:
            continue

        if state.config.bootable == ConfigFeature.enabled:
            die(f"A BIOS bootable image with grub was requested but {binary} was not found")

        installed = False

    return (have and bios and esp and root and installed) if partitions else have


def prepare_grub_config(state: MkosiState) -> Optional[Path]:
    prefix = find_grub_prefix(state)
    if not prefix:
        return None

    config = state.root / "efi" / prefix / "grub.cfg"
    with umask(~0o700):
        config.parent.mkdir(exist_ok=True)

    # For some unknown reason, if we don't set the timeout to zero, grub never leaves its menu, so we default
    # to a zero timeout, but only if the config file hasn't been provided by the user.
    if not config.exists():
        with umask(~0o600), config.open("w") as f:
            f.write("set timeout=0\n")

    # Signed EFI grub shipped by distributions reads its configuration from /EFI/<distribution>/grub.cfg in
    # the ESP so let's put a shim there to redirect to the actual configuration file.
    efi = state.root / "efi/EFI" / state.config.distribution.name / "grub.cfg"
    with umask(~0o700):
        efi.parent.mkdir(parents=True, exist_ok=True)

    # Read the actual config file from the root of the ESP.
    efi.write_text(f"configfile /{prefix}/grub.cfg\n")

    return config


def prepare_grub_efi(state: MkosiState) -> None:
    if not want_grub_efi(state):
        return

    config = prepare_grub_config(state)
    assert config

    with config.open("a") as f:
        f.write('if [ "${grub_platform}" == "efi" ]; then\n')

        for uki in (state.root / "efi/EFI/Linux").glob("*.efi"):
            f.write(
                textwrap.dedent(
                    f"""\
                    menuentry "{uki.stem}" {{
                        chainloader /{uki.relative_to(state.root / "efi")}
                    }}
                    """
                )
            )

        f.write("fi\n")


def prepare_grub_bios(state: MkosiState, partitions: Sequence[Partition]) -> None:
    if not want_grub_bios(state, partitions):
        return

    config = prepare_grub_config(state)
    assert config

    root = finalize_root(partitions)
    assert root

    dst = state.root / "efi" / state.config.distribution.name
    with umask(~0o700):
        dst.mkdir(exist_ok=True)

    with config.open("a") as f:
        f.write('if [ "${grub_platform}" == "pc" ]; then\n')

        for kver, kimg in gen_kernel_images(state):
            kdst = dst / kver
            with umask(~0o700):
                kdst.mkdir(exist_ok=True)

            kmods = build_kernel_modules_initrd(state, kver)

            with umask(~0o600):
                kimg = Path(shutil.copy2(state.root / kimg, kdst / "vmlinuz"))
                initrds = [
                    Path(shutil.copy2(initrd, dst / initrd.name))
                    for initrd in (state.config.initrds or [build_initrd(state)])
                ]
                kmods = Path(shutil.copy2(kmods, kdst / "kmods"))

                distribution = state.config.distribution
                image = Path("/") / kimg.relative_to(state.root / "efi")
                cmdline = " ".join(state.config.kernel_command_line)
                initrds = " ".join(
                    [os.fspath(Path("/") / initrd.relative_to(state.root / "efi")) for initrd in initrds]
                )
                kmods = Path("/") / kmods.relative_to(state.root / "efi")

                f.write(
                    textwrap.dedent(
                        f"""\
                        menuentry "{distribution}-{kver}" {{
                            linux {image} {root} {cmdline}
                            initrd {initrds} {kmods}
                        }}
                        """
                    )
                )

        f.write('fi\n')

    # grub-install insists on opening the root partition device to probe it's filesystem which requires root
    # so we're forced to reimplement its functionality. Luckily that's pretty simple, run grub-mkimage to
    # generate the required core.img and copy the relevant files to the ESP.

    mkimage = find_grub_binary(state, "grub-mkimage")
    assert mkimage

    directory = find_grub_bios_directory(state)
    assert directory

    prefix = find_grub_prefix(state)
    assert prefix

    esp = next(p for p in partitions if p.type == "esp")

    dst = state.root / "efi" / prefix / "i386-pc"
    dst.mkdir(parents=True, exist_ok=True)

    bwrap([mkimage,
           "--directory", directory,
           # What we really want to do is use grub's search utility in an embedded config file to search for
           # the ESP by its type UUID. Unfortunately, grub's search command only supports searching by
           # filesystem UUID and filesystem label, which don't work for us. So for now, we hardcode the
           # partition number of the ESP, but only very recent systemd-repart will output that information,
           # so if we're using older systemd-repart, we assume the ESP is the first partition.
           "--prefix", f"(hd0,gpt{esp.partno + 1 if esp.partno is not None else 1})/{prefix}",
           "--output", dst / "core.img",
           "--format", "i386-pc",
           *(["--verbose"] if ARG_DEBUG.get() else []),
           # Modules required to find and read from the ESP which has all the other modules.
           "fat",
           "part_gpt",
           "biosdisk"],
          options=["--bind", state.root / "usr", "/usr"])

    for p in directory.glob("*.mod"):
        shutil.copy2(p, dst)

    for p in directory.glob("*.lst"):
        shutil.copy2(p, dst)

    shutil.copy2(directory / "modinfo.sh", dst)
    shutil.copy2(directory / "boot.img", dst)

    dst = state.root / "efi" / prefix / "fonts"
    dst.mkdir()

    for prefix in ("grub", "grub2"):
        unicode = state.root / "usr/share" / prefix / "unicode.pf2"
        if unicode.exists():
            shutil.copy2(unicode, dst)


def install_grub_bios(state: MkosiState, partitions: Sequence[Partition]) -> None:
    if not want_grub_bios(state, partitions):
        return

    setup = find_grub_binary(state, "grub-bios-setup")
    assert setup

    prefix = find_grub_prefix(state)
    assert prefix

    # grub-bios-setup insists on being able to open the root device that --directory is located on, which
    # needs root privileges. However, it only uses the root device when it is unable to embed itself in the
    # bios boot partition. To make installation work unprivileged, we trick grub to think that the root
    # device is our image by mounting over its /proc/self/mountinfo file (where it gets its information from)
    # with our own file correlating the root directory to our image file.
    mountinfo = state.workspace / "mountinfo"
    mountinfo.write_text(f"1 0 1:1 / / - fat {state.staging / state.config.output_with_format}\n")

    with complete_step("Installing grub boot loader…"):
        # We don't setup the mountinfo bind mount with bwrap because we need to know the child process pid to
        # be able to do the mount and we don't know the pid beforehand.
        bwrap(["sh", "-c", f"mount --bind {mountinfo} /proc/$$/mountinfo && exec $0 \"$@\"",
               setup,
               "--directory", state.root / "efi" / prefix / "i386-pc",
               *(["--verbose"] if ARG_DEBUG.get() else []),
               state.staging / state.config.output_with_format],
              options=["--bind", state.root / "usr", "/usr"])


def install_base_trees(state: MkosiState) -> None:
    if not state.config.base_trees or state.config.overlay:
        return

    with complete_step("Copying in base trees…"):
        for path in state.config.base_trees:
            install_tree(state.config, path, state.root)


def install_skeleton_trees(state: MkosiState) -> None:
    if not state.config.skeleton_trees:
        return

    with complete_step("Copying in skeleton file trees…"):
        for source, target in state.config.skeleton_trees:
            install_tree(state.config, source, state.root, target)


def install_package_manager_trees(state: MkosiState) -> None:
    if not state.config.package_manager_trees:
        return

    with complete_step("Copying in package manager file trees…"):
        for source, target in state.config.package_manager_trees:
            install_tree(state.config, source, state.workspace / "pkgmngr", target)


def install_extra_trees(state: MkosiState) -> None:
    if not state.config.extra_trees:
        return

    with complete_step("Copying in extra file trees…"):
        for source, target in state.config.extra_trees:
            install_tree(state.config, source, state.root, target)


def install_build_dest(state: MkosiState) -> None:
    if not any(state.install_dir.iterdir()):
        return

    with complete_step("Copying in build tree…"):
        copy_tree(state.config, state.install_dir, state.root)


def gzip_binary() -> str:
    return "pigz" if shutil.which("pigz") else "gzip"


def gen_kernel_images(state: MkosiState) -> Iterator[tuple[str, Path]]:
    if not (state.root / "usr/lib/modules").exists():
        return

    for kver in sorted(
        (k for k in (state.root / "usr/lib/modules").iterdir() if k.is_dir()),
        key=lambda k: GenericVersion(k.name),
        reverse=True
    ):
        if not (kver / "vmlinuz").exists():
            continue

        yield kver.name, Path("usr/lib/modules") / kver.name / "vmlinuz"


def build_initrd(state: MkosiState) -> Path:
    if state.config.distribution == Distribution.custom:
        die("Building a default initrd is not supported for custom distributions")

    # Default values are assigned via the parser so we go via the argument parser to construct
    # the config for the initrd.

    password, hashed = state.config.root_password or (None, False)
    if password:
        rootpwopt = f"hashed:{password}" if hashed else password
    else:
        rootpwopt = None

    cmdline = [
        "--directory", "",
        "--distribution", str(state.config.distribution),
        "--release", state.config.release,
        "--architecture", str(state.config.architecture),
        *(["--mirror", state.config.mirror] if state.config.mirror else []),
        "--repository-key-check", str(state.config.repository_key_check),
        "--repositories", ",".join(state.config.repositories),
        "--package-manager-tree", ",".join(format_source_target(s, t) for s, t in state.config.package_manager_trees),
        *(["--compress-output", str(state.config.compress_output)] if state.config.compress_output else []),
        "--with-network", str(state.config.with_network),
        "--cache-only", str(state.config.cache_only),
        "--output-dir", str(state.workspace / "initrd"),
        *(["--workspace-dir", str(state.config.workspace_dir)] if state.config.workspace_dir else []),
        "--cache-dir", str(state.cache_dir.parent),
        *(["--local-mirror", str(state.config.local_mirror)] if state.config.local_mirror else []),
        "--incremental", str(state.config.incremental),
        "--acl", str(state.config.acl),
        "--format", "cpio",
        "--package", "systemd",
        "--package", "udev",
        "--package", "util-linux",
        "--package", "kmod",
        *(["--package", "dmsetup"] if state.config.distribution.is_apt_distribution() else []),
        *flatten(["--package", package] for package in state.config.initrd_packages),
        "--output", f"{state.config.output}-initrd",
        *(["--image-version", state.config.image_version] if state.config.image_version else []),
        "--make-initrd", "yes",
        "--bootable", "no",
        "--manifest-format", "",
        *(
            ["--source-date-epoch", str(state.config.source_date_epoch)]
            if state.config.source_date_epoch is not None else
            []
        ),
        *(["--locale", state.config.locale] if state.config.locale else []),
        *(["--locale-messages", state.config.locale_messages] if state.config.locale_messages else []),
        *(["--keymap", state.config.keymap] if state.config.keymap else []),
        *(["--timezone", state.config.timezone] if state.config.timezone else []),
        *(["--hostname", state.config.hostname] if state.config.hostname else []),
        *(["--root-password", rootpwopt] if rootpwopt else []),
        *([f"--environment={k}='{v}'" for k, v in state.config.environment.items()]),
        *(["-f"] * state.args.force),
        "build",
    ]

    args, [config] = parse_config(cmdline)
    assert config.output_dir

    config.output_dir.mkdir(exist_ok=True)

    if (config.output_dir / config.output).exists():
        return config.output_dir / config.output

    with complete_step("Building initrd"):
        build_image(args, config)

    return config.output_dir / config.output


def build_kernel_modules_initrd(state: MkosiState, kver: str) -> Path:
    kmods = state.workspace / f"initrd-kernel-modules-{kver}.img"
    if kmods.exists():
        return kmods

    make_cpio(
        state.root, kmods,
        gen_required_kernel_modules(
            state.root, kver,
            state.config.kernel_modules_initrd_include,
            state.config.kernel_modules_initrd_exclude,
        )
    )

    # Debian/Ubuntu do not compress their kernel modules, so we compress the initramfs instead. Note that
    # this is not ideal since the compressed kernel modules will all be decompressed on boot which
    # requires significant memory.
    if state.config.distribution.is_apt_distribution():
        maybe_compress(state.config, Compression.zst, kmods, kmods)

    return kmods


def python_binary(config: MkosiConfig) -> str:
    # If there's no tools tree, prefer the interpreter from MKOSI_INTERPRETER. If there is a tools
    # tree, just use the default python3 interpreter.
    return "python3" if config.tools_tree else os.getenv("MKOSI_INTERPRETER", "python3")


def extract_pe_section(state: MkosiState, binary: Path, section: str, output: Path) -> None:
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

    run([python_binary(state.config)], input=pefile)


def build_uki(
    state: MkosiState,
    kimg: Path,
    initrds: Sequence[Path],
    output: Path,
    roothash: Optional[str] = None,
) -> None:
    if (state.root / "etc/kernel/cmdline").exists():
        cmdline = [(state.root / "etc/kernel/cmdline").read_text().strip()]
    elif (state.root / "usr/lib/kernel/cmdline").exists():
        cmdline = [(state.root / "usr/lib/kernel/cmdline").read_text().strip()]
    else:
        cmdline = []

    if roothash:
        cmdline += [roothash]

    cmdline += state.config.kernel_command_line

    # Older versions of systemd-stub expect the cmdline section to be null terminated. We can't embed
    # nul terminators in argv so let's communicate the cmdline via a file instead.
    (state.workspace / "cmdline").write_text(f"{' '.join(cmdline).strip()}\x00")

    if not (arch := state.config.architecture.to_efi()):
        die(f"Architecture {state.config.architecture} does not support UEFI")

    stub = state.root / f"usr/lib/systemd/boot/efi/linux{arch}.efi.stub"
    if not stub.exists():
        die(f"sd-stub not found at /{stub.relative_to(state.root)} in the image")

    cmd: list[PathString] = [
        shutil.which("ukify") or "/usr/lib/systemd/ukify",
        "--cmdline", f"@{state.workspace / 'cmdline'}",
        "--os-release", f"@{state.root / 'usr/lib/os-release'}",
        "--stub", stub,
        "--output", output,
        "--efi-arch", arch,
    ]

    if not state.config.tools_tree:
        for p in state.config.extra_search_paths:
            cmd += ["--tools", p]

    uki_config = state.pkgmngr / "etc/kernel/uki.conf"
    if uki_config.exists():
        cmd += ["--config", uki_config]

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        cmd += ["--sign-kernel"]

        if state.config.secure_boot_sign_tool != SecureBootSignTool.pesign:
            cmd += [
                "--signtool", "sbsign",
                "--secureboot-private-key", state.config.secure_boot_key,
                "--secureboot-certificate", state.config.secure_boot_certificate,
            ]
        else:
            pesign_prepare(state)
            cmd += [
                "--signtool", "pesign",
                "--secureboot-certificate-dir", state.workspace / "pesign",
                "--secureboot-certificate-name", certificate_common_name(state.config.secure_boot_certificate),
            ]

        sign_expected_pcr = (state.config.sign_expected_pcr == ConfigFeature.enabled or
                            (state.config.sign_expected_pcr == ConfigFeature.auto and
                                shutil.which("systemd-measure") is not None))

        if sign_expected_pcr:
            cmd += [
                "--pcr-private-key", state.config.secure_boot_key,
                "--pcr-banks", "sha1,sha256",
            ]

    cmd += ["build", "--linux", state.root / kimg]

    for initrd in initrds:
        cmd += ["--initrd", initrd]

    run(cmd)


def want_uki(config: MkosiConfig) -> bool:
    # Do we want to build an UKI according to config?
    # Note that this returns True also in the case where autodetection might later
    # cause the UKI not to be installed after the file system has been populated.

    if config.bootable == ConfigFeature.disabled:
        return False

    if config.bootloader == Bootloader.none:
        return False

    if (config.output_format in (OutputFormat.cpio, OutputFormat.uki) and
        config.bootable == ConfigFeature.auto):
        return False

    if (config.architecture.to_efi() is None and
        config.bootable == ConfigFeature.auto):
        return False

    return True


def install_uki(state: MkosiState, partitions: Sequence[Partition]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if not want_uki(state.config):
        return

    arch = state.config.architecture.to_efi()
    stub = state.root / f"usr/lib/systemd/boot/efi/linux{arch}.efi.stub"
    if not stub.exists() and state.config.bootable == ConfigFeature.auto:
        return

    roothash = finalize_roothash(partitions)

    for kver, kimg in gen_kernel_images(state):
        with complete_step(f"Generating unified kernel image for {kimg}"):
            image_id = state.config.image_id or state.config.distribution.name

            # See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/#boot-counting
            boot_count = ""
            if (state.root / "etc/kernel/tries").exists():
                boot_count = f'+{(state.root / "etc/kernel/tries").read_text().strip()}'

            if state.config.bootloader == Bootloader.uki:
                boot_binary = state.root / "efi/EFI/BOOT/BOOTX64.EFI"
            elif state.config.image_version:
                boot_binary = (
                    state.root / f"efi/EFI/Linux/{image_id}_{state.config.image_version}-{kver}{boot_count}.efi"
                )
            elif roothash:
                _, _, h = roothash.partition("=")
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}-{kver}-{h}{boot_count}.efi"
            else:
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}-{kver}{boot_count}.efi"

            initrds = state.config.initrds.copy() or [build_initrd(state)]

            if state.config.kernel_modules_initrd:
                initrds += [build_kernel_modules_initrd(state, kver)]

            # Make sure the parent directory where we'll be writing the UKI exists.
            with umask(~0o700):
                boot_binary.parent.mkdir(parents=True, exist_ok=True)

            build_uki(state, kimg, initrds, boot_binary, roothash=roothash)

            if not (state.staging / state.config.output_split_initrd).exists():
                # Extract the combined initrds from the UKI so we can use it to direct kernel boot with qemu
                # if needed.
                extract_pe_section(state, boot_binary, ".initrd", state.staging / state.config.output_split_initrd)

            if not (state.staging / state.config.output_split_uki).exists():
                shutil.copy(boot_binary, state.staging / state.config.output_split_uki)

                # ukify will have signed the kernel image as well. Let's make sure we put the signed kernel
                # image in the output directory instead of the unsigned one by reading it from the UKI.
                extract_pe_section(state, boot_binary, ".linux", state.staging / state.config.output_split_kernel)

            print_output_size(boot_binary)

            if state.config.bootloader == Bootloader.uki:
                break

    if state.config.bootable == ConfigFeature.enabled and not (state.staging / state.config.output_split_uki).exists():
        die("A bootable image was requested but no kernel was found")


def make_uki(state: MkosiState, output: Path) -> None:
    make_cpio(state.root, state.staging / state.config.output_split_initrd)
    maybe_compress(state.config, state.config.compress_output,
                   state.staging / state.config.output_split_initrd,
                   state.staging / state.config.output_split_initrd)

    try:
        _, kimg = next(gen_kernel_images(state))
    except StopIteration:
        die("A kernel must be installed in the image to build a UKI")

    build_uki(state, kimg, [state.staging / state.config.output_split_initrd], output)
    extract_pe_section(state, output, ".linux", state.staging / state.config.output_split_kernel)


def compressor_command(compression: Compression) -> list[PathString]:
    """Returns a command suitable for compressing archives."""

    if compression == Compression.gz:
        return [gzip_binary(), "--fast", "--stdout", "-"]
    elif compression == Compression.xz:
        return ["xz", "--check=crc32", "--fast", "-T0", "--stdout", "-"]
    elif compression == Compression.zst:
        return ["zstd", "-q", "-T0", "--stdout", "-"]
    else:
        die(f"Unknown compression {compression}")


def maybe_compress(config: MkosiConfig, compression: Compression, src: Path, dst: Optional[Path] = None) -> None:
    if not compression or src.is_dir():
        if dst:
            move_tree(config, src, dst)
        return

    if not dst:
        dst = src.parent / f"{src.name}.{compression}"

    with complete_step(f"Compressing {src}"):
        with src.open("rb") as i:
            src.unlink() # if src == dst, make sure dst doesn't truncate the src file but creates a new file.

            with dst.open("wb") as o:
                run(compressor_command(compression), stdin=i, stdout=o)


def copy_nspawn_settings(state: MkosiState) -> None:
    if state.config.nspawn_settings is None:
        return None

    with complete_step("Copying nspawn settings file…"):
        shutil.copy2(state.config.nspawn_settings, state.staging / state.config.output_nspawn_settings)


def copy_vmlinuz(state: MkosiState) -> None:
    if (state.staging / state.config.output_split_kernel).exists():
        return

    for _, kimg in gen_kernel_images(state):
        shutil.copy(state.root / kimg, state.staging / state.config.output_split_kernel)
        break


def hash_file(of: TextIO, path: Path) -> None:
    bs = 16 * 1024**2
    h = hashlib.sha256()

    with path.open("rb") as sf:
        while (buf := sf.read(bs)):
            h.update(buf)

    of.write(h.hexdigest() + " *" + path.name + "\n")


def calculate_sha256sum(state: MkosiState) -> None:
    if state.config.output_format == OutputFormat.directory:
        return None

    if not state.config.checksum:
        return None

    with complete_step("Calculating SHA256SUMS…"):
        with open(state.workspace / state.config.output_checksum, "w") as f:
            for p in state.staging.iterdir():
                hash_file(f, p)

        (state.workspace / state.config.output_checksum).rename(state.staging / state.config.output_checksum)


def calculate_signature(state: MkosiState) -> None:
    if not state.config.sign:
        return None

    with complete_step("Signing SHA256SUMS…"):
        cmdline: list[PathString] = ["gpg", "--detach-sign"]

        # Need to specify key before file to sign
        if state.config.key is not None:
            cmdline += ["--default-key", state.config.key]

        cmdline += [
            "--output", state.staging / state.config.output_signature,
            state.staging / state.config.output_checksum,
        ]

        # Set the path of the keyring to use based on the environment if possible and fallback to the default
        # path. Without this the keyring for the root user will instead be used which will fail for a
        # non-root build.
        env = dict(GNUPGHOME=os.environ.get("GNUPGHOME", os.fspath(Path(os.environ["HOME"]) / ".gnupg")))
        if sys.stderr.isatty():
            env |= dict(GPGTTY=os.ttyname(sys.stderr.fileno()))

        run(
            cmdline,
            # Do not output warnings about keyring permissions
            stderr=subprocess.DEVNULL,
            env=env,
        )


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


def save_manifest(state: MkosiState, manifest: Optional[Manifest]) -> None:
    if not manifest:
        return

    if manifest.has_data():
        if ManifestFormat.json in state.config.manifest_format:
            with complete_step(f"Saving manifest {state.config.output_manifest}"):
                with open(state.staging / state.config.output_manifest, 'w') as f:
                    manifest.write_json(f)

        if ManifestFormat.changelog in state.config.manifest_format:
            with complete_step(f"Saving report {state.config.output_changelog}"):
                with open(state.staging / state.config.output_changelog, 'w') as f:
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
        for f in os.listdir(path):
            rmtree(path / f)
    except FileNotFoundError:
        pass


def unlink_output(args: MkosiArgs, config: MkosiConfig) -> None:
    # We remove any cached images if either the user used --force twice, or he/she called "clean" with it
    # passed once. Let's also remove the downloaded package cache if the user specified one additional
    # "--force". Let's also remove all versions if the user specified one additional "--force".

    if args.verb == Verb.clean:
        remove_build_cache = args.force > 0
        remove_package_cache = args.force > 1
        prefix = config.output if args.force > 1 else config.output_with_version
    else:
        remove_build_cache = args.force > 1
        remove_package_cache = args.force > 2
        prefix = config.output if args.force > 2 else config.output_with_version

    with complete_step("Removing output files…"):
        if config.output_dir_or_cwd().exists():
            for p in config.output_dir_or_cwd().iterdir():
                if p.name.startswith(prefix):
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
                empty_directory(config.cache_dir)


def cache_tree_paths(config: MkosiConfig) -> tuple[Path, Path, Path]:
    assert config.cache_dir
    return (
        config.cache_dir / f"{config.output}.cache",
        config.cache_dir / f"{config.output}.build.cache",
        config.cache_dir / f"{config.output}.manifest",
    )


def check_inputs(config: MkosiConfig) -> None:
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
        for src, _ in trees:
            if not src.exists():
                die(f"{name} tree {src} not found")

    if config.bootable != ConfigFeature.disabled:
        for p in config.initrds:
            if not p.exists():
                die(f"Initrd {p} not found")
            if not p.is_file():
                die(f"Initrd {p} is not a file")


def check_outputs(config: MkosiConfig) -> None:
    for f in (
        config.output_with_compression,
        config.output_checksum if config.checksum else None,
        config.output_signature if config.sign else None,
        config.output_nspawn_settings if config.nspawn_settings is not None else None,
    ):
        if f and (config.output_dir_or_cwd() / f).exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def check_systemd_tool(tool: PathString, *, reason: str, hint: Optional[str] = None) -> None:
    if not shutil.which(tool):
        die(f"Could not find '{tool}' which is required to {reason}.", hint=hint)

    v = GenericVersion(run([tool, "--version"], stdout=subprocess.PIPE).stdout.split()[1])
    if v < MINIMUM_SYSTEMD_VERSION:
        die(f"Found '{tool}' version {v} but version {MINIMUM_SYSTEMD_VERSION} or newer is required to {reason}.",
            hint=f"Use ToolsTree=default to get a newer version of '{tool}'.")


def check_tools(args: MkosiArgs, config: MkosiConfig) -> None:
    if want_uki(config):
        check_systemd_tool(
            shutil.which("ukify") or "/usr/lib/systemd/ukify",
            reason="build bootable images",
            hint="Bootable=no can be used to create a non-bootable image",
        )

    if config.output_format == OutputFormat.disk:
        check_systemd_tool("systemd-repart", reason="build disk images")

    if args.verb == Verb.boot:
        check_systemd_tool("systemd-nspawn", reason="boot images")


def configure_ssh(state: MkosiState) -> None:
    if not state.config.ssh:
        return

    unitdir = state.root / "usr/lib/systemd/system"
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
                # ssh always exits with 255 even on normal disconnect, so let's mark that as success so we
                # don't get noisy logs about SSH service failures.
                SuccessExitStatus=255
                """
            )
        )

    preset = state.root / "usr/lib/systemd/system-preset/80-mkosi-ssh.preset"
    with umask(~0o755):
        preset.parent.mkdir(parents=True, exist_ok=True)
    with umask(~0o644):
        preset.write_text("enable ssh.socket\n")


def configure_initrd(state: MkosiState) -> None:
    if (
        not (state.root / "init").exists() and
        not (state.root / "init").is_symlink() and
        (state.root / "usr/lib/systemd/systemd").exists()
    ):
        (state.root / "init").symlink_to("/usr/lib/systemd/systemd")

    if not state.config.make_initrd:
        return

    if not (state.root / "etc/initrd-release").exists() and not (state.root / "etc/initrd-release").is_symlink():
        (state.root / "etc/initrd-release").symlink_to("/etc/os-release")


def configure_clock(state: MkosiState) -> None:
    with umask(~0o644):
        (state.root / "usr/lib/clock-epoch").touch()


def run_depmod(state: MkosiState) -> None:
    if state.config.bootable == ConfigFeature.disabled:
        return

    outputs = (
        "modules.dep",
        "modules.dep.bin",
        "modules.symbols",
        "modules.symbols.bin",
    )

    filters = state.config.kernel_modules_include or state.config.kernel_modules_exclude

    for kver, _ in gen_kernel_images(state):
        if not filters and all((state.root / "usr/lib/modules" / kver / o).exists() for o in outputs):
            continue

        process_kernel_modules(
            state.root, kver,
            state.config.kernel_modules_include,
            state.config.kernel_modules_exclude,
        )

        with complete_step(f"Running depmod for {kver}"):
            bwrap(chroot_cmd(state.root) + ["depmod", "--all", kver])


def run_sysusers(state: MkosiState) -> None:
    if not shutil.which("systemd-sysusers"):
        logging.info("systemd-sysusers is not installed, not generating system users")
        return

    with complete_step("Generating system users"):
        run(["systemd-sysusers", "--root", state.root])


def run_preset(state: MkosiState) -> None:
    if not shutil.which("systemctl"):
        logging.info("systemctl is not installed, not applying presets")
        return

    with complete_step("Applying presets…"):
        run(["systemctl", "--root", state.root, "preset-all"])


def run_hwdb(state: MkosiState) -> None:
    if not shutil.which("systemd-hwdb"):
        logging.info("systemd-hwdb is not installed, not generating hwdb")
        return

    with complete_step("Generating hardware database"):
        run(["systemd-hwdb", "--root", state.root, "--usr", "--strict", "update"])

    # Remove any existing hwdb in /etc in favor of the one we just put in /usr.
    (state.root / "etc/udev/hwdb.bin").unlink(missing_ok=True)


def run_firstboot(state: MkosiState) -> None:
    password, hashed = state.config.root_password or (None, False)
    pwopt = "--root-password-hashed" if hashed else "--root-password"
    pwcred = "passwd.hashed-password.root" if hashed else "passwd.plaintext-password.root"

    settings = (
        ("--locale",          "firstboot.locale",          state.config.locale),
        ("--locale-messages", "firstboot.locale-messages", state.config.locale_messages),
        ("--keymap",          "firstboot.keymap",          state.config.keymap),
        ("--timezone",        "firstboot.timezone",        state.config.timezone),
        ("--hostname",        None,                        state.config.hostname),
        (pwopt,               pwcred,                      password),
        ("--root-shell",      "passwd.shell.root",         state.config.root_shell),
    )

    options = []
    creds = []

    for option, cred, value in settings:
        if not value:
            continue

        options += [option, value]

        if cred:
            creds += [(cred, value)]

    if not options and not creds:
        return

    with complete_step("Applying first boot settings"):
        run(["systemd-firstboot", "--root", state.root, "--force", *options])

        # Initrds generally don't ship with only /usr so there's not much point in putting the credentials in
        # /usr/lib/credstore.
        if state.config.output_format != OutputFormat.cpio or not state.config.make_initrd:
            with umask(~0o755):
                (state.root / "usr/lib/credstore").mkdir(exist_ok=True)

            for cred, value in creds:
                with umask(~0o600 if "password" in cred else ~0o644):
                    (state.root / "usr/lib/credstore" / cred).write_text(value)


def run_selinux_relabel(state: MkosiState) -> None:
    selinux = state.root / "etc/selinux/config"
    if not selinux.exists():
        return

    policy = run(["sh", "-c", f". {selinux} && echo $SELINUXTYPE"], stdout=subprocess.PIPE).stdout.strip()
    if not policy:
        return

    if not shutil.which("setfiles"):
        logging.info("setfiles is not installed, not relabeling files")
        return

    fc = state.root / "etc/selinux" / policy / "contexts/files/file_contexts"
    binpolicydir = state.root / "etc/selinux" / policy / "policy"

    try:
        # The policy file is named policy.XX where XX is the policy version that indicates what features are
        # available. It's not expected for there to be more than one file in this directory.
        binpolicy = next(binpolicydir.iterdir())
    except StopIteration:
        die(f"SELinux binary policy not found in {binpolicydir}")

    with complete_step(f"Relabeling files using {policy} policy"):
        run(["setfiles", "-mFr", state.root, "-c", binpolicy, fc, state.root])


def need_build_overlay(config: MkosiConfig) -> bool:
    return bool(config.build_scripts and (config.build_packages or config.prepare_scripts))


def save_cache(state: MkosiState) -> None:
    if not state.config.incremental:
        return

    final, build, manifest = cache_tree_paths(state.config)

    with complete_step("Installing cache copies"):
        rmtree(final)

        # We only use the cache-overlay directory for caching if we have a base tree, otherwise we just
        # cache the root directory.
        if (state.workspace / "cache-overlay").exists():
            move_tree(state.config, state.workspace / "cache-overlay", final)
        else:
            move_tree(state.config, state.root, final)

        if need_build_overlay(state.config) and (state.workspace / "build-overlay").exists():
            rmtree(build)
            move_tree(state.config, state.workspace / "build-overlay", build)

        manifest.write_text(json.dumps(state.config.cache_manifest()))


def reuse_cache(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    final, build, manifest = cache_tree_paths(state.config)
    if not final.exists() or (need_build_overlay(state.config) and not build.exists()):
        return False

    if manifest.exists():
        prev = json.loads(manifest.read_text())
        if prev != state.config.cache_manifest():
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
        copy_tree(state.config, final, state.root)
        if need_build_overlay(state.config):
            (state.workspace / "build-overlay").symlink_to(build)

    return True


def make_image(state: MkosiState, skip: Sequence[str] = [], split: bool = False) -> list[Partition]:
    if not state.config.output_format == OutputFormat.disk:
        return []

    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--no-pager",
        "--offline=yes",
        "--root", state.root,
        "--seed", str(state.config.seed) if state.config.seed else "random",
        state.staging / state.config.output_with_format,
    ]

    if not state.config.architecture.is_native():
        cmdline += ["--architecture", str(state.config.architecture)]
    if not (state.staging / state.config.output_with_format).exists():
        cmdline += ["--empty=create"]
    if state.config.passphrase:
        cmdline += ["--key-file", state.config.passphrase]
    if state.config.verity_key:
        cmdline += ["--private-key", state.config.verity_key]
    if state.config.verity_certificate:
        cmdline += ["--certificate", state.config.verity_certificate]
    if skip:
        cmdline += ["--defer-partitions", ",".join(skip)]
    if split and state.config.split_artifacts:
        cmdline += ["--split=yes"]
    if state.config.sector_size:
        cmdline += ["--sector-size", state.config.sector_size]

    if state.config.repart_dirs:
        for d in state.config.repart_dirs:
            cmdline += ["--definitions", d]

        # Subvolumes= only works with --offline=no.
        grep = run(["grep", "--recursive", "--include=*.conf", "Subvolumes=", *state.config.repart_dirs],
                   stdout=subprocess.DEVNULL, check=False)
        if grep.returncode == 0:
            cmdline += ["--offline=no"]
    else:
        definitions = state.workspace / "repart-definitions"
        if not definitions.exists():
            definitions.mkdir()
            if (arch := state.config.architecture.to_efi()):
                bootloader = state.root / f"efi/EFI/BOOT/BOOT{arch.upper()}.EFI"
            else:
                bootloader = None

            # If grub for BIOS is installed, let's add a BIOS boot partition onto which we can install grub.
            bios = (state.config.bootable != ConfigFeature.disabled and want_grub_bios(state))

            if bios:
                (definitions / "05-bios.conf").write_text(
                    textwrap.dedent(
                        f"""\
                        [Partition]
                        Type={Partition.GRUB_BOOT_PARTITION_UUID}
                        SizeMinBytes=1M
                        SizeMaxBytes=1M
                        """
                    )
                )

            esp = (
                state.config.bootable == ConfigFeature.enabled or
                (state.config.bootable == ConfigFeature.auto and bootloader and bootloader.exists())
            )

            if esp or bios:
                # Even if we're doing BIOS, let's still use the ESP to store the kernels, initrds and grub
                # modules. We cant use UKIs so we have to put each kernel and initrd on the ESP twice, so
                # let's make the ESP twice as big in that case.
                (definitions / "00-esp.conf").write_text(
                    textwrap.dedent(
                        f"""\
                        [Partition]
                        Type=esp
                        Format=vfat
                        CopyFiles=/efi:/
                        SizeMinBytes={"1G" if bios else "512M"}
                        SizeMaxBytes={"1G" if bios else "512M"}
                        """
                    )
                )

            (definitions / "10-root.conf").write_text(
                textwrap.dedent(
                    f"""\
                    [Partition]
                    Type=root
                    Format={state.config.distribution.filesystem()}
                    CopyFiles=/
                    Minimize=guess
                    """
                )
            )

        cmdline += ["--definitions", definitions]

    env = dict()
    for option, value in state.config.environment.items():
        if option.startswith("SYSTEMD_REPART_MKFS_OPTIONS_"):
            env[option] = value
        if option == "SOURCE_DATE_EPOCH":
            env[option] = value

    with complete_step("Generating disk image"):
        output = json.loads(run(cmdline, stdout=subprocess.PIPE, env=env).stdout)

    logging.debug(json.dumps(output, indent=4))

    partitions = [Partition.from_dict(d) for d in output]

    if split:
        for p in partitions:
            if p.split_path:
                maybe_compress(state.config, state.config.compress_output, p.split_path)

    return partitions


def finalize_staging(state: MkosiState) -> None:
    # Our output unlinking logic removes everything prefixed with the name of the image, so let's make
    # sure that everything we put into the output directory is prefixed with the name of the output.
    for f in state.staging.iterdir():
        name = f.name
        if not name.startswith(state.config.output_with_version):
            name = f"{state.config.output_with_version}-{name}"
        if name != f.name:
            f.rename(state.staging / name)

    for f in state.staging.iterdir():
        # Make sure all build outputs that are not directories are owned by the user running mkosi.
        if not f.is_dir():
            os.chown(f, INVOKING_USER.uid, INVOKING_USER.gid, follow_symlinks=False)
        move_tree(state.config, f, state.config.output_dir_or_cwd())


def normalize_mtime(root: Path, mtime: Optional[int], directory: Optional[Path] = None) -> None:
    if mtime is None:
        return

    directory = directory or Path("")

    with complete_step(f"Normalizing modification times of /{directory}"):
        os.utime(root / directory, (mtime, mtime), follow_symlinks=False)
        for p in (root / directory).rglob("*"):
            os.utime(p, (mtime, mtime), follow_symlinks=False)


def build_image(args: MkosiArgs, config: MkosiConfig) -> None:
    manifest = Manifest(config) if config.manifest_format else None
    workspace = tempfile.TemporaryDirectory(dir=config.workspace_dir_or_cwd(), prefix=".mkosi-tmp")

    with workspace, scopedenv({"TMPDIR" : workspace.name}):
        state = MkosiState(args, config, Path(workspace.name))
        install_package_manager_trees(state)

        with mount_base_trees(state):
            install_base_trees(state)
            install_skeleton_trees(state)
            cached = reuse_cache(state)

            state.config.distribution.setup(state)

            if not cached:
                with mount_cache_overlay(state):
                    install_distribution(state)
                    run_prepare_scripts(state, build=False)
                    install_build_packages(state)
                    run_prepare_scripts(state, build=True)

                save_cache(state)
                reuse_cache(state)

            check_root_populated(state)
            run_build_scripts(state)

            if state.config.output_format == OutputFormat.none:
                # Touch an empty file to indicate the image was built.
                (state.staging / state.config.output).touch()
                finalize_staging(state)
                return

            install_build_dest(state)
            install_extra_trees(state)
            run_postinst_scripts(state)

            configure_autologin(state)
            configure_os_release(state)
            configure_initrd(state)
            configure_ssh(state)
            configure_clock(state)

            install_systemd_boot(state)
            run_sysusers(state)
            run_preset(state)
            run_depmod(state)
            run_firstboot(state)
            run_hwdb(state)
            remove_packages(state)

            if manifest:
                with complete_step("Recording packages in manifest…"):
                    manifest.record_packages(state.root)

            clean_package_manager_metadata(state)
            remove_files(state)
            run_selinux_relabel(state)
            run_finalize_scripts(state)

        normalize_mtime(state.root, state.config.source_date_epoch)
        partitions = make_image(state, skip=("esp", "xbootldr"))
        install_uki(state, partitions)
        prepare_grub_efi(state)
        prepare_grub_bios(state, partitions)
        normalize_mtime(state.root, state.config.source_date_epoch, directory=Path("boot"))
        normalize_mtime(state.root, state.config.source_date_epoch, directory=Path("efi"))
        partitions = make_image(state)
        install_grub_bios(state, partitions)
        make_image(state, split=True)
        copy_vmlinuz(state)

        if state.config.output_format == OutputFormat.tar:
            make_tar(state.root, state.staging / state.config.output_with_format)
        elif state.config.output_format == OutputFormat.cpio:
            make_cpio(state.root, state.staging / state.config.output_with_format)
        elif state.config.output_format == OutputFormat.uki:
            make_uki(state, state.staging / state.config.output_with_format)
        elif state.config.output_format == OutputFormat.directory:
            state.root.rename(state.staging / state.config.output_with_format)

        if config.output_format != OutputFormat.uki:
            maybe_compress(state.config, state.config.compress_output,
                           state.staging / state.config.output_with_format,
                           state.staging / state.config.output_with_compression)

        copy_nspawn_settings(state)
        calculate_sha256sum(state)
        calculate_signature(state)
        save_manifest(state, manifest)

        output_base = state.staging / state.config.output
        if not output_base.exists() or output_base.is_symlink():
            output_base.unlink(missing_ok=True)
            output_base.symlink_to(state.config.output_with_compression)

        finalize_staging(state)

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
def acl_maybe_toggle(config: MkosiConfig, root: Path, uid: int, *, always: bool) -> Iterator[None]:
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
def acl_toggle_build(config: MkosiConfig, uid: int) -> Iterator[None]:
    if not config.acl:
        yield
        return

    extras = [e[0] for e in config.extra_trees]
    skeletons = [s[0] for s in config.skeleton_trees]

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
def acl_toggle_boot(config: MkosiConfig, uid: int) -> Iterator[None]:
    if not config.acl or config.output_format != OutputFormat.directory:
        yield
        return

    with acl_maybe_toggle(config, config.output_dir_or_cwd() / config.output, uid, always=False):
        yield


def run_shell(args: MkosiArgs, config: MkosiConfig) -> None:
    cmdline: list[PathString] = ["systemd-nspawn", "--quiet"]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings is not None:
        cmdline += ["--settings=trusted"]

    if args.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += [
            f"--rlimit=RLIMIT_CORE={format_rlimit(resource.RLIMIT_CORE)}",
            "--console=autopipe",
        ]

    # Underscores are not allowed in machine names so replace them with hyphens.
    cmdline += ["--machine", (config.image_id or config.image or config.output).replace("_", "-")]

    for k, v in config.credentials.items():
        cmdline += [f"--set-credential={k}:{v}"]

    with contextlib.ExitStack() as stack:
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

        for src, tgt in config.runtime_trees:
            # We add norbind because very often RuntimeTrees= will be used to mount the source directory into the
            # container and the output directory from which we're running will very likely be a subdirectory of the
            # source directory which would mean we'd be mounting the container root directory as a subdirectory in
            # itself which tends to lead to all kinds of weird issues, which we avoid by not doing a recursive mount
            # which means the container root directory mounts will be skipped.
            cmdline += ["--bind", f"{src}:{tgt or f'/root/src/{src.name}'}:norbind,rootidmap"]

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


def run_serve(config: MkosiConfig) -> None:
    """Serve the output directory via a tiny HTTP server"""

    port = "8081"

    with chdir(config.output_dir_or_cwd()):
        run([python_binary(config), "-m", "http.server", port],
            user=INVOKING_USER.uid, group=INVOKING_USER.gid, stdin=sys.stdin, stdout=sys.stdout)


def generate_key_cert_pair(args: MkosiArgs) -> None:
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

    run_openssl(["req",
                 "-new",
                 "-x509",
                 "-newkey", f"rsa:{keylength}",
                 "-keyout", "mkosi.key",
                 "-out", "mkosi.crt",
                 "-days", str(args.genkey_valid_days),
                 "-subj", f"/CN={cn}/",
                 "-nodes"])


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


def show_docs(args: MkosiArgs) -> None:
    if args.doc_format == DocFormat.auto:
        formats = [DocFormat.man, DocFormat.pandoc, DocFormat.markdown, DocFormat.system]
    else:
        formats = [args.doc_format]

    while formats:
        form = formats.pop(0)
        try:
            if form == DocFormat.man:
                with importlib.resources.path("mkosi.resources", "mkosi.1") as man:
                    if not man.exists():
                        raise FileNotFoundError()
                    run(["man", "--local-file", man])
                    return
            elif form == DocFormat.pandoc:
                if not shutil.which("pandoc"):
                    logging.debug("pandoc is not available")
                with importlib.resources.path("mkosi.resources", "mkosi.md") as mdr:
                    pandoc = run(["pandoc", "-t", "man", "-s", mdr], stdout=subprocess.PIPE)
                    run(["man", "--local-file", "-"], input=pandoc.stdout)
                    return
            elif form == DocFormat.markdown:
                md = importlib.resources.read_text("mkosi.resources", "mkosi.md")
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
    return s.replace("%u", INVOKING_USER.name)


def needs_build(args: MkosiArgs, config: MkosiConfig) -> bool:
    return (
        args.verb.needs_build() and
        (args.force > 0 or not (config.output_dir_or_cwd() / config.output_with_compression).exists())
    )


@contextlib.contextmanager
def prepend_to_environ_path(config: MkosiConfig) -> Iterator[None]:
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


def finalize_tools(args: MkosiArgs, images: Sequence[MkosiConfig]) -> Sequence[MkosiConfig]:
    new = []

    for p in images:
        if not p.tools_tree or p.tools_tree.name != "default":
            new.append(p)
            continue

        distribution = p.tools_tree_distribution or p.distribution.default_tools_tree_distribution()
        if not distribution:
            die(f"{p.distribution} does not have a default tools tree distribution",
                hint="use ToolsTreeDistribution= to set one explicitly")

        release = p.tools_tree_release or distribution.default_release()
        mirror = p.tools_tree_mirror or (p.mirror if p.mirror and p.distribution == distribution else None)

        cmdline = [
            "--directory", "",
            "--distribution", str(distribution),
            *(["--release", release] if release else []),
            *(["--mirror", mirror] if mirror else []),
            "--repository-key-check", str(p.repository_key_check),
            "--cache-only", str(p.cache_only),
            *(["--output-dir", str(p.output_dir)] if p.output_dir else []),
            *(["--workspace-dir", str(p.workspace_dir)] if p.workspace_dir else []),
            *(["--cache-dir", str(p.cache_dir.parent)] if p.cache_dir else []),
            "--incremental", str(p.incremental),
            "--acl", str(p.acl),
            "--format", "directory",
            *flatten(
                ["--package", package]
                for package in itertools.chain(distribution.tools_tree_packages(), p.tools_tree_packages)
            ),
            "--output", f"{distribution}-tools",
            "--bootable", "no",
            "--manifest-format", "",
            *(["--source-date-epoch", str(p.source_date_epoch)] if p.source_date_epoch is not None else []),
            *([f"--environment={k}='{v}'" for k, v in p.environment.items()]),
            *flatten(["--repositories", repo] for repo in distribution.tools_tree_repositories()),
            *([f"--extra-search-path={p}" for p in p.extra_search_paths]),
            *(["-f"] * args.force),
            "build",
        ]

        _, [config] = parse_config(cmdline)
        config = dataclasses.replace(config, image=f"{distribution}-tools")

        if config not in new:
            new.append(config)

        new.append(dataclasses.replace(p, tools_tree=config.output_dir_or_cwd() / config.output))

    return new


@contextlib.contextmanager
def mount_tools(tree: Optional[Path]) -> Iterator[None]:
    if not tree:
        yield
        return

    with contextlib.ExitStack() as stack:
        stack.enter_context(mount_usr(tree))

        # On recent Fedora versions, rpm has started doing very strict checks on GPG certificate validity. To
        # make these checks pass, we need to make sure a few directories from /etc in the tools tree are
        # mounted into the host as well. Because the directories might not exist on the host, we mount a
        # writable directory on top of /etc in an overlay so we can create these mountpoints without running
        # into permission errors.

        tmp = stack.enter_context(tempfile.TemporaryDirectory(dir="/var/tmp"))
        stack.enter_context(mount_overlay([Path("/etc")], Path(tmp), Path("/etc")))

        for subdir in ("etc/pki", "etc/ssl", "etc/crypto-policies", "etc/ca-certificates"):
            if not (tree / subdir).exists():
                continue

            (Path("/") / subdir).mkdir(parents=True, exist_ok=True)
            stack.enter_context(
                mount(what=tree / subdir, where=Path("/") / subdir, operation="--bind", read_only=True)
            )

        yield


def run_verb(args: MkosiArgs, images: Sequence[MkosiConfig]) -> None:
    if args.verb.needs_root() and os.getuid() != 0:
        die(f"Must be root to run the {args.verb} command")

    if args.verb == Verb.documentation:
        return show_docs(args)

    if args.verb == Verb.genkey:
        return generate_key_cert_pair(args)

    if all(config == MkosiConfig.default() for config in images):
        die("No configuration found",
            hint="Make sure you're running mkosi from a directory with configuration files")

    if args.verb == Verb.bump:
        return bump_image_version()

    if args.verb == Verb.summary:
        if args.json:
            text = json.dumps(
                {"Images": [config.to_dict() for config in images]},
                cls=MkosiJsonEncoder,
                indent=4,
                sort_keys=True
            )
        else:
            text = "\n".join(summary(config) for config in images)

        page(text, args.pager)
        return

    images = finalize_tools(args, images)
    last = images[-1]

    if args.verb in (Verb.shell, Verb.boot):
        opname = "acquire shell in" if args.verb == Verb.shell else "boot"
        if last.output_format in (OutputFormat.tar, OutputFormat.cpio):
            die(f"Sorry, can't {opname} a {last.output_format} archive.")
        if last.compress_output:
            die(f"Sorry, can't {opname} a compressed image.")

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
        d: os.open(d.device(), os.O_RDWR|os.O_CLOEXEC|os.O_NONBLOCK)
        for d in QemuDeviceNode
        if d.available(log=True)
    }

    # Get the user UID/GID either on the host or in the user namespace running the build
    become_root()
    init_mount_namespace()

    # For extra safety when running as root, remount a bunch of stuff read-only.
    for d in ("/usr", "/etc", "/opt", "/srv", "/boot", "/efi", "/media", "/mnt"):
        if Path(d).exists():
            run(["mount", "--rbind", d, d, "--options", "ro"])

    # First, process all directory removals because otherwise if different images share directories a later
    # image build could end up deleting the output generated by an earlier image build.

    for config in images:
        if not needs_build(args, config) and args.verb != Verb.clean:
            continue

        unlink_output(args, config)

    if args.verb == Verb.clean:
        return

    build = False

    for config in images:
        check_inputs(config)

        if not needs_build(args, config):
            continue

        with (
            complete_step(f"Building {config.image or 'default'} image"),\
            mount_tools(config.tools_tree),\
            mount_passwd(),\
            prepend_to_environ_path(config)\
        ):
            # After tools have been mounted, check if we have what we need
            check_tools(args, config)

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

            build = True

    if build and args.auto_bump:
        bump_image_version()

    if args.verb == Verb.build:
        return

    with (
        mount_usr(last.tools_tree),\
        mount_passwd(),\
        prepend_to_environ_path(last)\
    ):
        check_tools(args, last)

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
