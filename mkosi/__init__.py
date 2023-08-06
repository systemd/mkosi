# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import datetime
import hashlib
import http.server
import itertools
import json
import logging
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from textwrap import dedent
from typing import ContextManager, Optional, TextIO, Union

from mkosi.archive import extract_tar, make_cpio, make_tar
from mkosi.config import (
    Compression,
    ConfigFeature,
    ManifestFormat,
    MkosiArgs,
    MkosiConfig,
    MkosiConfigParser,
    OutputFormat,
    SecureBootSignTool,
    Verb,
    format_source_target,
    summary,
)
from mkosi.install import add_dropin_config_from_resource
from mkosi.installer import clean_package_manager_metadata, package_manager_scripts
from mkosi.kmod import gen_required_kernel_modules, process_kernel_modules
from mkosi.log import complete_step, die, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import mount_overlay, mount_passwd, mount_usr
from mkosi.pager import page
from mkosi.qemu import copy_ephemeral, run_qemu, run_ssh
from mkosi.run import become_root, bwrap, chroot_cmd, init_mount_namespace, run
from mkosi.state import MkosiState
from mkosi.tree import copy_tree, install_tree, move_tree, rmtree
from mkosi.types import PathString
from mkosi.util import (
    InvokingUser,
    flatten,
    format_bytes,
    format_rlimit,
    one_zero,
    scopedenv,
    try_import,
    umask,
)
from mkosi.versioncomp import GenericVersion


@contextlib.contextmanager
def mount_image(state: MkosiState) -> Iterator[None]:
    with complete_step("Mounting image…", "Unmounting image…"), contextlib.ExitStack() as stack:

        if state.config.base_trees and state.config.overlay:
            bases = []
            (state.workspace / "bases").mkdir(exist_ok=True)

            for path in state.config.base_trees:
                d = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=state.workspace / "bases", prefix=path.name)))
                d.rmdir() # We need the random name, but we want to create the directory ourselves

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

            stack.enter_context(mount_overlay(bases, state.root, state.root, read_only=False))

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

            if state.config.packages:
                state.config.distribution.install_packages(state, state.config.packages)

    for f in ("var/lib/systemd/random-seed", "var/lib/systemd/credential.secret", "etc/machine-info"):
        # Using missing_ok=True still causes an OSError if the mount is read-only even if the
        # file doesn't exist so do an explicit exists() check first.
        if (state.root / f).exists():
            (state.root / f).unlink()


def install_build_packages(state: MkosiState) -> None:
    if not need_build_packages(state.config):
        return

    with complete_step(f"Installing build packages for {str(state.config.distribution).capitalize()}"), mount_build_overlay(state):
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


def configure_autologin(state: MkosiState) -> None:
    if not state.config.autologin:
        return

    with complete_step("Setting up autologin…"):
        add_dropin_config_from_resource(state.root, "console-getty.service", "autologin",
                                        "mkosi.resources", "console_getty_autologin.conf")
        add_dropin_config_from_resource(state.root, "serial-getty@ttyS0.service", "autologin",
                                        "mkosi.resources", "serial_getty_autologin.conf")
        add_dropin_config_from_resource(state.root, "getty@tty1.service", "autologin",
                                        "mkosi.resources", "getty_autologin.conf")



@contextlib.contextmanager
def mount_cache_overlay(state: MkosiState) -> Iterator[None]:
    if not state.config.incremental or not any(state.root.iterdir()):
        yield
        return

    d = state.workspace / "cache-overlay"
    with umask(~0o755):
        d.mkdir(exist_ok=True)

    with mount_overlay([state.root], d, state.root, read_only=False):
        yield


def mount_build_overlay(state: MkosiState, read_only: bool = False) -> ContextManager[Path]:
    d = state.workspace / "build-overlay"
    if not d.is_symlink():
        with umask(~0o755):
            d.mkdir(exist_ok=True)
    return mount_overlay([state.root], state.workspace / "build-overlay", state.root, read_only)


def finalize_source_mounts(config: MkosiConfig) -> list[PathString]:
    sources = [
        (src, Path.cwd() / (str(target).lstrip("/") if target else "."))
        for src, target
        in ((Path.cwd(), None), *config.build_sources)
    ]

    return flatten(["--bind", src, target] for src, target in sorted(sources, key=lambda s: s[1]))


def finalize_writable_mounts(config: MkosiConfig) -> list[PathString]:
    """
    bwrap() mounts /home and /var read-only during execution. This functions finalizes the bind mount options
    for the directories that could be in /home or /var that we do need to be writable.
    """
    return flatten(["--bind", d, d] for d in (config.workspace_dir, config.cache_dir, config.output_dir, config.build_dir) if d)


def run_prepare_script(state: MkosiState, build: bool) -> None:
    if state.config.prepare_script is None:
        return
    if build and state.config.build_script is None:
        return

    env = dict(
        SCRIPT="/work/prepare",
        SRCDIR=str(Path.cwd()),
        CHROOT_SRCDIR="/work/src",
        BUILDROOT=str(state.root),
    )

    chroot: list[PathString] = chroot_cmd(
        state.root,
        options=[
            "--bind", state.config.prepare_script, "/work/prepare",
            "--bind", Path.cwd(), "/work/src",
            "--chdir", "/work/src",
            "--setenv", "SRCDIR", "/work/src",
            "--setenv", "BUILDROOT", "/",
        ],
        network=True,
    )

    if build:
        with complete_step("Running prepare script in build overlay…"), mount_build_overlay(state):
            bwrap(
                [state.config.prepare_script, "build"],
                options=finalize_source_mounts(state.config) + finalize_writable_mounts(state.config),
                scripts={"mkosi-chroot": chroot} | package_manager_scripts(state),
                env=env | state.config.environment,
                stdin=sys.stdin,
            )
    else:
        with complete_step("Running prepare script…"):
            bwrap(
                [state.config.prepare_script, "final"],
                options=finalize_source_mounts(state.config) + finalize_writable_mounts(state.config),
                scripts={"mkosi-chroot": chroot} | package_manager_scripts(state),
                env=env | state.config.environment,
                stdin=sys.stdin,
            )


def run_build_script(state: MkosiState) -> None:
    if state.config.build_script is None:
        return

    env = dict(
        WITH_DOCS=one_zero(state.config.with_docs),
        WITH_TESTS=one_zero(state.config.with_tests),
        WITH_NETWORK=one_zero(state.config.with_network),
        SCRIPT="/work/build-script",
        SRCDIR=str(Path.cwd()),
        CHROOT_SRCDIR="/work/src",
        DESTDIR=str(state.install_dir),
        CHROOT_DESTDIR="/work/dest",
        OUTPUTDIR=str(state.staging),
        CHROOT_OUTPUTDIR="/work/out",
        BUILDROOT=str(state.root),
    )

    if state.config.build_dir is not None:
        env |= dict(
            BUILDDIR=str(state.config.build_dir),
            CHROOT_BUILDDIR="/work/build",
        )

    chroot = chroot_cmd(
        state.root,
        options=[
            "--bind", state.config.build_script, "/work/build-script",
            "--bind", state.install_dir, "/work/dest",
            "--bind", state.staging, "/work/out",
            "--bind", Path.cwd(), "/work/src",
            *(["--bind", str(state.config.build_dir), "/work/build"] if state.config.build_dir else []),
            "--chdir", "/work/src",
            "--setenv", "SRCDIR", "/work/src",
            "--setenv", "DESTDIR", "/work/dest",
            "--setenv", "OUTPUTDIR", "/work/out",
            "--setenv", "BUILDROOT", "/",
            *(["--setenv", "BUILDDIR", "/work/build"] if state.config.build_dir else []),
            "--remount-ro", "/",
        ],
        network=state.config.with_network,
    )

    with complete_step("Running build script…"), mount_build_overlay(state):
        bwrap(
            [state.config.build_script],
            options=finalize_source_mounts(state.config) + finalize_writable_mounts(state.config),
            scripts={"mkosi-chroot": chroot} | package_manager_scripts(state),
            env=env | state.config.environment,
            stdin=sys.stdin,
        )


def run_postinst_script(state: MkosiState) -> None:
    if state.config.postinst_script is None:
        return

    env = dict(
        SCRIPT="/work/postinst",
        SRCDIR=str(Path.cwd()),
        CHROOT_SRCDIR="/work/src",
        OUTPUTDIR=str(state.staging),
        CHROOT_OUTPUTDIR="/work/out",
        BUILDROOT=str(state.root),
    )

    chroot = chroot_cmd(
        state.root,
        options=[
            "--bind", state.config.postinst_script, "/work/postinst",
            "--bind", state.staging, "/work/out",
            "--bind", Path.cwd(), "/work/src",
            "--chdir", "/work/src",
            "--setenv", "SRCDIR", "/work/src",
            "--setenv", "OUTPUTDIR", "/work/out",
            "--setenv", "BUILDROOT", "/",
        ],
        network=state.config.with_network,
    )

    with complete_step("Running postinstall script…"):
        bwrap(
            [state.config.postinst_script, "final"],
            options=finalize_source_mounts(state.config) + finalize_writable_mounts(state.config),
            scripts={"mkosi-chroot": chroot} | package_manager_scripts(state),
            env=env | state.config.environment,
            stdin=sys.stdin,
        )


def run_finalize_script(state: MkosiState) -> None:
    if state.config.finalize_script is None:
        return

    env = dict(
        SCRIPT="/work/finalize",
        SRCDIR=str(Path.cwd()),
        CHROOT_SRCDIR="/work/src",
        OUTPUTDIR=str(state.staging),
        CHROOT_OUTPUTDIR="/work/out",
        BUILDROOT=str(state.root),
    )

    chroot = chroot_cmd(
        state.root,
        options=[
            "--bind", state.config.finalize_script, "/work/finalize",
            "--bind", state.staging, "/work/out",
            "--bind", Path.cwd(), "/work/src",
            "--chdir", "/work/src",
            "--setenv", "SRCDIR", "/work/src",
            "--setenv", "OUTPUTDIR", "/work/out",
            "--setenv", "BUILDROOT", "/",
        ],
        network=state.config.with_network,
    )

    with complete_step("Running finalize script…"):
        bwrap(
            [state.config.finalize_script],
            options=finalize_source_mounts(state.config) + finalize_writable_mounts(state.config),
            scripts={"mkosi-chroot": chroot} | package_manager_scripts(state),
            env=env | state.config.environment,
            stdin=sys.stdin,
        )


def certificate_common_name(certificate: Path) -> str:
    output = run([
        "openssl",
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


def install_boot_loader(state: MkosiState) -> None:
    if state.config.bootable == ConfigFeature.disabled:
        return

    if state.config.output_format == OutputFormat.cpio and state.config.bootable == ConfigFeature.auto:
        return

    if not any(gen_kernel_images(state)) and state.config.bootable == ConfigFeature.auto:
        return

    if not shutil.which("bootctl"):
        if state.config.bootable == ConfigFeature.enabled:
            die("A bootable image was requested but bootctl was not found")
        return

    directory = state.root / "usr/lib/systemd/boot/efi"
    if not directory.exists() or not any(directory.iterdir()):
        if state.config.bootable == ConfigFeature.enabled:
            die("A bootable image was requested but systemd-boot was not found at "
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
        run(["bootctl", "install", "--root", state.root, "--all-architectures"],
            env={"SYSTEMD_ESP_PATH": "/efi"})

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        with complete_step("Setting up secure boot auto-enrollment…"):
            keys = state.root / "efi/loader/keys/auto"
            with umask(~0o700):
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
        yield kver.name, Path("usr/lib/modules") / kver.name / "vmlinuz"


def install_unified_kernel(state: MkosiState, roothash: Optional[str]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if state.config.bootable == ConfigFeature.disabled:
        return

    for kver, kimg in gen_kernel_images(state):
        shutil.copy(state.root / kimg, state.staging / state.config.output_split_kernel)
        break

    if state.config.output_format == OutputFormat.cpio and state.config.bootable == ConfigFeature.auto:
        return

    initrds = []

    if state.config.initrds:
        initrds = state.config.initrds
    elif any(gen_kernel_images(state)):
        # Default values are assigned via the parser so we go via the argument parser to construct
        # the config for the initrd.
        with complete_step("Building initrd"):
            password, hashed = state.config.root_password or (None, False)
            if password:
                rootpwopt = f"hashed:{password}" if hashed else password
            else:
                rootpwopt = None

            args, presets = MkosiConfigParser().parse([
                "--directory", "",
                "--distribution", str(state.config.distribution),
                "--release", state.config.release,
                "--architecture", str(state.config.architecture),
                *(["--mirror", state.config.mirror] if state.config.mirror else []),
                "--repository-key-check", str(state.config.repository_key_check),
                "--repositories", ",".join(state.config.repositories),
                "--package-manager-tree", ",".join(format_source_target(s, t) for s, t in state.config.package_manager_trees),
                *(["--tools-tree", str(state.config.tools_tree)] if state.config.tools_tree else []),
                *(["--compress-output", str(state.config.compress_output)] if state.config.compress_output else []),
                "--with-network", str(state.config.with_network),
                "--cache-only", str(state.config.cache_only),
                *(["--output-dir", str(state.config.output_dir)] if state.config.output_dir else []),
                *(["--workspace-dir", str(state.config.workspace_dir)] if state.config.workspace_dir else []),
                "--cache-dir", str(state.cache_dir.parent),
                *(["--local-mirror", str(state.config.local_mirror)] if state.config.local_mirror else []),
                "--incremental", str(state.config.incremental),
                "--acl", str(state.config.acl),
                "--format", "cpio",
                "--package", "systemd",
                "--package", "util-linux",
                "--package", "kmod",
                *(["--package", "dmsetup"] if state.config.distribution.is_apt_distribution() else []),
                *(["--package", "udev"] if not state.config.distribution.is_portage_distribution() else []),
                *(["--package", "bash"] if state.config.distribution.is_portage_distribution() else []),
                "--output", f"{state.config.output}-initrd",
                *(["--image-version", state.config.image_version] if state.config.image_version else []),
                "--make-initrd", "yes",
                "--bootable", "no",
                "--manifest-format", "",
                *(["--locale", state.config.locale] if state.config.locale else []),
                *(["--locale-messages", state.config.locale_messages] if state.config.locale_messages else []),
                *(["--keymap", state.config.keymap] if state.config.keymap else []),
                *(["--timezone", state.config.timezone] if state.config.timezone else []),
                *(["--hostname", state.config.hostname] if state.config.hostname else []),
                *(["--root-password", rootpwopt] if rootpwopt else []),
                *(["-f"] * state.args.force),
                "build",
            ])

            config = presets[0]
            unlink_output(args, config)
            build_image(args, config)

            initrds = [config.output_dir / config.output]

    for kver, kimg in gen_kernel_images(state):
        with complete_step(f"Generating unified kernel image for {kimg}"):
            image_id = state.config.image_id or f"mkosi-{state.config.distribution}"

            # See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/#boot-counting
            boot_count = ""
            if (state.root / "etc/kernel/tries").exists():
                boot_count = f'+{(state.root / "etc/kernel/tries").read_text().strip()}'

            if state.config.image_version:
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}_{state.config.image_version}-{kver}{boot_count}.efi"
            elif roothash:
                _, _, h = roothash.partition("=")
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}-{kver}-{h}{boot_count}.efi"
            else:
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}-{kver}{boot_count}.efi"

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

            stub = state.root / f"usr/lib/systemd/boot/efi/linux{state.config.architecture.to_efi()}.efi.stub"
            if not stub.exists():
                die(f"sd-stub not found at /{stub.relative_to(state.root)} in the image")

            cmd: list[PathString] = [
                shutil.which("ukify") or "/usr/lib/systemd/ukify",
                "--cmdline", f"@{state.workspace / 'cmdline'}",
                "--os-release", f"@{state.root / 'usr/lib/os-release'}",
                "--stub", stub,
                "--output", boot_binary,
                "--efi-arch", state.config.architecture.to_efi(),
            ]

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

            if state.config.kernel_modules_initrd:
                kmods = state.workspace / f"initramfs-kernel-modules-{kver}.img"

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

                cmd += ["--initrd", kmods]

            # Make sure the parent directory where we'll be writing the UKI exists.
            with umask(~0o700):
                boot_binary.parent.mkdir(parents=True, exist_ok=True)

            run(cmd)

            if not (state.staging / state.config.output_split_uki).exists():
                shutil.copy(boot_binary, state.staging / state.config.output_split_uki)

            print_output_size(boot_binary)

    if state.config.bootable == ConfigFeature.enabled and not (state.staging / state.config.output_split_uki).exists():
        die("A bootable image was requested but no kernel was found")


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

        run(
            cmdline,
            # Do not output warnings about keyring permissions
            stderr=subprocess.DEVNULL,
            env={
                # Set the path of the keyring to use based on the environment
                # if possible and fallback to the default path. Without this the
                # keyring for the root user will instead be used which will fail
                # for a non-root build.
                "GNUPGHOME": os.environ.get(
                    "GNUPGHOME",
                    os.fspath(((Path(os.environ["HOME"]) / ".gnupg"))),
                )
            },
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


def save_manifest(state: MkosiState, manifest: Manifest) -> None:
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
        if config.output_dir.exists():
            for p in config.output_dir.iterdir():
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
    Make sure all the inputs that aren't checked during config parsing because they might be created by an
    earlier preset exist.
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
        if f and (config.output_dir / f).exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def configure_ssh(state: MkosiState) -> None:
    if not state.config.ssh:
        return

    with umask(~0o644):
        (state.root / "usr/lib/systemd/system/ssh.socket").write_text(
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

        (state.root / "usr/lib/systemd/system/ssh@.service").write_text(
            dedent(
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

        presetdir = state.root / "usr/lib/systemd/system-preset"
        (presetdir / "80-mkosi-ssh.preset").write_text("enable ssh.socket\n")


def configure_initrd(state: MkosiState) -> None:
    if not (state.root / "init").exists() and (state.root / "usr/lib/systemd/systemd").exists():
        (state.root / "init").symlink_to("/usr/lib/systemd/systemd")

    if not state.config.make_initrd:
        return

    if not (state.root / "etc/initrd-release").exists():
        (state.root / "etc/initrd-release").symlink_to("/etc/os-release")


def run_depmod(state: MkosiState) -> None:
    if state.config.bootable == ConfigFeature.disabled:
        return

    for kver, _ in gen_kernel_images(state):
        process_kernel_modules(
            state.root, kver,
            state.config.kernel_modules_include,
            state.config.kernel_modules_exclude,
        )

        with complete_step(f"Running depmod for {kver}"):
            run(["depmod", "--all", "--basedir", state.root, kver])


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


def need_build_packages(config: MkosiConfig) -> bool:
    return config.build_script is not None and len(config.build_packages) > 0


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

        if need_build_packages(state.config) and (state.workspace / "build-overlay").exists():
            rmtree(build)
            move_tree(state.config, state.workspace / "build-overlay", build)

        manifest.write_text(json.dumps(state.config.cache_manifest()))


def reuse_cache(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    final, build, manifest = cache_tree_paths(state.config)
    if not final.exists() or (need_build_packages(state.config) and not build.exists()):
        return False

    if manifest.exists():
        prev = json.loads(manifest.read_text())
        if prev != state.config.cache_manifest():
            return False
    else:
        return False

    with complete_step("Copying cached trees"):
        copy_tree(state.config, final, state.root)
        if need_build_packages(state.config):
            (state.workspace / "build-overlay").symlink_to(build)

    return True


def make_image(state: MkosiState, skip: Sequence[str] = [], split: bool = False) -> tuple[Optional[str], list[Path]]:
    if not state.config.output_format == OutputFormat.disk:
        return None, []

    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--no-pager",
        "--offline=yes",
        "--root", state.root,
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

    if state.config.repart_dirs:
        for d in state.config.repart_dirs:
            cmdline += ["--definitions", d]
    else:
        definitions = state.workspace / "repart-definitions"
        if not definitions.exists():
            definitions.mkdir()
            bootdir = state.root / "efi/EFI/BOOT"

            # If Bootable=auto and we have at least one UKI and a bootloader, let's generate an ESP partition.
            add = (state.config.bootable == ConfigFeature.enabled or
                  (state.config.bootable == ConfigFeature.auto and
                   bootdir.exists() and
                   any(bootdir.iterdir()) and
                   any(gen_kernel_images(state))))

            if add:
                (definitions / "00-esp.conf").write_text(
                    dedent(
                        """\
                        [Partition]
                        Type=esp
                        Format=vfat
                        CopyFiles=/efi:/
                        SizeMinBytes=512M
                        SizeMaxBytes=512M
                        """
                    )
                )

            (definitions / "10-root.conf").write_text(
                dedent(
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

    split_paths = [Path(p["split_path"]) for p in output if p.get("split_path", "-") != "-"]

    return f"roothash={roothash}" if roothash else f"usrhash={usrhash}" if usrhash else None, split_paths


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
        move_tree(state.config, f, state.config.output_dir)


def build_image(args: MkosiArgs, config: MkosiConfig) -> None:
    manifest = Manifest(config)
    workspace = tempfile.TemporaryDirectory(dir=config.workspace_dir or Path.cwd(), prefix=".mkosi-tmp")

    # Make sure tmpfiles' aging doesn't interfere with our workspace
    # while we are working on it.
    with workspace, scopedenv({"TMPDIR" : workspace.name}):
        state = MkosiState(args, config, Path(workspace.name))
        install_package_manager_trees(state)

        with mount_image(state):
            install_base_trees(state)
            install_skeleton_trees(state)
            cached = reuse_cache(state)

            state.config.distribution.setup(state)

            if not cached:
                with mount_cache_overlay(state):
                    install_distribution(state)
                    run_prepare_script(state, build=False)
                    install_build_packages(state)
                    run_prepare_script(state, build=True)

                save_cache(state)
                reuse_cache(state)

            run_build_script(state)

            if state.config.output_format == OutputFormat.none:
                # Touch an empty file to indicate the image was built.
                (state.staging / state.config.output).touch()
                finalize_staging(state)
                return

            install_build_dest(state)
            install_extra_trees(state)
            run_postinst_script(state)

            configure_autologin(state)
            configure_initrd(state)
            configure_ssh(state)

            install_boot_loader(state)
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
            run_finalize_script(state)
            run_selinux_relabel(state)

        roothash, _ = make_image(state, skip=("esp", "xbootldr"))
        install_unified_kernel(state, roothash)
        _, split_paths = make_image(state, split=True)

        for p in split_paths:
            maybe_compress(state.config, state.config.compress_output, p)

        if state.config.output_format == OutputFormat.tar:
            make_tar(state.root, state.staging / state.config.output_with_format)
        elif state.config.output_format == OutputFormat.cpio:
            make_cpio(state.root, state.staging / state.config.output_with_format)
        elif state.config.output_format == OutputFormat.directory:
            state.root.rename(state.staging / state.config.output_with_format)

        maybe_compress(state.config, state.config.compress_output,
                       state.staging / state.config.output_with_format,
                       state.staging / state.config.output_with_compression)

        copy_nspawn_settings(state)
        calculate_sha256sum(state)
        calculate_signature(state)
        save_manifest(state, manifest)

        finalize_staging(state)

        output_base = state.config.output_dir / state.config.output
        if not output_base.exists() or output_base.is_symlink():
            output_base.unlink(missing_ok=True)
            output_base.symlink_to(state.config.output_with_compression)

    print_output_size(config.output_dir / config.output)


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
            stack.enter_context(acl_maybe_toggle(config, config.output_dir / config.output, uid, always=True))

        yield


@contextlib.contextmanager
def acl_toggle_boot(config: MkosiConfig, uid: int) -> Iterator[None]:
    if not config.acl or config.output_format != OutputFormat.directory:
        yield
        return

    with acl_maybe_toggle(config, config.output_dir / config.output, uid, always=False):
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
    cmdline += ["--machine", (config.image_id or config.preset or config.output).replace("_", "-")]

    for k, v in config.credentials.items():
        cmdline += [f"--set-credential={k}:{v}"]

    with contextlib.ExitStack() as stack:
        if config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir / config.output))
        else:
            fname = config.output_dir / config.output

        if config.output_format == OutputFormat.disk and args.verb == Verb.boot:
            run(["systemd-repart",
                 "--image", fname,
                 "--size", "8G",
                 "--no-pager",
                 "--dry-run=no",
                 "--offline=no",
                 fname])

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]

            owner = os.stat(fname).st_uid
            if owner != 0:
                cmdline += [f"--private-users={str(owner)}"]
        else:
            cmdline += ["--image", fname]

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
    """Serve the output directory via a tiny embedded HTTP server"""

    port = 8081

    if config.output_dir is not None:
        os.chdir(config.output_dir)

    with http.server.HTTPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Serving HTTP on port {port}: http://localhost:{port}/")
        httpd.serve_forever()


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
        dedent(
            f"""
            The keys will expire in {args.genkey_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    cmd: list[PathString] = [
        "openssl", "req",
        "-new",
        "-x509",
        "-newkey", f"rsa:{keylength}",
        "-keyout", "mkosi.key",
        "-out", "mkosi.crt",
        "-days", str(args.genkey_valid_days),
        "-subj", f"/CN={cn}/",
        "-nodes",
    ]
    run(cmd)


def bump_image_version(uid: int = -1, gid: int = -1) -> None:
    """Write current image version plus one to mkosi.version"""
    assert bool(uid) == bool(gid)

    version = Path("mkosi.version").read_text().strip()
    v = version.split(".")

    try:
        m = int(v[-1])
    except ValueError:
        new_version = version + ".2"
        logging.info(
            f"Last component of current version is not a decimal integer, appending '.2', bumping '{version}' → '{new_version}'."
        )
    else:
        new_version = ".".join(v[:-1] + [str(m + 1)])
        logging.info(f"Increasing last component of version by one, bumping '{version}' → '{new_version}'.")

    Path("mkosi.version").write_text(f"{new_version}\n")
    os.chown("mkosi.version", uid, gid)


def expand_specifier(s: str) -> str:
    return s.replace("%u", InvokingUser.name())


def needs_build(args: MkosiArgs, config: MkosiConfig) -> bool:
    return args.verb.needs_build() and (args.force > 0 or not (config.output_dir / config.output_with_compression).exists())


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


def run_verb(args: MkosiArgs, presets: Sequence[MkosiConfig]) -> None:
    if args.verb.needs_root() and os.getuid() != 0:
        die(f"Must be root to run the {args.verb} command")

    if args.verb == Verb.genkey:
        return generate_key_cert_pair(args)

    if args.verb == Verb.bump:
        return bump_image_version()

    if args.verb == Verb.summary:
        text = ""

        for config in presets:
            text += f"{summary(args, config)}\n"

        page(text, args.pager)
        return

    last = presets[-1]

    if args.verb == Verb.qemu and last.output_format in (
        OutputFormat.directory,
        OutputFormat.tar,
    ):
        die(f"{last.output_format} images cannot be booted in qemu.")

    if args.verb in (Verb.shell, Verb.boot):
        opname = "acquire shell in" if args.verb == Verb.shell else "boot"
        if last.output_format in (OutputFormat.tar, OutputFormat.cpio):
            die(f"Sorry, can't {opname} a {last.output_format} archive.")
        if last.compress_output:
            die(f"Sorry, can't {opname} a compressed image.")

    for config in presets:
        if args.verb == Verb.build and not args.force:
            check_outputs(config)

    # Because we overmount /usr when using a tools tree, we need to make sure we load all python modules we
    # might end up using before overmounting /usr. Any modules that might be dynamically loaded during
    # execution are forcibly loaded early here.
    try_import("importlib.readers")
    try_import("importlib.resources.readers")
    for config in presets:
        try_import(f"mkosi.distributions.{config.distribution}")

    name = InvokingUser.name()

    # Get the user UID/GID either on the host or in the user namespace running the build
    uid, gid = become_root()
    init_mount_namespace()

    # For extra safety when running as root, remount a bunch of stuff read-only.
    for d in ("/usr", "/etc", "/opt", "/srv", "/boot", "/efi", "/media", "/mnt"):
        if Path(d).exists():
            run(["mount", "--rbind", d, d, "--options", "ro"])

    # First, process all directory removals because otherwise if different presets share directories a later
    # preset could end up output generated by an earlier preset.

    for config in presets:
        if not needs_build(args, config) and args.verb != Verb.clean:
            continue

        unlink_output(args, config)

    if args.verb == Verb.clean:
        return

    build = False

    for config in presets:
        check_inputs(config)

        if not needs_build(args, config):
            continue

        with complete_step(f"Building {config.preset or 'default'} image"),\
            mount_usr(config.tools_tree),\
            prepend_to_environ_path(config):

            # Create these as the invoking user to make sure they're owned by the user running mkosi.
            for p in (
                config.output_dir,
                config.cache_dir,
                config.build_dir,
                config.workspace_dir,
            ):
                if p:
                    run(["mkdir", "--parents", p], user=uid, group=gid)

            with acl_toggle_build(config, uid):
                build_image(args, config)

            # Make sure all build outputs that are not directories are owned by the user running mkosi.
            for p in config.output_dir.iterdir():
                if not p.is_dir():
                    os.chown(p, uid, gid, follow_symlinks=False)

            build = True

    if build and args.auto_bump:
        bump_image_version(uid, gid)

    if args.verb == Verb.build:
        return

    # We want to drop privileges after mounting the last tools tree, but to unmount it we still need
    # privileges. To avoid a permission error, let's not unmount the final tools tree, since we'll exit
    # right after (and we're in a mount namespace so the /usr mount disappears when we exit)
    with mount_usr(last.tools_tree, umount=False), mount_passwd(name, uid, gid, umount=False):

        # After mounting the last tools tree, if we're not going to execute systemd-nspawn, we don't need to
        # be (fake) root anymore, so switch user to the invoking user.
        if args.verb not in (Verb.shell, Verb.boot):
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)

        with prepend_to_environ_path(last):
            if args.verb in (Verb.shell, Verb.boot):
                with acl_toggle_boot(last, uid):
                    run_shell(args, last)

            if args.verb == Verb.qemu:
                run_qemu(args, last)

            if args.verb == Verb.ssh:
                run_ssh(args, last)

            if args.verb == Verb.serve:
                run_serve(last)
