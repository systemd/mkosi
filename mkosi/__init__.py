# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import dataclasses
import datetime
import hashlib
import http.server
import importlib.resources
import itertools
import json
import logging
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, ContextManager, Mapping, Optional, TextIO, Union

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
    OutputFormat,
    SecureBootSignTool,
    Verb,
    format_source_target,
    parse_config,
    summary,
)
from mkosi.install import add_dropin_config_from_resource
from mkosi.installer import clean_package_manager_metadata, package_manager_scripts
from mkosi.kmod import gen_required_kernel_modules, process_kernel_modules
from mkosi.log import ARG_DEBUG, complete_step, die, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import mount_overlay, mount_passwd, mount_usr
from mkosi.pager import page
from mkosi.qemu import copy_ephemeral, run_qemu, run_ssh
from mkosi.run import become_root, bwrap, chroot_cmd, init_mount_namespace, run
from mkosi.state import MkosiState
from mkosi.tree import copy_tree, install_tree, move_tree, rmtree
from mkosi.types import _FILE, CompletedProcess, PathString
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


@dataclasses.dataclass(frozen=True)
class Partition:
    type: str
    uuid: str
    partno: Optional[int]
    split_path: Optional[Path]
    roothash: Optional[str]

    @classmethod
    def from_dict(cls, dict: Mapping[str, Any]) -> "Partition":
        return cls(
            type=dict["type"],
            uuid=dict["uuid"],
            partno=int(partno) if (partno := dict.get("partno")) else None,
            split_path=Path(p) if ((p := dict.get("split_path")) and p != "-") else None,
            roothash=dict.get("roothash"),
        )

    GRUB_BOOT_PARTITION_UUID = "21686148-6449-6e6f-744e-656564454649"


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

            # Some distributions install EFI binaries directly to /boot/efi. Let's redirect them to /efi
            # instead.
            rmtree(state.root / "boot/efi")
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
    )

    if build:
        with complete_step("Running prepare script in build overlay…"), mount_build_overlay(state):
            bwrap(
                [state.config.prepare_script, "build"],
                network=True,
                readonly=True,
                options=finalize_mounts(state.config),
                scripts={"mkosi-chroot": chroot} | package_manager_scripts(state),
                env=env | state.config.environment,
                stdin=sys.stdin,
            )
    else:
        with complete_step("Running prepare script…"):
            bwrap(
                [state.config.prepare_script, "final"],
                network=True,
                readonly=True,
                options=finalize_mounts(state.config),
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
    )

    with complete_step("Running build script…"), mount_build_overlay(state):
        bwrap(
            [state.config.build_script],
            network=state.config.with_network,
            readonly=True,
            options=finalize_mounts(state.config),
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
    )

    with complete_step("Running postinstall script…"):
        bwrap(
            [state.config.postinst_script, "final"],
            network=state.config.with_network,
            readonly=True,
            options=finalize_mounts(state.config),
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
    )

    with complete_step("Running finalize script…"):
        bwrap(
            [state.config.finalize_script],
            network=state.config.with_network,
            readonly=True,
            options=finalize_mounts(state.config),
            scripts={"mkosi-chroot": chroot} | package_manager_scripts(state),
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
    path = ":".join(os.fspath(p) for p in [state.root / "usr/bin", state.root / "usr/sbin"])

    assert "grub" in binary and not "grub2" in binary

    path = shutil.which(binary, path=path) or shutil.which(binary.replace("grub", "grub2"), path=path)
    if not path:
        return None

    return Path("/") / Path(path).relative_to(state.root)


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

    root = finalize_roothash(partitions)
    if not root:
        root = next((f"root=PARTUUID={p.uuid}" for p in partitions if p.type.startswith("root")), None)
    if not root:
        root = next((f"mount.usr=PARTUUID={p.uuid}" for p in partitions if p.type.startswith("usr")), None)

    assert root

    initrd = build_initrd(state)

    dst = state.root / "efi" / state.config.distribution.name
    with umask(~0o700):
        dst.mkdir(exist_ok=True)

    initrd = Path(shutil.copy2(initrd, dst / "initrd"))

    with config.open("a") as f:
        f.write('if [ "${grub_platform}" == "pc" ]; then\n')

        for kver, kimg in gen_kernel_images(state):
            kdst = dst / kver
            with umask(~0o700):
                kdst.mkdir(exist_ok=True)

            kmods = build_kernel_modules_initrd(state, kver)

            with umask(~0o600):
                kimg = Path(shutil.copy2(state.root / kimg, kdst / "vmlinuz"))
                kmods = Path(shutil.copy2(kmods, kdst / "kmods"))

                f.write(
                    textwrap.dedent(
                        f"""\
                        menuentry "{state.config.distribution}-{kver}" {{
                            linux /{kimg.relative_to(state.root / "efi")} {root} {" ".join(state.config.kernel_command_line)}
                            initrd /{initrd.relative_to(state.root / "efi")} /{kmods.relative_to(state.root / "efi")}
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
        yield kver.name, Path("usr/lib/modules") / kver.name / "vmlinuz"


def build_initrd(state: MkosiState) -> Path:
    symlink = state.workspace / "initrd"
    if symlink.exists():
        return symlink.resolve()

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
        "--output-dir", str(state.config.output_dir),
        "--workspace-dir", str(state.config.workspace_dir),
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
        "--output", f"{state.config.output}-initrd",
        *(["--image-version", state.config.image_version] if state.config.image_version else []),
        "--make-initrd", "yes",
        "--bootable", "no",
        "--manifest-format", "",
        *(["--source-date-epoch", str(state.config.source_date_epoch)] if state.config.source_date_epoch is not None else []),
        *(["--locale", state.config.locale] if state.config.locale else []),
        *(["--locale-messages", state.config.locale_messages] if state.config.locale_messages else []),
        *(["--keymap", state.config.keymap] if state.config.keymap else []),
        *(["--timezone", state.config.timezone] if state.config.timezone else []),
        *(["--hostname", state.config.hostname] if state.config.hostname else []),
        *(["--root-password", rootpwopt] if rootpwopt else []),
        *(["-f"] * state.args.force),
        "build",
    ]

    with complete_step("Building initrd"):
        args, [config] = parse_config(cmdline)
        unlink_output(args, config)
        build_image(args, config)

    symlink.symlink_to(config.output_dir / config.output)

    return symlink


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


def finalize_roothash(partitions: Sequence[Partition]) -> Optional[str]:
    roothash = usrhash = None

    for p in partitions:
        if (h := p.roothash) is None:
            continue

        if not (p.type.startswith("usr") or p.type.startswith("root")):
            die(f"Found roothash property on unexpected partition type {p.type}")

        # When there's multiple verity enabled root or usr partitions, the first one wins.
        if p.type.startswith("usr"):
            usrhash = usrhash or h
        else:
            roothash = roothash or h

    return f"roothash={roothash}" if roothash else f"usrhash={usrhash}" if usrhash else None


def install_unified_kernel(state: MkosiState, partitions: Sequence[Partition]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if state.config.bootable == ConfigFeature.disabled:
        return

    if state.config.bootloader == Bootloader.none:
        return

    for kver, kimg in gen_kernel_images(state):
        shutil.copy(state.root / kimg, state.staging / state.config.output_split_kernel)
        break

    if state.config.output_format == OutputFormat.cpio and state.config.bootable == ConfigFeature.auto:
        return

    roothash = finalize_roothash(partitions)
    initrds = []

    if state.config.initrds:
        initrds = state.config.initrds
    elif any(gen_kernel_images(state)):
        initrds = [build_initrd(state)]

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

            if state.config.kernel_modules_initrd:
                cmd += ["--initrd", build_kernel_modules_initrd(state, kver)]

            # Make sure the parent directory where we'll be writing the UKI exists.
            with umask(~0o700):
                boot_binary.parent.mkdir(parents=True, exist_ok=True)

            run(cmd)

            if not (state.staging / state.config.output_split_uki).exists():
                shutil.copy(boot_binary, state.staging / state.config.output_split_uki)

                # ukify will have signed the kernel image as well. Let's make sure we put the signed kernel
                # image in the output directory instead of the unsigned one by reading it from the UKI.

                # When using a tools tree, we want to use the pefile module from the tools tree instead of
                # requiring that python-pefile is installed on the host. So we execute python as a subprocess
                # to make sure we load pefile from the tools tree if one is used.

                # TODO: Use ignore_padding=True instead of length once we can depend on a newer pefile.
                pefile = textwrap.dedent(
                    f"""\
                    import pefile
                    from pathlib import Path
                    pe = pefile.PE("{boot_binary}", fast_load=True)
                    linux = {{s.Name.decode().strip("\\0"): s for s in pe.sections}}[".linux"]
                    (Path("{state.root}") / "{state.config.output_split_kernel}").write_bytes(linux.get_data(length=linux.Misc_VirtualSize))
                    """
                )

                # If there's no tools tree, prefer the interpreter from MKOSI_INTERPRETER. If there is a
                # tools tree, just use the default python3 interpreter.
                python = "python3" if state.config.tools_tree else os.getenv("MKOSI_INTERPRETER", "python3")

                run([python], input=pefile)

            print_output_size(boot_binary)

            if state.config.bootloader == Bootloader.uki:
                break

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

        # Set the path of the keyring to use based on the environment if possible and fallback to the default
        # path. Without this the keyring for the root user will instead be used which will fail for a
        # non-root build.
        env = dict(GNUPGHOME=os.environ.get("GNUPGHOME", os.fspath(((Path(os.environ["HOME"]) / ".gnupg")))))
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
    if not (state.root / "init").exists() and (state.root / "usr/lib/systemd/systemd").exists():
        (state.root / "init").symlink_to("/usr/lib/systemd/systemd")

    if not state.config.make_initrd:
        return

    if not (state.root / "etc/initrd-release").exists():
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
            bootloader = state.root / f"efi/EFI/BOOT/BOOT{state.config.architecture.to_efi().upper()}.EFI"

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

            esp = (state.config.bootable == ConfigFeature.enabled or
                  (state.config.bootable == ConfigFeature.auto and bootloader.exists()))

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
        move_tree(state.config, f, state.config.output_dir)


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
    workspace = tempfile.TemporaryDirectory(dir=config.workspace_dir, prefix=".mkosi-tmp")

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
            run_finalize_script(state)

        normalize_mtime(state.root, state.config.source_date_epoch)
        partitions = make_image(state, skip=("esp", "xbootldr"))
        install_unified_kernel(state, partitions)
        prepare_grub_efi(state)
        prepare_grub_bios(state, partitions)
        normalize_mtime(state.root, state.config.source_date_epoch, directory=Path("boot"))
        normalize_mtime(state.root, state.config.source_date_epoch, directory=Path("efi"))
        partitions = make_image(state)
        install_grub_bios(state, partitions)
        make_image(state, split=True)

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
                 fname],
                 stdin=sys.stdin)

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

    if args.verb == Verb.documentation:
        return show_docs(args)

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

    invoked_as_root = os.getuid() == 0
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
        # be (fake) root anymore, so switch user to the invoking user. If we're going to invoke qemu and
        # mkosi was executed as root, we also don't drop privileges as depending on the environment and
        # options passed, running qemu might need root privileges as well.
        if not args.verb.needs_root() and (args.verb != Verb.qemu or not invoked_as_root):
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
