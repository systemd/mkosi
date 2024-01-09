# SPDX-License-Identifier: LGPL-2.1+

import asyncio
import base64
import contextlib
import enum
import errno
import fcntl
import hashlib
import logging
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

from mkosi.config import (
    Architecture,
    Args,
    Config,
    ConfigFeature,
    OutputFormat,
    QemuFirmware,
    QemuVsockCID,
    format_bytes,
    want_selinux_relabel,
)
from mkosi.log import die
from mkosi.partition import finalize_root, find_partitions
from mkosi.run import AsyncioThread, become_root, find_binary, fork_and_wait, run, spawn
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import INVOKING_USER, StrEnum
from mkosi.versioncomp import GenericVersion

QEMU_KVM_DEVICE_VERSION = GenericVersion("9.0")
VHOST_VSOCK_SET_GUEST_CID = 0x4008af60


class QemuDeviceNode(StrEnum):
    kvm = enum.auto()
    vhost_vsock = enum.auto()

    def device(self) -> Path:
        return Path("/dev") / str(self)

    def description(self) -> str:
        return {
            QemuDeviceNode.kvm: "KVM acceleration",
            QemuDeviceNode.vhost_vsock: "a VSock device",
        }[self]

    def feature(self, config: Config) -> ConfigFeature:
        return {
            QemuDeviceNode.kvm: config.qemu_kvm,
            QemuDeviceNode.vhost_vsock: config.qemu_vsock,
        }[self]

    def open(self) -> int:
        return os.open(self.device(), os.O_RDWR|os.O_CLOEXEC|os.O_NONBLOCK)

    def available(self, log: bool = False) -> bool:
        try:
            os.close(self.open())
        except OSError as e:
            if e.errno not in (errno.ENOENT, errno.EPERM, errno.EACCES):
                raise e

            if log and e.errno == errno.ENOENT:
                logging.warning(f"{self.device()} not found. Not adding {self.description()} to the virtual machine.")

            if log and e.errno in (errno.EPERM, errno.EACCES):
                logging.warning(
                    f"Permission denied to access {self.device()}. "
                    f"Not adding {self.description()} to the virtual machine. "
                    "(Maybe a kernel module could not be loaded?)"
                )

            return False

        return True


def hash_output(config: Config) -> "hashlib._Hash":
    p = os.fspath(config.output_dir_or_cwd() / config.output_with_compression)
    return hashlib.sha256(p.encode())


def hash_to_vsock_cid(hash: "hashlib._Hash") -> int:
    cid = int.from_bytes(hash.digest()[:4], byteorder='little')
    # Make sure we don't return any of the well-known CIDs.
    return max(3, min(cid, 0xFFFFFFFF - 1))


def vsock_cid_in_use(vfd: int, cid: int) -> bool:
    try:
        fcntl.ioctl(vfd, VHOST_VSOCK_SET_GUEST_CID, struct.pack("=Q", cid))
    except OSError as e:
        if e.errno != errno.EADDRINUSE:
            raise

        return True

    return False


def find_unused_vsock_cid(config: Config, vfd: int) -> int:
    hash = hash_output(config)

    for i in range(64):
        cid = hash_to_vsock_cid(hash)

        if not vsock_cid_in_use(vfd, cid):
            return cid

        hash.update(i.to_bytes(length=4, byteorder='little'))

    for i in range(64):
        cid = random.randint(0, 0xFFFFFFFF - 1)

        if not vsock_cid_in_use(vfd, cid):
            return cid

    die("Failed to find an unused VSock connection ID")


class KernelType(StrEnum):
    pe      = enum.auto()
    uki     = enum.auto()
    unknown = enum.auto()

    @classmethod
    def identify(cls, config: Config, path: Path) -> "KernelType":
        type = run(["bootctl", "kernel-identify", path],
                   stdout=subprocess.PIPE, sandbox=config.sandbox(options=["--ro-bind", path, path])).stdout.strip()

        try:
            return cls(type)
        except ValueError:
            logging.warning(f"Unknown kernel type '{type}', assuming 'unknown'")
            return KernelType.unknown


def find_qemu_binary(config: Config) -> str:
    binaries = ["qemu", "qemu-kvm"] if config.architecture.is_native() else []
    binaries += [f"qemu-system-{config.architecture.to_qemu()}"]
    for binary in binaries:
        if find_binary(binary, root=config.tools()) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_ovmf_firmware(config: Config) -> tuple[Path, bool]:
    FIRMWARE_LOCATIONS = {
        Architecture.x86_64: [
            "usr/share/ovmf/x64/OVMF_CODE.secboot.fd",
            "usr/share/qemu/ovmf-x86_64.smm.bin",
            "usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
            "usr/share/edk2/x64/OVMF_CODE.secboot.fd",
        ],
        Architecture.x86: [
            "usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd",
            "usr/share/OVMF/OVMF32_CODE_4M.secboot.fd",
            "usr/share/edk2/ia32/OVMF_CODE.secboot.4m.fd",
            "usr/share/edk2/ia32/OVMF_CODE.secboot.fd",
        ],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if (config.tools() / firmware).exists():
            return Path("/") / firmware, True

    FIRMWARE_LOCATIONS = {
        Architecture.x86_64: [
            "usr/share/ovmf/ovmf_code_x64.bin",
            "usr/share/ovmf/x64/OVMF_CODE.fd",
            "usr/share/qemu/ovmf-x86_64.bin",
            "usr/share/edk2/x64/OVMF_CODE.4m.fd",
            "usr/share/edk2/x64/OVMF_CODE.fd",
        ],
        Architecture.x86: [
            "usr/share/ovmf/ovmf_code_ia32.bin",
            "usr/share/edk2/ovmf-ia32/OVMF_CODE.fd",
            "usr/share/edk2/ia32/OVMF_CODE.4m.fd",
            "usr/share/edk2/ia32/OVMF_CODE.fd",
        ],
        Architecture.arm64: ["usr/share/AAVMF/AAVMF_CODE.fd"],
        Architecture.arm: ["usr/share/AAVMF/AAVMF32_CODE.fd"],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if (config.tools() / firmware).exists():
            logging.warning("Couldn't find OVMF firmware blob with secure boot support, "
                            "falling back to OVMF firmware blobs without secure boot support.")
            return Path("/") / firmware, False

    # If we can't find an architecture specific path, fall back to some generic paths that might also work.

    FIRMWARE_LOCATIONS = [
        "usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "usr/share/edk2-ovmf/OVMF_CODE.secboot.fd",
        "usr/share/qemu/OVMF_CODE.secboot.fd",
        "usr/share/ovmf/OVMF.secboot.fd",
        "usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
        "usr/share/OVMF/OVMF_CODE.secboot.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if (config.tools() / firmware).exists():
            return Path("/") / firmware, True

    FIRMWARE_LOCATIONS = [
        "usr/share/edk2/ovmf/OVMF_CODE.fd",
        "usr/share/edk2-ovmf/OVMF_CODE.fd",
        "usr/share/qemu/OVMF_CODE.fd",
        "usr/share/ovmf/OVMF.fd",
        "usr/share/OVMF/OVMF_CODE_4M.fd",
        "usr/share/OVMF/OVMF_CODE.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if (config.tools() / firmware).exists():
            logging.warn("Couldn't find OVMF firmware blob with secure boot support, "
                         "falling back to OVMF firmware blobs without secure boot support.")
            return Path("/") / firmware, False

    die("Couldn't find OVMF UEFI firmware blob.")


def find_ovmf_vars(config: Config) -> Path:
    OVMF_VARS_LOCATIONS = []

    if config.architecture == Architecture.x86_64:
        OVMF_VARS_LOCATIONS += [
            "usr/share/ovmf/x64/OVMF_VARS.fd",
            "usr/share/qemu/ovmf-x86_64-vars.bin",
            "usr/share/edk2/x64/OVMF_VARS.4m.fd",
            "usr/share/edk2/x64/OVMF_VARS.fd",
        ]
    elif config.architecture == Architecture.x86:
        OVMF_VARS_LOCATIONS += [
            "usr/share/edk2/ovmf-ia32/OVMF_VARS.fd",
            "usr/share/OVMF/OVMF32_VARS_4M.fd",
            "usr/share/edk2/ia32/OVMF_VARS.4m.fd",
            "usr/share/edk2/ia32/OVMF_VARS.fd",
        ]
    elif config.architecture == Architecture.arm:
        OVMF_VARS_LOCATIONS += ["usr/share/AAVMF/AAVMF32_VARS.fd"]
    elif config.architecture == Architecture.arm64:
        OVMF_VARS_LOCATIONS += ["usr/share/AAVMF/AAVMF_VARS.fd"]

    OVMF_VARS_LOCATIONS += [
        "usr/share/edk2/ovmf/OVMF_VARS.fd",
        "usr/share/edk2-ovmf/OVMF_VARS.fd",
        "usr/share/qemu/OVMF_VARS.fd",
        "usr/share/ovmf/OVMF_VARS.fd",
        "usr/share/OVMF/OVMF_VARS_4M.fd",
        "usr/share/OVMF/OVMF_VARS.fd",
    ]

    for location in OVMF_VARS_LOCATIONS:
        if (config.tools() / location).exists():
            return config.tools() / location

    die("Couldn't find OVMF UEFI variables file.")


@contextlib.contextmanager
def start_swtpm(config: Config) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mkosi-swtpm") as state:
        cmdline = ["swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}"]

        # We create the socket ourselves and pass the fd to swtpm to avoid race conditions where we start qemu before
        # swtpm has had the chance to create the socket (or where we try to chown it first).
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            path = Path(state) / Path("sock")
            sock.bind(os.fspath(path))
            sock.listen()

            cmdline += ["--ctrl", f"type=unixio,fd={sock.fileno()}"]

            with spawn(
                cmdline,
                pass_fds=(sock.fileno(),),
                sandbox=config.sandbox(options=["--bind", state, state]),
            ) as proc:
                try:
                    yield path
                finally:
                    proc.terminate()
                    proc.wait()


def find_virtiofsd(*, tools: Path = Path("/")) -> Optional[Path]:
    if p := find_binary("virtiofsd", root=tools):
        return p

    if (p := tools / "usr/libexec/virtiofsd").exists():
        return Path("/") / p.relative_to(tools)

    if (p := tools / "usr/lib/virtiofsd").exists():
        return Path("/") / p.relative_to(tools)

    return None


@contextlib.contextmanager
def start_virtiofsd(config: Config, directory: Path, *, uidmap: bool) -> Iterator[Path]:
    virtiofsd = find_virtiofsd(tools=config.tools())
    if virtiofsd is None:
        die("virtiofsd must be installed to boot directory images or use RuntimeTrees= with mkosi qemu")

    cmdline: list[PathString] = [
        virtiofsd,
        "--shared-dir", directory,
        "--xattr",
        # qemu's client doesn't seem to support announcing submounts so disable the feature to avoid the warning.
        "--no-announce-submounts",
        "--sandbox=chroot",
    ]

    if not uidmap and want_selinux_relabel(config, directory, fatal=False):
        cmdline += ["--security-label"]

    # We create the socket ourselves and pass the fd to virtiofsd to avoid race conditions where we start qemu
    # before virtiofsd has had the chance to create the socket (or where we try to chown it first).
    with (
        tempfile.TemporaryDirectory(prefix="mkosi-virtiofsd") as context,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock,
    ):
        # Make sure virtiofsd can access the socket in this directory.
        os.chown(context, INVOKING_USER.uid, INVOKING_USER.gid)

        # Make sure we can use the socket name as a unique identifier for the fs as well but make sure it's not too
        # long as virtiofs tag names are limited to 36 bytes.
        path = Path(context) / f"sock-{uuid.uuid4().hex}"[:35]
        sock.bind(os.fspath(path))
        sock.listen()

        # Make sure virtiofsd can connect to the socket.
        os.chown(path, INVOKING_USER.uid, INVOKING_USER.gid)

        cmdline += ["--fd", str(sock.fileno())]

        with spawn(
            cmdline,
            pass_fds=(sock.fileno(),),
            # When not invoked as root, bubblewrap will automatically map the current uid/gid to the requested uid/gid
            # in the user namespace it spawns, so by specifying --uid 0 --gid 0 we'll get a userns with the current
            # uid/gid mapped to root in the userns. --cap-add=all is required to make virtiofsd work. Since it drops
            # capabilities itself, we don't bother figuring out the exact set of capabilities it needs.
            user=INVOKING_USER.uid if uidmap else None,
            group=INVOKING_USER.gid if uidmap else None,
            preexec_fn=become_root if not uidmap else None,
            sandbox=config.sandbox(
                options=[
                    "--uid", "0",
                    "--gid", "0",
                    "--cap-add", "all",
                    "--bind", directory, directory,
                ],
            ),
        ) as proc:
            try:
                yield path
            finally:
                proc.terminate()
                proc.wait()


@contextlib.contextmanager
def vsock_notify_handler() -> Iterator[tuple[str, dict[str, str]]]:
    """
    This yields a vsock address and a dict that will be filled in with the notifications from the VM. The
    dict should only be accessed after the context manager has been finalized.
    """
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as vsock:
        vsock.bind((socket.VMADDR_CID_ANY, socket.VMADDR_PORT_ANY))
        vsock.listen()
        vsock.setblocking(False)

        num_messages = 0
        num_bytes = 0
        messages = {}

        async def notify() -> None:
            nonlocal num_messages
            nonlocal num_bytes
            loop = asyncio.get_running_loop()

            while True:
                s, _ = await loop.sock_accept(vsock)

                num_messages += 1

                with s:
                    data = []
                    try:
                        while (buf := await loop.sock_recv(s, 4096)):
                            data.append(buf)
                    except ConnectionResetError:
                        logging.debug("vsock notify listener connection reset by peer")

                for msg in b"".join(data).decode().split("\n"):
                    if not msg:
                        continue

                    num_bytes += len(msg)
                    k, _, v = msg.partition("=")
                    messages[k] = v

        with AsyncioThread(notify()):
            yield f"vsock-stream:{socket.VMADDR_CID_HOST}:{vsock.getsockname()[1]}", messages

        logging.debug(f"Received {num_messages} notify messages totalling {format_bytes(num_bytes)} bytes")
        for k, v in messages.items():
            logging.debug(f"- {k}={v}")


@contextlib.contextmanager
def copy_ephemeral(config: Config, src: Path) -> Iterator[Path]:
    src = src.resolve()
    # tempfile doesn't provide an API to get a random filename in an arbitrary directory so we do this
    # instead.
    tmp = src.parent / f"{src.name}-{uuid.uuid4().hex}"

    try:
        def copy() -> None:
            if config.output_format == OutputFormat.directory:
                become_root()

            copy_tree(
                src, tmp,
                preserve=config.output_format == OutputFormat.directory,
                use_subvolumes=config.use_subvolumes,
                tools=config.tools(),
                sandbox=config.sandbox(options=["--ro-bind", src, src, "--bind", tmp.parent, tmp.parent]),
            )

        fork_and_wait(copy)
        yield tmp
    finally:
        def rm() -> None:
            if config.output_format == OutputFormat.directory:
                become_root()

            rmtree(tmp, sandbox=config.sandbox(options=["--ro-bind", src, src, "--bind", tmp.parent, tmp.parent]))

        fork_and_wait(rm)


def qemu_version(config: Config) -> GenericVersion:
    return GenericVersion(run([find_qemu_binary(config), "--version"],
                              stdout=subprocess.PIPE, sandbox=config.sandbox()).stdout.split()[3])


def want_scratch(config: Config) -> bool:
    return config.runtime_scratch == ConfigFeature.enabled or (
        config.runtime_scratch == ConfigFeature.auto and
        find_binary(f"mkfs.{config.distribution.filesystem()}", root=config.tools()) is not None
    )


def run_qemu(args: Args, config: Config) -> None:
    if config.output_format not in (
        OutputFormat.disk,
        OutputFormat.cpio,
        OutputFormat.uki,
        OutputFormat.esp,
        OutputFormat.directory,
    ):
        die(f"{config.output_format} images cannot be booted in qemu")

    if (
        config.output_format in (OutputFormat.cpio, OutputFormat.uki, OutputFormat.esp) and
        config.qemu_firmware not in (QemuFirmware.auto, QemuFirmware.linux, QemuFirmware.uefi)
    ):
        die(f"{config.output_format} images cannot be booted with the '{config.qemu_firmware}' firmware")

    if (config.runtime_trees and config.qemu_firmware == QemuFirmware.bios):
        die("RuntimeTrees= cannot be used when booting in BIOS firmware")

    if config.qemu_kvm == ConfigFeature.enabled and not config.architecture.is_native():
        die(f"KVM acceleration requested but {config.architecture} does not match the native host architecture")

    # After we unshare the user namespace to sandbox qemu, we might not have access to /dev/kvm or related device nodes
    # anymore as access to these might be gated behind the kvm group and we won't be part of the kvm group anymore
    # after unsharing the user namespace. To get around this, open all those device nodes early can pass them as file
    # descriptors to qemu later. Note that we can't pass the kvm file descriptor to qemu until version 9.0.
    qemu_device_fds = {
        d: d.open()
        for d in QemuDeviceNode
        if d.feature(config) != ConfigFeature.disabled and d.available(log=True)
    }

    have_kvm = ((qemu_version(config) < QEMU_KVM_DEVICE_VERSION and QemuDeviceNode.kvm.available()) or
                (qemu_version(config) >= QEMU_KVM_DEVICE_VERSION and QemuDeviceNode.kvm in qemu_device_fds))
    if (config.qemu_kvm == ConfigFeature.enabled and not have_kvm):
        die("KVM acceleration requested but cannot access /dev/kvm")

    if config.qemu_vsock == ConfigFeature.enabled and QemuDeviceNode.vhost_vsock not in qemu_device_fds:
        die("VSock requested but cannot access /dev/vhost-vsock")

    if config.qemu_kernel:
        kernel = config.qemu_kernel
    elif "-kernel" in args.cmdline:
        kernel = Path(args.cmdline[args.cmdline.index("-kernel") + 1])
    else:
        kernel = None

    if config.output_format in (OutputFormat.uki, OutputFormat.esp) and kernel:
        logging.warning(
            f"Booting UKI output, kernel {kernel} configured with QemuKernel= or passed with -kernel will not be used"
        )
        kernel = None

    if kernel and not kernel.exists():
        die(f"Kernel not found at {kernel}")

    if config.qemu_firmware == QemuFirmware.auto:
        if kernel:
            firmware = (
                QemuFirmware.uefi
                if KernelType.identify(config, kernel) != KernelType.unknown
                else QemuFirmware.linux
            )
        elif (
            config.output_format in (OutputFormat.cpio, OutputFormat.directory) or
            config.architecture.to_efi() is None
        ):
            firmware = QemuFirmware.linux
        else:
            firmware = QemuFirmware.uefi
    else:
        firmware = config.qemu_firmware

    if (
        not kernel and
        (
            firmware == QemuFirmware.linux or
            config.output_format in (OutputFormat.cpio, OutputFormat.directory, OutputFormat.uki)
        )
    ):
        if firmware == QemuFirmware.uefi:
            name = config.output if config.output_format == OutputFormat.uki else config.output_split_uki
            kernel = config.output_dir_or_cwd() / name
        else:
            kernel = config.output_dir_or_cwd() / config.output_split_kernel
        if not kernel.exists():
            die(
                f"Kernel or UKI not found at {kernel}, please install a kernel in the image "
                "or provide a -kernel argument to mkosi qemu"
            )

    ovmf, ovmf_supports_sb = find_ovmf_firmware(config) if firmware == QemuFirmware.uefi else (None, False)

    # A shared memory backend might increase ram usage so only add one if actually necessary for virtiofsd.
    shm = []
    if config.runtime_trees or config.output_format == OutputFormat.directory:
        shm = ["-object", f"memory-backend-memfd,id=mem,size={config.qemu_mem},share=on"]

    machine = f"type={config.architecture.default_qemu_machine()}"
    if firmware == QemuFirmware.uefi and config.architecture.supports_smm():
        machine += f",smm={'on' if ovmf_supports_sb else 'off'}"
    if shm:
        machine += ",memory-backend=mem"

    cmdline: list[PathString] = [
        find_qemu_binary(config),
        "-machine", machine,
        "-smp", config.qemu_smp,
        "-m", config.qemu_mem,
        "-object", "rng-random,filename=/dev/urandom,id=rng0",
        "-device", "virtio-rng-pci,rng=rng0,id=rng-device0",
        *shm,
    ]

    cmdline += ["-nic", f"user,model={config.architecture.default_qemu_nic_model()}"]

    if config.qemu_kvm != ConfigFeature.disabled and have_kvm and config.architecture.is_native():
        accel = "kvm"
        if qemu_version(config) >= QEMU_KVM_DEVICE_VERSION:
            cmdline += ["--add-fd", f"fd={qemu_device_fds[QemuDeviceNode.kvm]},set=1,opaque=/dev/kvm"]
            accel += ",device=/dev/fdset/1"
    else:
        accel = "tcg"

    cmdline += ["-accel", accel]

    if QemuDeviceNode.vhost_vsock in qemu_device_fds:
        if config.qemu_vsock_cid == QemuVsockCID.auto:
            cid = find_unused_vsock_cid(config, qemu_device_fds[QemuDeviceNode.vhost_vsock])
        elif config.qemu_vsock_cid == QemuVsockCID.hash:
            cid = hash_to_vsock_cid(hash_output(config))
        else:
            cid = config.qemu_vsock_cid

        if vsock_cid_in_use(qemu_device_fds[QemuDeviceNode.vhost_vsock], cid):
            die(f"VSock connection ID {cid} is already in use by another virtual machine",
                hint="Use QemuVsockConnectionId=auto to have mkosi automatically find a free vsock connection ID")

        cmdline += [
            "-device",
            f"vhost-vsock-pci,guest-cid={cid},vhostfd={qemu_device_fds[QemuDeviceNode.vhost_vsock]}"
        ]

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
            "-serial", "chardev:console",
            "-mon", "console",
        ]

    # QEMU has built-in logic to look for the BIOS firmware so we don't need to do anything special for that.
    if firmware == QemuFirmware.uefi:
        cmdline += ["-drive", f"if=pflash,format=raw,readonly=on,file={ovmf}"]
    notifications: dict[str, str] = {}

    with contextlib.ExitStack() as stack:
        if firmware == QemuFirmware.uefi:
            ovmf_vars = stack.enter_context(tempfile.NamedTemporaryFile(prefix="mkosi-ovmf-vars"))
            shutil.copy2(config.qemu_firmware_variables or find_ovmf_vars(config), Path(ovmf_vars.name))
            cmdline += ["-drive", f"file={ovmf_vars.name},if=pflash,format=raw"]
            if ovmf_supports_sb:
                cmdline += [
                    "-global", "ICH9-LPC.disable_s3=1",
                    "-global", "driver=cfi.pflash01,property=secure,value=on",
                ]

        if config.qemu_cdrom and config.output_format in (OutputFormat.disk, OutputFormat.esp):
            # CD-ROM devices have sector size 2048 so we transform disk images into ones with sector size 2048.
            src = (config.output_dir_or_cwd() / config.output_with_compression).resolve()
            fname = src.parent / f"{src.name}-{uuid.uuid4().hex}"
            run(
                [
                    "systemd-repart",
                    "--definitions", "",
                    "--no-pager",
                    "--pretty=no",
                    "--offline=yes",
                    "--empty=create",
                    "--size=auto",
                    "--sector-size=2048",
                    "--copy-from", src,
                    fname,
                ],
                sandbox=config.sandbox(options=["--bind", fname.parent, fname.parent, "--ro-bind", src, src]),
            )
            stack.callback(lambda: fname.unlink())
        elif config.ephemeral and config.output_format not in (OutputFormat.cpio, OutputFormat.uki):
            fname = stack.enter_context(
                copy_ephemeral(config, config.output_dir_or_cwd() / config.output_with_compression)
            )
        else:
            fname = config.output_dir_or_cwd() / config.output_with_compression

        if config.output_format == OutputFormat.disk and config.runtime_size:
            run(
                [
                    "systemd-repart",
                    "--definitions", "",
                    "--no-pager",
                    f"--size={config.runtime_size}",
                    "--pretty=no",
                    "--offline=yes",
                    fname,
                ],
                sandbox=config.sandbox(options=["--bind", fname, fname]),
            )

        if (
            kernel and
            (
                KernelType.identify(config, kernel) != KernelType.uki or
                not config.architecture.supports_smbios(firmware)
            )
        ):
            kcl = config.kernel_command_line + config.kernel_command_line_extra
        else:
            kcl = config.kernel_command_line_extra

        for k, v in config.credentials.items():
            payload = base64.b64encode(v.encode()).decode()
            if config.architecture.supports_smbios(firmware):
                cmdline += ["-smbios", f"type=11,value=io.systemd.credential.binary:{k}={payload}"]
            elif config.architecture.supports_fw_cfg():
                f = stack.enter_context(tempfile.NamedTemporaryFile(prefix="mkosi-fw-cfg", mode="w"))
                f.write(v)
                f.flush()
                cmdline += ["-fw_cfg", f"name=opt/io.systemd.credentials/{k},file={f.name}"]
            elif kernel:
                kcl += [f"systemd.set_credential_binary={k}:{payload}"]

        if kernel:
            cmdline += ["-kernel", kernel]

            if any(s.startswith("root=") for s in kcl):
                pass
            elif config.output_format == OutputFormat.disk:
                # We can't rely on gpt-auto-generator when direct kernel booting so synthesize a root=
                # kernel argument instead.
                root = finalize_root(
                    find_partitions(fname, sandbox=config.sandbox(options=["--ro-bind", fname, fname]))
                )
                if not root:
                    die("Cannot perform a direct kernel boot without a root or usr partition")

                kcl += [root]
            elif config.output_format == OutputFormat.directory:
                sock = stack.enter_context(start_virtiofsd(config, fname, uidmap=False))
                cmdline += [
                    "-chardev", f"socket,id={sock.name},path={sock}",
                    "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag=root",
                ]
                kcl += ["root=root", "rootfstype=virtiofs", "rw"]

        for tree in config.runtime_trees:
            sock = stack.enter_context(start_virtiofsd(config, tree.source, uidmap=True))
            tag = tree.target.name if tree.target else tree.source.name
            cmdline += [
                "-chardev", f"socket,id={sock.name},path={sock}",
                "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag={tag}",
            ]
            target = Path("/root/src") / (tree.target or tree.source.name)
            kcl += [f"systemd.mount-extra={tag}:{target}:virtiofs"]

        if want_scratch(config) or config.output_format in (OutputFormat.disk, OutputFormat.esp):
            cmdline += ["-device", "virtio-scsi-pci,id=scsi"]

        if want_scratch(config):
            scratch = stack.enter_context(tempfile.NamedTemporaryFile(dir="/var/tmp", prefix="mkosi-scratch"))
            scratch.truncate(1024**4)
            run([f"mkfs.{config.distribution.filesystem()}", "-L", "scratch", scratch.name],
                stdout=subprocess.DEVNULL, sandbox=config.sandbox(options=["--bind", scratch.name, scratch.name]))
            cmdline += [
                "-drive", f"if=none,id=scratch,file={scratch.name},format=raw",
                "-device", "scsi-hd,drive=scratch",
            ]
            kcl += [f"systemd.mount-extra=LABEL=scratch:/var/tmp:{config.distribution.filesystem()}"]

        if (
            kernel and
            (
                KernelType.identify(config, kernel) != KernelType.uki or
                not config.architecture.supports_smbios(firmware)
            )
        ):
            cmdline += ["-append", " ".join(kcl)]
        elif config.architecture.supports_smbios(firmware):
            cmdline += [
                "-smbios",
                f"type=11,value=io.systemd.stub.kernel-cmdline-extra={' '.join(kcl)}"
            ]

        if config.output_format == OutputFormat.cpio:
            cmdline += ["-initrd", fname]
        elif (
            kernel and KernelType.identify(config, kernel) != KernelType.uki and
            "-initrd" not in args.cmdline and
            (config.output_dir_or_cwd() / config.output_split_initrd).exists()
        ):
            cmdline += ["-initrd", config.output_dir_or_cwd() / config.output_split_initrd]

        if config.output_format in (OutputFormat.disk, OutputFormat.esp):
            cmdline += ["-drive", f"if=none,id=mkosi,file={fname},format=raw",
                        "-device", f"scsi-{'cd' if config.qemu_cdrom else 'hd'},drive=mkosi,bootindex=1"]

        if (
            firmware == QemuFirmware.uefi and
            config.qemu_swtpm != ConfigFeature.disabled and
            find_binary("swtpm", root=config.tools()) is not None
        ):
            sock = stack.enter_context(start_swtpm(config))
            cmdline += ["-chardev", f"socket,id=chrtpm,path={sock}",
                        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm"]

            if config.architecture == Architecture.x86_64:
                cmdline += ["-device", "tpm-tis,tpmdev=tpm0"]
            elif config.architecture == Architecture.arm64:
                cmdline += ["-device", "tpm-tis-device,tpmdev=tpm0"]

        if QemuDeviceNode.vhost_vsock in qemu_device_fds and config.architecture.supports_smbios(firmware):
            addr, notifications = stack.enter_context(vsock_notify_handler())
            cmdline += ["-smbios", f"type=11,value=io.systemd.credential:vmm.notify_socket={addr}"]

        for drive in config.qemu_drives:
            file = stack.enter_context(
                tempfile.NamedTemporaryFile(dir=drive.directory or "/var/tmp", prefix=f"mkosi-drive-{drive.id}")
            )
            file.truncate(drive.size)

            arg = f"if=none,id={drive.id},file={file.name},format=raw"
            if drive.options:
                arg += f",{drive.options}"

            cmdline += ["-drive", arg]

        cmdline += config.qemu_args
        cmdline += args.cmdline

        with spawn(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            pass_fds=qemu_device_fds.values(),
            env=os.environ,
            log=False,
            foreground=True,
            sandbox=config.sandbox(network=True, devices=True, relaxed=True),
        ) as qemu:
            # We have to close these before we wait for qemu otherwise we'll deadlock as qemu will never exit.
            for fd in qemu_device_fds.values():
                os.close(fd)

            qemu.wait()

    if status := int(notifications.get("EXIT_STATUS", 0)):
        raise subprocess.CalledProcessError(status, cmdline)


def run_ssh(args: Args, config: Config) -> None:
    if config.qemu_vsock_cid == QemuVsockCID.auto:
        die("Can't use ssh verb with QemuVSockCID=auto")

    if not config.ssh_key:
        die("SshKey= must be configured to use 'mkosi ssh'",
            hint="Use 'mkosi genkey' to generate a new SSH key and certificate")

    if config.qemu_vsock_cid == QemuVsockCID.hash:
        cid = hash_to_vsock_cid(hash_output(config))
    else:
        cid = config.qemu_vsock_cid

    cmd: list[PathString] = [
        "ssh",
        "-i", config.ssh_key,
        "-F", "none",
        # Silence known hosts file errors/warnings.
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "LogLevel=ERROR",
        "-o", f"ProxyCommand=socat - VSOCK-CONNECT:{cid}:%p",
        "root@mkosi",
    ]

    cmd += args.cmdline

    run(
        cmd,
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ,
        log=False,
        sandbox=config.sandbox(network=True, devices=True, relaxed=True),
    )
