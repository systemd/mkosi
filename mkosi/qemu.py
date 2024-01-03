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
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Optional

from mkosi.config import (
    Architecture,
    ConfigFeature,
    MkosiArgs,
    MkosiConfig,
    OutputFormat,
    QemuFirmware,
    QemuVsockCID,
    format_bytes,
)
from mkosi.log import die
from mkosi.mounts import mount_passwd
from mkosi.partition import finalize_root, find_partitions
from mkosi.run import (
    MkosiAsyncioThread,
    become_root,
    find_binary,
    fork_and_wait,
    run,
    spawn,
)
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import INVOKING_USER, StrEnum
from mkosi.versioncomp import GenericVersion

QEMU_KVM_DEVICE_VERSION = GenericVersion("8.3")
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

    def feature(self, config: MkosiConfig) -> ConfigFeature:
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


def hash_output(config: MkosiConfig) -> "hashlib._Hash":
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


def find_unused_vsock_cid(config: MkosiConfig, vfd: int) -> int:
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
    def identify(cls, path: PathString) -> "KernelType":
        type = run(["bootctl", "kernel-identify", path], stdout=subprocess.PIPE).stdout.strip()

        try:
            return cls(type)
        except ValueError:
            logging.warning(f"Unknown kernel type '{type}', assuming 'unknown'")
            return KernelType.unknown


def find_qemu_binary(config: MkosiConfig) -> str:
    binaries = ["qemu", "qemu-kvm"] if config.architecture.is_native() else []
    binaries += [f"qemu-system-{config.architecture.to_qemu()}"]
    for binary in binaries:
        if shutil.which(binary) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_ovmf_firmware(config: MkosiConfig) -> tuple[Path, bool]:
    FIRMWARE_LOCATIONS = {
        Architecture.x86_64: [
            "/usr/share/ovmf/x64/OVMF_CODE.secboot.fd",
            "/usr/share/qemu/ovmf-x86_64.smm.bin",
        ],
        Architecture.x86: [
            "/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd",
            "/usr/share/OVMF/OVMF32_CODE_4M.secboot.fd"
        ],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = {
        Architecture.x86_64: [
            "/usr/share/ovmf/ovmf_code_x64.bin",
            "/usr/share/ovmf/x64/OVMF_CODE.fd",
            "/usr/share/qemu/ovmf-x86_64.bin",
        ],
        Architecture.x86: ["/usr/share/ovmf/ovmf_code_ia32.bin", "/usr/share/edk2/ovmf-ia32/OVMF_CODE.fd"],
        Architecture.arm64: ["/usr/share/AAVMF/AAVMF_CODE.fd"],
        Architecture.arm: ["/usr/share/AAVMF/AAVMF32_CODE.fd"],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            logging.warning("Couldn't find OVMF firmware blob with secure boot support, "
                            "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    # If we can't find an architecture specific path, fall back to some generic paths that might also work.

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.secboot.fd",
        "/usr/share/qemu/OVMF_CODE.secboot.fd",
        "/usr/share/ovmf/OVMF.secboot.fd",
        "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
        "/usr/share/OVMF/OVMF_CODE.secboot.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.fd",
        "/usr/share/qemu/OVMF_CODE.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            logging.warn("Couldn't find OVMF firmware blob with secure boot support, "
                         "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    die("Couldn't find OVMF UEFI firmware blob.")


def find_ovmf_vars(config: MkosiConfig) -> Path:
    OVMF_VARS_LOCATIONS = []

    if config.architecture == Architecture.x86_64:
        OVMF_VARS_LOCATIONS += [
            "/usr/share/ovmf/x64/OVMF_VARS.fd",
            "/usr/share/qemu/ovmf-x86_64-vars.bin",
        ]
    elif config.architecture == Architecture.x86:
        OVMF_VARS_LOCATIONS += [
            "/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd",
            "/usr/share/OVMF/OVMF32_VARS_4M.fd",
        ]
    elif config.architecture == Architecture.arm:
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF32_VARS.fd"]
    elif config.architecture == Architecture.arm64:
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF_VARS.fd"]

    OVMF_VARS_LOCATIONS += [
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        "/usr/share/edk2-ovmf/OVMF_VARS.fd",
        "/usr/share/qemu/OVMF_VARS.fd",
        "/usr/share/ovmf/OVMF_VARS.fd",
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
        "/usr/share/OVMF/OVMF_VARS.fd",
    ]

    for location in OVMF_VARS_LOCATIONS:
        if os.path.exists(location):
            return Path(location)

    die("Couldn't find OVMF UEFI variables file.")


@contextlib.contextmanager
def start_swtpm() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mkosi-swtpm") as state:
        # Make sure qemu can access the swtpm socket in this directory.
        os.chown(state, INVOKING_USER.uid, INVOKING_USER.gid)

        cmdline = [
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate", f"dir={state}",
        ]

        # We create the socket ourselves and pass the fd to swtpm to avoid race conditions where we start qemu before
        # swtpm has had the chance to create the socket (or where we try to chown it first).
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            path = Path(state) / Path("sock")
            sock.bind(os.fspath(path))
            sock.listen()

            # Make sure qemu can connect to the swtpm socket.
            os.chown(path, INVOKING_USER.uid, INVOKING_USER.gid)

            cmdline += ["--ctrl", f"type=unixio,fd={sock.fileno()}"]

            with spawn(
                cmdline,
                user=INVOKING_USER.uid,
                group=INVOKING_USER.gid,
                pass_fds=(sock.fileno(),)
            ) as proc:
                try:
                    yield path
                finally:
                    proc.terminate()
                    proc.wait()


def find_virtiofsd() -> Optional[Path]:
    if p := find_binary("virtiofsd"):
        return p

    if (p := Path("/usr/libexec/virtiofsd")).exists():
        return p

    if (p := Path("/usr/lib/virtiofsd")).exists():
        return p

    return None


@contextlib.contextmanager
def start_virtiofsd(directory: Path, *, uidmap: bool) -> Iterator[Path]:
    virtiofsd = find_virtiofsd()
    if virtiofsd is None:
        die("virtiofsd must be installed to boot directory images or use RuntimeTrees= with mkosi qemu")

    cmdline: list[PathString] = [
        virtiofsd,
        "--shared-dir", directory,
        "--xattr",
        # qemu's client doesn't seem to support announcing submounts so disable the feature to avoid the warning.
        "--no-announce-submounts",
    ]

    # Map the given user/group to root in the virtual machine for the virtiofs instance to make sure all files
    # created by root in the VM are owned by the user running mkosi on the host.
    if uidmap:
        cmdline += [
            "--uid-map", f":0:{INVOKING_USER.uid}:1:",
            "--gid-map", f":0:{INVOKING_USER.gid}:1:"
        ]

    # We create the socket ourselves and pass the fd to virtiofsd to avoid race conditions where we start qemu
    # before virtiofsd has had the chance to create the socket (or where we try to chown it first).
    with (
        tempfile.TemporaryDirectory(prefix="mkosi-virtiofsd") as state,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock,
    ):
        # Make sure qemu can access the virtiofsd socket in this directory.
        os.chown(state, INVOKING_USER.uid, INVOKING_USER.gid)

        # Make sure we can use the socket name as a unique identifier for the fs as well but make sure it's not too
        # long as virtiofs tag names are limited to 36 bytes.
        path = Path(state) / f"sock-{uuid.uuid4().hex}"[:35]
        sock.bind(os.fspath(path))
        sock.listen()

        # Make sure qemu can connect to the virtiofsd socket.
        os.chown(path, INVOKING_USER.uid, INVOKING_USER.gid)

        cmdline += ["--fd", str(sock.fileno())]

        # virtiofsd has to run unprivileged to use the --uid-map and --gid-map options, so run it as the given
        # user/group if those are provided.
        with spawn(
            cmdline,
            user=INVOKING_USER.uid if uidmap else None,
            group=INVOKING_USER.gid if uidmap else None,
            pass_fds=(sock.fileno(),),
            preexec_fn=become_root if not uidmap and os.getuid() != 0 else None,
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

        with MkosiAsyncioThread(notify()):
            yield f"vsock-stream:{socket.VMADDR_CID_HOST}:{vsock.getsockname()[1]}", messages

        logging.debug(f"Received {num_messages} notify messages totalling {format_bytes(num_bytes)} bytes")
        for k, v in messages.items():
            logging.debug(f"- {k}={v}")


@contextlib.contextmanager
def copy_ephemeral(config: MkosiConfig, src: Path) -> Iterator[Path]:
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
                preserve_owner=config.output_format == OutputFormat.directory,
                use_subvolumes=config.use_subvolumes
            )

        fork_and_wait(copy)
        yield tmp
    finally:
        def rm() -> None:
            if config.output_format == OutputFormat.directory:
                become_root()

            rmtree(tmp)

        fork_and_wait(rm)


def qemu_version(config: MkosiConfig) -> GenericVersion:
    return GenericVersion(run([find_qemu_binary(config), "--version"], stdout=subprocess.PIPE).stdout.split()[3])


def run_qemu(args: MkosiArgs, config: MkosiConfig, qemu_device_fds: Mapping[QemuDeviceNode, int]) -> None:
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
            firmware = QemuFirmware.uefi if KernelType.identify(kernel) != KernelType.unknown else QemuFirmware.linux
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
        if (
            os.getuid() == 0 and
            not INVOKING_USER.invoked_as_root and
            config.runtime_trees
        ):
            # In this scenario newuidmap might fail when invoked by virtiofsd as the user running virtiofsd will not
            # be resolvable to a name via NSS so we have to trick newuidmap by mounting over /etc/passwd. Once
            # https://gitlab.com/virtio-fs/virtiofsd/-/issues/137 is fixed we can set up the user namespace ourselves
            # without uidmap to avoid having to mount over /etc/passwd.
            stack.enter_context(mount_passwd())

        if firmware == QemuFirmware.uefi:
            ovmf_vars = stack.enter_context(tempfile.NamedTemporaryFile(prefix="mkosi-ovmf-vars"))
            shutil.copy2(config.qemu_firmware_variables or find_ovmf_vars(config), Path(ovmf_vars.name))
            # Make sure qemu can access the ephemeral vars.
            os.chown(ovmf_vars.name, INVOKING_USER.uid, INVOKING_USER.gid)
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
            run(["systemd-repart",
                 "--definitions", "",
                 "--no-pager",
                 "--pretty=no",
                 "--offline=yes",
                 "--empty=create",
                 "--size=auto",
                 "--sector-size=2048",
                 "--copy-from", src,
                 fname])
            stack.callback(lambda: fname.unlink())
        elif config.ephemeral and config.output_format not in (OutputFormat.cpio, OutputFormat.uki):
            fname = stack.enter_context(
                copy_ephemeral(config, config.output_dir_or_cwd() / config.output_with_compression)
            )
        else:
            fname = config.output_dir_or_cwd() / config.output_with_compression

        # Make sure qemu can access the ephemeral copy. Not required for directory output because we don't pass that
        # directly to qemu, but indirectly via virtiofsd.
        if config.output_format != OutputFormat.directory:
            os.chown(fname, INVOKING_USER.uid, INVOKING_USER.gid)

        if config.output_format == OutputFormat.disk and config.runtime_size:
            run(["systemd-repart",
                 "--definitions", "",
                 "--no-pager",
                 f"--size={config.runtime_size}",
                 "--pretty=no",
                 "--offline=yes",
                 fname])

        if (
            kernel and
            (KernelType.identify(kernel) != KernelType.uki or not config.architecture.supports_smbios(firmware))
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
                os.fchown(f.fileno(), INVOKING_USER.uid, INVOKING_USER.gid)
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
                root = finalize_root(find_partitions(fname))
                if not root:
                    die("Cannot perform a direct kernel boot without a root or usr partition")

                kcl += [root]
            elif config.output_format == OutputFormat.directory:
                sock = stack.enter_context(start_virtiofsd(fname, uidmap=False))
                cmdline += [
                    "-chardev", f"socket,id={sock.name},path={sock}",
                    "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag=root",
                ]
                kcl += ["root=root", "rootfstype=virtiofs", "rw"]

        for tree in config.runtime_trees:
            sock = stack.enter_context(start_virtiofsd(tree.source, uidmap=True))
            cmdline += [
                "-chardev", f"socket,id={sock.name},path={sock}",
                "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag={sock.name}",
            ]
            target = Path("/root/src") / (tree.target or tree.source.name)
            kcl += [f"systemd.mount-extra={sock.name}:{target}:virtiofs"]

        if (
            kernel and
            (KernelType.identify(kernel) != KernelType.uki or not config.architecture.supports_smbios(firmware))
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
            kernel and KernelType.identify(kernel) != KernelType.uki and
            "-initrd" not in args.cmdline and
            (config.output_dir_or_cwd() / config.output_split_initrd).exists()
        ):
            cmdline += ["-initrd", config.output_dir_or_cwd() / config.output_split_initrd]

        if config.output_format in (OutputFormat.disk, OutputFormat.esp):
            cmdline += ["-drive", f"if=none,id=mkosi,file={fname},format=raw",
                        "-device", "virtio-scsi-pci,id=scsi",
                        "-device", f"scsi-{'cd' if config.qemu_cdrom else 'hd'},drive=mkosi,bootindex=1"]

        if (
            firmware == QemuFirmware.uefi and
            config.qemu_swtpm != ConfigFeature.disabled and
            shutil.which("swtpm") is not None
        ):
            sock = stack.enter_context(start_swtpm())
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
            os.chown(file.name, INVOKING_USER.uid, INVOKING_USER.gid)

            arg = f"if=none,id={drive.id},file={file.name},format=raw"
            if drive.options:
                arg += f",{drive.options}"

            cmdline += ["-drive", arg]

        cmdline += config.qemu_args
        cmdline += args.cmdline

        with spawn(
            cmdline,
            # On Debian/Ubuntu, only users in the kvm group can access /dev/kvm. The invoking user might be part of the
            # kvm group, but the user namespace fake root user will definitely not be. Thus, we have to run qemu as the
            # invoking user to make sure we can access /dev/kvm. Of course, if we were invoked as root, none of this
            # matters as the root user will always be able to access /dev/kvm.
            user=INVOKING_USER.uid if not INVOKING_USER.invoked_as_root else None,
            group=INVOKING_USER.gid if not INVOKING_USER.invoked_as_root else None,
            stdin=sys.stdin,
            stdout=sys.stdout,
            pass_fds=qemu_device_fds.values(),
            env=os.environ,
            log=False,
            foreground=True,
        ) as qemu:
            # We have to close these before we wait for qemu otherwise we'll deadlock as qemu will never exit.
            for fd in qemu_device_fds.values():
                os.close(fd)

            qemu.wait()

    if status := int(notifications.get("EXIT_STATUS", 0)):
        raise subprocess.CalledProcessError(status, cmdline)


def run_ssh(args: MkosiArgs, config: MkosiConfig) -> None:
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
        user=INVOKING_USER.uid,
        group=INVOKING_USER.gid,
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ,
        log=False,
    )
