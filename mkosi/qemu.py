# SPDX-License-Identifier: LGPL-2.1+

import asyncio
import base64
import contextlib
import enum
import hashlib
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.config import (
    ConfigFeature,
    MkosiArgs,
    MkosiConfig,
    OutputFormat,
    QemuFirmware,
    format_bytes,
)
from mkosi.log import die
from mkosi.partition import finalize_root, find_partitions
from mkosi.run import MkosiAsyncioThread, run, spawn
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import (
    INVOKING_USER,
    StrEnum,
    qemu_check_kvm_support,
    qemu_check_vsock_support,
)


class QemuDeviceNode(StrEnum):
    vhost_vsock = enum.auto()


def machine_cid(config: MkosiConfig) -> int:
    cid = int.from_bytes(hashlib.sha256(config.output_with_version.encode()).digest()[:4], byteorder='little')
    # Make sure we don't return any of the well-known CIDs.
    return max(3, min(cid, 0xFFFFFFFF - 1))


def find_qemu_binary(config: MkosiConfig) -> str:
    binaries = ["qemu", "qemu-kvm"] if config.architecture.is_native() else []
    binaries += [f"qemu-system-{config.architecture.to_qemu()}"]
    for binary in binaries:
        if shutil.which(binary) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_ovmf_firmware(config: MkosiConfig) -> tuple[Path, bool]:
    FIRMWARE_LOCATIONS = {
        Architecture.x86_64: ["/usr/share/ovmf/x64/OVMF_CODE.secboot.fd"],
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
        OVMF_VARS_LOCATIONS += ["/usr/share/ovmf/x64/OVMF_VARS.fd"]
    elif config.architecture == Architecture.x86:
        OVMF_VARS_LOCATIONS += [
            "/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd",
            "/usr/share/OVMF/OVMF32_VARS_4M.fd",
        ]
    elif config.architecture == Architecture.arm:
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF32_VARS.fd"]
    elif config.architecture == Architecture.arm64:
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF_VARS.fd"]

    OVMF_VARS_LOCATIONS += ["/usr/share/edk2/ovmf/OVMF_VARS.fd",
                            "/usr/share/edk2-ovmf/OVMF_VARS.fd",
                            "/usr/share/qemu/OVMF_VARS.fd",
                            "/usr/share/ovmf/OVMF_VARS.fd",
                            "/usr/share/OVMF/OVMF_VARS.fd"]

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

            proc = spawn(cmdline, user=INVOKING_USER.uid, group=INVOKING_USER.gid, pass_fds=(sock.fileno(),))

            try:
                yield path
            finally:
                proc.terminate()
                proc.wait()


@contextlib.contextmanager
def start_virtiofsd(directory: Path, *, uidmap: bool) -> Iterator[Path]:
    virtiofsd = shutil.which("virtiofsd")
    if virtiofsd is None:
        if Path("/usr/libexec/virtiofsd").exists():
            virtiofsd = "/usr/libexec/virtiofsd"
        elif Path("/usr/lib/virtiofsd").exists():
            virtiofsd = "/usr/lib/virtiofsd"
        else:
            die("virtiofsd must be installed to use RuntimeMounts= with mkosi qemu")

    cmdline: list[PathString] = [
        virtiofsd,
        "--shared-dir", directory,
        "--xattr",
        "--posix-acl",
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
        tempfile.TemporaryDirectory(prefix="mkosi-virtiofsd") as state,\
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock\
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
        proc = spawn(
            cmdline,
            user=INVOKING_USER.uid if uidmap else None,
            group=INVOKING_USER.gid if uidmap else None,
            pass_fds=(sock.fileno(),)
        )

        try:
            yield path
        finally:
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


@contextlib.contextmanager
def copy_ephemeral(config: MkosiConfig, src: Path) -> Iterator[Path]:
    src = src.resolve()
    # tempfile doesn't provide an API to get a random filename in an arbitrary directory so we do this
    # instead.
    tmp = src.parent / f"{src.name}-{uuid.uuid4().hex}"

    try:
        copy_tree(config, src, tmp)
        yield tmp
    finally:
        rmtree(tmp)


def run_qemu(args: MkosiArgs, config: MkosiConfig, qemu_device_fds: Mapping[QemuDeviceNode, int]) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.cpio, OutputFormat.uki, OutputFormat.directory):
        die(f"{config.output_format} images cannot be booted in qemu")

    if (
        config.output_format in (OutputFormat.cpio, OutputFormat.uki) and
        config.qemu_firmware not in (QemuFirmware.auto, QemuFirmware.linux, QemuFirmware.uefi)
    ):
        die(f"{config.output_format} images cannot be booted with the '{config.qemu_firmware}' firmware")

    if (config.runtime_trees and config.qemu_firmware == QemuFirmware.bios):
        die("RuntimeTrees= cannot be used when booting in BIOS firmware")

    accel = "tcg"
    auto = (
        config.qemu_kvm == ConfigFeature.auto and
        config.architecture.is_native() and
        qemu_check_kvm_support(log=True)
    )
    if config.qemu_kvm == ConfigFeature.enabled or auto:
        accel = "kvm"

    if config.qemu_firmware == QemuFirmware.auto:
        if config.output_format in (OutputFormat.cpio, OutputFormat.directory) or config.architecture.to_efi() is None:
            firmware = QemuFirmware.linux
        else:
            firmware = QemuFirmware.uefi
    else:
        firmware = config.qemu_firmware

    ovmf, ovmf_supports_sb = find_ovmf_firmware(config) if firmware == QemuFirmware.uefi else (None, False)

    # A shared memory backend might increase ram usage so only add one if actually necessary for virtiofsd.
    shm = []
    if config.runtime_trees or config.output_format == OutputFormat.directory:
        shm = ["-object", f"memory-backend-memfd,id=mem,size={config.qemu_mem},share=on"]

    if config.architecture == Architecture.arm64:
        machine = f"type=virt,accel={accel}"
    else:
        machine = f"type=q35,accel={accel},smm={'on' if ovmf_supports_sb else 'off'}"

    if shm:
        machine += ",memory-backend=mem"

    cmdline: list[PathString] = [
        find_qemu_binary(config),
        "-machine", machine,
        "-smp", config.qemu_smp,
        "-m", config.qemu_mem,
        "-object", "rng-random,filename=/dev/urandom,id=rng0",
        "-device", "virtio-rng-pci,rng=rng0,id=rng-device0",
        "-nic", "user,model=virtio-net-pci",
        *shm,
    ]

    use_vsock = (config.qemu_vsock == ConfigFeature.enabled or
                (config.qemu_vsock == ConfigFeature.auto and qemu_check_vsock_support(log=True)))
    if use_vsock:
        cmdline += [
            "-device",
            f"vhost-vsock-pci,guest-cid={machine_cid(config)},vhostfd={qemu_device_fds[QemuDeviceNode.vhost_vsock]}"
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

    if firmware == QemuFirmware.linux or config.output_format in (OutputFormat.cpio, OutputFormat.uki):
        kcl = config.kernel_command_line + config.kernel_command_line_extra
    elif config.architecture.supports_smbios():
        kcl = config.kernel_command_line_extra
    else:
        kcl = []

    notifications: dict[str, str] = {}

    with contextlib.ExitStack() as stack:
        for src, target in config.runtime_trees:
            sock = stack.enter_context(start_virtiofsd(src, uidmap=True))
            cmdline += [
                "-chardev", f"socket,id={sock.name},path={sock}",
                "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag={sock.name}",
            ]
            kcl += [f"systemd.mount-extra={sock.name}:{target or f'/root/src/{src.name}'}:virtiofs"]

        if config.architecture.supports_smbios():
            for k, v in config.credentials.items():
                payload = base64.b64encode(v.encode()).decode()
                cmdline += [
                    "-smbios", f"type=11,value=io.systemd.credential.binary:{k}={payload}"
                ]

            cmdline += [
                "-smbios",
                f"type=11,value=io.systemd.stub.kernel-cmdline-extra={' '.join(kcl)}"
            ]

        if firmware == QemuFirmware.uefi and ovmf_supports_sb:
            ovmf_vars = stack.enter_context(tempfile.NamedTemporaryFile(prefix="mkosi-ovmf-vars"))
            shutil.copy2(find_ovmf_vars(config), Path(ovmf_vars.name))
            # Make sure qemu can access the ephemeral vars.
            os.chown(ovmf_vars.name, INVOKING_USER.uid, INVOKING_USER.gid)
            cmdline += [
                "-global", "ICH9-LPC.disable_s3=1",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-drive", f"file={ovmf_vars.name},if=pflash,format=raw",
            ]

        if config.qemu_cdrom and config.output_format == OutputFormat.disk:
            # CD-ROM devices have sector size 2048 so we transform the disk image into one with sector size 2048.
            src = (config.output_dir_or_cwd() / config.output).resolve()
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
        elif config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = config.output_dir_or_cwd() / config.output

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
            firmware == QemuFirmware.linux or
            config.output_format in (OutputFormat.cpio, OutputFormat.uki, OutputFormat.directory)
        ):
            if config.output_format == OutputFormat.uki:
                kernel = fname if firmware == QemuFirmware.uefi else config.output_dir_or_cwd() / config.output_split_kernel
            elif config.qemu_kernel:
                kernel = config.qemu_kernel
            elif "-kernel" not in args.cmdline:
                if firmware == QemuFirmware.uefi:
                    kernel = config.output_dir_or_cwd() / config.output_split_uki
                else:
                    kernel = config.output_dir_or_cwd() / config.output_split_kernel
                if not kernel.exists():
                    die(
                        f"Kernel or UKI not found at {kernel}, please install a kernel in the image "
                        "or provide a -kernel argument to mkosi qemu"
                    )
            else:
                kernel = None

            if kernel:
                cmdline += ["-kernel", kernel]

            if config.output_format == OutputFormat.disk:
                # We can't rely on gpt-auto-generator when direct kernel booting so synthesize a root=
                # kernel argument instead.
                root = finalize_root(find_partitions(fname))
                if not root:
                    die("Cannot perform a direct kernel boot without a root or usr partition")
            elif config.output_format == OutputFormat.directory:
                sock = stack.enter_context(start_virtiofsd(fname, uidmap=False))
                cmdline += [
                    "-chardev", f"socket,id={sock.name},path={sock}",
                    "-device", f"vhost-user-fs-pci,queue-size=1024,chardev={sock.name},tag=root",
                ]
                root = "root=root rootfstype=virtiofs rw"
            else:
                root = ""

            cmdline += ["-append", " ".join([root] + kcl)]

        if config.output_format == OutputFormat.cpio:
            cmdline += ["-initrd", fname]
        elif (
            firmware == QemuFirmware.linux and
            config.output_format in (OutputFormat.uki, OutputFormat.directory, OutputFormat.disk) and
            (config.output_dir_or_cwd() / config.output_split_initrd).exists()
        ):
            cmdline += ["-initrd", config.output_dir_or_cwd() / config.output_split_initrd]

        if config.output_format == OutputFormat.disk:
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

        if use_vsock and config.architecture.supports_smbios():
            addr, notifications = stack.enter_context(vsock_notify_handler())
            cmdline += ["-smbios", f"type=11,value=io.systemd.credential:vmm.notify_socket={addr}"]

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
        ) as qemu:
            # We have to close these before we wait for qemu otherwise we'll deadlock as qemu will never exit.
            for fd in qemu_device_fds.values():
                os.close(fd)

            qemu.wait()

    if status := int(notifications.get("EXIT_STATUS", 0)):
        raise subprocess.CalledProcessError(status, cmdline)


def run_ssh(args: MkosiArgs, config: MkosiConfig) -> None:
    cmd = [
        "ssh",
        "-F", "none",
        # Silence known hosts file errors/warnings.
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "LogLevel=ERROR",
        "-o", f"ProxyCommand=socat - VSOCK-CONNECT:{machine_cid(config)}:%p",
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
