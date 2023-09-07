# SPDX-License-Identifier: LGPL-2.1+

import asyncio
import base64
import contextlib
import hashlib
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Iterator, Optional

from mkosi.architecture import Architecture
from mkosi.config import (
    ConfigFeature,
    MkosiArgs,
    MkosiConfig,
    OutputFormat,
    QemuFirmware,
)
from mkosi.log import die
from mkosi.run import MkosiAsyncioThread, run, spawn
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import format_bytes, qemu_check_kvm_support, qemu_check_vsock_support


def machine_cid(config: MkosiConfig) -> int:
    cid = int.from_bytes(hashlib.sha256(config.output_with_version.encode()).digest()[:4], byteorder='little')
    # Make sure we don't return any of the well-known CIDs.
    return max(3, min(cid, 0xFFFFFFFF - 1))


def find_qemu_binary(config: MkosiConfig) -> str:
    binaries = ["qemu", "qemu-kvm", f"qemu-system-{config.architecture.to_qemu()}"]
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
def start_swtpm() -> Iterator[Optional[Path]]:
    with tempfile.TemporaryDirectory() as state:
        sock = Path(state) / Path("sock")
        proc = spawn([
            "swtpm",
            "socket",
            "--tpm2",
            "--tpmstate", f"dir={state}",
            "--ctrl", f"type=unixio,path={sock}"
        ])

        try:
            yield sock
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


def run_qemu(args: MkosiArgs, config: MkosiConfig) -> None:
    accel = "tcg"
    auto = config.qemu_kvm == ConfigFeature.auto and config.architecture.is_native() and qemu_check_kvm_support(log=True)
    if config.qemu_kvm == ConfigFeature.enabled or auto:
        accel = "kvm"

    ovmf, ovmf_supports_sb = find_ovmf_firmware(config)
    smm = "on" if config.qemu_firmware == QemuFirmware.uefi and ovmf_supports_sb else "off"

    if config.architecture == Architecture.arm64:
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

    use_vsock = (config.qemu_vsock == ConfigFeature.enabled or
                (config.qemu_vsock == ConfigFeature.auto and qemu_check_vsock_support(log=True)))
    if use_vsock:
        cmdline += ["-device", f"vhost-vsock-pci,guest-cid={machine_cid(config)}"]

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

    for k, v in config.credentials.items():
        cmdline += ["-smbios", f"type=11,value=io.systemd.credential.binary:{k}={base64.b64encode(v.encode()).decode()}"]
    cmdline += ["-smbios", f"type=11,value=io.systemd.stub.kernel-cmdline-extra={' '.join(config.kernel_command_line_extra)}"]

    # QEMU has built-in logic to look for the BIOS firmware so we don't need to do anything special for that.
    if config.qemu_firmware == QemuFirmware.uefi:
        cmdline += ["-drive", f"if=pflash,format=raw,readonly=on,file={ovmf}"]

    notifications: dict[str, str] = {}

    with contextlib.ExitStack() as stack:
        if config.qemu_firmware == QemuFirmware.uefi and ovmf_supports_sb:
            ovmf_vars = stack.enter_context(tempfile.NamedTemporaryFile(prefix=".mkosi-"))
            shutil.copy2(find_ovmf_vars(config), Path(ovmf_vars.name))
            cmdline += [
                "-global", "ICH9-LPC.disable_s3=1",
                "-global", "driver=cfi.pflash01,property=secure,value=on",
                "-drive", f"file={ovmf_vars.name},if=pflash,format=raw",
            ]

        if config.qemu_cdrom and config.output_format == OutputFormat.disk:
            # CD-ROM devices have sector size 2048 so we transform the disk image into one with sector size 2048.
            src = (config.output_dir / config.output).resolve()
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
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir / config.output))
        else:
            fname = config.output_dir / config.output

        if config.output_format == OutputFormat.disk and not config.qemu_cdrom:
            run(["systemd-repart",
                 "--definitions", "",
                 "--no-pager",
                 "--size=8G",
                 "--pretty=no",
                 "--offline=yes",
                 fname])

        if config.qemu_firmware == QemuFirmware.direct or config.output_format == OutputFormat.cpio:
            if config.qemu_kernel:
                kernel = config.qemu_kernel
            elif "-kernel" not in args.cmdline:
                kernel = config.output_dir / config.output_split_kernel
                if not kernel.exists():
                    die("No kernel found, please install a kernel in the image or provide a -kernel argument to mkosi qemu")
            else:
                kernel = None

            if kernel:
                cmdline += ["-kernel", kernel]

            cmdline += ["-append", " ".join(config.kernel_command_line + config.kernel_command_line_extra)]

        if config.output_format == OutputFormat.cpio:
            cmdline += ["-initrd", fname]
        else:
            cmdline += ["-drive", f"if=none,id=mkosi,file={fname},format=raw",
                        "-device", "virtio-scsi-pci,id=scsi",
                        "-device", f"scsi-{'cd' if config.qemu_cdrom else 'hd'},drive=mkosi,bootindex=1"]

        if config.qemu_firmware == QemuFirmware.uefi and config.qemu_swtpm != ConfigFeature.disabled and shutil.which("swtpm") is not None:
            sock = stack.enter_context(start_swtpm())
            cmdline += ["-chardev", f"socket,id=chrtpm,path={sock}",
                        "-tpmdev", "emulator,id=tpm0,chardev=chrtpm"]

            if config.architecture == Architecture.x86_64:
                cmdline += ["-device", "tpm-tis,tpmdev=tpm0"]
            elif config.architecture == Architecture.arm64:
                cmdline += ["-device", "tpm-tis-device,tpmdev=tpm0"]

        if use_vsock:
            addr, notifications = stack.enter_context(vsock_notify_handler())
            cmdline += ["-smbios", f"type=11,value=io.systemd.credential:vmm.notify_socket={addr}"]

        cmdline += config.qemu_args
        cmdline += args.cmdline

        run(cmdline, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False)

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

    run(cmd, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False)
