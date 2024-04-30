# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import sys
from pathlib import Path

from mkosi.config import (
    Args,
    Config,
    Network,
    OutputFormat,
    QemuFirmware,
    yes_no,
)
from mkosi.log import die
from mkosi.mounts import finalize_source_mounts
from mkosi.qemu import (
    apply_runtime_size,
    copy_ephemeral,
    finalize_qemu_firmware,
)
from mkosi.run import run
from mkosi.types import PathString


def run_vmspawn(args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        die(f"{config.output_format} images cannot be booted in systemd-vmspawn")

    if config.qemu_firmware == QemuFirmware.bios:
        die("systemd-vmspawn cannot boot BIOS firmware images")

    if config.qemu_cdrom:
        die("systemd-vmspawn does not support CD-ROM images")

    if config.qemu_firmware_variables and config.qemu_firmware_variables != Path("microsoft"):
        die("mkosi vmspawn does not support QemuFirmwareVariables=")

    kernel = config.qemu_kernel
    firmware = finalize_qemu_firmware(config, kernel)

    if not kernel and firmware == QemuFirmware.linux:
        kernel = config.output_dir_or_cwd() / config.output_split_kernel
        if not kernel.exists():
            die(
                f"Kernel or UKI not found at {kernel}",
                hint="Please install a kernel in the image or provide a --qemu-kernel argument to mkosi vmspawn"
            )

    cmdline: list[PathString] = [
        "systemd-vmspawn",
        "--cpus", str(config.qemu_smp or os.cpu_count()),
        "--ram", str(config.qemu_mem),
        "--kvm", config.qemu_kvm.to_tristate(),
        "--vsock", config.qemu_vsock.to_tristate(),
        "--tpm", config.qemu_swtpm.to_tristate(),
        "--secure-boot", yes_no(config.secure_boot),
    ]

    if config.runtime_network == Network.user:
        cmdline += ["--network-user-mode"]
    elif config.runtime_network == Network.interface:
        cmdline += ["--network-tap"]

    if config.qemu_gui:
        cmdline += ["--console=gui"]

    cmdline += [f"--set-credential={k}:{v}" for k, v in config.credentials.items()]

    with contextlib.ExitStack() as stack:
        fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))

        apply_runtime_size(config, fname)

        if config.runtime_build_sources:
            with finalize_source_mounts(config, ephemeral=False) as mounts:
                for mount in mounts:
                    cmdline += ["--bind", f"{mount.src}:{mount.dst}"]

            if config.build_dir:
                cmdline += ["--bind", f"{config.build_dir}:/work/build"]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or "")
            cmdline += ["--bind", f"{tree.source}:{target}"]

        if kernel:
            cmdline += ["--linux", kernel]

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]

            owner = os.stat(fname).st_uid
            if owner != 0:
                cmdline += [f"--private-users={str(owner)}"]
        else:
            cmdline += ["--image", fname]

        if config.forward_journal:
            cmdline += ["--forward-journal", config.forward_journal]

        cmdline += [*args.cmdline, *config.kernel_command_line_extra]

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | config.environment,
            log=False,
            sandbox=config.sandbox(binary=cmdline[0], network=True, devices=True, relaxed=True),
        )
