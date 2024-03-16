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
from mkosi.qemu import (
    apply_runtime_size,
    copy_ephemeral,
    finalize_qemu_firmware,
    find_ovmf_firmware,
)
from mkosi.run import run
from mkosi.sandbox import Mount
from mkosi.types import PathString
from mkosi.util import flock_or_die


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

    if kernel and not kernel.exists():
        die(f"Kernel not found at {kernel}")

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
        "--cpus", str(config.qemu_smp),
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

    ovmf = find_ovmf_firmware(config, firmware)
    if ovmf:
        cmdline += ["--firmware", ovmf.description]

    cmdline += [f"--set-credential={k}:{v}" for k, v in config.credentials.items()]

    with contextlib.ExitStack() as stack:
        if config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = stack.enter_context(flock_or_die(config.output_dir_or_cwd() / config.output))

        apply_runtime_size(config, fname)

        kcl = config.kernel_command_line_extra

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or tree.source.name)
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

        cmdline += [*args.cmdline, *kcl]

        run(cmdline, stdin=sys.stdin, stdout=sys.stdout, env=os.environ | config.environment, log=False)
