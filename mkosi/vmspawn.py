# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import sys
from pathlib import Path

from mkosi.config import (
    Args,
    Config,
    OutputFormat,
    QemuFirmware,
    yes_no,
)
from mkosi.log import die
from mkosi.qemu import (
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
        "--qemu-smp", config.qemu_smp,
        "--qemu-mem", config.qemu_mem,
        "--qemu-kvm", config.qemu_kvm.to_tristate(),
        "--qemu-vsock", config.qemu_vsock.to_tristate(),
        "--tpm", config.qemu_swtpm.to_tristate(),
        "--secure-boot", yes_no(config.secure_boot),
    ]

    if config.qemu_gui:
        cmdline += ["--qemu-gui"]

    cmdline += [f"--set-credential={k}:{v}" for k, v in config.credentials.items()]

    with contextlib.ExitStack() as stack:
        if config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = config.output_dir_or_cwd() / config.output

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

        run(cmdline, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False)
