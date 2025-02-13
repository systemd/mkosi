# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import sys
from pathlib import Path

from mkosi.config import (
    Args,
    Config,
    Firmware,
    Network,
    OutputFormat,
    yes_no,
)
from mkosi.log import die
from mkosi.qemu import (
    apply_runtime_size,
    copy_ephemeral,
    finalize_credentials,
    finalize_firmware,
    finalize_kernel_command_line_extra,
    finalize_register,
)
from mkosi.run import run
from mkosi.util import PathString, current_home_dir


def run_vmspawn(args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.esp, OutputFormat.directory):
        die(f"{config.output_format} images cannot be booted in systemd-vmspawn")

    if config.firmware == Firmware.bios:
        die("systemd-vmspawn cannot boot BIOS firmware images")

    if config.cdrom:
        die("systemd-vmspawn does not support CD-ROM images")

    if config.firmware_variables and config.firmware_variables != Path("microsoft"):
        die("mkosi vmspawn does not support FirmwareVariables=")

    kernel = config.linux
    firmware = finalize_firmware(config, kernel)

    if not kernel and firmware == Firmware.linux:
        kernel = config.output_dir_or_cwd() / config.output_split_kernel
        if not kernel.exists():
            die(
                f"Kernel or UKI not found at {kernel}",
                hint="Please install a kernel in the image or provide a --linux argument to mkosi vmspawn",
            )

    cmdline: list[PathString] = [
        "systemd-vmspawn",
        "--cpus", str(config.cpus or os.cpu_count()),
        "--ram", str(config.ram),
        "--kvm", config.kvm.to_tristate(),
        "--vsock", config.vsock.to_tristate(),
        "--tpm", config.tpm.to_tristate(),
        "--secure-boot", yes_no(config.secure_boot),
        "--register", yes_no(finalize_register(config)),
        "--console", str(config.console),
    ]  # fmt: skip

    if config.runtime_network == Network.user:
        cmdline += ["--network-user-mode"]
    elif config.runtime_network == Network.interface:
        cmdline += ["--network-tap"]

    cmdline += [f"--set-credential={k}:{v}" for k, v in finalize_credentials(config).items()]

    with contextlib.ExitStack() as stack:
        fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))

        apply_runtime_size(config, fname)

        if config.runtime_build_sources:
            for t in config.build_sources:
                src, dst = t.with_prefix("/work/src")
                cmdline += ["--bind", f"{src}:{dst}"]

            if config.build_dir:
                cmdline += ["--bind", f"{config.build_dir}:/work/build"]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or "")
            cmdline += ["--bind", f"{tree.source}:{target}"]

        if config.runtime_home and (p := current_home_dir()):
            cmdline += ["--bind", f"{p}:/root"]

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

        cmdline += [*args.cmdline, *finalize_kernel_command_line_extra(config)]

        env = os.environ.copy()
        if config.qemu_args:
            env["SYSTEMD_VMSPAWN_QEMU_EXTRA"] = " ".join(config.qemu_args)

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=env | config.finalize_environment(),
            log=False,
            sandbox=config.sandbox(
                network=True,
                devices=True,
                relaxed=True,
                options=["--same-dir"],
            ),
        )
