# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import getpass
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
    copy_ephemeral,
    finalize_credentials,
    finalize_firmware,
    finalize_initrd,
    finalize_kernel_command_line_extra,
    finalize_register,
)
from mkosi.run import run
from mkosi.util import PathString


def run_vmspawn(args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.esp, OutputFormat.directory):
        die(f"{config.output_format} images cannot be booted in systemd-vmspawn")

    if config.firmware == Firmware.bios:
        die("systemd-vmspawn cannot boot BIOS firmware images")

    if config.firmware_variables and config.firmware_variables != Path("microsoft"):
        die("mkosi vmspawn does not support FirmwareVariables=")

    kernel = config.expand_linux_specifiers() if config.linux else None
    firmware = finalize_firmware(config, kernel)

    if not kernel and firmware.is_linux():
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
        "--grow-image", str(config.runtime_size),
    ]  # fmt: skip

    if config.bind_user:
        cmdline += ["--bind-user", getpass.getuser()]

    if config.runtime_network == Network.user:
        cmdline += ["--network-user-mode"]
    elif config.runtime_network == Network.interface:
        cmdline += ["--network-tap"]

    with contextlib.ExitStack() as stack:
        for f in finalize_credentials(config, stack).iterdir():
            cmdline += [f"--load-credential={f.name}:{f}"]

        fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))

        if config.runtime_build_sources:
            for t in config.build_sources:
                src, dst = t.with_prefix("/work/src")
                cmdline += ["--bind", f"{src}:{dst}"]

            if config.build_dir:
                cmdline += ["--bind", f"{config.build_subdir}:/work/build"]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or "")
            cmdline += ["--bind", f"{tree.source}:{target}"]

        if kernel:
            cmdline += ["--linux", kernel]

            if firmware != Firmware.linux_noinitrd and (
                initrd := stack.enter_context(finalize_initrd(config))
            ):
                cmdline += ["--initrd", initrd]

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
