# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import getpass
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from mkosi.config import (
    Args,
    Config,
    ConfigFeature,
    Firmware,
    Network,
    OutputFormat,
    QemuDiskType,
    yes_no,
)
from mkosi.log import die
from mkosi.qemu import (
    finalize_credentials,
    finalize_drive,
    finalize_firmware,
    finalize_firmware_variables,
    finalize_initrd,
    finalize_kernel_command_line_extra,
)
from mkosi.run import run
from mkosi.util import PathString, flock_or_die, groupby


def run_vmspawn(args: Args, config: Config) -> None:
    if config.output_format not in (
        OutputFormat.disk,
        OutputFormat.esp,
        OutputFormat.directory,
        OutputFormat.uki,
    ):
        die(f"{config.output_format} images cannot be booted in systemd-vmspawn")

    kernel = config.expand_linux_specifiers() if config.linux else None
    firmware = finalize_firmware(config, kernel)

    if kernel and not kernel.exists():
        die(f"Kernel not found at {kernel}")

    if not kernel and (
        firmware.is_linux() or config.output_format in (OutputFormat.directory, OutputFormat.uki)
    ):
        if firmware.is_uefi():
            name = config.output if config.output_format == OutputFormat.uki else config.output_split_uki
            kernel = config.output_dir_or_cwd() / name
        else:
            kernel = config.output_dir_or_cwd() / config.output_split_kernel
        if not kernel.exists():
            die(
                f"Kernel or UKI not found at {kernel}",
                hint="Please install a kernel in the image or provide a --linux argument to mkosi vmspawn",
            )

    features: list[str] = []
    if firmware == Firmware.uefi_secure_boot:
        features += ["secure-boot"]
    if config.firmware_variables in (Path("microsoft"), Path("microsoft-mok")):
        features += ["enrolled-keys"]

    vars = None
    if firmware.is_uefi():
        describe: list[PathString] = [
            "systemd-vmspawn",
            "--firmware=describe",
        ]
        if features:
            describe += ["--firmware-features", ",".join(features)]

        result = run(describe, stdout=subprocess.PIPE, sandbox=config.sandbox())
        j = json.loads(result.stdout)
        vars = Path(j["mapping"]["nvram-template"]["filename"])

    cmdline: list[PathString] = [
        "systemd-vmspawn",
        "--cpus", str(config.cpus or os.cpu_count()),
        "--ram", str(config.ram),
        "--kvm", config.kvm.to_tristate(),
        "--vsock", config.vsock.to_tristate(),
        "--tpm", config.tpm.to_tristate(),
        "--tpm-state=off",
        "--console", str(config.console),
        "--register", yes_no(config.register != ConfigFeature.disabled),
    ]  # fmt: skip

    if features:
        cmdline += ["--firmware-features", ",".join(features)]

    if config.runtime_size:
        cmdline += ["--grow-image", str(config.runtime_size)]

    if config.bind_user:
        cmdline += ["--bind-user", getpass.getuser(), "--bind-user-group=wheel"]

    if config.runtime_network == Network.user:
        cmdline += ["--network-user-mode"]
    elif config.runtime_network == Network.interface:
        cmdline += ["--network-tap"]

    with contextlib.ExitStack() as stack:
        if vars:
            ovmf_vars = finalize_firmware_variables(config, vars, stack)
            cmdline += ["--efi-nvram-template", ovmf_vars]

        for f in finalize_credentials(config, stack).iterdir():
            cmdline += [f"--load-credential={f.name}:{f}"]

        fname = config.output_dir_or_cwd() / config.output
        if config.ephemeral:
            cmdline += ["--ephemeral"]
        elif config.output_format != OutputFormat.uki:
            stack.enter_context(flock_or_die(fname))

        if config.runtime_build_sources:
            for t in config.build_sources:
                src, dst = t.with_prefix("/work/src")
                cmdline += ["--bind", f"{src}:{dst}"]

            if config.build_dir:
                cmdline += ["--bind", f"{config.build_subdir}:/work/build"]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or "")
            cmdline += ["--bind", f"{tree.source}:{target}"]

        qemu_args = list(config.qemu_args)

        for _, drives in groupby(config.drives, key=lambda d: d.file_id):
            file = stack.enter_context(finalize_drive(config, drives[0]))

            for drive in drives:
                arg = [
                    "driver=raw",
                    f"node-name={drive.id}",
                    "file.driver=file",
                    f"file.filename={file}",
                    "file.aio=io_uring",
                    "file.locking=off",
                    "cache.direct=on",
                    "cache.no-flush=yes",
                ]
                if drive.options:
                    arg += [drive.options]

                qemu_args += ["-blockdev", ",".join(arg)]

        if kernel:
            cmdline += ["--linux", kernel]

            if firmware != Firmware.linux_noinitrd and (
                initrd := stack.enter_context(finalize_initrd(config))
            ):
                cmdline += ["--initrd", initrd]

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]
        elif config.output_format != OutputFormat.uki:
            cmdline += ["--image", fname]

        if config.disk_type != QemuDiskType.virtio_blk:
            cmdline += ["--image-disk-type", str(config.disk_type)]

        if config.forward_journal:
            cmdline += [
                "--forward-journal", config.forward_journal,
                "--forward-journal-max-use=1T",
                "--forward-journal-keep-free=1G",
                "--forward-journal-max-file-size=4G",
                f"--forward-journal-max-files={1 if config.forward_journal.suffix == '.journal' else 100}",
            ]  # fmt: skip

        cmdline += [
            *args.cmdline,
            *config.kernel_command_line,
            *finalize_kernel_command_line_extra(args, config),
        ]

        env = os.environ.copy()
        if qemu_args:
            env["SYSTEMD_VMSPAWN_QEMU_EXTRA"] = " ".join(shlex.quote(str(a)) for a in qemu_args)

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
