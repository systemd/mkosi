# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from mkosi.config import Args, ArtifactOutput, Config, OutputFormat
from mkosi.log import die
from mkosi.run import run, workdir
from mkosi.user import become_root_cmd
from mkosi.util import PathString, flatten


def run_sysupdate(args: Args, config: Config) -> None:
    if not config.sysupdate_dir:
        die(
            "No sysupdate definitions directory specified",
            hint="Specify a directory containing systemd-sysupdate transfer definitions with "
            "SysupdateDirectory=",
        )

    if not (sysupdate := config.find_binary("systemd-sysupdate", "/usr/lib/systemd/systemd-sysupdate")):
        die("Could not find systemd-sysupdate")

    with contextlib.ExitStack() as stack:
        if config.tools() != Path("/"):
            # We explicitly run this without a sandbox, because / has to be the original root mountpoint for
            # bootctl --print-root-device to work properly.
            blockdev = run(["bootctl", "--print-root-device"], stdout=subprocess.PIPE).stdout.strip()

            tmp = stack.enter_context(tempfile.TemporaryDirectory())
            # If /run/systemd/volatile-root exists, systemd skips its root block device detection logic and
            # uses whatever block device /run/systemd/volatile-root points to instead. Let's make use of that
            # when using a tools tree as in that case the block device detection logic doesn't work properly.
            (Path(tmp) / "volatile-root").symlink_to(blockdev)
        else:
            tmp = None

        if (
            config.output_format == OutputFormat.disk
            and ArtifactOutput.partitions not in config.split_artifacts
        ):
            old = {p for p in config.output_dir_or_cwd().iterdir() if p.is_file()}

            # If we didn't generate split partitions as part of the image build, let's do it now.
            run(
                [
                    "systemd-repart",
                    "--split=yes",
                    *([f"--definitions={workdir(d)}" for d in config.repart_dirs]),
                    workdir(config.output_dir_or_cwd() / config.output_with_format),
                ],
                sandbox=config.sandbox(
                    options=[
                        "--bind", config.output_dir_or_cwd(), workdir(config.output_dir_or_cwd()),
                        *flatten(["--ro-bind", os.fspath(d), workdir(d)] for d in config.repart_dirs),
                    ],
                ),
            )  # fmt: skip

            for p in config.output_dir_or_cwd().iterdir():
                if p not in old and p.is_file():
                    stack.callback(p.unlink)

        cmd: list[PathString] = [
            sysupdate,
            "--definitions", config.sysupdate_dir,
            "--transfer-source", config.output_dir_or_cwd(),
            *args.cmdline,
        ]  # fmt: skip

        run(
            cmd,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | config.finalize_environment(),
            log=False,
            sandbox=config.sandbox(
                devices=True,
                network=True,
                relaxed=True,
                setup=become_root_cmd(),
                options=[
                    *(["--bind", "/boot", "/boot"] if Path("/boot").exists() else []),
                    *(["--bind", "/efi", "/efi"] if Path("/efi").exists() else []),
                    *(
                        [
                            # Make sure systemd-sysupdate parses os-release from the host and not the tools
                            # tree.
                            "--bind", "/usr/lib/os-release", "/usr/lib/os-release",
                            "--bind", tmp, "/run/systemd",
                        ]
                        if tmp
                        else []
                    ),
                    "--same-dir",
                ],
            ),
        )  # fmt: skip
