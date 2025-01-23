# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from mkosi.config import Args, ArtifactOutput, Config
from mkosi.log import die
from mkosi.run import run
from mkosi.user import become_root_cmd
from mkosi.util import PathString


def run_sysupdate(args: Args, config: Config) -> None:
    if ArtifactOutput.partitions not in config.split_artifacts:
        die("SplitArtifacts=partitions must be set to be able to use mkosi sysupdate")

    if not config.sysupdate_dir:
        die(
            "No sysupdate definitions directory specified",
            hint="Specify a directory containing systemd-sysupdate transfer definitions with "
            "SysupdateDirectory=",
        )

    if not (sysupdate := config.find_binary("systemd-sysupdate", "/usr/lib/systemd/systemd-sysupdate")):
        die("Could not find systemd-sysupdate")

    with tempfile.TemporaryDirectory() as tmp:
        if config.tools() != Path("/"):
            # We explicitly run this without a sandbox, because / has to be the original root mountpoint for
            # bootctl --print-root-device to work properly.
            blockdev = run(["bootctl", "--print-root-device"], stdout=subprocess.PIPE).stdout.strip()

            # If /run/systemd/volatile-root exists, systemd skips its root block device detection logic and
            # uses whatever block device /run/systemd/volatile-root points to instead. Let's make use of that
            # when using a tools tree as in that case the block device detection logic doesn't work properly.
            (Path(tmp) / "volatile-root").symlink_to(blockdev)

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
            env=os.environ | config.environment,
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
                        if config.tools() != Path("/")
                        else []
                    ),
                    "--same-dir",
                ],
            ),
        )  # fmt: skip
