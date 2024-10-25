# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import sys
from pathlib import Path

from mkosi.config import Args, ArtifactOutput, Config
from mkosi.log import die
from mkosi.run import run
from mkosi.types import PathString


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
            binary=sysupdate,
            devices=True,
            network=True,
            relaxed=True,
            setup=["run0"] if os.getuid() != 0 else [],
            options=[
                *(["--bind", "/boot", "/boot"] if Path("/boot").exists() else []),
                *(["--bind", "/efi", "/efi"] if Path("/efi").exists() else []),
            ],
        ),
    )
