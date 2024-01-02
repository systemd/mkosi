# SPDX-License-Identifier: LGPL-2.1+

import os
import sys

from mkosi.config import Args, Config, OutputFormat
from mkosi.log import complete_step, die
from mkosi.run import run


def run_burn(args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.esp):
        die(f"{config.output_format} images cannot be burned to disk")

    fname = config.output_dir_or_cwd() / config.output

    if len(args.cmdline) != 1:
        die("Expected device argument.")

    device = args.cmdline[0]

    cmd = [
        "systemd-repart",
        "--no-pager",
        "--pretty=no",
        "--offline=yes",
        "--empty=force",
        "--dry-run=no",
        f"--copy-from={fname}",
        device,
    ]

    with complete_step("Burning 🔥🔥🔥 to medium…", "Burnt. 🔥🔥🔥"):
        run(
            cmd,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ,
            log=False,
            sandbox=config.sandbox(devices=True, network=True, relaxed=True),
        )
