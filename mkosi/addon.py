# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import os
import sys
import tempfile
from pathlib import Path

import mkosi.resources
from mkosi.config import DocFormat
from mkosi.documentation import show_docs
from mkosi.initrd import include_system_config, initrd_common_args, initrd_finalize, process_crypttab
from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, log_setup
from mkosi.run import run, uncaught_exception_handler
from mkosi.util import PathString, resource_path


@uncaught_exception_handler()
def main() -> None:
    log_setup()

    parser = argparse.ArgumentParser(
        prog="mkosi-addon",
        description="Build initrd/cmdline/ucode addon for the current system using mkosi",
        allow_abbrev=False,
        usage="mkosi-addon [options...]",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="NAME",
        help="Output name",
        default="mkosi-local.addon.efi",
    )

    initrd_common_args(parser)

    args = parser.parse_args()

    if args.show_documentation:
        with resource_path(mkosi.resources) as r:
            show_docs("mkosi-addon", DocFormat.all(), resources=r)
        return

    with tempfile.TemporaryDirectory() as staging_dir:
        cmdline: list[PathString] = [
            "mkosi",
            "--force",
            "--directory", "",
            "--output", args.output,
            "--output-directory", staging_dir,
            "--build-sources", "",
            "--include=mkosi-addon",
            "--extra-tree",
            f"/usr/lib/modules/{args.kernel_version}:/usr/lib/modules/{args.kernel_version}",
            "--extra-tree=/usr/lib/firmware:/usr/lib/firmware",
        ]  # fmt: skip

        if args.debug:
            ARG_DEBUG.set(args.debug)
            cmdline += ["--debug"]
        if args.debug_shell:
            ARG_DEBUG_SHELL.set(args.debug_shell)
            cmdline += ["--debug-shell"]
        if args.debug_sandbox:
            cmdline += ["--debug-sandbox"]

        if os.getuid() == 0:
            cmdline += ["--output-mode=600"]

        cmdline += include_system_config("mkosi-addon")
        cmdline += process_crypttab(Path(staging_dir))

        if Path("/etc/kernel/cmdline").exists():
            cmdline += ["--kernel-command-line", Path("/etc/kernel/cmdline").read_text()]

        run(cmdline, stdin=sys.stdin, stdout=sys.stdout)

        initrd_finalize(Path(staging_dir), args.output, args.output_dir)


if __name__ == "__main__":
    main()
