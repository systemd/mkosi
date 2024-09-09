# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path

import mkosi.resources
from mkosi.config import DocFormat, OutputFormat
from mkosi.documentation import show_docs
from mkosi.log import log_setup
from mkosi.run import find_binary, run, uncaught_exception_handler
from mkosi.sandbox import __version__
from mkosi.types import PathString
from mkosi.util import resource_path


@uncaught_exception_handler()
def main() -> None:
    log_setup()

    parser = argparse.ArgumentParser(
        prog="mkosi-initrd",
        description="Build initrds or unified kernel images for the current system using mkosi",
        allow_abbrev=False,
        usage="mkosi-initrd [options...]",
    )

    parser.add_argument(
        "--kernel-version",
        metavar="KERNEL_VERSION",
        help="Kernel version string",
        default=platform.uname().release,
    )
    parser.add_argument(
        "-t", "--format",
        choices=[str(OutputFormat.cpio), str(OutputFormat.uki), str(OutputFormat.directory)],
        help="Output format (CPIO archive, UKI or local directory)",
        default="cpio",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="NAME",
        help="Output name",
        default="initrd",
    )
    parser.add_argument(
        "-O", "--output-dir",
        metavar="DIR",
        help="Output directory",
        default="",
    )
    parser.add_argument(
        "--debug",
        help="Turn on debugging output",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--debug-shell",
        help="Spawn debug shell if a sandboxed command fails",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-D", "--show-documentation",
        help="Show the man page",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mkosi {__version__}",
    )

    args = parser.parse_args()

    if args.show_documentation:
        with resource_path(mkosi.resources) as r:
            show_docs("mkosi-initrd", DocFormat.all(), resources=r)
        return

    cmdline: list[PathString] = [
        "mkosi",
        "--force",
        "--directory", "",
        "--format", str(args.format),
        "--output", args.output,
        "--output-dir", args.output_dir,
        "--extra-tree", f"/usr/lib/modules/{args.kernel_version}:/usr/lib/modules/{args.kernel_version}",
        "--extra-tree=/usr/lib/firmware:/usr/lib/firmware",
        "--remove-files=/usr/lib/firmware/*-ucode",
        "--kernel-modules-exclude=.*",
        "--kernel-modules-include=host",
        "--build-sources", "",
        "--include=mkosi-initrd",
    ]

    if args.debug:
        cmdline += ["--debug"]
    if args.debug_shell:
        cmdline += ["--debug-shell"]

    if os.getuid() == 0:
        cmdline += [
            "--workspace-dir=/var/tmp",
            "--package-cache-dir=/var",
            "--cache-only=metadata",
        ]

    for d in ("/usr/lib/mkosi-initrd", "/etc/mkosi-initrd"):
        if Path(d).exists():
            cmdline += ["--include", d]

    with tempfile.TemporaryDirectory() as d:
        # Make sure we don't use any of mkosi's default repositories.
        for p in (
            "yum.repos.d/mkosi.repo",
            "apt/sources.list.d/mkosi.sources",
            "zypp/repos.d/mkosi.repo",
            "pacman.conf",
        ):
            (Path(d) / "etc" / p).parent.mkdir(parents=True, exist_ok=True)
            (Path(d) / "etc" / p).touch()

        # Copy in the host's package manager configuration.
        for p in (
            "dnf",
            "yum.repos.d/",
            "apt",
            "zypp",
            "pacman.conf",
            "pacman.d/",
        ):
            if not (Path("/etc") / p).exists():
                continue

            (Path(d) / "etc" / p).parent.mkdir(parents=True, exist_ok=True)
            if (Path("/etc") / p).resolve().is_file():
                shutil.copy2(Path("/etc") / p, Path(d) / "etc" / p)
            else:
                shutil.copytree(Path("/etc") / p, Path(d) / "etc" / p,
                                ignore=shutil.ignore_patterns("gnupg"), dirs_exist_ok=True)

        cmdline += ["--sandbox-tree", d]

        # Prefer dnf as dnf5 has not yet officially replaced it and there's a much bigger chance that there will be a
        # populated dnf cache directory.
        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env={"MKOSI_DNF": dnf.name} if (dnf := find_binary("dnf", "dnf5")) else {}
        )


if __name__ == "__main__":
    main()
