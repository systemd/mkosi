# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import contextlib
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import cast

import mkosi.resources
from mkosi.config import DocFormat, OutputFormat
from mkosi.documentation import show_docs
from mkosi.log import log_notice, log_setup
from mkosi.run import find_binary, run, uncaught_exception_handler
from mkosi.sandbox import __version__, umask
from mkosi.tree import copy_tree
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
        "--kernel-image",
        metavar="KERNEL_IMAGE",
        help="Kernel image",
        type=Path,
    )
    parser.add_argument(
        "-t",
        "--format",
        choices=[str(OutputFormat.cpio), str(OutputFormat.uki), str(OutputFormat.directory)],
        help="Output format (CPIO archive, UKI or local directory)",
        default="cpio",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="NAME",
        help="Output name",
        default="initrd",
    )
    parser.add_argument(
        "-O",
        "--output-dir",
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
        "-D",
        "--show-documentation",
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

    with (
        tempfile.TemporaryDirectory() as staging_dir,
        tempfile.TemporaryDirectory() as sandbox_tree,
    ):
        cmdline: list[PathString] = [
            "mkosi",
            "--force",
            "--directory", "",
            "--format", args.format,
            "--output", args.output,
            "--output-directory", staging_dir,
            "--extra-tree", f"/usr/lib/modules/{args.kernel_version}:/usr/lib/modules/{args.kernel_version}",
            "--extra-tree=/usr/lib/firmware:/usr/lib/firmware",
            "--remove-files=/usr/lib/firmware/*-ucode",
            "--kernel-modules-exclude=.*",
            "--kernel-modules-include=host",
            "--build-sources", "",
            "--include=mkosi-initrd",
        ]  # fmt: skip

        if args.kernel_image:
            cmdline += [
                "--extra-tree", f"{args.kernel_image}:/usr/lib/modules/{args.kernel_version}/vmlinuz",
            ]  # fmt: skip

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
            if args.format != OutputFormat.directory.value:
                cmdline += ["--output-mode=600"]

        for d in (
            "/usr/lib/mkosi-initrd",
            "/usr/local/lib/mkosi-initrd",
            "/run/mkosi-initrd",
            "/etc/mkosi-initrd",
        ):
            if Path(d).exists():
                cmdline += ["--include", d]

        # Make sure we don't use any of mkosi's default repositories.
        for p in (
            "yum.repos.d/mkosi.repo",
            "apt/sources.list.d/mkosi.sources",
            "zypp/repos.d/mkosi.repo",
            "pacman.conf",
        ):
            (Path(sandbox_tree) / "etc" / p).parent.mkdir(parents=True, exist_ok=True)
            (Path(sandbox_tree) / "etc" / p).touch()

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

            (Path(sandbox_tree) / "etc" / p).parent.mkdir(parents=True, exist_ok=True)
            if (Path("/etc") / p).resolve().is_file():
                shutil.copy2(Path("/etc") / p, Path(sandbox_tree) / "etc" / p)
            else:
                shutil.copytree(
                    Path("/etc") / p,
                    Path(sandbox_tree) / "etc" / p,
                    ignore=shutil.ignore_patterns("gnupg"),
                    dirs_exist_ok=True,
                )

        cmdline += ["--sandbox-tree", sandbox_tree]

        # Generate crypttab with all the x-initrd.attach entries
        if Path("/etc/crypttab").exists():
            crypttab = [
                line
                for line in Path("/etc/crypttab").read_text().splitlines()
                if (
                    len(entry := line.split()) >= 4
                    and not entry[0].startswith("#")
                    and "x-initrd.attach" in entry[3]
                )
            ]
            if crypttab:
                with (Path(staging_dir) / "crypttab").open("w") as f:
                    f.write("# Automatically generated by mkosi-initrd\n")
                    f.write("\n".join(crypttab))
                cmdline += ["--extra-tree", f"{staging_dir}/crypttab:/etc/crypttab"]

        # Prefer dnf as dnf5 has not yet officially replaced it and there's a much bigger chance that there
        # will be a populated dnf cache directory.
        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env={"MKOSI_DNF": dnf.name} if (dnf := find_binary("dnf", "dnf5")) else {},
        )

        if args.output_dir:
            with umask(~0o700) if os.getuid() == 0 else cast(umask, contextlib.nullcontext()):
                Path(args.output_dir).mkdir(parents=True, exist_ok=True)
        else:
            args.output_dir = Path.cwd()

        log_notice(f"Copying {staging_dir}/{args.output} to {args.output_dir}/{args.output}")
        # mkosi symlinks the expected output image, so dereference it
        copy_tree(
            Path(f"{staging_dir}/{args.output}").resolve(),
            Path(f"{args.output_dir}/{args.output}"),
        )


if __name__ == "__main__":
    main()
