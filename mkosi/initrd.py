# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import contextlib
import dataclasses
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, cast

import mkosi.resources
from mkosi.config import DocFormat, InitrdProfile, OutputFormat
from mkosi.documentation import show_docs
from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, die, log_notice, log_setup
from mkosi.run import find_binary, run, uncaught_exception_handler
from mkosi.sandbox import __version__, umask
from mkosi.tree import copy_tree, move_tree, rmtree
from mkosi.util import PathString, mandatory_variable, resource_path


@dataclasses.dataclass(frozen=True)
class KernelInstallContext:
    command: str
    kernel_version: str
    entry_dir: Path
    kernel_image: Path
    initrds: list[Path]
    staging_area: Path
    layout: str
    image_type: str
    initrd_generator: Optional[str]
    uki_generator: Optional[str]
    verbose: bool

    @staticmethod
    def parse(*, name: str, description: str) -> "KernelInstallContext":
        parser = argparse.ArgumentParser(
            description=description,
            allow_abbrev=False,
            usage=f"{name} COMMAND KERNEL_VERSION ENTRY_DIR KERNEL_IMAGE…",
        )

        parser.add_argument(
            "command",
            metavar="COMMAND",
            help="The action to perform. Only 'add' is supported.",
        )
        parser.add_argument(
            "kernel_version",
            metavar="KERNEL_VERSION",
            help="Kernel version string",
        )
        parser.add_argument(
            "entry_dir",
            metavar="ENTRY_DIR",
            type=Path,
            nargs="?",
            help="Type#1 entry directory (ignored)",
        )
        parser.add_argument(
            "kernel_image",
            metavar="KERNEL_IMAGE",
            type=Path,
            nargs="?",
            help="Kernel image",
        )
        parser.add_argument(
            "initrds",
            metavar="INITRD…",
            type=Path,
            nargs="*",
            help="Initrd files",
        )
        parser.add_argument(
            "--version",
            action="version",
            version=f"mkosi {__version__}",
        )

        args = parser.parse_args()

        return KernelInstallContext(
            command=args.command,
            kernel_version=args.kernel_version,
            entry_dir=args.entry_dir,
            kernel_image=args.kernel_image,
            initrds=args.initrds,
            staging_area=Path(mandatory_variable("KERNEL_INSTALL_STAGING_AREA")),
            layout=mandatory_variable("KERNEL_INSTALL_LAYOUT"),
            image_type=mandatory_variable("KERNEL_INSTALL_IMAGE_TYPE"),
            initrd_generator=os.getenv("KERNEL_INSTALL_INITRD_GENERATOR"),
            uki_generator=os.getenv("KERNEL_INSTALL_UKI_GENERATOR"),
            verbose=int(os.getenv("KERNEL_INSTALL_VERBOSE", 0)) > 0,
        )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mkosi-initrd",
        description="Build initrds or unified kernel images for the current system using mkosi",
        allow_abbrev=False,
        usage="mkosi-initrd [options...]",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="NAME",
        help="Output name",
        default="initrd",
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
        "-g",
        "--generic",
        help="Build a generic initrd without host-specific kernel modules",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--profile",
        choices=InitrdProfile.values(),
        help="Which profiles to enable for the initrd",
        action="append",
        default=[],
    )

    initrd_common_args(parser)
    return parser


def is_valid_modulesd(modulesd: Path) -> bool:
    # Check whether a provided kernel modules directory is valid
    return modulesd.is_dir() and (
        (modulesd / "modules.dep").exists() or (modulesd / "modules.dep.bin").exists()
    )


def weak_modules(modulesd: Path) -> list[str]:
    return [
        f"--extra-tree={m.resolve()}:{m.resolve()}"
        for m in (modulesd / "weak-updates").rglob("*.ko*")
        if m.is_symlink()
    ]


def process_crypttab(staging_dir: Path) -> list[str]:
    cmdline = []

    # Generate crypttab with all the x-initrd.attach entries
    if Path("/etc/crypttab").exists():
        try:
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
                with (staging_dir / "crypttab").open("w") as f:
                    f.write("# Automatically generated by mkosi-initrd\n")
                    f.write("\n".join(crypttab))
                cmdline += ["--extra-tree", f"{staging_dir / 'crypttab'}:/etc/crypttab"]

                # Add key files
                for line in crypttab:
                    entry = line.split()
                    if (
                        entry[2] in ["-", "none"]
                        and Path(keyfile := f"/etc/cryptsetup-keys.d/{entry[0]}.key").exists()
                    ) or Path(keyfile := entry[2]).exists():
                        cmdline += ["--extra-tree", f"{keyfile}:{keyfile}"]

        except PermissionError:
            logging.warning("Permission denied to access /etc/crypttab, the initrd may be unbootable")

    return cmdline


def raid_config() -> list[str]:
    return [
        f"--extra-tree={f}:{f}"
        for f in ("/etc/mdadm.conf", "/etc/mdadm.conf.d", "/etc/mdadm/mdadm.conf", "/etc/mdadm/mdadm.conf.d")
        if Path(f).exists()
    ]


def vconsole_config() -> list[str]:
    return [
        f"--extra-tree={f}:{f}" for f in ("/etc/default/keyboard", "/etc/vconsole.conf") if Path(f).exists()
    ]


def initrd_finalize(staging_dir: Path, output: str, output_dir: Optional[Path]) -> None:
    if output_dir:
        with umask(~0o700) if os.getuid() == 0 else cast(umask, contextlib.nullcontext()):
            Path(output_dir).mkdir(parents=True, exist_ok=True)
    else:
        output_dir = Path.cwd()

    staging = staging_dir / output
    tmp = output_dir / f"{output}.new"
    final = output_dir / output

    log_notice(f"Copying {staging} to {tmp}")
    # mkosi symlinks the expected output image, so dereference it
    try:
        copy_tree(staging.resolve(), tmp)
    except subprocess.CalledProcessError:
        rmtree(tmp)
        raise

    log_notice(f"Moving {tmp} to {final}")
    rmtree(final)
    move_tree(tmp, final)


def initrd_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-k",
        "--kernel-version",
        metavar="KERNEL_VERSION",
        help="Kernel version string",
        default=platform.uname().release,
    )
    parser.add_argument(
        "-O",
        "--output-dir",
        metavar="DIR",
        help="Output directory",
        default=None,
        type=Path,
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
        "--debug-sandbox",
        help="Run mkosi-sandbox with strace",
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


def include_system_config(name: str) -> list[str]:
    cmdline = []

    for d in ("/usr/lib", "/usr/local/lib", "/run", "/etc"):
        p = Path(d) / name
        if p.exists():
            cmdline += ["--include", os.fspath(p)]

    return cmdline


@uncaught_exception_handler()
def main() -> None:
    log_setup()

    args = create_parser().parse_args()

    if args.show_documentation:
        with resource_path(mkosi.resources) as r:
            show_docs("mkosi-initrd", DocFormat.all(), resources=r)
        return

    modulesd = Path("/usr/lib/modules") / args.kernel_version
    if not is_valid_modulesd(modulesd):
        die(f"Invalid kernel directory: {modulesd}")

    with (
        tempfile.TemporaryDirectory() as staging_dir,
        tempfile.TemporaryDirectory() as sandbox_tree,
    ):
        cmdline: list[PathString] = [
            "mkosi",
            "--force",
            "--directory=",
            f"--format={args.format}",
            f"--output={args.output}",
            f"--output-directory={staging_dir}",
            f"--extra-tree={modulesd}:{modulesd}",
            "--extra-tree=/usr/lib/firmware:/usr/lib/firmware",
            "--remove-files=/usr/lib/firmware/*-ucode",
            "--build-sources=",
            "--include=mkosi-initrd",
        ]  # fmt: skip

        if not args.generic:
            cmdline += ["--kernel-modules=host"]

        cmdline += weak_modules(modulesd)

        for p in args.profile:
            cmdline += ["--profile", p]
            if p == "raid":
                cmdline += raid_config()

        if args.kernel_image:
            cmdline += [
                f"--extra-tree={args.kernel_image}:{modulesd}/vmlinuz",
            ]

        if args.debug:
            ARG_DEBUG.set(args.debug)
            cmdline += ["--debug"]
        if args.debug_shell:
            ARG_DEBUG_SHELL.set(args.debug_shell)
            cmdline += ["--debug-shell"]
        if args.debug_sandbox:
            cmdline += ["--debug-sandbox"]

        if os.getuid() == 0:
            cmdline += [
                "--workspace-dir=/var/tmp",
                "--package-cache-dir=/var",
                "--cache-only=metadata",
            ]
            if args.format != OutputFormat.directory.value:
                cmdline += ["--output-mode=600"]

        cmdline += include_system_config("mkosi-initrd")

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
            "pki/rpm-gpg",
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
                    # If we're running as root, use the keyring from the host, but make sure we don't try to
                    # copy any gpg-agent sockets that might be in /etc/pacman.d/gnupg. If we're not running
                    # as root, we might not have the necessary permissions to access the keyring so don't try
                    # to copy the keyring in that case.
                    ignore=shutil.ignore_patterns("S.*" if os.getuid() == 0 else "gnupg"),
                    dirs_exist_ok=True,
                )

        cmdline += [f"--sandbox-tree={sandbox_tree}"]

        cmdline += process_crypttab(Path(staging_dir))

        if Path("/etc/kernel/cmdline").exists():
            cmdline += ["--kernel-command-line", Path("/etc/kernel/cmdline").read_text()]

        cmdline += vconsole_config()

        # Resolve dnf binary to determine which version the host uses by default
        # (to avoid preferring dnf5 if the host uses dnf4)
        # as there's a much bigger chance that it has a populated dnf cache directory.
        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | ({"MKOSI_DNF": dnf.resolve().name} if (dnf := find_binary("dnf")) else {}),
        )

        initrd_finalize(Path(staging_dir), args.output, args.output_dir)


if __name__ == "__main__":
    main()
