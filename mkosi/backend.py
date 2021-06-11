# SPDX-License-Identifier: LGPL-2.1+

import argparse
import contextlib
import dataclasses
import enum
import os
import shlex
import shutil
import signal
import subprocess
import sys
import uuid
from types import FrameType
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generator,
    List,
    NoReturn,
    Optional,
    Union,
)

# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[Any]
else:
    CompletedProcess = subprocess.CompletedProcess


class MkosiException(Exception):
    """Leads to sys.exit"""


# This global should be initialized after parsing arguments
ARG_DEBUG = ()


class Distribution(enum.Enum):
    fedora = 1
    debian = 2
    ubuntu = 3
    arch = 4
    opensuse = 5
    mageia = 6
    centos = 7
    centos_epel = 8
    clear = 9
    photon = 10
    openmandriva = 11

    def __str__(self) -> str:
        return self.name


class SourceFileTransfer(enum.Enum):
    copy_all = "copy-all"
    copy_git_cached = "copy-git-cached"
    copy_git_others = "copy-git-others"
    copy_git_more = "copy-git-more"
    mount = "mount"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def doc(cls) -> Dict["SourceFileTransfer", str]:
        return {
            cls.copy_all: "normal file copy",
            cls.copy_git_cached: "use git-ls-files --cached, ignoring any file that git itself ignores",
            cls.copy_git_others: "use git-ls-files --others, ignoring any file that git itself ignores",
            cls.copy_git_more: "use git-ls-files --cached, ignoring any file that git itself ignores, but include the .git/ directory",
            cls.mount: "bind mount source files into the build image",
        }


class OutputFormat(enum.Enum):
    directory = enum.auto()
    subvolume = enum.auto()
    tar = enum.auto()

    gpt_ext4 = enum.auto()
    gpt_xfs = enum.auto()
    gpt_btrfs = enum.auto()
    gpt_squashfs = enum.auto()

    plain_squashfs = enum.auto()

    # Kept for backwards compatibility
    raw_ext4 = raw_gpt = gpt_ext4
    raw_xfs = gpt_xfs
    raw_btrfs = gpt_btrfs
    raw_squashfs = gpt_squashfs

    def __repr__(self) -> str:
        """Return the member name without the class name"""
        return self.name

    def __str__(self) -> str:
        """Return the member name without the class name"""
        return self.name

    @classmethod
    def from_string(cls, name: str) -> "OutputFormat":
        """A convenience method to be used with argparse"""
        try:
            return cls[name]
        except KeyError:
            raise argparse.ArgumentTypeError(f"unknown Format: {name!r}")

    def is_disk_rw(self) -> bool:
        "Output format is a disk image with a parition table and a writable filesystem"
        return self in (OutputFormat.gpt_ext4, OutputFormat.gpt_xfs, OutputFormat.gpt_btrfs)

    def is_disk(self) -> bool:
        "Output format is a disk image with a partition table"
        return self.is_disk_rw() or self == OutputFormat.gpt_squashfs

    def is_squashfs(self) -> bool:
        "The output format contains a squashfs partition"
        return self in {OutputFormat.gpt_squashfs, OutputFormat.plain_squashfs}

    def can_minimize(self) -> bool:
        "The output format can be 'minimized'"
        return self in (OutputFormat.gpt_ext4, OutputFormat.gpt_btrfs)

    def needed_kernel_module(self) -> str:
        if self == OutputFormat.gpt_btrfs:
            return "btrfs"
        elif self == OutputFormat.gpt_squashfs or self == OutputFormat.plain_squashfs:
            return "squashfs"
        elif self == OutputFormat.gpt_xfs:
            return "xfs"
        else:
            return "ext4"


@dataclasses.dataclass
class CommandLineArguments:
    """Type-hinted storage for command line arguments."""

    verb: str
    cmdline: List[str]
    distribution: Distribution
    release: str
    mirror: Optional[str]
    repositories: List[str]
    architecture: Optional[str]
    output_format: OutputFormat
    output: str
    output_dir: Optional[str]
    force_count: int
    bootable: bool
    boot_protocols: List[str]
    kernel_command_line: List[str]
    secure_boot: bool
    secure_boot_key: str
    secure_boot_certificate: str
    secure_boot_valid_days: str
    secure_boot_common_name: str
    read_only: bool
    encrypt: Optional[str]
    verity: bool
    compress: Union[None, str, bool]
    mksquashfs_tool: List[str]
    xz: bool
    qcow2: bool
    image_version: Optional[str]
    image_id: Optional[str]
    hostname: Optional[str]
    no_chown: bool
    tar_strip_selinux_context: bool
    incremental: bool
    minimize: bool
    with_unified_kernel_images: bool
    gpt_first_lba: Optional[int]
    hostonly_initrd: bool
    base_packages: Union[str, bool]
    packages: List[str]
    with_docs: bool
    with_tests: bool
    cache_path: Optional[str]
    extra_trees: List[str]
    skeleton_trees: List[str]
    build_script: Optional[str]
    build_env: List[str]
    build_sources: Optional[str]
    build_dir: Optional[str]
    include_dir: Optional[str]
    install_dir: Optional[str]
    build_packages: List[str]
    skip_final_phase: bool
    postinst_script: Optional[str]
    prepare_script: Optional[str]
    finalize_script: Optional[str]
    source_file_transfer: SourceFileTransfer
    source_file_transfer_final: Optional[SourceFileTransfer]
    with_network: bool
    nspawn_settings: Optional[str]
    root_size: int
    esp_size: Optional[int]
    xbootldr_size: Optional[int]
    swap_size: Optional[int]
    home_size: Optional[int]
    srv_size: Optional[int]
    var_size: Optional[int]
    tmp_size: Optional[int]
    usr_only: bool
    split_artifacts: bool
    checksum: bool
    sign: bool
    key: Optional[str]
    bmap: bool
    password: Optional[str]
    password_is_hashed: bool
    autologin: bool
    extra_search_paths: List[str]
    network_veth: bool
    ephemeral: bool
    ssh: bool
    ssh_key: Optional[str]
    ssh_timeout: int
    directory: Optional[str]
    default_path: Optional[str]
    all: bool
    all_directory: Optional[str]
    debug: List[str]
    auto_bump: bool
    workspace_dir: Optional[str]

    # QEMU-specific options
    qemu_headless: bool
    qemu_smp: str
    qemu_mem: str

    # Some extra stuff that's stored in CommandLineArguments for convenience but isn't populated by arguments
    verity_size: Optional[int]
    machine_id: str
    force: bool
    original_umask: int
    passphrase: Optional[Dict[str, str]]

    output_checksum: Optional[str] = None
    output_nspawn_settings: Optional[str] = None
    output_sshkey: Optional[str] = None
    output_root_hash_file: Optional[str] = None
    output_bmap: Optional[str] = None
    output_split_root: Optional[str] = None
    output_split_verity: Optional[str] = None
    output_split_kernel: Optional[str] = None
    cache_pre_inst: Optional[str] = None
    cache_pre_dev: Optional[str] = None
    output_signature: Optional[str] = None

    root_partno: Optional[int] = None
    swap_partno: Optional[int] = None
    esp_partno: Optional[int] = None
    xbootldr_partno: Optional[int] = None
    bios_partno: Optional[int] = None
    home_partno: Optional[int] = None
    srv_partno: Optional[int] = None
    var_partno: Optional[int] = None
    tmp_partno: Optional[int] = None
    verity_partno: Optional[int] = None

    releasever: Optional[str] = None
    ran_sfdisk: bool = False


def workspace(root: str) -> str:
    return os.path.dirname(root)


def var_tmp(root: str) -> str:
    return mkdir_last(os.path.join(workspace(root), "var-tmp"))


def mkdir_last(path: str, mode: int = 0o777) -> str:
    """Create directory path

    Only the final component will be created, so this is different than mkdirs().
    """
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        if not os.path.isdir(path):
            raise
    return path


def partition(loopdev: str, partno: int) -> str:
    return loopdev + "p" + str(partno)


def nspawn_params_for_blockdev_access(args: CommandLineArguments, loopdev: str) -> List[str]:
    params = [
        f"--bind-ro={loopdev}",
        f"--bind-ro=/dev/block",
        f"--bind-ro=/dev/disk",
        f"--property=DeviceAllow={loopdev}",
    ]
    for partno in (args.esp_partno, args.bios_partno, args.root_partno, args.xbootldr_partno):
        if partno is not None:
            p = partition(loopdev, partno)
            if os.path.exists(p):
                params += [f"--bind-ro={p}", f"--property=DeviceAllow={p}"]
    return params


def run_workspace_command(
    args: CommandLineArguments,
    root: str,
    cmd: List[str],
    network: bool = False,
    env: Dict[str, str] = {},
    nspawn_params: List[str] = [],
) -> None:
    cmdline = [
        "systemd-nspawn",
        "--quiet",
        "--directory=" + root,
        "--uuid=" + args.machine_id,
        "--machine=mkosi-" + uuid.uuid4().hex,
        "--as-pid2",
        "--register=no",
        "--bind=" + var_tmp(root) + ":/var/tmp",
        "--setenv=SYSTEMD_OFFLINE=1",
    ]

    if network:
        # If we're using the host network namespace, use the same resolver
        cmdline += ["--bind-ro=/etc/resolv.conf"]
    else:
        cmdline += ["--private-network"]

    cmdline += [f"--setenv={k}={v}" for k, v in env.items()]

    if nspawn_params:
        cmdline += nspawn_params

    result = run(cmdline + ["--"] + cmd, check=False)
    if result.returncode != 0:
        if "workspace-command" in ARG_DEBUG:
            run(cmdline, check=False)
        die(f"Workspace command `{' '.join(cmd)}` returned non-zero exit code {result.returncode}.")


@contextlib.contextmanager
def delay_interrupt() -> Generator[None, None, None]:
    # CTRL+C is sent to the entire process group. We delay its handling in mkosi itself so the subprocess can
    # exit cleanly before doing mkosi's cleanup. If we don't do this, we get device or resource is busy
    # errors when unmounting stuff later on during cleanup. We only delay a single CTRL+C interrupt so that a
    # user can always exit mkosi even if a subprocess hangs by pressing CTRL+C twice.
    interrupted = False

    def handler(signal: int, frame: FrameType) -> None:
        nonlocal interrupted
        if interrupted:
            raise KeyboardInterrupt()
        else:
            interrupted = True

    s = signal.signal(signal.SIGINT, handler)

    try:
        yield
    finally:
        signal.signal(signal.SIGINT, s)

        if interrupted:
            die("Interrupted")


# Borrowed from https://github.com/python/typeshed/blob/3d14016085aed8bcf0cf67e9e5a70790ce1ad8ea/stdlib/3/subprocess.pyi#L24
_FILE = Union[None, int, IO[Any]]


def run(
    cmdline: List[str],
    check: bool = True,
    stdout: _FILE = None,
    stderr: _FILE = None,
    **kwargs: Any,
) -> CompletedProcess:
    if "run" in ARG_DEBUG:
        MkosiPrinter.info("+ " + " ".join(shlex.quote(x) for x in cmdline))

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess output on stderr since we do so as well
        # for mkosi's own output.
        stdout = sys.stderr

    try:
        with delay_interrupt():
            return subprocess.run(cmdline, check=check, stdout=stdout, stderr=stderr, **kwargs)
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")


def tmp_dir() -> str:
    return os.environ.get("TMPDIR") or "/var/tmp"


def patch_file(filepath: str, line_rewriter: Callable[[str], str]) -> None:
    temp_new_filepath = filepath + ".tmp.new"

    with open(filepath, "r") as old:
        with open(temp_new_filepath, "w") as new:
            for line in old:
                new.write(line_rewriter(line))

    shutil.copystat(filepath, temp_new_filepath)
    os.remove(filepath)
    shutil.move(temp_new_filepath, filepath)


def write_grub_config(args: CommandLineArguments, root: str) -> None:
    kernel_cmd_line = " ".join(args.kernel_command_line)
    grub_cmdline = f'GRUB_CMDLINE_LINUX="{kernel_cmd_line}"\n'
    os.makedirs(os.path.join(root, "etc/default"), exist_ok=True, mode=0o755)
    grub_config = os.path.join(root, "etc/default/grub")
    if not os.path.exists(grub_config):
        with open(grub_config, "w+") as f:
            f.write(grub_cmdline)
    else:

        def jj(line: str) -> str:
            if line.startswith("GRUB_CMDLINE_LINUX="):
                return grub_cmdline
            if args.qemu_headless:
                if "GRUB_TERMINAL_INPUT" in line:
                    return 'GRUB_TERMINAL_INPUT="console serial"'
                if "GRUB_TERMINAL_OUTPUT" in line:
                    return 'GRUB_TERMINAL_OUTPUT="console serial"'
            return line

        patch_file(grub_config, jj)

        if args.qemu_headless:
            with open(grub_config, "a") as f:
                f.write('GRUB_SERIAL_COMMAND="serial --unit=0 --speed 115200"\n')


def install_grub(args: CommandLineArguments, root: str, loopdev: str, grub: str) -> None:
    if args.bios_partno is None:
        return

    write_grub_config(args, root)

    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    cmdline = [f"{grub}-install", "--modules=ext2 part_gpt", "--target=i386-pc", loopdev]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)

    # TODO: Remove os.path.basename once https://github.com/systemd/systemd/pull/16645 is widely available.
    cmdline = [f"{grub}-mkconfig", f"--output=/boot/{os.path.basename(grub)}/grub.cfg"]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)


def die(message: str) -> NoReturn:
    MkosiPrinter.warn(f"Error: {message}")
    raise MkosiException(message)


def warn(message: str) -> None:
    MkosiPrinter.warn(f"Warning: {message}")


class MkosiPrinter:
    out_file = sys.stderr
    isatty = out_file.isatty()

    bold = "\033[0;1;39m" if isatty else ""
    red = "\033[31;1m" if isatty else ""
    reset = "\033[0m" if isatty else ""

    prefix = "‣ "

    @classmethod
    def _print(cls, text: str) -> None:
        cls.out_file.write(text)

    @classmethod
    def print_step(cls, text: str) -> None:
        cls._print(f"{cls.prefix}{cls.bold}{text}{cls.reset}\n")

    @classmethod
    def info(cls, text: str) -> None:
        cls._print(text + "\n")

    @classmethod
    def warn(cls, text: str) -> None:
        cls._print(f"{cls.prefix}{cls.red}{text}{cls.reset}\n")
