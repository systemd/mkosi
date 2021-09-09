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
from pathlib import Path
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
    Sequence,
    Set,
    Union,
    cast,
)

PathString = Union[Path, str]


def shell_join(cmd: Sequence[PathString]) -> str:
    return " ".join(shlex.quote(str(x)) for x in cmd)


# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[Any]
    Popen = subprocess.Popen[Any]
else:
    CompletedProcess = subprocess.CompletedProcess
    Popen = subprocess.Popen


class MkosiException(Exception):
    """Leads to sys.exit"""


# This global should be initialized after parsing arguments
ARG_DEBUG: Set[str] = set()


class Parseable:
    "A mix-in to provide conversions for argparse"

    def __repr__(self) -> str:
        """Return the member name without the class name"""
        return cast(str, getattr(self, "name"))

    def __str__(self) -> str:
        return self.__repr__()

    @classmethod
    def from_string(cls: Any, name: str) -> Any:
        """A convenience method to be used with argparse"""
        try:
            return cls[name]
        except KeyError:
            raise argparse.ArgumentTypeError(f"unknown Format: {name!r}")

    @classmethod
    def parse_list(cls: Any, string: str) -> List[Any]:
        return [cls.from_string(p) for p in string.split(",") if p]


class PackageType(enum.Enum):
    rpm = 1
    deb = 2
    pkg = 3
    bundle = 4


class Distribution(enum.Enum):
    package_type: PackageType
    fedora = 0, PackageType.rpm
    debian = 1, PackageType.deb
    ubuntu = 2, PackageType.deb
    arch = 3, PackageType.pkg
    opensuse = 4, PackageType.rpm
    mageia = 5, PackageType.rpm
    centos = 6, PackageType.rpm
    centos_epel = 7, PackageType.rpm
    clear = 8, PackageType.bundle
    photon = 9, PackageType.rpm
    openmandriva = 10, PackageType.rpm

    def __new__(cls, number: int, package_type: PackageType) -> "Distribution":
        # This turns the list above into enum entries with .package_type attributes.
        # See https://docs.python.org/3.9/library/enum.html#when-to-use-new-vs-init
        # for an explanation.
        entry = object.__new__(cls)
        entry._value_ = number
        entry.package_type = package_type
        return cast("Distribution", entry)

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


class OutputFormat(Parseable, enum.Enum):
    directory = enum.auto()
    subvolume = enum.auto()
    tar = enum.auto()
    cpio = enum.auto()

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

    def is_disk_rw(self) -> bool:
        "Output format is a disk image with a parition table and a writable filesystem"
        return self in (OutputFormat.gpt_ext4, OutputFormat.gpt_xfs, OutputFormat.gpt_btrfs)

    def is_disk(self) -> bool:
        "Output format is a disk image with a partition table"
        return self.is_disk_rw() or self == OutputFormat.gpt_squashfs

    def is_squashfs(self) -> bool:
        "The output format contains a squashfs partition"
        return self in {OutputFormat.gpt_squashfs, OutputFormat.plain_squashfs}

    def is_btrfs(self) -> bool:
        "The output format contains a btrfs partition"
        return self in {OutputFormat.gpt_btrfs, OutputFormat.subvolume}

    def can_minimize(self) -> bool:
        "The output format can be 'minimized'"
        return self in (OutputFormat.gpt_ext4, OutputFormat.gpt_btrfs)

    def needed_kernel_module(self) -> str:
        if self == OutputFormat.gpt_btrfs:
            return "btrfs"
        elif self in (OutputFormat.gpt_squashfs, OutputFormat.plain_squashfs):
            return "squashfs"
        elif self == OutputFormat.gpt_xfs:
            return "xfs"
        else:
            return "ext4"

    def has_fs_compression(self) -> bool:
        return self.is_squashfs() or self.is_btrfs()


class ManifestFormat(Parseable, enum.Enum):
    json = "json"  # the standard manifest in json format
    changelog = "changelog"  # human-readable text file with package changelogs


@dataclasses.dataclass
class CommandLineArguments:
    """Type-hinted storage for command line arguments."""

    verb: str
    cmdline: List[str]

    distribution: Distribution
    release: str
    mirror: Optional[str]
    repositories: List[str]
    use_system_repositories: bool
    architecture: Optional[str]
    output_format: OutputFormat
    manifest_format: List[ManifestFormat]
    output: Path
    output_dir: Optional[Path]
    force_count: int
    bootable: bool
    boot_protocols: List[str]
    kernel_command_line: List[str]
    secure_boot: bool
    secure_boot_key: Path
    secure_boot_certificate: Path
    secure_boot_valid_days: str
    secure_boot_common_name: str
    read_only: bool
    encrypt: Optional[str]
    verity: bool
    compress: Union[None, str, bool]
    compress_fs: Union[None, str, bool]
    compress_output: Union[None, str, bool]
    mksquashfs_tool: List[PathString]
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
    cache_path: Optional[Path]
    extra_trees: List[Path]
    skeleton_trees: List[Path]
    clean_package_metadata: Union[bool, str]
    remove_files: List[Path]
    environment: List[str]
    build_sources: Optional[Path]
    build_dir: Optional[Path]
    include_dir: Optional[Path]
    install_dir: Optional[Path]
    build_packages: List[str]
    skip_final_phase: bool
    build_script: Optional[Path]
    prepare_script: Optional[Path]
    postinst_script: Optional[Path]
    finalize_script: Optional[Path]
    source_file_transfer: SourceFileTransfer
    source_file_transfer_final: Optional[SourceFileTransfer]
    source_resolve_symlinks: bool
    source_resolve_symlinks_final: bool
    with_network: Union[bool, str]
    nspawn_settings: Optional[Path]
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
    extra_search_paths: List[Path]
    network_veth: bool
    ephemeral: bool
    ssh: bool
    ssh_key: Optional[Path]
    ssh_timeout: int
    directory: Optional[Path]
    default_path: Optional[Path]
    all: bool
    all_directory: Optional[Path]
    debug: List[str]
    auto_bump: bool
    workspace_dir: Optional[Path]

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

    output_checksum: Optional[Path] = None
    output_nspawn_settings: Optional[Path] = None
    output_sshkey: Optional[Path] = None
    output_root_hash_file: Optional[Path] = None
    output_bmap: Optional[Path] = None
    output_split_root: Optional[Path] = None
    output_split_verity: Optional[Path] = None
    output_split_kernel: Optional[Path] = None
    cache_pre_inst: Optional[Path] = None
    cache_pre_dev: Optional[Path] = None
    output_signature: Optional[Path] = None

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


def should_compress_fs(args: Union[argparse.Namespace, CommandLineArguments]) -> Union[bool, str]:
    """True for the default compression, a string, or False.

    When explicitly configured with --compress-fs=, just return
    whatever was specified. When --compress= was used, try to be
    smart, so that either this function or should_compress_output()
    returns True as appropriate.
    """
    c = args.compress_fs
    if c is None and args.output_format.has_fs_compression():
        c = args.compress
    return False if c is None else c


def should_compress_output(args: Union[argparse.Namespace, CommandLineArguments]) -> Union[bool, str]:
    """A string or False.

    When explicitly configured with --compress-output=, use
    that. Since we have complete freedom with selecting the outer
    compression algorithm, pick some default when True. When
    --compress= was used, try to be smart, so that either this
    function or should_compress_fs() returns True as appropriate.
    """
    c = args.compress_output
    if c is None and not args.output_format.has_fs_compression():
        c = args.compress
    if c is True:
        return "xz"  # default compression
    return False if c is None else c


def workspace(root: Path) -> Path:
    return root.parent


def var_tmp(root: Path) -> Path:
    p = workspace(root) / "var-tmp"
    p.mkdir(exist_ok=True)
    return p


def partition(loopdev: Path, partno: int) -> Path:
    return Path(f"{loopdev}p{partno}")


def nspawn_params_for_blockdev_access(args: CommandLineArguments, loopdev: Path) -> List[str]:
    params = [
        f"--bind-ro={loopdev}",
        f"--property=DeviceAllow={loopdev}",
        "--bind-ro=/dev/block",
        "--bind-ro=/dev/disk",
    ]

    for partno in (args.esp_partno, args.bios_partno, args.root_partno, args.xbootldr_partno):
        if partno is not None:
            p = partition(loopdev, partno)
            if p.exists():
                params += [f"--bind-ro={p}", f"--property=DeviceAllow={p}"]

    params += [f"--setenv={env}" for env in args.environment]

    return params


def run_workspace_command(
    args: CommandLineArguments,
    root: Path,
    cmd: Sequence[PathString],
    network: bool = False,
    env: Optional[Dict[str, str]] = None,
    nspawn_params: Optional[List[str]] = None,
) -> None:
    nspawn = [
        "systemd-nspawn",
        "--quiet",
        f"--directory={root}",
        "--uuid=" + args.machine_id,
        "--machine=mkosi-" + uuid.uuid4().hex,
        "--as-pid2",
        "--register=no",
        f"--bind={var_tmp(root)}:/var/tmp",
        "--setenv=SYSTEMD_OFFLINE=1",
    ]

    if network:
        # If we're using the host network namespace, use the same resolver
        nspawn += ["--bind-ro=/etc/resolv.conf"]
    else:
        nspawn += ["--private-network"]

    if env:
        nspawn += [f"--setenv={k}={v}" for k, v in env.items()]

    if nspawn_params:
        nspawn += nspawn_params

    result = run([*nspawn, "--", *cmd], check=False)
    if result.returncode != 0:
        if "workspace-command" in ARG_DEBUG:
            run(nspawn, check=False)
        die(f"Workspace command {shell_join(cmd)} returned non-zero exit code {result.returncode}.")


@contextlib.contextmanager
def do_delay_interrupt() -> Generator[None, None, None]:
    # CTRL+C is sent to the entire process group. We delay its handling in mkosi itself so the subprocess can
    # exit cleanly before doing mkosi's cleanup. If we don't do this, we get device or resource is busy
    # errors when unmounting stuff later on during cleanup. We only delay a single CTRL+C interrupt so that a
    # user can always exit mkosi even if a subprocess hangs by pressing CTRL+C twice.
    interrupted = False

    def handler(signal: int, frame: Optional[FrameType]) -> None:
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


@contextlib.contextmanager
def do_noop() -> Generator[None, None, None]:
    yield


# Borrowed from https://github.com/python/typeshed/blob/3d14016085aed8bcf0cf67e9e5a70790ce1ad8ea/stdlib/3/subprocess.pyi#L24
_FILE = Union[None, int, IO[Any]]


def spawn(
    cmdline: Sequence[PathString],
    delay_interrupt: bool = True,
    stdout: _FILE = None,
    stderr: _FILE = None,
    **kwargs: Any,
) -> Popen:
    if "run" in ARG_DEBUG:
        MkosiPrinter.info(f"+ {shell_join(cmdline)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    cm = do_delay_interrupt if delay_interrupt else do_noop
    try:
        with cm():
            return subprocess.Popen(cmdline, stdout=stdout, stderr=stderr, **kwargs)
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")


def run(
    cmdline: Sequence[PathString],
    check: bool = True,
    delay_interrupt: bool = True,
    stdout: _FILE = None,
    stderr: _FILE = None,
    **kwargs: Any,
) -> CompletedProcess:
    cmdline = [str(x) for x in cmdline]

    if "run" in ARG_DEBUG:
        MkosiPrinter.info(f"+ {shell_join(cmdline)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    cm = do_delay_interrupt if delay_interrupt else do_noop
    try:
        with cm():
            return subprocess.run(cmdline, check=check, stdout=stdout, stderr=stderr, **kwargs)
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")


def tmp_dir() -> Path:
    path = os.environ.get("TMPDIR") or "/var/tmp"
    return Path(path)


def patch_file(filepath: Path, line_rewriter: Callable[[str], str]) -> None:
    temp_new_filepath = filepath.with_suffix(filepath.suffix + ".tmp.new")

    with filepath.open("r") as old, temp_new_filepath.open("w") as new:
        for line in old:
            new.write(line_rewriter(line))

    shutil.copystat(filepath, temp_new_filepath)
    os.remove(filepath)
    shutil.move(str(temp_new_filepath), filepath)


def path_relative_to_cwd(path: PathString) -> Path:
    "Return path as relative to $PWD if underneath, absolute path otherwise"
    path = Path(path)

    try:
        return path.relative_to(os.getcwd())
    except ValueError:
        return path


def write_grub_config(args: CommandLineArguments, root: Path) -> None:
    kernel_cmd_line = " ".join(args.kernel_command_line)
    grub_cmdline = f'GRUB_CMDLINE_LINUX="{kernel_cmd_line}"\n'
    os.makedirs(root / "etc/default", exist_ok=True, mode=0o755)
    grub_config = root / "etc/default/grub"
    if not os.path.exists(grub_config):
        grub_config.write_text(grub_cmdline)
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


def install_grub(args: CommandLineArguments, root: Path, loopdev: Path, grub: str) -> None:
    if args.bios_partno is None:
        return

    write_grub_config(args, root)

    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    cmdline: Sequence[PathString] = [f"{grub}-install", "--modules=ext2 part_gpt", "--target=i386-pc", loopdev]
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

    level = 0

    @classmethod
    def _print(cls, text: str) -> None:
        cls.out_file.write(text)

    @classmethod
    def print_step(cls, text: str) -> None:
        prefix = cls.prefix + " " * cls.level
        if sys.exc_info()[0]:
            # We are falling through exception handling blocks.
            # De-emphasize this step here, so the user can tell more
            # easily which step generated the exception. The exception
            # or error will only be printed after we finish cleanup.
            cls._print(f"{prefix}({text})\n")
        else:
            cls._print(f"{prefix}{cls.bold}{text}{cls.reset}\n")

    @classmethod
    def info(cls, text: str) -> None:
        cls._print(text + "\n")

    @classmethod
    def warn(cls, text: str) -> None:
        cls._print(f"{cls.prefix}{cls.red}{text}{cls.reset}\n")

    @classmethod
    @contextlib.contextmanager
    def complete_step(cls, text: str, text2: Optional[str] = None) -> Generator[List[Any], None, None]:
        cls.print_step(text)

        cls.level += 1
        try:
            args: List[Any] = []
            yield args
        finally:
            cls.level -= 1
            assert cls.level >= 0

        if text2 is not None:
            cls.print_step(text2.format(*args))
