# SPDX-License-Identifier: LGPL-2.1+

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import enum
import math
import os
import platform
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import FrameType
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    NoReturn,
    Optional,
    Sequence,
    Set,
    Type,
    Union,
    cast,
)

PathString = Union[Path, str]


def shell_join(cmd: Sequence[PathString]) -> str:
    return " ".join(shlex.quote(str(x)) for x in cmd)


@contextlib.contextmanager
def set_umask(mask: int) -> Iterator[int]:
    old = os.umask(mask)
    try:
        yield old
    finally:
        os.umask(old)


def print_between_lines(s: str) -> None:
    size = os.get_terminal_size()
    print('-' * size.columns)
    print(s.rstrip('\n'))
    print('-' * size.columns)


def roundup(x: int, step: int) -> int:
    return ((x + step - 1) // step) * step


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


class MkosiNotSupportedException(MkosiException):
    """Leads to sys.exit when an invalid combination of parsed arguments happens"""


# This global should be initialized after parsing arguments
ARG_DEBUG: Set[str] = set()


class Parseable:
    "A mix-in to provide conversions for argparse"

    def __str__(self) -> str:
        """Return the member name without the class name"""
        return cast(str, getattr(self, "name"))

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
    ebuild = 5


class Verb(enum.Enum):
    build   = "build"
    clean   = "clean"
    summary = "summary"
    shell   = "shell"
    boot    = "boot"
    qemu    = "qemu"
    ssh     = "ssh"
    serve   = "serve"
    bump    = "bump"
    help    = "help"
    genkey  = "genkey"

    # Defining __str__ is required to get "print_help()" output to include the human readable (values) of Verb.
    def __str__(self) -> str:
        return self.value


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
    openmandriva = 10, PackageType.rpm
    rocky = 11, PackageType.rpm
    rocky_epel = 12, PackageType.rpm
    alma = 13, PackageType.rpm
    alma_epel = 14, PackageType.rpm
    gentoo = 15, PackageType.ebuild

    def __new__(cls, number: int, package_type: PackageType) -> Distribution:
        # This turns the list above into enum entries with .package_type attributes.
        # See https://docs.python.org/3.9/library/enum.html#when-to-use-new-vs-init
        # for an explanation.
        entry = object.__new__(cls)
        entry._value_ = number
        entry.package_type = package_type
        return entry

    def __str__(self) -> str:
        return self.name

def is_rpm_distribution(d: Distribution) -> bool:
    return d in (
        Distribution.fedora,
        Distribution.mageia,
        Distribution.centos,
        Distribution.centos_epel,
        Distribution.openmandriva,
        Distribution.rocky,
        Distribution.rocky_epel,
        Distribution.alma,
        Distribution.alma_epel
    )


def is_centos_variant(d: Distribution) -> bool:
    return d in (
        Distribution.centos,
        Distribution.centos_epel,
        Distribution.alma,
        Distribution.alma_epel,
        Distribution.rocky,
        Distribution.rocky_epel,
    )


def is_epel_variant(d: Distribution) -> bool:
    return d in (
        Distribution.centos_epel,
        Distribution.alma_epel,
        Distribution.rocky_epel,
    )


class SourceFileTransfer(enum.Enum):
    copy_all = "copy-all"
    copy_git_cached = "copy-git-cached"
    copy_git_others = "copy-git-others"
    copy_git_more = "copy-git-more"
    mount = "mount"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def doc(cls) -> Dict[SourceFileTransfer, str]:
        return {
            cls.copy_all: "normal file copy",
            cls.copy_git_cached: "use git ls-files --cached, ignoring any file that git itself ignores",
            cls.copy_git_others: "use git ls-files --others, ignoring any file that git itself ignores",
            cls.copy_git_more: "use git ls-files --cached, ignoring any file that git itself ignores, but include the .git/ directory",
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

    def __str__(self) -> str:
        return Parseable.__str__(self)

class ManifestFormat(Parseable, enum.Enum):
    json      = "json"       # the standard manifest in json format
    changelog = "changelog"  # human-readable text file with package changelogs

    def __str__(self) -> str:
        return Parseable.__str__(self)

class PartitionIdentifier(enum.Enum):
    esp        = "esp"
    bios       = "bios"
    xbootldr   = "xbootldr"
    root       = "root"
    swap       = "swap"
    home       = "home"
    srv        = "srv"
    var        = "var"
    tmp        = "tmp"
    verity     = "verity"
    verity_sig = "verity-sig"


@dataclasses.dataclass
class Partition:
    number: int

    n_sectors: int
    type_uuid: uuid.UUID
    part_uuid: Optional[uuid.UUID]
    read_only: Optional[bool]

    description: str

    def blockdev(self, loopdev: Path) -> Path:
        return Path(f"{loopdev}p{self.number}")

    def sfdisk_spec(self) -> str:
        desc = [f'size={self.n_sectors}',
                f'type={self.type_uuid}',
                f'attrs={"GUID:60" if self.read_only else ""}',
                f'name="{self.description}"',
                f'uuid={self.part_uuid}' if self.part_uuid is not None else None]
        return ', '.join(filter(None, desc))


@dataclasses.dataclass
class PartitionTable:
    partitions: Dict[PartitionIdentifier, Partition] = dataclasses.field(default_factory=dict)
    last_partition_sector: Optional[int] = None
    sector_size: int = 512
    first_lba: Optional[int] = None

    grain: int = 4096

    def first_partition_offset(self, max_partitions: int = 128) -> int:
        if self.first_lba is not None:
            # No rounding here, we honour the specified value exactly.
            return self.first_lba * self.sector_size
        else:
            # The header is like the footer, but we have a one-sector "protective MBR" at offset 0
            return roundup(self.sector_size + self.footer_size(), self.grain)

    def last_partition_offset(self, max_partitions: int = 128) -> int:
        if self.last_partition_sector:
            return roundup(self.last_partition_sector * self.sector_size, self.grain)
        else:
            return self.first_partition_offset(max_partitions)

    def partition_offset(self, partition: Partition) -> int:
        offset = self.first_partition_offset()

        for p in self.partitions.values():
            if p == partition:
                break

            offset += p.n_sectors * self.sector_size

        return offset

    def partition_size(self, partition: Partition) -> int:
        return partition.n_sectors * self.sector_size

    def footer_size(self, max_partitions: int = 128) -> int:
        # The footer must have enough space for the GPT header (one sector),
        # and the GPT parition entry area. PEA size of 16384 (128 partitions)
        # is recommended.
        pea_sectors = math.ceil(max_partitions * 128 / self.sector_size)
        return (1 + pea_sectors) * self.sector_size

    def disk_size(self) -> int:
        return roundup(self.last_partition_offset() + self.footer_size(), self.grain)

    def add(self,
            ident: PartitionIdentifier,
            size: int,
            type_uuid: uuid.UUID,
            description: str,
            part_uuid: Optional[uuid.UUID] = None,
            read_only: Optional[bool] = False) -> Partition:

        assert '"' not in description

        size = roundup(size, self.grain)
        n_sectors = size // self.sector_size

        part = Partition(len(self.partitions) + 1,
                         n_sectors, type_uuid, part_uuid, read_only, description)
        self.partitions[ident] = part

        self.last_partition_sector = self.last_partition_offset() // self.sector_size + n_sectors

        return part

    def partition_path(self, ident: PartitionIdentifier, loopdev: Path) -> Optional[Path]:
        part = self.partitions.get(ident)
        if part is None:
            return None

        return part.blockdev(loopdev)

    def sfdisk_spec(self) -> str:
        table = ["label: gpt",
                 f"grain: {self.grain}",
                 f"first-lba: {self.first_partition_offset() // self.sector_size}",
                 *(p.sfdisk_spec() for p in self.partitions.values())]
        return '\n'.join(table)

    def run_sfdisk(self, device: PathString, *, quiet: bool = False) -> None:
        spec = self.sfdisk_spec()
        device = Path(device)

        if 'disk' in ARG_DEBUG:
            print_between_lines(spec)

        cmd: List[PathString] = ["sfdisk", "--color=never", "--no-reread", "--no-tell-kernel", device]
        if quiet:
            cmd += ["--quiet"]

        try:
            run(cmd, input=spec.encode("utf-8"))
        except subprocess.CalledProcessError:
            print_between_lines(spec)
            raise

        if device.is_block_device():
            run(["sync"])
            run_with_backoff(["blockdev", "--rereadpt", device], attempts=10)


@dataclasses.dataclass
class MkosiArgs:
    """Type-hinted storage for command line arguments."""

    verb: Verb
    cmdline: List[str]
    force: int

    distribution: Distribution
    release: str
    mirror: Optional[str]
    repositories: List[str]
    use_host_repositories: bool
    repos_dir: Optional[str]
    architecture: str
    output_format: OutputFormat
    manifest_format: List[ManifestFormat]
    output: Path
    output_dir: Optional[Path]
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
    verity: Union[bool, str]
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
    cache_initrd: bool
    base_packages: Union[str, bool]
    packages: List[str]
    remove_packages: List[str]
    with_docs: bool
    with_tests: bool
    cache_path: Optional[Path]
    extra_trees: List[Path]
    skeleton_trees: List[Path]
    clean_package_metadata: Union[bool, str]
    remove_files: List[Path]
    environment: Dict[str, str]
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
    base_image: Optional[Path]
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
    netdev: bool
    ephemeral: bool
    ssh: bool
    ssh_key: Optional[Path]
    ssh_agent: Optional[Path]
    ssh_timeout: int
    ssh_port: int
    directory: Optional[Path]
    default_path: Optional[Path]
    all: bool
    all_directory: Optional[Path]
    debug: List[str]
    auto_bump: bool
    workspace_dir: Optional[Path]
    machine_id: str

    # QEMU-specific options
    qemu_headless: bool
    qemu_smp: str
    qemu_mem: str
    qemu_kvm: bool
    qemu_args: Sequence[str]
    qemu_boot: str

    # systemd-nspawn specific options
    nspawn_keep_unit: bool

    # Some extra stuff that's stored in MkosiArgs for convenience but isn't populated by arguments
    machine_id_is_fixed: bool
    original_umask: int
    passphrase: Optional[Dict[str, str]]

    output_checksum: Optional[Path] = None
    output_nspawn_settings: Optional[Path] = None
    output_sshkey: Optional[Path] = None
    output_root_hash_file: Optional[Path] = None
    output_root_hash_p7s_file: Optional[Path] = None
    output_bmap: Optional[Path] = None
    output_split_root: Optional[Path] = None
    output_split_verity: Optional[Path] = None
    output_split_verity_sig: Optional[Path] = None
    output_split_kernel: Optional[Path] = None
    cache_pre_inst: Optional[Path] = None
    cache_pre_dev: Optional[Path] = None
    output_signature: Optional[Path] = None

    partition_table: Optional[PartitionTable] = None

    def get_partition(self, ident: PartitionIdentifier) -> Optional[Partition]:
        "A shortcut to check that we have a partition table and extract the partition object"
        if self.partition_table is None:
            return None
        return self.partition_table.partitions.get(ident)

    def architecture_is_native(self) -> bool:
        return self.architecture == platform.machine()


def should_compress_fs(args: Union[argparse.Namespace, MkosiArgs]) -> Union[bool, str]:
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


def should_compress_output(args: Union[argparse.Namespace, MkosiArgs]) -> Union[bool, str]:
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


def nspawn_params_for_blockdev_access(args: MkosiArgs, loopdev: Path) -> List[str]:
    assert args.partition_table is not None

    params = [
        f"--bind-ro={loopdev}",
        f"--property=DeviceAllow={loopdev}",
        "--bind-ro=/dev/block",
        "--bind-ro=/dev/disk",
    ]

    for ident in (PartitionIdentifier.esp,
                  PartitionIdentifier.bios,
                  PartitionIdentifier.root,
                  PartitionIdentifier.xbootldr):
        path = args.partition_table.partition_path(ident, loopdev)
        if path and path.exists():
            params += [f"--bind-ro={path}", f"--property=DeviceAllow={path}"]

    params += [f"--setenv={env}={value}" for env, value in args.environment.items()]

    return params


def format_rlimit(rlimit: int) -> str:
        limits = resource.getrlimit(rlimit)
        soft = "infinity" if limits[0] == resource.RLIM_INFINITY else str(limits[0])
        hard = "infinity" if limits[1] == resource.RLIM_INFINITY else str(limits[1])
        return f"{soft}:{hard}"


def nspawn_rlimit_params() -> Sequence[str]:
    return [
        f"--rlimit=RLIMIT_CORE={format_rlimit(resource.RLIMIT_CORE)}",
    ]


def nspawn_executable() -> str:
    return os.getenv("MKOSI_NSPAWN_EXECUTABLE", "systemd-nspawn")


def nspawn_version() -> int:
    return int(run([nspawn_executable(), "--version"], stdout=subprocess.PIPE).stdout.strip().split()[1])


def run_workspace_command(
    args: MkosiArgs,
    root: Path,
    cmd: Sequence[PathString],
    network: bool = False,
    env: Optional[Mapping[str, str]] = None,
    nspawn_params: Optional[List[str]] = None,
    capture_stdout: bool = False,
    check: bool = True,
) -> CompletedProcess:
    nspawn = [
        nspawn_executable(),
        "--quiet",
        f"--directory={root}",
        "--uuid=" + args.machine_id,
        "--machine=mkosi-" + uuid.uuid4().hex,
        "--as-pid2",
        "--register=no",
        f"--bind={var_tmp(root)}:/var/tmp",
        "--setenv=SYSTEMD_OFFLINE=1",
        *nspawn_rlimit_params(),
    ]
    stdout = None

    if network:
        # If we're using the host network namespace, use the same resolver
        nspawn += ["--bind-ro=/etc/resolv.conf"]
    else:
        nspawn += ["--private-network"]

    if env:
        nspawn += [f"--setenv={k}={v}" for k, v in env.items()]
    if "workspace-command" in ARG_DEBUG:
        nspawn += ["--setenv=SYSTEMD_LOG_LEVEL=debug"]

    if nspawn_params:
        nspawn += nspawn_params

    if capture_stdout:
        stdout = subprocess.PIPE
        nspawn += ["--console=pipe"]

    if args.usr_only:
        nspawn += [f"--bind={root_home(args, root)}:/root"]

    if args.nspawn_keep_unit:
        nspawn += ["--keep-unit"]

    try:
        return run([*nspawn, "--", *cmd], check=check, stdout=stdout, text=capture_stdout)
    except subprocess.CalledProcessError as e:
        if "workspace-command" in ARG_DEBUG:
            run(nspawn, check=False)
        die(f"Workspace command {shell_join(cmd)} returned non-zero exit code {e.returncode}.")


def root_home(args: MkosiArgs, root: Path) -> Path:

    # If UsrOnly= is turned on the /root/ directory (i.e. the root
    # user's home directory) is not persistent (after all everything
    # outside of /usr/ is not around). In that case let's mount it in
    # from an external place, so that we can have persistency. It is
    # after all where we place our build sources and suchlike.

    if args.usr_only:
        return workspace(root) / "home-root"

    return root / "root"


@contextlib.contextmanager
def do_delay_interrupt() -> Iterator[None]:
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
def do_noop() -> Iterator[None]:
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
    env: Mapping[str, Any] = {},
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

    # This is a workaround for copy_git_files, which uses the user= option to
    # subprocess.run, which is only available starting with Python 3.9
    # TODO: remove this branch once mkosi defaults to at least Python 3.9
    if "user" in kwargs and sys.version_info < (3, 9):
        user = kwargs.pop("user")
        user = f"#{user}" if isinstance(user, int) else user
        cmdline = ["sudo", "-u", user] + cmdline

    cm = do_delay_interrupt if delay_interrupt else do_noop
    try:
        with cm():
            return subprocess.run(cmdline, check=check, stdout=stdout, stderr=stderr, env={**os.environ, **env}, **kwargs)
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")


def run_with_backoff(
    cmdline: Sequence[PathString],
    check: bool = True,
    delay_interrupt: bool = True,
    stdout: _FILE = None,
    stderr: _FILE = None,
    *,
    attempts: int,
    **kwargs: Any,
) -> CompletedProcess:
    delay = 0.0
    for attempt in range(attempts):
        try:
            return run(cmdline, check, delay_interrupt, stdout, stderr, **kwargs)
        except subprocess.CalledProcessError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2 + 0.01, 1)

    assert False  # make mypy happy


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


def write_grub_config(args: MkosiArgs, root: Path) -> None:
    kernel_cmd_line = " ".join(args.kernel_command_line)
    grub_cmdline = f'GRUB_CMDLINE_LINUX="{kernel_cmd_line}"\n'
    os.makedirs(root / "etc/default", exist_ok=True, mode=0o755)
    grub_config = root / "etc/default/grub"
    if not os.path.exists(grub_config):
        grub_config.write_text(grub_cmdline)
    else:

        def jj(line: str) -> str:
            if line.startswith(("GRUB_CMDLINE_LINUX=", "#GRUB_CMDLINE_LINUX=")):  # GENTOO:
                return grub_cmdline
            if args.qemu_headless:
                if "GRUB_TERMINAL" in line:
                    return line.strip('#').split('=')[0] + '="console serial"'
            return line

        patch_file(grub_config, jj)

        if args.qemu_headless:
            with open(grub_config, "a") as f:
                f.write('GRUB_SERIAL_COMMAND="serial --unit=0 --speed 115200"\n')


def install_grub(args: MkosiArgs, root: Path, loopdev: Path) -> None:
    assert args.partition_table is not None

    part = args.get_partition(PartitionIdentifier.bios)
    if not part:
        return

    write_grub_config(args, root)

    nspawn_params = nspawn_params_for_blockdev_access(args, loopdev)

    grub = "/usr/sbin/grub" if root.joinpath("usr/sbin/grub-install").exists() else "/usr/sbin/grub2"

    cmdline: Sequence[PathString] = [f"{grub}-install", "--modules=ext2 part_gpt", "--target=i386-pc", loopdev]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)

    # TODO: Remove os.path.basename once https://github.com/systemd/systemd/pull/16645 is widely available.
    cmdline = [f"{grub}-mkconfig", f"--output=/boot/{os.path.basename(grub)}/grub.cfg"]
    run_workspace_command(args, root, cmdline, nspawn_params=nspawn_params)


def die(message: str, exception: Type[MkosiException] = MkosiException) -> NoReturn:
    MkosiPrinter.warn(f"Error: {message}")
    raise exception(message)


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
    def complete_step(cls, text: str, text2: Optional[str] = None) -> Iterator[List[Any]]:
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
