# SPDX-License-Identifier: LGPL-2.1+

import argparse
import ast
import contextlib
import dataclasses
import enum
import functools
import importlib
import itertools
import os
import platform
import pwd
import re
import resource
import shutil
import sys
import tarfile
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union, cast

from mkosi.distributions import DistributionInstaller
from mkosi.log import MkosiException, die

T = TypeVar("T")
V = TypeVar("V")


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
    def parse_list(cls: Any, string: str) -> list[Any]:
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

    fedora       = "fedora", PackageType.rpm
    debian       = "debian", PackageType.deb
    ubuntu       = "ubuntu", PackageType.deb
    arch         = "arch", PackageType.pkg
    opensuse     = "opensuse", PackageType.rpm
    mageia       = "mageia", PackageType.rpm
    centos       = "centos", PackageType.rpm
    openmandriva = "openmandriva", PackageType.rpm
    rocky        = "rocky", PackageType.rpm
    alma         = "alma", PackageType.rpm
    gentoo       = "gentoo", PackageType.ebuild

    def __new__(cls, name: str, package_type: PackageType) -> "Distribution":
        # This turns the list above into enum entries with .package_type attributes.
        # See https://docs.python.org/3.9/library/enum.html#when-to-use-new-vs-init
        # for an explanation.
        entry = object.__new__(cls)
        entry._value_ = name
        entry.package_type = package_type
        return entry

    def __str__(self) -> str:
        return self.name


def dictify(f: Callable[..., Iterator[tuple[T, V]]]) -> Callable[..., dict[T, V]]:
    def wrapper(*args: Any, **kwargs: Any) -> dict[T, V]:
        return dict(f(*args, **kwargs))

    return functools.update_wrapper(wrapper, f)


@dictify
def read_os_release() -> Iterator[tuple[str, str]]:
    try:
        filename = "/etc/os-release"
        f = open(filename)
    except FileNotFoundError:
        filename = "/usr/lib/os-release"
        f = open(filename)

    with f:
        for line_number, line in enumerate(f, start=1):
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            if (m := re.match(r"([A-Z][A-Z_0-9]+)=(.*)", line)):
                name, val = m.groups()
                if val and val[0] in "\"'":
                    val = ast.literal_eval(val)
                yield name, val
            else:
                print(f"{filename}:{line_number}: bad line {line!r}", file=sys.stderr)


def detect_distribution() -> tuple[Optional[Distribution], Optional[str]]:
    try:
        os_release = read_os_release()
    except FileNotFoundError:
        return None, None

    dist_id = os_release.get("ID", "linux")
    dist_id_like = os_release.get("ID_LIKE", "").split()
    version = os_release.get("VERSION", None)
    version_id = os_release.get("VERSION_ID", None)
    version_codename = os_release.get("VERSION_CODENAME", None)
    extracted_codename = None

    if version:
        # extract Debian release codename
        m = re.search(r"\((.*?)\)", version)
        if m:
            extracted_codename = m.group(1)

    d: Optional[Distribution] = None
    for the_id in [dist_id, *dist_id_like]:
        d = Distribution.__members__.get(the_id, None)
        if d is not None:
            break

    if d in {Distribution.debian, Distribution.ubuntu} and (version_codename or extracted_codename):
        # debootstrap needs release codenames, not version numbers
        version_id = version_codename or extracted_codename

    return d, version_id


def is_rpm_distribution(d: Distribution) -> bool:
    return d in (
        Distribution.fedora,
        Distribution.mageia,
        Distribution.centos,
        Distribution.openmandriva,
        Distribution.rocky,
        Distribution.alma,
    )


def is_centos_variant(d: Distribution) -> bool:
    return d in (
        Distribution.centos,
        Distribution.alma,
        Distribution.rocky,
    )


class OutputFormat(Parseable, enum.Enum):
    directory = enum.auto()
    subvolume = enum.auto()
    tar = enum.auto()
    cpio = enum.auto()
    disk = enum.auto()

    def __str__(self) -> str:
        return Parseable.__str__(self)

class ManifestFormat(Parseable, enum.Enum):
    json      = "json"       # the standard manifest in json format
    changelog = "changelog"  # human-readable text file with package changelogs

    def __str__(self) -> str:
        return Parseable.__str__(self)

KNOWN_SUFFIXES = {
    ".xz",
    ".zstd",
    ".raw",
    ".tar",
    ".cpio",
    ".qcow2",
}


def strip_suffixes(path: Path) -> Path:
    while path.suffix in KNOWN_SUFFIXES:
        path = path.with_suffix("")
    return path


@dataclasses.dataclass(frozen=True)
class MkosiConfig:
    """Type-hinted storage for command line arguments.

    Only user configuration is stored here while dynamic state exists in
    MkosiState. If a field of the same name exists in both classes always
    access the value from state.
    """

    verb: Verb
    cmdline: list[str]
    force: int

    distribution: Distribution
    release: str
    mirror: Optional[str]
    local_mirror: Optional[str]
    repository_key_check: bool
    repositories: list[str]
    repo_dirs: list[Path]
    repart_dir: Optional[str]
    architecture: str
    output_format: OutputFormat
    manifest_format: list[ManifestFormat]
    output: Path
    output_dir: Optional[Path]
    bootable: bool
    kernel_command_line: list[str]
    secure_boot: bool
    secure_boot_key: Path
    secure_boot_certificate: Path
    secure_boot_valid_days: str
    secure_boot_common_name: str
    sign_expected_pcr: bool
    compress_output: Union[None, str, bool]
    qcow2: bool
    image_version: Optional[str]
    image_id: Optional[str]
    hostname: Optional[str]
    tar_strip_selinux_context: bool
    incremental: bool
    cache_initrd: bool
    base_packages: Union[str, bool]
    packages: list[str]
    remove_packages: list[str]
    with_docs: bool
    with_tests: bool
    cache_path: Path
    extra_trees: list[Path]
    skeleton_trees: list[Path]
    clean_package_metadata: Union[bool, str]
    remove_files: list[Path]
    environment: dict[str, str]
    build_sources: Path
    build_dir: Optional[Path]
    install_dir: Optional[Path]
    build_packages: list[str]
    skip_final_phase: bool
    build_script: Optional[Path]
    prepare_script: Optional[Path]
    postinst_script: Optional[Path]
    finalize_script: Optional[Path]
    with_network: Union[bool, str]
    nspawn_settings: Optional[Path]
    base_image: Optional[Path]
    checksum: bool
    split_artifacts: bool
    sign: bool
    key: Optional[str]
    bmap: bool
    password: Optional[str]
    password_is_hashed: bool
    autologin: bool
    extra_search_paths: list[Path]
    netdev: bool
    ephemeral: bool
    ssh: bool
    ssh_key: Optional[Path]
    ssh_agent: Optional[Path]
    ssh_timeout: int
    ssh_port: int
    credentials: dict[str, str]
    directory: Optional[Path]
    config_path: Optional[Path]
    debug: list[str]
    auto_bump: bool
    workspace_dir: Optional[Path]

    # QEMU-specific options
    qemu_headless: bool
    qemu_smp: str
    qemu_mem: str
    qemu_kvm: bool
    qemu_args: Sequence[str]

    passphrase: Optional[Path]

    def architecture_is_native(self) -> bool:
        return self.architecture == platform.machine()

    @property
    def output_split_kernel(self) -> Path:
        return build_auxiliary_output_path(self, ".efi")

    @property
    def output_nspawn_settings(self) -> Path:
        return build_auxiliary_output_path(self, ".nspawn")

    @property
    def output_checksum(self) -> Path:
        return Path("SHA256SUMS")

    @property
    def output_signature(self) -> Path:
        return Path("SHA256SUMS.gpg")

    @property
    def output_bmap(self) -> Path:
        return build_auxiliary_output_path(self, ".bmap")

    @property
    def output_sshkey(self) -> Path:
        return build_auxiliary_output_path(self, ".ssh")

    @property
    def output_manifest(self) -> Path:
        return build_auxiliary_output_path(self, ".manifest")

    @property
    def output_changelog(self) -> Path:
        return build_auxiliary_output_path(self, ".changelog")

    def output_paths(self) -> tuple[Path, ...]:
        return (
            self.output,
            self.output_split_kernel,
            self.output_nspawn_settings,
            self.output_checksum,
            self.output_signature,
            self.output_bmap,
            self.output_sshkey,
            self.output_manifest,
            self.output_changelog,
        )


def build_auxiliary_output_path(args: Union[argparse.Namespace, MkosiConfig], suffix: str) -> Path:
    output = strip_suffixes(args.output)
    return output.with_name(f"{output.name}{suffix}")


@dataclasses.dataclass
class MkosiState:
    """State related properties."""

    uid: int
    gid: int
    config: MkosiConfig
    workspace: Path
    cache: Path
    do_run_build_script: bool
    for_cache: bool
    environment: dict[str, str] = dataclasses.field(init=False)
    installer: DistributionInstaller = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.environment = self.config.environment.copy()
        if self.config.image_id is not None:
            self.environment['IMAGE_ID'] = self.config.image_id
        if self.config.image_version is not None:
            self.environment['IMAGE_VERSION'] = self.config.image_version
        try:
            distro = str(self.config.distribution)
            mod = importlib.import_module(f"mkosi.distributions.{distro}")
            installer = getattr(mod, f"{distro.title().replace('_','')}Installer")
            instance = installer() if issubclass(installer, DistributionInstaller) else None
        except (ImportError, AttributeError):
            instance = None
        if instance is None:
            die("No installer for this distribution.")
        self.installer = instance

        self.root.mkdir(exist_ok=True, mode=0o755)
        self.var_tmp.mkdir(exist_ok=True)
        self.staging.mkdir(exist_ok=True)

    @property
    def root(self) -> Path:
        return self.workspace / "root"

    @property
    def var_tmp(self) -> Path:
        return self.workspace / "var-tmp"

    @property
    def staging(self) -> Path:
        return self.workspace / "staging"


def should_compress_output(config: Union[argparse.Namespace, MkosiConfig]) -> Union[bool, str]:
    """A string or False.

    When explicitly configured with --compress-output=, use
    that. Since we have complete freedom with selecting the outer
    compression algorithm, pick some default when True.
    """
    c = config.compress_output
    if c is None and config.output_format == OutputFormat.tar:
        c = True
    if c is True:
        return "xz"  # default compression
    return False if c is None else c


def format_rlimit(rlimit: int) -> str:
    limits = resource.getrlimit(rlimit)
    soft = "infinity" if limits[0] == resource.RLIM_INFINITY else str(limits[0])
    hard = "infinity" if limits[1] == resource.RLIM_INFINITY else str(limits[1])
    return f"{soft}:{hard}"


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
    shutil.move(temp_new_filepath, filepath)


def path_relative_to_cwd(path: Path) -> Path:
    "Return path as relative to $PWD if underneath, absolute path otherwise"
    try:
        return path.relative_to(os.getcwd())
    except ValueError:
        return path


def safe_tar_extract(tar: tarfile.TarFile, path: Path=Path("."), *, numeric_owner: bool=False) -> None:
    """Extract a tar without CVE-2007-4559.

    Throws a MkosiException if a member of the tar resolves to a path that would
    be outside of the passed in target path.

    Omits the member argument from TarFile.extractall, since we don't need it at
    the moment.

    See https://github.com/advisories/GHSA-gw9q-c7gh-j9vm
    """
    path = path.resolve()
    for member in tar.getmembers():
        target = path / member.name
        try:
            # a.relative_to(b) throws a ValueError if a is not a subpath of b
            target.resolve().relative_to(path)
        except ValueError as e:
            raise MkosiException(f"Attempted path traversal in tar file {tar.name!r}") from e

    tar.extractall(path, numeric_owner=numeric_owner)


def disable_pam_securetty(root: Path) -> None:
    def _rm_securetty(line: str) -> str:
        if "pam_securetty.so" in line:
            return ""
        return line

    patch_file(root / "etc/pam.d/login", _rm_securetty)


def add_packages(
    config: MkosiConfig, packages: set[str], *names: str, conditional: Optional[str] = None
) -> None:

    """Add packages in @names to @packages, if enabled by --base-packages.

    If @conditional is specified, rpm-specific syntax for boolean
    dependencies will be used to include @names if @conditional is
    satisfied.
    """
    assert config.base_packages is True or config.base_packages is False or config.base_packages == "conditional"

    if config.base_packages is True or (config.base_packages == "conditional" and conditional):
        for name in names:
            packages.add(f"({name} if {conditional})" if conditional else name)


def sort_packages(packages: Iterable[str]) -> list[str]:
    """Sorts packages: normal first, paths second, conditional third"""

    m = {"(": 2, "/": 1}
    sort = lambda name: (m.get(name[0], 0), name)
    return sorted(packages, key=sort)


def flatten(lists: Iterable[Iterable[T]]) -> list[T]:
    """Flatten a sequence of sequences into a single list."""
    return list(itertools.chain.from_iterable(lists))


def current_user_uid_gid() -> tuple[int, int]:
    uid = int(os.getenv("SUDO_UID") or os.getenv("PKEXEC_UID") or os.getuid())
    gid = pwd.getpwuid(uid).pw_gid
    return uid, gid
