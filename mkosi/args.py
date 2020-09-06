from dataclasses import dataclass, field, fields, Field, MISSING
from typing import (
    Any,
    List,
    TypeVar,
    Optional,
    overload,
    Union,
    Sequence,
    Iterable,
    Callable,
)
import argparse

from . import (
    Distribution,
    OutputFormat,
    MKOSI_COMMANDS_CMDLINE,
    MKOSI_COMMANDS,
    SourceFileTransfer,
)


_T = TypeVar("_T")


@overload
def arg(*, default: _T, **kwargs: Any) -> _T:
    ...


@overload
def arg(*, default_factory: Callable[[], _T], **kwargs: Any) -> _T:
    ...


@overload
def arg(**kwargs: Any) -> Any:
    ...


# metadata is passed to ArgumentParser.add_argument()
def arg(default=MISSING, default_factory=MISSING, **kwargs):  # type: ignore
    return field(default=default, default_factory=default_factory, metadata=kwargs)  # type: ignore


def parse_boolean(s: str) -> bool:
    "Parse 1/true/yes as true and 0/false/no as false"
    s_l = s.lower()
    if s_l in {"1", "true", "yes"}:
        return True

    if s_l in {"0", "false", "no"}:
        return False

    raise ValueError(f"Invalid literal for bool(): {s!r}")


def parse_compression(value: str) -> Union[str, bool]:
    if value in ["zlib", "lzo", "zstd", "lz4", "xz"]:
        return value
    return parse_boolean(value)


def parse_bytes(num_bytes: Optional[str]) -> Optional[int]:
    if num_bytes is None:
        return num_bytes

    if num_bytes.endswith("G"):
        factor = 1024 ** 3
    elif num_bytes.endswith("M"):
        factor = 1024 ** 2
    elif num_bytes.endswith("K"):
        factor = 1024
    else:
        factor = 1

    if factor > 1:
        num_bytes = num_bytes[:-1]

    result = int(num_bytes) * factor
    if result <= 0:
        raise ValueError("Size out of range")

    if result % 512 != 0:
        raise ValueError("Size not a multiple of 512")

    return result


class ListAction(argparse.Action):
    delimiter: str

    def __init__(
        self, *args: Any, choices: Optional[Iterable[Any]] = None, **kwargs: Any
    ) -> None:
        self.list_choices = choices
        super().__init__(*args, **kwargs)

    def __call__(
        self,  # These type-hints are copied from argparse.pyi
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        assert isinstance(values, str)
        ary = getattr(namespace, self.dest)
        if ary is None:
            ary = []

        # Support list syntax for comma separated lists as well
        if self.delimiter == "," and values.startswith("[") and values.endswith("]"):
            values = values[1:-1]

        new = values.split(self.delimiter)

        for x in new:
            x = x.strip()
            if not x:  # ignore empty entries
                continue
            if self.list_choices is not None and x not in self.list_choices:
                raise ValueError(f"Unknown value {x!r}")

            # Remove ! prefixed list entries from list. !* removes all entries. This works for strings only now.
            if x.startswith("!*"):
                ary = []
            elif x.startswith("!"):
                if x[1:] in ary:
                    ary.remove(x[1:])
            else:
                ary.append(x)
        setattr(namespace, self.dest, ary)


class CommaDelimitedListAction(ListAction):
    delimiter = ","


class ColonDelimitedListAction(ListAction):
    delimiter = ":"


class SpaceDelimitedListAction(ListAction):
    delimiter = " "


class BooleanAction(argparse.Action):
    """Parse boolean command line arguments

    The argument may be added more than once. The argument may be set explicitly (--foo yes)
    or implicitly --foo. If the parameter name starts with "not-" or "without-" the value gets
    inverted.
    """

    def __init__(
        self,  # These type-hints are copied from argparse.pyi
        option_strings: Sequence[str],
        dest: str,
        nargs: Optional[Union[int, str]] = None,
        const: Any = True,
        default: Any = False,
        **kwargs: Any,
    ) -> None:
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(BooleanAction, self).__init__(
            option_strings, dest, nargs="?", const=const, default=default, **kwargs
        )

    def __call__(
        self,  # These type-hints are copied from argparse.pyi
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:
        new_value = self.default
        if isinstance(values, str):
            try:
                new_value = parse_boolean(values)
            except ValueError as exp:
                raise argparse.ArgumentError(self, str(exp))
        elif isinstance(values, bool):  # Assign const
            new_value = values
        else:
            raise argparse.ArgumentError(
                self, "Invalid argument for %s %s" % (str(option_string), str(values))
            )

        # invert the value if the argument name starts with "not" or "without"
        for option in self.option_strings:
            if option[2:].startswith("not-") or option[2:].startswith("without-"):
                new_value = not new_value
                break

        setattr(namespace, self.dest, new_value)


class WithNetworkAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:

        if isinstance(values, str):
            if values == "never":
                setattr(namespace, self.dest, "never")
                return

        super().__call__(parser, namespace, values, option_string)


@dataclass
class CommandLineArguments:
    # Commands
    verb: str = arg(
        names=["verb"],
        default="build",
        choices=MKOSI_COMMANDS,
        help="Operation to execute",
    )
    cmdline: List[str] = arg(
        names=["cmdline"],
        nargs=argparse.REMAINDER,
        help=f"The command line to use for {str(MKOSI_COMMANDS_CMDLINE)[1:-1]}",
    )

    # Distribution
    distribution: Optional[Distribution] = arg(
        choices=Distribution.__members__, help="Distribution to install"
    )
    release: Optional[str] = arg(short="-r", help="Distribution release to install")
    mirror: Optional[str] = arg(short="-m", help="Distribution mirror to use")
    repositories: List[str] = arg(
        action=CommaDelimitedListAction,
        default_factory=list,
        help="Repositories to use",
    )
    architecture: Optional[str] = arg(help="Override the architecture of installation")

    # Output
    output_format: OutputFormat = arg(
        names=["--format", "-t"],
        choices=OutputFormat,
        default=OutputFormat.gpt_ext4,
        type=OutputFormat.from_string,
        help="Output Format",
    )
    output: Optional[str] = arg(short="-o", help="Output image path", metavar="PATH")
    output_dir: Optional[str] = arg(
        short="-O", help="Output root directory", metavar="DIR"
    )
    force: int = arg(
        short="-f",
        action="count",
        default=0,
        help="Remove existing image file before operation",
    )
    bootable: bool = arg(
        short="-b",
        action=BooleanAction,
        help="Make image bootable on EFI (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    boot_protocols: List[str] = arg(
        action=CommaDelimitedListAction,
        default_factory=list,
        metavar="PROTOCOLS",
        help="Boot protocols to use on a bootable image",
    )
    kernel_command_line: List[str] = arg(
        action=SpaceDelimitedListAction,
        default_factory=lambda: ["rhgb", "quiet", "selinux=0", "audit=0", "rw"],
        help="Set the kernel command line (only bootable images)",
    )
    secure_boot: bool = arg(
        action=BooleanAction,
        help="Sign the resulting kernel/initrd image for UEFI SecureBoot",
    )
    secure_boot_key: Optional[str] = arg(
        metavar="PATH", help="UEFI SecureBoot private key in PEM format"
    )
    secure_boot_certificate: Optional[str] = arg(
        metavar="PATH", help="UEFI SecureBoot certificate in X509 format"
    )
    read_only: bool = arg(
        action=BooleanAction,
        help="Make root volume read-only (only gpt_ext4, gpt_xfs, gpt_btrfs, subvolume, implied with gpt_squashfs and plain_squashfs)",
    )
    encrypt: Optional[str] = arg(
        choices=("all", "data"),
        help='Encrypt everything except: ESP ("all") or ESP and ' 'root ("data")',
    )
    verity: bool = arg(
        action=BooleanAction, help="Add integrity partition (implies --read-only)"
    )
    compress: Optional[Union[str, bool]] = arg(
        type=parse_compression,
        help="Enable compression in file system (only gpt_btrfs, subvolume, gpt_squashfs, plain_squashfs)",
    )
    mksquashfs: List[str] = arg(
        type=str.split, help="Script to call instead of mksquashfs"
    )
    xz: bool = arg(
        action=BooleanAction,
        help="Compress resulting image with xz (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs, implied on tar)",
    )
    qcow2: bool = arg(
        action=BooleanAction,
        help="Convert resulting image to qcow2 (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    hostname: bool = arg(help="Set hostname")
    no_chown: bool = arg(
        action=BooleanAction,
        help="When running with sudo, disable reassignment of ownership of the generated files to the original user",
    )
    incremental: bool = arg(
        short="-i",
        action=BooleanAction,
        help="Make use of and generate intermediary cache images",
    )
    minimize: bool = arg(
        short="-M", action=BooleanAction, help="Minimize root file system size"
    )
    with_unified_kernel_images: bool = arg(
        names=["--with-unified-kernel-images", "--without-unified-kernel-images"],
        default=True,
        action=BooleanAction,
        help="Do not install unified kernel images",
    )

    # Packages
    packages: List[str] = arg(
        names=["--package", "-p"],
        action=CommaDelimitedListAction,
        default_factory=list,
        metavar="PACKAGE",
        help="Add an additional package to the OS image",
    )
    with_docs: bool = arg(action=BooleanAction, help="Install documentation")
    with_tests: bool = arg(
        names=["--with-tests", "--without-tests", "-T"],
        default=True,
        action=BooleanAction,
    )
    cache_path: str = arg(names=["--cache"], metavar="PATH", help="Package cache path")
    extra_trees: List[str] = arg(
        names=["--extra-tree"],
        default_factory=list,
        action=CommaDelimitedListAction,
        metavar="PATH",
        help="Copy an extra tree on top of image",
    )
    skeleton_trees: List[str] = arg(
        names=["--skeleton-tree"],
        default_factory=list,
        action="append",
        metavar="PATH",
        help="Use a skeleton tree to bootstrap the image before installing anything",
    )
    build_script: Optional[str] = arg(
        metavar="PATH", help="Build script to run inside image"
    )
    build_sources: Optional[str] = arg(metavar="PATH", help="Path for sources to build")
    build_directory: Optional[str] = arg(
        names=["build-dir", "--build-directory"],
        metavar="PATH",
        help="Path to use as persistent build directory",
    )
    build_packages: List[str] = arg(
        names=["--build-package"],
        action=CommaDelimitedListAction,
        default_factory=list,
        metavar="PACKAGE",
        help="Additional packages needed for build script",
    )
    skip_final_phase: bool = arg(
        action=BooleanAction, help="Skip the (second) final image building phase"
    )
    postinst_script: Optional[str] = arg(
        metavar="PATH", help="Postinstall script to run inside image"
    )
    prepare_script: Optional[str] = arg(
        metavar="PATH",
        help="Prepare script to run inside the image before it is cached",
    )
    finalize_script: Optional[str] = arg(
        metavar="PATH", help="Postinstall script to run outside image"
    )
    source_file_transfer: Optional[SourceFileTransfer] = arg(
        type=SourceFileTransfer,
        choices=list(SourceFileTransfer),
        default=None,
        help="Method used to copy build sources to the build image (default: copy-git-cached if in a git repository, otherwise copy-all)",
    )
    with_network: bool = arg(
        action=WithNetworkAction,
        help="Run build and postinst scripts with network access (instead of private network)",
    )
    nspawn_settings: str = arg(
        names=["--settings"], metavar="PATH", help="Add in .nspawn settings file"
    )

    # Partitions
    root_size: int = arg(
        type=parse_bytes,
        default=3 * 1024 * 1024 * 1024,
        metavar="BYTES",
        help="Set size of root partition (only gpt_ext4, gpt_xfs, gpt_btrfs)",
    )
    esp_size: int = arg(
        type=parse_bytes,
        default=256 * 1024 * 1024,
        metavar="BYTES",
        help="Set size of EFI system partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    xbootldr_size: Optional[int] = arg(
        type=parse_bytes,
        metavar="BYTES",
        help="Set size of the XBOOTLDR partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    swap_size: Optional[int] = arg(
        type=parse_bytes,
        metavar="BYTES",
        help="Set size of swap partition (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    home_size: Optional[int] = arg(
        type=parse_bytes,
        metavar="BYTES",
        help="Set size of /home partition (only gpt_ext4, gpt_xfs, gpt_squashfs)",
    )
    srv_size: Optional[int] = arg(
        type=parse_bytes,
        metavar="BYTES",
        help="Set size of /srv partition (only gpt_ext4, gpt_xfs, gpt_squashfs)",
    )
    var_size: Optional[int] = arg(
        type=parse_bytes,
        metavar="BYTES",
        help="Set size of /var partition (only gpt_ext4, gpt_xfs, gpt_squashfs)",
    )
    tmp_size: Optional[int] = arg(
        type=parse_bytes,
        metavar="BYTES",
        help="Set size of /var/tmp partition (only gpt_ext4, gpt_xfs, gpt_squashfs)",
    )

    # Validation
    checksum: bool = arg(action=BooleanAction, help="Write SHA256SUMS file")
    sign: bool = arg(action=BooleanAction, help="Write and sign SHA256SUMS file")
    key: str = arg(help="GPG key to use for signing")
    bmap: bool = arg(
        action=BooleanAction,
        help="Write block map file (.bmap) for bmaptool usage (only gpt_ext4, gpt_btrfs)",
    )
    password: str = arg(help="Set the root password")
    password_is_hashed: bool = arg(
        action=BooleanAction,
        help="Indicate that the root password has already been hashed",
    )

    # Additional Configuration
    extra_search_paths: List[str] = arg(
        names=["--extra-search-path", "--extra-search-paths"],
        action=ColonDelimitedListAction,
        default_factory=list,
        help="List of colon-separated paths to look for programs before looking in PATH",
    )
    qemu_headless: bool = arg(
        action=BooleanAction, help="Configure image for qemu's -nographic mode"
    )
    directory: str = arg(
        short="-C",
        metavar="PATH",
        help="Change to specified directory before doing anything",
    )
    default_path: str = arg(
        names=["--default"], metavar="PATH", help="Read configuration data from file"
    )
    all: bool = arg(
        short="-a", action="store_true", help="Build all settings files in mkosi.files/"
    )
    all_directory: str = arg(
        metavar="PATH", help="Specify path to directory to read settings files from"
    )
    debug: List[str] = arg(
        action=CommaDelimitedListAction,
        default_factory=list,
        help="Turn on debugging output",
        metavar="SELECTOR",
        choices=["run", "build-script", "workspace-command"],
    )

    @staticmethod
    def parse(argv: List[str]) -> CommandLineArguments:
        parser = argparse.ArgumentParser()

        def names(field: Field[Any]) -> str:
            default = [f"--{field.name.replace('_', '-')}"]
            short = field.metadata.get("short", None)
            if short:
                default.append(short)
            return field.metadata.get("names", default)

        for field in fields(CommandLineArguments):
            if field.default != MISSING:
                default = field.default
            elif field.default_factory != MISSING:  # type: ignore
                default = field.default_factory()  # type: ignore
            else:
                default = None

            parser.add_argument(
                *names(field), type=field.type, default=default, *field.metadata
            )

        return parser.parse_args(argv, CommandLineArguments())
