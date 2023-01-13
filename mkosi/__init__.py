# SPDX-License-Identifier: LGPL-2.1+

import argparse
import configparser
import contextlib
import crypt
import ctypes
import ctypes.util
import dataclasses
import datetime
import errno
import fcntl
import glob
import hashlib
import http.server
import importlib
import importlib.resources
import itertools
import json
import math
import os
import platform
import re
import shlex
import shutil
import string
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from textwrap import dedent, wrap
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
    NoReturn,
    Optional,
    TextIO,
    TypeVar,
    Union,
    cast,
)

from mkosi.backend import (
    ARG_DEBUG,
    Distribution,
    ManifestFormat,
    MkosiConfig,
    MkosiException,
    MkosiNotSupportedException,
    MkosiPrinter,
    MkosiState,
    OutputFormat,
    SourceFileTransfer,
    Verb,
    chown_to_running_user,
    detect_distribution,
    die,
    is_centos_variant,
    is_epel_variant,
    is_rpm_distribution,
    mkdirp_chown_current_user,
    nspawn_knows_arg,
    nspawn_rlimit_params,
    nspawn_version,
    patch_file,
    path_relative_to_cwd,
    run,
    run_workspace_command,
    scandir_recursive,
    set_umask,
    should_compress_output,
    spawn,
    tmp_dir,
    warn,
)
from mkosi.install import (
    add_dropin_config,
    add_dropin_config_from_resource,
    copy_file,
    copy_file_object,
    copy_path,
    install_skeleton_trees,
    open_close,
)
from mkosi.manifest import Manifest
from mkosi.mounts import dissect_and_mount, mount_bind, mount_overlay, mount_tmpfs
from mkosi.remove import unlink_try_hard

complete_step = MkosiPrinter.complete_step
color_error = MkosiPrinter.color_error


__version__ = "14"


# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[Any]
    TempDir = tempfile.TemporaryDirectory[str]
else:
    CompletedProcess = subprocess.CompletedProcess
    TempDir = tempfile.TemporaryDirectory

SomeIO = Union[BinaryIO, TextIO]
PathString = Union[Path, str]

MKOSI_COMMANDS_NEED_BUILD = (Verb.shell, Verb.boot, Verb.qemu, Verb.serve)
MKOSI_COMMANDS_SUDO = (Verb.build, Verb.clean, Verb.shell, Verb.boot)
MKOSI_COMMANDS_CMDLINE = (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.ssh)

DRACUT_SYSTEMD_EXTRAS = [
    "/usr/bin/systemd-ask-password",
    "/usr/bin/systemd-repart",
    "/usr/bin/systemd-tty-ask-password-agent",
    "/usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "/usr/lib/systemd/system/initrd-root-fs.target.wants/systemd-repart.service",
    "/usr/lib/systemd/system/initrd-usr-fs.target",
    "/usr/lib/systemd/system/initrd.target.wants/systemd-pcrphase-initrd.service",
    "/usr/lib/systemd/system/sysinit.target.wants/veritysetup.target",
    "/usr/lib/systemd/system/systemd-pcrphase-initrd.service",
    "/usr/lib/systemd/system/systemd-repart.service",
    "/usr/lib/systemd/system/systemd-volatile-root.service",
    "/usr/lib/systemd/system/veritysetup.target",
    "/usr/lib/systemd/systemd-pcrphase",
    "/usr/lib/systemd/systemd-veritysetup",
    "/usr/lib/systemd/systemd-volatile-root",
    "/usr/lib64/libtss2-esys.so.0",
    "/usr/lib64/libtss2-mu.so.0",
    "/usr/lib64/libtss2-rc.so.0",
    "/usr/lib64/libtss2-tcti-device.so.0",
]


T = TypeVar("T")


def list_to_string(seq: Iterator[str]) -> str:
    """Print contents of a list to a comma-separated string

    ['a', "b", 11] → "'a', 'b', 11"
    """
    return str(list(seq))[1:-1]


def print_running_cmd(cmdline: Iterable[PathString]) -> None:
    MkosiPrinter.print_step("Running command:")
    MkosiPrinter.print_step(" ".join(shlex.quote(str(x)) for x in cmdline) + "\n")


CLONE_NEWNS = 0x00020000

# EFI has its own conventions too
EFI_ARCHITECTURES = {
    "x86_64": "x64",
    "x86": "ia32",
    "aarch64": "aa64",
    "armhfp": "arm",
    "riscv64:": "riscv64",
}


def unshare(flags: int) -> None:
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        die("Could not find libc")
    libc = ctypes.CDLL(libc_name, use_errno=True)

    if libc.unshare(ctypes.c_int(flags)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def format_bytes(num_bytes: int) -> str:
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes/1024**3 :0.1f}G"
    if num_bytes >= 1024 * 1024:
        return f"{num_bytes/1024**2 :0.1f}M"
    if num_bytes >= 1024:
        return f"{num_bytes/1024 :0.1f}K"

    return f"{num_bytes}B"


@complete_step("Detaching namespace")
def init_namespace() -> None:
    unshare(CLONE_NEWNS)
    run(["mount", "--make-rslave", "/"])


def setup_workspace(config: MkosiConfig) -> TempDir:
    with complete_step("Setting up temporary workspace.", "Temporary workspace set up in {.name}") as output:
        if config.workspace_dir is not None:
            d = tempfile.TemporaryDirectory(dir=config.workspace_dir, prefix="")
        else:
            p = config.output.parent

            # The build sources might be mounted inside the workspace directory so if the workspace directory
            # is located inside the build sources directory, we get an infinite mount loop which causes all
            # sorts of issues, so let's make sure the workspace directory is located outside of the sources
            # directory.
            while str(p).startswith(str(config.build_sources)):
                p = p.parent

            d = tempfile.TemporaryDirectory(dir=p, prefix=f"mkosi.{config.build_sources.name}.tmp")
        output.append(d)

    return d


def btrfs_subvol_create(path: Path, mode: int = 0o755) -> None:
    with set_umask(~mode & 0o7777):
        run(["btrfs", "subvol", "create", path])


def disable_cow(path: PathString) -> None:
    """Disable copy-on-write if applicable on filesystem"""

    run(["chattr", "+C", path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def copy_image_temporary(src: Path, dir: Path) -> BinaryIO:
    with src.open("rb") as source:
        f: BinaryIO = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=dir))

        # So on one hand we want CoW off, since this stuff will
        # have a lot of random write accesses. On the other we
        # want the copy to be snappy, hence we do want CoW. Let's
        # ask for both, and let the kernel figure things out:
        # let's turn off CoW on the file, but start with a CoW
        # copy. On btrfs that works: the initial copy is made as
        # CoW but later changes do not result in CoW anymore.

        disable_cow(f.name)
        copy_file_object(source, f)

        return f


def copy_file_temporary(src: PathString, dir: Path) -> BinaryIO:
    with open(src, "rb") as source:
        f = cast(BinaryIO, tempfile.NamedTemporaryFile(prefix=".mkosi-", dir=dir))
        copy_file_object(source, f)
        return f


@contextlib.contextmanager
def mount_image(state: MkosiState, cached: bool) -> Iterator[None]:
    with complete_step("Mounting image…", "Unmounting image…"), contextlib.ExitStack() as stack:

        if state.config.base_image is not None:
            if state.config.base_image.is_dir():
                base = state.config.base_image
            else:
                base = stack.enter_context(dissect_and_mount(state.config.base_image, state.workspace / "base"))

            workdir = state.workspace / "workdir"
            workdir.mkdir()
            stack.enter_context(mount_overlay(base, state.root, workdir, state.root))
        else:
            # always have a root of the tree as a mount point so we can recursively unmount anything that
            # ends up mounted there.
            stack.enter_context(mount_bind(state.root))

        # Make sure /tmp and /run are not part of the image
        stack.enter_context(mount_tmpfs(state.root / "run"))
        stack.enter_context(mount_tmpfs(state.root / "tmp"))

        if state.do_run_build_script and state.config.include_dir and not cached:
            stack.enter_context(mount_bind(state.config.include_dir, state.root / "usr/include"))

        yield


def configure_locale(root: Path, cached: bool) -> None:
    if cached:
        return

    etc_locale = root / "etc/locale.conf"

    etc_locale.unlink(missing_ok=True)

    # Let's ensure we use a UTF-8 locale everywhere.
    etc_locale.write_text("LANG=C.UTF-8\n")


def configure_hostname(state: MkosiState, cached: bool) -> None:
    if cached:
        return

    etc_hostname = state.root / "etc/hostname"

    # Always unlink first, so that we don't get in trouble due to a
    # symlink or suchlike. Also if no hostname is configured we really
    # don't want the file to exist, so that systemd's implicit
    # hostname logic can take effect.
    etc_hostname.unlink(missing_ok=True)

    if state.config.hostname:
        with complete_step("Assigning hostname"):
            etc_hostname.write_text(state.config.hostname + "\n")


@contextlib.contextmanager
def mount_cache(state: MkosiState) -> Iterator[None]:
    cache_paths = state.installer.cache_path()

    # We can't do this in mount_image() yet, as /var itself might have to be created as a subvolume first
    with complete_step("Mounting Package Cache", "Unmounting Package Cache"), contextlib.ExitStack() as stack:
        for cache_path in cache_paths:
            stack.enter_context(mount_bind(state.cache, state.root / cache_path))
        yield


def configure_dracut(state: MkosiState, cached: bool) -> None:
    if not state.config.bootable or state.do_run_build_script or cached:
        return

    dracut_dir = state.root / "etc/dracut.conf.d"
    dracut_dir.mkdir(mode=0o755, exist_ok=True)

    dracut_dir.joinpath("30-mkosi-qemu.conf").write_text('add_dracutmodules+=" qemu "\n')

    with dracut_dir.joinpath("30-mkosi-systemd-extras.conf").open("w") as f:
        for extra in DRACUT_SYSTEMD_EXTRAS:
            f.write(f'install_optional_items+=" {extra} "\n')
        f.write('install_optional_items+=" /etc/systemd/system.conf "\n')
        if state.root.joinpath("etc/systemd/system.conf.d").exists():
            for conf in state.root.joinpath("etc/systemd/system.conf.d").iterdir():
                f.write(f'install_optional_items+=" {Path("/") / conf.relative_to(state.root)} "\n')

    if state.config.bootable:
        # efivarfs must be present in order to GPT root discovery work
        dracut_dir.joinpath("30-mkosi-efivarfs.conf").write_text(
            '[[ $(modinfo -k "$kernel" -F filename efivarfs 2>/dev/null) == /* ]] && add_drivers+=" efivarfs "\n'
        )


def prepare_tree_root(state: MkosiState) -> None:
    if state.config.output_format == OutputFormat.subvolume:
        with complete_step("Setting up OS tree root…"):
            btrfs_subvol_create(state.root)


def prepare_tree(state: MkosiState, cached: bool) -> None:
    if cached:
        # Reuse machine-id from cached image.
        state.machine_id = uuid.UUID(state.root.joinpath("etc/machine-id").read_text().strip()).hex
        # Always update kernel command line.
        if not state.do_run_build_script and state.config.bootable:
            state.root.joinpath("etc/kernel/cmdline").write_text(" ".join(state.config.kernel_command_line) + "\n")
        return

    with complete_step("Setting up basic OS tree…"):
        # We need an initialized machine ID for the build & boot logic to work
        state.root.joinpath("etc").mkdir(mode=0o755, exist_ok=True)
        state.root.joinpath("etc/machine-id").write_text(f"{state.machine_id}\n")

        state.root.joinpath("etc/kernel").mkdir(mode=0o755, exist_ok=True)
        state.root.joinpath("etc/kernel/cmdline").write_text(" ".join(state.config.kernel_command_line) + "\n")
        state.root.joinpath("etc/kernel/entry-token").write_text(f"{state.machine_id}\n")
        state.root.joinpath("etc/kernel/install.conf").write_text("layout=bls\n")


def flatten(lists: Iterable[Iterable[T]]) -> list[T]:
    """Flatten a sequence of sequences into a single list."""
    return list(itertools.chain.from_iterable(lists))


def clean_paths(
        root: Path,
        globs: Sequence[str],
        tool: str,
        always: bool) -> None:
    """Remove globs under root if always or if tool is not found under root."""

    toolp = root / tool.lstrip('/')
    cond = always or not os.access(toolp, os.F_OK, follow_symlinks=False)

    paths = flatten(root.glob(glob.lstrip('/')) for glob in globs)

    if not cond or not paths:
        return

    with complete_step(f"Cleaning {toolp.name} metadata…"):
        for path in paths:
            unlink_try_hard(path)


def clean_dnf_metadata(root: Path, always: bool) -> None:
    """Remove dnf metadata if /bin/dnf is not present in the image

    If dnf is not installed, there doesn't seem to be much use in keeping the
    dnf metadata, since it's not usable from within the image anyway.
    """
    paths = [
        "/var/lib/dnf",
        "/var/log/dnf.*",
        "/var/log/hawkey.*",
        "/var/cache/dnf",
    ]

    clean_paths(root, paths, tool='/bin/dnf', always=always)


def clean_yum_metadata(root: Path, always: bool) -> None:
    """Remove yum metadata if /bin/yum is not present in the image"""
    paths = [
        "/var/lib/yum",
        "/var/log/yum.*",
        "/var/cache/yum",
    ]

    clean_paths(root, paths, tool='/bin/yum', always=always)


def clean_rpm_metadata(root: Path, always: bool) -> None:
    """Remove rpm metadata if /bin/rpm is not present in the image"""
    paths = [
        "/var/lib/rpm",
        "/usr/lib/sysimage/rpm",
    ]

    clean_paths(root, paths, tool='/bin/rpm', always=always)


def clean_apt_metadata(root: Path, always: bool) -> None:
    """Remove apt metadata if /usr/bin/apt is not present in the image"""
    paths = [
        "/var/lib/apt",
        "/var/log/apt",
        "/var/cache/apt",
    ]

    clean_paths(root, paths, tool='/usr/bin/apt', always=always)


def clean_dpkg_metadata(root: Path, always: bool) -> None:
    """Remove dpkg metadata if /usr/bin/dpkg is not present in the image"""
    paths = [
        "/var/lib/dpkg",
        "/var/log/dpkg.log",
    ]

    clean_paths(root, paths, tool='/usr/bin/dpkg', always=always)


def clean_pacman_metadata(root: Path, always: bool) -> None:
    """Remove pacman metadata if /usr/bin/pacman is not present in the image"""
    paths = [
        "/var/lib/pacman",
        "/var/cache/pacman",
        "/var/log/pacman.log"
    ]

    clean_paths(root, paths, tool='/usr/bin/pacman', always=always)


def clean_package_manager_metadata(state: MkosiState) -> None:
    """Remove package manager metadata

    Try them all regardless of the distro: metadata is only removed if the
    package manager is present in the image.
    """

    assert state.config.clean_package_metadata in (False, True, 'auto')
    if state.config.clean_package_metadata is False:
        return

    # we try then all: metadata will only be touched if any of them are in the
    # final image
    always = state.config.clean_package_metadata is True
    clean_dnf_metadata(state.root, always=always)
    clean_yum_metadata(state.root, always=always)
    clean_rpm_metadata(state.root, always=always)
    clean_apt_metadata(state.root, always=always)
    clean_dpkg_metadata(state.root, always=always)
    clean_pacman_metadata(state.root, always=always)
    # FIXME: implement cleanup for other package managers: swupd


def remove_files(state: MkosiState) -> None:
    """Remove files based on user-specified patterns"""

    if not state.config.remove_files:
        return

    with complete_step("Removing files…"):
        # Note: Path('/foo') / '/bar' == '/bar'. We need to strip the slash.
        # https://bugs.python.org/issue44452
        paths = [state.root / str(p).lstrip("/") for p in state.config.remove_files]
        remove_glob(*paths)


def parse_epel_release(release: str) -> int:
    fields = release.split(".")
    return int(fields[0].removesuffix("-stream"))


def install_distribution(state: MkosiState, cached: bool) -> None:
    if cached:
        return

    with mount_cache(state):
        state.installer.install(state)


def remove_packages(state: MkosiState) -> None:
    """Remove packages listed in config.remove_packages"""

    if not state.config.remove_packages:
        return

    with complete_step(f"Removing {len(state.config.packages)} packages…"):
        try:
            state.installer.remove_packages(state, state.config.remove_packages)
        except NotImplementedError:
            die(f"Removing packages is not supported for {state.config.distribution}")


def reset_machine_id(state: MkosiState) -> None:
    """Make /etc/machine-id an empty file.

    This way, on the next boot is either initialized and committed (if /etc is
    writable) or the image runs with a transient machine ID, that changes on
    each boot (if the image is read-only).
    """

    if state.do_run_build_script:
        return
    if state.for_cache:
        return

    with complete_step("Resetting machine ID"):
        if not state.config.machine_id:
            machine_id = state.root / "etc/machine-id"
            machine_id.unlink(missing_ok=True)
            machine_id.write_text("uninitialized\n")

        dbus_machine_id = state.root / "var/lib/dbus/machine-id"
        try:
            dbus_machine_id.unlink()
        except FileNotFoundError:
            pass
        else:
            dbus_machine_id.symlink_to("../../../etc/machine-id")


def reset_random_seed(root: Path) -> None:
    """Remove random seed file, so that it is initialized on first boot"""
    random_seed = root / "var/lib/systemd/random-seed"
    if not random_seed.exists():
        return

    with complete_step("Removing random seed"):
        random_seed.unlink()


def configure_root_password(state: MkosiState, cached: bool) -> None:
    "Set the root account password, or just delete it so it's easy to log in"

    if state.do_run_build_script:
        return
    if cached:
        return

    if state.config.password == "":
        with complete_step("Deleting root password"):

            def delete_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", ""] + line.split(":")[2:])
                return line

            patch_file(state.root / "etc/passwd", delete_root_pw)
    elif state.config.password:
        with complete_step("Setting root password"):
            if state.config.password_is_hashed:
                password = state.config.password
            else:
                password = crypt.crypt(state.config.password, crypt.mksalt(crypt.METHOD_SHA512))

            def set_root_pw(line: str) -> str:
                if line.startswith("root:"):
                    return ":".join(["root", password] + line.split(":")[2:])
                return line

            patch_file(state.root / "etc/shadow", set_root_pw)


def pam_add_autologin(root: Path, ttys: list[str]) -> None:
    login = root / "etc/pam.d/login"
    original = login.read_text() if login.exists() else ""

    login.parent.mkdir(exist_ok=True)
    with open(login, "w") as f:
        for tty in ttys:
            # Some PAM versions require the /dev/ prefix, others don't. Just add both variants.
            f.write(f"auth sufficient pam_succeed_if.so tty = {tty}\n")
            f.write(f"auth sufficient pam_succeed_if.so tty = /dev/{tty}\n")
        f.write(original)


def configure_autologin(state: MkosiState, cached: bool) -> None:
    if state.do_run_build_script or cached or not state.config.autologin:
        return

    with complete_step("Setting up autologin…"):
        add_dropin_config_from_resource(state.root, "console-getty.service", "autologin",
                                        "mkosi.resources", "console_getty_autologin.conf")

        ttys = []
        ttys += ["pts/0"]

        add_dropin_config_from_resource(state.root, "serial-getty@ttyS0.service", "autologin",
                                        "mkosi.resources", "serial_getty_autologin.conf")

        ttys += ["ttyS0"]

        add_dropin_config_from_resource(state.root, "getty@tty1.service", "autologin",
                                        "mkosi.resources", "getty_autologin.conf")

        ttys += ["tty1"]
        ttys += ["console"]

        pam_add_autologin(state.root, ttys)


def configure_serial_terminal(state: MkosiState, cached: bool) -> None:
    """Override TERM for the serial console with the terminal type from the host."""

    if state.do_run_build_script or cached or not state.config.qemu_headless:
        return

    with complete_step("Configuring serial tty (/dev/ttyS0)…"):
        columns, lines = shutil.get_terminal_size(fallback=(80, 24))
        add_dropin_config(state.root, "serial-getty@ttyS0.service", "term",
                          f"""\
                          [Service]
                          Environment=TERM={os.getenv('TERM', 'vt220')}
                          Environment=COLUMNS={columns}
                          Environment=LINES={lines}
                          TTYColumns={columns}
                          TTYRows={lines}
                          """)


def nspawn_id_map_supported() -> bool:
    if nspawn_version() < 252:
        return False

    ret = run(["systemd-analyze", "compare-versions", platform.release(), ">=", "5.12"])
    return ret.returncode == 0


def nspawn_params_for_build_sources(config: MkosiConfig, sft: SourceFileTransfer) -> list[str]:
    params = ["--setenv=SRCDIR=/root/src",
              "--chdir=/root/src"]
    if sft == SourceFileTransfer.mount:
        idmap_opt = ":rootidmap" if nspawn_id_map_supported() and config.idmap else ""
        params += [f"--bind={config.build_sources}:/root/src{idmap_opt}"]

    return params


def run_prepare_script(state: MkosiState, cached: bool) -> None:
    if state.config.prepare_script is None:
        return
    if cached:
        return

    verb = "build" if state.do_run_build_script else "final"

    with mount_cache(state), complete_step("Running prepare script…"):

        # We copy the prepare script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(state.config.prepare_script, state.root / "root/prepare")

        nspawn_params = nspawn_params_for_build_sources(state.config, SourceFileTransfer.mount)
        run_workspace_command(state, ["/root/prepare", verb],
                              network=True, nspawn_params=nspawn_params, env=state.environment)

        srcdir = state.root / "root/src"
        if srcdir.exists():
            os.rmdir(srcdir)

        os.unlink(state.root / "root/prepare")


def run_postinst_script(state: MkosiState) -> None:
    if state.config.postinst_script is None:
        return
    if state.for_cache:
        return

    verb = "build" if state.do_run_build_script else "final"

    with mount_cache(state), complete_step("Running postinstall script…"):

        # We copy the postinst script into the build tree. We'd prefer
        # mounting it into the tree, but for that we'd need a good
        # place to mount it to. But if we create that we might as well
        # just copy the file anyway.

        shutil.copy2(state.config.postinst_script, state.root / "root/postinst")

        run_workspace_command(state, ["/root/postinst", verb],
                              network=(state.config.with_network is True), env=state.environment)
        state.root.joinpath("root/postinst").unlink()


def run_finalize_script(state: MkosiState) -> None:
    if state.config.finalize_script is None:
        return
    if state.for_cache:
        return

    verb = "build" if state.do_run_build_script else "final"

    with complete_step("Running finalize script…"):
        run([state.config.finalize_script, verb],
            env={**state.environment, "BUILDROOT": str(state.root), "OUTPUTDIR": str(state.config.output_dir or Path.cwd())})


def install_boot_loader(state: MkosiState) -> None:
    if not state.config.bootable or state.do_run_build_script or state.for_cache:
        return

    with complete_step("Installing boot loader…"):
        run(["bootctl", "install", "--root", state.root], env={"SYSTEMD_ESP_PATH": "/boot"})


def install_extra_trees(state: MkosiState) -> None:
    if not state.config.extra_trees:
        return

    if state.for_cache:
        return

    with complete_step("Copying in extra file trees…"):
        for tree in state.config.extra_trees:
            if tree.is_dir():
                copy_path(tree, state.root, copystat=False)
            else:
                # unpack_archive() groks Paths, but mypy doesn't know this.
                # Pretend that tree is a str.
                shutil.unpack_archive(tree, state.root)


def copy_git_files(src: Path, dest: Path, *, source_file_transfer: SourceFileTransfer) -> None:
    what_files = ["--exclude-standard", "--cached"]
    if source_file_transfer == SourceFileTransfer.copy_git_others:
        what_files += ["--others", "--exclude=.mkosi-*"]

    uid = int(os.getenv("SUDO_UID", 0))

    c = run(["git", "-C", src, "ls-files", "-z", *what_files], stdout=subprocess.PIPE, text=False, user=uid)
    files = {x.decode("utf-8") for x in c.stdout.rstrip(b"\0").split(b"\0")}

    # Add the .git/ directory in as well.
    if source_file_transfer == SourceFileTransfer.copy_git_more:
        top = os.path.join(src, ".git/")
        for path, _, filenames in os.walk(top):
            for filename in filenames:
                fp = os.path.join(path, filename)  # full path
                fr = os.path.join(".git/", fp.removeprefix(top))  # relative to top
                files.add(fr)

    # Get submodule files
    c = run(["git", "-C", src, "submodule", "status", "--recursive"], stdout=subprocess.PIPE, text=True, user=uid)
    submodules = {x.split()[1] for x in c.stdout.splitlines()}

    # workaround for git ls-files returning the path of submodules that we will
    # still parse
    files -= submodules

    for sm in submodules:
        sm = Path(sm)
        c = run(
            ["git", "-C", src / sm, "ls-files", "-z"] + what_files,
            stdout=subprocess.PIPE,
            text=False,
            user=uid,
        )
        files |= {sm / x.decode("utf-8") for x in c.stdout.rstrip(b"\0").split(b"\0")}
        files -= submodules

        # Add the .git submodule file well.
        if source_file_transfer == SourceFileTransfer.copy_git_more:
            files.add(os.path.join(sm, ".git"))

    del c

    for path in files:
        src_path = src / path
        dest_path = dest / path

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if src_path.is_dir():
            copy_path(src_path, dest_path)
        else:
            copy_file(src_path, dest_path)


def install_build_src(state: MkosiState) -> None:
    if state.for_cache:
        return

    if state.do_run_build_script:
        if state.config.build_script is not None:
            with complete_step("Copying in build script…"):
                copy_file(state.config.build_script, state.root / "root" / state.config.build_script.name)
        else:
            return

    sft: Optional[SourceFileTransfer] = None
    resolve_symlinks: bool = False
    if state.do_run_build_script:
        sft = state.config.source_file_transfer
        resolve_symlinks = state.config.source_resolve_symlinks
    else:
        sft = state.config.source_file_transfer_final
        resolve_symlinks = state.config.source_resolve_symlinks_final

    if sft is None:
        return

    with complete_step("Copying in sources…"):
        target = state.root / "root/src"

        if sft in (
            SourceFileTransfer.copy_git_others,
            SourceFileTransfer.copy_git_cached,
            SourceFileTransfer.copy_git_more,
        ):
            copy_git_files(state.config.build_sources, target, source_file_transfer=sft)
        elif sft == SourceFileTransfer.copy_all:
            ignore = shutil.ignore_patterns(
                ".git",
                ".mkosi-*",
                "*.cache-pre-dev",
                "*.cache-pre-inst",
                f"{state.config.output_dir.name}/" if state.config.output_dir else "mkosi.output/",
                f"{state.config.workspace_dir.name}/" if state.config.workspace_dir else "mkosi.workspace/",
                f"{state.config.cache_path.name}/" if state.config.cache_path else "mkosi.cache/",
                f"{state.config.build_dir.name}/" if state.config.build_dir else "mkosi.builddir/",
                f"{state.config.include_dir.name}/" if state.config.include_dir else "mkosi.includedir/",
                f"{state.config.install_dir.name}/" if state.config.install_dir else "mkosi.installdir/",
            )
            shutil.copytree(state.config.build_sources, target, symlinks=not resolve_symlinks, ignore=ignore)


def install_build_dest(state: MkosiState) -> None:
    if state.do_run_build_script:
        return
    if state.for_cache:
        return

    if state.config.build_script is None:
        return

    with complete_step("Copying in build tree…"):
        copy_path(install_dir(state), state.root, copystat=False)


def xz_binary() -> str:
    return "pxz" if shutil.which("pxz") else "xz"


def compressor_command(option: Union[str, bool], src: Path) -> list[PathString]:
    """Returns a command suitable for compressing archives."""

    if option == "xz":
        return [xz_binary(), "--check=crc32", "--lzma2=dict=1MiB", "-T0", src]
    elif option == "zstd":
        return ["zstd", "-15", "-q", "-T0", "--rm", src]
    else:
        die(f"Unknown compression {option}")


def tar_binary() -> str:
    # Some distros (Mandriva) install BSD tar as "tar", hence prefer
    # "gtar" if it exists, which should be GNU tar wherever it exists.
    # We are interested in exposing same behaviour everywhere hence
    # it's preferable to use the same implementation of tar
    # everywhere. In particular given the limited/different SELinux
    # support in BSD tar and the different command line syntax
    # compared to GNU tar.
    return "gtar" if shutil.which("gtar") else "tar"


def make_tar(state: MkosiState) -> None:
    if state.do_run_build_script:
        return
    if state.config.output_format != OutputFormat.tar:
        return
    if state.for_cache:
        return

    cmd: list[PathString] = [tar_binary(), "-C", state.root, "-c", "--xattrs", "--xattrs-include=*"]
    if state.config.tar_strip_selinux_context:
        cmd += ["--xattrs-exclude=security.selinux"]

    cmd += [".", "-f", state.staging / state.config.output.name]

    with complete_step("Creating archive…"):
        run(cmd)


def find_files(root: Path) -> Iterator[Path]:
    """Generate a list of all filepaths relative to @root"""
    yield from scandir_recursive(root,
                                 lambda entry: Path(entry.path).relative_to(root))


def make_cpio(state: MkosiState) -> None:
    if state.do_run_build_script:
        return
    if state.config.output_format != OutputFormat.cpio:
        return
    if state.for_cache:
        return

    with complete_step("Creating archive…"), open(state.staging / state.config.output.name, "wb") as f:
        files = find_files(state.root)
        cmd: list[PathString] = [
            "cpio", "-o", "--reproducible", "--null", "-H", "newc", "--quiet", "-D", state.root
        ]

        with spawn(cmd, stdin=subprocess.PIPE, stdout=f) as cpio:
            #  https://github.com/python/mypy/issues/10583
            assert cpio.stdin is not None

            for file in files:
                cpio.stdin.write(os.fspath(file).encode("utf8") + b"\0")
            cpio.stdin.close()
        if cpio.wait() != 0:
            die("Failed to create archive")


def make_directory(state: MkosiState) -> None:
    if state.do_run_build_script or state.config.output_format != OutputFormat.directory or state.for_cache:
        return

    os.rename(state.root, state.staging / state.config.output.name)


def gen_kernel_images(state: MkosiState) -> Iterator[tuple[str, Path]]:
    # Apparently openmandriva hasn't yet completed its usrmerge so we use lib here instead of usr/lib.
    if not state.root.joinpath("lib/modules").exists():
        return

    for kver in state.root.joinpath("lib/modules").iterdir():
        if not kver.is_dir():
            continue

        kimg = state.installer.kernel_image(kver.name, state.config.architecture)

        yield kver.name, kimg


def initrd_path(state: MkosiState, kver: str) -> Path:
    # initrd file is versioned in Debian Bookworm
    initrd = state.root / boot_directory(state, kver) / f"initrd.img-{kver}"
    if not initrd.exists():
        initrd = state.root / boot_directory(state, kver) / "initrd"

    return initrd


def install_unified_kernel(state: MkosiState, label: Optional[str], root_hash: Optional[str], usr_only: bool) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if not state.config.bootable:
        return

    # Don't run dracut if this is for the cache. The unified kernel
    # typically includes the image ID, roothash and other data that
    # differs between cached version and final result. Moreover, we
    # want that the initrd for the image actually takes the changes we
    # make to the image into account (e.g. when we build a systemd
    # test image with this we want that the systemd we just built is
    # in the initrd, and not one from the cache. Hence even though
    # dracut is slow we invoke it only during the last final build,
    # never for the cached builds.
    if state.for_cache:
        return

    # Don't bother running dracut if this is a development build. Strictly speaking it would probably be a
    # good idea to run it, so that the development environment differs as little as possible from the final
    # build, but then again the initrd should not be relevant for building, and dracut is simply very slow,
    # hence let's avoid it invoking it needlessly, given that we never actually invoke the boot loader on the
    # development image.
    if state.do_run_build_script:
        return

    prefix = "boot"

    with complete_step("Generating combined kernel + initrd boot file…"):
        for kver, kimg in gen_kernel_images(state):
            image_id = state.config.image_id or f"mkosi-{state.config.distribution}"

            # See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/#boot-counting
            boot_count = ""
            if state.root.joinpath("etc/kernel/tries").exists():
                boot_count = f'+{state.root.joinpath("etc/kernel/tries").read_text().strip()}'

            if state.config.image_version:
                boot_binary = state.root / prefix / f"EFI/Linux/{image_id}_{state.config.image_version}{boot_count}.efi"
            elif root_hash:
                boot_binary = state.root / prefix / f"EFI/Linux/{image_id}-{kver}-{root_hash}{boot_count}.efi"
            else:
                boot_binary = state.root / prefix / f"EFI/Linux/{image_id}-{kver}{boot_count}.efi"

            if state.root.joinpath("etc/kernel/cmdline").exists():
                boot_options = state.root.joinpath("etc/kernel/cmdline").read_text().strip()
            elif state.root.joinpath("/usr/lib/kernel/cmdline").exists():
                boot_options = state.root.joinpath("usr/lib/kernel/cmdline").read_text().strip()
            else:
                boot_options = ""

            if root_hash:
                option = "usrhash" if usr_only else "roothash"
                boot_options = f"{boot_options} {option}={root_hash}"
            else:
                # Direct Linux boot means we can't rely on systemd-gpt-auto-generator to
                # figure out the root partition for us so we have to encode it manually
                # in the kernel cmdline.
                option = "mount.usr" if usr_only else "root"
                boot_options = f"{boot_options} {option}=LABEL={label}"

            cmd: list[PathString] = [
                "ukify",
                "--cmdline", boot_options,
                "--os-release", f"@{state.root / 'usr/lib/os-release'}",
                "--stub", state.root / f"lib/systemd/boot/efi/linux{EFI_ARCHITECTURES[state.config.architecture]}.efi.stub",
                "--output", boot_binary,
                "--efi-arch", EFI_ARCHITECTURES[state.config.architecture],
            ]

            for p in state.config.extra_search_paths:
                cmd += ["--tools", p]

            if state.config.secure_boot:
                cmd += [
                    "--secureboot-private-key", state.config.secure_boot_key,
                    "--secureboot-certificate", state.config.secure_boot_certificate,
                ]

                if state.config.sign_expected_pcr:
                    cmd += [
                        "--pcr-private-key", state.config.secure_boot_key,
                        "--pcr-banks", "sha1,sha256"
                    ]

            cmd += [state.root / kimg, initrd_path(state, kver)]

            run(cmd)

            if not state.staging.joinpath(state.staging / state.config.output_split_kernel.name).exists():
                copy_file(boot_binary, state.staging / state.config.output_split_kernel.name)


def secure_boot_sign(state: MkosiState, directory: Path, replace: bool = False) -> None:
    if state.do_run_build_script:
        return
    if not state.config.bootable:
        return
    if not state.config.secure_boot:
        return
    if state.for_cache:
        return

    for f in itertools.chain(directory.glob('*.efi'), directory.glob('*.EFI')):
        if os.path.exists(f"{f}.signed"):
            MkosiPrinter.info(f"Not overwriting existing signed EFI binary {f}.signed")
            continue

        with complete_step(f"Signing EFI binary {f}…"):
            run(
                [
                    "sbsign",
                    "--key",
                    state.config.secure_boot_key,
                    "--cert",
                    state.config.secure_boot_certificate,
                    "--output",
                    f"{f}.signed",
                    f,
                ],
            )

            if replace:
                os.rename(f"{f}.signed", f)


def compress_output(config: MkosiConfig, src: Path) -> None:
    compress = should_compress_output(config)

    if not src.is_file():
        return

    if not compress:
        # If we shan't compress, then at least make the output file sparse
        with complete_step(f"Digging holes into output file {src}…"):
            run(["fallocate", "--dig-holes", src])
    else:
        with complete_step(f"Compressing output file {src}…"):
            run(compressor_command(compress, src))


def qcow2_output(state: MkosiState) -> None:
    if not state.config.output_format == OutputFormat.disk:
        return

    if not state.config.qcow2:
        return

    with complete_step("Converting image file to qcow2…"):
        run(["qemu-img", "convert", "-onocow=on", "-fraw", "-Oqcow2",
             state.staging / state.config.output.name,
             state.workspace / "qemu.img"])
        os.rename(state.workspace / "qemu.img", state.staging / state.config.output.name)


def copy_nspawn_settings(state: MkosiState) -> None:
    if state.config.nspawn_settings is None:
        return None

    with complete_step("Copying nspawn settings file…"):
        copy_file(state.config.nspawn_settings, state.staging / state.config.output_nspawn_settings.name)


def hash_file(of: TextIO, path: Path) -> None:
    bs = 16 * 1024**2
    h = hashlib.sha256()

    with path.open("wb") as sf:
        while (buf := sf.read(bs)):
            h.update(buf)

    of.write(h.hexdigest() + " *" + path.name + "\n")


def calculate_sha256sum(state: MkosiState) -> None:
    if state.config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        return None

    if not state.config.checksum:
        return None

    with complete_step("Calculating SHA256SUMS…"):
        with open(state.workspace / state.config.output_checksum.name, "w") as f:
            for p in state.staging.iterdir():
                hash_file(f, p)

        os.rename(state.workspace / state.config.output_checksum.name, state.staging / state.config.output_checksum.name)


def calculate_signature(state: MkosiState) -> None:
    if not state.config.sign:
        return None

    with complete_step("Signing SHA256SUMS…"):
        cmdline: list[PathString] = [
            "gpg",
            "--detach-sign",
            "-o", state.staging / state.config.output_signature.name,
            state.staging / state.config.output_checksum.name,
        ]

        if state.config.key is not None:
            cmdline += ["--default-key", state.config.key]

        run(cmdline)


def calculate_bmap(state: MkosiState) -> None:
    if not state.config.bmap:
        return

    if not state.config.output_format == OutputFormat.disk:
        return

    with complete_step("Creating BMAP file…"):
        cmdline: list[PathString] = [
            "bmaptool",
            "create",
            "--output", state.staging / state.config.output_bmap.name,
            state.staging / state.config.output.name,
        ]

        run(cmdline)


def save_cache(state: MkosiState) -> None:
    cache = cache_tree_path(state.config, is_final_image=False) if state.do_run_build_script else cache_tree_path(state.config, is_final_image=True)

    with complete_step("Installing cache copy…", f"Installed cache copy {path_relative_to_cwd(cache)}"):
        unlink_try_hard(cache)
        shutil.move(state.root, cache)

    if state.config.chown:
        chown_to_running_user(cache)


def dir_size(path: PathString) -> int:
    dir_sum = 0
    for entry in os.scandir(path):
        if entry.is_symlink():
            # We can ignore symlinks because they either point into our tree,
            # in which case we'll include the size of target directory anyway,
            # or outside, in which case we don't need to.
            continue
        elif entry.is_file():
            dir_sum += entry.stat().st_blocks * 512
        elif entry.is_dir():
            dir_sum += dir_size(entry.path)
    return dir_sum


def save_manifest(state: MkosiState, manifest: Manifest) -> None:
    if manifest.has_data():
        if ManifestFormat.json in state.config.manifest_format:
            with complete_step(f"Saving manifest {state.config.output_manifest.name}"):
                with open(state.staging / state.config.output_manifest.name, 'w') as f:
                    manifest.write_json(f)

        if ManifestFormat.changelog in state.config.manifest_format:
            with complete_step(f"Saving report {state.config.output_changelog.name}"):
                with open(state.staging / state.config.output_changelog.name, 'w') as f:
                    manifest.write_package_report(f)


def print_output_size(config: MkosiConfig) -> None:
    if not config.output.exists():
        return

    if config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        MkosiPrinter.print_step("Resulting image size is " + format_bytes(dir_size(config.output)) + ".")
    else:
        st = os.stat(config.output)
        size = format_bytes(st.st_size)
        space = format_bytes(st.st_blocks * 512)
        MkosiPrinter.print_step(f"Resulting image size is {size}, consumes {space}.")


def setup_package_cache(config: MkosiConfig, workspace: Path) -> Path:
    if not config.cache_path:
        cache = workspace / "cache"
    else:
        cache = config.cache_path
        mkdirp_chown_current_user(cache, chown=config.chown, mode=0o755)

    return cache


def remove_duplicates(items: list[T]) -> list[T]:
    "Return list with any repetitions removed"
    # We use a dictionary to simulate an ordered set
    return list({x: None for x in items})


class ListAction(argparse.Action):
    delimiter: str
    deduplicate: bool = True

    def __init__(self, *args: Any, choices: Optional[Iterable[Any]] = None, **kwargs: Any) -> None:
        self.list_choices = choices
        # mypy doesn't like the following call due to https://github.com/python/mypy/issues/6799,
        # so let's, temporarily, ignore the error
        super().__init__(choices=choices, *args, **kwargs)  # type: ignore[misc]

    def __call__(
        self,  # These type-hints are copied from argparse.pyi
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None],
        option_string: Optional[str] = None,
    ) -> None:
        ary = getattr(namespace, self.dest)
        if ary is None:
            ary = []

        if isinstance(values, (str, Path)):
            # Save the actual type so we can restore it later after processing the argument
            t = type(values)
            values = str(values)
            # Support list syntax for comma separated lists as well
            if self.delimiter == "," and values.startswith("[") and values.endswith("]"):
                values = values[1:-1]

            # Make sure delimiters between quotes are ignored.
            # Inspired by https://stackoverflow.com/a/2787979.
            values = [t(x.strip()) for x in re.split(f"""{self.delimiter}(?=(?:[^'"]|'[^']*'|"[^"]*")*$)""", values) if x]

        if isinstance(values, list):
            for x in values:
                if self.list_choices is not None and x not in self.list_choices:
                    raise ValueError(f"Unknown value {x!r}")

                # Remove ! prefixed list entries from list. !* removes all entries. This works for strings only now.
                if x == "!*":
                    ary = []
                elif isinstance(x, str) and x.startswith("!"):
                    if x[1:] in ary:
                        ary.remove(x[1:])
                else:
                    ary.append(x)
        else:
            ary.append(values)

        if self.deduplicate:
            ary = remove_duplicates(ary)
        setattr(namespace, self.dest, ary)


class CommaDelimitedListAction(ListAction):
    delimiter = ","


class ColonDelimitedListAction(ListAction):
    delimiter = ":"


class SpaceDelimitedListAction(ListAction):
    delimiter = " "


class RepeatableSpaceDelimitedListAction(SpaceDelimitedListAction):
    deduplicate = False


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
        super().__init__(option_strings, dest, nargs="?", const=const, default=default, **kwargs)

    def __call__(
        self,  # These type-hints are copied from argparse.pyi
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:
        if isinstance(values, str):
            try:
                new_value = parse_boolean(values)
            except ValueError as exp:
                raise argparse.ArgumentError(self, str(exp))
        elif isinstance(values, bool):  # Assign const
            new_value = values
        else:
            raise argparse.ArgumentError(self, f"Invalid argument for {option_string}: {values}")

        # invert the value if the argument name starts with "not" or "without"
        for option in self.option_strings:
            if option[2:].startswith("not-") or option[2:].startswith("without-"):
                new_value = not new_value
                break

        setattr(namespace, self.dest, new_value)


class CleanPackageMetadataAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:

        if isinstance(values, str) and values == "auto":
            setattr(namespace, self.dest, "auto")
        else:
            super().__call__(parser, namespace, values, option_string)


class WithNetworkAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:

        if isinstance(values, str) and values == "never":
            setattr(namespace, self.dest, "never")
        else:
            super().__call__(parser, namespace, values, option_string)


def parse_sign_expected_pcr(value: Union[bool, str]) -> bool:
    if isinstance(value, bool):
        return value

    if value == "auto":
        return bool(shutil.which('systemd-measure'))

    val = parse_boolean(value)
    if val:
        if not shutil.which('systemd-measure'):
            die("Couldn't find systemd-measure binary. It is needed for the --sign-expected-pcr option.")

    return val


class SignExpectedPcrAction(BooleanAction):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Union[str, Sequence[Any], None, bool],
        option_string: Optional[str] = None,
    ) -> None:
        if values is None:
            parsed = False
        elif isinstance(values, bool) or isinstance(values, str):
            parsed = parse_sign_expected_pcr(values)
        else:
            raise argparse.ArgumentError(self, f"Invalid argument for {option_string}: {values}")
        setattr(namespace, self.dest, parsed)


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        default = self._get_default_metavar_for_optional(action)
        args_string = self._format_args(action, default)
        return ", ".join(action.option_strings) + " " + args_string

    def _split_lines(self, text: str, width: int) -> list[str]:
        """Wraps text to width, each line separately.
        If the first line of text ends in a colon, we assume that
        this is a list of option descriptions, and subindent them.
        Otherwise, the text is wrapped without indentation.
        """
        lines = text.splitlines()
        subindent = '    ' if lines[0].endswith(':') else ''
        return list(itertools.chain.from_iterable(wrap(line, width,
                                                       break_long_words=False, break_on_hyphens=False,
                                                       subsequent_indent=subindent) for line in lines))


class ArgumentParserMkosi(argparse.ArgumentParser):
    """ArgumentParser with support for mkosi configuration file(s)

    This derived class adds a simple ini file parser to python's ArgumentParser features.
    Each line of the ini file is converted to a command line argument. Example:
    "FooBar=Hello_World"  in the ini file appends "--foo-bar Hello_World" to sys.argv.

    Command line arguments starting with - or --are considered as regular arguments. Arguments
    starting with @ are considered as files which are fed to the ini file parser implemented
    in this class.
    """

    # Mapping of parameters supported in config files but not as command line arguments.
    SPECIAL_MKOSI_DEFAULT_PARAMS = {
        "QCow2": "--qcow2",
        "OutputDirectory": "--output-dir",
        "WorkspaceDirectory": "--workspace-dir",
        "NSpawnSettings": "--settings",
        "CheckSum": "--checksum",
        "BMap": "--bmap",
        "Packages": "--package",
        "RemovePackages": "--remove-package",
        "ExtraTrees": "--extra-tree",
        "SkeletonTrees": "--skeleton-tree",
        "BuildPackages": "--build-package",
        "PostInstallationScript": "--postinst-script",
        "TarStripSELinuxContext": "--tar-strip-selinux-context",
        "MachineID": "--machine-id",
        "SignExpectedPCR": "--sign-expected-pcr",
    }

    def __init__(self, *kargs: Any, **kwargs: Any) -> None:
        self._ini_file_section = ""
        self._ini_file_key = ""  # multi line list processing
        self._ini_file_list_mode = False

        # we need to suppress mypy here: https://github.com/python/mypy/issues/6799
        super().__init__(*kargs,
                         # Add config files to be parsed:
                         fromfile_prefix_chars='@',
                         formatter_class=CustomHelpFormatter,
                         # Tweak defaults:
                         allow_abbrev=False,
                         # Pass through the other options:
                         **kwargs,
                         ) # type: ignore

    @staticmethod
    def _camel_to_arg(camel: str) -> str:
        s1 = re.sub("(.)([A-Z][a-z]+)", r"\1-\2", camel)
        return re.sub("([a-z0-9])([A-Z])", r"\1-\2", s1).lower()

    @classmethod
    def _ini_key_to_cli_arg(cls, key: str) -> str:
        return cls.SPECIAL_MKOSI_DEFAULT_PARAMS.get(key) or ("--" + cls._camel_to_arg(key))

    def _read_args_from_files(self, arg_strings: list[str]) -> list[str]:
        """Convert @-prefixed command line arguments with corresponding file content

        Regular arguments are just returned. Arguments prefixed with @ are considered
        configuration file paths. The settings of each file are parsed and returned as
        command line arguments.
        Example:
          The following mkosi config is loaded.
          [Distribution]
          Distribution=fedora

          mkosi is called like: mkosi -p httpd

          arg_strings: ['@mkosi.conf', '-p', 'httpd']
          return value: ['--distribution', 'fedora', '-p', 'httpd']
        """

        # expand arguments referencing files
        new_arg_strings = []
        for arg_string in arg_strings:
            # for regular arguments, just add them back into the list
            if not arg_string.startswith('@'):
                new_arg_strings.append(arg_string)
                continue
            # replace arguments referencing files with the file content
            try:
                # This used to use configparser.ConfigParser before, but
                # ConfigParser's interpolation clashes with systemd style
                # specifier, e.g. %u for user, since both use % as a sigil.
                config = configparser.RawConfigParser(delimiters="=", inline_comment_prefixes=("#",))
                config.optionxform = str  # type: ignore
                with open(arg_string[1:]) as args_file:
                    config.read_file(args_file)

                # Rename old [Packages] section to [Content]
                if config.has_section("Packages") and not config.has_section("Content"):
                    config.read_dict({"Content": dict(config.items("Packages"))})
                    config.remove_section("Packages")

                for section in config.sections():
                    for key, value in config.items(section):
                        cli_arg = self._ini_key_to_cli_arg(key)

                        # \n in value strings is forwarded. Depending on the action type, \n is considered as a delimiter or needs to be replaced by a ' '
                        for action in self._actions:
                            if cli_arg in action.option_strings:
                                if isinstance(action, ListAction):
                                    value = value.replace(os.linesep, action.delimiter)
                        new_arg_strings.append(f"{cli_arg}={value}")
            except OSError as e:
                self.error(str(e))
        # return the modified argument list
        return new_arg_strings

    def error(self, message: str) -> NoReturn:
        # This is a copy of super's method but with self.print_usage() removed
        self.exit(2, f'{self.prog}: error: {message}\n')


COMPRESSION_ALGORITHMS = "zlib", "lzo", "zstd", "lz4", "xz"


def parse_compression(value: str) -> Union[str, bool]:
    if value in COMPRESSION_ALGORITHMS:
        return value
    return parse_boolean(value)


def parse_source_file_transfer(value: str) -> Optional[SourceFileTransfer]:
    if value == "":
        return None
    try:
        return SourceFileTransfer(value)
    except Exception as exp:
        raise argparse.ArgumentTypeError(str(exp))


def parse_base_packages(value: str) -> Union[str, bool]:
    if value == "conditional":
        return value
    return parse_boolean(value)


def parse_remove_files(value: str) -> list[str]:
    """Normalize paths as relative to / to ensure we don't go outside of our root."""

    # os.path.normpath() leaves leading '//' untouched, even though it normalizes '///'.
    # This follows POSIX specification, see
    # https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_13.
    # Let's use lstrip() to handle zero or more leading slashes correctly.
    return ["/" + os.path.normpath(p).lstrip("/") for p in value.split(",") if p]


def parse_ssh_agent(value: str) -> Optional[Path]:
    """Will return None or a path to a socket."""

    if not value:
        return None

    try:
        if not parse_boolean(value):
            return None
    except ValueError:
        pass
    else:
        value = os.getenv("SSH_AUTH_SOCK", "")
        if not value:
            die("--ssh-agent=true but $SSH_AUTH_SOCK is not set (consider running 'sudo' with '-E')")

    sock = Path(value)
    if not sock.is_socket():
        die(f"SSH agent socket {sock} is not an AF_UNIX socket")
    return sock

USAGE = """
       mkosi [options...] {b}summary{e}
       mkosi [options...] {b}build{e} [script parameters...]
       mkosi [options...] {b}shell{e} [command line...]
       mkosi [options...] {b}boot{e} [nspawn settings...]
       mkosi [options...] {b}qemu{e} [qemu parameters...]
       mkosi [options...] {b}ssh{e} [command line...]
       mkosi [options...] {b}clean{e}
       mkosi [options...] {b}serve{e}
       mkosi [options...] {b}bump{e}
       mkosi [options...] {b}genkey{e}
       mkosi [options...] {b}help{e}
       mkosi -h | --help
       mkosi --version
""".format(b=MkosiPrinter.bold, e=MkosiPrinter.reset)

def create_parser() -> ArgumentParserMkosi:
    parser = ArgumentParserMkosi(
        prog="mkosi",
        description="Build Bespoke OS Images",
        usage=USAGE,
        add_help=False,
    )

    parser.add_argument(
        "verb",
        type=Verb,
        choices=list(Verb),
        default=Verb.build,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "cmdline",
        nargs=argparse.REMAINDER,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-h", "--help",
        action="help",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + __version__,
        help=argparse.SUPPRESS,
    )

    group = parser.add_argument_group("Distribution options")
    group.add_argument("-d", "--distribution", choices=Distribution.__members__, help="Distribution to install")
    group.add_argument("-r", "--release", help="Distribution release to install")
    group.add_argument("--architecture", help="Override the architecture of installation", default=platform.machine())
    group.add_argument("-m", "--mirror", help="Distribution mirror to use")
    group.add_argument("--local-mirror", help="Use a single local, flat and plain mirror to build the image",
    )
    group.add_argument(
        "--repository-key-check",
        metavar="BOOL",
        action=BooleanAction,
        help="Controls signature and key checks on repositories",
        default=True,
    )

    group.add_argument(
        "--repositories",
        metavar="REPOS",
        action=CommaDelimitedListAction,
        default=[],
        help="Repositories to use",
    )
    group.add_argument(
        "--use-host-repositories",
        metavar="BOOL",
        action=BooleanAction,
        help="Use host's existing software repositories (only for dnf-based distributions)",
    )
    group.add_argument(
        "--repository-directory",
        metavar="PATH",
        dest="repos_dir",
        help="Directory container extra distribution specific repository files",
    )

    group = parser.add_argument_group("Output options")
    group.add_argument(
        "-t", "--format",
        dest="output_format",
        metavar="FORMAT",
        choices=OutputFormat,
        type=OutputFormat.from_string,
        help="Output Format",
    )
    group.add_argument(
        "--manifest-format",
        metavar="FORMAT",
        action=CommaDelimitedListAction,
        type=cast(Callable[[str], ManifestFormat], ManifestFormat.parse_list),
        help="Manifest Format",
    )
    group.add_argument(
        "-o", "--output",
        help="Output image path",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "-O", "--output-dir",
        help="Output root directory",
        type=Path,
        metavar="DIR",
    )
    group.add_argument(
        "--workspace-dir",
        help="Workspace directory",
        type=Path,
        metavar="DIR",
    )
    group.add_argument(
        "-f", "--force",
        action="count",
        dest="force",
        default=0,
        help="Remove existing image file before operation",
    )
    group.add_argument(
        "-b", "--bootable",
        metavar="BOOL",
        action=BooleanAction,
        help="Make image bootable on EFI (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    group.add_argument(
        "--kernel-command-line",
        metavar="OPTIONS",
        action=SpaceDelimitedListAction,
        default=["rhgb", "selinux=0", "audit=0"],
        help="Set the kernel command line (only bootable images)",
    )
    group.add_argument(
        "--secure-boot",
        metavar="BOOL",
        action=BooleanAction,
        help="Sign the resulting kernel/initrd image for UEFI SecureBoot",
    )
    group.add_argument(
        "--secure-boot-key",
        help="UEFI SecureBoot private key in PEM format",
        type=Path,
        metavar="PATH",
        default=Path("./mkosi.secure-boot.key"),
    )
    group.add_argument(
        "--secure-boot-certificate",
        help="UEFI SecureBoot certificate in X509 format",
        type=Path,
        metavar="PATH",
        default=Path("./mkosi.secure-boot.crt"),
    )
    group.add_argument(
        "--secure-boot-valid-days",
        help="Number of days UEFI SecureBoot keys should be valid when generating keys",
        metavar="DAYS",
        default="730",
    )
    group.add_argument(
        "--secure-boot-common-name",
        help="Template for the UEFI SecureBoot CN when generating keys",
        metavar="CN",
        default="mkosi of %u",
    )
    group.add_argument(
        "--sign-expected-pcr",
        metavar="BOOL",
        default="auto",
        action=SignExpectedPcrAction,
        type=parse_sign_expected_pcr,
        help="Measure the components of the unified kernel image (UKI) and embed the PCR signature into the UKI",
    )
    group.add_argument(
        "--compress-output",
        type=parse_compression,
        nargs="?",
        metavar="ALG",
        help="Enable whole-output compression (with images or archives)",
    )
    group.add_argument(
        "--qcow2",
        action=BooleanAction,
        metavar="BOOL",
        help="Convert resulting image to qcow2 (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs)",
    )
    group.add_argument("--hostname", help="Set hostname")
    group.add_argument("--image-version", help="Set version for image")
    group.add_argument("--image-id", help="Set ID for image")
    group.add_argument(
        "--chown",
        metavar="BOOL",
        action=BooleanAction,
        default=True,
        help="When running with sudo, reassign ownership of the generated files to the original user",
    )  # NOQA: E501
    group.add_argument(
        "--idmap",
        metavar="BOOL",
        action=BooleanAction,
        default=True,
        help="Use systemd-nspawn's rootidmap option for bind-mounted directories.",
    )
    group.add_argument(
        "--tar-strip-selinux-context",
        metavar="BOOL",
        action=BooleanAction,
        help="Do not include SELinux file context information in tar. Not compatible with bsdtar.",
    )
    group.add_argument(
        "-i", "--incremental",
        metavar="BOOL",
        action=BooleanAction,
        help="Make use of and generate intermediary cache images",
    )
    group.add_argument(
        "--cache-initrd",
        metavar="BOOL",
        action=BooleanAction,
        help="When using incremental mode, build the initrd in the cache image and don't rebuild it in the final image",
    )
    group.add_argument(
        "--split-artifacts",
        metavar="BOOL",
        action=BooleanAction,
        help="Generate split partitions",
    )
    group.add_argument(
        "--repart-directory",
        metavar="PATH",
        dest="repart_dir",
        help="Directory containing systemd-repart partition definitions",
    )

    group = parser.add_argument_group("Content options")
    group.add_argument(
        "--base-packages",
        type=parse_base_packages,
        default=True,
        help="Automatically inject basic packages in the system (systemd, kernel, …)",
        metavar="OPTION",
    )
    group.add_argument(
        "-p",
        "--package",
        action=CommaDelimitedListAction,
        dest="packages",
        default=[],
        help="Add an additional package to the OS image",
        metavar="PACKAGE",
    )
    group.add_argument(
        "--remove-package",
        action=CommaDelimitedListAction,
        dest="remove_packages",
        default=[],
        help="Remove package from the image OS image after installation",
        metavar="PACKAGE",
    )
    group.add_argument(
        "--with-docs",
        metavar="BOOL",
        action=BooleanAction,
        help="Install documentation",
    )
    group.add_argument(
        "-T", "--without-tests",
        action=BooleanAction,
        dest="with_tests",
        default=True,
        help="Do not run tests as part of build script, if supported",
    )
    group.add_argument(
        "--with-tests",       # Compatibility option
        action=BooleanAction,
        default=True,
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--machine-id",
        help="Defines a fixed machine ID for all our build-time runs.",
    )

    group.add_argument("--password", help="Set the root password")
    group.add_argument(
        "--password-is-hashed",
        metavar="BOOL",
        action=BooleanAction,
        help="Indicate that the root password has already been hashed",
    )
    group.add_argument(
        "--autologin",
        metavar="BOOL",
        action=BooleanAction,
        help="Enable root autologin",
    )
    group.add_argument(
        "--cache",
        dest="cache_path",
        help="Package cache path",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--extra-tree",
        action=CommaDelimitedListAction,
        dest="extra_trees",
        default=[],
        help="Copy an extra tree on top of image",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--skeleton-tree",
        action="append",
        dest="skeleton_trees",
        default=[],
        help="Use a skeleton tree to bootstrap the image before installing anything",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--clean-package-metadata",
        action=CleanPackageMetadataAction,
        help="Remove package manager database and other files",
        default='auto',
    )
    group.add_argument(
        "--remove-files",
        action=CommaDelimitedListAction,
        default=[],
        help="Remove files from built image",
        type=parse_remove_files,
        metavar="GLOB",
    )
    group.add_argument(
        "--environment",
        "-E",
        action=SpaceDelimitedListAction,
        default=[],
        help="Set an environment variable when running scripts",
        metavar="NAME[=VALUE]",
    )
    group.add_argument(
        "--build-environment",   # Compatibility option
        action=SpaceDelimitedListAction,
        default=[],
        dest="environment",
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--build-sources",
        help="Path for sources to build",
        metavar="PATH",
        type=Path,
    )
    group.add_argument(
        "--build-dir",           # Compatibility option
        help=argparse.SUPPRESS,
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--build-directory",
        dest="build_dir",
        help="Path to use as persistent build directory",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--include-directory",
        dest="include_dir",
        help="Path to use as persistent include directory",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--install-directory",
        dest="install_dir",
        help="Path to use as persistent install directory",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--build-package",
        action=CommaDelimitedListAction,
        dest="build_packages",
        default=[],
        help="Additional packages needed for build script",
        metavar="PACKAGE",
    )
    group.add_argument(
        "--skip-final-phase",
        metavar="BOOL",
        action=BooleanAction,
        help="Skip the (second) final image building phase.",
        default=False,
    )
    group.add_argument(
        "--build-script",
        help="Build script to run inside image",
        type=script_path,
        metavar="PATH",
    )
    group.add_argument(
        "--prepare-script",
        help="Prepare script to run inside the image before it is cached",
        type=script_path,
        metavar="PATH",
    )
    group.add_argument(
        "--postinst-script",
        help="Postinstall script to run inside image",
        type=script_path,
        metavar="PATH",
    )
    group.add_argument(
        "--finalize-script",
        help="Postinstall script to run outside image",
        type=script_path,
        metavar="PATH",
    )
    group.add_argument(
        "--source-file-transfer",
        type=parse_source_file_transfer,
        choices=[*list(SourceFileTransfer), None],
        metavar="METHOD",
        default=None,
        help='\n'.join(('How to copy build sources to the build image:',
                        *(f"'{k}': {v}" for k, v in SourceFileTransfer.doc().items()),
                        '(default: copy-git-others if in a git repository, otherwise copy-all)')),
    )
    group.add_argument(
        "--source-file-transfer-final",
        type=parse_source_file_transfer,
        choices=[*list(SourceFileTransfer), None],
        metavar="METHOD",
        default=None,
        help='\n'.join(('How to copy build sources to the final image:',
                        *(f"'{k}': {v}" for k, v in SourceFileTransfer.doc().items()
                          if k != SourceFileTransfer.mount),
                        '(default: None)')),
    )
    group.add_argument(
        "--source-resolve-symlinks",
        metavar="BOOL",
        action=BooleanAction,
        help=("If true, symbolic links in the build sources are followed and the "
              "file contents copied to the build image. If false, they are left as "
              "symbolic links. "
              "Only applies if --source-file-transfer-final is set to 'copy-all'.\n"
              "(default: false)"),
    )
    group.add_argument(
        "--source-resolve-symlinks-final",
        metavar="BOOL",
        action=BooleanAction,
        help=("If true, symbolic links in the build sources are followed and the "
              "file contents copied to the final image. If false, they are left as "
              "symbolic links in the final image. "
              "Only applies if --source-file-transfer-final is set to 'copy-all'.\n"
              "(default: false)"),
    )
    group.add_argument(
        "--with-network",
        action=WithNetworkAction,
        help="Run build and postinst scripts with network access (instead of private network)",
    )
    group.add_argument(
        "--settings",
        dest="nspawn_settings",
        help="Add in .nspawn settings file",
        type=Path,
        metavar="PATH",
    )

    group = parser.add_argument_group("Partitions options")
    group.add_argument('--base-image',
                       help='Use the given image as base (e.g. lower sysext layer)',
                       type=Path,
                       metavar='IMAGE')

    group = parser.add_argument_group("Validation options (only gpt_ext4, gpt_xfs, gpt_btrfs, gpt_squashfs, tar, cpio)")
    group.add_argument(
        "--checksum",
        metavar="BOOL",
        action=BooleanAction,
        help="Write SHA256SUMS file",
    )
    group.add_argument(
        "--sign",
        metavar="BOOL",
        action=BooleanAction,
        help="Write and sign SHA256SUMS file",
    )
    group.add_argument("--key", help="GPG key to use for signing")
    group.add_argument(
        "--bmap",
        metavar="BOOL",
        action=BooleanAction,
        help="Write block map file (.bmap) for bmaptool usage (only gpt_ext4, gpt_btrfs)",
    )

    group = parser.add_argument_group("Host configuration options")
    group.add_argument(
        "--extra-search-path",
        dest="extra_search_paths",
        action=ColonDelimitedListAction,
        default=[],
        type=Path,
        help="List of colon-separated paths to look for programs before looking in PATH",
    )
    group.add_argument(
        "--extra-search-paths",    # Compatibility option
        dest="extra_search_paths",
        action=ColonDelimitedListAction,
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--qemu-headless",
        metavar="BOOL",
        action=BooleanAction,
        help="Configure image for qemu's -nographic mode",
    )
    group.add_argument(
        "--qemu-smp",
        metavar="SMP",
        default="1",
        help="Configure guest's SMP settings",
    )
    group.add_argument(
        "--qemu-mem",
        metavar="MEM",
        default="1G",
        help="Configure guest's RAM size",
    )
    group.add_argument(
        "--qemu-kvm",
        metavar="BOOL",
        action=BooleanAction,
        help="Configure whether to use KVM or not",
        default=qemu_check_kvm_support(),
    )
    group.add_argument(
        "--qemu-args",
        action=RepeatableSpaceDelimitedListAction,
        default=[],
        # Suppress the command line option because it's already possible to pass qemu args as normal
        # arguments.
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--nspawn-keep-unit",
        metavar="BOOL",
        action=BooleanAction,
        help="If specified, underlying systemd-nspawn containers use the resources of the current unit.",
    )
    group.add_argument(
        "--network-veth",     # Compatibility option
        dest="netdev",
        metavar="BOOL",
        action=BooleanAction,
        help=argparse.SUPPRESS,
    )
    group.add_argument(
        "--netdev",
        metavar="BOOL",
        action=BooleanAction,
        help="Create a virtual Ethernet link between the host and the container/VM",
    )
    group.add_argument(
        "--ephemeral",
        metavar="BOOL",
        action=BooleanAction,
        help=('If specified, the container/VM is run with a temporary snapshot of the output '
              'image that is removed immediately when the container/VM terminates'),
    )
    group.add_argument(
        "--ssh",
        metavar="BOOL",
        action=BooleanAction,
        help="Set up SSH access from the host to the final image via 'mkosi ssh'",
    )
    group.add_argument(
        "--ssh-key",
        type=Path,
        metavar="PATH",
        help="Use the specified private key when using 'mkosi ssh' (requires a corresponding public key)",
    )
    group.add_argument(
        "--ssh-timeout",
        metavar="SECONDS",
        type=int,
        default=0,
        help="Wait up to SECONDS seconds for the SSH connection to be available when using 'mkosi ssh'",
    )
    group.add_argument(
        "--ssh-agent",
        type=parse_ssh_agent,
        default="",
        metavar="PATH",
        help="Path to the ssh agent socket, or true to use $SSH_AUTH_SOCK.",
    )
    group.add_argument(
        "--ssh-port",
        type=int,
        default=22,
        metavar="PORT",
        help="If specified, 'mkosi ssh' will use this port to connect",
    )
    group.add_argument(
        "--credential",
        dest="credentials",
        action=SpaceDelimitedListAction,
        default=[],
        help="Pass a systemd credential to systemd-nspawn or qemu",
        metavar="NAME=VALUE",
    )

    group = parser.add_argument_group("Additional configuration options")
    group.add_argument(
        "-C", "--directory",
        help="Change to specified directory before doing anything",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--config",
        dest="config_path",
        help="Read configuration data from file",
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "--default",
        dest="config_path",
        help=argparse.SUPPRESS,
        type=Path,
        metavar="PATH",
    )
    group.add_argument(
        "-a", "--all",
        action="store_true",
        dest="all",
        default=False,
        help="Build all settings files in mkosi.files/",
    )
    group.add_argument(
        "--all-directory",
        metavar="PATH",
        type=Path,
        dest="all_directory",
        help="Specify path to directory to read settings files from",
    )
    group.add_argument(
        "-B",
        "--auto-bump",
        metavar="BOOL",
        action=BooleanAction,
        help="Automatically bump image version after building",
    )
    group.add_argument(
        "--debug",
        action=CommaDelimitedListAction,
        default=[],
        help="Turn on debugging output",
    )
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    return parser


def load_distribution(args: argparse.Namespace) -> argparse.Namespace:
    if args.distribution is not None:
        args.distribution = Distribution[args.distribution]

    if args.distribution is None or args.release is None:
        d, r = detect_distribution()

        if args.distribution is None:
            args.distribution = d

        if args.distribution == d and args.release is None:
            args.release = r

    if args.distribution is None:
        die("Couldn't detect distribution.")

    return args


def parse_args(argv: Optional[Sequence[str]] = None) -> dict[str, argparse.Namespace]:
    """Load config values from files and parse command line arguments

    Do all about config files and command line arguments parsing. If --all argument is passed
    more than one job needs to be processed. The returned tuple contains MkosiConfig
    valid for all jobs as well as a dict containing the arguments per job.
    """
    parser = create_parser()

    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)  # make a copy 'cause we'll be modifying the list later on

    # If ArgumentParserMkosi loads settings from mkosi configuration files, the settings from files
    # are converted to command line arguments. This breaks ArgumentParser's support for default
    # values of positional arguments. Make sure the verb command gets explicitly passed.
    # Insert a -- before the positional verb argument otherwise it might be considered as an argument of
    # a parameter with nargs='?'. For example mkosi -i summary would be treated as -i=summary.
    for verb in Verb:
        try:
            v_i = argv.index(verb.name)
        except ValueError:
            continue

        if v_i > 0 and argv[v_i - 1] != "--":
            argv.insert(v_i, "--")
        break
    else:
        argv += ["--", "build"]

    # First run of command line arguments parsing to get the directory of the config file and the verb argument.
    args_pre_parsed, _ = parser.parse_known_args(argv)

    if args_pre_parsed.verb == Verb.help:
        parser.print_help()
        sys.exit(0)

    # Make sure all paths are absolute and valid.
    # Relative paths are not valid yet since we are not in the final working directory yet.
    if args_pre_parsed.directory is not None:
        directory = args_pre_parsed.directory = args_pre_parsed.directory.absolute()
    else:
        directory = Path.cwd()

    # Note that directory will be ignored if .all_directory or .config_path are absolute
    all_directory = directory / (args_pre_parsed.all_directory or "mkosi.files")
    if args_pre_parsed.config_path and not directory.joinpath(args_pre_parsed.config_path).exists():
        die(f"No config file found at {directory / args_pre_parsed.config_path}")

    for name in (args_pre_parsed.config_path, "mkosi.conf"):
        if not name:
            continue

        config_path = directory / name
        if config_path.exists():
            break
    else:
        config_path = directory / "mkosi.default"

    if args_pre_parsed.all and args_pre_parsed.config_path:
        die("--all and --config= may not be combined.")

    # Parse everything in --all mode
    args_all = {}
    if args_pre_parsed.all:
        if not os.path.isdir(all_directory):
            die(f"all-directory {all_directory} does not exist")
        for f in os.scandir(all_directory):
            if not f.name.startswith("mkosi."):
                continue
            args = parse_args_file(argv, Path(f.path))
            args_all[f.name] = args
    # Parse everything in normal mode
    else:
        args = parse_args_file_group(argv, config_path)

        args = load_distribution(args)

        if args.distribution:
            # Parse again with any extra distribution files included.
            args = parse_args_file_group(argv, config_path, args.distribution)

        args_all["default"] = args

    return args_all


def parse_args_file(argv: list[str], config_path: Path) -> argparse.Namespace:
    """Parse just one mkosi.* file (--all mode)."""

    # Parse all parameters handled by mkosi.
    # Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    argv = argv[:1] + [f"@{config_path}"] + argv[1:]

    return create_parser().parse_args(argv)


def parse_args_file_group(
    argv: list[str], config_path: Path, distribution: Optional[Distribution] = None
) -> argparse.Namespace:
    """Parse a set of mkosi config files"""
    # Add the @ prefixed filenames to current argument list in inverse priority order.
    config_files = []

    if config_path.exists():
        config_files += [f"@{config_path}"]

    d = config_path.parent

    dirs = [Path("mkosi.conf.d"), Path("mkosi.default.d")]
    if not d.samefile(Path.cwd()):
        dirs += [Path(d / "mkosi.conf.d"), Path(d / "mkosi.default.d")]

    if distribution is not None:
        dirs += [d / str(distribution) for d in dirs]

    for dropin_dir in dirs:
        if dropin_dir.is_dir():
            for entry in sorted(dropin_dir.iterdir()):
                if entry.is_file():
                    config_files += [f"@{entry}"]

    # Parse all parameters handled by mkosi.
    # Parameters forwarded to subprocesses such as nspawn or qemu end up in cmdline_argv.
    return create_parser().parse_args(config_files + argv)


def parse_bytes(num_bytes: Optional[str], *, sector_size: int = 512) -> int:
    """Convert a string for a number of bytes into a number rounding up to sector size."""
    if num_bytes is None:
        return 0

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

    result = math.ceil(float(num_bytes) * factor)
    if result <= 0:
        raise ValueError("Size out of range")

    rem = result % sector_size
    if rem != 0:
        result += sector_size - rem

    return result


def remove_glob(*patterns: PathString) -> None:
    pathgen = (glob.glob(str(pattern)) for pattern in patterns)
    paths: set[str] = set(sum(pathgen, []))  # uniquify
    for path in paths:
        unlink_try_hard(Path(path))


def empty_directory(path: Path) -> None:
    try:
        for f in os.listdir(path):
            unlink_try_hard(path / f)
    except FileNotFoundError:
        pass


def unlink_output(config: MkosiConfig) -> None:
    if not config.skip_final_phase:
        with complete_step("Removing output files…"):
            if config.output.parent.exists():
                for p in config.output.parent.iterdir():
                    if p.name.startswith(config.output.name) and "cache" not in p.name:
                        unlink_try_hard(p)
            unlink_try_hard(f"{config.output}.manifest")
            unlink_try_hard(f"{config.output}.changelog")

            if config.checksum:
                unlink_try_hard(config.output_checksum)

            if config.sign:
                unlink_try_hard(config.output_signature)

            if config.bmap:
                unlink_try_hard(config.output_bmap)

            if config.output_split_kernel.parent.exists():
                for p in config.output_split_kernel.parent.iterdir():
                    if p.name.startswith(config.output_split_kernel.name):
                        unlink_try_hard(p)
            unlink_try_hard(config.output_split_kernel)

            if config.nspawn_settings is not None:
                unlink_try_hard(config.output_nspawn_settings)

        if config.ssh and config.output_sshkey is not None:
            unlink_try_hard(config.output_sshkey)

    # We remove any cached images if either the user used --force
    # twice, or he/she called "clean" with it passed once. Let's also
    # remove the downloaded package cache if the user specified one
    # additional "--force".

    if config.verb == Verb.clean:
        remove_build_cache = config.force > 0
        remove_package_cache = config.force > 1
    else:
        remove_build_cache = config.force > 1
        remove_package_cache = config.force > 2

    if remove_build_cache:
        with complete_step("Removing incremental cache files…"):
            unlink_try_hard(cache_tree_path(config, is_final_image=False))
            unlink_try_hard(cache_tree_path(config, is_final_image=True))

        if config.build_dir is not None:
            with complete_step("Clearing out build directory…"):
                empty_directory(config.build_dir)

        if config.include_dir is not None:
            with complete_step("Clearing out include directory…"):
                empty_directory(config.include_dir)

        if config.install_dir is not None:
            with complete_step("Clearing out install directory…"):
                empty_directory(config.install_dir)

    if remove_package_cache:
        if config.cache_path is not None:
            with complete_step("Clearing out package cache…"):
                empty_directory(config.cache_path)


def parse_boolean(s: str) -> bool:
    "Parse 1/true/yes/y/t/on as true and 0/false/no/n/f/off/None as false"
    s_l = s.lower()
    if s_l in {"1", "true", "yes", "y", "t", "on"}:
        return True

    if s_l in {"0", "false", "no", "n", "f", "off"}:
        return False

    raise ValueError(f"Invalid literal for bool(): {s!r}")


def find_nspawn_settings(args: argparse.Namespace) -> None:
    if args.nspawn_settings is not None:
        return

    if os.path.exists("mkosi.nspawn"):
        args.nspawn_settings = "mkosi.nspawn"


def find_extra(args: argparse.Namespace) -> None:

    if len(args.extra_trees) > 0:
        return

    if os.path.isdir("mkosi.extra"):
        args.extra_trees.append(Path("mkosi.extra"))
    if os.path.isfile("mkosi.extra.tar"):
        args.extra_trees.append(Path("mkosi.extra.tar"))


def find_skeleton(args: argparse.Namespace) -> None:

    if len(args.skeleton_trees) > 0:
        return

    if os.path.isdir("mkosi.skeleton"):
        args.skeleton_trees.append(Path("mkosi.skeleton"))
    if os.path.isfile("mkosi.skeleton.tar"):
        args.skeleton_trees.append(Path("mkosi.skeleton.tar"))


def args_find_path(args: argparse.Namespace, name: str, path: str, *, as_list: bool = False) -> None:
    if getattr(args, name) is not None:
        return
    abspath = Path(path).absolute()
    if abspath.exists():
        setattr(args, name, [abspath] if as_list else abspath)


def find_output(args: argparse.Namespace) -> None:
    subdir = f"{args.distribution}~{args.release}"

    if args.output_dir is not None:
        args.output_dir = Path(args.output_dir, subdir)
    elif os.path.exists("mkosi.output/"):
        args.output_dir = Path("mkosi.output", subdir)
    else:
        return


def find_builddir(args: argparse.Namespace) -> None:
    subdir = f"{args.distribution}~{args.release}"

    if args.build_dir is not None:
        args.build_dir = Path(args.build_dir, subdir)
    elif os.path.exists("mkosi.builddir/"):
        args.build_dir = Path("mkosi.builddir", subdir)
    else:
        return


def find_cache(args: argparse.Namespace) -> None:
    subdir = f"{args.distribution}~{args.release}"

    if args.cache_path is not None:
        args.cache_path = Path(args.cache_path, subdir)
    elif os.path.exists("mkosi.cache/"):
        args.cache_path = Path("mkosi.cache", subdir)
    else:
        return


def require_private_file(name: PathString, description: str) -> None:
    mode = os.stat(name).st_mode & 0o777
    if mode & 0o007:
        warn(dedent(f"""\
            Permissions of '{name}' of '{mode:04o}' are too open.
            When creating {description} files use an access mode that restricts access to the owner only.
        """))


def find_passphrase(args: argparse.Namespace) -> None:
    if not needs_build(args):
        args.passphrase = None
        return

    passphrase = Path("mkosi.passphrase")
    if passphrase.exists():
        require_private_file(passphrase, "passphrase")
        args.passphrase = passphrase
    else:
        args.passphrase = None


def find_password(args: argparse.Namespace) -> None:
    if not needs_build(args) or args.password is not None:
        return

    try:
        require_private_file("mkosi.rootpw", "root password")

        with open("mkosi.rootpw") as f:
            args.password = f.read().strip()

    except FileNotFoundError:
        pass


def find_secure_boot(args: argparse.Namespace) -> None:
    if not args.secure_boot:
        return

    if args.secure_boot_key is None:
        if os.path.exists("mkosi.secure-boot.key"):
            args.secure_boot_key = Path("mkosi.secure-boot.key")

    if args.secure_boot_certificate is None:
        if os.path.exists("mkosi.secure-boot.crt"):
            args.secure_boot_certificate = Path("mkosi.secure-boot.crt")


def find_image_version(args: argparse.Namespace) -> None:
    if args.image_version is not None:
        return

    try:
        with open("mkosi.version") as f:
            args.image_version = f.read().strip()
    except FileNotFoundError:
        pass


def xescape(s: str) -> str:
    "Escape a string udev-style, for inclusion in /dev/disk/by-*/* symlinks"

    ret = ""
    for c in s:
        if ord(c) <= 32 or ord(c) >= 127 or c == "/":
            ret = ret + "\\x%02x" % ord(c)
        else:
            ret = ret + str(c)

    return ret


DISABLED = Path('DISABLED')  # A placeholder value to suppress autodetection.
                             # This is used as a singleton, i.e. should be compared with
                             # 'is' in other parts of the code.

def script_path(value: Optional[str]) -> Optional[Path]:
    if value is None:
        return None
    if value == '':
        return DISABLED
    return Path(value)


def normalize_script(path: Optional[Path]) -> Optional[Path]:
    if not path or path is DISABLED:
        return None
    return Path(path).absolute()


def load_args(args: argparse.Namespace) -> MkosiConfig:
    global ARG_DEBUG
    ARG_DEBUG.update(args.debug)

    args_find_path(args, "nspawn_settings", "mkosi.nspawn")
    args_find_path(args, "build_script", "mkosi.build")
    args_find_path(args, "include_dir", "mkosi.includedir/")
    args_find_path(args, "install_dir", "mkosi.installdir/")
    args_find_path(args, "postinst_script", "mkosi.postinst")
    args_find_path(args, "prepare_script", "mkosi.prepare")
    args_find_path(args, "finalize_script", "mkosi.finalize")
    args_find_path(args, "workspace_dir", "mkosi.workspace/")
    args_find_path(args, "repos_dir", "mkosi.reposdir/")
    args_find_path(args, "repart_dir", "mkosi.repart/")

    find_extra(args)
    find_skeleton(args)
    find_secure_boot(args)
    find_image_version(args)

    args.extra_search_paths = expand_paths(args.extra_search_paths)

    if args.cmdline and args.verb not in MKOSI_COMMANDS_CMDLINE:
        die(f"Parameters after verb are only accepted for {list_to_string(verb.name for verb in MKOSI_COMMANDS_CMDLINE)}.")

    if args.output_format is None:
        args.output_format = OutputFormat.disk

    args = load_distribution(args)

    if args.release is None:
        if args.distribution == Distribution.fedora:
            args.release = "36"
        elif args.distribution in (Distribution.centos, Distribution.centos_epel):
            args.release = "9-stream"
        elif args.distribution in (Distribution.rocky, Distribution.rocky_epel):
            args.release = "9"
        elif args.distribution in (Distribution.alma, Distribution.alma_epel):
            args.release = "9"
        elif args.distribution == Distribution.mageia:
            args.release = "7"
        elif args.distribution == Distribution.debian:
            args.release = "testing"
        elif args.distribution == Distribution.ubuntu:
            args.release = "jammy"
        elif args.distribution == Distribution.opensuse:
            args.release = "tumbleweed"
        elif args.distribution == Distribution.openmandriva:
            args.release = "cooker"
        elif args.distribution == Distribution.gentoo:
            args.release = "17.1"
        else:
            args.release = "rolling"

    if args.bootable:
        if args.verb == Verb.qemu and args.output_format in (
            OutputFormat.directory,
            OutputFormat.subvolume,
            OutputFormat.tar,
            OutputFormat.cpio,
        ):
            die("Directory, subvolume, tar, cpio, and plain squashfs images cannot be booted.", MkosiNotSupportedException)

    if shutil.which("bsdtar") and args.distribution == Distribution.openmandriva and args.tar_strip_selinux_context:
        die("Sorry, bsdtar on OpenMandriva is incompatible with --tar-strip-selinux-context", MkosiNotSupportedException)

    find_cache(args)
    find_output(args)
    find_builddir(args)

    if args.mirror is None:
        if args.distribution in (Distribution.fedora, Distribution.centos):
            args.mirror = None
        elif args.distribution == Distribution.debian:
            args.mirror = "http://deb.debian.org/debian"
        elif args.distribution == Distribution.ubuntu:
            if args.architecture == "x86" or args.architecture == "x86_64":
                args.mirror = "http://archive.ubuntu.com/ubuntu"
            else:
                args.mirror = "http://ports.ubuntu.com"
        elif args.distribution == Distribution.arch:
            if args.architecture == "aarch64":
                args.mirror = "http://mirror.archlinuxarm.org"
            else:
                args.mirror = "https://geo.mirror.pkgbuild.com"
        elif args.distribution == Distribution.opensuse:
            args.mirror = "http://download.opensuse.org"
        elif args.distribution in (Distribution.rocky, Distribution.rocky_epel):
            args.mirror = None
        elif args.distribution in (Distribution.alma, Distribution.alma_epel):
            args.mirror = None

    if args.sign:
        args.checksum = True

    if args.output is None:
        iid = args.image_id if args.image_id is not None else "image"
        prefix = f"{iid}_{args.image_version}" if args.image_version is not None else iid

        if args.output_format == OutputFormat.disk:
            output = prefix + (".qcow2" if args.qcow2 else ".raw")
        elif args.output_format == OutputFormat.tar:
            output = f"{prefix}.tar"
        elif args.output_format == OutputFormat.cpio:
            output = f"{prefix}.cpio"
        else:
            output = prefix
        args.output = Path(output)

    if args.manifest_format is None:
        args.manifest_format = [ManifestFormat.json]

    if args.output_dir is not None:
        args.output_dir = args.output_dir.absolute()

        if "/" not in str(args.output):
            args.output = args.output_dir / args.output
        else:
            warn("Ignoring configured output directory as output file is a qualified path.")

    args.output = args.output.absolute()

    if args.nspawn_settings is not None:
        args.nspawn_settings = args.nspawn_settings.absolute()

    if args.build_sources is not None:
        args.build_sources = args.build_sources.absolute()
    else:
        args.build_sources = Path.cwd()

    if args.build_dir is not None:
        args.build_dir = args.build_dir.absolute()

    if args.include_dir is not None:
        args.include_dir = args.include_dir.absolute()

    if args.install_dir is not None:
        args.install_dir = args.install_dir.absolute()

    args.build_script = normalize_script(args.build_script)
    args.prepare_script = normalize_script(args.prepare_script)
    args.postinst_script = normalize_script(args.postinst_script)
    args.finalize_script = normalize_script(args.finalize_script)

    if args.environment:
        env = {}
        for s in args.environment:
            key, _, value = s.partition("=")
            value = value or os.getenv(key, "")
            env[key] = value
        args.environment = env
    else:
        args.environment = {}

    if args.credentials:
        credentials = {}
        for s in args.credentials:
            key, _, value = s.partition("=")
            credentials[key] = value
        args.credentials = credentials
    else:
        args.credentials = {}

    if args.cache_path is not None:
        args.cache_path = args.cache_path.absolute()

    if args.extra_trees:
        for i in range(len(args.extra_trees)):
            args.extra_trees[i] = args.extra_trees[i].absolute()

    if args.skeleton_trees is not None:
        for i in range(len(args.skeleton_trees)):
            args.skeleton_trees[i] = args.skeleton_trees[i].absolute()

    if args.secure_boot_key is not None:
        args.secure_boot_key = args.secure_boot_key.absolute()

    if args.secure_boot_certificate is not None:
        args.secure_boot_certificate = args.secure_boot_certificate.absolute()

    if args.secure_boot:
        if args.secure_boot_key is None:
            die(
                "UEFI SecureBoot enabled, but couldn't find private key. (Consider placing it in mkosi.secure-boot.key?)"
            )  # NOQA: E501

        if args.secure_boot_certificate is None:
            die(
                "UEFI SecureBoot enabled, but couldn't find certificate. (Consider placing it in mkosi.secure-boot.crt?)"
            )  # NOQA: E501

    # Resolve passwords late so we can accurately determine whether a build is needed
    find_password(args)
    find_passphrase(args)

    if args.verb in (Verb.shell, Verb.boot):
        opname = "acquire shell" if args.verb == Verb.shell else "boot"
        if args.output_format in (OutputFormat.tar, OutputFormat.cpio):
            die(f"Sorry, can't {opname} with a {args.output_format} archive.", MkosiNotSupportedException)
        if should_compress_output(args):
            die(f"Sorry, can't {opname} with a compressed image.", MkosiNotSupportedException)
        if args.qcow2:
            die(f"Sorry, can't {opname} using a qcow2 image.", MkosiNotSupportedException)

    if args.verb == Verb.qemu:
        if not args.output_format == OutputFormat.disk:
            die("Sorry, can't boot non-disk images with qemu.", MkosiNotSupportedException)

    if needs_build(args) and args.verb == Verb.qemu and not args.bootable:
        die("Images built without the --bootable option cannot be booted using qemu", MkosiNotSupportedException)

    if needs_build(args) and args.qemu_headless and not args.bootable:
        die("--qemu-headless requires --bootable", MkosiNotSupportedException)

    if args.qemu_headless and "console=ttyS0" not in args.kernel_command_line:
        args.kernel_command_line.append("console=ttyS0")

    # By default, the serial console gets spammed with kernel log messages.
    # Let's up the log level to only show warning and error messages when
    # --qemu-headless is enabled to avoid this spam.
    if args.qemu_headless and not any("loglevel" in x for x in args.kernel_command_line):
        args.kernel_command_line.append("loglevel=4")

    if args.source_file_transfer is None:
        if os.path.exists(".git") or args.build_sources.joinpath(".git").exists():
            args.source_file_transfer = SourceFileTransfer.copy_git_others
        else:
            args.source_file_transfer = SourceFileTransfer.copy_all

    if args.source_file_transfer_final == SourceFileTransfer.mount and args.verb == Verb.qemu:
        die("Sorry, --source-file-transfer-final=mount is not supported when booting in QEMU")

    if args.skip_final_phase and args.verb != Verb.build:
        die("--skip-final-phase can only be used when building an image using 'mkosi build'", MkosiNotSupportedException)

    if args.ssh_timeout < 0:
        die("--ssh-timeout must be >= 0")

    if args.ssh_port <= 0:
        die("--ssh-port must be > 0")

    if args.repos_dir and not (is_rpm_distribution(args.distribution) or args.distribution == Distribution.arch):
        die("--repository-directory is only supported on RPM based distributions and Arch")

    if args.netdev and is_centos_variant(args.distribution) and not is_epel_variant(args.distribution):
        die("--netdev is only supported on EPEL centOS variants")

    if args.machine_id is not None:
        try:
            uuid.UUID(hex=args.machine_id)
        except ValueError:
            die(f"Sorry, {args.machine_id} is not a valid machine ID.")

    # If we are building a sysext we don't want to add base packages to the
    # extension image, as they will already be in the base image.
    if args.base_image is not None:
        args.base_packages = False

    if args.qemu_kvm and not qemu_check_kvm_support():
        die("Sorry, the host machine does not support KVM acceleration.")

    return MkosiConfig(**vars(args))


def cache_tree_path(config: MkosiConfig, is_final_image: bool) -> Path:
    suffix = "final-cache" if is_final_image else "build-cache"

    # If the image ID is specified, use cache file names that are independent of the image versions, so that
    # rebuilding and bumping versions is cheap and reuses previous versions if cached.
    if config.image_id is not None and config.output_dir:
        return config.output_dir / f"{config.image_id}.{suffix}"
    elif config.image_id:
        return Path(f"{config.image_id}.{suffix}")
    # Otherwise, derive the cache file names directly from the output file names.
    else:
        return Path(f"{config.output}.{suffix}")


def check_tree_input(path: Optional[Path]) -> None:
    # Each path may be a directory or a tarball.
    # Open the file or directory to simulate an access check.
    # If that fails, an exception will be thrown.
    if not path:
        return

    os.open(path, os.R_OK)


def check_script_input(path: Optional[Path]) -> None:
    if not path:
        return

    os.open(path, os.R_OK)
    if not path.is_file():
        raise OSError(errno.ENOENT, 'Not a normal file')
    if not os.access(path, os.X_OK):
        raise OSError(errno.ENOENT, 'Not executable')
    return None


def check_inputs(config: MkosiConfig) -> None:
    try:
        check_tree_input(config.base_image)

        for tree in (config.skeleton_trees,
                     config.extra_trees):
            for item in tree:
                check_tree_input(item)

        for path in (config.build_script,
                     config.prepare_script,
                     config.postinst_script,
                     config.finalize_script):
            check_script_input(path)
    except OSError as e:
        die(f'{e.filename} {e.strerror}')


def check_outputs(config: MkosiConfig) -> None:
    if config.skip_final_phase:
        return

    for f in (
        config.output,
        config.output_checksum if config.checksum else None,
        config.output_signature if config.sign else None,
        config.output_bmap if config.bmap else None,
        config.output_nspawn_settings if config.nspawn_settings is not None else None,
        config.output_sshkey if config.ssh else None,
    ):
        if f and f.exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def yes_no(b: Optional[bool]) -> str:
    return "yes" if b else "no"


def yes_no_or(b: Union[bool, str]) -> str:
    return b if isinstance(b, str) else yes_no(b)


def format_bytes_or_disabled(sz: int) -> str:
    if sz == 0:
        return "(disabled)"

    return format_bytes(sz)


def format_bytes_or_auto(sz: int) -> str:
    if sz == 0:
        return "(automatic)"

    return format_bytes(sz)


def none_to_na(s: Optional[T]) -> Union[T, str]:
    return "n/a" if s is None else s

def none_to_no(s: Optional[T]) -> Union[T, str]:
    return "no" if s is None else s

def none_to_none(s: Optional[T]) -> Union[T, str]:
    return "none" if s is None else s


def path_or_none(
        path: Optional[Path],
        checker: Optional[Callable[[Optional[Path]], None]] = None,
) -> Union[Optional[Path], str]:
    try:
        if checker:
            checker(path)
    except OSError as e:
        return f'{color_error(path)} ({e.strerror})'
    else:
        return path

def line_join_list(
        array: Sequence[PathString],
        checker: Optional[Callable[[Optional[Path]], None]] = None,
) -> str:
    if not array:
        return "none"

    items = (str(path_or_none(cast(Path, item), checker=checker)) for item in array)
    return "\n                            ".join(items)


def print_summary(config: MkosiConfig) -> None:
    print("COMMANDS:")

    print("                      verb:", config.verb)
    print("                   cmdline:", " ".join(config.cmdline))

    print("\nDISTRIBUTION:")

    print("              Distribution:", config.distribution.name)
    print("                   Release:", none_to_na(config.release))
    print("              Architecture:", config.architecture)

    if config.mirror is not None:
        print("                    Mirror:", config.mirror)

    if config.local_mirror is not None:
        print("      Local Mirror (build):", config.local_mirror)

    print("  Repo Signature/Key check:", yes_no(config.repository_key_check))

    if config.repositories is not None and len(config.repositories) > 0:
        print("              Repositories:", ",".join(config.repositories))

    print("     Use Host Repositories:", yes_no(config.use_host_repositories))

    print("\nOUTPUT:")

    if config.hostname:
        print("                  Hostname:", config.hostname)

    if config.image_id is not None:
        print("                  Image ID:", config.image_id)

    if config.image_version is not None:
        print("             Image Version:", config.image_version)

    print("             Output Format:", config.output_format.name)

    maniformats = (" ".join(str(i) for i in config.manifest_format)) or "(none)"
    print("          Manifest Formats:", maniformats)

    if config.output_dir:
        print("          Output Directory:", config.output_dir)

    if config.workspace_dir:
        print("       Workspace Directory:", config.workspace_dir)

    print("                    Output:", config.output)
    print("           Output Checksum:", none_to_na(config.output_checksum if config.checksum else None))
    print("          Output Signature:", none_to_na(config.output_signature if config.sign else None))
    print("               Output Bmap:", none_to_na(config.output_bmap if config.bmap else None))
    print("    Output nspawn Settings:", none_to_na(config.output_nspawn_settings if config.nspawn_settings is not None else None))
    print("                   SSH key:", none_to_na((config.ssh_key or config.output_sshkey or config.ssh_agent) if config.ssh else None))
    if config.ssh_port != 22:
        print("                  SSH port:", config.ssh_port)

    print("               Incremental:", yes_no(config.incremental))
    print("               Compression:", yes_no_or(should_compress_output(config)))

    if config.output_format == OutputFormat.disk:
        print("                     QCow2:", yes_no(config.qcow2))

    print("                  Bootable:", yes_no(config.bootable))

    if config.bootable:
        print("       Kernel Command Line:", " ".join(config.kernel_command_line))
        print("           UEFI SecureBoot:", yes_no(config.secure_boot))

    if config.secure_boot_key:
        print("SecureBoot Sign Key:", config.secure_boot_key)
    if config.secure_boot_certificate:
        print("   SecureBoot Cert.:", config.secure_boot_certificate)

    print("                Machine ID:", none_to_no(config.machine_id))

    print("\nCONTENT:")

    print("                  Packages:", line_join_list(config.packages))

    if config.distribution in (
        Distribution.fedora,
        Distribution.centos,
        Distribution.centos_epel,
        Distribution.mageia,
        Distribution.rocky,
        Distribution.rocky_epel,
        Distribution.alma,
        Distribution.alma_epel,
    ):
        print("        With Documentation:", yes_no(config.with_docs))

    print("             Package Cache:", none_to_none(config.cache_path))
    print("               Extra Trees:", line_join_list(config.extra_trees, check_tree_input))
    print("            Skeleton Trees:", line_join_list(config.skeleton_trees, check_tree_input))
    print("      CleanPackageMetadata:", yes_no_or(config.clean_package_metadata))

    if config.remove_files:
        print("              Remove Files:", line_join_list(config.remove_files))
    if config.remove_packages:
        print("           Remove Packages:", line_join_list(config.remove_packages))

    print("             Build Sources:", config.build_sources)
    print("      Source File Transfer:", none_to_none(config.source_file_transfer))
    print("Source File Transfer Final:", none_to_none(config.source_file_transfer_final))
    print("           Build Directory:", none_to_none(config.build_dir))
    print("         Include Directory:", none_to_none(config.include_dir))
    print("         Install Directory:", none_to_none(config.install_dir))
    print("            Build Packages:", line_join_list(config.build_packages))
    print("          Skip final phase:", yes_no(config.skip_final_phase))

    print("              Build Script:", path_or_none(config.build_script, check_script_input))

    env = [f"{k}={v}" for k, v in config.environment.items()]
    if config.build_script:
        print("                 Run tests:", yes_no(config.with_tests))

    print("        Postinstall Script:", path_or_none(config.postinst_script, check_script_input))
    print("            Prepare Script:", path_or_none(config.prepare_script, check_script_input))
    print("           Finalize Script:", path_or_none(config.finalize_script, check_script_input))

    print("        Script Environment:", line_join_list(env))
    print("      Scripts with network:", yes_no_or(config.with_network))
    print("           nspawn Settings:", none_to_none(config.nspawn_settings))

    print("                  Password:", ("(default)" if config.password is None else "(set)"))
    print("                 Autologin:", yes_no(config.autologin))

    if config.output_format == OutputFormat.disk:
        print("\nVALIDATION:")

        print("                  Checksum:", yes_no(config.checksum))
        print("                      Sign:", yes_no(config.sign))
        print("                   GPG Key:", ("default" if config.key is None else config.key))

    print("\nHOST CONFIGURATION:")

    print("        Extra search paths:", line_join_list(config.extra_search_paths))
    print("             QEMU Headless:", yes_no(config.qemu_headless))
    print("      QEMU Extra Arguments:", line_join_list(config.qemu_args))
    print("                    Netdev:", yes_no(config.netdev))


def make_output_dir(config: MkosiConfig) -> None:
    """Create the output directory if set and not existing yet"""
    if config.output_dir is None:
        return

    mkdirp_chown_current_user(config.output_dir, chown=config.chown, mode=0o755)


def make_build_dir(config: MkosiConfig) -> None:
    """Create the build directory if set and not existing yet"""
    if config.build_dir is None:
        return

    mkdirp_chown_current_user(config.build_dir, chown=config.chown, mode=0o755)


def make_cache_dir(config: MkosiConfig) -> None:
    """Create the output directory if set and not existing yet"""
    # TODO: mypy complains that having the same structure as above, makes  the
    # return on None unreachable code. I can't see right now, why it *should* be
    # unreachable, so invert the structure here to be on the safe side.
    if config.cache_path is not None:
        mkdirp_chown_current_user(config.cache_path, chown=config.chown, mode=0o755)


def configure_ssh(state: MkosiState, cached: bool) -> None:
    if state.do_run_build_script or not state.config.ssh:
        return

    if state.config.distribution in (Distribution.debian, Distribution.ubuntu):
        unit = "ssh.socket"

        if state.config.ssh_port != 22:
            add_dropin_config(state.root, unit, "port",
                              f"""\
                              [Socket]
                              ListenStream=
                              ListenStream={state.config.ssh_port}
                              """)

        add_dropin_config(state.root, "ssh@.service", "runtime-directory-preserve",
                          """\
                          [Service]
                          RuntimeDirectoryPreserve=yes
                          """)
    else:
        unit = "sshd"

    # We cache the enable sshd step but not the keygen step because it creates a separate file on the host
    # which introduces non-trivial issue when trying to cache it.

    if not cached:
        run(["systemctl", "--root", state.root, "enable", unit])

    if state.for_cache:
        return

    authorized_keys = state.root / "root/.ssh/authorized_keys"
    if state.config.ssh_key:
        copy_file(f"{state.config.ssh_key}.pub", authorized_keys)
    elif state.config.ssh_agent is not None:
        env = {"SSH_AUTH_SOCK": state.config.ssh_agent}
        result = run(["ssh-add", "-L"], env=env, text=True, stdout=subprocess.PIPE)
        authorized_keys.write_text(result.stdout)
    else:
        p = state.staging / state.config.output_sshkey.name

        with complete_step("Generating SSH key pair…"):
            # Write a 'y' to confirm to overwrite the file.
            run(
                ["ssh-keygen", "-f", p, "-N", state.config.password or "", "-C", "mkosi", "-t", "ed25519"],
                input="y\n",
                text=True,
                stdout=subprocess.DEVNULL,
            )

        authorized_keys.parent.mkdir(parents=True, exist_ok=True)
        copy_file(p.with_suffix(".pub"), authorized_keys)
        os.remove(p.with_suffix(".pub"))

    authorized_keys.chmod(0o600)


def configure_netdev(state: MkosiState, cached: bool) -> None:
    if state.do_run_build_script or cached or not state.config.netdev:
        return

    with complete_step("Setting up netdev…"):
        network_file = state.root / "etc/systemd/network/80-mkosi-netdev.network"
        with open(network_file, "w") as f:
            # Adapted from https://github.com/systemd/systemd/blob/v247/network/80-container-host0.network
            f.write(
                dedent(
                    """\
                    [Match]
                    Virtualization=!container
                    Type=ether
                    Driver=virtio_net

                    [Network]
                    DHCP=yes
                    LinkLocalAddressing=yes
                    LLDP=yes
                    EmitLLDP=customer-bridge

                    [DHCP]
                    UseTimezone=yes
                    """
                )
            )

        os.chmod(network_file, 0o644)

        run(["systemctl", "--root", state.root, "enable", "systemd-networkd"])


def boot_directory(state: MkosiState, kver: str) -> Path:
    return Path("boot") / state.machine_id / kver


def run_kernel_install(state: MkosiState, cached: bool) -> None:
    if not state.config.bootable or state.do_run_build_script:
        return

    if not state.config.cache_initrd and state.for_cache:
        return

    if state.config.cache_initrd and cached:
        return

    with complete_step("Generating initramfs images…"):
        for kver, kimg in gen_kernel_images(state):
            run_workspace_command(state, ["kernel-install", "add", kver, Path("/") / kimg])


def reuse_cache_tree(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    cache = cache_tree_path(state.config, is_final_image=not state.do_run_build_script)
    if not cache.exists():
        return False
    if state.for_cache and cache.exists():
        return True

    with complete_step(f"Basing off cached tree {cache}", "Copied cached tree"):
        copy_path(cache, state.root)

    return True


def invoke_repart(
    state: MkosiState,
    skip: Sequence[str] = [],
    split: bool = False,
) -> tuple[Optional[str], Optional[str], bool]:
    if not state.config.output_format == OutputFormat.disk or state.for_cache or state.do_run_build_script:
        return (None, None, False)

    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--root", state.root,
        state.staging / state.config.output.name,
    ]

    if not state.staging.joinpath(state.config.output.name).exists():
        cmdline += ["--empty=create"]
    if state.config.passphrase:
        cmdline += ["--key-file", state.config.passphrase]
    if state.config.secure_boot_key.exists():
        cmdline += ["--private-key", state.config.secure_boot_key]
    if state.config.secure_boot_certificate.exists():
        cmdline += ["--certificate", state.config.secure_boot_certificate]
    if not state.config.bootable:
        cmdline += ["--exclude-partitions=esp,xbootldr"]
    if skip:
        cmdline += ["--defer-partitions", ",".join(skip)]
    if split and state.config.split_artifacts:
        cmdline += ["--split=yes"]

    with contextlib.ExitStack() as stack:
        if state.config.repart_dir:
            definitions = Path(state.config.repart_dir)
        else:
            definitions = stack.enter_context(importlib.resources.path("mkosi.resources", "repart"))

        cmdline += ["--definitions", definitions]

        output = json.loads(run(cmdline, stdout=subprocess.PIPE).stdout)

        for p in output:
            if p["type"].startswith("usr") or p["type"].startswith("root"):
                usr_only = p["type"].startswith("usr")
                return (p["label"], p.get("roothash"), usr_only)

    return (None, None, False)


def build_image(state: MkosiState, *, manifest: Optional[Manifest] = None) -> None:
    # If there's no build script set, there's no point in executing
    # the build script iteration. Let's quit early.
    if state.config.build_script is None and state.do_run_build_script:
        return

    make_build_dir(state.config)

    cached = reuse_cache_tree(state)
    if state.for_cache and cached:
        return

    with mount_image(state, cached):
        prepare_tree(state, cached)
        install_skeleton_trees(state, cached)
        install_distribution(state, cached)
        configure_locale(state.root, cached)
        configure_hostname(state, cached)
        configure_root_password(state, cached)
        configure_serial_terminal(state, cached)
        configure_autologin(state, cached)
        configure_dracut(state, cached)
        configure_netdev(state, cached)
        run_prepare_script(state, cached)
        install_build_src(state)
        install_build_dest(state)
        install_extra_trees(state)
        run_kernel_install(state, cached)
        install_boot_loader(state)
        configure_ssh(state, cached)
        run_postinst_script(state)
        # Sign systemd-boot / sd-boot EFI binaries
        secure_boot_sign(state, state.root / 'usr/lib/systemd/boot/efi')

        cleanup = not state.for_cache and not state.do_run_build_script

        if cleanup:
            remove_packages(state)

        if manifest:
            with complete_step("Recording packages in manifest…"):
                manifest.record_packages(state.root)

        if cleanup:
            clean_package_manager_metadata(state)
            remove_files(state)
        reset_machine_id(state)
        reset_random_seed(state.root)
        run_finalize_script(state)

    label, roothash, usr_only = invoke_repart(state, skip=("esp", "xbootldr"))

    install_unified_kernel(state, label, roothash, usr_only)
    # Sign EFI binaries under these directories within the ESP
    for esp_dir in ['boot/EFI/BOOT', 'boot/EFI/systemd', 'boot/EFI/Linux']:
        secure_boot_sign(state, state.root / esp_dir, replace=True)

    invoke_repart(state, split=True)

    make_tar(state)
    make_cpio(state)
    make_directory(state)


def one_zero(b: bool) -> str:
    return "1" if b else "0"


def install_dir(state: MkosiState) -> Path:
    return state.config.install_dir or state.workspace / "dest"


def run_build_script(state: MkosiState) -> None:
    if state.config.build_script is None:
        return

    idmap_opt = ":rootidmap" if nspawn_id_map_supported() and state.config.idmap else ""

    with complete_step("Running build script…"):
        os.makedirs(install_dir(state), mode=0o755, exist_ok=True)

        with_network = 1 if state.config.with_network is True else 0

        cmdline = [
            "systemd-nspawn",
            "--quiet",
            f"--directory={state.root}",
            f"--machine=mkosi-{uuid.uuid4().hex}",
            "--as-pid2",
            "--link-journal=no",
            "--register=no",
            f"--bind={install_dir(state)}:/root/dest{idmap_opt}",
            f"--bind={state.var_tmp()}:/var/tmp{idmap_opt}",
            f"--setenv=WITH_DOCS={one_zero(state.config.with_docs)}",
            f"--setenv=WITH_TESTS={one_zero(state.config.with_tests)}",
            f"--setenv=WITH_NETWORK={with_network}",
            "--setenv=DESTDIR=/root/dest",
            *nspawn_rlimit_params(),
        ]

        # TODO: Use --autopipe once systemd v247 is widely available.
        console_arg = f"--console={'interactive' if sys.stdout.isatty() else 'pipe'}"
        if nspawn_knows_arg(console_arg):
            cmdline += [console_arg]

        if state.config.config_path is not None:
            cmdline += [
                f"--setenv=MKOSI_CONFIG={state.config.config_path}",
                f"--setenv=MKOSI_DEFAULT={state.config.config_path}"
            ]

        cmdline += nspawn_params_for_build_sources(state.config, state.config.source_file_transfer)

        if state.config.build_dir is not None:
            cmdline += ["--setenv=BUILDDIR=/root/build",
                        f"--bind={state.config.build_dir}:/root/build{idmap_opt}"]

        if state.config.include_dir is not None:
            cmdline += [f"--bind={state.config.include_dir}:/usr/include{idmap_opt}"]

        if state.config.with_network is True:
            # If we're using the host network namespace, use the same resolver
            cmdline += ["--bind-ro=/etc/resolv.conf"]
        else:
            cmdline += ["--private-network"]

        if state.config.nspawn_keep_unit:
            cmdline += ["--keep-unit"]

        cmdline += [f"--setenv={env}={value}" for env, value in state.environment.items()]

        cmdline += [f"/root/{state.config.build_script.name}"]

        # When we're building the image because it's required for another verb, any passed arguments are most
        # likely intended for the target verb, and not for "build", so don't add them in that case.
        if state.config.verb == Verb.build:
            cmdline += state.config.cmdline

        # build-script output goes to stdout so we can run language servers from within mkosi build-scripts.
        # See https://github.com/systemd/mkosi/pull/566 for more information.
        result = run(cmdline, stdout=sys.stdout, check=False)
        if result.returncode != 0:
            if "build-script" in ARG_DEBUG:
                run(cmdline[:-1], check=False)
            die(f"Build script returned non-zero exit code {result.returncode}.")


def need_cache_trees(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    if state.config.force > 1:
        return True

    return not cache_tree_path(state.config, is_final_image=True).exists() or not cache_tree_path(state.config, is_final_image=False).exists()


def remove_artifacts(state: MkosiState, for_cache: bool = False) -> None:
    if for_cache:
        what = "cache build"
    elif state.do_run_build_script:
        what = "development build"
    else:
        return

    with complete_step(f"Removing artifacts from {what}…"):
        unlink_try_hard(state.root)
        unlink_try_hard(state.var_tmp())


def build_stuff(config: MkosiConfig) -> None:
    make_output_dir(config)
    make_cache_dir(config)
    workspace = setup_workspace(config)
    cache = setup_package_cache(config, Path(workspace.name))

    manifest = Manifest(config)

    # Make sure tmpfiles' aging doesn't interfere with our workspace
    # while we are working on it.
    with open_close(workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC) as dir_fd:

        fcntl.flock(dir_fd, fcntl.LOCK_EX)

        state = MkosiState(
            config=config,
            workspace=Path(workspace.name),
            cache=cache,
            do_run_build_script=False,
            machine_id=config.machine_id or uuid.uuid4().hex,
            for_cache=False,
        )

        # If caching is requested, then make sure we have cache trees around we can make use of
        if need_cache_trees(state):

            # There is no point generating a pre-dev cache image if no build script is provided
            if config.build_script:
                with complete_step("Running first (development) stage to generate cached copy…"):
                    # Generate the cache version of the build image, and store it as "cache-pre-dev"
                    state = dataclasses.replace(state, do_run_build_script=True, for_cache=True)
                    build_image(state)
                    save_cache(state)
                    remove_artifacts(state)

            with complete_step("Running second (final) stage to generate cached copy…"):
                # Generate the cache version of the build image, and store it as "cache-pre-inst"
                state = dataclasses.replace(state, do_run_build_script=False, for_cache=True)
                build_image(state)
                save_cache(state)
                remove_artifacts(state)

        if config.build_script:
            with complete_step("Running first (development) stage…"):
                # Run the image builder for the first (development) stage in preparation for the build script
                state = dataclasses.replace(state, do_run_build_script=True, for_cache=False)
                build_image(state)
                run_build_script(state)
                remove_artifacts(state)

        # Run the image builder for the second (final) stage
        if not config.skip_final_phase:
            with complete_step("Running second (final) stage…"):
                state = dataclasses.replace(state, do_run_build_script=False, for_cache=False)
                build_image(state, manifest=manifest)
        else:
            MkosiPrinter.print_step("Skipping (second) final image build phase.")

        qcow2_output(state)
        calculate_bmap(state)
        copy_nspawn_settings(state)
        calculate_sha256sum(state)
        calculate_signature(state)
        save_manifest(state, manifest)

        for p in state.config.output_paths():
            if state.staging.joinpath(p.name).exists():
                shutil.move(state.staging / p.name, p)
                if p in (state.config.output, state.config.output_split_kernel):
                    compress_output(state.config, p)
            if state.config.chown and p.exists():
                chown_to_running_user(p)

        for p in state.staging.iterdir():
            shutil.move(p, state.config.output.parent / p.name)
            if p.name.startswith(state.config.output.name):
                compress_output(state.config, p)


def check_root() -> None:
    if os.getuid() != 0:
        die("Must be invoked as root.")


def check_native(config: MkosiConfig) -> None:
    if not config.architecture_is_native() and config.build_script and nspawn_version() < 250:
        die("Cannot (currently) override the architecture and run build commands")


@contextlib.contextmanager
def suppress_stacktrace() -> Iterator[None]:
    try:
        yield
    except subprocess.CalledProcessError as e:
        # MkosiException is silenced in main() so it doesn't print a stacktrace.
        raise MkosiException() from e


def machine_name(config: MkosiConfig) -> str:
    return config.hostname or config.image_id or config.output.with_suffix("").name.partition("_")[0]


def interface_name(config: MkosiConfig) -> str:
    # Shorten to 12 characters so we can prefix with ve- or vt- for the netdev ifname which is limited
    # to 15 characters.
    return machine_name(config)[:12]


def has_networkd_vm_vt() -> bool:
    return any(
        Path(path, "80-vm-vt.network").exists()
        for path in ("/usr/lib/systemd/network", "/lib/systemd/network", "/etc/systemd/network")
    )


def ensure_networkd(config: MkosiConfig) -> bool:
    networkd_is_running = run(["systemctl", "is-active", "--quiet", "systemd-networkd"], check=False).returncode == 0
    if not networkd_is_running:
        if config.verb != Verb.ssh:
            # Some programs will use 'mkosi ssh' with pexpect, so don't print warnings that will break
            # them.
            warn("--netdev requires systemd-networkd to be running to initialize the host interface "
                 "of the virtual link ('systemctl enable --now systemd-networkd')")
        return False

    if config.verb == Verb.qemu and not has_networkd_vm_vt():
        warn(dedent(r"""\
            mkosi didn't find 80-vm-vt.network. This is one of systemd's built-in
            systemd-networkd config files which configures vt-* interfaces.
            mkosi needs this file in order for --netdev to work properly for QEMU
            virtual machines. The file likely cannot be found because the systemd version
            on the host is too old (< 246) and it isn't included yet.

            As a workaround until the file is shipped by the systemd package of your distro,
            add a network file /etc/systemd/network/80-vm-vt.network with the following
            contents:

            [Match]
            Name=vt-*
            Driver=tun

            [Network]
            # Default to using a /28 prefix, giving up to 13 addresses per VM.
            Address=0.0.0.0/28
            LinkLocalAddressing=yes
            DHCPServer=yes
            IPMasquerade=yes
            LLDP=yes
            EmitLLDP=customer-bridge
            IPv6PrefixDelegation=yes
            """
        ))
        return False

    return True


def run_shell(config: MkosiConfig) -> None:
    if config.output_format in (OutputFormat.directory, OutputFormat.subvolume):
        target = f"--directory={config.output}"
    else:
        target = f"--image={config.output}"

    cmdline = ["systemd-nspawn", "--quiet", target]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings is not None:
        cmdline += ["--settings=trusted"]

    if config.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += nspawn_rlimit_params()

        # Redirecting output correctly when not running directly from the terminal.
        console_arg = f"--console={'interactive' if sys.stdout.isatty() else 'pipe'}"
        if nspawn_knows_arg(console_arg):
            cmdline += [console_arg]

    if config.netdev:
        if ensure_networkd(config):
            cmdline += ["--network-veth"]

    if config.ephemeral:
        cmdline += ["--ephemeral"]

    cmdline += ["--machine", machine_name(config)]

    if config.nspawn_keep_unit:
        cmdline += ["--keep-unit"]

    if config.source_file_transfer_final == SourceFileTransfer.mount:
        cmdline += [f"--bind={config.build_sources}:/root/src", "--chdir=/root/src"]

    for k, v in config.credentials.items():
        cmdline += [f"--set-credential={k}:{v}"]

    if config.verb == Verb.boot:
        # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
        cmdline += config.cmdline
        # kernel cmdline config of the form systemd.xxx= get interpreted by systemd when running in nspawn as
        # well.
        cmdline += config.kernel_command_line
    elif config.cmdline:
        cmdline += ["--"]
        cmdline += config.cmdline

    run(cmdline)


def find_qemu_binary(config: MkosiConfig) -> str:
    binaries = ["qemu", "qemu-kvm", f"qemu-system-{config.architecture}"]
    for binary in binaries:
        if shutil.which(binary) is not None:
            return binary

    die("Couldn't find QEMU/KVM binary")


def find_qemu_firmware(config: MkosiConfig) -> tuple[Path, bool]:
    FIRMWARE_LOCATIONS = {
        "x86_64": ["/usr/share/ovmf/x64/OVMF_CODE.secboot.fd"],
        "i386": [
            "/usr/share/edk2/ovmf-ia32/OVMF_CODE.secboot.fd",
            "/usr/share/OVMF/OVMF32_CODE_4M.secboot.fd"
        ],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = {
        "x86_64": [
            "/usr/share/ovmf/ovmf_code_x64.bin",
            "/usr/share/ovmf/x64/OVMF_CODE.fd",
            "/usr/share/qemu/ovmf-x86_64.bin",
        ],
        "i386": ["/usr/share/ovmf/ovmf_code_ia32.bin", "/usr/share/edk2/ovmf-ia32/OVMF_CODE.fd"],
        "aarch64": ["/usr/share/AAVMF/AAVMF_CODE.fd"],
        "armhfp": ["/usr/share/AAVMF/AAVMF32_CODE.fd"],
    }.get(config.architecture, [])

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            warn("Couldn't find OVMF firmware blob with secure boot support, "
                 "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    # If we can't find an architecture specific path, fall back to some generic paths that might also work.

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.secboot.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.secboot.fd",
        "/usr/share/ovmf/OVMF.secboot.fd",
        "/usr/share/OVMF/OVMF_CODE.secboot.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            return Path(firmware), True

    FIRMWARE_LOCATIONS = [
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.fd",  # GENTOO:
        "/usr/share/qemu/OVMF_CODE.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ]

    for firmware in FIRMWARE_LOCATIONS:
        if os.path.exists(firmware):
            warn("Couldn't find OVMF firmware blob with secure boot support, "
                 "falling back to OVMF firmware blobs without secure boot support.")
            return Path(firmware), False

    die("Couldn't find OVMF UEFI firmware blob.")


def find_ovmf_vars(config: MkosiConfig) -> Path:
    OVMF_VARS_LOCATIONS = []

    if config.architecture == "x86_64":
        OVMF_VARS_LOCATIONS += ["/usr/share/ovmf/x64/OVMF_VARS.fd"]
    elif config.architecture == "i386":
        OVMF_VARS_LOCATIONS += [
            "/usr/share/edk2/ovmf-ia32/OVMF_VARS.fd",
            "/usr/share/OVMF/OVMF32_VARS_4M.fd",
        ]
    elif config.architecture == "armhfp":
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF32_VARS.fd"]
    elif config.architecture == "aarch64":
        OVMF_VARS_LOCATIONS += ["/usr/share/AAVMF/AAVMF_VARS.fd"]

    OVMF_VARS_LOCATIONS += ["/usr/share/edk2/ovmf/OVMF_VARS.fd",
                            "/usr/share/edk2-ovmf/OVMF_VARS.fd",  # GENTOO:
                            "/usr/share/qemu/OVMF_VARS.fd",
                            "/usr/share/ovmf/OVMF_VARS.fd",
                            "/usr/share/OVMF/OVMF_VARS.fd"]

    for location in OVMF_VARS_LOCATIONS:
        if os.path.exists(location):
            return Path(location)

    die("Couldn't find OVMF UEFI variables file.")


def qemu_check_kvm_support() -> bool:
    kvm = Path("/dev/kvm")
    if not kvm.is_char_device():
        return False
    # some CI runners may present a non-working KVM device
    try:
        with kvm.open("r+b"):
            return True
    except OSError:
        return False


@contextlib.contextmanager
def start_swtpm() -> Iterator[Optional[Path]]:

    if not shutil.which("swtpm"):
        MkosiPrinter.info("Couldn't find swtpm binary, not invoking qemu with TPM2 device.")
        yield None
        return

    with tempfile.TemporaryDirectory() as swtpm_state:
        swtpm_sock = Path(swtpm_state) / Path("sock")

        cmd = ["swtpm",
               "socket",
               "--tpm2",
               "--tpmstate", f"dir={swtpm_state}",
               "--ctrl", f"type=unixio,path={swtpm_sock}",
         ]

        swtpm_proc = spawn(cmd)

        try:
            yield swtpm_sock
        finally:
            swtpm_proc.wait()


def run_qemu(config: MkosiConfig) -> None:
    accel = "kvm" if config.qemu_kvm else "tcg"

    firmware, fw_supports_sb = find_qemu_firmware(config)
    smm = "on" if fw_supports_sb else "off"

    if config.architecture == "aarch64":
        machine = f"type=virt,accel={accel}"
    else:
        machine = f"type=q35,accel={accel},smm={smm}"

    cmdline: list[PathString] = [
        find_qemu_binary(config),
        "-machine",
        machine,
        "-smp",
        config.qemu_smp,
        "-m",
        config.qemu_mem,
        "-object",
        "rng-random,filename=/dev/urandom,id=rng0",
        "-device",
        "virtio-rng-pci,rng=rng0,id=rng-device0",
    ]

    cmdline += ["-cpu", "max"]

    if config.qemu_headless:
        # -nodefaults removes the default CDROM device which avoids an error message during boot
        # -serial mon:stdio adds back the serial device removed by -nodefaults.
        cmdline += ["-nographic", "-nodefaults", "-serial", "mon:stdio"]
    else:
        cmdline += ["-vga", "virtio"]

    if config.netdev:
        if not ensure_networkd(config) or os.getuid() != 0:
            # Fall back to usermode networking if the host doesn't have networkd (eg: Debian).
            # Also fall back if running as an unprivileged user, which likely can't set up the tap interface.
            fwd = f",hostfwd=tcp::{config.ssh_port}-:{config.ssh_port}" if config.ssh_port != 22 else ""
            cmdline += ["-nic", f"user,model=virtio-net-pci{fwd}"]
        else:
            # Use vt- prefix so we can take advantage of systemd-networkd's builtin network file for VMs.
            ifname = f"vt-{interface_name(config)}"
            # vt-<image-name> is the ifname on the host and is automatically picked up by systemd-networkd which
            # starts a DHCP server on that interface. This gives IP connectivity to the VM. By default, QEMU
            # itself tries to bring up the vt network interface which conflicts with systemd-networkd which is
            # trying to do the same. By specifiying script=no and downscript=no, We tell QEMU to not touch vt
            # after it is created.
            cmdline += ["-nic", f"tap,script=no,downscript=no,ifname={ifname},model=virtio-net-pci"]

    cmdline += ["-drive", f"if=pflash,format=raw,readonly=on,file={firmware}"]

    for k, v in config.credentials.items():
        cmdline += ["-smbios", f"type=11,value=io.systemd.credential:{k}={v}"]

    with contextlib.ExitStack() as stack:
        if fw_supports_sb:
            ovmf_vars = stack.enter_context(copy_file_temporary(src=find_ovmf_vars(config), dir=tmp_dir()))
            cmdline += [
                "-global",
                "ICH9-LPC.disable_s3=1",
                "-global",
                "driver=cfi.pflash01,property=secure,value=on",
                "-drive",
                f"file={ovmf_vars.name},if=pflash,format=raw",
            ]

        if config.ephemeral:
            f = stack.enter_context(copy_image_temporary(src=config.output, dir=config.output.parent))
            fname = Path(f.name)
        else:
            fname = config.output

        # Debian images fail to boot with virtio-scsi, see: https://github.com/systemd/mkosi/issues/725
        if config.distribution == Distribution.debian:
            cmdline += [
                "-drive",
                f"if=virtio,id=hd,file={fname},format={'qcow2' if config.qcow2 else 'raw'}",
            ]
        else:
            cmdline += [
                "-drive",
                f"if=none,id=hd,file={fname},format={'qcow2' if config.qcow2 else 'raw'}",
                "-device",
                "virtio-scsi-pci,id=scsi",
                "-device",
                "scsi-hd,drive=hd,bootindex=1",
            ]

        swtpm_socket = stack.enter_context(start_swtpm())
        if swtpm_socket is not None:
            cmdline += [
                "-chardev", f"socket,id=chrtpm,path={swtpm_socket}",
                "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            ]

            if config.architecture == "x86_64":
                cmdline += ["-device", "tpm-tis,tpmdev=tpm0"]
            elif config.architecture == "aarch64":
                cmdline += ["-device", "tpm-tis-device,tpmdev=tpm0"]

        cmdline += config.qemu_args
        cmdline += config.cmdline

        print_running_cmd(cmdline)
        run(cmdline)


def interface_exists(dev: str) -> bool:
    rc = run(["ip", "link", "show", dev],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode
    return rc == 0


def find_address(config: MkosiConfig) -> tuple[str, str]:
    if not ensure_networkd(config) and config.ssh_port != 22:
        return "", "127.0.0.1"

    name = interface_name(config)
    timeout = float(config.ssh_timeout)

    while timeout >= 0:
        stime = time.time()
        try:
            if interface_exists(f"ve-{name}"):
                dev = f"ve-{name}"
            elif interface_exists(f"vt-{name}"):
                dev = f"vt-{name}"
            else:
                die(f"Container/VM interface ve-{name}/vt-{name} not found")

            link = json.loads(run(["ip", "-j", "link", "show", "dev", dev],
                                  stdout=subprocess.PIPE, text=True).stdout)[0]
            if link["operstate"] == "DOWN":
                raise MkosiException(
                    f"{dev} is not enabled. Make sure systemd-networkd is running so it can manage the interface."
                )

            # Trigger IPv6 neighbor discovery of which we can access the results via 'ip neighbor'. This allows us to
            # find out the link-local IPv6 address of the container/VM via which we can connect to it.
            run(["ping", "-c", "1", "-w", "15", f"ff02::1%{dev}"], stdout=subprocess.DEVNULL)

            for _ in range(50):
                neighbors = json.loads(
                    run(["ip", "-j", "neighbor", "show", "dev", dev], stdout=subprocess.PIPE, text=True).stdout
                )

                for neighbor in neighbors:
                    dst = cast(str, neighbor["dst"])
                    if dst.startswith("fe80"):
                        return f"%{dev}", dst

                time.sleep(0.4)
        except MkosiException as e:
            if time.time() - stime > timeout:
                die(str(e))

        time.sleep(1)
        timeout -= time.time() - stime

    die("Container/VM address not found")


def run_ssh(config: MkosiConfig) -> None:
    cmd = [
            "ssh",
            # Silence known hosts file errors/warnings.
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=no",
            "-o", "LogLevel=ERROR",
        ]

    if config.ssh_agent is None:
        ssh_key = config.ssh_key or config.output_sshkey
        assert ssh_key is not None

        if not ssh_key.exists():
            die(
                f"SSH key not found at {ssh_key}. Are you running from the project's root directory "
                "and did you build with the --ssh option?"
            )

        cmd += ["-i", cast(str, ssh_key)]
    else:
        cmd += ["-o", f"IdentityAgent={config.ssh_agent}"]

    if config.ssh_port != 22:
        cmd += ["-p", f"{config.ssh_port}"]

    dev, address = find_address(config)
    cmd += [f"root@{address}{dev}"]
    cmd += config.cmdline

    run(cmd)


def run_serve(config: MkosiConfig) -> None:
    """Serve the output directory via a tiny embedded HTTP server"""

    port = 8081

    if config.output_dir is not None:
        os.chdir(config.output_dir)

    with http.server.HTTPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Serving HTTP on port {port}: http://localhost:{port}/")
        httpd.serve_forever()


def generate_secure_boot_key(config: MkosiConfig) -> None:
    """Generate secure boot keys using openssl"""

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(config.secure_boot_valid_days))
    cn = expand_specifier(config.secure_boot_common_name)

    for f in (config.secure_boot_key, config.secure_boot_certificate):
        if f.exists() and not config.force:
            die(
                dedent(
                    f"""\
                    {f} already exists.
                    If you are sure you want to generate new secure boot keys
                    remove {config.secure_boot_key} and {config.secure_boot_certificate} first.
                    """
                )
            )

    MkosiPrinter.print_step(f"Generating secure boot keys rsa:{keylength} for CN {cn!r}.")
    MkosiPrinter.info(
        dedent(
            f"""
            The keys will expire in {config.secure_boot_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    cmd: list[PathString] = [
        "openssl",
        "req",
        "-new",
        "-x509",
        "-newkey",
        f"rsa:{keylength}",
        "-keyout",
        config.secure_boot_key,
        "-out",
        config.secure_boot_certificate,
        "-days",
        str(config.secure_boot_valid_days),
        "-subj",
        f"/CN={cn}/",
        "-nodes",
    ]
    run(cmd)


def bump_image_version(config: MkosiConfig) -> None:
    """Write current image version plus one to mkosi.version"""

    if config.image_version is None or config.image_version == "":
        print("No version configured so far, starting with version 1.")
        new_version = "1"
    else:
        v = config.image_version.split(".")

        try:
            m = int(v[-1])
        except ValueError:
            new_version = config.image_version + ".2"
            print(
                f"Last component of current version is not a decimal integer, appending '.2', bumping '{config.image_version}' → '{new_version}'."
            )
        else:
            new_version = ".".join(v[:-1] + [str(m + 1)])
            print(f"Increasing last component of version by one, bumping '{config.image_version}' → '{new_version}'.")

    Path("mkosi.version").write_text(new_version + "\n")


def expand_paths(paths: Sequence[str]) -> list[Path]:
    if not paths:
        return []

    environ = os.environ.copy()
    # Add a fake SUDO_HOME variable to allow non-root users specify
    # paths in their home when using mkosi via sudo.
    sudo_user = os.getenv("SUDO_USER")
    if sudo_user and "SUDO_HOME" not in environ:
        environ["SUDO_HOME"] = os.path.expanduser(f"~{sudo_user}")

    # No os.path.expandvars because it treats unset variables as empty.
    expanded = []
    for path in paths:
        try:
            expanded += [Path(string.Template(path).substitute(environ))]
        except KeyError:
            # Skip path if it uses a variable not defined.
            pass
    return expanded


@contextlib.contextmanager
def prepend_to_environ_path(paths: Sequence[Path]) -> Iterator[None]:
    if not paths:
        yield
        return

    with tempfile.TemporaryDirectory(prefix="mkosi.path", dir=tmp_dir()) as d:

        for path in paths:
            if not path.is_dir():
                Path(d).joinpath(path.name).symlink_to(path.absolute())

        paths = [Path(d), *paths]

        news = [os.fspath(path) for path in paths if path.is_dir()]
        olds = os.getenv("PATH", "").split(":")
        os.environ["PATH"] = ":".join(news + olds)

        yield


def expand_specifier(s: str) -> str:
    user = os.getenv("SUDO_USER") or os.getenv("USER")
    assert user is not None
    return s.replace("%u", user)


def needs_build(config: Union[argparse.Namespace, MkosiConfig]) -> bool:
    return config.verb == Verb.build or (config.verb in MKOSI_COMMANDS_NEED_BUILD and (not config.output.exists() or config.force > 0))


def run_verb(raw: argparse.Namespace) -> None:
    config: MkosiConfig = load_args(raw)

    with prepend_to_environ_path(config.extra_search_paths):
        if config.verb == Verb.genkey:
            return generate_secure_boot_key(config)

        if config.verb == Verb.bump:
            bump_image_version(config)

        if config.verb in MKOSI_COMMANDS_SUDO:
            check_root()

        if config.verb == Verb.build:
            check_inputs(config)

            if not config.force:
                check_outputs(config)

        if needs_build(config) or config.verb == Verb.clean:
            check_root()
            unlink_output(config)

        if config.verb == Verb.summary:
            print_summary(config)

        if needs_build(config):
            check_native(config)
            init_namespace()
            build_stuff(config)

            if config.auto_bump:
                bump_image_version(config)

            print_output_size(config)

        with suppress_stacktrace():
            if config.verb in (Verb.shell, Verb.boot):
                run_shell(config)

            if config.verb == Verb.qemu:
                run_qemu(config)

            if config.verb == Verb.ssh:
                run_ssh(config)

        if config.verb == Verb.serve:
            run_serve(config)
