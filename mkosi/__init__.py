# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import datetime
import errno
import hashlib
import http.server
import itertools
import json
import logging
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from textwrap import dedent
from typing import Callable, ContextManager, Optional, TextIO, Union, cast

from mkosi.btrfs import btrfs_maybe_snapshot_subvolume
from mkosi.config import (
    ConfigFeature,
    GenericVersion,
    MkosiArgs,
    MkosiConfig,
    MkosiConfigParser,
    SecureBootSignTool,
)
from mkosi.install import add_dropin_config_from_resource, copy_path, flock
from mkosi.log import Style, color_error, complete_step, die, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import mount_overlay, scandir_recursive
from mkosi.pager import page
from mkosi.qemu import copy_ephemeral, machine_cid, run_qemu
from mkosi.remove import unlink_try_hard
from mkosi.run import (
    become_root,
    bwrap,
    bwrap_cmd,
    fork_and_wait,
    run,
    run_workspace_command,
    spawn,
)
from mkosi.state import MkosiState
from mkosi.types import PathString
from mkosi.util import (
    Compression,
    InvokingUser,
    ManifestFormat,
    OutputFormat,
    Verb,
    flatten,
    format_bytes,
    format_rlimit,
    is_apt_distribution,
    is_portage_distribution,
    prepend_to_environ_path,
)

MKOSI_COMMANDS_NEED_BUILD = (Verb.build, Verb.shell, Verb.boot, Verb.qemu, Verb.serve)
MKOSI_COMMANDS_SUDO = (Verb.shell, Verb.boot)


@contextlib.contextmanager
def mount_image(state: MkosiState) -> Iterator[None]:
    with complete_step("Mounting image…", "Unmounting image…"), contextlib.ExitStack() as stack:

        if state.config.base_trees and state.config.overlay:
            bases = []
            state.workspace.joinpath("bases").mkdir(exist_ok=True)

            for path in state.config.base_trees:
                d = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=state.workspace / "bases", prefix=path.name)))
                d.rmdir() # We need the random name, but we want to create the directory ourselves

                if path.is_dir():
                    bases += [path]
                elif path.suffix == ".tar":
                    shutil.unpack_archive(path, d)
                    bases += [d]
                elif path.suffix == ".raw":
                    # We want to use bwrap() here but it doesn't propagate mounts so we use run() instead.
                    run(["systemd-dissect", "-M", path, d])
                    stack.callback(lambda: run(["systemd-dissect", "-U", d]))
                    bases += [d]
                else:
                    die(f"Unsupported base tree source {path}")

            stack.enter_context(mount_overlay(bases, state.root, state.root, read_only=False))

        yield


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

    if state.config.clean_package_metadata == ConfigFeature.disabled:
        return

    # we try then all: metadata will only be touched if any of them are in the
    # final image
    always = state.config.clean_package_metadata == ConfigFeature.enabled
    clean_dnf_metadata(state.root, always=always)
    clean_yum_metadata(state.root, always=always)
    clean_rpm_metadata(state.root, always=always)
    clean_apt_metadata(state.root, always=always)
    clean_dpkg_metadata(state.root, always=always)
    clean_pacman_metadata(state.root, always=always)


def remove_files(state: MkosiState) -> None:
    """Remove files based on user-specified patterns"""

    if not state.config.remove_files:
        return

    with complete_step("Removing files…"):
        for pattern in state.config.remove_files:
            for p in state.root.glob(pattern.lstrip("/")):
                unlink_try_hard(p)


def install_distribution(state: MkosiState) -> None:
    if state.config.base_trees:
        if not state.config.packages:
            return

        with complete_step(f"Installing extra packages for {str(state.config.distribution).capitalize()}"):
            state.installer.install_packages(state, state.config.packages)
    else:
        with complete_step(f"Installing {str(state.config.distribution).capitalize()}"):
            state.installer.install(state)

            # Ensure /efi exists so that the ESP is mounted there, as recommended by
            # https://0pointer.net/blog/linux-boot-partitions.html. Use the most restrictive access mode we
            # can without tripping up mkfs tools since this directory is only meant to be overmounted and
            # should not be read from or written to.
            state.root.joinpath("efi").mkdir(mode=0o500, exist_ok=True)

            if state.config.packages:
                state.installer.install_packages(state, state.config.packages)


def install_build_packages(state: MkosiState) -> None:
    if not need_build_packages(state.config):
        return

    with complete_step(f"Installing build packages for {str(state.config.distribution).capitalize()}"), mount_build_overlay(state):
        state.installer.install_packages(state, state.config.build_packages)


def remove_packages(state: MkosiState) -> None:
    """Remove packages listed in config.remove_packages"""

    if not state.config.remove_packages:
        return

    with complete_step(f"Removing {len(state.config.packages)} packages…"):
        try:
            state.installer.remove_packages(state, state.config.remove_packages)
        except NotImplementedError:
            die(f"Removing packages is not supported for {state.config.distribution}")


def configure_autologin(state: MkosiState) -> None:
    if not state.config.autologin:
        return

    with complete_step("Setting up autologin…"):
        add_dropin_config_from_resource(state.root, "console-getty.service", "autologin",
                                        "mkosi.resources", "console_getty_autologin.conf")
        add_dropin_config_from_resource(state.root, "serial-getty@ttyS0.service", "autologin",
                                        "mkosi.resources", "serial_getty_autologin.conf")
        add_dropin_config_from_resource(state.root, "getty@tty1.service", "autologin",
                                        "mkosi.resources", "getty_autologin.conf")



@contextlib.contextmanager
def mount_cache_overlay(state: MkosiState) -> Iterator[None]:
    if not state.config.incremental or not any(state.root.iterdir()):
        yield
        return

    d = state.workspace / "cache-overlay"
    d.mkdir(mode=0o755, exist_ok=True)

    with mount_overlay([state.root], d, state.root, read_only=False):
        yield


def mount_build_overlay(state: MkosiState, read_only: bool = False) -> ContextManager[Path]:
    d = state.workspace / "build-overlay"
    if not d.is_symlink():
        d.mkdir(mode=0o755, exist_ok=True)
    return mount_overlay([state.root], state.workspace / "build-overlay", state.root, read_only)


def finalize_sources(config: MkosiConfig) -> list[tuple[Path, Path]]:
    sources = [
        (src, Path("work/src") / (str(target).lstrip("/") if target else "."))
        for src, target
        in config.build_sources
    ]

    return sorted(sources, key=lambda s: s[1])


def run_prepare_script(state: MkosiState, build: bool) -> None:
    if state.config.prepare_script is None:
        return
    if build and state.config.build_script is None:
        return

    bwrap: list[PathString] = [
        "--bind", state.config.prepare_script, "/work/prepare",
        "--chdir", "/work/src",
    ]

    for src, target in finalize_sources(state.config):
        bwrap += ["--bind", src, Path("/") / target]

    if build:
        with complete_step("Running prepare script in build overlay…"), mount_build_overlay(state):
            run_workspace_command(
                state.root,
                ["/work/prepare", "build"],
                network=True,
                bwrap_params=bwrap,
                env=dict(SRCDIR="/work/src") | state.environment,
            )
            shutil.rmtree(state.root / "work")
    else:
        with complete_step("Running prepare script…"):
            run_workspace_command(
                state.root,
                ["/work/prepare", "final"],
                network=True,
                bwrap_params=bwrap,
                env=dict(SRCDIR="/work/src") | state.environment,
            )
            shutil.rmtree(state.root / "work")


def run_postinst_script(state: MkosiState) -> None:
    if state.config.postinst_script is None:
        return

    with complete_step("Running postinstall script…"):
        bwrap: list[PathString] = [
            "--bind", state.config.postinst_script, "/work/postinst",
        ]

        run_workspace_command(state.root, ["/work/postinst", "final"], bwrap_params=bwrap,
                              network=state.config.with_network, env=state.environment)

        shutil.rmtree(state.root / "work")


def run_finalize_script(state: MkosiState) -> None:
    if state.config.finalize_script is None:
        return

    with complete_step("Running finalize script…"):
        bwrap([state.config.finalize_script],
              tools=state.config.tools_tree,
              env={**state.environment, "BUILDROOT": str(state.root), "OUTPUTDIR": str(state.staging)})


def certificate_common_name(state: MkosiState, certificate: Path) -> str:
    output = bwrap([
        "openssl",
        "x509",
        "-noout",
        "-subject",
        "-nameopt", "multiline",
        "-in", certificate,
    ], tools=state.config.tools_tree, stdout=subprocess.PIPE).stdout

    for line in output.splitlines():
        if not line.strip().startswith("commonName"):
            continue

        _, sep, value = line.partition("=")
        if not sep:
            die("Missing '=' delimiter in openssl output")

        return cast(str, value.strip())

    die(f"Certificate {certificate} is missing Common Name")


def pesign_prepare(state: MkosiState) -> None:
    assert state.config.secure_boot_key
    assert state.config.secure_boot_certificate

    if (state.workspace / "pesign").exists():
        return

    (state.workspace / "pesign").mkdir()

    # pesign takes a certificate directory and a certificate common name as input arguments, so we have
    # to transform our input key and cert into that format. Adapted from
    # https://www.mankier.com/1/pesign#Examples-Signing_with_the_certificate_and_private_key_in_individual_files
    bwrap(["openssl",
           "pkcs12",
           "-export",
           # Arcane incantation to create a pkcs12 certificate without a password.
           "-keypbe", "NONE",
           "-certpbe", "NONE",
           "-nomaciter",
           "-passout", "pass:",
           "-out", state.workspace / "secure-boot.p12",
           "-inkey", state.config.secure_boot_key,
           "-in", state.config.secure_boot_certificate],
          tools=state.config.tools_tree)

    bwrap(["pk12util",
           "-K", "",
           "-W", "",
           "-i", state.workspace / "secure-boot.p12",
           "-d", state.workspace / "pesign"],
          tools=state.config.tools_tree)


def install_boot_loader(state: MkosiState) -> None:
    if state.config.bootable == ConfigFeature.disabled:
        return

    if state.config.output_format == OutputFormat.cpio and state.config.bootable == ConfigFeature.auto:
        return

    if not any(gen_kernel_images(state)) and state.config.bootable == ConfigFeature.auto:
        return

    if not shutil.which("bootctl"):
        if state.config.bootable == ConfigFeature.enabled:
            die("A bootable image was requested but bootctl was not found")
        return

    directory = state.root / "usr/lib/systemd/boot/efi"
    if not directory.exists() or not any(directory.iterdir()):
        if state.config.bootable == ConfigFeature.enabled:
            die("A bootable image was requested but systemd-boot was not found at "
                f"{directory.relative_to(state.root)}")
        return

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        with complete_step("Signing systemd-boot binaries…"):
            for input in itertools.chain(directory.glob('*.efi'), directory.glob('*.EFI')):
                output = directory / f"{input}.signed"

                if (state.config.secure_boot_sign_tool == SecureBootSignTool.sbsign or
                    state.config.secure_boot_sign_tool == SecureBootSignTool.auto and
                    shutil.which("sbsign") is not None):
                    bwrap(["sbsign",
                           "--key", state.config.secure_boot_key,
                           "--cert", state.config.secure_boot_certificate,
                           "--output", output,
                           input],
                          tools=state.config.tools_tree)
                elif (state.config.secure_boot_sign_tool == SecureBootSignTool.pesign or
                      state.config.secure_boot_sign_tool == SecureBootSignTool.auto and
                      shutil.which("pesign") is not None):
                    pesign_prepare(state)
                    bwrap(["pesign",
                           "--certdir", state.workspace / "pesign",
                           "--certificate", certificate_common_name(state, state.config.secure_boot_certificate),
                           "--sign",
                           "--force",
                           "--in", input,
                           "--out", output],
                          tools=state.config.tools_tree)
                else:
                    die("One of sbsign or pesign is required to use SecureBoot=")

    with complete_step("Installing boot loader…"):
        bwrap(["bootctl", "install", "--root", state.root, "--all-architectures"],
              env={"SYSTEMD_ESP_PATH": "/efi"}, tools=state.config.tools_tree)

    if state.config.secure_boot:
        assert state.config.secure_boot_key
        assert state.config.secure_boot_certificate

        with complete_step("Setting up secure boot auto-enrollment…"):
            keys = state.root / "efi/loader/keys/auto"
            keys.mkdir(parents=True, exist_ok=True)

            # sbsiglist expects a DER certificate.
            bwrap(["openssl",
                   "x509",
                   "-outform", "DER",
                   "-in", state.config.secure_boot_certificate,
                   "-out", state.workspace / "mkosi.der"],
                  tools=state.config.tools_tree)
            bwrap(["sbsiglist",
                   "--owner", str(uuid.uuid4()),
                   "--type", "x509",
                   "--output", state.workspace / "mkosi.esl",
                   state.workspace / "mkosi.der"],
                  tools=state.config.tools_tree)

            # We reuse the key for all secure boot databases to keep things simple.
            for db in ["PK", "KEK", "db"]:
                bwrap(["sbvarsign",
                       "--attr",
                           "NON_VOLATILE,BOOTSERVICE_ACCESS,RUNTIME_ACCESS,TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
                       "--key", state.config.secure_boot_key,
                       "--cert", state.config.secure_boot_certificate,
                       "--output", keys / f"{db}.auth",
                       db,
                       state.workspace / "mkosi.esl"],
                      tools=state.config.tools_tree)


def install_base_trees(state: MkosiState) -> None:
    if not state.config.base_trees or state.config.overlay:
        return

    with complete_step("Copying in base trees…"):
        for path in state.config.base_trees:
            if path.is_dir():
                btrfs_maybe_snapshot_subvolume(state.config, path, state.root)
            elif path.suffix == ".tar":
                shutil.unpack_archive(path, state.root)
            elif path.suffix == ".raw":
                bwrap(["systemd-dissect", "--copy-from", path, "/", state.root],
                      tools=state.config.tools_tree)
            else:
                die(f"Unsupported base tree source {path}")


def install_skeleton_trees(state: MkosiState) -> None:
    if not state.config.skeleton_trees:
        return

    with complete_step("Copying in skeleton file trees…"):
        for source, target in state.config.skeleton_trees:
            t = state.root
            if target:
                t = state.root / target.relative_to("/")

            t.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

            if source.is_dir() or target:
                copy_path(source, t, preserve_owner=False, tools=state.config.tools_tree)
            else:
                shutil.unpack_archive(source, t)


def install_package_manager_trees(state: MkosiState) -> None:
    if not state.config.package_manager_trees:
        return

    with complete_step("Copying in package maneger file trees…"):
        for source, target in state.config.package_manager_trees:
            t = state.workspace / "pkgmngr"
            if target:
                t = state.workspace / "pkgmngr" / target.relative_to("/")

            t.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

            if source.is_dir() or target:
                copy_path(source, t, preserve_owner=False, tools=state.config.tools_tree)
            else:
                shutil.unpack_archive(source, t)


def install_extra_trees(state: MkosiState) -> None:
    if not state.config.extra_trees:
        return

    with complete_step("Copying in extra file trees…"):
        for source, target in state.config.extra_trees:
            t = state.root
            if target:
                t = state.root / target.relative_to("/")

            t.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

            if source.is_dir() or target:
                copy_path(source, t, preserve_owner=False, tools=state.config.tools_tree)
            else:
                shutil.unpack_archive(source, t)


def install_build_dest(state: MkosiState) -> None:
    if state.config.build_script is None:
        return

    with complete_step("Copying in build tree…"):
        copy_path(state.install_dir, state.root, tools=state.config.tools_tree)


def gzip_binary() -> str:
    return "pigz" if shutil.which("pigz") else "gzip"


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
    if state.config.output_format != OutputFormat.tar:
        return

    cmd: list[PathString] = [
        tar_binary(),
        "-C", state.root,
        "-c", "--xattrs",
        "--xattrs-include=*",
        "--file", state.staging / state.config.output_with_format,
        *(["--xattrs-exclude=security.selinux"] if state.config.tar_strip_selinux_context else []),
        ".",
    ]

    with complete_step("Creating archive…"):
        bwrap(cmd, tools=state.config.tools_tree)


def find_files(dir: Path, root: Path) -> Iterator[Path]:
    """Generate a list of all filepaths in directory @dir relative to @root"""
    yield from scandir_recursive(dir,
                                 lambda entry: Path(entry.path).relative_to(root))


def make_initrd(state: MkosiState) -> None:
    if state.config.output_format != OutputFormat.cpio:
        return

    make_cpio(state, find_files(state.root, state.root), state.staging / state.config.output_with_format)


def make_cpio(state: MkosiState, files: Iterator[Path], output: Path) -> None:
    with complete_step(f"Creating cpio {output}…"), bwrap_cmd(tools=state.config.tools_tree) as bwrap:
        cmd: list[PathString] = [
            *bwrap,
            "cpio",
            "-o",
            "--reproducible",
            "--null",
            "-H", "newc",
            "--quiet",
            "-D", state.root,
            "-O", output
        ]

        with spawn(cmd, stdin=subprocess.PIPE, text=True) as cpio:
            #  https://github.com/python/mypy/issues/10583
            assert cpio.stdin is not None

            for file in files:
                cpio.stdin.write(os.fspath(file))
                cpio.stdin.write("\0")
            cpio.stdin.close()


def make_directory(state: MkosiState) -> None:
    if state.config.output_format != OutputFormat.directory:
        return

    state.root.rename(state.staging / state.config.output_with_format)


def gen_kernel_images(state: MkosiState) -> Iterator[tuple[str, Path]]:
    if not state.root.joinpath("usr/lib/modules").exists():
        return

    for kver in sorted(
        (k for k in state.root.joinpath("usr/lib/modules").iterdir() if k.is_dir()),
        key=lambda k: GenericVersion(k.name),
        reverse=True
    ):
        kimg = Path("usr/lib/modules") / kver.name / "vmlinuz"
        if not kimg.exists():
            kimg = state.installer.kernel_image(kver.name, state.config.architecture)

        yield kver.name, kimg


def filter_kernel_modules(root: Path, kver: str, include: Sequence[str], exclude: Sequence[str]) -> list[Path]:
    modulesd = Path("usr/lib/modules") / kver
    modules = set(m.relative_to(root) for m in (root / modulesd).glob("**/*.ko*"))

    keep = set()
    for pattern in include:
        regex = re.compile(pattern)
        for m in modules:
            rel = os.fspath(m.relative_to(modulesd / "kernel"))
            if regex.search(rel):
                logging.debug(f"Including module {rel}")
                keep.add(m)

    for pattern in exclude:
        regex = re.compile(pattern)
        remove = set()
        for m in modules:
            rel = os.fspath(m.relative_to(modulesd / "kernel"))
            if rel not in keep and regex.search(rel):
                logging.debug(f"Excluding module {rel}")
                remove.add(m)

        modules -= remove

    return sorted(modules)


def module_path_to_name(path: Path) -> str:
    return path.name.partition(".")[0]


def resolve_module_dependencies(state: MkosiState, kver: str, modules: Sequence[str]) -> tuple[set[Path], set[Path]]:
    """
    Returns a tuple of lists containing the paths to the module and firmware dependencies of the given list
    of module names (including the given module paths themselves). The paths are returned relative to the
    root directory.
    """
    modulesd = Path("usr/lib/modules") / kver
    builtin = set(module_path_to_name(Path(m)) for m in (state.root / modulesd / "modules.builtin").read_text().splitlines())
    allmodules = set((state.root / modulesd / "kernel").glob("**/*.ko*"))
    nametofile = {module_path_to_name(m): m.relative_to(state.root) for m in allmodules}

    # We could run modinfo once for each module but that's slow. Luckily we can pass multiple modules to
    # modinfo and it'll process them all in a single go. We get the modinfo for all modules to build two maps
    # that map the path of the module to its module dependencies and its firmware dependencies respectively.
    info = bwrap(["modinfo", "--basedir", state.root, "--set-version", kver, "--null", *nametofile.keys(), *builtin],
                 stdout=subprocess.PIPE, tools=state.config.tools_tree).stdout

    moddep = {}
    firmwaredep = {}

    depends = []
    firmware = []
    for line in info.split("\0"):
        key, sep, value = line.partition(":")
        if not sep:
            key, sep, value = line.partition("=")

        if key in ("depends", "softdep"):
            depends += [d for d in value.strip().split(",") if d]

        elif key == "firmware":
            firmware += [f.relative_to(state.root) for f in state.root.joinpath("usr/lib/firmware").glob(f"{value.strip()}*")]

        elif key == "name":
            name = value.strip()

            moddep[name] = depends
            firmwaredep[name] = firmware

            depends = []
            firmware = []

    todo = [*builtin, *modules]
    mods = set()
    firmware = set()

    while todo:
        m = todo.pop()
        if m in mods:
            continue

        depends = moddep.get(m, [])
        for d in depends:
            if d not in nametofile and d not in builtin:
                logging.warning(f"{d} is a dependency of {m} but is not installed, ignoring ")

        mods.add(m)
        todo += depends
        firmware.update(firmwaredep.get(m, []))

    return set(nametofile[m] for m in mods if m in nametofile), set(firmware)


def gen_kernel_modules_initrd(state: MkosiState, kver: str) -> Path:
    def files() -> Iterator[Path]:
        modulesd = Path("usr/lib/modules") / kver
        yield modulesd.parent
        yield modulesd
        yield modulesd / "kernel"

        for d in (modulesd, Path("usr/lib/firmware")):
            for p in (state.root / d).glob("**/*"):
                if p.is_dir():
                    yield p.relative_to(state.root)

        modules = filter_kernel_modules(state.root, kver,
                                        state.config.kernel_modules_initrd_include,
                                        state.config.kernel_modules_initrd_exclude)

        names = [module_path_to_name(m) for m in modules]
        mods, firmware = resolve_module_dependencies(state, kver, names)

        for p in sorted(mods) + sorted(firmware):
            yield p

        for p in (state.root / modulesd).iterdir():
            if not p.name.startswith("modules"):
                continue

            yield p.relative_to(state.root)

        if (state.root / modulesd / "vdso").exists():
            yield modulesd / "vdso"

            for p in (state.root / modulesd / "vdso").iterdir():
                yield p.relative_to(state.root)

    kmods = state.workspace / f"initramfs-kernel-modules-{kver}.img"

    with complete_step(f"Generating kernel modules initrd for kernel {kver}"):
        make_cpio(state, files(), kmods)

        # Debian/Ubuntu do not compress their kernel modules, so we compress the initramfs instead. Note that
        # this is not ideal since the compressed kernel modules will all be decompressed on boot which
        # requires significant memory.
        if is_apt_distribution(state.config.distribution):
            maybe_compress(state, Compression.zst, kmods, kmods)

    return kmods


def install_unified_kernel(state: MkosiState, roothash: Optional[str]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if state.config.bootable == ConfigFeature.disabled:
        return

    for kver, kimg in gen_kernel_images(state):
        shutil.copy(state.root / kimg, state.staging / state.config.output_split_kernel)
        break

    if state.config.output_format == OutputFormat.cpio and state.config.bootable == ConfigFeature.auto:
        return

    initrds = []

    if state.config.initrds:
        initrds = state.config.initrds
    elif any(gen_kernel_images(state)):
        # Default values are assigned via the parser so we go via the argument parser to construct
        # the config for the initrd.
        with complete_step("Building initrd"):
            password, hashed = state.config.root_password or (None, False)
            if password:
                rootpwopt = f"hashed:{password}" if hashed else password
            else:
                rootpwopt = None

            args, presets = MkosiConfigParser().parse([
                "--directory", "",
                "--distribution", str(state.config.distribution),
                "--release", state.config.release,
                "--architecture", str(state.config.architecture),
                *(["--mirror", state.config.mirror] if state.config.mirror else []),
                "--repository-key-check", yes_no(state.config.repository_key_check),
                "--repositories", ",".join(state.config.repositories),
                "--package-manager-tree", ",".join(format_source_target(s, t) for s, t in state.config.package_manager_trees),
                *(["--tools-tree", str(state.config.tools_tree)] if state.config.tools_tree else []),
                *(["--compress-output", str(state.config.compress_output)] if state.config.compress_output else []),
                "--with-network", yes_no(state.config.with_network),
                "--cache-only", yes_no(state.config.cache_only),
                *(["--output-dir", str(state.config.output_dir)] if state.config.output_dir else []),
                *(["--workspace-dir", str(state.config.workspace_dir)] if state.config.workspace_dir else []),
                "--cache-dir", str(state.cache_dir.parent),
                *(["--local-mirror", str(state.config.local_mirror)] if state.config.local_mirror else []),
                "--incremental", yes_no(state.config.incremental),
                "--acl", yes_no(state.config.acl),
                "--format", "cpio",
                "--package", "systemd",
                *(["--package", "udev"] if not is_portage_distribution(state.config.distribution) else []),
                "--package", "kmod",
                *(["--package", "dmsetup"] if is_apt_distribution(state.config.distribution) else []),
                "--output", f"{state.config.output}-initrd",
                *(["--image-version", state.config.image_version] if state.config.image_version else []),
                "--make-initrd", "yes",
                "--bootable", "no",
                "--manifest-format", "",
                *(["--locale", state.config.locale] if state.config.locale else []),
                *(["--locale-messages", state.config.locale_messages] if state.config.locale_messages else []),
                *(["--keymap", state.config.keymap] if state.config.keymap else []),
                *(["--timezone", state.config.timezone] if state.config.timezone else []),
                *(["--hostname", state.config.hostname] if state.config.hostname else []),
                *(["--root-password", rootpwopt] if rootpwopt else []),
                *(["-f"] * state.args.force),
                "build",
            ])

            config = presets[0]
            unlink_output(args, config)
            build_image(args, config, state.uid, state.gid)

            initrds = [config.output_dir / config.output]

    for kver, kimg in gen_kernel_images(state):
        with complete_step(f"Generating unified kernel image for {kimg}"):
            image_id = state.config.image_id or f"mkosi-{state.config.distribution}"

            # See https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/#boot-counting
            boot_count = ""
            if state.root.joinpath("etc/kernel/tries").exists():
                boot_count = f'+{state.root.joinpath("etc/kernel/tries").read_text().strip()}'

            if state.config.image_version:
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}_{state.config.image_version}-{kver}{boot_count}.efi"
            elif roothash:
                _, _, h = roothash.partition("=")
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}-{kver}-{h}{boot_count}.efi"
            else:
                boot_binary = state.root / f"efi/EFI/Linux/{image_id}-{kver}{boot_count}.efi"

            if state.root.joinpath("etc/kernel/cmdline").exists():
                cmdline = [state.root.joinpath("etc/kernel/cmdline").read_text().strip()]
            elif state.root.joinpath("usr/lib/kernel/cmdline").exists():
                cmdline = [state.root.joinpath("usr/lib/kernel/cmdline").read_text().strip()]
            else:
                cmdline = []

            cmdline += state.installer.kernel_command_line(state)

            if roothash:
                cmdline += [roothash]

            cmdline += state.config.kernel_command_line

            # Older versions of systemd-stub expect the cmdline section to be null terminated. We can't embed
            # nul terminators in argv so let's communicate the cmdline via a file instead.
            state.workspace.joinpath("cmdline").write_text(f"{' '.join(cmdline).strip()}\x00")

            stub = state.root / f"usr/lib/systemd/boot/efi/linux{state.config.architecture.to_efi()}.efi.stub"
            if not stub.exists():
                die(f"sd-stub not found at /{stub.relative_to(state.root)} in the image")

            cmd: list[PathString] = [
                shutil.which("ukify") or "/usr/lib/systemd/ukify",
                "--cmdline", f"@{state.workspace / 'cmdline'}",
                "--os-release", f"@{state.root / 'usr/lib/os-release'}",
                "--stub", stub,
                "--output", boot_binary,
                "--efi-arch", state.config.architecture.to_efi(),
            ]

            for p in state.config.extra_search_paths:
                cmd += ["--tools", p]

            uki_config = state.pkgmngr / "etc/kernel/uki.conf"
            if uki_config.exists():
                cmd += ["--config", uki_config]

            if state.config.secure_boot:
                assert state.config.secure_boot_key
                assert state.config.secure_boot_certificate

                cmd += ["--sign-kernel"]

                if state.config.secure_boot_sign_tool != SecureBootSignTool.pesign:
                    cmd += [
                        "--signtool", "sbsign",
                        "--secureboot-private-key", state.config.secure_boot_key,
                        "--secureboot-certificate", state.config.secure_boot_certificate,
                    ]
                else:
                    pesign_prepare(state)
                    cmd += [
                        "--signtool", "pesign",
                        "--secureboot-certificate-dir", state.workspace / "pesign",
                        "--secureboot-certificate-name", certificate_common_name(state, state.config.secure_boot_certificate),
                    ]

                sign_expected_pcr = (state.config.sign_expected_pcr == ConfigFeature.enabled or
                                    (state.config.sign_expected_pcr == ConfigFeature.auto and
                                     shutil.which("systemd-measure") is not None))

                if sign_expected_pcr:
                    cmd += [
                        "--pcr-private-key", state.config.secure_boot_key,
                        "--pcr-banks", "sha1,sha256",
                    ]

            cmd += [state.root / kimg] + initrds

            if state.config.kernel_modules_initrd:
                cmd += [gen_kernel_modules_initrd(state, kver)]

            bwrap(cmd, tools=state.config.tools_tree)

            if not state.staging.joinpath(state.config.output_split_uki).exists():
                shutil.copy(boot_binary, state.staging / state.config.output_split_uki)

            print_output_size(boot_binary)

    if state.config.bootable == ConfigFeature.enabled and not state.staging.joinpath(state.config.output_split_uki).exists():
        die("A bootable image was requested but no kernel was found")


def compressor_command(compression: Compression) -> list[PathString]:
    """Returns a command suitable for compressing archives."""

    if compression == Compression.gz:
        return [gzip_binary(), "--fast", "--stdout", "-"]
    elif compression == Compression.xz:
        return ["xz", "--check=crc32", "--fast", "-T0", "--stdout", "-"]
    elif compression == Compression.zst:
        return ["zstd", "-q", "-T0", "--stdout", "-"]
    else:
        die(f"Unknown compression {compression}")


def maybe_compress(state: MkosiState, compression: Compression, src: Path, dst: Optional[Path] = None) -> None:
    if not compression or src.is_dir():
        if dst:
            shutil.move(src, dst)
        return

    if not dst:
        dst = src.parent / f"{src.name}.{compression}"

    with complete_step(f"Compressing {src}"):
        with src.open("rb") as i:
            src.unlink() # if src == dst, make sure dst doesn't truncate the src file but creates a new file.

            with dst.open("wb") as o:
                bwrap(compressor_command(compression), stdin=i, stdout=o, tools=state.config.tools_tree)
                os.chown(dst, uid=state.uid, gid=state.gid)


def copy_nspawn_settings(state: MkosiState) -> None:
    if state.config.nspawn_settings is None:
        return None

    with complete_step("Copying nspawn settings file…"):
        shutil.copy(state.config.nspawn_settings, state.staging / state.config.output_nspawn_settings)


def hash_file(of: TextIO, path: Path) -> None:
    bs = 16 * 1024**2
    h = hashlib.sha256()

    with path.open("rb") as sf:
        while (buf := sf.read(bs)):
            h.update(buf)

    of.write(h.hexdigest() + " *" + path.name + "\n")


def calculate_sha256sum(state: MkosiState) -> None:
    if state.config.output_format == OutputFormat.directory:
        return None

    if not state.config.checksum:
        return None

    with complete_step("Calculating SHA256SUMS…"):
        with open(state.workspace / state.config.output_checksum, "w") as f:
            for p in state.staging.iterdir():
                hash_file(f, p)

        state.workspace.joinpath(state.config.output_checksum).rename(state.staging / state.config.output_checksum)


def calculate_signature(state: MkosiState) -> None:
    if not state.config.sign:
        return None

    with complete_step("Signing SHA256SUMS…"):
        cmdline: list[PathString] = ["gpg", "--detach-sign"]

        # Need to specify key before file to sign
        if state.config.key is not None:
            cmdline += ["--default-key", state.config.key]

        cmdline += [
            "--output", state.staging / state.config.output_signature,
            state.staging / state.config.output_checksum,
        ]

        bwrap(
            cmdline,
            # Do not output warnings about keyring permissions
            stderr=subprocess.DEVNULL,
            env={
                # Set the path of the keyring to use based on the environment
                # if possible and fallback to the default path. Without this the
                # keyring for the root user will instead be used which will fail
                # for a non-root build.
                'GNUPGHOME': os.environ.get(
                    'GNUPGHOME',
                    Path(os.environ['HOME']).joinpath('.gnupg')
                )
            },
            tools=state.config.tools_tree,
        )


def dir_size(path: Union[Path, os.DirEntry[str]]) -> int:
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
            dir_sum += dir_size(entry)
    return dir_sum


def save_manifest(state: MkosiState, manifest: Manifest) -> None:
    if manifest.has_data():
        if ManifestFormat.json in state.config.manifest_format:
            with complete_step(f"Saving manifest {state.config.output_manifest}"):
                with open(state.staging / state.config.output_manifest, 'w') as f:
                    manifest.write_json(f)

        if ManifestFormat.changelog in state.config.manifest_format:
            with complete_step(f"Saving report {state.config.output_changelog}"):
                with open(state.staging / state.config.output_changelog, 'w') as f:
                    manifest.write_package_report(f)


def print_output_size(path: Path) -> None:
    if path.is_dir():
        log_step(f"{path} size is " + format_bytes(dir_size(path)) + ".")
    else:
        size = format_bytes(path.stat().st_size)
        space = format_bytes(path.stat().st_blocks * 512)
        log_step(f"{path} size is {size}, consumes {space}.")


def empty_directory(path: Path) -> None:
    try:
        for f in os.listdir(path):
            unlink_try_hard(path / f)
    except FileNotFoundError:
        pass


def unlink_output(args: MkosiArgs, config: MkosiConfig) -> None:
    # We remove any cached images if either the user used --force twice, or he/she called "clean" with it
    # passed once. Let's also remove the downloaded package cache if the user specified one additional
    # "--force". Let's also remove all versions if the user specified one additional "--force".

    if args.verb == Verb.clean:
        remove_build_cache = args.force > 0
        remove_package_cache = args.force > 1
        prefix = config.output if args.force > 1 else config.output_with_version
    else:
        remove_build_cache = args.force > 1
        remove_package_cache = args.force > 2
        prefix = config.output if args.force > 2 else config.output_with_version

    with complete_step("Removing output files…"):
        if config.output_dir.exists():
            for p in config.output_dir.iterdir():
                if p.name.startswith(prefix):
                    unlink_try_hard(p)

    if remove_build_cache:
        if config.cache_dir:
            for p in cache_tree_paths(config):
                if p.exists():
                    with complete_step(f"Removing cache entry {p}…"):
                        unlink_try_hard(p)

        if config.build_dir and config.build_dir.exists() and any(config.build_dir.iterdir()):
            with complete_step("Clearing out build directory…"):
                empty_directory(config.build_dir)

    if remove_package_cache:
        if config.cache_dir and config.cache_dir.exists() and any(config.cache_dir.iterdir()):
            with complete_step("Clearing out package cache…"):
                empty_directory(config.cache_dir)


def cache_tree_paths(config: MkosiConfig) -> tuple[Path, Path, Path]:
    assert config.cache_dir
    return (
        config.cache_dir / f"{config.output}.cache",
        config.cache_dir / f"{config.output}.build.cache",
        config.cache_dir / f"{config.output}.manifest",
    )


def check_tree_input(path: Optional[Path]) -> None:
    # Each path may be a directory or a tarball.
    # Open the file or directory to simulate an access check.
    # If that fails, an exception will be thrown.
    if not path:
        return

    os.open(path, os.R_OK)


def check_source_target_input(tree: tuple[Path, Optional[Path]]) -> None:
    source, _ = tree
    os.open(source, os.R_OK)


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
        for base in config.base_trees:
            check_tree_input(base)

        check_tree_input(config.tools_tree)

        for tree in (config.skeleton_trees,
                     config.extra_trees):
            for item in tree:
                check_source_target_input(item)

        for path in (config.build_script,
                     config.prepare_script,
                     config.postinst_script,
                     config.finalize_script):
            check_script_input(path)

        if config.bootable != ConfigFeature.disabled:
            for p in config.initrds:
                if not p.exists():
                    die(f"Initrd {p} not found")
                if not p.is_file():
                    die(f"Initrd {p} is not a file")

    except OSError as e:
        die(f'{e.filename}: {e.strerror}')


def check_outputs(config: MkosiConfig) -> None:
    for f in (
        config.output_with_compression,
        config.output_checksum if config.checksum else None,
        config.output_signature if config.sign else None,
        config.output_nspawn_settings if config.nspawn_settings is not None else None,
    ):
        if f and config.output_dir.joinpath(f).exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def yes_no(b: bool) -> str:
    return "yes" if b else "no"


def yes_no_auto(f: ConfigFeature) -> str:
    return "auto" if f is ConfigFeature.auto else yes_no(f == ConfigFeature.enabled)


def none_to_na(s: Optional[object]) -> str:
    return "n/a" if s is None else str(s)


def none_to_none(s: Optional[object]) -> str:
    return "none" if s is None else str(s)


def none_to_default(s: Optional[object]) -> str:
    return "default" if s is None else str(s)


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
    return "\n                                ".join(items)


def format_source_target(source: Path, target: Optional[Path]) -> str:
    return f"{source}:{target}" if target else f"{source}"


def line_join_source_target_list(array: Sequence[tuple[Path, Optional[Path]]]) -> str:
    if not array:
        return "none"

    items = [format_source_target(source, target) for source, target in array]
    return "\n                                ".join(items)


def summary(args: MkosiArgs, config: MkosiConfig) -> str:
    b = Style.bold
    e = Style.reset
    bold: Callable[..., str] = lambda s: f"{b}{s}{e}"

    maniformats = (" ".join(i.name for i in config.manifest_format)) or "(none)"
    env = [f"{k}={v}" for k, v in config.environment.items()]

    summary = f"""\
{bold(f"PRESET: {config.preset or 'default'}")}

    {bold("COMMANDS")}:
                          verb: {bold(args.verb)}
                       cmdline: {bold(" ".join(args.cmdline))}

    {bold("DISTRIBUTION")}:
                  Distribution: {bold(config.distribution.name)}
                       Release: {bold(none_to_na(config.release))}
                  Architecture: {config.architecture}
                        Mirror: {none_to_default(config.mirror)}
          Local Mirror (build): {none_to_none(config.local_mirror)}
      Repo Signature/Key check: {yes_no(config.repository_key_check)}
                  Repositories: {",".join(config.repositories)}

    {bold("OUTPUT")}:
                      Image ID: {config.image_id}
                 Image Version: {config.image_version}
                 Output Format: {config.output_format.name}
              Manifest Formats: {maniformats}
              Output Directory: {none_to_default(config.output_dir)}
           Workspace Directory: {none_to_default(config.workspace_dir)}
               Cache Directory: {none_to_none(config.cache_dir)}
               Build Directory: {none_to_none(config.build_dir)}
            Repart Directories: {line_join_list(config.repart_dirs)}
                        Output: {bold(config.output_with_compression)}
               Output Checksum: {none_to_na(config.output_checksum if config.checksum else None)}
              Output Signature: {none_to_na(config.output_signature if config.sign else None)}
        Output nspawn Settings: {none_to_na(config.output_nspawn_settings if config.nspawn_settings is not None else None)}
                   Compression: {config.compress_output.name}

    {bold("CONTENT")}:
                      Packages: {line_join_list(config.packages)}
            With Documentation: {yes_no(config.with_docs)}
                Skeleton Trees: {line_join_source_target_list(config.skeleton_trees)}
         Package Manager Trees: {line_join_source_target_list(config.package_manager_trees)}
                   Extra Trees: {line_join_source_target_list(config.extra_trees)}
        Clean Package Metadata: {yes_no_auto(config.clean_package_metadata)}
                  Remove Files: {line_join_list(config.remove_files)}
               Remove Packages: {line_join_list(config.remove_packages)}
                 Build Sources: {line_join_source_target_list(config.build_sources)}
                Build Packages: {line_join_list(config.build_packages)}
                  Build Script: {path_or_none(config.build_script, check_script_input)}
     Run Tests in Build Script: {yes_no(config.with_tests)}
            Postinstall Script: {path_or_none(config.postinst_script, check_script_input)}
                Prepare Script: {path_or_none(config.prepare_script, check_script_input)}
               Finalize Script: {path_or_none(config.finalize_script, check_script_input)}
            Script Environment: {line_join_list(env)}
          Scripts with network: {yes_no(config.with_network)}
                      Bootable: {yes_no_auto(config.bootable)}
           Kernel Command Line: {" ".join(config.kernel_command_line)}
                       Initrds: {",".join(os.fspath(p) for p in config.initrds)}
                        Locale: {none_to_default(config.locale)}
               Locale Messages: {none_to_default(config.locale_messages)}
                        Keymap: {none_to_default(config.keymap)}
                      Timezone: {none_to_default(config.timezone)}
                      Hostname: {none_to_default(config.hostname)}
                 Root Password: {("(set)" if config.root_password else "(default)")}
                    Root Shell: {none_to_default(config.root_shell)}
                     Autologin: {yes_no(config.autologin)}

    {bold("HOST CONFIGURATION")}:
                   Incremental: {yes_no(config.incremental)}
               NSpawn Settings: {none_to_none(config.nspawn_settings)}
            Extra search paths: {line_join_list(config.extra_search_paths)}
          QEMU Extra Arguments: {line_join_list(config.qemu_args)}
     Extra Kernel Command Line: {line_join_list(config.kernel_command_line_extra)}
"""

    if config.output_format == OutputFormat.disk:
        summary += f"""\

    {bold("VALIDATION")}:
               UEFI SecureBoot: {yes_no(config.secure_boot)}
        SecureBoot Signing Key: {none_to_none(config.secure_boot_key)}
        SecureBoot Certificate: {none_to_none(config.secure_boot_certificate)}
          SecureBoot Sign Tool: {config.secure_boot_sign_tool}
            Verity Signing Key: {none_to_none(config.verity_key)}
            Verity Certificate: {none_to_none(config.verity_certificate)}
                      Checksum: {yes_no(config.checksum)}
                          Sign: {yes_no(config.sign)}
                       GPG Key: ({"default" if config.key is None else config.key})
"""

    return summary


def configure_ssh(state: MkosiState) -> None:
    if not state.config.ssh:
        return

    state.root.joinpath("usr/lib/systemd/system/ssh.socket").write_text(
        dedent(
            """\
            [Unit]
            Description=Mkosi SSH Server VSock Socket
            ConditionVirtualization=!container
            Wants=sshd-keygen.target

            [Socket]
            ListenStream=vsock::22
            Accept=yes

            [Install]
            WantedBy=sockets.target
            """
        )
    )

    state.root.joinpath("usr/lib/systemd/system/ssh@.service").write_text(
        dedent(
            """\
            [Unit]
            Description=Mkosi SSH Server
            After=sshd-keygen.target

            [Service]
            # We disable PAM because of an openssh-server bug where it sets PAM_RHOST=UNKNOWN when -i is used
            # causing a very slow reverse DNS lookup by pam.
            ExecStart=sshd -i -o UsePAM=no
            StandardInput=socket
            RuntimeDirectoryPreserve=yes
            # ssh always exits with 255 even on normal disconnect, so let's mark that as success so we don't
            # get noisy logs about SSH service failures.
            SuccessExitStatus=255
            """
        )
    )

    presetdir = state.root / "usr/lib/systemd/system-preset"
    presetdir.joinpath("80-mkosi-ssh.preset").write_text("enable ssh.socket\n")


def configure_initrd(state: MkosiState) -> None:
    if not state.root.joinpath("init").exists() and state.root.joinpath("usr/lib/systemd/systemd").exists():
        state.root.joinpath("init").symlink_to("/usr/lib/systemd/systemd")

    if not state.config.make_initrd:
        return

    if not state.root.joinpath("etc/initrd-release").exists():
        state.root.joinpath("etc/initrd-release").symlink_to("/etc/os-release")


def process_kernel_modules(state: MkosiState, kver: str) -> None:
    if not state.config.kernel_modules_include and not state.config.kernel_modules_exclude:
        return

    with complete_step("Applying kernel module filters"):
        modulesd = Path("usr/lib/modules") / kver
        modules = filter_kernel_modules(state.root, kver,
                                        state.config.kernel_modules_include,
                                        state.config.kernel_modules_exclude)

        names = [module_path_to_name(m) for m in modules]
        mods, firmware = resolve_module_dependencies(state, kver, names)

        allmodules = set(m.relative_to(state.root) for m in (state.root / modulesd).glob("**/*.ko*"))
        allfirmware = set(m.relative_to(state.root) for m in (state.root / "usr/lib/firmware").glob("**/*") if not m.is_dir())

        for m in allmodules:
            if m in mods:
                continue

            logging.debug(f"Removing module {m}")
            (state.root / m).unlink()

        for fw in allfirmware:
            if fw in firmware:
                continue

            logging.debug(f"Removing firmware {fw}")
            (state.root / fw).unlink()


def run_depmod(state: MkosiState) -> None:
    if state.config.bootable == ConfigFeature.disabled:
        return

    for kver, _ in gen_kernel_images(state):
        process_kernel_modules(state, kver)

        with complete_step(f"Running depmod for {kver}"):
            bwrap(["depmod", "--all", "--basedir", state.root, kver], tools=state.config.tools_tree)


def run_sysusers(state: MkosiState) -> None:
    with complete_step("Generating system users"):
        bwrap(["systemd-sysusers", "--root", state.root], tools=state.config.tools_tree)


def run_preset(state: MkosiState) -> None:
    with complete_step("Applying presets…"):
        bwrap(["systemctl", "--root", state.root, "preset-all"], tools=state.config.tools_tree)


def run_hwdb(state: MkosiState) -> None:
    with complete_step("Generating hardware database"):
        bwrap(["systemd-hwdb", "--root", state.root, "--usr", "--strict", "update"],
              tools=state.config.tools_tree)


def run_firstboot(state: MkosiState) -> None:
    password, hashed = state.config.root_password or (None, False)
    pwopt = "--root-password-hashed" if hashed else "--root-password"
    pwcred = "passwd.hashed-password.root" if hashed else "passwd.plaintext-password.root"

    settings = (
        ("--locale",          "firstboot.locale",          state.config.locale),
        ("--locale-messages", "firstboot.locale-messages", state.config.locale_messages),
        ("--keymap",          "firstboot.keymap",          state.config.keymap),
        ("--timezone",        "firstboot.timezone",        state.config.timezone),
        ("--hostname",        None,                        state.config.hostname),
        (pwopt,               pwcred,                      password),
        ("--root-shell",      "passwd.shell.root",         state.config.root_shell),
    )

    options = []
    creds = []

    for option, cred, value in settings:
        if not value:
            continue

        options += [option, value]

        if cred:
            creds += [(cred, value)]

    if not options and not creds:
        return

    with complete_step("Applying first boot settings"):
        bwrap(["systemd-firstboot", "--root", state.root, "--force", *options],
              tools=state.config.tools_tree)

        # Initrds generally don't ship with only /usr so there's not much point in putting the credentials in
        # /usr/lib/credstore.
        if state.config.output_format != OutputFormat.cpio or not state.config.make_initrd:
            (state.root / "usr/lib/credstore").mkdir(mode=0o755, exist_ok=True)

            for cred, value in creds:
                (state.root / "usr/lib/credstore" / cred).write_text(value)

                if "password" in cred:
                    (state.root / "usr/lib/credstore" / cred).chmod(0o600)


def run_selinux_relabel(state: MkosiState) -> None:
    selinux = state.root / "etc/selinux/config"
    if not selinux.exists():
        return

    policy = bwrap(["sh", "-c", f". {selinux} && echo $SELINUXTYPE"],
                   stdout=subprocess.PIPE, tools=state.config.tools_tree).stdout.strip()
    if not policy:
        return

    fc = Path('/etc/selinux') / policy / 'contexts/files/file_contexts'

    # We want to be able to relabel the underlying APIVFS mountpoints, so mount root non-recursive to a
    # temporary location so that the underlying mountpoints become visible.
    cmd = f"mkdir /tmp/relabel && mount --bind / /tmp/relabel && exec setfiles -m -r /tmp/relabel -F {fc} /tmp/relabel || exit $?"

    with complete_step(f"Relabeling files using {policy} policy"):
        run_workspace_command(state.root, ["sh", "-c", cmd], env=state.environment)


def need_build_packages(config: MkosiConfig) -> bool:
    return config.build_script is not None and len(config.build_packages) > 0


def save_cache(state: MkosiState) -> None:
    if not state.config.incremental:
        return

    final, build, manifest = cache_tree_paths(state.config)

    with complete_step("Installing cache copies"):
        unlink_try_hard(final)

        # We only use the cache-overlay directory for caching if we have a base tree, otherwise we just
        # cache the root directory.
        if state.workspace.joinpath("cache-overlay").exists():
            shutil.move(state.workspace / "cache-overlay", final)
        else:
            shutil.move(state.root, final)

        if need_build_packages(state.config) and (state.workspace / "build-overlay").exists():
            unlink_try_hard(build)
            shutil.move(state.workspace / "build-overlay", build)

        manifest.write_text(json.dumps(state.config.cache_manifest()))


def reuse_cache(state: MkosiState) -> bool:
    if not state.config.incremental:
        return False

    final, build, manifest = cache_tree_paths(state.config)
    if not final.exists() or (need_build_packages(state.config) and not build.exists()):
        return False

    if manifest.exists():
        prev = json.loads(manifest.read_text())
        if prev != state.config.cache_manifest():
            return False
    else:
        return False

    with complete_step("Copying cached trees"):
        btrfs_maybe_snapshot_subvolume(state.config, final, state.root)
        if need_build_packages(state.config):
            state.workspace.joinpath("build-overlay").symlink_to(build)

    return True


def make_image(state: MkosiState, skip: Sequence[str] = [], split: bool = False) -> tuple[Optional[str], list[Path]]:
    if not state.config.output_format == OutputFormat.disk:
        return None, []

    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--no-pager",
        "--offline=yes",
        "--root", state.root,
        state.staging / state.config.output_with_format,
    ]

    if not state.config.architecture.is_native():
        cmdline += ["--architecture", str(state.config.architecture)]
    if not state.staging.joinpath(state.config.output_with_format).exists():
        cmdline += ["--empty=create"]
    if state.config.passphrase:
        cmdline += ["--key-file", state.config.passphrase]
    if state.config.verity_key:
        cmdline += ["--private-key", state.config.verity_key]
    if state.config.verity_certificate:
        cmdline += ["--certificate", state.config.verity_certificate]
    if skip:
        cmdline += ["--defer-partitions", ",".join(skip)]
    if split and state.config.split_artifacts:
        cmdline += ["--split=yes"]

    if state.config.repart_dirs:
        for d in state.config.repart_dirs:
            cmdline += ["--definitions", d]
    else:
        definitions = state.workspace / "repart-definitions"
        if not definitions.exists():
            definitions.mkdir()
            bootdir = state.root.joinpath("efi/EFI/BOOT")

            # If Bootable=auto and we have at least one UKI and a bootloader, let's generate an ESP partition.
            add = (state.config.bootable == ConfigFeature.enabled or
                  (state.config.bootable == ConfigFeature.auto and
                   bootdir.exists() and
                   any(bootdir.iterdir()) and
                   any(gen_kernel_images(state))))

            if add:
                definitions.joinpath("00-esp.conf").write_text(
                    dedent(
                        """\
                        [Partition]
                        Type=esp
                        Format=vfat
                        CopyFiles=/efi:/
                        SizeMinBytes=512M
                        SizeMaxBytes=512M
                        """
                    )
                )

            definitions.joinpath("10-root.conf").write_text(
                dedent(
                    f"""\
                    [Partition]
                    Type=root
                    Format={state.installer.filesystem()}
                    CopyFiles=/
                    Minimize=guess
                    """
                )
            )

        cmdline += ["--definitions", definitions]

    env = dict(TMPDIR=str(state.workspace))
    for fs, options in state.installer.filesystem_options(state).items():
        env[f"SYSTEMD_REPART_MKFS_OPTIONS_{fs.upper()}"] = " ".join(options)

    for option, value in state.environment.items():
        if option.startswith("SYSTEMD_REPART_MKFS_OPTIONS_"):
            env[option] = value

    with complete_step("Generating disk image"):
        output = json.loads(bwrap(cmdline, stdout=subprocess.PIPE, env=env,
                                  tools=state.config.tools_tree).stdout)

    roothash = usrhash = None
    for p in output:
        if (h := p.get("roothash")) is None:
            continue

        if not (p["type"].startswith("usr") or p["type"].startswith("root")):
            die(f"Found roothash property on unexpected partition type {p['type']}")

        # When there's multiple verity enabled root or usr partitions, the first one wins.
        if p["type"].startswith("usr"):
            usrhash = usrhash or h
        else:
            roothash = roothash or h

    split_paths = [Path(p["split_path"]) for p in output if p.get("split_path", "-") != "-"]

    return f"roothash={roothash}" if roothash else f"usrhash={usrhash}" if usrhash else None, split_paths


def finalize_staging(state: MkosiState) -> None:
    for f in state.staging.iterdir():
        if not f.is_dir():
            os.chown(f, state.uid, state.gid)

        shutil.move(f, state.config.output_dir)


def build_image(args: MkosiArgs, config: MkosiConfig, uid: int, gid: int) -> None:
    state = MkosiState(args, config, uid, gid)
    manifest = Manifest(config)

    # Make sure tmpfiles' aging doesn't interfere with our workspace
    # while we are working on it.
    with flock(state.workspace), acl_toggle_build(state):
        install_package_manager_trees(state)

        with mount_image(state):
            install_base_trees(state)
            install_skeleton_trees(state)
            cached = reuse_cache(state)

            if not cached:
                with mount_cache_overlay(state):
                    install_distribution(state)
                    run_prepare_script(state, build=False)
                    install_build_packages(state)
                    run_prepare_script(state, build=True)

                save_cache(state)
                reuse_cache(state)

            configure_autologin(state)
            configure_initrd(state)
            run_build_script(state)

            if state.config.output_format == OutputFormat.none:
                finalize_staging(state)
                return

            install_build_dest(state)
            install_extra_trees(state)
            install_boot_loader(state)
            configure_ssh(state)
            run_postinst_script(state)
            run_sysusers(state)
            run_preset(state)
            run_depmod(state)
            run_firstboot(state)
            run_hwdb(state)
            remove_packages(state)

            if manifest:
                with complete_step("Recording packages in manifest…"):
                    manifest.record_packages(state.root)

            clean_package_manager_metadata(state)
            remove_files(state)
            run_finalize_script(state)
            run_selinux_relabel(state)

        roothash, _ = make_image(state, skip=("esp", "xbootldr"))
        install_unified_kernel(state, roothash)
        _, split_paths = make_image(state, split=True)

        for p in split_paths:
            maybe_compress(state, state.config.compress_output, p)

        make_tar(state)
        make_initrd(state)
        make_directory(state)

        maybe_compress(state, state.config.compress_output,
                       state.staging / state.config.output_with_format,
                       state.staging / state.config.output_with_compression)

        copy_nspawn_settings(state)
        calculate_sha256sum(state)
        calculate_signature(state)
        save_manifest(state, manifest)

        finalize_staging(state)

        output_base = state.config.output_dir.joinpath(state.config.output)
        if not output_base.exists() or output_base.is_symlink():
            output_base.unlink(missing_ok=True)
            output_base.symlink_to(state.config.output_with_compression)
            os.chown(output_base, uid, gid, follow_symlinks=False)

    print_output_size(config.output_dir / config.output)


def one_zero(b: bool) -> str:
    return "1" if b else "0"


def run_build_script(state: MkosiState) -> None:
    if state.config.build_script is None:
        return

    # Create a few necessary mount points inside the build overlay.
    with mount_build_overlay(state):
        state.root.joinpath("work").mkdir(mode=0o755, exist_ok=True)
        state.root.joinpath("work/src").mkdir(mode=0o755, exist_ok=True)
        state.root.joinpath("work/dest").mkdir(mode=0o755, exist_ok=True)
        state.root.joinpath("work/out").mkdir(mode=0o755, exist_ok=True)
        state.root.joinpath("work/build-script").touch(mode=0o755, exist_ok=True)
        state.root.joinpath("work/build").mkdir(mode=0o755, exist_ok=True)

        for _, target in finalize_sources(state.config):
            state.root.joinpath(target).mkdir(mode=0o755, exist_ok=True, parents=True)

    with complete_step("Running build script…"), mount_build_overlay(state, read_only=True):
        bwrap: list[PathString] = [
            "--bind", state.config.build_script, "/work/build-script",
            "--bind", state.install_dir, "/work/dest",
            "--bind", state.staging, "/work/out",
            "--chdir", "/work/src",
        ]

        for src, target in finalize_sources(state.config):
            bwrap += ["--bind", src, Path("/") / target]

        env = dict(
            WITH_DOCS=one_zero(state.config.with_docs),
            WITH_TESTS=one_zero(state.config.with_tests),
            WITH_NETWORK=one_zero(state.config.with_network),
            SRCDIR="/work/src",
            DESTDIR="/work/dest",
            OUTPUTDIR="/work/out",
        )

        if state.config.build_dir is not None:
            bwrap += ["--bind", state.config.build_dir, "/work/build"]
            env |= dict(BUILDDIR="/work/build")

        # build-script output goes to stdout so we can run language servers from within mkosi
        # build-scripts. See https://github.com/systemd/mkosi/pull/566 for more information.
        run_workspace_command(state.root, ["/work/build-script"], network=state.config.with_network,
                              bwrap_params=bwrap, stdout=sys.stdout, env=env | state.environment)


def setfacl(config: MkosiConfig, root: Path, uid: int, allow: bool) -> None:
    bwrap(["setfacl",
           "--physical",
           "--modify" if allow else "--remove",
           f"user:{uid}:rwx" if allow else f"user:{uid}",
           "-"],
           tools=config.tools_tree,
           # Supply files via stdin so we don't clutter --debug run output too much
           input="\n".join([str(root),
                           *(e.path for e in cast(Iterator[os.DirEntry[str]], scandir_recursive(root)) if e.is_dir())])
    )


@contextlib.contextmanager
def acl_maybe_toggle(config: MkosiConfig, root: Path, uid: int, *, always: bool) -> Iterator[None]:
    if not config.acl:
        yield
        return

    # getfacl complains about absolute paths so make sure we pass a relative one.
    if root.exists():
        has_acl = f"user:{uid}:rwx" in bwrap([
            "getfacl", "-n", root.relative_to(Path.cwd())],
            stdout=subprocess.PIPE,
            tools=config.tools_tree,
        ).stdout

        if not has_acl and not always:
            yield
            return
    else:
        has_acl = False

    try:
        if has_acl:
            with complete_step(f"Removing ACLs from {root}"):
                setfacl(config, root, uid, allow=False)

        yield
    finally:
        if has_acl or always:
            with complete_step(f"Adding ACLs to {root}"):
                setfacl(config, root, uid, allow=True)


@contextlib.contextmanager
def acl_toggle_build(state: MkosiState) -> Iterator[None]:
    if not state.config.acl:
        yield
        return

    extras = [e[0] for e in state.config.extra_trees]
    skeletons = [s[0] for s in state.config.skeleton_trees]

    with contextlib.ExitStack() as stack:
        for p in (*state.config.base_trees, *extras, *skeletons):
            if p and p.is_dir():
                stack.enter_context(acl_maybe_toggle(state.config, p, state.uid, always=False))

        for p in (state.config.cache_dir, state.config.build_dir):
            if p:
                stack.enter_context(acl_maybe_toggle(state.config, p, state.uid, always=True))

        if state.config.output_format == OutputFormat.directory:
            stack.enter_context(acl_maybe_toggle(state.config,
                                                 state.config.output_dir / state.config.output,
                                                 state.uid, always=True))

        yield


def check_root() -> None:
    if os.getuid() != 0:
        die("Must be invoked as root.")


@contextlib.contextmanager
def acl_toggle_boot(config: MkosiConfig) -> Iterator[None]:
    if not config.acl or config.output_format != OutputFormat.directory:
        yield
        return

    with acl_maybe_toggle(config, config.output_dir / config.output, InvokingUser.uid(), always=False):
        yield


def run_shell(args: MkosiArgs, config: MkosiConfig) -> None:
    cmdline: list[PathString] = ["systemd-nspawn", "--quiet"]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings is not None:
        cmdline += ["--settings=trusted"]

    if args.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += [
            f"--rlimit=RLIMIT_CORE={format_rlimit(resource.RLIMIT_CORE)}",
            "--console=autopipe",
        ]

    cmdline += ["--machine", config.output]

    for k, v in config.credentials.items():
        cmdline += [f"--set-credential={k}:{v}"]

    with contextlib.ExitStack() as stack:
        if config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir / config.output))
        else:
            fname = config.output_dir / config.output

        if config.output_format == OutputFormat.disk and args.verb == Verb.boot:
            bwrap(["systemd-repart",
                   "--image", fname,
                   "--size", "8G",
                   "--no-pager",
                   "--dry-run=no",
                   "--offline=no",
                   fname],
                  tools=config.tools_tree)

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]

            owner = os.stat(fname).st_uid
            if owner != 0:
                cmdline += [f"--private-users={str(owner)}"]
        else:
            cmdline += ["--image", fname]

        if args.verb == Verb.boot:
            # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
            cmdline += args.cmdline
            # kernel cmdline config of the form systemd.xxx= get interpreted by systemd when running in nspawn as
            # well.
            cmdline += config.kernel_command_line
            cmdline += config.kernel_command_line_extra
        elif args.cmdline:
            cmdline += ["--"]
            cmdline += args.cmdline

        stack.enter_context(acl_toggle_boot(config))

        bwrap(cmdline,
              stdin=sys.stdin,
              stdout=sys.stdout,
              env=os.environ,
              log=False,
              tools=config.tools_tree)


def run_ssh(args: MkosiArgs, config: MkosiConfig) -> None:
    cmd = [
        "ssh",
        # Silence known hosts file errors/warnings.
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=no",
        "-o", "LogLevel=ERROR",
        "-o", f"ProxyCommand=socat - VSOCK-CONNECT:{machine_cid(config)}:%p",
        "root@mkosi",
    ]

    cmd += args.cmdline

    bwrap(cmd, stdin=sys.stdin, stdout=sys.stdout, env=os.environ, log=False, tools=config.tools_tree)


def run_serve(config: MkosiConfig) -> None:
    """Serve the output directory via a tiny embedded HTTP server"""

    port = 8081

    if config.output_dir is not None:
        os.chdir(config.output_dir)

    with http.server.HTTPServer(("", port), http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"Serving HTTP on port {port}: http://localhost:{port}/")
        httpd.serve_forever()


def generate_key_cert_pair(args: MkosiArgs) -> None:
    """Generate a private key and accompanying X509 certificate using openssl"""

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(args.genkey_valid_days))
    cn = expand_specifier(args.genkey_common_name)

    for f in ("mkosi.key", "mkosi.crt"):
        if Path(f).exists() and not args.force:
            die(f"{f} already exists",
                hint=("To generate new keys, first remove mkosi.key and mkosi.crt"))

    log_step(f"Generating keys rsa:{keylength} for CN {cn!r}.")
    logging.info(
        dedent(
            f"""
            The keys will expire in {args.genkey_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    cmd: list[PathString] = [
        "openssl", "req",
        "-new",
        "-x509",
        "-newkey", f"rsa:{keylength}",
        "-keyout", "mkosi.key",
        "-out", "mkosi.crt",
        "-days", str(args.genkey_valid_days),
        "-subj", f"/CN={cn}/",
        "-nodes",
    ]
    run(cmd)


def bump_image_version() -> None:
    """Write current image version plus one to mkosi.version"""

    version = Path("mkosi.version").read_text().strip()
    v = version.split(".")

    try:
        m = int(v[-1])
    except ValueError:
        new_version = version + ".2"
        logging.info(
            f"Last component of current version is not a decimal integer, appending '.2', bumping '{version}' → '{new_version}'."
        )
    else:
        new_version = ".".join(v[:-1] + [str(m + 1)])
        logging.info(f"Increasing last component of version by one, bumping '{version}' → '{new_version}'.")

    Path("mkosi.version").write_text(f"{new_version}\n")


def expand_specifier(s: str) -> str:
    return s.replace("%u", InvokingUser.name())


def needs_build(args: MkosiArgs, config: MkosiConfig) -> bool:
    return args.verb in MKOSI_COMMANDS_NEED_BUILD and (args.force > 0 or not config.output_dir.joinpath(config.output_with_compression).exists())


def run_verb(args: MkosiArgs, presets: Sequence[MkosiConfig]) -> None:
    if args.verb in MKOSI_COMMANDS_SUDO:
        check_root()

    if args.verb == Verb.genkey:
        return generate_key_cert_pair(args)

    if args.verb == Verb.bump:
        return bump_image_version()

    if args.verb == Verb.summary:
        text = ""

        for config in presets:
            text += f"{summary(args, config)}\n"

        page(text, args.pager)
        return

    last = presets[-1]

    if args.verb == Verb.qemu and last.output_format in (
        OutputFormat.directory,
        OutputFormat.tar,
    ):
        die(f"{last.output_format} images cannot be booted in qemu.")

    if args.verb in (Verb.shell, Verb.boot):
        opname = "acquire shell in" if args.verb == Verb.shell else "boot"
        if last.output_format in (OutputFormat.tar, OutputFormat.cpio):
            die(f"Sorry, can't {opname} a {last.output_format} archive.")
        if last.compress_output:
            die(f"Sorry, can't {opname} a compressed image.")

    for config in presets:
        if args.verb == Verb.build and not args.force:
            check_outputs(config)

    # First, process all directory removals because otherwise if different presets share directories a later
    # preset could end up output generated by an earlier preset.

    for config in presets:
        if not needs_build(args, config) and args.verb != Verb.clean:
            continue

        def target() -> None:
            become_root()
            unlink_output(args, config)

        fork_and_wait(target)

    if args.verb == Verb.clean:
        return

    build = False

    for config in presets:
        check_inputs(config)

        if not needs_build(args, config):
            continue

        with prepend_to_environ_path(config.extra_search_paths):
            def target() -> None:
                # Create these before changing user to make sure they're owned by the user running mkosi.
                for d in (
                    config.output_dir,
                    config.cache_dir,
                    config.build_dir,
                    config.workspace_dir,
                ):
                    if d:
                        d.mkdir(parents=True, exist_ok=True)

                # Get the user UID/GID either on the host or in the user namespace running the build
                uid, gid = become_root()
                build_image(args, config, uid, gid)

            # We only want to run the build in a user namespace but not the following steps. Since we
            # can't rejoin the parent user namespace after unsharing from it, let's run the build in a
            # fork so that the main process does not leave its user namespace.
            with complete_step(f"Building {config.preset or 'default'} image"):
                fork_and_wait(target)

            build = True

    if build and args.auto_bump:
        bump_image_version()

    with prepend_to_environ_path(last.extra_search_paths):
        if args.verb in (Verb.shell, Verb.boot):
            run_shell(args, last)

        if args.verb == Verb.qemu:
            run_qemu(args, last)

        if args.verb == Verb.ssh:
            run_ssh(args, last)

        if args.verb == Verb.serve:
            run_serve(last)
