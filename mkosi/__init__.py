# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import dataclasses
import datetime
import functools
import hashlib
import itertools
import json
import logging
import os
import re
import resource
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import uuid
import zipapp
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Optional, Union, cast

from mkosi.archive import can_extract_tar, extract_tar, make_cpio, make_tar
from mkosi.bootloader import (
    efi_boot_binary,
    extract_pe_section,
    gen_kernel_images,
    grub_bios_setup,
    install_grub,
    install_shim,
    install_systemd_boot,
    prepare_grub_config,
    python_binary,
    run_systemd_sign_tool,
    shim_second_stage_binary,
    sign_efi_binary,
    want_efi,
    want_grub_bios,
    want_grub_efi,
)
from mkosi.burn import run_burn
from mkosi.completion import print_completion
from mkosi.config import (
    PACKAGE_GLOBS,
    Args,
    ArtifactOutput,
    Cacheonly,
    CertificateSourceType,
    Compression,
    Config,
    ConfigFeature,
    DocFormat,
    Incremental,
    JsonEncoder,
    KeySourceType,
    ManifestFormat,
    Network,
    OutputFormat,
    SecureBootSignTool,
    ShimBootloader,
    Ssh,
    Verb,
    Verity,
    Vmm,
    cat_config,
    dump_json,
    expand_delayed_specifiers,
    finalize_configdir,
    format_bytes,
    in_sandbox,
    parse_boolean,
    parse_config,
    resolve_deps,
    summary,
    systemd_tool_version,
    want_selinux_relabel,
    yes_no,
)
from mkosi.context import Context
from mkosi.distributions import Distribution, detect_distribution
from mkosi.documentation import show_docs
from mkosi.installer import clean_package_manager_metadata
from mkosi.kmod import gen_required_kernel_modules, loaded_modules, process_kernel_modules
from mkosi.log import ARG_DEBUG, complete_step, die, log_notice, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import (
    finalize_certificate_mounts,
    finalize_source_mounts,
    finalize_volatile_tmpdir,
    mount_overlay,
)
from mkosi.pager import page
from mkosi.partition import Partition, finalize_root, finalize_roothash
from mkosi.qemu import (
    KernelType,
    copy_ephemeral,
    finalize_credentials,
    finalize_kernel_command_line_extra,
    finalize_register,
    join_initrds,
    run_qemu,
    run_ssh,
    start_journal_remote,
)
from mkosi.run import (
    Popen,
    apivfs_options,
    chroot_cmd,
    chroot_options,
    finalize_interpreter,
    finalize_passwd_symlinks,
    fork_and_wait,
    run,
    spawn,
    workdir,
)
from mkosi.sandbox import (
    CAP_SYS_ADMIN,
    CLONE_NEWNS,
    MOUNT_ATTR_NODEV,
    MOUNT_ATTR_NOEXEC,
    MOUNT_ATTR_NOSUID,
    MOUNT_ATTR_RDONLY,
    MS_REC,
    MS_SLAVE,
    __version__,
    acquire_privileges,
    have_effective_cap,
    join_new_session_keyring,
    mount,
    mount_rbind,
    umask,
    unshare,
    userns_has_single_user,
)
from mkosi.sysupdate import run_sysupdate
from mkosi.tree import copy_tree, make_tree, move_tree, rmtree
from mkosi.user import INVOKING_USER, become_root_cmd
from mkosi.util import (
    PathString,
    current_home_dir,
    flatten,
    flock,
    flock_or_die,
    format_rlimit,
    hash_file,
    make_executable,
    one_zero,
    read_env_file,
    resource_path,
    scopedenv,
)
from mkosi.versioncomp import GenericVersion
from mkosi.vmspawn import run_vmspawn


@contextlib.contextmanager
def mount_base_trees(context: Context) -> Iterator[None]:
    if not context.config.base_trees or not context.config.overlay:
        yield
        return

    with complete_step("Mounting base trees…"), contextlib.ExitStack() as stack:
        bases = []
        (context.workspace / "bases").mkdir(exist_ok=True)

        for path in context.config.base_trees:
            d = context.workspace / f"bases/{path.name}-{uuid.uuid4().hex}"

            path = path.resolve()

            if path.is_dir():
                bases += [path]
            elif can_extract_tar(path):
                extract_tar(path, d, sandbox=context.sandbox)
                bases += [d]
            elif path.suffix == ".raw":
                run(
                    ["systemd-dissect", "--mount", "--mkdir", path, d],
                    env=dict(SYSTEMD_DISSECT_VERITY_EMBEDDED="no", SYSTEMD_DISSECT_VERITY_SIDECAR="no"),
                )
                stack.callback(lambda: run(["systemd-dissect", "--umount", "--rmdir", d]))
                bases += [d]
            else:
                die(f"Unsupported base tree source {path}")

        with mount_overlay(bases, context.root, upperdir=context.root):
            yield

        stack.enter_context(mount_overlay(bases, context.workspace / "lower"))

        for p in context.root.rglob("*"):
            rel = p.relative_to(context.root)
            q = context.workspace / "lower" / rel

            if (
                context.config.output_format == OutputFormat.sysext
                and not rel.is_relative_to("usr")
                and not rel.is_relative_to("opt")
            ):
                continue

            if context.config.output_format == OutputFormat.confext and not rel.is_relative_to("etc"):
                continue

            if not q.is_symlink() and not q.exists():
                continue

            if not p.is_symlink() and p.is_dir():
                if q.is_symlink() or not q.is_dir():
                    die(f"/{rel} is a directory in the overlay but not in the base tree")
                shutil.copystat(q, p)
            else:
                logging.info(f"Removing duplicate path /{rel} from overlay")
                p.unlink()


def remove_files(context: Context) -> None:
    """Remove files based on user-specified patterns"""

    if context.config.remove_files:
        with complete_step("Removing files…"):
            remove = flatten(
                context.root.glob(pattern.lstrip("/")) for pattern in context.config.remove_files
            )
            rmtree(*remove, sandbox=context.sandbox)

    if context.config.output_format.is_extension_image():
        with complete_step("Removing empty directories…"):
            for path, dirs, _ in os.walk(context.root, topdown=False):
                p = Path(path)

                for d in dirs:
                    t = p / d
                    if not t.is_symlink() and not any(t.iterdir()):
                        t.rmdir()


def install_distribution(context: Context) -> None:
    if context.config.base_trees:
        if not context.config.packages:
            return

        with complete_step(f"Installing extra packages for {context.config.distribution.pretty_name()}"):
            context.config.distribution.package_manager(context.config).install(
                context, context.config.packages
            )
    else:
        if context.config.overlay or context.config.output_format.is_extension_image():
            if context.config.packages:
                die(
                    "Cannot install packages in extension images without a base tree",
                    hint="Configure a base tree with the BaseTrees= setting",
                )
            return

        with complete_step(f"Installing {context.config.distribution.pretty_name()}"):
            context.config.distribution.install(context)

            if context.config.machine_id:
                with umask(~0o755):
                    (context.root / "etc").mkdir(exist_ok=True)
                with umask(~0o444):
                    (context.root / "etc/machine-id").write_text(context.config.machine_id.hex)
            elif (context.root / "etc").exists() and not (context.root / "etc/machine-id").exists():
                # Uninitialized means we want it to get initialized on first boot.
                with umask(~0o444):
                    (context.root / "etc/machine-id").write_text("uninitialized\n")

            # Ensure /efi exists so that the ESP is mounted there, as recommended by
            # https://0pointer.net/blog/linux-boot-partitions.html. Use the most restrictive access
            # mode we can without tripping up mkfs tools since this directory is only meant to be
            # overmounted and should not be read from or written to.
            with umask(~0o500):
                (context.root / "efi").mkdir(exist_ok=True)
                (context.root / "boot").mkdir(exist_ok=True)

            # Ensure /boot/loader/entries.srel exists and has "type1" written to it to nudge
            # kernel-install towards using the boot loader specification layout.
            with umask(~0o700):
                (context.root / "boot/loader").mkdir(exist_ok=True)
            with umask(~0o600):
                (context.root / "boot/loader/entries.srel").write_text("type1\n")

            if context.config.packages:
                context.config.distribution.package_manager(context.config).install(
                    context, context.config.packages
                )

    for f in (
        "var/lib/systemd/random-seed",
        "var/lib/systemd/credential.secret",
        "etc/machine-info",
        "var/lib/dbus/machine-id",
    ):
        # Using missing_ok=True still causes an OSError if the mount is read-only even if the
        # file doesn't exist so do an explicit exists() check first.
        if (context.root / f).exists():
            (context.root / f).unlink()


def install_build_packages(context: Context) -> None:
    if not context.config.build_scripts or not context.config.build_packages:
        return

    with (
        complete_step(f"Installing build packages for {context.config.distribution.pretty_name()}"),
        setup_build_overlay(context),
    ):
        context.config.distribution.package_manager(context.config).install(
            context, context.config.build_packages
        )


def install_volatile_packages(context: Context) -> None:
    if not context.config.volatile_packages:
        return

    with complete_step(f"Installing volatile packages for {context.config.distribution.pretty_name()}"):
        context.config.distribution.package_manager(context.config).install(
            context, context.config.volatile_packages
        )


def remove_packages(context: Context) -> None:
    """Remove packages listed in config.remove_packages"""

    if not context.config.remove_packages:
        return

    with complete_step(f"Removing {len(context.config.remove_packages)} packages…"):
        try:
            context.config.distribution.package_manager(context.config).remove(
                context, context.config.remove_packages
            )
        except NotImplementedError:
            die(f"Removing packages is not supported for {context.config.distribution}")


def check_root_populated(context: Context) -> None:
    if (
        context.config.output_format == OutputFormat.none
        or context.config.output_format.is_extension_image()
    ):
        return

    """Check that the root was populated by looking for a os-release file."""
    osrelease = context.root / "usr/lib/os-release"
    if not osrelease.exists():
        die(
            f"{osrelease} not found.",
            hint=(
                "The root must be populated by the distribution, or from base trees, "
                "skeleton trees, and prepare scripts."
            ),
        )


def configure_os_release(context: Context) -> None:
    """Write IMAGE_ID and IMAGE_VERSION to /usr/lib/os-release in the image."""

    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    for candidate in ["usr/lib/os-release", "usr/lib/initrd-release", "etc/os-release"]:
        osrelease = context.root / candidate

        if not osrelease.is_file() or osrelease.is_symlink():
            continue

        if context.config.image_id or context.config.image_version or context.config.hostname:
            # at this point we know we will either change or add to the file
            newosrelease = osrelease.with_suffix(".new")

            image_id_written = image_version_written = default_hostname_written = False
            with osrelease.open("r") as old, newosrelease.open("w") as new:
                # fix existing values
                for line in old.readlines():
                    if context.config.image_id and line.startswith("IMAGE_ID="):
                        new.write(f'IMAGE_ID="{context.config.image_id}"\n')
                        image_id_written = True
                    elif context.config.image_version and line.startswith("IMAGE_VERSION="):
                        new.write(f'IMAGE_VERSION="{context.config.image_version}"\n')
                        image_version_written = True
                    elif context.config.hostname and line.startswith("DEFAULT_HOSTNAME="):
                        new.write(f'DEFAULT_HOSTNAME="{context.config.hostname}"\n')
                        default_hostname_written = True
                    else:
                        new.write(line)

                # append if they were missing
                if context.config.image_id and not image_id_written:
                    new.write(f'IMAGE_ID="{context.config.image_id}"\n')
                if context.config.image_version and not image_version_written:
                    new.write(f'IMAGE_VERSION="{context.config.image_version}"\n')
                if context.config.hostname and not default_hostname_written:
                    new.write(f'DEFAULT_HOSTNAME="{context.config.hostname}"\n')

            newosrelease.rename(osrelease)

        if ArtifactOutput.os_release in context.config.split_artifacts:
            shutil.copy(osrelease, context.staging / context.config.output_split_os_release)


def configure_extension_release(context: Context) -> None:
    if context.config.output_format not in (OutputFormat.sysext, OutputFormat.confext):
        return

    prefix = "SYSEXT" if context.config.output_format == OutputFormat.sysext else "CONFEXT"
    d = "usr/lib" if context.config.output_format == OutputFormat.sysext else "etc"
    p = context.root / d / f"extension-release.d/extension-release.{context.config.output}"
    p.parent.mkdir(parents=True, exist_ok=True)

    osrelease = read_env_file(q) if (q := context.root / "usr/lib/os-release").exists() else {}
    extrelease = read_env_file(p) if p.exists() else {}
    new = p.with_suffix(".new")

    with new.open("w") as f:
        for k, v in extrelease.items():
            f.write(f"{k}={v}\n")

        if "ID" not in extrelease:
            f.write(f"ID={osrelease.get('ID', '_any')}\n")

        if f"{prefix}_LEVEL" not in extrelease and (level := osrelease.get(f"{prefix}_LEVEL")):
            f.write(f"{prefix}_LEVEL={level}\n")

        if "VERSION_ID" not in extrelease and (version := osrelease.get("VERSION_ID")):
            f.write(f"VERSION_ID={version}\n")

        if f"{prefix}_ID" not in extrelease and context.config.image_id:
            f.write(f"{prefix}_ID={context.config.image_id}\n")

        if f"{prefix}_VERSION_ID" not in extrelease and context.config.image_version:
            f.write(f"{prefix}_VERSION_ID={context.config.image_version}\n")

        if f"{prefix}_SCOPE" not in extrelease:
            f.write(
                f"{prefix}_SCOPE="
                f"{context.config.finalize_environment().get(f'{prefix}_SCOPE', 'initrd system portable')}\n"
            )

        if "ARCHITECTURE" not in extrelease:
            f.write(f"ARCHITECTURE={context.config.architecture}\n")

    new.rename(p)


def configure_autologin_service(context: Context, service: str, extra: str) -> None:
    dropin = context.root / f"usr/lib/systemd/system/{service}.d/autologin.conf"
    with umask(~0o755):
        dropin.parent.mkdir(parents=True, exist_ok=True)
    with umask(~0o644):
        dropin.write_text(
            textwrap.dedent(
                f"""\
                [Service]
                ExecStart=
                ExecStart=-agetty -o '-f -p -- \\\\u' --autologin root {extra} $TERM
                StandardInput=tty
                StandardOutput=tty
                """
            )
        )


def configure_autologin(context: Context) -> None:
    if not context.config.autologin:
        return

    with complete_step("Setting up autologin…"):
        configure_autologin_service(
            context,
            "console-getty.service",
            "--noclear --keep-baud console 115200,38400,9600",
        )
        configure_autologin_service(
            context,
            "getty@tty1.service",
            "--noclear -",
        )
        configure_autologin_service(
            context,
            "serial-getty@hvc0.service",
            "--keep-baud 115200,57600,38400,9600 -",
        )


@contextlib.contextmanager
def setup_build_overlay(context: Context, volatile: bool = False) -> Iterator[None]:
    d = context.workspace / "build-overlay"
    if not d.is_symlink():
        with umask(~0o755):
            d.mkdir(exist_ok=True)

    # We don't support multiple levels of root overlay.
    assert not context.lowerdirs
    assert not context.upperdir
    assert not context.workdir

    with contextlib.ExitStack() as stack:
        if volatile:
            context.lowerdirs = [d]
            context.upperdir = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(
                        prefix="volatile-overlay.",
                        dir=finalize_volatile_tmpdir(),
                    )
                )
            )
            os.chmod(context.upperdir, d.stat().st_mode)
        else:
            context.upperdir = d

        context.workdir = stack.enter_context(
            tempfile.TemporaryDirectory(
                dir=Path(context.upperdir).parent,
                prefix=f"{Path(context.upperdir).name}-workdir",
            )
        )

        try:
            yield
        finally:
            context.lowerdirs = []
            context.upperdir = None
            context.workdir = None


@contextlib.contextmanager
def finalize_scripts(config: Config, scripts: Mapping[str, Sequence[PathString]]) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mkosi-scripts-") as d:
        for name, script in scripts.items():
            # Make sure we don't end up in a recursive loop when we name a script after the binary
            # it execs by removing the scripts directory from the PATH when we execute a script.
            with (Path(d) / name).open("w") as f:
                f.write("#!/bin/sh\n")

                if config.find_binary(name):
                    f.write(
                        textwrap.dedent(
                            """\
                            DIR="$(cd "$(dirname "$0")" && pwd)"
                            PATH="$(echo "$PATH" | tr ':' '\\n' | grep -v "$DIR" | tr '\\n' ':')"
                            export PATH
                            """
                        )
                    )

                f.write(f'exec {shlex.join(os.fspath(s) for s in script)} "$@"\n')

            make_executable(Path(d) / name)
            os.utime(Path(d) / name, (0, 0))

        yield Path(d)


def finalize_host_scripts(
    context: Context,
    helpers: Mapping[str, Sequence[PathString]] = {},
) -> AbstractContextManager[Path]:
    scripts: dict[str, Sequence[PathString]] = {}
    for binary in ("useradd", "groupadd"):
        if context.config.find_binary(binary):
            scripts[binary] = (binary, "--root", "/buildroot")
    if ukify := context.config.find_binary("ukify"):
        scripts["ukify"] = (python_binary(context.config), ukify)
    return finalize_scripts(context.config, scripts | dict(helpers))


@contextlib.contextmanager
def finalize_config_json(config: Config) -> Iterator[Path]:
    with tempfile.NamedTemporaryFile(mode="w") as f:
        f.write(dump_json(config.to_dict()))
        f.flush()
        yield Path(f.name)


def run_configure_scripts(config: Config) -> Config:
    if not config.configure_scripts:
        return config

    for script in config.configure_scripts:
        if not os.access(script, os.X_OK):
            die(f"{script} is not executable")

    env = dict(
        DISTRIBUTION=str(config.distribution),
        RELEASE=config.release,
        ARCHITECTURE=str(config.architecture),
        QEMU_ARCHITECTURE=config.architecture.to_qemu(),
        DISTRIBUTION_ARCHITECTURE=config.distribution.architecture(config.architecture),
        SRCDIR="/work/src",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if config.profiles:
        env["PROFILES"] = " ".join(config.profiles)

    with finalize_source_mounts(config, ephemeral=False) as sources:
        for script in config.configure_scripts:
            with complete_step(f"Running configure script {script}…"):
                result = run(
                    ["/work/configure"],
                    env=env | config.finalize_environment(),
                    sandbox=config.sandbox(
                        options=[
                            "--dir", "/work/src",
                            "--chdir", "/work/src",
                            "--ro-bind", script, "/work/configure",
                            *sources,
                        ],
                    ),
                    input=dump_json(config.to_dict(), indent=None),
                    stdout=subprocess.PIPE,
                )  # fmt: skip

                config = Config.from_json(result.stdout)

    return config


def run_sync_scripts(config: Config) -> None:
    if not config.sync_scripts:
        return

    for script in config.sync_scripts:
        if not os.access(script, os.X_OK):
            die(f"{script} is not executable")

    env = dict(
        DISTRIBUTION=str(config.distribution),
        RELEASE=config.release,
        ARCHITECTURE=str(config.architecture),
        DISTRIBUTION_ARCHITECTURE=config.distribution.architecture(config.architecture),
        SRCDIR="/work/src",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        CACHED=one_zero(have_cache(config)),
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if config.profiles:
        env["PROFILES"] = " ".join(config.profiles)

    with (
        finalize_source_mounts(config, ephemeral=False) as sources,
        finalize_config_json(config) as json,
        tempfile.TemporaryDirectory(
            dir=config.workspace_dir_or_default(),
            prefix="mkosi-metadata-",
        ) as sandbox_tree,
    ):
        install_sandbox_trees(config, Path(sandbox_tree))

        for script in config.sync_scripts:
            options = [
                *finalize_certificate_mounts(config),
                "--ro-bind", script, "/work/sync",
                "--ro-bind", json, "/work/config.json",
                # We need to make sure SSH keys and such can be accessed when git is used so bind in /home to
                # make sure that works.
                "--ro-bind", "/home", "/home",
                # e.g. the ssh-agent socket and such will be in /run and might be used by git so make sure
                # those are available as well.
                "--ro-bind", "/run", "/run",
                "--dir", "/work/src",
                "--chdir", "/work/src",
                *sources,
            ]  # fmt: skip

            with complete_step(f"Running sync script {script}…"):
                run(
                    ["/work/sync", "final"],
                    env=os.environ | env | config.finalize_environment(),
                    stdin=sys.stdin,
                    sandbox=config.sandbox(
                        network=True,
                        options=options,
                        overlay=Path(sandbox_tree),
                    ),
                )


@contextlib.contextmanager
def script_maybe_chroot_sandbox(
    context: Context,
    *,
    script: Path,
    options: Sequence[PathString],
    network: bool,
) -> Iterator[list[PathString]]:
    options = ["--dir", "/work/src", "--chdir", "/work/src", *options]
    suppress_chown = parse_boolean(
        context.config.finalize_environment().get("MKOSI_CHROOT_SUPPRESS_CHOWN", "0")
    )

    helpers = {
        "mkosi-chroot": [
            finalize_interpreter(bool(context.config.tools_tree)), "-SI", "/sandbox.py",
            "--bind", "/buildroot", "/",
            "--bind", "/var/tmp", "/var/tmp",
            *apivfs_options(root=Path("/")),
            *chroot_options(),
            "--bind", "/work", "/work",
            "--chdir", "/work/src",
            *(["--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"] if network else []),
            *(["--suppress-chown"] if suppress_chown else []),
        ],
        **context.config.distribution.package_manager(context.config).scripts(context),
    }  # fmt: skip

    with finalize_host_scripts(context, helpers) as hd:
        if script.suffix != ".chroot":
            with context.sandbox(
                network=network,
                options=[
                    *options,
                    *context.rootoptions(),
                    *context.config.distribution.package_manager(context.config).mounts(context),
                ],
                scripts=hd,
            ) as sandbox:  # fmt: skip
                yield sandbox
        else:
            if suppress_chown:
                options += ["--suppress-chown"]

            with chroot_cmd(
                root=context.rootoptions,
                network=network,
                options=options,
            ) as sandbox:
                yield sandbox


def run_prepare_scripts(context: Context, build: bool) -> None:
    if not context.config.prepare_scripts:
        return
    if build and not context.config.build_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        DISTRIBUTION_ARCHITECTURE=context.config.distribution.architecture(context.config.architecture),
        BUILDROOT="/buildroot",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        ARTIFACTDIR="/work/artifacts",
        SCRIPT="/work/prepare",
        CHROOT_SCRIPT="/work/prepare",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if context.config.profiles:
        env["PROFILES"] = " ".join(context.config.profiles)

    env |= context.config.finalize_environment()

    with (
        setup_build_overlay(context) if build else contextlib.nullcontext(),
        finalize_source_mounts(
            context.config,
            ephemeral=bool(context.config.build_sources_ephemeral),
        ) as sources,
        finalize_config_json(context.config) as json,
    ):
        if build:
            step_msg = "Running prepare script {} in build overlay…"
            arg = "build"
        else:
            step_msg = "Running prepare script {}…"
            arg = "final"

        for script in context.config.prepare_scripts:
            with complete_step(step_msg.format(script)):
                options: list[PathString] = [
                    "--ro-bind", script, "/work/prepare",
                    "--ro-bind", json, "/work/config.json",
                    "--bind", context.artifacts, "/work/artifacts",
                    "--bind", context.package_dir, "/work/packages",
                    *sources,
                ]  # fmt: skip

                run(
                    ["/work/prepare", arg],
                    env=env,
                    stdin=sys.stdin,
                    sandbox=script_maybe_chroot_sandbox(
                        context,
                        script=script,
                        options=options,
                        network=True,
                    ),
                )


def run_build_scripts(context: Context) -> None:
    if not context.config.build_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        DISTRIBUTION_ARCHITECTURE=context.config.distribution.architecture(context.config.architecture),
        BUILDROOT="/buildroot",
        DESTDIR="/work/dest",
        CHROOT_DESTDIR="/work/dest",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        ARTIFACTDIR="/work/artifacts",
        SCRIPT="/work/build-script",
        CHROOT_SCRIPT="/work/build-script",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if context.config.profiles:
        env["PROFILES"] = " ".join(context.config.profiles)

    if context.config.build_dir is not None:
        env |= dict(
            BUILDDIR="/work/build",
            CHROOT_BUILDDIR="/work/build",
        )

    env |= context.config.finalize_environment()

    with (
        setup_build_overlay(context, volatile=True),
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
        finalize_config_json(context.config) as json,
    ):
        for script in context.config.build_scripts:
            cmdline = context.args.cmdline if context.args.verb == Verb.build else []

            with complete_step(f"Running build script {script}…"):
                options: list[PathString] = [
                    "--ro-bind", script, "/work/build-script",
                    "--ro-bind", json, "/work/config.json",
                    "--bind", context.install_dir, "/work/dest",
                    "--bind", context.artifacts, "/work/artifacts",
                    "--bind", context.package_dir, "/work/packages",
                    *(
                        ["--bind", os.fspath(context.config.build_subdir), "/work/build"]
                        if context.config.build_dir
                        else []
                    ),
                    *sources,
                ]  # fmt: skip

                run(
                    ["/work/build-script", *cmdline],
                    env=env,
                    stdin=sys.stdin,
                    stdout=sys.stdout,
                    sandbox=script_maybe_chroot_sandbox(
                        context,
                        script=script,
                        options=options,
                        network=context.config.with_network,
                    ),
                )


def run_postinst_scripts(context: Context) -> None:
    if not context.config.postinst_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        DISTRIBUTION_ARCHITECTURE=context.config.distribution.architecture(context.config.architecture),
        BUILDROOT="/buildroot",
        OUTPUTDIR="/work/out",
        CHROOT_OUTPUTDIR="/work/out",
        SCRIPT="/work/postinst",
        CHROOT_SCRIPT="/work/postinst",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        ARTIFACTDIR="/work/artifacts",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        WITH_NETWORK=one_zero(context.config.with_network),
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if context.config.profiles:
        env["PROFILES"] = " ".join(context.config.profiles)

    if context.config.build_dir is not None:
        env |= dict(BUILDDIR="/work/build")

    env |= context.config.finalize_environment()

    with (
        finalize_source_mounts(
            context.config,
            ephemeral=bool(context.config.build_sources_ephemeral),
        ) as sources,
        finalize_config_json(context.config) as json,
    ):
        for script in context.config.postinst_scripts:
            with complete_step(f"Running postinstall script {script}…"):
                options: list[PathString] = [
                    "--ro-bind", script, "/work/postinst",
                    "--ro-bind", json, "/work/config.json",
                    "--bind", context.staging, "/work/out",
                    "--bind", context.artifacts, "/work/artifacts",
                    "--bind", context.package_dir, "/work/packages",
                    *(
                        ["--ro-bind", os.fspath(context.config.build_subdir), "/work/build"]
                        if context.config.build_dir
                        else []
                    ),
                    *sources,
                ]  # fmt: skip

                run(
                    ["/work/postinst", "final"],
                    env=env,
                    stdin=sys.stdin,
                    sandbox=script_maybe_chroot_sandbox(
                        context,
                        script=script,
                        options=options,
                        network=context.config.with_network,
                    ),
                )


def run_finalize_scripts(context: Context) -> None:
    if not context.config.finalize_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        DISTRIBUTION_ARCHITECTURE=context.config.distribution.architecture(context.config.architecture),
        BUILDROOT="/buildroot",
        OUTPUTDIR="/work/out",
        CHROOT_OUTPUTDIR="/work/out",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        ARTIFACTDIR="/work/artifacts",
        SCRIPT="/work/finalize",
        CHROOT_SCRIPT="/work/finalize",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        WITH_NETWORK=one_zero(context.config.with_network),
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if context.config.profiles:
        env["PROFILES"] = " ".join(context.config.profiles)

    if context.config.build_dir is not None:
        env |= dict(BUILDDIR="/work/build")

    env |= context.config.finalize_environment()

    with (
        finalize_source_mounts(
            context.config,
            ephemeral=bool(context.config.build_sources_ephemeral),
        ) as sources,
        finalize_config_json(context.config) as json,
    ):
        for script in context.config.finalize_scripts:
            with complete_step(f"Running finalize script {script}…"):
                options: list[PathString] = [
                    "--ro-bind", script, "/work/finalize",
                    "--ro-bind", json, "/work/config.json",
                    "--bind", context.staging, "/work/out",
                    "--bind", context.artifacts, "/work/artifacts",
                    "--bind", context.package_dir, "/work/packages",
                    *(
                        ["--ro-bind", os.fspath(context.config.build_subdir), "/work/build"]
                        if context.config.build_dir
                        else []
                    ),
                    *sources,
                ]  # fmt: skip

                run(
                    ["/work/finalize"],
                    env=env,
                    stdin=sys.stdin,
                    sandbox=script_maybe_chroot_sandbox(
                        context,
                        script=script,
                        options=options,
                        network=context.config.with_network,
                    ),
                )


def run_postoutput_scripts(context: Context) -> None:
    if not context.config.postoutput_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        DISTRIBUTION_ARCHITECTURE=context.config.distribution.architecture(context.config.architecture),
        SRCDIR="/work/src",
        OUTPUTDIR="/work/out",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if context.config.profiles:
        env["PROFILES"] = " ".join(context.config.profiles)

    with (
        finalize_source_mounts(
            context.config,
            ephemeral=bool(context.config.build_sources_ephemeral),
        ) as sources,
        finalize_config_json(context.config) as json,
    ):
        for script in context.config.postoutput_scripts:
            with complete_step(f"Running post-output script {script}…"):
                run(
                    ["/work/postoutput"],
                    env=env | context.config.finalize_environment(),
                    sandbox=context.sandbox(
                        # postoutput scripts should run as (fake) root so that file ownership is
                        # always recorded as if owned by root.
                        options=[
                            "--ro-bind", script, "/work/postoutput",
                            "--ro-bind", json, "/work/config.json",
                            "--bind", context.staging, "/work/out",
                            "--dir", "/work/src",
                            "--chdir", "/work/src",
                            "--dir", "/work/out",
                            "--become-root",
                            *sources,
                        ],
                    ),
                    stdin=sys.stdin,
                )  # fmt: skip


def install_tree(
    config: Config,
    src: Path,
    dst: Path,
    *,
    target: Optional[Path] = None,
    preserve: bool = True,
) -> None:
    src = src.resolve()

    t = dst
    if target:
        t = dst / target.relative_to("/")

    with umask(~0o755):
        t.parent.mkdir(parents=True, exist_ok=True)

    def copy() -> None:
        copy_tree(
            src,
            t,
            preserve=preserve,
            use_subvolumes=config.use_subvolumes,
            sandbox=config.sandbox,
        )

    if src.is_dir() or (src.is_file() and target):
        copy()
    elif can_extract_tar(src):
        extract_tar(src, t, sandbox=config.sandbox)
    elif src.suffix == ".raw":
        run(
            ["systemd-dissect", "--copy-from", workdir(src), "/", workdir(t)],
            env=dict(SYSTEMD_DISSECT_VERITY_EMBEDDED="no", SYSTEMD_DISSECT_VERITY_SIDECAR="no"),
            sandbox=config.sandbox(
                devices=True,
                network=True,
                options=[
                    "--ro-bind", src, workdir(src),
                    "--bind", t.parent, workdir(t.parent),
                ],
            ),
        )  # fmt: skip
    else:
        # If we get an unknown file without a target, we just copy it into /.
        copy()


def install_base_trees(context: Context) -> None:
    if not context.config.base_trees or context.config.overlay:
        return

    with complete_step("Copying in base trees…"):
        for path in context.config.base_trees:
            install_tree(context.config, path, context.root)


def install_skeleton_trees(context: Context) -> None:
    if not context.config.skeleton_trees:
        return

    with complete_step("Copying in skeleton file trees…"):
        for tree in context.config.skeleton_trees:
            install_tree(context.config, tree.source, context.root, target=tree.target, preserve=False)


def install_sandbox_trees(config: Config, dst: Path) -> None:
    # Ensure /etc exists in the sandbox
    (dst / "etc").mkdir(exist_ok=True)

    if (p := config.tools() / "usr/share/crypto-policies/back-ends/DEFAULT").exists():
        Path(dst / "etc/crypto-policies").mkdir(exist_ok=True)
        copy_tree(p, dst / "etc/crypto-policies/back-ends", sandbox=config.sandbox)

    if config.sandbox_trees:
        with complete_step("Copying in sandbox trees…"):
            for tree in config.sandbox_trees:
                install_tree(config, tree.source, dst, target=tree.target, preserve=False)

    if Path("/etc/passwd").exists():
        shutil.copy("/etc/passwd", dst / "etc/passwd")
    if Path("/etc/group").exists():
        shutil.copy("/etc/group", dst / "etc/group")

    if not (dst / "etc/mtab").is_symlink():
        (dst / "etc/mtab").symlink_to("../proc/self/mounts")

    Path(dst / "etc/resolv.conf").unlink(missing_ok=True)
    Path(dst / "etc/resolv.conf").touch()

    if not (dst / "etc/nsswitch.conf").exists():
        (dst / "etc/nsswitch.conf").write_text(
            textwrap.dedent(
                """\
                passwd:     files
                shadow:     files
                group:      files
                hosts:      files myhostname resolve [!UNAVAIL=return] dns
                services:   files
                netgroup:   files
                automount:  files

                aliases:    files
                ethers:     files
                gshadow:    files
                networks:   files dns
                protocols:  files
                publickey:  files
                rpc:        files
                """
            )
        )

    if not (dst / "etc/hosts").exists() and Path("/etc/hosts").exists():
        shutil.copy("/etc/hosts", dst / "etc/hosts")

    Path(dst / "etc/static").unlink(missing_ok=True)
    if (config.tools() / "etc/static").is_symlink():
        (dst / "etc/static").symlink_to((config.tools() / "etc/static").readlink())

    # Create various mountpoints in /etc as /etc from the sandbox tree is mounted read-only into the sandbox.

    for d in (
        "etc/pki",
        "etc/ssl",
        "etc/ca-certificates",
        "etc/pacman.d/gnupg",
        "etc/alternatives",
    ):
        (dst / d).mkdir(parents=True, exist_ok=True)

    for f in (
        "etc/passwd",
        "etc/group",
        "etc/shadow",
        "etc/gshadow",
        "etc/ld.so.cache",
    ):
        (dst / f).touch(exist_ok=True)


def install_package_directories(context: Context, directories: Sequence[Path]) -> None:
    directories = [d for d in directories if any(d.iterdir())]

    if not directories:
        return

    with complete_step("Copying in extra packages…"):
        for d in directories:
            for p in itertools.chain(*(d.glob(glob) for glob in PACKAGE_GLOBS)):
                shutil.copy(p, context.repository, follow_symlinks=True)


def install_extra_trees(context: Context) -> None:
    if not context.config.extra_trees:
        return

    with complete_step("Copying in extra file trees…"):
        for tree in context.config.extra_trees:
            install_tree(context.config, tree.source, context.root, target=tree.target, preserve=False)


def install_build_dest(context: Context) -> None:
    if not any(context.install_dir.iterdir()):
        return

    with complete_step("Copying in build tree…"):
        copy_tree(
            context.install_dir,
            context.root,
            use_subvolumes=context.config.use_subvolumes,
            sandbox=context.sandbox,
        )


def gzip_binary(context: Context) -> str:
    return "pigz" if context.config.find_binary("pigz") else "gzip"


def fixup_vmlinuz_location(context: Context) -> None:
    # Some architectures ship an uncompressed vmlinux (ppc64el, riscv64)
    for type in ("vmlinuz", "vmlinux"):
        for d in context.root.glob(f"boot/{type}-*"):
            if d.is_symlink():
                continue

            kver = d.name.removeprefix(f"{type}-")
            vmlinuz = context.root / "usr/lib/modules" / kver / type
            if not vmlinuz.parent.exists():
                continue
            # Some distributions (OpenMandriva) symlink /usr/lib/modules/<kver>/vmlinuz to
            # /boot/vmlinuz-<kver>, so get rid of the symlink and copy the actual vmlinuz to
            # /usr/lib/modules/<kver>.
            if vmlinuz.is_symlink() and vmlinuz.resolve().is_relative_to("/boot"):
                vmlinuz.unlink()
            if not vmlinuz.exists():
                shutil.copy2(d, vmlinuz)


def want_initrd(context: Context) -> bool:
    if context.config.bootable == ConfigFeature.disabled:
        return False

    if context.config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        return False

    if not any((context.artifacts / "io.mkosi.initrd").glob("*")) and not any(gen_kernel_images(context)):
        return False

    return True


def finalize_default_initrd(
    config: Config,
    *,
    resources: Path,
    tools: bool = True,
    output_dir: Optional[Path] = None,
) -> Config:
    if config.root_password:
        password, hashed = config.root_password
        rootpwopt = f"hashed:{password}" if hashed else password
    else:
        rootpwopt = None

    relabel = (
        ConfigFeature.auto if config.selinux_relabel == ConfigFeature.enabled else config.selinux_relabel
    )

    # Default values are assigned via the parser so we go via the argument parser to construct
    # the config for the initrd.
    cmdline = [
        "--directory=",
        f"--distribution={config.distribution}",
        f"--release={config.release}",
        f"--architecture={config.architecture}",
        *([f"--mirror={config.mirror}"] if config.mirror else []),
        f"--repository-key-check={config.repository_key_check}",
        f"--repository-key-fetch={config.repository_key_fetch}",
        *([f"--repositories={repository}" for repository in config.repositories]),
        *([f"--sandbox-tree={tree}" for tree in config.sandbox_trees]),
        # Note that when compress_output == Compression.none == 0 we don't pass --compress-output
        # which means the default compression will get picked. This is exactly what we want so that
        # initrds are always compressed.
        *([f"--compress-output={c}"] if (c := config.compress_output) else []),
        f"--compress-level={config.compress_level}",
        f"--with-network={config.with_network}",
        f"--cache-only={config.cacheonly}",
        *([f"--output-directory={os.fspath(output_dir)}"] if output_dir else []),
        *([f"--workspace-directory={os.fspath(config.workspace_dir)}"] if config.workspace_dir else []),
        *([f"--cache-directory={os.fspath(config.cache_dir)}"] if config.cache_dir else []),
        f"--cache-key={config.cache_key or '-'}",
        *([f"--package-cache-directory={os.fspath(p)}"] if (p := config.package_cache_dir) else []),
        *([f"--local-mirror={config.local_mirror}"] if config.local_mirror else []),
        f"--incremental={config.incremental}",
        *(f"--profile={profile}" for profile in config.initrd_profiles),
        *(f"--package={package}" for package in config.initrd_packages),
        *(f"--volatile-package={package}" for package in config.initrd_volatile_packages),
        *(f"--package-directory={d}" for d in config.package_directories),
        *(f"--volatile-package-directory={d}" for d in config.volatile_package_directories),
        "--output=initrd",
        *([f"--image-id={config.image_id}"] if config.image_id else []),
        *([f"--image-version={config.image_version}"] if config.image_version else []),
        *(
            [f"--source-date-epoch={config.source_date_epoch}"]
            if config.source_date_epoch is not None else
            []
        ),
        *([f"--locale={config.locale}"] if config.locale else []),
        *([f"--locale-messages={config.locale_messages}"] if config.locale_messages else []),
        *([f"--keymap={config.keymap}"] if config.keymap else []),
        *([f"--timezone={config.timezone}"] if config.timezone else []),
        *([f"--hostname={config.hostname}"] if config.hostname else []),
        *([f"--root-password={rootpwopt}"] if rootpwopt else []),
        *([f"--environment={k}='{v}'" for k, v in config.environment.items()]),
        *([f"--tools-tree={os.fspath(config.tools_tree)}"] if config.tools_tree and tools else []),
        f"--tools-tree-certificates={config.tools_tree_certificates}",
        *([f"--extra-search-path={os.fspath(p)}" for p in config.extra_search_paths]),
        *([f"--proxy-url={config.proxy_url}"] if config.proxy_url else []),
        *([f"--proxy-exclude={host}" for host in config.proxy_exclude]),
        *([f"--proxy-peer-certificate={os.fspath(p)}"] if (p := config.proxy_peer_certificate) else []),
        *([f"--proxy-client-certificate={os.fspath(p)}"] if (p := config.proxy_client_certificate) else []),
        *([f"--proxy-client-key={os.fspath(p)}"] if (p := config.proxy_client_key) else []),
        f"--selinux-relabel={relabel}",
        "--include=mkosi-initrd",
    ]  # fmt: skip

    _, _, [initrd] = parse_config(cmdline + ["build"], resources=resources)

    run_configure_scripts(initrd)

    initrd = dataclasses.replace(initrd, image="default-initrd")

    if initrd.is_incremental() and initrd.expand_key_specifiers(
        initrd.cache_key
    ) == config.expand_key_specifiers(config.cache_key):
        die(
            f"Image '{config.image}' and its default initrd image have the same cache key '{config.expand_key_specifiers(config.cache_key)}'",  # noqa: E501
            hint="Add the &I specifier to the cache key to avoid this issue",
        )

    return initrd


def build_default_initrd(context: Context) -> Path:
    if context.config.distribution == Distribution.custom:
        die("Building a default initrd is not supported for custom distributions")

    config = finalize_default_initrd(
        context.config,
        resources=context.resources,
        output_dir=context.workspace,
    )

    assert config.output_dir

    if config.is_incremental() and config.incremental == Incremental.strict and not have_cache(config):
        die(
            f"Strict incremental mode is enabled and cache for image {config.image} is out-of-date",
            hint="Build once with -i yes to update the image cache",
        )

    config.output_dir.mkdir(exist_ok=True)

    if (config.output_dir / config.output).exists():
        return config.output_dir / config.output

    with (
        complete_step("Building default initrd"),
        setup_workspace(context.args, config) as workspace,
    ):
        build_image(
            Context(
                context.args,
                config,
                workspace=workspace,
                resources=context.resources,
                # Reuse the keyring, repository metadata and local package repository from the main image for
                # the default initrd.
                keyring_dir=context.keyring_dir,
                metadata_dir=context.metadata_dir,
                package_dir=context.package_dir,
            )
        )

    return config.output_dir / config.output


def identify_cpu(root: Path) -> tuple[Optional[Path], Optional[Path]]:
    for entry in Path("/proc/cpuinfo").read_text().split("\n\n"):
        vendor_id = family = model = stepping = None
        for line in entry.splitlines():
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            if not key or not value:
                continue

            if key == "vendor_id":
                vendor_id = value
            elif key == "cpu family":
                family = int(value)
            elif key == "model":
                model = int(value)
            elif key == "stepping":
                stepping = int(value)

        if vendor_id is not None and family is not None and model is not None and stepping is not None:
            break
    else:
        return (None, None)

    if vendor_id == "AuthenticAMD":
        uroot = root / "usr/lib/firmware/amd-ucode"
        if family > 21:
            ucode = uroot / f"microcode_amd_fam{family:x}h.bin"
        else:
            ucode = uroot / "microcode_amd.bin"
        if ucode.exists():
            return (Path(f"{vendor_id}.bin"), ucode)
    elif vendor_id == "GenuineIntel":
        uroot = root / "usr/lib/firmware/intel-ucode"
        if (ucode := uroot / f"{family:02x}-{model:02x}-{stepping:02x}").exists():
            return (Path(f"{vendor_id}.bin"), ucode)
        if (ucode := uroot / f"{family:02x}-{model:02x}-{stepping:02x}.initramfs").exists():
            return (Path(f"{vendor_id}.bin"), ucode)

    return (Path(f"{vendor_id}.bin"), None)


def build_microcode_initrd(context: Context) -> list[Path]:
    if not context.config.architecture.is_x86_variant():
        return []

    microcode = context.workspace / "microcode.initrd"
    if microcode.exists():
        return [microcode]

    amd = context.root / "usr/lib/firmware/amd-ucode"
    intel = context.root / "usr/lib/firmware/intel-ucode"

    if not amd.exists() and not intel.exists():
        logging.warning("/usr/lib/firmware/{amd-ucode,intel-ucode} not found, not adding microcode")
        return []

    root = context.workspace / "microcode-root"
    destdir = root / "kernel/x86/microcode"

    with umask(~0o755):
        destdir.mkdir(parents=True, exist_ok=True)

    if context.config.microcode_host:
        vendorfile, ucodefile = identify_cpu(context.root)
        if vendorfile is None or ucodefile is None:
            logging.warning("Unable to identify CPU for MicrocodeHostonly=")
            return []
        with (destdir / vendorfile).open("wb") as f:
            f.write(ucodefile.read_bytes())
    else:
        if amd.exists():
            with (destdir / "AuthenticAMD.bin").open("wb") as f:
                for p in amd.iterdir():
                    f.write(p.read_bytes())

        if intel.exists():
            with (destdir / "GenuineIntel.bin").open("wb") as f:
                for p in intel.iterdir():
                    f.write(p.read_bytes())

    make_cpio(root, microcode, sandbox=context.sandbox)

    return [microcode]


def finalize_kernel_modules_include(context: Context, *, include: Sequence[str], host: bool) -> set[str]:
    final = {i for i in include if i not in ("default", "host")}
    if "default" in include:
        initrd = finalize_default_initrd(context.config, resources=context.resources)
        final.update(initrd.kernel_modules_include)
    if host or "host" in include:
        final.update(loaded_modules())

    return final


def build_kernel_modules_initrd(context: Context, kver: str) -> Path:
    kmods = context.workspace / f"kernel-modules-{kver}.initrd"
    if kmods.exists():
        return kmods

    make_cpio(
        context.root,
        kmods,
        files=gen_required_kernel_modules(
            context,
            kver,
            modules_include=finalize_kernel_modules_include(
                context,
                include=context.config.kernel_modules_initrd_include,
                host=context.config.kernel_modules_initrd_include_host,
            ),
            modules_exclude=context.config.kernel_modules_initrd_exclude,
            firmware_include=context.config.firmware_include,
            firmware_exclude=context.config.firmware_exclude,
        ),
        sandbox=context.sandbox,
    )

    if context.config.distribution.is_apt_distribution():
        # Older Debian and Ubuntu releases do not compress their kernel modules, so we compress the
        # initramfs instead. Note that this is not ideal since the compressed kernel modules will
        # all be decompressed on boot which requires significant memory.
        if context.config.distribution == Distribution.debian and context.config.release in (
            "sid",
            "testing",
        ):
            compression = Compression.none
        else:
            compression = Compression.zstd

        maybe_compress(context, compression, kmods, kmods)

    return kmods


def find_devicetree(context: Context, kver: str) -> Path:
    assert context.config.devicetree

    for d in (
        context.root / f"usr/lib/firmware/{kver}/device-tree",
        context.root / f"usr/lib/linux-image-{kver}",
        context.root / f"usr/lib/modules/{kver}/dtb",
    ):
        dtb = d / context.config.devicetree
        if dtb.exists():
            return dtb

    die(f"Requested devicetree {context.config.devicetree} not found")


def want_signed_pcrs(config: Config) -> bool:
    return config.sign_expected_pcr == ConfigFeature.enabled or (
        config.sign_expected_pcr == ConfigFeature.auto
        and config.find_binary("systemd-measure", "/usr/lib/systemd/systemd-measure") is not None
        and bool(config.sign_expected_pcr_key)
        and bool(config.sign_expected_pcr_certificate)
    )


def run_ukify(
    context: Context,
    stub: Path,
    output: Path,
    *,
    cmdline: Sequence[str] = (),
    arguments: Sequence[PathString] = (),
    options: Sequence[PathString] = (),
    sign: bool = True,
    json_out: bool = False,
) -> dict[str, Any]:
    ukify = context.config.find_binary("ukify", "/usr/lib/systemd/ukify")
    if not ukify:
        die("Could not find ukify")

    if not (arch := context.config.architecture.to_efi()):
        die(f"Architecture {context.config.architecture} does not support UEFI")

    # Older versions of systemd-stub expect the cmdline section to be null terminated. We can't
    # embed NUL terminators in argv so let's communicate the cmdline via a file instead.
    (context.workspace / "cmdline").write_text(f"{' '.join(cmdline)}\x00")

    cmd = [
        python_binary(context.config),
        ukify,
        "build",
        *arguments,
        "--efi-arch", arch,
        "--stub", workdir(stub),
        "--output", workdir(output),
        *(["--cmdline", f"@{workdir(context.workspace / 'cmdline')}"] if cmdline else []),
    ]  # fmt: skip

    opt: list[PathString] = [
        "--ro-bind", stub, workdir(stub),
        "--bind", output.parent, workdir(output.parent),
        "--ro-bind", context.workspace / "cmdline", workdir(context.workspace / "cmdline"),
    ]  # fmt: skip

    if sign and context.config.secure_boot:
        assert context.config.secure_boot_key
        assert context.config.secure_boot_certificate

        cmd += [
            "--signtool", (
                "sbsign"
                if context.config.secure_boot_sign_tool == SecureBootSignTool.sbsign
                or not context.config.find_binary("systemd-sbsign", "/usr/lib/systemd/systemd-sbsign")
                else "systemd-sbsign"
            ),
        ]  # fmt: skip

        if (
            context.config.secure_boot_key_source.type != KeySourceType.file
            or context.config.secure_boot_certificate_source.type != CertificateSourceType.file
        ):
            opt += ["--bind", "/run", "/run"]

        if context.config.secure_boot_key_source.type == KeySourceType.engine:
            cmd += ["--signing-engine", context.config.secure_boot_key_source.source]
        elif context.config.secure_boot_key_source.type == KeySourceType.provider:
            cmd += ["--signing-provider", context.config.secure_boot_key_source.source]

        if context.config.secure_boot_key.exists():
            cmd += ["--secureboot-private-key", workdir(context.config.secure_boot_key)]
            opt += ["--ro-bind", context.config.secure_boot_key, workdir(context.config.secure_boot_key)]
        else:
            cmd += ["--secureboot-private-key", context.config.secure_boot_key]

        if context.config.secure_boot_certificate_source.type == CertificateSourceType.provider:
            cmd += ["--certificate-provider", context.config.secure_boot_certificate_source.source]

        if context.config.secure_boot_certificate.exists():
            cmd += ["--secureboot-certificate", workdir(context.config.secure_boot_certificate)]
            opt += [
                "--ro-bind", context.config.secure_boot_certificate, workdir(context.config.secure_boot_certificate),  # noqa: E501
            ]  # fmt: skip
        else:
            cmd += ["--secureboot-certificate", context.config.secure_boot_certificate]

    if json_out:
        cmd += ["--json=short"]
        stdout = subprocess.PIPE
    else:
        stdout = None

    result = run(
        cmd,
        stdin=(
            sys.stdin
            if context.config.secure_boot_key_source.type != KeySourceType.file
            else subprocess.DEVNULL
        ),
        stdout=stdout,
        env=context.config.finalize_environment(),
        sandbox=context.sandbox(
            options=[*opt, *options],
            devices=context.config.secure_boot_key_source.type != KeySourceType.file,
        ),
    )

    if json_out:
        return cast(dict[str, Any], json.loads(result.stdout.strip()))

    return {}


def build_uki(
    context: Context,
    stub: Path,
    kver: str,
    kimg: Path,
    microcodes: list[Path],
    initrds: list[Path],
    cmdline: Sequence[str],
    profiles: Sequence[Path],
    output: Path,
) -> dict[str, Any]:
    if not (ukify := context.config.find_binary("ukify", "/usr/lib/systemd/ukify")):
        die("Could not find ukify")

    json_out = False

    arguments: list[PathString] = [
        "--os-release", f"@{workdir(context.root / 'usr/lib/os-release')}",
        "--uname", kver,
        "--linux", workdir(kimg),
        *flatten(["--join-profile", os.fspath(workdir(profile))] for profile in profiles),
    ]  # fmt: skip

    if (
        context.config.unified_kernel_image_profiles
        and context.config.sign_expected_pcr
        and any(not profile.sign_expected_pcr for profile in context.config.unified_kernel_image_profiles)
    ):
        arguments += ["--sign-profile=main"]
        arguments += flatten(
            ["--sign-profile", profile.profile["ID"]]
            for profile in context.config.unified_kernel_image_profiles
            if profile.sign_expected_pcr
        )

    options: list[PathString] = [
        "--ro-bind", context.root / "usr/lib/os-release", workdir(context.root / "usr/lib/os-release"),
        "--ro-bind", kimg, workdir(kimg),
        *flatten(["--ro-bind", os.fspath(profile), os.fspath(workdir(profile))] for profile in profiles),
    ]  # fmt: skip

    if context.config.devicetree:
        dtb = find_devicetree(context, kver)
        arguments += ["--devicetree", workdir(dtb)]
        options += ["--ro-bind", dtb, workdir(dtb)]

    if context.config.splash:
        splash = context.root / os.fspath(context.config.splash).lstrip("/")
        arguments += ["--splash", workdir(splash)]
        options += ["--ro-bind", splash, workdir(splash)]

    if context.config.secure_boot:
        assert context.config.secure_boot_key
        assert context.config.secure_boot_certificate

        arguments += ["--sign-kernel"]

    if want_signed_pcrs(context.config):
        assert context.config.sign_expected_pcr_key
        assert context.config.sign_expected_pcr_certificate

        arguments += [
            # SHA1 might be disabled in OpenSSL depending on the distro so we opt to not sign
            # for SHA1 to avoid having to manage a bunch of configuration to re-enable SHA1.
            "--pcr-banks", "sha256",
        ]  # fmt: skip

        # TODO: bump version to 258 once it is released
        if (
            systemd_tool_version(
                python_binary(context.config),
                ukify,
                sandbox=context.sandbox,
            )
            >= "257.999"
        ):
            cert_parameter = "--pcr-certificate"
        else:
            cert_parameter = "--pcr-public-key"

        # If we're providing the private key via an engine or provider, we have to pass in a X.509
        # certificate via --pcr-certificate as well.
        if context.config.sign_expected_pcr_key_source.type != KeySourceType.file:
            if context.config.sign_expected_pcr_certificate_source.type == CertificateSourceType.provider:
                arguments += [
                    "--certificate-provider",
                    f"provider:{context.config.sign_expected_pcr_certificate_source.source}",
                ]

            options += ["--bind", "/run", "/run"]

            if context.config.sign_expected_pcr_certificate.exists():
                arguments += [
                    cert_parameter, workdir(context.config.sign_expected_pcr_certificate),
                ]  # fmt: skip
                options += [
                    "--ro-bind", context.config.sign_expected_pcr_certificate, workdir(context.config.sign_expected_pcr_certificate),  # noqa: E501
                ]  # fmt: skip
            else:
                arguments += [cert_parameter, context.config.sign_expected_pcr_certificate]

        if context.config.sign_expected_pcr_key_source.type == KeySourceType.engine:
            arguments += ["--signing-engine", context.config.sign_expected_pcr_key_source.source]
        elif context.config.sign_expected_pcr_key_source.type == KeySourceType.provider:
            arguments += ["--signing-provider", context.config.sign_expected_pcr_key_source.source]

        if context.config.sign_expected_pcr_key.exists():
            arguments += ["--pcr-private-key", workdir(context.config.sign_expected_pcr_key)]
            options += [
                "--ro-bind", context.config.sign_expected_pcr_key, workdir(context.config.sign_expected_pcr_key),  # noqa: E501
            ]  # fmt: skip
        else:
            arguments += ["--pcr-private-key", context.config.sign_expected_pcr_key]
    elif ArtifactOutput.pcrs in context.config.split_artifacts:
        assert context.config.sign_expected_pcr_certificate

        json_out = True
        arguments += [
            "--policy-digest",
            "--pcr-banks", "sha256",
            "--pcr-certificate", workdir(context.config.sign_expected_pcr_certificate),
        ]  # fmt: skip
        options += [
            "--ro-bind", context.config.sign_expected_pcr_certificate, workdir(context.config.sign_expected_pcr_certificate),  # noqa: E501
        ]  # fmt: skip

    if microcodes:
        # new .ucode section support?
        if (
            systemd_tool_version(
                python_binary(context.config),
                ukify,
                sandbox=context.sandbox,
            )
            >= "256"
            and (version := systemd_stub_version(context, stub))
            and version >= "256"
        ):
            for microcode in microcodes:
                arguments += ["--microcode", workdir(microcode)]
                options += ["--ro-bind", microcode, workdir(microcode)]
        else:
            initrds = microcodes + initrds

    for initrd in initrds:
        arguments += ["--initrd", workdir(initrd)]
        options += ["--ro-bind", initrd, workdir(initrd)]

    with complete_step(f"Generating unified kernel image for kernel version {kver}"):
        return run_ukify(
            context,
            stub,
            output,
            cmdline=cmdline,
            arguments=arguments,
            options=options,
            json_out=json_out,
        )


def systemd_stub_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    stub = context.root / f"usr/lib/systemd/boot/efi/linux{arch}.efi.stub"
    return stub


def systemd_stub_version(context: Context, stub: Path) -> Optional[GenericVersion]:
    try:
        sdmagic = extract_pe_section(context, stub, ".sdmagic", context.workspace / "sdmagic")
    except KeyError:
        return None

    sdmagic_text = sdmagic.read_text().strip("\x00")

    # Older versions of the stub have misaligned sections which results in an empty sdmagic text.
    # Let's check for that explicitly and treat it as no version.
    #
    # TODO: Drop this logic once every distribution we support ships systemd-stub v254 or newer.
    if not sdmagic_text:
        return None

    if not (
        version := re.match(
            r"#### LoaderInfo: systemd-stub (?P<version>[.~^a-zA-Z0-9-+_]+) ####", sdmagic_text
        )
    ):
        die(f"Unable to determine systemd-stub version, found {sdmagic_text!r}")

    return GenericVersion(version.group("version"))


def want_uki(context: Context) -> bool:
    return want_efi(context.config) and (
        context.config.bootloader.is_uki()
        or context.config.unified_kernel_images == ConfigFeature.enabled
        or (
            context.config.unified_kernel_images == ConfigFeature.auto
            and systemd_stub_binary(context).exists()
            and context.config.find_binary("ukify", "/usr/lib/systemd/ukify") is not None
        )
    )


def find_entry_token(context: Context) -> str:
    if (
        not context.config.find_binary("kernel-install")
        or (
            "--version"
            not in run(
                ["kernel-install", "--help"],
                stdout=subprocess.PIPE,
                sandbox=context.sandbox(),
            ).stdout
        )
        or systemd_tool_version("kernel-install", sandbox=context.sandbox) < "255.1"
    ):
        return context.config.image_id or context.config.distribution.name

    output = json.loads(
        run(
            ["kernel-install", "--root=/buildroot", "--json=pretty", "inspect"],
            sandbox=context.sandbox(options=context.rootoptions(readonly=True)),
            stdout=subprocess.PIPE,
            env={"BOOT_ROOT": "/boot"},
        ).stdout
    )

    logging.debug(json.dumps(output, indent=4))
    return cast(str, output["EntryToken"])


def finalize_cmdline(
    context: Context, partitions: Sequence[Partition], roothash: Optional[str]
) -> list[str]:
    if (context.root / "etc/kernel/cmdline").exists():
        cmdline = [(context.root / "etc/kernel/cmdline").read_text().strip()]
    elif (context.root / "usr/lib/kernel/cmdline").exists():
        cmdline = [(context.root / "usr/lib/kernel/cmdline").read_text().strip()]
    else:
        cmdline = []

    cmdline += context.config.kernel_command_line

    for name in ("root", "mount.usr"):
        type_prefix = name.removeprefix("mount.")
        if not (root := next((p.uuid for p in partitions if p.type.startswith(type_prefix)), None)):
            continue

        cmdline = [f"{name}=PARTUUID={root}" if c == f"{name}=PARTUUID" else c for c in cmdline]

    if roothash and (
        (roothash.startswith("roothash=") and not any(c.startswith("root=") for c in cmdline))
        or (roothash.startswith("usrhash=") and not any(c.startswith("mount.usr") for c in cmdline))
    ):
        cmdline += [roothash]

    return cmdline


def finalize_microcode(context: Context) -> list[Path]:
    if any((context.artifacts / "io.mkosi.microcode").glob("*")):
        return sorted((context.artifacts / "io.mkosi.microcode").iterdir())
    elif microcode := build_microcode_initrd(context):
        return microcode
    return []


def finalize_initrds(context: Context) -> list[Path]:
    if context.config.initrds:
        return context.config.initrds
    elif any((context.artifacts / "io.mkosi.initrd").glob("*")):
        return sorted((context.artifacts / "io.mkosi.initrd").iterdir())
    return [build_default_initrd(context)]


def install_type1(
    context: Context,
    kver: str,
    kimg: Path,
    token: str,
    partitions: Sequence[Partition],
    cmdline: list[str],
) -> None:
    dst = context.root / "boot" / token / kver
    entry = context.root / f"boot/loader/entries/{token}-{kver}.conf"
    with umask(~0o700):
        dst.mkdir(parents=True, exist_ok=True)
        entry.parent.mkdir(parents=True, exist_ok=True)

    kmods = build_kernel_modules_initrd(context, kver)

    dtb = None
    if context.config.devicetree:
        dtb = dst / context.config.devicetree
        with umask(~0o700):
            dtb.parent.mkdir(parents=True, exist_ok=True)

    with umask(~0o600):
        if (
            want_efi(context.config)
            and context.config.secure_boot
            and not context.config.bootloader.is_signed()
            and KernelType.identify(context.config, kimg) == KernelType.pe
        ):
            kimg = sign_efi_binary(context, kimg, dst / "vmlinuz")
        else:
            kimg = Path(shutil.copy2(context.root / kimg, dst / "vmlinuz"))

        initrds = [
            Path(shutil.copy2(initrd, dst.parent / initrd.name))
            for initrd in finalize_microcode(context) + finalize_initrds(context)
        ]
        initrds += [Path(shutil.copy2(kmods, dst / "kernel-modules.initrd"))]

        if dtb:
            shutil.copy2(find_devicetree(context, kver), dtb)

        with entry.open("w") as f:
            f.write(
                textwrap.dedent(
                    f"""\
                    title {token} {kver}
                    version {kver}
                    linux /{kimg.relative_to(context.root / "boot")}
                    options {" ".join(cmdline)}
                    """
                )
            )

            for initrd in initrds:
                f.write(f"initrd /{initrd.relative_to(context.root / 'boot')}\n")

            if dtb:
                f.write(f"devicetree /{dtb.relative_to(context.root / 'boot')}\n")

    if want_grub_efi(context) or want_grub_bios(context, partitions):
        config = prepare_grub_config(context)
        assert config

        if (
            not any(c.startswith("root=PARTUUID=") for c in context.config.kernel_command_line)
            and not any(c.startswith("mount.usr=PARTUUID=") for c in context.config.kernel_command_line)
            and (root := finalize_root(partitions))
        ):
            cmdline = [root] + cmdline

        with config.open("a") as f:
            f.write("if [ ")

            conditions = []
            if want_grub_efi(context) and not want_uki(context):
                conditions += ['"${grub_platform}" == "efi"']
            if want_grub_bios(context, partitions):
                conditions += ['"${grub_platform}" == "pc"']

            f.write(" -o ".join(conditions))
            f.write(" ]; then\n")

            f.write(
                textwrap.dedent(
                    f"""\
                    menuentry "{token}-{kver}" {{
                        linux /{kimg.relative_to(context.root / "boot")} {" ".join(cmdline)}
                        initrd {" ".join(os.fspath(Path("/") / i.relative_to(context.root / "boot")) for i in initrds)}
                    }}
                    """  # noqa: E501
                )
            )

            f.write("fi\n")


def expand_kernel_specifiers(text: str, kver: str, token: str, roothash: str) -> str:
    specifiers = {
        "&": "&",
        "e": token,
        "k": kver,
        "h": roothash,
    }

    return expand_delayed_specifiers(specifiers, text)


def finalize_bootloader_entry_format(
    context: Context,
    kver: str,
    token: str,
    partitions: Sequence[Partition] = (),
) -> str:
    bootloader_entry_format = context.config.unified_kernel_image_format or "&e-&k"

    roothash_value = ""
    if roothash := finalize_roothash(partitions):
        roothash_value = roothash.partition("=")[2]

        if not context.config.unified_kernel_image_format:
            bootloader_entry_format += "-&h"

    return expand_kernel_specifiers(
        bootloader_entry_format,
        kver=kver,
        token=token,
        roothash=roothash_value,
    )


def finalize_uki_path(context: Context, name: str) -> Path:
    if not context.config.bootloader.is_uki():
        return Path(f"boot/EFI/Linux/{name}.efi")

    if context.config.shim_bootloader != ShimBootloader.none:
        return shim_second_stage_binary(context)

    return efi_boot_binary(context)


def install_uki(
    context: Context,
    kver: str,
    kimg: Path,
    token: str,
    partitions: Sequence[Partition],
    profiles: Sequence[Path],
    cmdline: list[str],
) -> dict[str, Any]:
    boot_binary = context.root / finalize_uki_path(
        context, finalize_bootloader_entry_format(context, kver, token, partitions)
    )

    pcrs: dict[str, Any] = {}

    # Make sure the parent directory where we'll be writing the UKI exists.
    with umask(~0o700):
        boot_binary.parent.mkdir(parents=True, exist_ok=True)

    if context.config.bootloader.is_signed():
        for p in (context.root / "usr/lib/modules" / kver).glob("*.efi"):
            log_step(f"Installing prebuilt UKI at {p} to {boot_binary}")
            shutil.copy2(p, boot_binary)
            break
        else:
            if context.config.bootable == ConfigFeature.enabled:
                die(f"Couldn't find a signed UKI binary installed at /usr/lib/modules/{kver} in the image")

            return pcrs
    else:
        microcodes = finalize_microcode(context)

        initrds = finalize_initrds(context)
        if context.config.kernel_modules_initrd:
            initrds += [build_kernel_modules_initrd(context, kver)]

        pcrs = build_uki(
            context,
            systemd_stub_binary(context),
            kver,
            context.root / kimg,
            microcodes,
            initrds,
            cmdline,
            profiles,
            boot_binary,
        )

        print_output_size(boot_binary)

    if want_grub_efi(context):
        config = prepare_grub_config(context)
        assert config

        with config.open("a") as f:
            f.write('if [ "${grub_platform}" == "efi" ]; then\n')

            f.write(
                textwrap.dedent(
                    f"""\
                    menuentry "{boot_binary.stem}" {{
                        chainloader /{boot_binary.relative_to(context.root / "boot")}
                    }}
                    """
                )
            )

            f.write("fi\n")

    return pcrs


def systemd_addon_stub_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    stub = context.root / f"usr/lib/systemd/boot/efi/addon{arch}.efi.stub"
    return stub


def build_uki_profiles(context: Context, cmdline: Sequence[str]) -> list[Path]:
    if not context.config.unified_kernel_image_profiles:
        return []

    stub = systemd_addon_stub_binary(context)
    if not stub.exists():
        die(f"sd-stub not found at /{stub.relative_to(context.root)} in the image")

    (context.workspace / "uki-profiles").mkdir()

    profiles = []

    for profile in context.config.unified_kernel_image_profiles:
        id = profile.profile["ID"]
        output = context.workspace / f"uki-profiles/{id}.efi"

        profile_section = context.workspace / f"uki-profiles/{id}.profile"

        with profile_section.open("w") as f:
            for k, v in profile.profile.items():
                if not all(c.isalnum() for c in v):
                    v = f'"{v}"'

                f.write(f"{k}={v}\n")

        with complete_step(f"Generating UKI profile '{id}'"):
            run_ukify(
                context,
                stub,
                output,
                cmdline=[*cmdline, *profile.cmdline],
                arguments=["--profile", f"@{profile_section}"],
                options=["--ro-bind", profile_section, profile_section],
                sign=False,
            )

        profiles += [output]

    return profiles


def install_kernel(context: Context, partitions: Sequence[Partition]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of
    # the ESP. sd-boot iterates through them and shows them in the menu. These "unified"
    # single-file images have the benefit that they can be signed like normal EFI binaries, and can
    # encode everything necessary to boot a specific root device, including the root hash.

    if context.config.output_format in (OutputFormat.uki, OutputFormat.esp):
        return

    if context.config.bootable == ConfigFeature.disabled:
        return

    if context.config.bootable == ConfigFeature.auto and (
        context.config.output_format == OutputFormat.cpio
        or context.config.output_format.is_extension_or_portable_image()
        or context.config.overlay
    ):
        return

    stub = systemd_stub_binary(context)
    if want_uki(context) and not stub.exists():
        die(
            "Unified kernel image(s) requested but systemd-stub not found at "
            f"/{stub.relative_to(context.root)}"
        )

    if context.config.bootable == ConfigFeature.enabled and not any(gen_kernel_images(context)):
        die("A bootable image was requested but no kernel was found")

    token = find_entry_token(context)
    cmdline = finalize_cmdline(context, partitions, finalize_roothash(partitions))
    profiles = build_uki_profiles(context, cmdline) if want_uki(context) else []
    # The first processed UKI is the one that will be used as split artifact, so take pcrs from
    # it and ignore the rest
    # TODO: we should probably support signing pcrs for all built UKIs
    pcrs: dict[str, Any] = {}

    for kver, kimg in gen_kernel_images(context):
        if want_uki(context):
            pcrs = pcrs or install_uki(context, kver, kimg, token, partitions, profiles, cmdline)
        if not want_uki(context) or want_grub_bios(context, partitions):
            install_type1(context, kver, kimg, token, partitions, cmdline)

        if context.config.bootloader.is_uki():
            break

    if ArtifactOutput.pcrs in context.config.split_artifacts and pcrs:
        (context.staging / context.config.output_split_pcrs).write_text(json.dumps(pcrs))


def make_uki(
    context: Context,
    stub: Path,
    kver: str,
    kimg: Path,
    microcode: list[Path],
    output: Path,
) -> None:
    make_cpio(context.root, context.workspace / "initrd", sandbox=context.sandbox)
    maybe_compress(
        context,
        context.config.compress_output,
        context.workspace / "initrd",
        context.workspace / "initrd",
    )

    initrds = [context.workspace / "initrd"]
    pcrs = build_uki(
        context,
        stub,
        kver,
        kimg,
        microcode,
        initrds,
        context.config.kernel_command_line,
        build_uki_profiles(context, context.config.kernel_command_line),
        output,
    )

    if ArtifactOutput.kernel in context.config.split_artifacts:
        extract_pe_section(context, output, ".linux", context.staging / context.config.output_split_kernel)

    if ArtifactOutput.initrd in context.config.split_artifacts:
        extract_pe_section(context, output, ".initrd", context.staging / context.config.output_split_initrd)

    if ArtifactOutput.pcrs in context.config.split_artifacts and pcrs:
        (context.staging / context.config.output_split_pcrs).write_text(json.dumps(pcrs))


def make_addon(context: Context, stub: Path, output: Path) -> None:
    arguments: list[PathString] = []
    options: list[PathString] = []

    if any(context.root.iterdir()):
        make_cpio(context.root, context.workspace / "initrd", sandbox=context.sandbox)
        maybe_compress(
            context,
            context.config.compress_output,
            context.workspace / "initrd",
            context.workspace / "initrd",
        )
        arguments += ["--initrd", workdir(context.workspace / "initrd")]
        options += [
            "--ro-bind", context.workspace / "initrd", workdir(context.workspace / "initrd")
        ]  # fmt: skip

    with complete_step(f"Generating PE addon {output}"):
        run_ukify(
            context,
            stub,
            output,
            cmdline=context.config.kernel_command_line,
            arguments=arguments,
            options=options,
        )


def compressor_command(context: Context, compression: Compression) -> list[PathString]:
    """Returns a command suitable for compressing archives."""

    if compression == Compression.gz:
        return [gzip_binary(context), f"-{context.config.compress_level}", "--stdout", "-"]
    elif compression == Compression.xz:
        return ["xz", "--check=crc32", f"-{context.config.compress_level}", "-T0", "--stdout", "-"]
    elif compression == Compression.zstd:
        return ["zstd", "-q", f"-{context.config.compress_level}", "-T0", "--stdout", "-"]
    else:
        die(f"Unknown compression {compression}")


def maybe_compress(
    context: Context,
    compression: Compression,
    src: Path,
    dst: Optional[Path] = None,
) -> None:
    if not compression or src.is_dir():
        if dst:
            move_tree(
                src,
                dst,
                use_subvolumes=context.config.use_subvolumes,
                sandbox=context.sandbox,
            )
        return

    if not dst:
        dst = src.parent / f"{src.name}.{compression.extension()}"

    cmd = compressor_command(context, compression)

    with complete_step(f"Compressing {src} with {compression}"):
        with src.open("rb") as i:
            # if src == dst, make sure dst doesn't truncate the src file but creates a new file.
            src.unlink()

            with dst.open("wb") as o:
                run(cmd, stdin=i, stdout=o, sandbox=context.sandbox())


def copy_nspawn_settings(context: Context) -> None:
    if context.config.nspawn_settings is None:
        return None

    with complete_step("Copying nspawn settings file…"):
        shutil.copy2(context.config.nspawn_settings, context.staging / context.config.output_nspawn_settings)


def get_uki_path(context: Context) -> Optional[Path]:
    if not want_efi(context.config) or context.config.unified_kernel_images == ConfigFeature.disabled:
        return None

    ukis = sorted(
        (context.root / "boot/EFI/Linux").glob("*.efi"),
        key=lambda p: GenericVersion(p.name),
        reverse=True,
    )

    if (uki := context.root / efi_boot_binary(context)).exists() and (
        KernelType.identify(context.config, uki) == KernelType.uki
    ):
        pass
    elif (uki := context.root / shim_second_stage_binary(context)).exists() and (
        KernelType.identify(context.config, uki) == KernelType.uki
    ):
        pass
    elif ukis:
        uki = ukis[0]
    else:
        return None

    return uki


def copy_uki(context: Context) -> None:
    if ArtifactOutput.uki not in context.config.split_artifacts:
        return

    if (context.staging / context.config.output_split_uki).exists():
        return

    if uki := get_uki_path(context):
        shutil.copy(uki, context.staging / context.config.output_split_uki)


def copy_vmlinuz(context: Context) -> None:
    if ArtifactOutput.kernel not in context.config.split_artifacts:
        return

    if (context.staging / context.config.output_split_kernel).exists():
        return

    # ukify will have signed the kernel image as well. Let's make sure we put the signed kernel
    # image in the output directory instead of the unsigned one by reading it from the UKI.
    if uki := get_uki_path(context):
        extract_pe_section(context, uki, ".linux", context.staging / context.config.output_split_kernel)
        return

    for _, kimg in gen_kernel_images(context):
        shutil.copy(context.root / kimg, context.staging / context.config.output_split_kernel)
        break


def copy_initrd(context: Context) -> None:
    if ArtifactOutput.initrd not in context.config.split_artifacts:
        return

    if not want_initrd(context):
        return

    if (context.staging / context.config.output_split_initrd).exists():
        return

    # Extract the combined initrds from the UKI so we can use it to direct kernel boot with qemu if needed.
    if uki := get_uki_path(context):
        extract_pe_section(context, uki, ".initrd", context.staging / context.config.output_split_initrd)
        return

    for kver, _ in gen_kernel_images(context):
        initrds = finalize_initrds(context)

        if context.config.kernel_modules_initrd:
            kver = next(gen_kernel_images(context))[0]
            initrds += [build_kernel_modules_initrd(context, kver)]
        join_initrds(context.config, initrds, context.staging / context.config.output_split_initrd)
        break


def calculate_sha256sum(context: Context) -> None:
    if not context.config.checksum:
        return

    with complete_step("Calculating SHA256SUMS…"):
        with open(context.workspace / context.config.output_checksum, "w") as f:
            for p in context.staging.iterdir():
                if p.is_dir():
                    logging.warning(f"Cannot checksum directory '{p}', skipping")
                    continue

                print(hash_file(p) + " *" + p.name, file=f)

        (context.workspace / context.config.output_checksum).rename(
            context.staging / context.config.output_checksum
        )


def calculate_signature(context: Context) -> None:
    if not context.config.sign or not context.config.checksum:
        return

    if context.config.openpgp_tool == "gpg":
        calculate_signature_gpg(context)
    else:
        calculate_signature_sop(context)


def calculate_signature_gpg(context: Context) -> None:
    cmdline: list[PathString] = ["gpg", "--detach-sign", "--pinentry-mode", "loopback"]

    # Need to specify key before file to sign
    if context.config.key is not None:
        cmdline += ["--default-key", context.config.key]

    cmdline += [
        "--output",
        workdir(context.staging / context.config.output_signature),
        workdir(context.staging / context.config.output_checksum),
    ]

    home = Path(context.config.finalize_environment().get("GNUPGHOME", Path.home() / ".gnupg"))
    if not home.exists():
        die(f"GPG home {home} not found")

    env = dict(GNUPGHOME=os.fspath(workdir(home)))
    if sys.stderr.isatty():
        env |= dict(GPG_TTY=os.ttyname(sys.stderr.fileno()))

    options: list[PathString] = [
        "--bind", home, workdir(home),
        "--bind", context.staging, workdir(context.staging),
        "--bind", "/run", "/run",
    ]  # fmt: skip

    with complete_step("Signing SHA256SUMS…"):
        run(
            cmdline,
            env=env,
            sandbox=context.sandbox(options=options),
        )


def calculate_signature_sop(context: Context) -> None:
    if context.config.key is None:
        die("Signing key is mandatory when using SOP signing")

    with (
        complete_step("Signing SHA256SUMS…"),
        open(context.staging / context.config.output_checksum, "rb") as i,
        open(context.staging / context.config.output_signature, "wb") as o,
    ):
        run(
            [context.config.openpgp_tool, "sign", "/signing-key.pgp"],
            env=context.config.finalize_environment(),
            stdin=i,
            stdout=o,
            sandbox=context.sandbox(
                options=[
                    "--bind", context.config.key, "/signing-key.pgp",
                    "--bind", context.staging, workdir(context.staging),
                    "--bind", "/run", "/run",
                ],
            ),
        )  # fmt: skip


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


def save_manifest(context: Context, manifest: Optional[Manifest]) -> None:
    if not manifest:
        return

    if manifest.has_data():
        if ManifestFormat.json in context.config.manifest_format:
            with complete_step(f"Saving manifest {context.config.output_manifest}"):
                with open(context.staging / context.config.output_manifest, "w") as f:
                    manifest.write_json(f)

        if ManifestFormat.changelog in context.config.manifest_format:
            with complete_step(f"Saving report {context.config.output_changelog}"):
                with open(context.staging / context.config.output_changelog, "w") as f:
                    manifest.write_package_report(f)


def print_output_size(path: Path) -> None:
    if path.is_dir():
        log_step(f"{path} size is " + format_bytes(dir_size(path)) + ".")
    else:
        size = format_bytes(path.stat().st_size)
        space = format_bytes(path.stat().st_blocks * 512)
        log_step(f"{path} size is {size}, consumes {space}.")


def cache_tree_paths(config: Config) -> tuple[Path, Path, Path]:
    if config.image == "tools":
        return (
            config.output_dir_or_cwd() / "mkosi.tools",
            config.output_dir_or_cwd() / "mkosi.tools.build.cache",
            config.output_dir_or_cwd() / "mkosi.tools.manifest",
        )

    assert config.cache_dir
    return (
        config.cache_dir / f"{config.expand_key_specifiers(config.cache_key)}.cache",
        config.cache_dir / f"{config.expand_key_specifiers(config.cache_key)}.build.cache",
        config.cache_dir / f"{config.expand_key_specifiers(config.cache_key)}.manifest",
    )


def keyring_cache(config: Config) -> Path:
    assert config.cache_dir
    return config.cache_dir / f"{config.expand_key_specifiers(config.cache_key)}.keyring.cache"


def metadata_cache(config: Config) -> Path:
    assert config.cache_dir
    return config.cache_dir / f"{config.expand_key_specifiers(config.cache_key)}.metadata.cache"


def check_inputs(config: Config) -> None:
    """
    Make sure all the inputs exist that aren't checked during config parsing because they might
    be created by an earlier build.
    """
    if config.overlay and not config.base_trees:
        die("--overlay=yes can only be used with --base-tree=")

    if config.is_incremental() and not config.cache_dir:
        die("A cache directory must be configured in order to use --incremental=yes")

    for base in config.base_trees:
        if not base.exists():
            die(f"Base tree {base} not found")

        if base.is_file() and base.suffix == ".raw" and os.getuid() != 0:
            die("Must run as root to use disk images in base trees")

    if config.tools_tree and not config.tools_tree.exists():
        die(f"Tools tree {config.tools_tree} not found")

    trees_with_name = [
        ("skeleton", config.skeleton_trees),
        ("sandbox", config.sandbox_trees),
    ]

    if config.output_format != OutputFormat.none:
        trees_with_name += [("extra", config.extra_trees)]

    for name, trees in trees_with_name:
        for tree in trees:
            if not tree.source.exists():
                die(f"{name.capitalize()} tree {tree.source} not found")

            if (
                tree.source.is_file()
                and tree.source.suffix == ".raw"
                and not tree.target
                and os.getuid() != 0
            ):
                die(f"Must run as root to use disk images in {name} trees")

    if config.output_format != OutputFormat.none and config.bootable != ConfigFeature.disabled:
        for p in config.initrds:
            if not p.exists():
                die(f"Initrd {p} not found")
            if not p.is_file():
                die(f"Initrd {p} is not a file")

    for script in itertools.chain(
        config.sync_scripts,
        config.prepare_scripts,
        config.build_scripts,
        config.postinst_scripts,
        config.finalize_scripts,
        config.postoutput_scripts,
    ):
        if not os.access(script, os.X_OK):
            die(f"{script} is not executable")

    if config.secure_boot and not config.secure_boot_key:
        die(
            "SecureBoot= is enabled but no secure boot key is configured",
            hint="Run mkosi genkey to generate a key/certificate pair",
        )

    if config.secure_boot and not config.secure_boot_certificate:
        die(
            "SecureBoot= is enabled but no secure boot certificate is configured",
            hint="Run mkosi genkey to generate a key/certificate pair",
        )

    if config.sign_expected_pcr == ConfigFeature.enabled and not config.sign_expected_pcr_key:
        die(
            "SignExpectedPcr= is enabled but no private key is configured",
            hint="Run mkosi genkey to generate a key/certificate pair",
        )

    if config.sign_expected_pcr == ConfigFeature.enabled and not config.sign_expected_pcr_certificate:
        die(
            "SignExpectedPcr= is enabled but no certificate is configured",
            hint="Run mkosi genkey to generate a key/certificate pair",
        )

    if config.secure_boot_key_source != config.sign_expected_pcr_key_source:
        die("Secure boot key source and expected PCR signatures key source have to be the same")

    if config.secure_boot_certificate_source != config.sign_expected_pcr_certificate_source:
        die(
            "Secure boot certificate source and expected PCR signatures certificate source have to be the same"  # noqa: E501
        )  # fmt: skip

    if config.verity == Verity.signed and not config.verity_key:
        die(
            "Verity= is enabled but no verity key is configured",
            hint="Run mkosi genkey to generate a key/certificate pair",
        )

    if config.verity == Verity.signed and not config.verity_certificate:
        die(
            "Verity= is enabled but no verity certificate is configured",
            hint="Run mkosi genkey to generate a key/certificate pair",
        )

    for profile in config.unified_kernel_image_profiles:
        if "ID" not in profile.profile:
            die(
                "UKI Profile is missing ID key in its .profile section",
                hint="Use Profile= to configure the profile ID",
            )


def check_tool(config: Config, *tools: PathString, reason: str, hint: Optional[str] = None) -> Path:
    tool = config.find_binary(*tools)
    if not tool:
        die(f"Could not find '{tools[0]}' which is required to {reason}.", hint=hint)

    return tool


def check_systemd_tool(
    config: Config,
    *tools: PathString,
    version: str,
    reason: str,
    hint: Optional[str] = None,
) -> None:
    tool = check_tool(config, *tools, reason=reason, hint=hint)

    v = systemd_tool_version(tool, sandbox=config.sandbox)
    if v < version:
        die(
            f"Found '{tool}' with version {v} but version {version} or newer is required to {reason}.",
            hint=f"Use ToolsTree=default to get a newer version of '{tools[0]}'.",
        )


def check_ukify(
    config: Config,
    version: str,
    reason: str,
    hint: Optional[str] = None,
) -> None:
    ukify = check_tool(config, "ukify", "/usr/lib/systemd/ukify", reason=reason, hint=hint)

    v = systemd_tool_version(python_binary(config), ukify, sandbox=config.sandbox)
    if v < version:
        die(
            f"Found '{ukify}' with version {v} but version {version} or newer is required to {reason}.",
            hint="Use ToolsTree=default to get a newer version of 'ukify'.",
        )


def check_tools(config: Config, verb: Verb) -> None:
    if verb == Verb.build:
        if config.output_format == OutputFormat.none:
            return

        if (
            want_efi(config) or config.output_format in (OutputFormat.uki, OutputFormat.esp)
        ) and config.unified_kernel_image_profiles:
            # TODO: bump version to 258 once it is released
            check_ukify(
                config,
                version=(
                    "257.999"
                    if any(not profile.sign_expected_pcr for profile in config.unified_kernel_image_profiles)
                    else "257"
                ),
                reason="build unified kernel image profiles",
                hint=("Use ToolsTree=default to download most required tools including ukify automatically"),
            )
        elif want_efi(config) and config.unified_kernel_images == ConfigFeature.enabled:
            check_ukify(
                config,
                version="254",
                reason="build bootable images",
                hint=(
                    "Use ToolsTree=default to download most required tools including ukify "
                    "automatically or use Bootable=no to create a non-bootable image which doesn't "
                    "require ukify"
                ),
            )

        if config.output_format in (OutputFormat.disk, OutputFormat.esp):
            check_systemd_tool(config, "systemd-repart", version="254", reason="build disk images")

        if config.selinux_relabel == ConfigFeature.enabled:
            check_tool(config, "setfiles", reason="relabel files")

        if config.secure_boot_key_source.type != KeySourceType.file:
            check_ukify(
                config,
                version="256",
                reason="sign Unified Kernel Image with OpenSSL engine",
            )

            if want_signed_pcrs(config):
                check_systemd_tool(
                    config,
                    "systemd-measure",
                    "/usr/lib/systemd/systemd-measure",
                    version="256",
                    reason="sign PCR hashes with OpenSSL engine",
                )

        if config.verity_key_source.type != KeySourceType.file:
            check_systemd_tool(
                config,
                "systemd-repart",
                version="256",
                reason="sign verity roothash signature with OpenSSL engine",
            )

        if (
            want_efi(config)
            and config.secure_boot
            and config.secure_boot_auto_enroll
            and (
                not config.find_binary("bootctl")
                or systemd_tool_version("bootctl", sandbox=config.sandbox) < "257"
            )
        ):
            check_tool(config, "sbsiglist", reason="set up systemd-boot secure boot auto-enrollment")
            check_tool(config, "sbvarsign", reason="set up systemd-boot secure boot auto-enrollment")

        if ArtifactOutput.pcrs in config.split_artifacts:
            # TODO: bump version to 258 once it is released
            check_systemd_tool(
                config,
                "systemd-measure",
                "/usr/lib/systemd/systemd-measure",
                version="257.999",
                reason="generate TPM2 policy digests",
            )

    if verb == Verb.boot:
        check_systemd_tool(config, "systemd-nspawn", version="254", reason="boot images")

    if verb in (Verb.vm, Verb.qemu) and config.vmm == Vmm.vmspawn:
        check_systemd_tool(config, "systemd-vmspawn", version="256", reason="boot images with vmspawn")

    if verb == Verb.sysupdate:
        check_systemd_tool(
            config,
            "systemd-sysupdate",
            "/usr/lib/systemd/systemd-sysupdate",
            version="257",
            reason="Update the host system with systemd-sysupdate",
        )


def configure_ssh(context: Context) -> None:
    if context.config.ssh in (Ssh.never, Ssh.runtime):
        return

    if (
        context.config.ssh == Ssh.auto
        and (context.root / "usr/lib/systemd/system-generators/systemd-ssh-generator").exists()
    ):
        # systemd-ssh-generator is installed, so we don't need to configure SSH.
        return

    unitdir = context.root / "usr/lib/systemd/system"
    with umask(~0o755):
        unitdir.mkdir(parents=True, exist_ok=True)

    with umask(~0o644):
        (unitdir / "ssh.socket").write_text(
            textwrap.dedent(
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

        (unitdir / "ssh@.service").write_text(
            textwrap.dedent(
                """\
                [Unit]
                Description=Mkosi SSH Server
                After=sshd-keygen.target

                [Service]
                # We disable PAM because of an openssh-server bug where it sets PAM_RHOST=UNKNOWN when -i is
                # used causing a very slow reverse DNS lookup by pam.
                ExecStart=sshd -i -o UsePAM=no
                StandardInput=socket
                RuntimeDirectoryPreserve=yes
                RuntimeDirectory=sshd
                # ssh always exits with 255 even on normal disconnect, so let's mark that as success so we
                # don't get noisy logs about SSH service failures.
                SuccessExitStatus=255
                """
            )
        )

    preset = context.root / "usr/lib/systemd/system-preset/80-mkosi-ssh.preset"
    with umask(~0o755):
        preset.parent.mkdir(parents=True, exist_ok=True)
    with umask(~0o644):
        preset.write_text("enable ssh.socket\n")


def configure_initrd(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_or_portable_image():
        return

    if (
        not (context.root / "init").exists()
        and not (context.root / "init").is_symlink()
        and (context.root / "usr/lib/systemd/systemd").exists()
    ):
        (context.root / "init").symlink_to("/usr/lib/systemd/systemd")

    if not context.config.make_initrd:
        return

    if (
        not (context.root / "etc/initrd-release").exists()
        and not (context.root / "etc/initrd-release").is_symlink()
    ):
        (context.root / "etc/initrd-release").symlink_to("/etc/os-release")


def configure_clock(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    with umask(~0o644):
        (context.root / "usr/lib/clock-epoch").touch()


def run_depmod(context: Context, *, cache: bool = False) -> None:
    if context.config.overlay or context.config.image == "tools":
        return

    if not cache:
        for modulesd in (context.root / "usr/lib/modules").glob("*"):
            if not modulesd.is_dir() or (
                (modulesd / "updates").exists() and len(list(modulesd.glob("*"))) == 1
            ):
                continue

            process_kernel_modules(
                context,
                modulesd.name,
                modules_include=finalize_kernel_modules_include(
                    context,
                    include=context.config.kernel_modules_include,
                    host=context.config.kernel_modules_include_host,
                ),
                modules_exclude=context.config.kernel_modules_exclude,
                firmware_include=context.config.firmware_include,
                firmware_exclude=context.config.firmware_exclude,
            )

    if context.config.output_format.is_extension_or_portable_image():
        return

    outputs = (
        "modules.dep",
        "modules.dep.bin",
        "modules.symbols",
        "modules.symbols.bin",
    )

    for modulesd in (context.root / "usr/lib/modules").glob("*"):
        if not modulesd.is_dir() or ((modulesd / "updates").exists() and len(list(modulesd.glob("*"))) == 1):
            continue

        if (
            not cache
            and not context.config.kernel_modules_exclude
            and all((modulesd / o).exists() for o in outputs)
        ):
            mtime = (modulesd / "modules.dep").stat().st_mtime
            if all(m.stat().st_mtime <= mtime for m in modulesd.rglob("*.ko*")):
                continue

        with complete_step(f"Running depmod for {modulesd.name}"):
            run(["depmod", "--all", modulesd.name], sandbox=chroot_cmd(root=context.rootoptions))


def run_sysusers(context: Context) -> None:
    if (
        context.config.overlay
        or context.config.output_format.is_extension_image()
        or context.config.image == "tools"
    ):
        return

    if not context.config.find_binary("systemd-sysusers"):
        logging.warning("systemd-sysusers is not installed, not generating system users")
        return

    with complete_step("Generating system users"):
        run(
            ["systemd-sysusers", "--root=/buildroot"],
            sandbox=context.sandbox(options=context.rootoptions()),
        )


def run_tmpfiles(context: Context) -> None:
    if (
        context.config.overlay
        or context.config.output_format.is_extension_image()
        or context.config.image == "tools"
    ):
        return

    if not context.config.find_binary("systemd-tmpfiles"):
        logging.warning("systemd-tmpfiles is not installed, not generating volatile files")
        return

    with complete_step("Generating volatile files"):
        run(
            [
                "systemd-tmpfiles",
                "--root=/buildroot",
                "--boot",
                "--create",
                "--remove",
                # Exclude APIVFS and temporary files directories.
                *(f"--exclude-prefix={d}" for d in ("/tmp", "/var/tmp", "/run", "/proc", "/sys", "/dev")),
                # Exclude /var if we're not invoked as root as all the chown()'s for daemon owned
                # directories will fail.
                *(["--exclude-prefix=/var"] if os.getuid() != 0 or userns_has_single_user() else []),
            ],
            env={"SYSTEMD_TMPFILES_FORCE_SUBVOL": "0"},
            # systemd-tmpfiles can exit with DATAERR or CANTCREAT in some cases which are handled
            # as success by the systemd-tmpfiles service so we handle those as success as well.
            success_exit_status=(0, 65, 73),
            sandbox=context.sandbox(
                options=[
                    *context.rootoptions(),
                    # systemd uses acl.h to parse ACLs in tmpfiles snippets which uses the host's
                    # passwd so we have to symlink the image's passwd to make ACL parsing work.
                    *finalize_passwd_symlinks("/buildroot"),
                    # Sometimes directories are configured to be owned by root in tmpfiles snippets
                    # so we want to make sure those chown()'s succeed by making ourselves the root
                    # user so that the root user exists.
                    "--become-root",
                ],
            ),
        )  # fmt: skip


def run_preset(context: Context) -> None:
    if (
        context.config.overlay
        or context.config.output_format.is_extension_image()
        or context.config.image == "tools"
    ):
        return

    if not context.config.find_binary("systemctl"):
        logging.warning("systemctl is not installed, not applying presets")
        return

    with complete_step("Applying presets…"):
        run(
            ["systemctl", "--root=/buildroot", "preset-all"],
            sandbox=context.sandbox(options=context.rootoptions()),
        )
        run(
            ["systemctl", "--root=/buildroot", "--global", "preset-all"],
            sandbox=context.sandbox(options=context.rootoptions()),
        )


def run_hwdb(context: Context) -> None:
    if (
        context.config.overlay
        or context.config.output_format.is_extension_image()
        or context.config.image == "tools"
    ):
        return

    if not context.config.find_binary("systemd-hwdb"):
        logging.warning("systemd-hwdb is not installed, not generating hwdb")
        return

    with complete_step("Generating hardware database"):
        run(
            ["systemd-hwdb", "--root=/buildroot", "--usr", "--strict", "update"],
            sandbox=context.sandbox(options=context.rootoptions()),
        )

    # Remove any existing hwdb in /etc in favor of the one we just put in /usr.
    (context.root / "etc/udev/hwdb.bin").unlink(missing_ok=True)


def run_firstboot(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_or_portable_image():
        return

    if not context.config.find_binary("systemd-firstboot"):
        logging.warning("systemd-firstboot is not installed, not applying first boot settings")
        return

    password, hashed = context.config.root_password or (None, False)
    if password and not hashed:
        password = run(
            ["openssl", "passwd", "-stdin", "-6"],
            sandbox=context.sandbox(),
            input=password,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    settings = (
        ("--locale",               "firstboot.locale",            context.config.locale),
        ("--locale-messages",      "firstboot.locale-messages",   context.config.locale_messages),
        ("--keymap",               "firstboot.keymap",            context.config.keymap),
        ("--timezone",             "firstboot.timezone",          context.config.timezone),
        ("--hostname",             None,                          context.config.hostname),
        ("--root-password-hashed", "passwd.hashed-password.root", password),
        ("--root-shell",           "passwd.shell.root",           context.config.root_shell),
    )  # fmt: skip

    options = []
    creds = []

    for option, cred, value in settings:
        # Check for None as password might be the empty string
        if value is None:
            continue

        options += [option, value]

        if cred:
            creds += [(cred, value)]

    if not options and not creds:
        return

    with complete_step("Applying first boot settings"):
        run(
            ["systemd-firstboot", "--root=/buildroot", "--force", *options],
            sandbox=context.sandbox(options=context.rootoptions()),
        )

        # Initrds generally don't ship with only /usr so there's not much point in putting the
        # credentials in /usr/lib/credstore.
        if context.config.output_format != OutputFormat.cpio or not context.config.make_initrd:
            with umask(~0o755):
                (context.root / "usr/lib/credstore").mkdir(exist_ok=True)

            for cred, value in creds:
                with umask(~0o600 if "password" in cred else ~0o644):
                    (context.root / "usr/lib/credstore" / cred).write_text(value)


def run_selinux_relabel(context: Context) -> None:
    if not (selinux := want_selinux_relabel(context.config, context.root)):
        return

    setfiles, policy, fc, binpolicy = selinux
    fc = Path("/buildroot") / fc.relative_to(context.root)
    binpolicy = Path("/buildroot") / binpolicy.relative_to(context.root)

    with complete_step(f"Relabeling files using {policy} policy"):
        run(
            [setfiles, "-mFr", "/buildroot", "-T0", "-c", binpolicy, fc, "/buildroot"],
            sandbox=context.sandbox(options=context.rootoptions()),
            check=context.config.selinux_relabel == ConfigFeature.enabled,
        )


def need_build_overlay(config: Config) -> bool:
    return bool(config.build_scripts and (config.build_packages or config.prepare_scripts))


def save_cache(context: Context) -> None:
    if not context.config.is_incremental():
        return

    final, build, manifest = cache_tree_paths(context.config)

    with complete_step("Installing cache copies"):
        rmtree(final)
        move_tree(
            context.root,
            final,
            use_subvolumes=context.config.use_subvolumes,
            sandbox=context.sandbox,
        )

        if need_build_overlay(context.config) and (context.workspace / "build-overlay").exists():
            rmtree(build)
            move_tree(
                context.workspace / "build-overlay",
                build,
                use_subvolumes=context.config.use_subvolumes,
                sandbox=context.sandbox,
            )

        manifest.write_text(
            json.dumps(
                context.config.cache_manifest(),
                cls=JsonEncoder,
                indent=4,
                sort_keys=True,
            )
        )


def have_cache(config: Config) -> bool:
    # The default tools tree is always cached regardless of the incremental mode.
    if not config.is_incremental() and config.image != "tools":
        return False

    final, build, manifest = cache_tree_paths(config)
    if not final.exists():
        logging.debug(f"{final} does not exist, not reusing cached images")
        return False

    if config.image != "tools" and (uid := final.stat().st_uid) != os.getuid():
        logging.debug(
            f"{final} uid ({uid}) does not match user uid ({os.getuid()}), not reusing cached images"
        )
        return False

    if need_build_overlay(config) and not build.exists():
        logging.debug(f"{build} does not exist, not reusing cached images")
        return False

    if manifest.exists():
        prev = json.loads(manifest.read_text())
        new = json.dumps(config.cache_manifest(), cls=JsonEncoder, indent=4, sort_keys=True)
        if prev != json.loads(new):
            logging.info(f"Cache manifest mismatch for {config.image} image, not reusing cached images")
            if ARG_DEBUG.get():
                run(
                    ["diff", "--unified", workdir(manifest), "-"],
                    input=new,
                    check=False,
                    sandbox=config.sandbox(
                        tools=False,
                        options=["--bind", manifest, workdir(manifest)],
                    ),
                )

            return False
    else:
        logging.debug(f"{manifest} does not exist, not reusing cached images")
        return False

    return True


def reuse_cache(context: Context) -> bool:
    if not context.config.is_incremental():
        return False

    final, build, _ = cache_tree_paths(context.config)
    if not final.exists() or (need_build_overlay(context.config) and not build.exists()):
        return False

    with complete_step("Copying cached trees"):
        copy_tree(
            final,
            context.root,
            use_subvolumes=context.config.use_subvolumes,
            sandbox=context.sandbox,
        )

        if need_build_overlay(context.config):
            (context.workspace / "build-overlay").symlink_to(build)

    return True


def save_esp_components(
    context: Context,
) -> tuple[Optional[Path], Optional[str], Optional[Path], list[Path]]:
    if context.config.output_format == OutputFormat.addon:
        stub = systemd_addon_stub_binary(context)
        if not stub.exists():
            die(f"sd-stub not found at /{stub.relative_to(context.root)} in the image")

        return Path(shutil.copy2(stub, context.workspace)), None, None, []

    if context.config.output_format not in (OutputFormat.uki, OutputFormat.esp):
        return None, None, None, []

    try:
        kver, kimg = next(gen_kernel_images(context))
    except StopIteration:
        if context.config.output_format == OutputFormat.uki:
            die("A kernel must be installed in the image to build a UKI")

        return None, None, None, []

    kimg = Path(shutil.copy2(context.root / kimg, context.workspace))

    if not context.config.architecture.to_efi():
        die(f"Architecture {context.config.architecture} does not support UEFI")

    stub = systemd_stub_binary(context)
    if not stub.exists():
        die(f"sd-stub not found at /{stub.relative_to(context.root)} in the image")

    stub = Path(shutil.copy2(stub, context.workspace))
    microcode = build_microcode_initrd(context)

    return stub, kver, kimg, microcode


def make_image(
    context: Context,
    msg: str,
    skip: Sequence[str] = [],
    split: bool = False,
    tabs: bool = False,
    verity: Verity = Verity.disabled,
    definitions: Sequence[Path] = [],
    options: Sequence[PathString] = (),
) -> list[Partition]:
    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--no-pager",
        "--root=/buildroot",
        f"--offline={yes_no(context.config.repart_offline)}",
        "--seed", str(context.config.seed),
        workdir(context.staging / context.config.output_with_format),
    ]  # fmt: skip
    opts: list[PathString] = [
        *options,
        # Make sure we're root so that the mkfs tools invoked by systemd-repart think the files
        # that go into the disk image are owned by root.
        "--become-root",
        "--bind", context.staging, workdir(context.staging),
        *context.rootoptions(),
    ]  # fmt: skip

    if not context.config.architecture.is_native():
        cmdline += ["--architecture", str(context.config.architecture)]
    if not (context.staging / context.config.output_with_format).exists():
        cmdline += ["--empty=create"]
    if context.config.passphrase:
        cmdline += ["--key-file", workdir(context.config.passphrase)]
        opts += ["--ro-bind", context.config.passphrase, workdir(context.config.passphrase)]
    if skip:
        cmdline += ["--defer-partitions", ",".join(skip)]
    if split:
        cmdline += ["--split=yes"]
    if context.config.sector_size:
        cmdline += ["--sector-size", str(context.config.sector_size)]
    if tabs and systemd_tool_version("systemd-repart", sandbox=context.sandbox) >= 256:
        cmdline += [
            "--generate-fstab=/etc/fstab",
            "--generate-crypttab=/etc/crypttab",
        ]

    for d in definitions:
        cmdline += ["--definitions", workdir(d)]
        opts += ["--ro-bind", d, workdir(d)]

    def can_orphan_file(distribution: Optional[Distribution], release: Optional[str]) -> bool:
        if distribution is None:
            return True

        return not (
            (distribution == Distribution.centos and release and GenericVersion(release) == 9)
            or (distribution == Distribution.ubuntu and release == "jammy")
        )

    # Make sure the ext4 orphan_file feature is disabled if the target distribution official kernel does not
    # support it.
    env = {}
    if (
        not can_orphan_file(context.config.distribution, context.config.release)
        and can_orphan_file(*detect_distribution(context.config.tools()))
        and "SYSTEMD_REPART_MKFS_EXT4_OPTIONS" not in context.config.environment
    ):
        env["SYSTEMD_REPART_MKFS_EXT4_OPTIONS"] = "-O ^orphan_file"

    with complete_step(msg):
        output = json.loads(
            run_systemd_sign_tool(
                context.config,
                cmdline=cmdline,
                options=opts,
                certificate=(
                    context.config.verity_certificate if verity in (Verity.auto, Verity.signed) else None
                ),
                certificate_source=context.config.verity_certificate_source,
                key=context.config.verity_key if verity in (Verity.auto, Verity.signed) else None,
                key_source=context.config.verity_key_source,
                env=env,
                stdout=subprocess.PIPE,
                devices=not context.config.repart_offline,
            ).stdout
        )

    logging.debug(json.dumps(output, indent=4))

    partitions = [Partition.from_dict(d) for d in output]
    arch = context.config.architecture

    if verity == Verity.signed and not any(
        p.type.startswith(f"usr-{arch}-verity-sig") or p.type.startswith(f"root-{arch}-verity-sig")
        for p in partitions
    ):
        die(
            "Verity is explicitly enabled but didn't find any verity signature partition",
            hint="Make sure to add verity signature partitions in mkosi.repart if building a disk image",
        )

    if split:
        for p in partitions:
            if p.split_path:
                maybe_compress(context, context.config.compress_output, p.split_path)

    if ArtifactOutput.roothash in context.config.split_artifacts and (
        roothash := finalize_roothash(partitions)
    ):
        (context.staging / context.config.output_split_roothash).write_text(roothash.partition("=")[2])

    return partitions


def make_disk(
    context: Context,
    msg: str,
    skip: Sequence[str] = [],
    split: bool = False,
    tabs: bool = False,
) -> list[Partition]:
    if context.config.output_format != OutputFormat.disk:
        return []

    if context.config.repart_dirs:
        definitions = context.config.repart_dirs
    else:
        defaults = context.workspace / "repart-definitions"
        if not defaults.exists():
            defaults.mkdir()
            if context.config.architecture.to_efi():
                bootloader = context.root / efi_boot_binary(context)
            else:
                bootloader = None

            esp = context.config.bootable == ConfigFeature.enabled or (
                context.config.bootable == ConfigFeature.auto and bootloader and bootloader.exists()
            )
            bios = context.config.bootable != ConfigFeature.disabled and want_grub_bios(context)

            if esp or bios:
                # Even if we're doing BIOS, let's still use the ESP to store the kernels, initrds
                # and grub modules. We can't use UKIs so we have to put each kernel and initrd on
                # the ESP twice, so let's make the ESP twice as big in that case.
                (defaults / "00-esp.conf").write_text(
                    textwrap.dedent(
                        f"""\
                        [Partition]
                        Type=esp
                        Format=vfat
                        CopyFiles=/boot:/
                        CopyFiles=/efi:/
                        SizeMinBytes={"1G" if bios else "512M"}
                        SizeMaxBytes={"1G" if bios else "512M"}
                        """
                    )
                )

            # If grub for BIOS is installed, let's add a BIOS boot partition onto which we can
            # install grub.
            if bios:
                (defaults / "05-bios.conf").write_text(
                    textwrap.dedent(
                        f"""\
                        [Partition]
                        Type={Partition.GRUB_BOOT_PARTITION_UUID}
                        SizeMinBytes=1M
                        SizeMaxBytes=1M
                        """
                    )
                )

            (defaults / "10-root.conf").write_text(
                textwrap.dedent(
                    f"""\
                    [Partition]
                    Type=root
                    Format={context.config.distribution.filesystem()}
                    CopyFiles=/
                    Minimize=guess
                    """
                )
            )

        definitions = [defaults]

    if context.config.verity == Verity.defer:
        skip = [
            *skip,
            f"root-{context.config.architecture}-verity-sig",
            f"usr-{context.config.architecture}-verity-sig",
        ]

    return make_image(
        context,
        msg=msg,
        skip=skip,
        split=split,
        tabs=tabs,
        verity=context.config.verity,
        definitions=definitions,
    )


def make_oci(context: Context, root_layer: Path, dst: Path) -> None:
    ca_store = dst / "blobs" / "sha256"
    with umask(~0o755):
        ca_store.mkdir(parents=True)

    layer_diff_digest = hash_file(root_layer)
    maybe_compress(
        context,
        context.config.compress_output,
        context.staging / "rootfs.layer",
        # Pass explicit destination to suppress adding an extension
        context.staging / "rootfs.layer",
    )
    layer_digest = hash_file(root_layer)
    root_layer.rename(ca_store / layer_digest)

    creation_time = (
        datetime.datetime.fromtimestamp(context.config.source_date_epoch, tz=datetime.timezone.utc)
        if context.config.source_date_epoch is not None
        else datetime.datetime.now(tz=datetime.timezone.utc)
    ).isoformat()

    oci_config = {
        "created": creation_time,
        "architecture": context.config.architecture.to_oci(),
        # Name of the operating system which the image is built to run on as defined by
        # https://github.com/opencontainers/image-spec/blob/v1.0.2/config.md#properties.
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": [f"sha256:{layer_diff_digest}"],
        },
        "config": {
            "Cmd": [
                "/sbin/init",
                *context.config.kernel_command_line,
            ],
        },
        "history": [
            {
                "created": creation_time,
                "comment": "Created by mkosi",
            },
        ],
    }
    oci_config_blob = json.dumps(oci_config)
    oci_config_digest = hashlib.sha256(oci_config_blob.encode()).hexdigest()
    with umask(~0o644):
        (ca_store / oci_config_digest).write_text(oci_config_blob)

    layer_suffix = context.config.compress_output.oci_media_type_suffix()
    oci_manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": f"sha256:{oci_config_digest}",
            "size": (ca_store / oci_config_digest).stat().st_size,
        },
        "layers": [
            {
                "mediaType": f"application/vnd.oci.image.layer.v1.tar{layer_suffix}",
                "digest": f"sha256:{layer_digest}",
                "size": (ca_store / layer_digest).stat().st_size,
            }
        ],
        "annotations": {
            "io.systemd.mkosi.version": __version__,
            **(
                {
                    "org.opencontainers.image.version": context.config.image_version,
                }
                if context.config.image_version
                else {}
            ),
        },
    }
    oci_manifest_blob = json.dumps(oci_manifest)
    oci_manifest_digest = hashlib.sha256(oci_manifest_blob.encode()).hexdigest()
    with umask(~0o644):
        (ca_store / oci_manifest_digest).write_text(oci_manifest_blob)

        (dst / "index.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": f"sha256:{oci_manifest_digest}",
                            "size": (ca_store / oci_manifest_digest).stat().st_size,
                        }
                    ],
                }
            )
        )

        (dst / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))


def make_esp(
    context: Context,
    stub: Optional[Path],
    kver: Optional[str],
    kimg: Optional[Path],
    microcode: list[Path],
) -> list[Partition]:
    if not context.config.architecture.to_efi():
        die(f"Architecture {context.config.architecture} does not support UEFI")

    if stub and kver and kimg:
        token = find_entry_token(context)
        uki = context.root / finalize_uki_path(
            context, finalize_bootloader_entry_format(context, kver, token)
        )
        with umask(~0o700):
            uki.parent.mkdir(parents=True, exist_ok=True)

        make_uki(context, stub, kver, kimg, microcode, uki)

    definitions = context.workspace / "esp-definitions"
    definitions.mkdir(exist_ok=True)

    # Use a minimum of 36MB or 260MB depending on sector size because otherwise the generated FAT
    # filesystem will have too few clusters to be considered a FAT32 filesystem by OVMF which will
    # refuse to boot from it. See
    # https://superuser.com/questions/1702331/what-is-the-minimum-size-of-a-4k-native-partition-when-formatted-with-fat32/1717643#1717643
    if context.config.sector_size == 512:
        m = 36
    # TODO: Figure out minimum size for 2K sector size
    else:
        m = 260

    size = dir_size(context.root / "boot") + dir_size(context.root / "efi")
    # Always reserve 10MB for filesystem metadata.
    size = max(size, (m - 10) * 1024**2) + 10 * 1024**2

    # TODO: Remove the extra 4096 for the max size once
    # https://github.com/systemd/systemd/pull/29954 is in a stable release.
    (definitions / "00-esp.conf").write_text(
        textwrap.dedent(
            f"""\
            [Partition]
            Type=esp
            Format=vfat
            CopyFiles=/boot:/
            CopyFiles=/efi:/
            SizeMinBytes={size}
            SizeMaxBytes={size + 4096}
            """
        )
    )

    return make_image(
        context,
        msg="Generating ESP image",
        definitions=[definitions],
    )


def make_extension_or_portable_image(context: Context, output: Path) -> None:
    if context.config.verity == Verity.disabled or (
        context.config.verity == Verity.auto
        and (not context.config.verity_key or not context.config.verity_certificate)
    ):
        unsigned = "-unsigned"
    else:
        unsigned = ""

    r = context.resources / f"repart/definitions/{context.config.output_format}{unsigned}.repart.d"

    cmdline: list[PathString] = [
        "systemd-repart",
        "--root=/buildroot",
        "--json=pretty",
        "--dry-run=no",
        "--no-pager",
        f"--offline={yes_no(context.config.repart_offline)}",
        "--seed", str(context.config.seed) if context.config.seed else "random",
        "--empty=create",
        "--size=auto",
        "--definitions", workdir(r),
        workdir(output),
    ]  # fmt: skip
    options: list[PathString] = [
        # Make sure we're root so that the mkfs tools invoked by systemd-repart think the files
        # that go into the disk image are owned by root.
        "--become-root",
        "--bind", output.parent, workdir(output.parent),
        *context.rootoptions(readonly=True),
        "--ro-bind", r, workdir(r),
    ]  # fmt: skip

    if not context.config.architecture.is_native():
        cmdline += ["--architecture", str(context.config.architecture)]
    if context.config.passphrase:
        cmdline += ["--key-file", context.config.passphrase]
        options += ["--ro-bind", context.config.passphrase, workdir(context.config.passphrase)]
    if context.config.sector_size:
        cmdline += ["--sector-size", str(context.config.sector_size)]
    if ArtifactOutput.partitions in context.config.split_artifacts:
        cmdline += ["--split=yes"]

    verity = [
        f"root-{context.config.architecture}-verity-sig",
        f"usr-{context.config.architecture}-verity-sig",
    ]
    if context.config.verity == Verity.hash:
        cmdline += [f"--exclude-partitions={','.join(verity)}"]
    elif context.config.verity == Verity.defer:
        cmdline += [f"--defer-partitions={','.join(verity)}"]

    with complete_step(f"Building {context.config.output_format} extension image"):
        j = json.loads(
            run_systemd_sign_tool(
                context.config,
                cmdline=cmdline,
                options=options,
                certificate=(
                    context.config.verity_certificate
                    if context.config.verity in (Verity.auto, Verity.signed)
                    else None
                ),
                certificate_source=context.config.verity_certificate_source,
                key=(
                    context.config.verity_key
                    if context.config.verity in (Verity.auto, Verity.signed)
                    else None
                ),
                key_source=context.config.verity_key_source,
                stdout=subprocess.PIPE,
                devices=not context.config.repart_offline,
            ).stdout
        )

    logging.debug(json.dumps(j, indent=4))

    if ArtifactOutput.partitions in context.config.split_artifacts:
        for p in (Partition.from_dict(d) for d in j):
            if p.split_path:
                maybe_compress(context, context.config.compress_output, p.split_path)


def finalize_staging(context: Context) -> None:
    rmtree(
        *(context.config.output_dir_or_cwd() / f.name for f in context.staging.iterdir()),
        sandbox=context.sandbox,
    )

    for f in context.staging.iterdir():
        if f.is_symlink():
            (context.config.output_dir_or_cwd() / f.name).symlink_to(f.readlink())
            continue

        if f.is_file() and context.config.output_mode is not None:
            os.chmod(f, context.config.output_mode)

        move_tree(
            f,
            context.config.output_dir_or_cwd(),
            use_subvolumes=context.config.use_subvolumes,
            sandbox=context.sandbox,
        )


def clamp_mtime(path: Path, mtime: int) -> None:
    st = os.stat(path, follow_symlinks=False)
    orig = (st.st_atime_ns, st.st_mtime_ns)
    updated = (min(orig[0], mtime * 1_000_000_000),
               min(orig[1], mtime * 1_000_000_000))  # fmt: skip
    if orig != updated:
        os.utime(path, ns=updated, follow_symlinks=False)


def normalize_mtime(root: Path, mtime: Optional[int], directory: Path = Path("")) -> None:
    if mtime is None:
        return

    if not (root / directory).exists():
        return

    with complete_step(f"Normalizing modification times of /{directory}"):
        clamp_mtime(root / directory, mtime)
        for p in (root / directory).rglob("*"):
            clamp_mtime(p, mtime)


@contextlib.contextmanager
def setup_workspace(args: Args, config: Config) -> Iterator[Path]:
    with contextlib.ExitStack() as stack:
        workspace = Path(tempfile.mkdtemp(dir=config.workspace_dir_or_default(), prefix="mkosi-workspace-"))
        # Discard setuid/setgid bits as these are inherited and can leak into the image.
        workspace.chmod(stat.S_IMODE(workspace.stat().st_mode) & ~(stat.S_ISGID | stat.S_ISUID))
        # Explicitly pass the "root" subdirectory first because on btrfs it's likely a subvolume and this
        # allows us to delete it with btrfs subvolume delete instead of a costly rm -rf.
        stack.callback(lambda: rmtree(workspace / "root", workspace, sandbox=config.sandbox))
        (workspace / "tmp").mkdir(mode=0o1777)

        with scopedenv({"TMPDIR": os.fspath(workspace / "tmp")}):
            try:
                yield Path(workspace)
            finally:
                if args.debug_workspace:
                    stack.pop_all()
                    log_notice(f"Workspace: {workspace}")


@contextlib.contextmanager
def lock_repository_metadata(config: Config) -> Iterator[None]:
    subdir = config.distribution.package_manager(config).subdir(config)

    with contextlib.ExitStack() as stack:
        for d in ("cache", "lib"):
            if (src := config.package_cache_dir_or_default() / d / subdir).exists():
                stack.enter_context(flock(src))

        yield


def copy_repository_metadata(config: Config, dst: Path) -> None:
    subdir = config.distribution.package_manager(config).subdir(config)

    with complete_step("Copying repository metadata"):
        cachedir = config.package_cache_dir_or_default() / "cache" / subdir
        if cachedir.exists():
            with umask(~0o755):
                (dst / "cache" / subdir).mkdir(parents=True, exist_ok=True)

            with tempfile.TemporaryDirectory() as tmp:
                os.chmod(tmp, 0o755)

                # cp doesn't support excluding directories but we can imitate it by bind mounting
                # an empty directory over the directories we want to exclude.
                exclude = flatten(
                    ("--ro-bind", tmp, workdir(p))
                    for p in config.distribution.package_manager(config).package_subdirs(cachedir)
                )

                subdst = dst / "cache" / subdir
                with umask(~0o755):
                    subdst.mkdir(parents=True, exist_ok=True)

                def sandbox(
                    *,
                    options: Sequence[PathString] = (),
                ) -> AbstractContextManager[list[PathString]]:
                    return config.sandbox(options=[*options, *exclude])

                copy_tree(cachedir, subdst, sandbox=sandbox)
        else:
            logging.debug(f"{cachedir} does not exist, not copying repository metadata from it")

        statedir = config.package_cache_dir_or_default() / "lib" / subdir

        with umask(~0o755):
            (dst / "lib" / subdir).mkdir(parents=True, exist_ok=True)

        for src in config.distribution.package_manager(config).state_subdirs(statedir):
            if not src.exists():
                logging.debug(f"{src} does not exist, not copying repository metadata from it")
                continue

            subdst = dst / "lib" / subdir / src.relative_to(statedir)
            with umask(~0o755):
                subdst.mkdir(parents=True, exist_ok=True)

            copy_tree(src, subdst, sandbox=config.sandbox)


@contextlib.contextmanager
def createrepo(context: Context) -> Iterator[None]:
    st = context.repository.stat()
    try:
        yield
    finally:
        if context.repository.stat().st_mtime_ns != st.st_mtime_ns:
            with complete_step("Rebuilding local package repository"):
                context.config.distribution.createrepo(context)


def make_rootdir(context: Context) -> None:
    if context.root.exists():
        return

    with umask(~0o755):
        # Using a btrfs subvolume as the upperdir in an overlayfs results in EXDEV so make sure we
        # create the root directory as a regular directory if the Overlay= option is enabled.
        if context.config.overlay:
            context.root.mkdir()
        else:
            make_tree(context.root, use_subvolumes=context.config.use_subvolumes, sandbox=context.sandbox)


def build_image(context: Context) -> None:
    manifest = Manifest(context) if context.config.manifest_format else None

    install_sandbox_trees(context.config, context.sandbox_tree)

    with mount_base_trees(context):
        install_base_trees(context)
        cached = reuse_cache(context)
        make_rootdir(context)

        wantrepo = (
            (
                not cached
                and (
                    context.config.packages
                    or context.config.build_packages
                    or context.config.prepare_scripts
                )
            )
            or context.config.volatile_packages
            or context.config.postinst_scripts
            or context.config.finalize_scripts
        )

        context.config.distribution.setup(context)
        if wantrepo:
            with createrepo(context):
                install_package_directories(context, context.config.package_directories)
                install_package_directories(context, context.config.volatile_package_directories)
                install_package_directories(context, [context.package_dir])

        if not cached:
            install_skeleton_trees(context)
            install_distribution(context)
            run_prepare_scripts(context, build=False)
            install_build_packages(context)
            run_prepare_scripts(context, build=True)
            fixup_vmlinuz_location(context)
            run_depmod(context, cache=True)

            save_cache(context)
            reuse_cache(context)

        check_root_populated(context)
        run_build_scripts(context)

        if context.config.output_format == OutputFormat.none or context.args.rerun_build_scripts:
            return

        if wantrepo:
            with createrepo(context):
                install_package_directories(context, [context.package_dir])

        install_volatile_packages(context)
        install_build_dest(context)
        install_extra_trees(context)
        run_postinst_scripts(context)
        fixup_vmlinuz_location(context)

        configure_autologin(context)
        configure_os_release(context)
        configure_extension_release(context)
        configure_initrd(context)
        configure_ssh(context)
        configure_clock(context)

        install_systemd_boot(context)
        install_grub(context)
        install_shim(context)
        run_sysusers(context)
        run_tmpfiles(context)
        run_preset(context)
        run_depmod(context)
        run_firstboot(context)
        run_hwdb(context)

        # These might be removed by the next steps, so let's save them for later if needed.
        stub, kver, kimg, microcode = save_esp_components(context)

        remove_packages(context)

        if manifest:
            manifest.record_packages()

        run_selinux_relabel(context)

    clean_package_manager_metadata(context)
    remove_files(context)
    run_finalize_scripts(context)

    rmtree(context.root / "work")

    normalize_mtime(context.root, context.config.source_date_epoch)
    partitions = make_disk(context, skip=("esp", "xbootldr"), tabs=True, msg="Generating disk image")
    install_kernel(context, partitions)
    normalize_mtime(context.root, context.config.source_date_epoch, directory=Path("boot"))
    normalize_mtime(context.root, context.config.source_date_epoch, directory=Path("efi"))
    partitions = make_disk(context, msg="Formatting ESP/XBOOTLDR partitions")
    grub_bios_setup(context, partitions)

    if ArtifactOutput.partitions in context.config.split_artifacts:
        make_disk(context, split=True, msg="Extracting partitions")

    if (
        context.config.output_format != OutputFormat.tar
        and ArtifactOutput.tar in context.config.split_artifacts
    ):
        make_tar(context.root, context.staging / context.config.output_tar, sandbox=context.sandbox)

    copy_nspawn_settings(context)
    copy_uki(context)
    copy_vmlinuz(context)
    copy_initrd(context)

    if context.config.output_format == OutputFormat.tar:
        make_tar(context.root, context.staging / context.config.output_with_format, sandbox=context.sandbox)
    elif context.config.output_format == OutputFormat.oci:
        make_tar(context.root, context.staging / "rootfs.layer", sandbox=context.sandbox)
        make_oci(
            context,
            context.staging / "rootfs.layer",
            context.staging / context.config.output_with_format,
        )
    elif context.config.output_format == OutputFormat.cpio:
        make_cpio(context.root, context.staging / context.config.output_with_format, sandbox=context.sandbox)
    elif context.config.output_format == OutputFormat.uki:
        assert stub and kver and kimg
        make_uki(context, stub, kver, kimg, microcode, context.staging / context.config.output_with_format)
    elif context.config.output_format == OutputFormat.esp:
        make_esp(context, stub, kver, kimg, microcode)
    elif context.config.output_format == OutputFormat.addon:
        assert stub
        make_addon(context, stub, context.staging / context.config.output_with_format)
    elif context.config.output_format.is_extension_or_portable_image():
        make_extension_or_portable_image(context, context.staging / context.config.output_with_format)
    elif context.config.output_format == OutputFormat.directory:
        context.root.rename(context.staging / context.config.output_with_format)

    if context.config.output_format.use_outer_compression():
        maybe_compress(
            context,
            context.config.compress_output,
            context.staging / context.config.output_with_format,
            context.staging / context.config.output_with_compression,
        )

    calculate_sha256sum(context)
    calculate_signature(context)
    save_manifest(context, manifest)

    output_base = context.staging / context.config.output
    if not output_base.exists() or output_base.is_symlink():
        output_base.unlink(missing_ok=True)
        output_base.symlink_to(context.config.output_with_compression)

    run_postoutput_scripts(context)
    finalize_staging(context)

    print_output_size(context.config.output_dir_or_cwd() / context.config.output_with_compression)


def run_sandbox(args: Args, config: Config) -> None:
    if in_sandbox():
        die(
            "mkosi sandbox cannot be invoked from within another mkosi sandbox environment",
            hint="Exit the current sandbox environment and try again",
        )

    if not args.cmdline:
        die("Please specify a command to execute in the sandbox")

    mounts = finalize_certificate_mounts(config, relaxed=True)

    if config.tools() != Path("/") and (config.tools() / "etc/crypto-policies").exists():
        mounts += ["--ro-bind", config.tools() / "etc/crypto-policies", Path("/etc/crypto-policies")]

    # Since we reuse almost every top level directory from the host except /usr, the crypto mountpoints
    # have to exist already in these directories or we'll fail with a permission error. Let's check this
    # early and show a better error and a suggestion on how users can fix this issue. We use slice
    # notation to get every 3rd item from the mounts list which is the destination path.
    for dst in mounts[2::3]:
        if not Path(dst).exists():
            die(
                f"Missing mountpoint {dst}",
                hint=f"Create an empty directory at {dst} using 'mkdir -p {dst}' as root and try again",
            )

    hd, hr = detect_distribution()

    env = {"MKOSI_IN_SANDBOX": "1"}
    if hd:
        env |= {"MKOSI_HOST_DISTRIBUTION": str(hd)}
    if hr:
        env |= {"MKOSI_HOST_RELEASE": hr}
    if config.tools() != Path("/"):
        env |= {"MKOSI_DEFAULT_TOOLS_TREE_PATH": os.fspath(config.tools())}

    cmdline = [*args.cmdline]

    if sys.stdin.isatty() and config.find_binary("systemd-pty-forward"):
        cmdline = [
            "systemd-pty-forward",
            "--title=mkosi-sandbox",
            "--background=48;2;12;51;51",  # cyan
            *cmdline,
        ]

    with contextlib.ExitStack() as stack:
        if config.tools() != Path("/"):
            d = stack.enter_context(tempfile.TemporaryDirectory(prefix="mkosi-path-"))

            # We have to point zipapp to a directory containing the mkosi module and set the entrypoint
            # manually instead of directly at the mkosi package, otherwise we get ModuleNotFoundError when
            # trying to run a zipapp created from a packaged version of mkosi. While zipapp.create_archive()
            # supports a filter= argument, trying to use this within a site-packages directory is rather slow
            # so we copy the mkosi package to a temporary directory instead which is much faster.
            with (
                tempfile.TemporaryDirectory(prefix="mkosi-zipapp-") as tmp,
                resource_path(sys.modules[__package__ or __name__]) as module,
            ):
                copy_tree(module, Path(tmp) / module.name, sandbox=config.sandbox)
                zipapp.create_archive(
                    source=tmp,
                    target=Path(d) / "mkosi",
                    main="mkosi.__main__:main",
                    interpreter="/usr/bin/env python3",
                )

            make_executable(Path(d) / "mkosi")
            mounts += ["--ro-bind", d, "/mkosi"]
            stack.enter_context(scopedenv({"PATH": f"/mkosi:{os.environ['PATH']}"}))

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | env,
            log=False,
            sandbox=config.sandbox(
                devices=True,
                network=True,
                relaxed=True,
                options=["--same-dir", *mounts],
            ),
        )


def run_shell(args: Args, config: Config) -> None:
    opname = "acquire shell in" if args.verb == Verb.shell else "boot"
    if config.output_format not in (OutputFormat.directory, OutputFormat.disk):
        die(f"Cannot {opname} {config.output_format} images with systemd-nspawn")
    if config.output_format.use_outer_compression() and config.compress_output:
        die(f"Cannot {opname} compressed {config.output_format} images with systemd-nspawn")

    cmdline: list[PathString] = ["systemd-nspawn", "--quiet", "--link-journal=no"]

    if config.runtime_network == Network.user:
        cmdline += ["--resolv-conf=auto"]
    elif config.runtime_network == Network.interface:
        cmdline += ["--private-network", "--network-veth"]
    elif config.runtime_network == Network.none:
        cmdline += ["--private-network"]

    # If we copied in a .nspawn file, make sure it's actually honoured
    if config.nspawn_settings:
        cmdline += ["--settings=trusted"]

    if args.verb == Verb.boot:
        cmdline += ["--boot"]
    else:
        cmdline += [
            f"--rlimit=RLIMIT_CORE={format_rlimit(resource.RLIMIT_CORE)}",
            "--console=autopipe",
        ]

    # Underscores are not allowed in machine names so replace them with hyphens.
    name = config.machine_or_name().replace("_", "-")
    cmdline += ["--machine", name]

    for k, v in finalize_credentials(config).items():
        cmdline += [f"--set-credential={k}:{v}"]

    cmdline += ["--register", yes_no(finalize_register(config))]

    with contextlib.ExitStack() as stack:
        # Make sure the latest nspawn settings are always used.
        if config.nspawn_settings:
            if not (config.output_dir_or_cwd() / f"{name}.nspawn").exists():
                stack.callback(
                    lambda: (config.output_dir_or_cwd() / f"{name}.nspawn").unlink(missing_ok=True)
                )
            shutil.copy2(config.nspawn_settings, config.output_dir_or_cwd() / f"{name}.nspawn")

        # If we're booting a directory image that wasn't built by root, we always make an ephemeral
        # copy to avoid ending up with files not owned by the directory image owner in the
        # directory image.
        if config.ephemeral or (
            config.output_format == OutputFormat.directory
            and args.verb == Verb.boot
            and (config.output_dir_or_cwd() / config.output).stat().st_uid != 0
        ):
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = stack.enter_context(flock_or_die(config.output_dir_or_cwd() / config.output))

        if config.output_format == OutputFormat.disk and args.verb == Verb.boot:
            run(
                [
                    "systemd-repart",
                    "--image", workdir(fname),
                    *([f"--size={config.runtime_size}"] if config.runtime_size else []),
                    "--no-pager",
                    "--dry-run=no",
                    "--offline=no",
                    "--pretty=no",
                    workdir(fname),
                ],
                stdin=sys.stdin,
                env=config.finalize_environment(),
                sandbox=config.sandbox(
                    network=True,
                    devices=True,
                    options=["--bind", fname, workdir(fname)],
                    setup=become_root_cmd(),
                ),
            )  # fmt: skip

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]

            owner = os.stat(fname).st_uid
            if owner != 0:
                # Let's allow running a shell in a non-ephemeral image but in that case only map a
                # single user into the image so it can't get polluted with files or directories
                # owned by other users.
                if (
                    args.verb == Verb.shell
                    and config.output_format == OutputFormat.directory
                    and not config.ephemeral
                ):
                    range = 1
                else:
                    range = 65536

                cmdline += [f"--private-users={owner}:{range}"]
        else:
            cmdline += ["--image", fname]

        if config.runtime_build_sources:
            for t in config.build_sources:
                src, dst = t.with_prefix("/work/src")
                uidmap = "rootidmap" if src.stat().st_uid != 0 else "noidmap"
                cmdline += ["--bind", f"{src}:{dst}:norbind,{uidmap}"]

            if config.build_dir:
                uidmap = "rootidmap" if config.build_subdir.stat().st_uid != 0 else "noidmap"
                cmdline += ["--bind", f"{config.build_subdir}:/work/build:norbind,{uidmap}"]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or "")
            # We add norbind because very often RuntimeTrees= will be used to mount the source
            # directory into the container and the output directory from which we're running will
            # very likely be a subdirectory of the source directory which would mean we'd be
            # mounting the container root directory as a subdirectory in itself which tends to lead
            # to all kinds of weird issues, which we avoid by not doing a recursive mount which
            # means the container root directory mounts will be skipped.
            uidmap = "rootidmap" if tree.source.stat().st_uid != 0 else "noidmap"
            cmdline += ["--bind", f"{tree.source}:{target}:norbind,{uidmap}"]

        if config.runtime_home and (path := current_home_dir()):
            uidmap = "rootidmap" if path.stat().st_uid != 0 else "noidmap"
            cmdline += ["--bind", f"{path}:/root:norbind,{uidmap}"]

        if config.runtime_scratch == ConfigFeature.enabled or (
            config.runtime_scratch == ConfigFeature.auto and config.output_format == OutputFormat.disk
        ):
            scratch = stack.enter_context(tempfile.TemporaryDirectory(dir="/var/tmp"))
            os.chmod(scratch, 0o1777)
            cmdline += ["--bind", f"{scratch}:/var/tmp"]

        if args.verb == Verb.boot and config.forward_journal:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                addr = (
                    Path(os.getenv("TMPDIR", "/tmp")) / f"mkosi-journal-remote-unix-{uuid.uuid4().hex[:16]}"
                )
                sock.bind(os.fspath(addr))
                sock.listen()
                if config.output_format == OutputFormat.directory and (stat := os.stat(fname)).st_uid != 0:
                    os.chown(addr, stat.st_uid, stat.st_gid)
                stack.enter_context(start_journal_remote(config, sock.fileno()))
                cmdline += [
                    f"--bind={addr}:/run/host/journal/socket",
                    "--set-credential=journal.forward_to_socket:/run/host/journal/socket",
                ]

        for p in config.unit_properties:
            cmdline += ["--property", p]

        if args.verb == Verb.boot:
            # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
            argv = args.cmdline

            # When invoked by the kernel, all unknown arguments are passed as environment variables
            # to pid1. Let's mimic the same behavior when we invoke nspawn as a container.
            for arg in itertools.chain(
                config.kernel_command_line,
                finalize_kernel_command_line_extra(config),
            ):
                name, sep, value = arg.partition("=")

                # If there's a '.' in the argument name, it's not considered an environment
                # variable by the kernel.
                if sep and "." not in name:
                    cmdline += ["--setenv", f"{name.replace('-', '_')}={value}"]
                else:
                    # kernel cmdline config of the form systemd.xxx= get interpreted by systemd
                    # when running in nspawn as well.
                    argv += [arg]

            cmdline += argv
        elif args.cmdline:
            cmdline += ["--"]
            cmdline += args.cmdline

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | config.finalize_environment(),
            log=False,
            sandbox=config.sandbox(
                devices=True,
                network=True,
                relaxed=True,
                options=["--same-dir"],
                setup=become_root_cmd(),
            ),
        )


def run_systemd_tool(tool: str, args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        die(f"{config.output_format} images cannot be inspected with {tool}")

    if (
        args.verb in (Verb.journalctl, Verb.coredumpctl)
        and config.output_format == OutputFormat.disk
        and os.getuid() != 0
    ):
        need_root = True
    else:
        need_root = False

    if (tool_path := config.find_binary(tool)) is None:
        die(f"Failed to find {tool}")

    if config.ephemeral:
        die(f"Images booted in ephemeral mode cannot be inspected with {tool}")

    if not (output := config.output_dir_or_cwd() / config.output).exists():
        die(
            f"Output {output} does not exist, cannot inspect with {tool}",
            hint=f"Build and boot the image first before inspecting it with {tool}",
        )

    run(
        [tool_path, "--root" if output.is_dir() else "--image", output, *args.cmdline],
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ | config.finalize_environment(),
        log=False,
        sandbox=config.sandbox(
            network=True,
            devices=config.output_format == OutputFormat.disk,
            relaxed=True,
            setup=become_root_cmd() if need_root else [],
        ),
    )


def run_journalctl(args: Args, config: Config) -> None:
    run_systemd_tool("journalctl", args, config)


def run_coredumpctl(args: Args, config: Config) -> None:
    run_systemd_tool("coredumpctl", args, config)


def start_storage_target_mode(config: Config) -> AbstractContextManager[Optional[Popen]]:
    if config.storage_target_mode == ConfigFeature.disabled:
        return contextlib.nullcontext()

    if config.storage_target_mode == ConfigFeature.auto and os.getuid() != 0:
        return contextlib.nullcontext()

    if config.output_format != OutputFormat.disk:
        if config.storage_target_mode == ConfigFeature.enabled:
            die("Storage target mode is only supported for the 'disk' output format")

        return contextlib.nullcontext()

    if not config.find_binary("/usr/lib/systemd/systemd-storagetm"):
        if config.storage_target_mode == ConfigFeature.enabled:
            die("Storage target mode enabled but systemd-storagetm is not installed")

        return contextlib.nullcontext()

    return spawn(
        ["/usr/lib/systemd/systemd-storagetm", config.output_with_format],
        stdin=sys.stdin,
        stdout=sys.stdout,
        sandbox=config.sandbox(
            network=True,
            relaxed=True,
            options=["--chdir", config.output_dir_or_cwd()],
            setup=become_root_cmd(),
        ),
    )


def run_serve(args: Args, config: Config) -> None:
    """Serve the output directory via a tiny HTTP server"""

    with contextlib.ExitStack() as stack:
        http = stack.enter_context(
            spawn(
                [python_binary(config), "-m", "http.server", "8081"],
                stdin=sys.stdin,
                stdout=sys.stdout,
                sandbox=config.sandbox(
                    network=True,
                    relaxed=True,
                    options=["--chdir", config.output_dir_or_cwd()],
                ),
            )
        )

        storagetm = stack.enter_context(start_storage_target_mode(config))

        # If we run systemd-storagetm with run0, it replaces the foreground process group with its own which
        # means the http process doesn't get SIGINT from the terminal, so let's send it ourselves in that
        # case.
        if storagetm and os.getuid() != 0:
            storagetm.wait()
            http.send_signal(signal.SIGINT)


def generate_key_cert_pair(args: Args) -> None:
    """Generate a private key and accompanying X509 certificate using openssl"""

    keylength = 2048
    expiration_date = datetime.date.today() + datetime.timedelta(int(args.genkey_valid_days))

    configdir = finalize_configdir(args)

    for f in (configdir / "mkosi.key", configdir / "mkosi.crt"):
        if f.exists() and not args.force:
            die(
                f"{f} already exists",
                hint="To generate new keys, first remove mkosi.key and mkosi.crt",
            )

    log_step(f"Generating keys rsa:{keylength} for CN {args.genkey_common_name!r}.")
    logging.info(
        textwrap.dedent(
            f"""
            The keys will expire in {args.genkey_valid_days} days ({expiration_date:%A %d. %B %Y}).
            Remember to roll them over to new ones before then.
            """
        )
    )

    run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-newkey", f"rsa:{keylength}",
            "-keyout", configdir / "mkosi.key",
            "-out", configdir / "mkosi.crt",
            "-days", str(args.genkey_valid_days),
            "-subj", f"/CN={args.genkey_common_name}/",
            "-nodes"
        ],
        env=dict(OPENSSL_CONF="/dev/null"),
    )  # fmt: skip


def finalize_image_version(args: Args, config: Config) -> None:
    p = finalize_configdir(args) / "mkosi.version"
    assert config.image_version
    p.write_text(config.image_version)
    logging.info(f"Wrote new version {config.image_version} to {p}")


def check_workspace_directory(config: Config) -> None:
    wd = config.workspace_dir_or_default()

    for tree in config.build_sources:
        if wd.is_relative_to(tree.source):
            die(
                f"The workspace directory ({wd}) cannot be a subdirectory of "
                f"any source directory ({tree.source})",
                hint="Set BuildSources= to the empty string or use WorkspaceDirectory= to configure "
                "a different workspace directory",
            )


def run_clean_scripts(config: Config) -> None:
    if not config.clean_scripts:
        return

    for script in config.clean_scripts:
        if not os.access(script, os.X_OK):
            die(f"{script} is not executable")

    env = dict(
        DISTRIBUTION=str(config.distribution),
        RELEASE=config.release,
        ARCHITECTURE=str(config.architecture),
        DISTRIBUTION_ARCHITECTURE=config.distribution.architecture(config.architecture),
        SRCDIR="/work/src",
        OUTPUTDIR="/work/out",
        MKOSI_UID=str(os.getuid()),
        MKOSI_GID=str(os.getgid()),
        MKOSI_CONFIG="/work/config.json",
        MKOSI_DEBUG=one_zero(ARG_DEBUG.get()),
    )

    if config.profiles:
        env["PROFILES"] = " ".join(config.profiles)

    with (
        finalize_source_mounts(config, ephemeral=False) as sources,
        finalize_config_json(config) as json,
    ):
        for script in config.clean_scripts:
            with complete_step(f"Running clean script {script}…"):
                run(
                    ["/work/clean"],
                    env=env | config.finalize_environment(),
                    sandbox=config.sandbox(
                        tools=False,
                        options=[
                            "--dir", "/work/src",
                            "--chdir", "/work/src",
                            "--dir", "/work/out",
                            "--ro-bind", script, "/work/clean",
                            "--ro-bind", json, "/work/config.json",
                            *(["--bind", os.fspath(o), "/work/out"] if (o := config.output_dir_or_cwd()).exists() else []),  # noqa: E501
                            *sources,
                        ],
                    ),
                    stdin=sys.stdin,
                )  # fmt: skip


def validate_certificates_and_keys(config: Config) -> None:
    keyutil = config.find_binary("systemd-keyutil", "/usr/lib/systemd/systemd-keyutil")
    if not keyutil:
        return

    if config.verity in (Verity.auto, Verity.signed) and config.verity_certificate and config.verity_key:
        run_systemd_sign_tool(
            config,
            cmdline=[keyutil, "validate"],
            options=[],
            certificate=config.verity_certificate,
            certificate_source=config.verity_certificate_source,
            key=config.verity_key,
            key_source=config.verity_key_source,
            stdout=subprocess.DEVNULL,
        )

    if (
        config.bootable != ConfigFeature.disabled
        and config.secure_boot
        and config.secure_boot_certificate
        and config.secure_boot_key
    ):
        run_systemd_sign_tool(
            config,
            cmdline=[keyutil, "validate"],
            options=[],
            certificate=config.secure_boot_certificate,
            certificate_source=config.secure_boot_certificate_source,
            key=config.secure_boot_key,
            key_source=config.secure_boot_key_source,
            stdout=subprocess.DEVNULL,
        )

    if (
        config.bootable != ConfigFeature.disabled
        and config.sign_expected_pcr != ConfigFeature.disabled
        and config.sign_expected_pcr_certificate
        and config.sign_expected_pcr_key
    ):
        run_systemd_sign_tool(
            config,
            cmdline=[keyutil, "validate"],
            options=[],
            certificate=config.sign_expected_pcr_certificate,
            certificate_source=config.sign_expected_pcr_certificate_source,
            key=config.sign_expected_pcr_key,
            key_source=config.sign_expected_pcr_key_source,
            stdout=subprocess.DEVNULL,
        )


def needs_build(args: Args, config: Config, force: int = 1) -> bool:
    if args.rerun_build_scripts:
        return False

    return (
        (args.force >= force)
        or not (config.output_dir_or_cwd() / config.output_with_compression).exists()
        # When the output is a directory, its name is the same as the symlink we create that points to the
        # actual output when not building a directory. So if the full output path exists, we have to check
        # that it's not a symlink as well.
        or (config.output_dir_or_cwd() / config.output_with_compression).is_symlink()
    )


def remove_cache_entries(config: Config, *, extra: Sequence[Path] = ()) -> None:
    if not config.cache_dir:
        return

    sandbox = functools.partial(config.sandbox, tools=False)

    if any(p.exists() for p in itertools.chain(cache_tree_paths(config), extra)):
        with complete_step(f"Removing cache entries of {config.image} image…"):
            rmtree(
                *(p for p in itertools.chain(cache_tree_paths(config), extra) if p.exists()),
                sandbox=sandbox,
            )


def run_clean(args: Args, config: Config) -> None:
    # We remove any cached images if either the user used --force twice, or he/she called "clean"
    # with it passed once. Let's also remove the downloaded package cache if the user specified one
    # additional "--force".

    # We don't want to require a tools tree to run mkosi clean so we pass in a sandbox that
    # disables use of the tools tree. We still need a sandbox as we need to acquire privileges to
    # be able to remove various files from the rootfs.
    sandbox = functools.partial(config.sandbox, tools=False)

    if args.verb == Verb.clean:
        remove_outputs = True
        remove_build_cache = args.force > 0 or args.wipe_build_dir
        remove_image_cache = args.force > 0
        remove_package_cache = args.force > 1
    else:
        remove_outputs = args.force > 0 or (config.is_incremental() and not have_cache(config))
        remove_build_cache = args.force > 1 or args.wipe_build_dir
        remove_image_cache = args.force > 1 or not have_cache(config)
        remove_package_cache = args.force > 2

    if remove_outputs:
        outputs = {
            config.output_dir_or_cwd() / output
            for output in config.outputs
            if (
                (config.output_dir_or_cwd() / output).exists()
                or (config.output_dir_or_cwd() / output).is_symlink()
            )
        }

        # Make sure we resolve the symlink we create in the output directory and remove its target
        # as well as it might not be in the list of outputs anymore if the compression or output
        # format was changed.
        outputs |= {o.resolve() for o in outputs}

        if outputs:
            with (
                complete_step(f"Removing output files of {config.image} image…"),
                flock_or_die(config.output_dir_or_cwd() / config.output)
                if (config.output_dir_or_cwd() / config.output).exists()
                else contextlib.nullcontext(),
            ):
                rmtree(*outputs, sandbox=sandbox)

        run_clean_scripts(config)

    if (
        remove_build_cache
        and config.build_dir
        and config.build_subdir.exists()
        and any(config.build_subdir.iterdir())
    ):
        with complete_step(f"Clearing out build directory of {config.image} image…"):
            rmtree(*config.build_subdir.iterdir(), sandbox=sandbox)

    if remove_image_cache and config.cache_dir:
        if config.image in ("main", "tools"):
            extra = [keyring_cache(config), metadata_cache(config)]
        else:
            extra = []

        remove_cache_entries(config, extra=extra)

    if remove_package_cache and any(config.package_cache_dir_or_default().glob("*")):
        subdir = config.distribution.package_manager(config).subdir(config)

        with (
            complete_step(f"Clearing out package cache of {config.image} image…"),
            lock_repository_metadata(config),
        ):
            rmtree(
                *(config.package_cache_dir_or_default() / d / subdir for d in ("cache", "lib")),
                sandbox=sandbox,
            )


def ensure_directories_exist(config: Config) -> None:
    for p in (
        config.output_dir,
        config.cache_dir,
        config.package_cache_dir_or_default(),
        config.build_dir,
        config.workspace_dir,
    ):
        if not p or p.exists():
            continue

        p.mkdir(parents=True, exist_ok=True)

    if config.build_dir:
        config.build_subdir.mkdir(exist_ok=True)

        st = config.build_subdir.stat()

        # Discard setuid/setgid bits if set as these are inherited and can leak into the image.
        if stat.S_IMODE(st.st_mode) & (stat.S_ISGID | stat.S_ISUID):
            config.build_subdir.chmod(stat.S_IMODE(st.st_mode) & ~(stat.S_ISGID | stat.S_ISUID))


def sync_repository_metadata(
    args: Args,
    images: Sequence[Config],
    *,
    resources: Path,
    keyring_dir: Path,
    metadata_dir: Path,
) -> None:
    last = images[-1]

    # If we have a metadata cache and any cached image and using cached metadata is not explicitly disabled,
    # reuse the metadata cache.
    if (
        last.is_incremental()
        and keyring_cache(last).exists()
        and metadata_cache(last).exists()
        and last.cacheonly != Cacheonly.never
        and any(have_cache(config) for config in images)
    ):
        if any(keyring_cache(last).iterdir()):
            with complete_step("Copying cached package manager keyring"):
                copy_tree(
                    keyring_cache(last),
                    keyring_dir,
                    use_subvolumes=last.use_subvolumes,
                    sandbox=last.sandbox,
                )

        with complete_step("Copying cached package manager metadata"):
            copy_tree(
                metadata_cache(last),
                metadata_dir,
                use_subvolumes=last.use_subvolumes,
                sandbox=last.sandbox,
            )

        return

    subdir = last.distribution.package_manager(last).subdir(last)

    for d in ("cache", "lib"):
        (last.package_cache_dir_or_default() / d / subdir).mkdir(parents=True, exist_ok=True)

    # Sync repository metadata unless explicitly disabled.
    if last.cacheonly not in (Cacheonly.always, Cacheonly.metadata):
        with setup_workspace(args, last) as workspace:
            context = Context(
                args,
                last,
                workspace=workspace,
                resources=resources,
                keyring_dir=keyring_dir,
                metadata_dir=last.package_cache_dir_or_default(),
            )
            context.root.mkdir(mode=0o755)

            install_sandbox_trees(context.config, context.sandbox_tree)
            context.config.distribution.setup(context)

            context.config.distribution.keyring(context)

            with complete_step("Syncing package manager metadata"), lock_repository_metadata(last):
                context.config.distribution.package_manager(context.config).sync(
                    context,
                    force=context.args.force > 1 or context.config.cacheonly == Cacheonly.never,
                )

    src = last.package_cache_dir_or_default() / "cache" / subdir
    for p in last.distribution.package_manager(last).package_subdirs(src):
        p.mkdir(parents=True, exist_ok=True)

    # If we're in incremental mode and caching metadata is not explicitly disabled, cache the keyring and the
    # synced repository metadata so we can reuse them later.
    if last.is_incremental() and last.cacheonly != Cacheonly.never:
        rmtree(keyring_cache(last), metadata_cache(last), sandbox=last.sandbox)

        for p in (keyring_cache(last), metadata_cache(last)):
            make_tree(p, use_subvolumes=last.use_subvolumes, sandbox=last.sandbox)

        copy_tree(keyring_dir, keyring_cache(last), use_subvolumes=last.use_subvolumes, sandbox=last.sandbox)
        copy_repository_metadata(last, metadata_cache(last))
        copy_tree(
            metadata_cache(last),
            metadata_dir,
            use_subvolumes=last.use_subvolumes,
            sandbox=last.sandbox,
        )
    else:
        copy_repository_metadata(last, metadata_dir)


def run_build(
    args: Args,
    config: Config,
    *,
    resources: Path,
    keyring_dir: Path,
    metadata_dir: Path,
    package_dir: Optional[Path] = None,
) -> None:
    if not have_effective_cap(CAP_SYS_ADMIN):
        acquire_privileges()
        unshare(CLONE_NEWNS)
    else:
        unshare(CLONE_NEWNS)
        mount("", "/", "", MS_SLAVE | MS_REC, "")

    # For extra safety when running as root, remount a bunch of directories read-only unless the output
    # directory is located in it.
    if os.getuid() == 0:
        remount = ["/etc", "/opt", "/boot", "/efi", "/media", "/usr"]

        for d in remount:
            if not Path(d).exists():
                continue

            if any(
                p and p.is_relative_to(d)
                for p in (
                    config.workspace_dir_or_default(),
                    config.package_cache_dir_or_default(),
                    config.cache_dir,
                    config.output_dir_or_cwd(),
                )
            ):
                continue

            attrs = MOUNT_ATTR_RDONLY
            if d in ("/boot", "/efi"):
                attrs |= MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC

            mount_rbind(d, d, attrs)

    with (
        complete_step(f"Building {config.image} image"),
        setup_workspace(args, config) as workspace,
    ):
        build_image(
            Context(
                args,
                config,
                workspace=workspace,
                resources=resources,
                keyring_dir=keyring_dir,
                metadata_dir=metadata_dir,
                package_dir=package_dir,
            )
        )


def run_verb(args: Args, tools: Optional[Config], images: Sequence[Config], *, resources: Path) -> None:
    images = list(images)

    if args.verb == Verb.init:
        copy_tree(resources / "tmpfiles.d", INVOKING_USER.tmpfiles_dir(), preserve=False)
        log_notice(f"Copied mkosi tmpfiles dropins to {INVOKING_USER.tmpfiles_dir()}")
        return

    if args.verb == Verb.completion:
        return print_completion(args, resources=resources)

    if args.verb == Verb.documentation:
        if args.cmdline:
            manual = {
                "addon": "mkosi-addon",
                "initrd": "mkosi-initrd",
                "sandbox": "mkosi-sandbox",
                "news": "mkosi.news",
            }.get(args.cmdline[0], args.cmdline[0])
        else:
            manual = "mkosi"
        formats: list[DocFormat] = (
            [args.doc_format] if args.doc_format != DocFormat.auto else DocFormat.all()
        )
        chapter = {"mkosi.news": 7}.get(manual, 1)
        return show_docs(manual, formats, man_chapter=chapter, resources=resources, pager=args.pager)

    if args.verb == Verb.genkey:
        return generate_key_cert_pair(args)

    if args.verb == Verb.dependencies:
        _, _, [deps] = parse_config(
            ["--directory=", "--repositories=", *args.cmdline, "--include=mkosi-tools", "build"],
            resources=resources,
        )

        for p in sorted(deps.packages):
            print(p)

        return

    if all(config == Config.default() for config in images):
        die(
            "No configuration found",
            hint="Make sure mkosi is run from a directory with configuration files",
        )

    if args.verb == Verb.summary:
        if args.json:
            text = dump_json(
                {
                    "Tools": tools.to_dict() if tools else None,
                    "Images": [config.to_dict() for config in images],
                }
            )
        else:
            text = f"{summary(tools)}\n" if tools else ""
            text += "\n".join(summary(config) for config in images)

        page(text, args.pager)
        return

    if args.verb == Verb.cat_config:
        text = cat_config(images)
        page(text, args.pager)
        return

    # The images array has been modified so we need to reevaluate last again.
    last = images[-1]

    if args.verb == Verb.bump:
        finalize_image_version(args, last)
        return

    if args.verb == Verb.clean:
        if tools and args.force > 0:
            run_clean(args, tools)

        for config in images:
            run_clean(args, config)

        if args.force > 0 and last.distribution != Distribution.custom:
            remove_cache_entries(finalize_default_initrd(last, tools=False, resources=resources))

        rmtree(Path(".mkosi-private"))

        return

    # For the default tools tree have_cache() encompasses the "has the tools tree been built at all" check.
    if tools and not have_cache(tools):
        if (args.rerun_build_scripts or args.verb != Verb.build) and args.force == 0:
            die(
                "Default tools tree requested but it is out-of-date or has not been built yet",
                hint="Make sure to (re)build the tools tree first with 'mkosi build' or use '--force'",
            )
        elif last.incremental == Incremental.strict:
            die(
                "Default tools tree is out-of-date but the strict incremental mode is enabled",
                hint="Build once without --incremental=strict to rebuild the default tools tree",
            )

        run_clean(args, tools)

        run_sync_scripts(tools)
        check_tools(tools, Verb.build)
        ensure_directories_exist(tools)

        with (
            tempfile.TemporaryDirectory(
                dir=tools.workspace_dir_or_default(),
                prefix="mkosi-keyring-",
            ) as keyring_dir,
            tempfile.TemporaryDirectory(
                dir=tools.workspace_dir_or_default(),
                prefix="mkosi-metadata-",
            ) as metadata_dir,
        ):
            sync_repository_metadata(
                args,
                [tools],
                resources=resources,
                keyring_dir=Path(keyring_dir),
                metadata_dir=Path(metadata_dir),
            )
            fork_and_wait(
                run_build,
                args,
                tools,
                resources=resources,
                keyring_dir=Path(keyring_dir),
                metadata_dir=Path(metadata_dir),
            )

        _, _, manifest = cache_tree_paths(tools)
        manifest.write_text(dump_json(tools.cache_manifest()))

    if args.verb.needs_tools():
        return {
            Verb.ssh: run_ssh,
            Verb.journalctl: run_journalctl,
            Verb.coredumpctl: run_coredumpctl,
            Verb.sandbox: run_sandbox,
        }[args.verb](args, last)

    if last.output_format == OutputFormat.none:
        if args.verb != Verb.build:
            die(f"Cannot run '{args.verb}' verb on image with output format 'none'")

    output = last.output_dir_or_cwd() / last.output_with_compression

    if (
        args.verb == Verb.build
        and not args.force
        and last.output_format != OutputFormat.none
        and output.exists()
        and not output.is_symlink()
        and not args.rerun_build_scripts
    ):
        logging.info(f"Output path {output} exists already. (Use --force to rebuild.)")
        return

    if args.rerun_build_scripts and last.output_format != OutputFormat.none and not output.exists():
        die(
            f"Image '{last.image}' must be built once before --rerun-build-scripts can be used",
            hint="Build the image once with 'mkosi build'",
        )

    if (
        args.verb != Verb.build
        and not args.force
        and last.output_format != OutputFormat.none
        and not output.exists()
    ):
        die(
            f"Image '{last.image}' has not been built yet",
            hint="Make sure to build the image first with 'mkosi build' or use '--force'",
        )

    if not last.repart_offline and os.getuid() != 0:
        die(f"Must be root to build {last.image} image configured with RepartOffline=no")

    check_workspace_directory(last)

    if args.rerun_build_scripts and not last.is_incremental():
        die("Incremental= must be enabled to be able to use --rerun-build-scripts")

    if last.is_incremental():
        for a, b in itertools.combinations(images, 2):
            if a.expand_key_specifiers(a.cache_key) == b.expand_key_specifiers(b.cache_key):
                die(
                    f"Image {a.image} and {b.image} have the same cache key '{a.expand_key_specifiers(a.cache_key)}'",  # noqa: E501
                    hint="Add the &I specifier to the cache key to avoid this issue",
                )

    if last.is_incremental() and (last.incremental == Incremental.strict or args.rerun_build_scripts):
        if args.force > 1:
            die(
                "Cannot remove incremental caches when building with Incremental=strict",
                hint="Build once with '-i yes' to update the image cache",
            )

        if any((c := config).is_incremental() and not have_cache(config) for config in images):
            if args.rerun_build_scripts:
                die(
                    f"Cannot use --rerun-build-scripts as the cache for image {c.image} is out-of-date",
                    hint="Rebuild the image to update the image cache",
                )
            else:
                die(
                    f"Strict incremental mode is enabled and cache for image {c.image} is out-of-date",
                    hint="Build once with '-i yes' to update the image cache",
                )

    # First, process all directory removals because otherwise if different images share directories
    # a later image build could end up deleting the output generated by an earlier image build.
    if needs_build(args, last) or args.wipe_build_dir:
        for config in images:
            run_clean(args, config)

        if last.distribution != Distribution.custom:
            initrd = finalize_default_initrd(last, resources=resources)

            if args.force > 1 or not have_cache(initrd):
                remove_cache_entries(initrd)

    for i, config in enumerate(images):
        if args.verb != Verb.build:
            check_tools(config, args.verb)

        images[i] = config = run_configure_scripts(config)

    # The images array has been modified so we need to reevaluate last again.
    # Also ensure that all other images are reordered in case their dependencies were modified.
    last = images[-1]
    images = resolve_deps(images[:-1], last.dependencies) + [last]

    if (
        args.rerun_build_scripts
        or last.output_format == OutputFormat.none
        or not (last.output_dir_or_cwd() / last.output).exists()
    ):
        for config in images:
            if any(
                source.type != KeySourceType.file
                for source in (
                    config.verity_key_source,
                    config.secure_boot_key_source,
                    config.sign_expected_pcr_key_source,
                )
            ):
                join_new_session_keyring()
                break

        validate = [
            c
            for c in images
            if c.output_format != OutputFormat.none and not (c.output_dir_or_cwd() / c.output).exists()
        ]
        if validate:
            with complete_step("Validating certificates and keys"):
                for config in validate:
                    validate_certificates_and_keys(config)

        ensure_directories_exist(last)

        with (
            tempfile.TemporaryDirectory(
                dir=last.workspace_dir_or_default(),
                prefix="mkosi-keyring-",
            ) as keyring_dir,
            tempfile.TemporaryDirectory(
                dir=last.workspace_dir_or_default(),
                prefix="mkosi-metadata-",
            ) as metadata_dir,
            tempfile.TemporaryDirectory(
                dir=last.workspace_dir_or_default(),
                prefix="mkosi-packages-",
            ) as package_dir,
        ):
            for config in images:
                run_sync_scripts(config)

            synced = False

            for config in images:
                # If the output format is "none" or we're rebuilding and there are no build scripts, there's
                # nothing to do so exit early.
                if (
                    config.output_format == OutputFormat.none
                    or (args.rerun_build_scripts and (config.output_dir_or_cwd() / config.output).exists())
                ) and not config.build_scripts:
                    continue

                check_tools(config, Verb.build)
                check_inputs(config)
                ensure_directories_exist(config)

                if not synced:
                    sync_repository_metadata(
                        args,
                        images,
                        resources=resources,
                        keyring_dir=Path(keyring_dir),
                        metadata_dir=Path(metadata_dir),
                    )
                    synced = True

                fork_and_wait(
                    run_build,
                    args,
                    config,
                    resources=resources,
                    keyring_dir=Path(keyring_dir),
                    metadata_dir=Path(metadata_dir),
                    package_dir=Path(package_dir),
                )

            if not synced:
                logging.info("All images have already been built and do not have any build scripts")

        if args.auto_bump:
            finalize_image_version(args, last)

    if args.verb == Verb.build:
        return

    if (
        last.output_format == OutputFormat.directory
        and (last.output_dir_or_cwd() / last.output).stat().st_uid == 0
        and os.getuid() != 0
    ):
        die(
            "Cannot operate on directory images built as root when running unprivileged",
            hint="Clean the root owned image by running mkosi -ff clean as root and then rebuild the image",
        )

    run_vm = {
        Vmm.qemu: run_qemu,
        Vmm.vmspawn: run_vmspawn,
    }[last.vmm]

    {
        Verb.shell: run_shell,
        Verb.boot: run_shell,
        Verb.vm: run_vm,
        Verb.qemu: run_vm,
        Verb.serve: run_serve,
        Verb.burn: run_burn,
        Verb.sysupdate: run_sysupdate,
    }[args.verb](args, last)
