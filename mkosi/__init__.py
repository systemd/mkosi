# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import dataclasses
import datetime
import hashlib
import io
import itertools
import json
import logging
import os
import re
import resource
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Optional, Union, cast

from mkosi.archive import can_extract_tar, extract_tar, make_cpio, make_tar
from mkosi.burn import run_burn
from mkosi.completion import print_completion
from mkosi.config import (
    PACKAGE_GLOBS,
    Args,
    BiosBootloader,
    Bootloader,
    Cacheonly,
    Compression,
    Config,
    ConfigFeature,
    DocFormat,
    JsonEncoder,
    KeySource,
    ManifestFormat,
    Network,
    OutputFormat,
    SecureBootSignTool,
    ShimBootloader,
    Verb,
    Vmm,
    __version__,
    format_bytes,
    parse_config,
    summary,
    systemd_tool_version,
    want_selinux_relabel,
    yes_no,
)
from mkosi.context import Context
from mkosi.distributions import Distribution
from mkosi.installer import clean_package_manager_metadata
from mkosi.kmod import gen_required_kernel_modules, loaded_modules, process_kernel_modules
from mkosi.log import ARG_DEBUG, complete_step, die, log_notice, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import finalize_crypto_mounts, finalize_source_mounts, mount_overlay
from mkosi.pager import page
from mkosi.partition import Partition, finalize_root, finalize_roothash
from mkosi.qemu import KernelType, copy_ephemeral, run_qemu, run_ssh, start_journal_remote
from mkosi.run import (
    find_binary,
    fork_and_wait,
    run,
)
from mkosi.sandbox import Mount, chroot_cmd, finalize_passwd_mounts
from mkosi.tree import copy_tree, move_tree, rmtree
from mkosi.types import PathString
from mkosi.user import CLONE_NEWNS, INVOKING_USER, become_root, unshare
from mkosi.util import (
    flatten,
    flock,
    flock_or_die,
    format_rlimit,
    hash_file,
    make_executable,
    one_zero,
    read_env_file,
    round_up,
    scopedenv,
    umask,
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
                run(["systemd-dissect", "--mount", "--mkdir", path, d])
                stack.callback(lambda: run(["systemd-dissect", "--umount", "--rmdir", d]))
                bases += [d]
            else:
                die(f"Unsupported base tree source {path}")

        stack.enter_context(mount_overlay(bases, context.root, context.root))

        yield


def remove_files(context: Context) -> None:
    """Remove files based on user-specified patterns"""

    if not context.config.remove_files:
        return

    with complete_step("Removing files…"):
        remove = flatten(context.root.glob(pattern.lstrip("/")) for pattern in context.config.remove_files)
        rmtree(*remove, sandbox=context.sandbox)


def install_distribution(context: Context) -> None:
    if context.config.base_trees:
        if not context.config.packages:
            return

        with complete_step(f"Installing extra packages for {str(context.config.distribution).capitalize()}"):
            context.config.distribution.install_packages(context, context.config.packages)
    else:
        if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
            if context.config.packages:
                die("Cannot install packages in extension images without a base tree",
                    hint="Configure a base tree with the BaseTrees= setting")
            return

        with complete_step(f"Installing {str(context.config.distribution).capitalize()}"):
            context.config.distribution.install(context)

            if not (context.root / "etc/machine-id").exists():
                # Uninitialized means we want it to get initialized on first boot.
                with umask(~0o444):
                    (context.root / "etc/machine-id").write_text("uninitialized\n")

            # Ensure /efi exists so that the ESP is mounted there, as recommended by
            # https://0pointer.net/blog/linux-boot-partitions.html. Use the most restrictive access mode we
            # can without tripping up mkfs tools since this directory is only meant to be overmounted and
            # should not be read from or written to.
            with umask(~0o500):
                (context.root / "efi").mkdir(exist_ok=True)
                (context.root / "boot").mkdir(exist_ok=True)

            # Ensure /boot/loader/entries.srel exists and has type1 written to it to nudge kernel-install towards using
            # the boot loader specification layout.
            with umask(~0o700):
                (context.root / "boot/loader").mkdir(exist_ok=True)
            with umask(~0o600):
                (context.root / "boot/loader/entries.srel").write_text("type1\n")

            if context.config.packages:
                context.config.distribution.install_packages(context, context.config.packages)

    for f in ("var/lib/systemd/random-seed",
              "var/lib/systemd/credential.secret",
              "etc/machine-info",
              "var/lib/dbus/machine-id"):
        # Using missing_ok=True still causes an OSError if the mount is read-only even if the
        # file doesn't exist so do an explicit exists() check first.
        if (context.root / f).exists():
            (context.root / f).unlink()


def install_build_packages(context: Context) -> None:
    if not context.config.build_scripts or not context.config.build_packages:
        return

    with (
        complete_step(f"Installing build packages for {context.config.distribution.pretty_name()}"),
        mount_build_overlay(context),
    ):
        context.config.distribution.install_packages(context, context.config.build_packages)


def install_volatile_packages(context: Context) -> None:
    if not context.config.volatile_packages:
        return

    with complete_step(f"Installing volatile packages for {context.config.distribution.pretty_name()}"):
        context.config.distribution.install_packages(context, context.config.volatile_packages)


def remove_packages(context: Context) -> None:
    """Remove packages listed in config.remove_packages"""

    if not context.config.remove_packages:
        return

    with complete_step(f"Removing {len(context.config.remove_packages)} packages…"):
        try:
            context.config.distribution.remove_packages(context, context.config.remove_packages)
        except NotImplementedError:
            die(f"Removing packages is not supported for {context.config.distribution}")


def check_root_populated(context: Context) -> None:
    if context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
        return

    """Check that the root was populated by looking for a os-release file."""
    osrelease = context.root / "usr/lib/os-release"
    if not osrelease.exists():
        die(
            f"{osrelease} not found.",
            hint=(
                "The root must be populated by the distribution, or from base trees, "
                "skeleton trees, and prepare scripts."
            )
        )


def configure_os_release(context: Context) -> None:
    """Write IMAGE_ID and IMAGE_VERSION to /usr/lib/os-release in the image."""
    if not context.config.image_id and not context.config.image_version:
        return

    if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
        return

    for candidate in ["usr/lib/os-release", "usr/lib/initrd-release", "etc/os-release"]:
        osrelease = context.root / candidate
        # at this point we know we will either change or add to the file
        newosrelease = osrelease.with_suffix(".new")

        if not osrelease.is_file() or osrelease.is_symlink():
            continue

        image_id_written = image_version_written = False
        with osrelease.open("r") as old, newosrelease.open("w") as new:
            # fix existing values
            for line in old.readlines():
                if context.config.image_id and line.startswith("IMAGE_ID="):
                    new.write(f'IMAGE_ID="{context.config.image_id}"\n')
                    image_id_written = True
                elif context.config.image_version and line.startswith("IMAGE_VERSION="):
                    new.write(f'IMAGE_VERSION="{context.config.image_version}"\n')
                    image_version_written = True
                else:
                    new.write(line)

            # append if they were missing
            if context.config.image_id and not image_id_written:
                new.write(f'IMAGE_ID="{context.config.image_id}"\n')
            if context.config.image_version and not image_version_written:
                new.write(f'IMAGE_VERSION="{context.config.image_version}"\n')

        newosrelease.rename(osrelease)


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

        if "VERSION_ID" not in extrelease and (version := osrelease.get("VERSION_ID")):
            f.write(f"VERSION_ID={version}\n")

        if f"{prefix}_ID" not in extrelease and context.config.image_id:
            f.write(f"{prefix}_ID={context.config.image_id}\n")

        if f"{prefix}_VERSION_ID" not in extrelease and context.config.image_version:
            f.write(f"{prefix}_VERSION_ID={context.config.image_version}\n")

        if f"{prefix}_SCOPE" not in extrelease:
            f.write(f"{prefix}_SCOPE={context.config.environment.get(f'{prefix}_SCOPE', 'initrd system portable')}\n")

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
        configure_autologin_service(context, "console-getty.service",
                                    "--noclear --keep-baud console 115200,38400,9600")
        configure_autologin_service(context, "getty@tty1.service",
                                    "--noclear -")
        configure_autologin_service(context,
                                    "serial-getty@hvc0.service",
                                    "--keep-baud 115200,57600,38400,9600 -")


@contextlib.contextmanager
def mount_build_overlay(context: Context, volatile: bool = False) -> Iterator[Path]:
    d = context.workspace / "build-overlay"
    if not d.is_symlink():
        with umask(~0o755):
            d.mkdir(exist_ok=True)

    with contextlib.ExitStack() as stack:
        lower = [context.root]

        if volatile:
            lower += [d]
            upper = None
        else:
            upper = d

        stack.enter_context(mount_overlay(lower, upper, context.root))

        yield context.root


@contextlib.contextmanager
def finalize_scripts(config: Config, scripts: Mapping[str, Sequence[PathString]]) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mkosi-scripts-") as d:
        # Make sure than when mkosi-as-caller is used the scripts can still be accessed.
        os.chmod(d, 0o755)

        for name, script in scripts.items():
            # Make sure we don't end up in a recursive loop when we name a script after the binary it execs
            # by removing the scripts directory from the PATH when we execute a script.
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

                f.write(f'exec {shlex.join(str(s) for s in script)} "$@"\n')

            make_executable(Path(d) / name)
            os.chmod(Path(d) / name, 0o755)
            os.utime(Path(d) / name, (0, 0))

        yield Path(d)


GIT_ENV = {
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "safe.directory",
    "GIT_CONFIG_VALUE_0": "*",
}


def mkosi_as_caller() -> tuple[str, ...]:
    return (
        "setpriv",
        f"--reuid={INVOKING_USER.uid}",
        f"--regid={INVOKING_USER.gid}",
        "--clear-groups",
    )


def finalize_host_scripts(
    context: Context,
    helpers: Mapping[str, Sequence[PathString]] = {},
) -> AbstractContextManager[Path]:
    scripts: dict[str, Sequence[PathString]] = {}
    for binary in ("useradd", "groupadd"):
        if context.config.find_binary(binary):
            scripts[binary] = (binary, "--root", "/buildroot")
    if ukify := context.config.find_binary("ukify"):
        # A script will always run with the tools tree mounted so we pass binary=None to disable the conditional search
        # logic of python_binary() depending on whether the binary is in an extra search path or not.
        scripts["ukify"] = (python_binary(context.config, binary=None), ukify)
    return finalize_scripts(context.config, scripts | dict(helpers))


@contextlib.contextmanager
def finalize_config_json(config: Config) -> Iterator[Path]:
    with tempfile.NamedTemporaryFile(mode="w") as f:
        f.write(config.to_json())
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
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
    )

    if config.profile:
        env["PROFILE"] = config.profile

    with finalize_source_mounts(config, ephemeral=False) as sources:
        for script in config.configure_scripts:
            with complete_step(f"Running configure script {script}…"):
                result = run(
                    ["/work/configure"],
                    env=env | config.environment,
                    sandbox=config.sandbox(
                        binary=None,
                        vartmp=True,
                        mounts=[*sources, Mount(script, "/work/configure", ro=True)],
                        options=["--dir", "/work/src", "--chdir", "/work/src"]
                    ),
                    input=config.to_json(indent=None),
                    stdout=subprocess.PIPE,
                )

                config = Config.from_json(result.stdout)

    return config


def run_sync_scripts(context: Context) -> None:
    if not context.config.sync_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        DISTRIBUTION_ARCHITECTURE=context.config.distribution.architecture(context.config.architecture),
        SRCDIR="/work/src",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
        CACHED=one_zero(have_cache(context.config)),
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    # We make sure to mount everything in to make ssh work since syncing might involve git which could invoke ssh.
    if agent := os.getenv("SSH_AUTH_SOCK"):
        env["SSH_AUTH_SOCK"] = agent

    with (
        finalize_source_mounts(context.config, ephemeral=False) as sources,
        finalize_config_json(context.config) as json,
    ):
        for script in context.config.sync_scripts:
            mounts = [
                *sources,
                *finalize_crypto_mounts(context.config),
                Mount(script, "/work/sync", ro=True),
                Mount(json, "/work/config.json", ro=True),
            ]

            if (p := INVOKING_USER.home()).exists() and p != Path("/"):
                # We use a writable mount here to keep git worktrees working which encode absolute paths to the parent
                # git repository and might need to modify the git config in the parent git repository when submodules
                # are in use as well.
                mounts += [Mount(p, p)]
                env["HOME"] = os.fspath(p)
            if (p := Path(f"/run/user/{INVOKING_USER.uid}")).exists():
                mounts += [Mount(p, p, ro=True)]

            with complete_step(f"Running sync script {script}…"):
                run(
                    ["/work/sync", "final"],
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                    sandbox=context.sandbox(
                        binary=None,
                        network=True,
                        vartmp=True,
                        mounts=mounts,
                        options=["--dir", "/work/src", "--chdir", "/work/src"]
                    ),
                )


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
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
        **GIT_ENV,
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    if context.config.build_dir is not None:
        env |= dict(BUILDDIR="/work/build")

    with (
        mount_build_overlay(context) if build else contextlib.nullcontext(),
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
    ):
        if build:
            step_msg = "Running prepare script {} in build overlay…"
            arg = "build"
        else:
            step_msg = "Running prepare script {}…"
            arg = "final"

        for script in context.config.prepare_scripts:
            chroot = chroot_cmd(resolve=True, work=True)

            helpers = {
                "mkosi-chroot": chroot,
                "mkosi-as-caller": mkosi_as_caller(),
                **context.config.distribution.package_manager(context.config).scripts(context),
            }

            with (
                finalize_host_scripts(context, helpers) as hd,
                finalize_config_json(context.config) as json,
                complete_step(step_msg.format(script)),
            ):
                run(
                    ["/work/prepare", arg],
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                    sandbox=context.sandbox(
                        binary=None,
                        network=True,
                        vartmp=True,
                        mounts=[
                            *sources,
                            Mount(script, "/work/prepare", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(context.root, "/buildroot"),
                            Mount(context.artifacts, "/work/artifacts"),
                            Mount(context.package_dir, "/work/packages"),
                            *(
                                [Mount(context.config.build_dir, "/work/build", ro=True)]
                                if context.config.build_dir
                                else []
                            ),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                        extra=chroot if script.suffix == ".chroot" else [],
                    )
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
        OUTPUTDIR="/work/out",
        CHROOT_OUTPUTDIR="/work/out",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        ARTIFACTDIR="/work/artifacts",
        SCRIPT="/work/build-script",
        CHROOT_SCRIPT="/work/build-script",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
        **GIT_ENV,
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    if context.config.build_dir is not None:
        env |= dict(
            BUILDDIR="/work/build",
            CHROOT_BUILDDIR="/work/build",
        )

    with (
        mount_build_overlay(context, volatile=True),
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
    ):
        for script in context.config.build_scripts:
            chroot = chroot_cmd(resolve=context.config.with_network, work=True)

            helpers = {
                "mkosi-chroot": chroot,
                "mkosi-as-caller": mkosi_as_caller(),
                **context.config.distribution.package_manager(context.config).scripts(context),
            }

            cmdline = context.args.cmdline if context.args.verb == Verb.build else []

            with (
                finalize_host_scripts(context, helpers) as hd,
                finalize_config_json(context.config) as json,
                complete_step(f"Running build script {script}…"),
            ):
                run(
                    ["/work/build-script", *cmdline],
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                    sandbox=context.sandbox(
                        binary=None,
                        network=context.config.with_network,
                        vartmp=True,
                        mounts=[
                            *sources,
                            Mount(script, "/work/build-script", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(context.root, "/buildroot"),
                            Mount(context.install_dir, "/work/dest"),
                            Mount(context.staging, "/work/out"),
                            Mount(context.artifacts, "/work/artifacts"),
                            Mount(context.package_dir, "/work/packages"),
                            *(
                                [Mount(context.config.build_dir, "/work/build")]
                                if context.config.build_dir
                                else []
                            ),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                        extra=chroot if script.suffix == ".chroot" else [],
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
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
        WITH_NETWORK=one_zero(context.config.with_network),
        **GIT_ENV,
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    if context.config.build_dir is not None:
        env |= dict(BUILDDIR="/work/build")

    with (
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
    ):
        for script in context.config.postinst_scripts:
            chroot = chroot_cmd(resolve=context.config.with_network, work=True)

            helpers = {
                "mkosi-chroot": chroot,
                "mkosi-as-caller": mkosi_as_caller(),
                **context.config.distribution.package_manager(context.config).scripts(context),
            }

            with (
                finalize_host_scripts(context, helpers) as hd,
                finalize_config_json(context.config) as json,
                complete_step(f"Running postinstall script {script}…"),
            ):
                run(
                    ["/work/postinst", "final"],
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                    sandbox=context.sandbox(
                        binary=None,
                        network=context.config.with_network,
                        vartmp=True,
                        mounts=[
                            *sources,
                            Mount(script, "/work/postinst", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(context.root, "/buildroot"),
                            Mount(context.staging, "/work/out"),
                            Mount(context.artifacts, "/work/artifacts"),
                            Mount(context.package_dir, "/work/packages"),
                            *(
                                [Mount(context.config.build_dir, "/work/build", ro=True)]
                                if context.config.build_dir
                                else []
                            ),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                        extra=chroot if script.suffix == ".chroot" else [],
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
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
        WITH_NETWORK=one_zero(context.config.with_network),
        **GIT_ENV,
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    if context.config.build_dir is not None:
        env |= dict(BUILDDIR="/work/build")

    with finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources:
        for script in context.config.finalize_scripts:
            chroot = chroot_cmd(resolve=context.config.with_network, work=True)

            helpers = {
                "mkosi-chroot": chroot,
                "mkosi-as-caller": mkosi_as_caller(),
                **context.config.distribution.package_manager(context.config).scripts(context),
            }

            with (
                finalize_host_scripts(context, helpers) as hd,
                finalize_config_json(context.config) as json,
                complete_step(f"Running finalize script {script}…"),
            ):
                run(
                    ["/work/finalize"],
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                    sandbox=context.sandbox(
                        binary=None,
                        network=context.config.with_network,
                        vartmp=True,
                        mounts=[
                            *sources,
                            Mount(script, "/work/finalize", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(context.root, "/buildroot"),
                            Mount(context.staging, "/work/out"),
                            Mount(context.artifacts, "/work/artifacts"),
                            Mount(context.package_dir, "/work/packages"),
                            *(
                                [Mount(context.config.build_dir, "/work/build", ro=True)]
                                if context.config.build_dir
                                else []
                            ),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                        extra=chroot if script.suffix == ".chroot" else [],
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
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    with (
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
        finalize_config_json(context.config) as json,
    ):
        for script in context.config.postoutput_scripts:
            with complete_step(f"Running post-output script {script}…"):
                run(
                    ["/work/postoutput"],
                    env=env | context.config.environment,
                    sandbox=context.sandbox(
                        binary=None,
                        vartmp=True,
                        mounts=[
                            *sources,
                            Mount(script, "/work/postoutput", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(context.staging, "/work/out"),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src", "--dir", "/work/out"]
                    ),
                    stdin=sys.stdin,
                )


def certificate_common_name(context: Context, certificate: Path) -> str:
    output = run(
        [
            "openssl",
            "x509",
            "-noout",
            "-subject",
            "-nameopt", "multiline",
            "-in", certificate,
        ],
        stdout=subprocess.PIPE,
        sandbox=context.sandbox(binary="openssl", mounts=[Mount(certificate, certificate, ro=True)]),
    ).stdout

    for line in output.splitlines():
        if not line.strip().startswith("commonName"):
            continue

        _, sep, value = line.partition("=")
        if not sep:
            die("Missing '=' delimiter in openssl output")

        return value.strip()

    die(f"Certificate {certificate} is missing Common Name")


def pesign_prepare(context: Context) -> None:
    assert context.config.secure_boot_key
    assert context.config.secure_boot_certificate

    if (context.workspace / "pesign").exists():
        return

    (context.workspace / "pesign").mkdir()

    # pesign takes a certificate directory and a certificate common name as input arguments, so we have
    # to transform our input key and cert into that format. Adapted from
    # https://www.mankier.com/1/pesign#Examples-Signing_with_the_certificate_and_private_key_in_individual_files
    with open(context.workspace / "secure-boot.p12", "wb") as f:
        run(
            [
                "openssl",
                "pkcs12",
                "-export",
                # Arcane incantation to create a pkcs12 certificate without a password.
                "-keypbe", "NONE",
                "-certpbe", "NONE",
                "-nomaciter",
                "-passout", "pass:",
                "-inkey", context.config.secure_boot_key,
                "-in", context.config.secure_boot_certificate,
            ],
            stdout=f,
            sandbox=context.sandbox(
                binary="openssl",
                mounts=[
                    Mount(context.config.secure_boot_key, context.config.secure_boot_key, ro=True),
                    Mount(context.config.secure_boot_certificate, context.config.secure_boot_certificate, ro=True),
                ],
            ),
        )

    (context.workspace / "pesign").mkdir(exist_ok=True)

    run(
        [
            "pk12util",
            "-K", "",
            "-W", "",
            "-i", context.workspace / "secure-boot.p12",
            "-d", context.workspace / "pesign",
        ],
        sandbox=context.sandbox(
            binary="pk12util",
            mounts=[
                Mount(context.workspace / "secure-boot.p12", context.workspace / "secure-boot.p12", ro=True),
                Mount(context.workspace / "pesign", context.workspace / "pesign"),
            ],
        ),
    )


def efi_boot_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    assert arch
    return Path(f"efi/EFI/BOOT/BOOT{arch.upper()}.EFI")


def shim_second_stage_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    assert arch
    if context.config.distribution == Distribution.opensuse:
        return Path("efi/EFI/BOOT/grub.EFI")
    else:
        return Path(f"efi/EFI/BOOT/grub{arch}.EFI")


def sign_efi_binary(context: Context, input: Path, output: Path) -> Path:
    assert context.config.secure_boot_key
    assert context.config.secure_boot_certificate

    if (
        context.config.secure_boot_sign_tool == SecureBootSignTool.sbsign or
        context.config.secure_boot_sign_tool == SecureBootSignTool.auto and
        context.config.find_binary("sbsign") is not None
    ):
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=output.name) as f:
            os.chmod(f.name, stat.S_IMODE(input.stat().st_mode))
            cmd: list[PathString] = [
                "sbsign",
                "--key", context.config.secure_boot_key,
                "--cert", context.config.secure_boot_certificate,
                "--output", "/dev/stdout",
            ]
            mounts = [
                Mount(context.config.secure_boot_certificate, context.config.secure_boot_certificate, ro=True),
                Mount(input, input, ro=True),
            ]
            if context.config.secure_boot_key_source.type == KeySource.Type.engine:
                cmd += ["--engine", context.config.secure_boot_key_source.source]
            if context.config.secure_boot_key.exists():
                mounts += [Mount(context.config.secure_boot_key, context.config.secure_boot_key, ro=True)]
            cmd += [input]
            run(
                cmd,
                stdout=f,
                sandbox=context.sandbox(
                    binary="sbsign",
                    mounts=mounts,
                    devices=context.config.secure_boot_key_source.type != KeySource.Type.file,
                )
            )
            output.unlink(missing_ok=True)
            os.link(f.name, output)
    elif (
        context.config.secure_boot_sign_tool == SecureBootSignTool.pesign or
        context.config.secure_boot_sign_tool == SecureBootSignTool.auto and
        context.config.find_binary("pesign") is not None
    ):
        pesign_prepare(context)
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=output.name) as f:
            os.chmod(f.name, stat.S_IMODE(input.stat().st_mode))
            run(
                [
                    "pesign",
                    "--certdir", context.workspace / "pesign",
                    "--certificate", certificate_common_name(context, context.config.secure_boot_certificate),
                    "--sign",
                    "--force",
                    "--in", input,
                    "--out", "/dev/stdout",
                ],
                stdout=f,
                sandbox=context.sandbox(
                    binary="pesign",
                    mounts=[
                        Mount(context.workspace / "pesign", context.workspace / "pesign", ro=True),
                        Mount(input, input, ro=True),
                    ]
                ),
            )
            output.unlink(missing_ok=True)
            os.link(f.name, output)
    else:
        die("One of sbsign or pesign is required to use SecureBoot=")

    return output


def install_systemd_boot(context: Context) -> None:
    if not want_efi(context.config):
        return

    if context.config.bootloader != Bootloader.systemd_boot:
        return

    if not any(gen_kernel_images(context)) and context.config.bootable == ConfigFeature.auto:
        return

    if not context.config.find_binary("bootctl"):
        if context.config.bootable == ConfigFeature.enabled:
            die("An EFI bootable image with systemd-boot was requested but bootctl was not found")
        return

    directory = context.root / "usr/lib/systemd/boot/efi"
    signed = context.config.shim_bootloader == ShimBootloader.signed
    if not directory.glob("*.efi.signed" if signed else "*.efi"):
        if context.config.bootable == ConfigFeature.enabled:
            die(f"An EFI bootable image with systemd-boot was requested but a {'signed ' if signed else ''}"
                f"systemd-boot binary was not found at {directory.relative_to(context.root)}")
        return

    if context.config.secure_boot and not signed:
        with complete_step("Signing systemd-boot binaries…"):
            for input in itertools.chain(directory.glob('*.efi'), directory.glob('*.EFI')):
                output = directory / f"{input}.signed"
                sign_efi_binary(context, input, output)

    with complete_step("Installing systemd-boot…"):
        run(
            ["bootctl", "install", "--root=/buildroot", "--all-architectures", "--no-variables"],
            env={"SYSTEMD_ESP_PATH": "/efi", "SYSTEMD_XBOOTLDR_PATH": "/boot"},
            sandbox=context.sandbox(binary="bootctl", mounts=[Mount(context.root, "/buildroot")]),
        )
        # TODO: Use --random-seed=no when we can depend on systemd 256.
        Path(context.root / "efi/loader/random-seed").unlink(missing_ok=True)

        if context.config.shim_bootloader != ShimBootloader.none:
            shutil.copy2(
                context.root / f"efi/EFI/systemd/systemd-boot{context.config.architecture.to_efi()}.efi",
                context.root / shim_second_stage_binary(context),
            )

    if context.config.secure_boot and context.config.secure_boot_auto_enroll:
        assert context.config.secure_boot_key
        assert context.config.secure_boot_certificate

        with complete_step("Setting up secure boot auto-enrollment…"):
            keys = context.root / "efi/loader/keys/auto"
            with umask(~0o700):
                keys.mkdir(parents=True, exist_ok=True)

            # sbsiglist expects a DER certificate.
            with umask(~0o600), open(context.workspace / "mkosi.der", "wb") as f:
                run(
                    [
                        "openssl",
                        "x509",
                        "-outform", "DER",
                        "-in", context.config.secure_boot_certificate,
                    ],
                    stdout=f,
                    sandbox=context.sandbox(
                        binary="openssl",
                        mounts=[
                            Mount(
                                context.config.secure_boot_certificate,
                                context.config.secure_boot_certificate,
                                ro=True
                            ),
                        ],
                    ),
                )

            with umask(~0o600), open(context.workspace / "mkosi.esl", "wb") as f:
                run(
                    [
                        "sbsiglist",
                        "--owner", str(uuid.uuid4()),
                        "--type", "x509",
                        "--output", "/dev/stdout",
                        context.workspace / "mkosi.der",
                    ],
                    stdout=f,
                    sandbox=context.sandbox(
                        binary="sbsiglist",
                        mounts=[Mount(context.workspace / "mkosi.der", context.workspace / "mkosi.der", ro=True)]
                    ),
                )

            # We reuse the key for all secure boot databases to keep things simple.
            for db in ["PK", "KEK", "db"]:
                with umask(~0o600), open(keys / f"{db}.auth", "wb") as f:
                    cmd: list[PathString] = [
                        "sbvarsign",
                        "--attr",
                            "NON_VOLATILE,BOOTSERVICE_ACCESS,RUNTIME_ACCESS,TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
                        "--key", context.config.secure_boot_key,
                        "--cert", context.config.secure_boot_certificate,
                        "--output", "/dev/stdout",
                    ]
                    mounts = [
                        Mount(
                            context.config.secure_boot_certificate,
                            context.config.secure_boot_certificate,
                            ro=True
                        ),
                        Mount(context.workspace / "mkosi.esl", context.workspace / "mkosi.esl", ro=True),
                    ]
                    if context.config.secure_boot_key_source.type == KeySource.Type.engine:
                        cmd += ["--engine", context.config.secure_boot_key_source.source]
                    if context.config.secure_boot_key.exists():
                        mounts += [Mount(context.config.secure_boot_key, context.config.secure_boot_key, ro=True)]
                    cmd += [db, context.workspace / "mkosi.esl"]
                    run(
                        cmd,
                        stdout=f,
                        sandbox=context.sandbox(
                            binary="sbvarsign",
                            mounts=mounts,
                            devices=context.config.secure_boot_key_source.type != KeySource.Type.file,
                        ),
                    )


def find_and_install_shim_binary(
    context: Context,
    name: str,
    signed: Sequence[str],
    unsigned: Sequence[str],
    output: Path,
) -> None:
    if context.config.shim_bootloader == ShimBootloader.signed:
        for pattern in signed:
            for p in context.root.glob(pattern):
                if p.is_symlink() and p.readlink().is_absolute():
                    logging.warning(f"Ignoring signed {name} EFI binary which is an absolute path to {p.readlink()}")
                    continue

                rel = p.relative_to(context.root)
                if (context.root / output).is_dir():
                    output /= rel.name

                log_step(f"Installing signed {name} EFI binary from /{rel} to /{output}")
                shutil.copy2(p, context.root / output)
                return

        if context.config.bootable == ConfigFeature.enabled:
            die(f"Couldn't find signed {name} EFI binary installed in the image")
    else:
        for pattern in unsigned:
            for p in context.root.glob(pattern):
                if p.is_symlink() and p.readlink().is_absolute():
                    logging.warning(f"Ignoring unsigned {name} EFI binary which is an absolute path to {p.readlink()}")
                    continue

                rel = p.relative_to(context.root)
                if (context.root / output).is_dir():
                    output /= rel.name

                if context.config.secure_boot:
                    log_step(f"Signing and installing unsigned {name} EFI binary from /{rel} to /{output}")
                    sign_efi_binary(context, p, context.root / output)
                else:
                    log_step(f"Installing unsigned {name} EFI binary /{rel} to /{output}")
                    shutil.copy2(p, context.root / output)

                return

        if context.config.bootable == ConfigFeature.enabled:
            die(f"Couldn't find unsigned {name} EFI binary installed in the image")


def install_shim(context: Context) -> None:
    if not want_efi(context.config):
        return

    if context.config.shim_bootloader == ShimBootloader.none:
        return

    if not any(gen_kernel_images(context)) and context.config.bootable == ConfigFeature.auto:
        return

    dst = efi_boot_binary(context)
    with umask(~0o700):
        (context.root / dst).parent.mkdir(parents=True, exist_ok=True)

    arch = context.config.architecture.to_efi()

    signed = [
        f"usr/lib/shim/shim{arch}.efi.signed.latest", # Ubuntu
        f"usr/lib/shim/shim{arch}.efi.signed", # Debian
        f"boot/efi/EFI/*/shim{arch}.efi", # Fedora/CentOS
        "usr/share/efi/*/shim.efi", # OpenSUSE
    ]

    unsigned = [
        f"usr/lib/shim/shim{arch}.efi", # Debian/Ubuntu
        f"usr/share/shim/*/*/shim{arch}.efi", # Fedora/CentOS
        f"usr/share/shim/shim{arch}.efi", # Arch
    ]

    find_and_install_shim_binary(context, "shim", signed, unsigned, dst)

    signed = [
        f"usr/lib/shim/mm{arch}.efi.signed", # Debian
        f"usr/lib/shim/mm{arch}.efi", # Ubuntu
        f"boot/efi/EFI/*/mm{arch}.efi", # Fedora/CentOS
        "usr/share/efi/*/MokManager.efi", # OpenSUSE
    ]

    unsigned = [
        f"usr/lib/shim/mm{arch}.efi", # Debian/Ubuntu
        f"usr/share/shim/*/*/mm{arch}.efi", # Fedora/CentOS
        f"usr/share/shim/mm{arch}.efi", # Arch
    ]

    find_and_install_shim_binary(context, "mok", signed, unsigned, dst.parent)


def find_grub_directory(context: Context, *, target: str) -> Optional[Path]:
    for d in ("usr/lib/grub", "usr/share/grub2"):
        if (p := context.root / d / target).exists() and any(p.iterdir()):
            return p

    return None


def find_grub_binary(config: Config, binary: str) -> Optional[Path]:
    assert "grub" not in binary

    # Debian has a bespoke setup where if only grub-pc-bin is installed, grub-bios-setup is installed in
    # /usr/lib/i386-pc instead of in /usr/bin. Let's take that into account and look for binaries in
    # /usr/lib/grub/i386-pc as well.
    return config.find_binary(f"grub-{binary}", f"grub2-{binary}", f"/usr/lib/grub/i386-pc/grub-{binary}")


def want_grub_efi(context: Context) -> bool:
    if not want_efi(context.config):
        return False

    if context.config.bootloader != Bootloader.grub:
        return False

    if context.config.shim_bootloader != ShimBootloader.signed:
        have = find_grub_directory(context, target="x86_64-efi") is not None
        if not have and context.config.bootable == ConfigFeature.enabled:
            die("An EFI bootable image with grub was requested but grub for EFI is not installed")

    return True


def want_grub_bios(context: Context, partitions: Sequence[Partition] = ()) -> bool:
    if context.config.bootable == ConfigFeature.disabled:
        return False

    if context.config.output_format != OutputFormat.disk:
        return False

    if context.config.bios_bootloader != BiosBootloader.grub:
        return False

    if context.config.overlay:
        return False

    have = find_grub_directory(context, target="i386-pc") is not None
    if not have and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but grub for BIOS is not installed")

    bios = any(p.type == Partition.GRUB_BOOT_PARTITION_UUID for p in partitions)
    if partitions and not bios and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no BIOS Boot Partition was configured")

    esp = any(p.type == "esp" for p in partitions)
    if partitions and not esp and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no ESP partition was configured")

    root = any(p.type.startswith("root") or p.type.startswith("usr") for p in partitions)
    if partitions and not root and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no root or usr partition was configured")

    installed = True

    for binary in ("mkimage", "bios-setup"):
        if find_grub_binary(context.config, binary):
            continue

        if context.config.bootable == ConfigFeature.enabled:
            die(f"A BIOS bootable image with grub was requested but {binary} was not found")

        installed = False

    return (have and bios and esp and root and installed) if partitions else have


def prepare_grub_config(context: Context) -> Optional[Path]:
    config = context.root / "efi" / context.config.distribution.grub_prefix() / "grub.cfg"
    with umask(~0o700):
        config.parent.mkdir(exist_ok=True)

    # For some unknown reason, if we don't set the timeout to zero, grub never leaves its menu, so we default
    # to a zero timeout, but only if the config file hasn't been provided by the user.
    if not config.exists():
        with umask(~0o600), config.open("w") as f:
            f.write("set timeout=0\n")

    if want_grub_efi(context):
        # Signed EFI grub shipped by distributions reads its configuration from /EFI/<distribution>/grub.cfg (except
        # in OpenSUSE) in the ESP so let's put a shim there to redirect to the actual configuration file.
        if context.config.distribution == Distribution.opensuse:
            earlyconfig = context.root / "efi/EFI/BOOT/grub.cfg"
        else:
            earlyconfig = context.root / "efi/EFI" / context.config.distribution.name / "grub.cfg"

        with umask(~0o700):
            earlyconfig.parent.mkdir(parents=True, exist_ok=True)

        # Read the actual config file from the root of the ESP.
        earlyconfig.write_text(f"configfile /{context.config.distribution.grub_prefix()}/grub.cfg\n")

    return config


def grub_mkimage(
    context: Context,
    *,
    target: str,
    modules: Sequence[str] = (),
    output: Optional[Path] = None,
    sbat: Optional[Path] = None,
) -> None:
    mkimage = find_grub_binary(context.config, "mkimage")
    assert mkimage

    directory = find_grub_directory(context, target=target)
    assert directory

    with (
        complete_step(f"Generating grub image for {target}"),
        tempfile.NamedTemporaryFile("w", prefix="grub-early-config") as earlyconfig
    ):
        earlyconfig.write(
            textwrap.dedent(
                f"""\
                search --no-floppy --set=root --file /{context.config.distribution.grub_prefix()}/grub.cfg
                set prefix=($root)/{context.config.distribution.grub_prefix()}
                """
            )
        )

        earlyconfig.flush()

        run(
            [
                mkimage,
                "--directory", "/grub",
                "--config", earlyconfig.name,
                "--prefix", f"/{context.config.distribution.grub_prefix()}",
                "--output", output or ("/grub/core.img"),
                "--format", target,
                *(["--sbat", str(sbat)] if sbat else []),
                *(["--disable-shim-lock"] if context.config.shim_bootloader == ShimBootloader.none else []),
                "cat",
                "cmp",
                "div",
                "echo",
                "fat",
                "hello",
                "help",
                "keylayouts",
                "linux",
                "loadenv",
                "ls",
                "normal",
                "part_gpt",
                "read",
                "reboot",
                "search_fs_file",
                "search",
                "sleep",
                "test",
                "tr",
                "true",
                *modules,
            ],
            sandbox=context.sandbox(
                binary=mkimage,
                mounts=[
                    Mount(directory, "/grub"),
                    Mount(earlyconfig.name, earlyconfig.name, ro=True),
                    *([Mount(output.parent, output.parent)] if output else []),
                    *([Mount(str(sbat), str(sbat), ro=True)] if sbat else []),
                ],
            ),
        )


def find_signed_grub_image(context: Context) -> Optional[Path]:
    arch = context.config.architecture.to_efi()

    patterns = [
        f"usr/lib/grub/*-signed/grub{arch}.efi.signed", # Debian/Ubuntu
        f"boot/efi/EFI/*/grub{arch}.efi", # Fedora/CentOS
        "usr/share/efi/*/grub.efi", # OpenSUSE
    ]

    for p in flatten(context.root.glob(pattern) for pattern in patterns):
        if p.is_symlink() and p.readlink().is_absolute():
            logging.warning(f"Ignoring signed grub EFI binary which is an absolute path to {p.readlink()}")
            continue

        return p

    return None


def install_grub(context: Context) -> None:
    if not want_grub_bios(context) and not want_grub_efi(context):
        return

    if want_grub_bios(context):
        grub_mkimage(context, target="i386-pc", modules=("biosdisk",))

    if want_grub_efi(context):
        if context.config.shim_bootloader != ShimBootloader.none:
            output = context.root / shim_second_stage_binary(context)
        else:
            output = context.root / efi_boot_binary(context)

        with umask(~0o700):
            output.parent.mkdir(parents=True, exist_ok=True)

        if context.config.shim_bootloader == ShimBootloader.signed:
            if not (signed := find_signed_grub_image(context)):
                if context.config.bootable == ConfigFeature.enabled:
                    die("Couldn't find a signed grub EFI binary installed in the image")

                return

            rel = output.relative_to(context.root)
            log_step(f"Installing signed grub EFI binary from /{signed.relative_to(context.root)} to /{rel}")
            shutil.copy2(signed, output)
        else:
            if context.config.secure_boot and context.config.shim_bootloader != ShimBootloader.none:
                if not (signed := find_signed_grub_image(context)):
                    die("Couldn't find a signed grub EFI binary installed in the image to extract SBAT from")

                sbat = extract_pe_section(context, signed, ".sbat", context.workspace / "sbat")
            else:
                sbat = None

            grub_mkimage(context, target="x86_64-efi", output=output, modules=("chain",), sbat=sbat)
            if context.config.secure_boot:
                sign_efi_binary(context, output, output)

    dst = context.root / "efi" / context.config.distribution.grub_prefix() / "fonts"
    with umask(~0o700):
        dst.mkdir(parents=True, exist_ok=True)

    for d in ("grub", "grub2"):
        unicode = context.root / "usr/share" / d / "unicode.pf2"
        if unicode.exists():
            shutil.copy2(unicode, dst)


def grub_bios_setup(context: Context, partitions: Sequence[Partition]) -> None:
    if not want_grub_bios(context, partitions):
        return

    setup = find_grub_binary(context.config, "bios-setup")
    assert setup

    directory = find_grub_directory(context, target="i386-pc")
    assert directory

    with (
        complete_step("Installing grub boot loader for BIOS…"),
        tempfile.NamedTemporaryFile(mode="w") as mountinfo,
    ):
        # grub-bios-setup insists on being able to open the root device that --directory is located on, which
        # needs root privileges. However, it only uses the root device when it is unable to embed itself in the
        # bios boot partition. To make installation work unprivileged, we trick grub to think that the root
        # device is our image by mounting over its /proc/self/mountinfo file (where it gets its information from)
        # with our own file correlating the root directory to our image file.
        mountinfo.write(f"1 0 1:1 / / - fat {context.staging / context.config.output_with_format}\n")
        mountinfo.flush()

        # We don't setup the mountinfo bind mount with bwrap because we need to know the child process pid to
        # be able to do the mount and we don't know the pid beforehand.
        run(
            [
                setup,
                "--directory", "/grub",
                context.staging / context.config.output_with_format,
            ],
            sandbox=context.sandbox(
                binary=setup,
                mounts=[
                    Mount(directory, "/grub"),
                    Mount(context.staging, context.staging),
                    Mount(mountinfo.name, mountinfo.name),
                ],
                extra=["sh", "-c", f"mount --bind {mountinfo.name} /proc/$$/mountinfo && exec $0 \"$@\""],
            ),
        )


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
            src, t,
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
            ["systemd-dissect", "--copy-from", src, "/", t],
            sandbox=config.sandbox(
                binary="systemd-dissect",
                devices=True,
                network=True,
                mounts=[Mount(src, src, ro=True), Mount(t.parent, t.parent)],
            ),
        )
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


def install_package_manager_trees(context: Context) -> None:
    # Ensure /etc exists in the package manager tree
    (context.pkgmngr / "etc").mkdir(exist_ok=True)

    # Backwards compatibility symlink.
    (context.pkgmngr / "etc/mtab").symlink_to("../proc/self/mounts")

    # Required to be able to access certificates in the sandbox when running from nix.
    if Path("/etc/static").is_symlink():
        (context.pkgmngr / "etc/static").symlink_to(Path("/etc/static").readlink())

    (context.pkgmngr / "var/log").mkdir(parents=True)

    with (context.pkgmngr / "etc/passwd").open("w") as passwd:
        passwd.write("root:x:0:0:root:/root:/bin/sh\n")
        if INVOKING_USER.uid != 0:
            name = INVOKING_USER.name()
            home = INVOKING_USER.home()
            passwd.write(f"{name}:x:{INVOKING_USER.uid}:{INVOKING_USER.gid}:{name}:{home}:/bin/sh\n")
        os.fchown(passwd.fileno(), INVOKING_USER.uid, INVOKING_USER.gid)

    with (context.pkgmngr / "etc/group").open("w") as group:
        group.write("root:x:0:\n")
        if INVOKING_USER.uid != 0:
            group.write(f"{INVOKING_USER.name()}:x:{INVOKING_USER.gid}:\n")
        os.fchown(group.fileno(), INVOKING_USER.uid, INVOKING_USER.gid)

    if (p := context.config.tools() / "etc/crypto-policies").exists():
        copy_tree(
            p, context.pkgmngr / "etc/crypto-policies",
            preserve=False,
            dereference=True,
            sandbox=context.config.sandbox,
        )

    if not context.config.package_manager_trees:
        return

    with complete_step("Copying in package manager file trees…"):
        for tree in context.config.package_manager_trees:
            install_tree(context.config, tree.source, context.pkgmngr, target=tree.target, preserve=False)


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
            context.install_dir, context.root,
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
            # Some distributions (OpenMandriva) symlink /usr/lib/modules/<kver>/vmlinuz to /boot/vmlinuz-<kver>, so
            # get rid of the symlink and copy the actual vmlinuz to /usr/lib/modules/<kver>.
            if vmlinuz.is_symlink() and vmlinuz.is_relative_to("/boot"):
                vmlinuz.unlink()
            if not vmlinuz.exists():
                shutil.copy2(d, vmlinuz)


def gen_kernel_images(context: Context) -> Iterator[tuple[str, Path]]:
    if not (context.root / "usr/lib/modules").exists():
        return

    for kver in sorted(
        (k for k in (context.root / "usr/lib/modules").iterdir() if k.is_dir()),
        key=lambda k: GenericVersion(k.name),
        reverse=True
    ):
        # Make sure we look for anything that remotely resembles vmlinuz, as
        # the arch specific install scripts in the kernel source tree sometimes
        # do weird stuff. But let's make sure we're not returning UKIs as the
        # UKI on Fedora is named vmlinuz-virt.efi. Also look for uncompressed
        # images (vmlinux) as some architectures ship those. Prefer vmlinuz if
        # both are present.
        for kimg in kver.glob("vmlinuz*"):
            if KernelType.identify(context.config, kimg) != KernelType.uki:
                yield kver.name, kimg
                break
        else:
            for kimg in kver.glob("vmlinux*"):
                if KernelType.identify(context.config, kimg) != KernelType.uki:
                    yield kver.name, kimg
                    break


def want_initrd(context: Context) -> bool:
    if context.config.bootable == ConfigFeature.disabled:
        return False

    if context.config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        return False

    if not any((context.artifacts / "io.mkosi.initrd").glob("*")) and not any(gen_kernel_images(context)):
        return False

    return True


def finalize_default_initrd(
    args: Args,
    config: Config,
    *,
    resources: Path,
    output_dir: Optional[Path] = None,
) -> Config:
    if config.root_password:
        password, hashed = config.root_password
        rootpwopt = f"hashed:{password}" if hashed else password
    else:
        rootpwopt = None

    relabel = ConfigFeature.auto if config.selinux_relabel == ConfigFeature.enabled else config.selinux_relabel

    # Default values are assigned via the parser so we go via the argument parser to construct
    # the config for the initrd.
    cmdline = [
        "--directory", "",
        "--distribution", str(config.distribution),
        "--release", config.release,
        "--architecture", str(config.architecture),
        *(["--mirror", config.mirror] if config.mirror else []),
        "--repository-key-check", str(config.repository_key_check),
        "--repository-key-fetch", str(config.repository_key_fetch),
        "--repositories", ",".join(config.repositories),
        "--package-manager-tree", ",".join(str(t) for t in config.package_manager_trees),
        # Note that when compress_output == Compression.none == 0 we don't pass --compress-output which means the
        # default compression will get picked. This is exactly what we want so that initrds are always compressed.
        *(["--compress-output", str(config.compress_output)] if config.compress_output else []),
        "--compress-level", str(config.compress_level),
        "--with-network", str(config.with_network),
        "--cache-only", str(config.cacheonly),
        *(["--output-dir", str(output_dir)] if output_dir else []),
        *(["--workspace-dir", str(config.workspace_dir)] if config.workspace_dir else []),
        *(["--cache-dir", str(config.cache_dir)] if config.cache_dir else []),
        *(["--package-cache-dir", str(config.package_cache_dir)] if config.package_cache_dir else []),
        *(["--local-mirror", str(config.local_mirror)] if config.local_mirror else []),
        "--incremental", str(config.incremental),
        "--acl", str(config.acl),
        *(f"--package={package}" for package in config.initrd_packages),
        *(f"--volatile-package={package}" for package in config.initrd_volatile_packages),
        *(f"--package-directory={d}" for d in config.package_directories),
        *(f"--volatile-package-directory={d}" for d in config.volatile_package_directories),
        "--output", "initrd",
        *(["--image-id", config.image_id] if config.image_id else []),
        *(["--image-version", config.image_version] if config.image_version else []),
        *(
            ["--source-date-epoch", str(config.source_date_epoch)]
            if config.source_date_epoch is not None else
            []
        ),
        *(["--locale", config.locale] if config.locale else []),
        *(["--locale-messages", config.locale_messages] if config.locale_messages else []),
        *(["--keymap", config.keymap] if config.keymap else []),
        *(["--timezone", config.timezone] if config.timezone else []),
        *(["--hostname", config.hostname] if config.hostname else []),
        *(["--root-password", rootpwopt] if rootpwopt else []),
        *([f"--environment={k}='{v}'" for k, v in config.environment.items()]),
        *(["--tools-tree", str(config.tools_tree)] if config.tools_tree else []),
        *([f"--extra-search-path={p}" for p in config.extra_search_paths]),
        *(["--proxy-url", config.proxy_url] if config.proxy_url else []),
        *([f"--proxy-exclude={host}" for host in config.proxy_exclude]),
        *(["--proxy-peer-certificate", str(p)] if (p := config.proxy_peer_certificate) else []),
        *(["--proxy-client-certificate", str(p)] if (p := config.proxy_client_certificate) else []),
        *(["--proxy-client-key", str(p)] if (p := config.proxy_client_key) else []),
        "--selinux-relabel", str(relabel),
        *(["-f"] * args.force),
    ]

    cmdline += ["--include=mkosi-initrd"]

    for include in config.initrd_include:
        cmdline += ["--include", os.fspath(include)]

    _, [config] = parse_config(cmdline + ["build"], resources=resources)

    run_configure_scripts(config)

    return dataclasses.replace(config, image="default-initrd")


def build_default_initrd(context: Context) -> Path:
    if context.config.distribution == Distribution.custom:
        die("Building a default initrd is not supported for custom distributions")

    config = finalize_default_initrd(
        context.args,
        context.config,
        resources=context.resources,
        output_dir=context.workspace,
    )

    assert config.output_dir

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
                # Re-use the repository metadata snapshot from the main image for the initrd.
                package_cache_dir=context.package_cache_dir,
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
        initrd = finalize_default_initrd(context.args, context.config, resources=context.resources)
        final.update(initrd.kernel_modules_include)
    if host or "host" in include:
        final.update(loaded_modules())

    return final


def build_kernel_modules_initrd(context: Context, kver: str) -> Path:
    kmods = context.workspace / f"kernel-modules-{kver}.initrd"
    if kmods.exists():
        return kmods

    make_cpio(
        context.root, kmods,
        files=gen_required_kernel_modules(
            context.root, kver,
            include=finalize_kernel_modules_include(
                context,
                include=context.config.kernel_modules_initrd_include,
                host=context.config.kernel_modules_initrd_include_host,
            ),
            exclude=context.config.kernel_modules_initrd_exclude,
            sandbox=context.sandbox,
        ),
        sandbox=context.sandbox,
    )


    if context.config.distribution.is_apt_distribution():
        # Ubuntu Focal's kernel does not support zstd-compressed initrds so use xz instead.
        if context.config.distribution == Distribution.ubuntu and context.config.release == "focal":
            compression = Compression.xz
        # Older Debian and Ubuntu releases do not compress their kernel modules, so we compress the initramfs instead.
        # Note that this is not ideal since the compressed kernel modules will all be decompressed on boot which
        # requires significant memory.
        elif context.config.distribution == Distribution.debian and context.config.release in ("sid", "testing"):
            compression = Compression.none
        else:
            compression = Compression.zstd

        maybe_compress(context, compression, kmods, kmods)

    return kmods


def join_initrds(initrds: Sequence[Path], output: Path) -> Path:
    assert initrds

    if len(initrds) == 1:
        shutil.copy2(initrds[0], output)
        return output

    seq = io.BytesIO()
    for p in initrds:
        initrd = p.read_bytes()
        n = len(initrd)
        padding = b'\0' * (round_up(n, 4) - n)  # pad to 32 bit alignment
        seq.write(initrd)
        seq.write(padding)

    output.write_bytes(seq.getbuffer())
    return output


def python_binary(config: Config, *, binary: Optional[PathString]) -> str:
    tools = (
        not binary or
        not (path := config.find_binary(binary)) or
        not any(path.is_relative_to(d) for d in config.extra_search_paths)
    )

    # If there's no tools tree, prefer the interpreter from MKOSI_INTERPRETER. If there is a tools
    # tree, just use the default python3 interpreter.
    return "python3" if tools and config.tools_tree else os.getenv("MKOSI_INTERPRETER", "python3")


def extract_pe_section(context: Context, binary: Path, section: str, output: Path) -> Path:
    # When using a tools tree, we want to use the pefile module from the tools tree instead of requiring that
    # python-pefile is installed on the host. So we execute python as a subprocess to make sure we load
    # pefile from the tools tree if one is used.

    # TODO: Use ignore_padding=True instead of length once we can depend on a newer pefile.
    # TODO: Drop KeyError logic once we drop support for Ubuntu Jammy and sdmagic will always be available.
    pefile = textwrap.dedent(
        f"""\
        import pefile
        import sys
        from pathlib import Path
        pe = pefile.PE("{binary}", fast_load=True)
        section = {{s.Name.decode().strip("\\0"): s for s in pe.sections}}.get("{section}")
        if not section:
            sys.exit(67)
        sys.stdout.buffer.write(section.get_data(length=section.Misc_VirtualSize))
        """
    )

    with open(output, "wb") as f:
        result = run(
            [python_binary(context.config, binary=None)],
            input=pefile,
            stdout=f,
            sandbox=context.sandbox(
                binary=python_binary(context.config, binary=None),
                mounts=[Mount(binary, binary, ro=True),
            ]),
            success_exit_status=(0, 67),
        )
        if result.returncode == 67:
            raise KeyError(f"{section} section not found in {binary}")

    return output


def want_signed_pcrs(config: Config) -> bool:
    return (
        config.sign_expected_pcr == ConfigFeature.enabled or
        (
            config.sign_expected_pcr == ConfigFeature.auto and
            config.find_binary("systemd-measure", "/usr/lib/systemd/systemd-measure") is not None
        )
    )


def build_uki(
    context: Context,
    stub: Path,
    kver: str,
    kimg: Path,
    microcodes: list[Path],
    initrds: list[Path],
    cmdline: Sequence[str],
    output: Path,
) -> None:
    # Older versions of systemd-stub expect the cmdline section to be null terminated. We can't embed
    # nul terminators in argv so let's communicate the cmdline via a file instead.
    (context.workspace / "cmdline").write_text(f"{' '.join(cmdline).strip()}\x00")

    if not (arch := context.config.architecture.to_efi()):
        die(f"Architecture {context.config.architecture} does not support UEFI")

    if not (ukify := context.config.find_binary("ukify", "/usr/lib/systemd/ukify")):
        die("Could not find ukify")

    cmd: list[PathString] = [
        python_binary(context.config, binary=ukify),
        ukify,
        *(["--cmdline", f"@{context.workspace / 'cmdline'}"] if cmdline else []),
        "--os-release", f"@{context.root / 'usr/lib/os-release'}",
        "--stub", stub,
        "--output", output,
        "--efi-arch", arch,
        "--uname", kver,
    ]

    mounts = [
        Mount(output.parent, output.parent),
        Mount(context.workspace / "cmdline", context.workspace / "cmdline", ro=True),
        Mount(context.root / "usr/lib/os-release", context.root / "usr/lib/os-release", ro=True),
        Mount(stub, stub, ro=True),
    ]

    if context.config.secure_boot:
        assert context.config.secure_boot_key
        assert context.config.secure_boot_certificate

        cmd += ["--sign-kernel"]

        if context.config.secure_boot_sign_tool != SecureBootSignTool.pesign:
            cmd += [
                "--signtool", "sbsign",
                "--secureboot-private-key",
                context.config.secure_boot_key,
                "--secureboot-certificate",
                context.config.secure_boot_certificate,
            ]
            mounts += [
                Mount(context.config.secure_boot_certificate, context.config.secure_boot_certificate, ro=True),
            ]
            if context.config.secure_boot_key_source.type == KeySource.Type.engine:
                cmd += ["--signing-engine", context.config.secure_boot_key_source.source]
            if context.config.secure_boot_key.exists():
                mounts += [Mount(context.config.secure_boot_key, context.config.secure_boot_key, ro=True)]
        else:
            pesign_prepare(context)
            cmd += [
                "--signtool", "pesign",
                "--secureboot-certificate-dir",
                context.workspace / "pesign",
                "--secureboot-certificate-name",
                certificate_common_name(context, context.config.secure_boot_certificate),
            ]
            mounts += [Mount(context.workspace / "pesign", context.workspace / "pesign", ro=True)]

        if want_signed_pcrs(context.config):
            cmd += [
                "--pcr-private-key", context.config.secure_boot_key,
                # SHA1 might be disabled in OpenSSL depending on the distro so we opt to not sign for SHA1 to avoid
                # having to manage a bunch of configuration to re-enable SHA1.
                "--pcr-banks", "sha256",
            ]
            if context.config.secure_boot_key.exists():
                mounts += [Mount(context.config.secure_boot_key, context.config.secure_boot_key)]
            if context.config.secure_boot_key_source.type == KeySource.Type.engine:
                cmd += [
                    "--signing-engine", context.config.secure_boot_key_source.source,
                    "--pcr-public-key", context.config.secure_boot_certificate,
                ]
                mounts += [
                    Mount(context.config.secure_boot_certificate, context.config.secure_boot_certificate, ro=True),
                ]

    cmd += ["build", "--linux", kimg]
    mounts += [Mount(kimg, kimg, ro=True)]

    if microcodes:
        # new .ucode section support?
        if (
            systemd_tool_version(
                python_binary(context.config, binary=ukify),
                ukify,
                sandbox=context.sandbox,
            ) >= "256" and
            (version := systemd_stub_version(context, stub)) and
            version >= "256"
        ):
            for microcode in microcodes:
                cmd += ["--microcode", microcode]
                mounts += [Mount(microcode, microcode, ro=True)]
        else:
            initrds = microcodes + initrds

    for initrd in initrds:
        cmd += ["--initrd", initrd]
        mounts += [Mount(initrd, initrd, ro=True)]

    with complete_step(f"Generating unified kernel image for kernel version {kver}"):
        run(
            cmd,
            sandbox=context.sandbox(
                binary=ukify,
                mounts=mounts,
                devices=context.config.secure_boot_key_source.type != KeySource.Type.file,
            ),
        )


def want_efi(config: Config) -> bool:
    # Do we want to make the image bootable on EFI firmware?
    # Note that this returns True also in the case where autodetection might later
    # cause the system to not be made bootable on EFI firmware after the filesystem
    # has been populated.

    if config.output_format in (OutputFormat.uki, OutputFormat.esp):
        return True

    if config.bootable == ConfigFeature.disabled:
        return False

    if config.bootloader == Bootloader.none:
        return False

    if (
        (config.output_format == OutputFormat.cpio or config.output_format.is_extension_image() or config.overlay)
        and config.bootable == ConfigFeature.auto
    ):
        return False

    if config.architecture.to_efi() is None:
        if config.bootable == ConfigFeature.enabled:
            die(f"Cannot make image bootable on UEFI on {config.architecture} architecture")

        return False

    return True


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

    # Older versions of the stub have misaligned sections which results in an empty sdmagic text. Let's check for that
    # explicitly and treat it as no version.
    # TODO: Drop this logic once every distribution we support ships systemd-stub v254 or newer.
    if not sdmagic_text:
        return None

    if not (version := re.match(r"#### LoaderInfo: systemd-stub (?P<version>[.~^a-zA-Z0-9-+]+) ####", sdmagic_text)):
        die(f"Unable to determine systemd-stub version, found {sdmagic_text!r}")

    return GenericVersion(version.group("version"))


def want_uki(context: Context) -> bool:
    return want_efi(context.config) and (
            context.config.bootloader == Bootloader.uki or
            context.config.unified_kernel_images == ConfigFeature.enabled or (
                context.config.unified_kernel_images == ConfigFeature.auto and
                systemd_stub_binary(context).exists() and
                context.config.find_binary("ukify", "/usr/lib/systemd/ukify") is not None
            )
    )


def find_entry_token(context: Context) -> str:
    if (
        not context.config.find_binary("kernel-install") or
        "--version" not in run(["kernel-install", "--help"],
                               stdout=subprocess.PIPE, sandbox=context.sandbox(binary="kernel-install")).stdout or
        systemd_tool_version("kernel-install", sandbox=context.sandbox) < "255.1"
    ):
        return context.config.image_id or context.config.distribution.name

    output = json.loads(
        run(
            ["kernel-install", "--root=/buildroot", "--json=pretty", "inspect"],
            sandbox=context.sandbox(binary="kernel-install", mounts=[Mount(context.root, "/buildroot", ro=True)]),
            stdout=subprocess.PIPE,
            env={"BOOT_ROOT": "/boot"},
        ).stdout
    )

    logging.debug(json.dumps(output, indent=4))
    return cast(str, output["EntryToken"])


def finalize_cmdline(context: Context, partitions: Sequence[Partition], roothash: Optional[str]) -> list[str]:
    if (context.root / "etc/kernel/cmdline").exists():
        cmdline = [(context.root / "etc/kernel/cmdline").read_text().strip()]
    elif (context.root / "usr/lib/kernel/cmdline").exists():
        cmdline = [(context.root / "usr/lib/kernel/cmdline").read_text().strip()]
    else:
        cmdline = []

    if roothash:
        cmdline += [roothash]

    cmdline += context.config.kernel_command_line

    if not roothash:
        for name in ("root", "mount.usr"):
            type_prefix = name.removeprefix("mount.")
            if not (root := next((p.uuid for p in partitions if p.type.startswith(type_prefix)), None)):
                continue

            cmdline = [f"{name}=PARTUUID={root}" if c == f"{name}=PARTUUID" else c for c in cmdline]

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
) -> None:
    dst = context.root / "boot" / token / kver
    entry = context.root / f"boot/loader/entries/{token}-{kver}.conf"
    with umask(~0o700):
        dst.mkdir(parents=True, exist_ok=True)
        entry.parent.mkdir(parents=True, exist_ok=True)

    kmods = build_kernel_modules_initrd(context, kver)
    cmdline = finalize_cmdline(context, partitions, finalize_roothash(partitions))

    with umask(~0o600):
        if (
            want_efi(context.config) and
            context.config.secure_boot and
            context.config.shim_bootloader != ShimBootloader.signed and
            KernelType.identify(context.config, kimg) == KernelType.pe
        ):
            kimg = sign_efi_binary(context, kimg, dst / "vmlinuz")
        else:
            kimg = Path(shutil.copy2(context.root / kimg, dst / "vmlinuz"))

        initrds = [
            Path(shutil.copy2(initrd, dst.parent / initrd.name))
            for initrd in finalize_microcode(context) + finalize_initrds(context)
        ]
        initrds += [Path(shutil.copy2(kmods, dst / "kernel-modules.initrd"))]

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
                f.write(f'initrd /{initrd.relative_to(context.root / "boot")}\n')

    if want_grub_efi(context) or want_grub_bios(context, partitions):
        config = prepare_grub_config(context)
        assert config

        if (
            not any(c.startswith("root=PARTUUID=") for c in context.config.kernel_command_line) and
            not any(c.startswith("mount.usr=PARTUUID=") for c in context.config.kernel_command_line) and
            (root := finalize_root(partitions))
        ):
            cmdline = [root] + cmdline

        with config.open("a") as f:
            f.write("if ")

            conditions = []
            if want_grub_efi(context) and not want_uki(context):
                conditions += ['[ "${grub_platform}" = efi ]']
            if want_grub_bios(context, partitions):
                conditions += ['[ "${grub_platform}" = pc ]']

            f.write(" || ".join(conditions))
            f.write("; then\n")

            f.write(
                textwrap.dedent(
                    f"""\
                    menuentry "{token}-{kver}" {{
                        linux /{kimg.relative_to(context.root / "boot")} {" ".join(cmdline)}
                        initrd {" ".join(os.fspath(Path("/") / i.relative_to(context.root / "boot")) for i in initrds)}
                    }}
                    """
                )
            )

            f.write("fi\n")


def expand_kernel_specifiers(text: str, kver: str, token: str, roothash: str, boot_count: str) -> str:
    specifiers = {
        "&": "&",
        "e": token,
        "k": kver,
        "h": roothash,
        "c": boot_count
    }

    def replacer(match: re.Match[str]) -> str:
        m = match.group("specifier")
        if specifier := specifiers.get(m):
            return specifier

        logging.warning(f"Unknown specifier '&{m}' found in {text}, ignoring")
        return ""

    return re.sub(r"&(?P<specifier>[&a-zA-Z])", replacer, text)


def install_uki(context: Context, kver: str, kimg: Path, token: str, partitions: Sequence[Partition]) -> None:
    bootloader_entry_format = context.config.unified_kernel_image_format or "&e-&k"

    roothash_value = ""
    if roothash := finalize_roothash(partitions):
        roothash_value = roothash.partition("=")[2]

        if not context.config.unified_kernel_image_format:
            bootloader_entry_format += "-&h"

    boot_count = ""
    if (context.root / "etc/kernel/tries").exists():
        boot_count = (context.root / "etc/kernel/tries").read_text().strip()

        if not context.config.unified_kernel_image_format:
            bootloader_entry_format += "+&c"

    bootloader_entry = expand_kernel_specifiers(
        bootloader_entry_format,
        kver=kver,
        token=token,
        roothash=roothash_value,
        boot_count=boot_count,
    )

    if context.config.bootloader == Bootloader.uki:
        if context.config.shim_bootloader != ShimBootloader.none:
            boot_binary = context.root / shim_second_stage_binary(context)
        else:
            boot_binary = context.root / efi_boot_binary(context)
    else:
        boot_binary = context.root / f"boot/EFI/Linux/{bootloader_entry}.efi"

    # Make sure the parent directory where we'll be writing the UKI exists.
    with umask(~0o700):
        boot_binary.parent.mkdir(parents=True, exist_ok=True)

    if context.config.shim_bootloader == ShimBootloader.signed:
        for p in (context.root / "usr/lib/modules" / kver).glob("*.efi"):
            log_step(f"Installing prebuilt UKI at {p} to {boot_binary}")
            shutil.copy2(p, boot_binary)
            break
        else:
            if context.config.bootable == ConfigFeature.enabled:
                die(f"Couldn't find a signed UKI binary installed at /usr/lib/modules/{kver} in the image")

            return
    else:
        microcodes = finalize_microcode(context)

        initrds = finalize_initrds(context)
        if context.config.kernel_modules_initrd:
            initrds += [build_kernel_modules_initrd(context, kver)]

        build_uki(
            context,
            systemd_stub_binary(context),
            kver,
            context.root / kimg,
            microcodes,
            initrds,
            finalize_cmdline(context, partitions, roothash),
            boot_binary,
        )

        print_output_size(boot_binary)

    if want_grub_efi(context):
        config = prepare_grub_config(context)
        assert config

        with config.open("a") as f:
            f.write('if [ "${grub_platform}" = efi ]; then\n')

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


def install_kernel(context: Context, partitions: Sequence[Partition]) -> None:
    # Iterates through all kernel versions included in the image and generates a combined
    # kernel+initrd+cmdline+osrelease EFI file from it and places it in the /EFI/Linux directory of the ESP.
    # sd-boot iterates through them and shows them in the menu. These "unified" single-file images have the
    # benefit that they can be signed like normal EFI binaries, and can encode everything necessary to boot a
    # specific root device, including the root hash.

    if context.config.output_format in (OutputFormat.uki, OutputFormat.esp):
        return

    if context.config.bootable == ConfigFeature.disabled:
        return

    if context.config.bootable == ConfigFeature.auto and (
        context.config.output_format == OutputFormat.cpio or
        context.config.output_format.is_extension_image() or
        context.config.overlay
    ):
        return

    stub = systemd_stub_binary(context)
    if want_uki(context) and not stub.exists():
        die(f"Unified kernel image(s) requested but systemd-stub not found at /{stub.relative_to(context.root)}")

    if context.config.bootable == ConfigFeature.enabled and not any(gen_kernel_images(context)):
        die("A bootable image was requested but no kernel was found")

    token = find_entry_token(context)

    for kver, kimg in gen_kernel_images(context):
        if want_uki(context):
            install_uki(context, kver, kimg, token, partitions)
        if not want_uki(context) or want_grub_bios(context, partitions):
            install_type1(context, kver, kimg, token, partitions)

        if context.config.bootloader == Bootloader.uki:
            break


def make_uki(context: Context, stub: Path, kver: str, kimg: Path, microcode: list[Path], output: Path) -> None:
    make_cpio(context.root, context.workspace / "initrd", sandbox=context.sandbox)
    maybe_compress(context, context.config.compress_output, context.workspace / "initrd", context.workspace / "initrd")

    initrds = [context.workspace / "initrd"]

    build_uki(context, stub, kver, kimg, microcode, initrds, context.config.kernel_command_line, output)
    extract_pe_section(context, output, ".linux", context.staging / context.config.output_split_kernel)
    extract_pe_section(context, output, ".initrd", context.staging / context.config.output_split_initrd)


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


def maybe_compress(context: Context, compression: Compression, src: Path, dst: Optional[Path] = None) -> None:
    if not compression or src.is_dir():
        if dst:
            move_tree(
                src, dst,
                use_subvolumes=context.config.use_subvolumes,
                sandbox=context.sandbox,
            )
        return

    if not dst:
        dst = src.parent / f"{src.name}{compression.extension()}"

    cmd = compressor_command(context, compression)

    with complete_step(f"Compressing {src} with {compression}"):
        with src.open("rb") as i:
            src.unlink() # if src == dst, make sure dst doesn't truncate the src file but creates a new file.

            with dst.open("wb") as o:
                run(cmd, stdin=i, stdout=o, sandbox=context.sandbox(binary=cmd[0]))


def copy_uki(context: Context) -> None:
    if (context.staging / context.config.output_split_uki).exists():
        return

    if not want_efi(context.config) or context.config.unified_kernel_images == ConfigFeature.disabled:
        return

    ukis = sorted(
        (context.root / "boot/EFI/Linux").glob("*.efi"),
        key=lambda p: GenericVersion(p.name),
        reverse=True,
    )

    if (
        (uki := context.root / efi_boot_binary(context)).exists() and
        KernelType.identify(context.config, uki) == KernelType.uki
    ):
        pass
    elif (
        (uki := context.root / shim_second_stage_binary(context)).exists() and
        KernelType.identify(context.config, uki) == KernelType.uki
    ):
        pass
    elif ukis:
        uki = ukis[0]
    else:
        return

    shutil.copy(uki, context.staging / context.config.output_split_uki)

    # Extract the combined initrds from the UKI so we can use it to direct kernel boot with qemu if needed.
    extract_pe_section(context, uki, ".initrd", context.staging / context.config.output_split_initrd)

    # ukify will have signed the kernel image as well. Let's make sure we put the signed kernel image in the output
    # directory instead of the unsigned one by reading it from the UKI.
    extract_pe_section(context, uki, ".linux", context.staging / context.config.output_split_kernel)


def copy_vmlinuz(context: Context) -> None:
    if (context.staging / context.config.output_split_kernel).exists():
        return

    for _, kimg in gen_kernel_images(context):
        shutil.copy(context.root / kimg, context.staging / context.config.output_split_kernel)
        break


def copy_nspawn_settings(context: Context) -> None:
    if context.config.nspawn_settings is None:
        return None

    with complete_step("Copying nspawn settings file…"):
        shutil.copy2(context.config.nspawn_settings, context.staging / context.config.output_nspawn_settings)


def copy_initrd(context: Context) -> None:
    if not want_initrd(context):
        return

    if (context.staging / context.config.output_split_initrd).exists():
        return

    for kver, _ in gen_kernel_images(context):
        initrds = finalize_initrds(context)

        if context.config.kernel_modules_initrd:
            kver = next(gen_kernel_images(context))[0]
            initrds += [build_kernel_modules_initrd(context, kver)]
        join_initrds(initrds, context.staging / context.config.output_split_initrd)
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

        (context.workspace / context.config.output_checksum).rename(context.staging / context.config.output_checksum)


def calculate_signature(context: Context) -> None:
    if not context.config.sign or not context.config.checksum:
        return

    cmdline: list[PathString] = ["gpg", "--detach-sign"]

    # Need to specify key before file to sign
    if context.config.key is not None:
        cmdline += ["--default-key", context.config.key]

    cmdline += ["--output", "-", "-"]

    home = Path(context.config.environment.get("GNUPGHOME", INVOKING_USER.home() / ".gnupg"))
    if not home.exists():
        die(f"GPG home {home} not found")

    env = dict(GNUPGHOME=os.fspath(home))
    if sys.stderr.isatty():
        env |= dict(GPGTTY=os.ttyname(sys.stderr.fileno()))

    options: list[PathString] = ["--perms", "755", "--dir", home]
    mounts = [Mount(home, home)]

    # gpg can communicate with smartcard readers via this socket so bind mount it in if it exists.
    if (p := Path("/run/pcscd/pcscd.comm")).exists():
        options += ["--perms", "755", "--dir", p.parent]
        mounts += [Mount(p, p)]

    with (
        complete_step("Signing SHA256SUMS…"),
        open(context.staging / context.config.output_checksum, "rb") as i,
        open(context.staging / context.config.output_signature, "wb") as o,
    ):
        run(
            cmdline,
            env=env,
            stdin=i,
            stdout=o,
            # GPG messes with the user's home directory so we run it as the invoking user.
            sandbox=context.sandbox(
                binary="gpg",
                mounts=mounts,
                options=options,
                extra=["setpriv", f"--reuid={INVOKING_USER.uid}", f"--regid={INVOKING_USER.gid}", "--clear-groups"],
            )
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


def save_manifest(context: Context, manifest: Optional[Manifest]) -> None:
    if not manifest:
        return

    if manifest.has_data():
        if ManifestFormat.json in context.config.manifest_format:
            with complete_step(f"Saving manifest {context.config.output_manifest}"):
                with open(context.staging / context.config.output_manifest, 'w') as f:
                    manifest.write_json(f)

        if ManifestFormat.changelog in context.config.manifest_format:
            with complete_step(f"Saving report {context.config.output_changelog}"):
                with open(context.staging / context.config.output_changelog, 'w') as f:
                    manifest.write_package_report(f)


def print_output_size(path: Path) -> None:
    if path.is_dir():
        log_step(f"{path} size is " + format_bytes(dir_size(path)) + ".")
    else:
        size = format_bytes(path.stat().st_size)
        space = format_bytes(path.stat().st_blocks * 512)
        log_step(f"{path} size is {size}, consumes {space}.")


def cache_tree_paths(config: Config) -> tuple[Path, Path, Path]:
    fragments = [config.distribution, config.release, config.architecture]

    if config.image:
        fragments += [config.image]

    key = '~'.join(str(s) for s in fragments)

    assert config.cache_dir
    return (
        config.cache_dir / f"{key}.cache",
        config.cache_dir / f"{key}.build.cache",
        config.cache_dir / f"{key}.manifest",
    )


def check_inputs(config: Config) -> None:
    """
    Make sure all the inputs exist that aren't checked during config parsing because they might be created by an
    earlier build.
    """
    for base in config.base_trees:
        if not base.exists():
            die(f"Base tree {base} not found")

        if base.is_file() and base.suffix == ".raw" and os.getuid() != 0:
            die("Must run as root to use disk images in base trees")

    if config.tools_tree and not config.tools_tree.exists():
        die(f"Tools tree {config.tools_tree} not found")

    trees = [
        ("skeleton", config.skeleton_trees),
        ("package manager", config.package_manager_trees),
    ]

    if config.output_format != OutputFormat.none:
        trees += [("extra", config.extra_trees)]

    for name, trees in trees:
        for tree in trees:
            if not tree.source.exists():
                die(f"{name.capitalize()} tree {tree.source} not found")

            if tree.source.is_file() and tree.source.suffix == ".raw" and not tree.target and os.getuid() != 0:
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


def check_outputs(config: Config) -> None:
    if config.output_format == OutputFormat.none:
        return

    f = config.output_dir_or_cwd() / config.output_with_compression

    if f.exists() and not f.is_symlink():
        logging.info(f"Output path {f} exists already. (Use --force to rebuild.)")


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
        die(f"Found '{tool}' with version {v} but version {version} or newer is required to {reason}.",
            hint=f"Use ToolsTree=default to get a newer version of '{tools[0]}'.")


def check_ukify(
    config: Config,
    version: str,
    reason: str,
    hint: Optional[str] = None,
) -> None:
    ukify = check_tool(config, "ukify", "/usr/lib/systemd/ukify", reason=reason, hint=hint)

    v = systemd_tool_version(python_binary(config, binary=ukify), ukify, sandbox=config.sandbox)
    if v < version:
        die(f"Found '{ukify}' with version {v} but version {version} or newer is required to {reason}.",
            hint="Use ToolsTree=default to get a newer version of 'ukify'.")


def check_tools(config: Config, verb: Verb) -> None:
    check_tool(config, "bwrap", reason="execute sandboxed commands")

    if verb == Verb.build:
        if config.bootable != ConfigFeature.disabled:
            check_tool(config, "depmod", reason="generate kernel module dependencies")

        if want_efi(config) and config.unified_kernel_images == ConfigFeature.enabled:
            check_ukify(
                config,
                version="254",
                reason="build bootable images",
                hint="Use ToolsTree=default to download most required tools including ukify automatically or use "
                     "Bootable=no to create a non-bootable image which doesn't require ukify",
            )

        if config.output_format in (OutputFormat.disk, OutputFormat.esp):
            check_systemd_tool(config, "systemd-repart", version="254", reason="build disk images")

        if config.selinux_relabel == ConfigFeature.enabled:
            check_tool(config, "setfiles", reason="relabel files")

        if config.secure_boot_key_source.type != KeySource.Type.file:
            check_ukify(
                config,
                version="256",
                reason="sign Unified Kernel Image with OpenSSL engine",
            )

            if want_signed_pcrs(config):
                check_systemd_tool(
                    config,
                    "systemd-measure",
                    version="256",
                    reason="sign PCR hashes with OpenSSL engine",
                )

        if config.verity_key_source.type != KeySource.Type.file:
            check_systemd_tool(
                config,
                "systemd-repart",
                version="256",
                reason="sign verity roothash signature with OpenSSL engine",
            )

        if want_efi(config) and config.secure_boot and config.secure_boot_auto_enroll:
            check_tool(config, "sbsiglist", reason="set up systemd-boot secure boot auto-enrollment")
            check_tool(config, "sbvarsign", reason="set up systemd-boot secure boot auto-enrollment")

    if verb == Verb.boot:
        check_systemd_tool(config, "systemd-nspawn", version="254", reason="boot images")

    if verb == Verb.qemu and config.vmm == Vmm.vmspawn:
        check_systemd_tool(config, "systemd-vmspawn", version="256", reason="boot images with vmspawn")


def configure_ssh(context: Context) -> None:
    if not context.config.ssh:
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
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    if (
        not (context.root / "init").exists() and
        not (context.root / "init").is_symlink() and
        (context.root / "usr/lib/systemd/systemd").exists()
    ):
        (context.root / "init").symlink_to("/usr/lib/systemd/systemd")

    if not context.config.make_initrd:
        return

    if not (context.root / "etc/initrd-release").exists() and not (context.root / "etc/initrd-release").is_symlink():
        (context.root / "etc/initrd-release").symlink_to("/etc/os-release")


def configure_clock(context: Context) -> None:
    if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
        return

    with umask(~0o644):
        (context.root / "usr/lib/clock-epoch").touch()


def run_depmod(context: Context, *, cache: bool = False) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    outputs = (
        "modules.dep",
        "modules.dep.bin",
        "modules.symbols",
        "modules.symbols.bin",
    )

    for kver, _ in gen_kernel_images(context):
        modulesd = context.root / "usr/lib/modules" / kver

        if (
            not cache and
            not context.config.kernel_modules_exclude and
            all((modulesd / o).exists() for o in outputs)
        ):
            mtime = (modulesd / "modules.dep").stat().st_mtime
            if all(m.stat().st_mtime <= mtime for m in modulesd.rglob("*.ko*")):
                continue

        if not cache:
            process_kernel_modules(
                context.root, kver,
                include=finalize_kernel_modules_include(
                    context,
                    include=context.config.kernel_modules_include,
                    host=context.config.kernel_modules_include_host,
                ),
                exclude=context.config.kernel_modules_exclude,
                sandbox=context.sandbox,
            )

        with complete_step(f"Running depmod for {kver}"):
            run(
                ["depmod", "--all", kver],
                sandbox=context.sandbox(
                    binary=None,
                    mounts=[Mount(context.root, "/buildroot")],
                    extra=chroot_cmd(),
                )
            )


def run_sysusers(context: Context) -> None:
    if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
        return

    if not context.config.find_binary("systemd-sysusers"):
        logging.warning("systemd-sysusers is not installed, not generating system users")
        return

    with complete_step("Generating system users"):
        run(["systemd-sysusers", "--root=/buildroot"],
            sandbox=context.sandbox(binary="systemd-sysusers", mounts=[Mount(context.root, "/buildroot")]))


def run_tmpfiles(context: Context) -> None:
    if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
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
            ],
            env={"SYSTEMD_TMPFILES_FORCE_SUBVOL": "0"},
            # systemd-tmpfiles can exit with DATAERR or CANTCREAT in some cases which are handled as success by the
            # systemd-tmpfiles service so we handle those as success as well.
            success_exit_status=(0, 65, 73),
            sandbox=context.sandbox(
                binary="systemd-tmpfiles",
                mounts=[
                    Mount(context.root, "/buildroot"),
                    # systemd uses acl.h to parse ACLs in tmpfiles snippets which uses the host's passwd so we have to
                    # mount the image's passwd over it to make ACL parsing work.
                    *finalize_passwd_mounts(context.root)
                ],
            ),
        )


def run_preset(context: Context) -> None:
    if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
        return

    if not context.config.find_binary("systemctl"):
        logging.warning("systemctl is not installed, not applying presets")
        return

    with complete_step("Applying presets…"):
        run(["systemctl", "--root=/buildroot", "preset-all"],
            sandbox=context.sandbox(binary="systemctl", mounts=[Mount(context.root, "/buildroot")]))
        run(["systemctl", "--root=/buildroot", "--global", "preset-all"],
            sandbox=context.sandbox(binary="systemctl", mounts=[Mount(context.root, "/buildroot")]))


def run_hwdb(context: Context) -> None:
    if context.config.overlay or context.config.output_format in (OutputFormat.sysext, OutputFormat.confext):
        return

    if not context.config.find_binary("systemd-hwdb"):
        logging.warning("systemd-hwdb is not installed, not generating hwdb")
        return

    with complete_step("Generating hardware database"):
        run(["systemd-hwdb", "--root=/buildroot", "--usr", "--strict", "update"],
            sandbox=context.sandbox(binary="systemd-hwdb", mounts=[Mount(context.root, "/buildroot")]))

    # Remove any existing hwdb in /etc in favor of the one we just put in /usr.
    (context.root / "etc/udev/hwdb.bin").unlink(missing_ok=True)


def run_firstboot(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    if not context.config.find_binary("systemd-firstboot"):
        logging.warning("systemd-firstboot is not installed, not applying first boot settings")
        return

    password, hashed = context.config.root_password or (None, False)
    if password and not hashed:
        password = run(
            ["openssl", "passwd", "-stdin", "-6"],
            sandbox=context.sandbox(binary="openssl"),
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
    )

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
        run(["systemd-firstboot", "--root=/buildroot", "--force", *options],
            sandbox=context.sandbox(binary="systemd-firstboot", mounts=[Mount(context.root, "/buildroot")]))

        # Initrds generally don't ship with only /usr so there's not much point in putting the credentials in
        # /usr/lib/credstore.
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
        run([setfiles, "-mFr", "/buildroot", "-c", binpolicy, fc, "/buildroot"],
            sandbox=context.sandbox(binary=setfiles, mounts=[Mount(context.root, "/buildroot")]),
            check=context.config.selinux_relabel == ConfigFeature.enabled)


def need_build_overlay(config: Config) -> bool:
    return bool(config.build_scripts and (config.build_packages or config.prepare_scripts))


def save_cache(context: Context) -> None:
    if not context.config.incremental or context.config.base_trees or context.config.overlay:
        return

    final, build, manifest = cache_tree_paths(context.config)

    with complete_step("Installing cache copies"):
        rmtree(final, sandbox=context.sandbox)

        move_tree(
            context.root, final,
            use_subvolumes=context.config.use_subvolumes,
            sandbox=context.sandbox,
        )

        if need_build_overlay(context.config) and (context.workspace / "build-overlay").exists():
            rmtree(build, sandbox=context.sandbox)
            move_tree(
                context.workspace / "build-overlay", build,
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
    if not config.incremental or config.base_trees or config.overlay:
        return False

    final, build, manifest = cache_tree_paths(config)
    if not final.exists():
        logging.info(f"{final} does not exist, not reusing cached images")
        return False

    if need_build_overlay(config) and not build.exists():
        logging.info(f"{build} does not exist, not reusing cached images")
        return False

    if manifest.exists():
        prev = json.loads(manifest.read_text())
        new = json.dumps(config.cache_manifest(), cls=JsonEncoder, indent=4, sort_keys=True)
        if prev != json.loads(new):
            logging.info("Cache manifest mismatch, not reusing cached images")
            if ARG_DEBUG.get():
                run(["diff", manifest, "-"], input=new, check=False,
                    sandbox=config.sandbox(binary="diff", mounts=[Mount(manifest, manifest)]))

            return False
    else:
        logging.info(f"{manifest} does not exist, not reusing cached images")
        return False

    return True


def reuse_cache(context: Context) -> bool:
    if not have_cache(context.config):
        return False

    final, build, _ = cache_tree_paths(context.config)

    if final.stat().st_uid != os.getuid():
        return False

    with complete_step("Copying cached trees"):
        copy_tree(
            final, context.root,
            use_subvolumes=context.config.use_subvolumes,
            sandbox=context.sandbox,
        )

        if need_build_overlay(context.config):
            (context.workspace / "build-overlay").symlink_to(build)

    return True


def save_uki_components(context: Context) -> tuple[Optional[Path], Optional[str], Optional[Path], list[Path]]:
    if context.config.output_format not in (OutputFormat.uki, OutputFormat.esp):
        return None, None, None, []

    try:
        kver, kimg = next(gen_kernel_images(context))
    except StopIteration:
        die("A kernel must be installed in the image to build a UKI")

    kimg = shutil.copy2(context.root / kimg, context.workspace)

    if not context.config.architecture.to_efi():
        die(f"Architecture {context.config.architecture} does not support UEFI")

    stub = systemd_stub_binary(context)
    if not stub.exists():
        die(f"sd-stub not found at /{stub.relative_to(context.root)} in the image")

    stub = shutil.copy2(stub, context.workspace)
    microcode = build_microcode_initrd(context)

    return stub, kver, kimg, microcode


def make_image(
    context: Context,
    msg: str,
    skip: Sequence[str] = [],
    split: bool = False,
    tabs: bool = False,
    root: Optional[Path] = None,
    definitions: Sequence[Path] = [],
) -> list[Partition]:
    cmdline: list[PathString] = [
        "systemd-repart",
        "--empty=allow",
        "--size=auto",
        "--dry-run=no",
        "--json=pretty",
        "--no-pager",
        f"--offline={yes_no(context.config.repart_offline)}",
        "--seed", str(context.config.seed),
        context.staging / context.config.output_with_format,
    ]
    mounts = [Mount(context.staging, context.staging)]

    if root:
        cmdline += ["--root=/buildroot"]
        mounts += [Mount(root, "/buildroot")]
    if not context.config.architecture.is_native():
        cmdline += ["--architecture", str(context.config.architecture)]
    if not (context.staging / context.config.output_with_format).exists():
        cmdline += ["--empty=create"]
    if context.config.passphrase:
        cmdline += ["--key-file", context.config.passphrase]
        mounts += [Mount(context.config.passphrase, context.config.passphrase, ro=True)]
    if context.config.verity_key:
        cmdline += ["--private-key", context.config.verity_key]
        if context.config.verity_key_source.type != KeySource.Type.file:
            cmdline += ["--private-key-source", str(context.config.verity_key_source)]
        if context.config.verity_key.exists():
            mounts += [Mount(context.config.verity_key, context.config.verity_key, ro=True)]
    if context.config.verity_certificate:
        cmdline += ["--certificate", context.config.verity_certificate]
        mounts += [Mount(context.config.verity_certificate, context.config.verity_certificate, ro=True)]
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
        cmdline += ["--definitions", d]
        mounts += [Mount(d, d, ro=True)]

    with complete_step(msg):
        output = json.loads(
            run(
                cmdline,
                stdout=subprocess.PIPE,
                env=context.config.environment,
                sandbox=context.sandbox(
                    binary="systemd-repart",
                    devices=(
                        not context.config.repart_offline or
                        context.config.verity_key_source.type != KeySource.Type.file
                    ),
                    vartmp=True,
                    mounts=mounts,
                ),
            ).stdout
        )

    logging.debug(json.dumps(output, indent=4))

    partitions = [Partition.from_dict(d) for d in output]

    if split:
        for p in partitions:
            if p.split_path:
                maybe_compress(context, context.config.compress_output, p.split_path)

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
            if arch := context.config.architecture.to_efi():
                bootloader = context.root / f"efi/EFI/BOOT/BOOT{arch.upper()}.EFI"
            else:
                bootloader = None

            esp = (
                context.config.bootable == ConfigFeature.enabled or
                (context.config.bootable == ConfigFeature.auto and bootloader and bootloader.exists())
            )
            bios = (context.config.bootable != ConfigFeature.disabled and want_grub_bios(context))

            if esp or bios:
                # Even if we're doing BIOS, let's still use the ESP to store the kernels, initrds and grub
                # modules. We cant use UKIs so we have to put each kernel and initrd on the ESP twice, so
                # let's make the ESP twice as big in that case.
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

            # If grub for BIOS is installed, let's add a BIOS boot partition onto which we can install grub.
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

    return make_image(context, msg=msg, skip=skip, split=split, tabs=tabs, root=context.root, definitions=definitions)


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
            **({
                "org.opencontainers.image.version": context.config.image_version,
            } if context.config.image_version else {}),
        }
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


def make_esp(context: Context, uki: Path) -> list[Partition]:
    if not (arch := context.config.architecture.to_efi()):
        die(f"Architecture {context.config.architecture} does not support UEFI")

    definitions = context.workspace / "esp-definitions"
    definitions.mkdir(exist_ok=True)

    # Use a minimum of 36MB or 260MB depending on sector size because otherwise the generated FAT filesystem will have
    # too few clusters to be considered a FAT32 filesystem by OVMF which will refuse to boot from it.
    # See https://superuser.com/questions/1702331/what-is-the-minimum-size-of-a-4k-native-partition-when-formatted-with-fat32/1717643#1717643
    if context.config.sector_size == 512:
        m = 36
    # TODO: Figure out minimum size for 2K sector size
    else:
        m = 260

    # Always reserve 10MB for filesystem metadata.
    size = max(uki.stat().st_size, (m - 10) * 1024**2) + 10 * 1024**2

    # TODO: Remove the extra 4096 for the max size once https://github.com/systemd/systemd/pull/29954 is in a stable
    # release.
    (definitions / "00-esp.conf").write_text(
        textwrap.dedent(
            f"""\
            [Partition]
            Type=esp
            Format=vfat
            CopyFiles={uki}:/EFI/BOOT/BOOT{arch.upper()}.EFI
            SizeMinBytes={size}
            SizeMaxBytes={size + 4096}
            """
        )
    )

    return make_image(context, msg="Generating ESP image", definitions=[definitions])


def make_extension_image(context: Context, output: Path) -> None:
    r = context.resources / f"repart/definitions/{context.config.output_format}.repart.d"

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
        "--definitions", r,
        output,
    ]
    mounts = [
        Mount(output.parent, output.parent),
        Mount(context.root, "/buildroot", ro=True),
        Mount(r, r, ro=True),
    ]

    if not context.config.architecture.is_native():
        cmdline += ["--architecture", str(context.config.architecture)]
    if context.config.passphrase:
        cmdline += ["--key-file", context.config.passphrase]
        mounts += [Mount(context.config.passphrase, context.config.passphrase, ro=True)]
    if context.config.verity_key:
        cmdline += ["--private-key", context.config.verity_key]
        if context.config.verity_key_source.type != KeySource.Type.file:
            cmdline += ["--private-key-source", str(context.config.verity_key_source)]
        if context.config.verity_key.exists():
            mounts += [Mount(context.config.verity_key, context.config.verity_key, ro=True)]
    if context.config.verity_certificate:
        cmdline += ["--certificate", context.config.verity_certificate]
        mounts += [Mount(context.config.verity_certificate, context.config.verity_certificate, ro=True)]
    if context.config.sector_size:
        cmdline += ["--sector-size", str(context.config.sector_size)]
    if context.config.split_artifacts:
        cmdline += ["--split=yes"]

    with complete_step(f"Building {context.config.output_format} extension image"):
        j = json.loads(
            run(
                cmdline,
                stdout=subprocess.PIPE,
                env=context.config.environment,
                sandbox=context.sandbox(
                    binary="systemd-repart",
                    devices=(
                        not context.config.repart_offline or
                        context.config.verity_key_source.type != KeySource.Type.file
                    ),
                    vartmp=True,
                    mounts=mounts,
                ),
            ).stdout
        )

    logging.debug(json.dumps(j, indent=4))

    if context.config.split_artifacts:
        for p in (Partition.from_dict(d) for d in j):
            if p.split_path:
                maybe_compress(context, context.config.compress_output, p.split_path)


def finalize_staging(context: Context) -> None:
    rmtree(*(context.config.output_dir_or_cwd() / f.name for f in context.staging.iterdir()))

    for f in context.staging.iterdir():
        # Make sure all build outputs that are not directories are owned by the user running mkosi.
        if not f.is_dir():
            os.chown(f, INVOKING_USER.uid, INVOKING_USER.gid, follow_symlinks=False)

        if f.is_symlink():
            (context.config.output_dir_or_cwd() / f.name).symlink_to(f.readlink())
            os.chown(f, INVOKING_USER.uid, INVOKING_USER.gid, follow_symlinks=False)
            continue

        move_tree(
            f, context.config.output_dir_or_cwd(),
            use_subvolumes=context.config.use_subvolumes,
            sandbox=context.sandbox,
        )


def clamp_mtime(path: Path, mtime: int) -> None:
    st = os.stat(path, follow_symlinks=False)
    orig = (st.st_atime_ns, st.st_mtime_ns)
    updated = (min(orig[0], mtime * 1_000_000_000),
               min(orig[1], mtime * 1_000_000_000))
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
        workspace.chmod(stat.S_IMODE(workspace.stat().st_mode) & ~(stat.S_ISGID|stat.S_ISUID))
        stack.callback(lambda: rmtree(workspace, sandbox=config.sandbox))
        (workspace / "tmp").mkdir(mode=0o1777)

        with scopedenv({"TMPDIR" : os.fspath(workspace / "tmp")}):
            try:
                yield Path(workspace)
            except BaseException:
                if args.debug_workspace:
                    stack.pop_all()
                    log_notice(f"Workspace: {workspace}")
                    workspace.chmod(0o755)

                raise


@contextlib.contextmanager
def lock_repository_metadata(config: Config) -> Iterator[None]:
    subdir = config.distribution.package_manager(config).subdir(config)

    with contextlib.ExitStack() as stack:
        for d in ("cache", "lib"):
            if (src := config.package_cache_dir_or_default() / d / subdir).exists():
                stack.enter_context(flock(src))

        yield


def copy_repository_metadata(context: Context) -> None:
    subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

    # Don't copy anything if the repository metadata directories are already populated and we're not explicitly asked
    # to sync repository metadata.
    if (
        context.config.cacheonly != Cacheonly.never and
        (
            any((context.package_cache_dir / "cache" / subdir).glob("*")) or
            any((context.package_cache_dir / "lib" / subdir).glob("*"))
        )
    ):
        logging.debug(f"Found repository metadata in {context.package_cache_dir}, not copying repository metadata")
        return

    with lock_repository_metadata(context.config):
        for d in ("cache", "lib"):
            src = context.config.package_cache_dir_or_default() / d / subdir
            if not src.exists():
                logging.debug(f"{src} does not exist, not copying repository metadata from it")
                continue

            with tempfile.TemporaryDirectory() as tmp:
                os.chmod(tmp, 0o755)

                # cp doesn't support excluding directories but we can imitate it by bind mounting an empty directory
                # over the directories we want to exclude.
                if d == "cache":
                    exclude = [
                        Mount(tmp, p, ro=True)
                        for p in context.config.distribution.package_manager(context.config).cache_subdirs(src)
                    ]
                else:
                    exclude = [
                        Mount(tmp, p, ro=True)
                        for p in context.config.distribution.package_manager(context.config).state_subdirs(src)
                    ]

                dst = context.package_cache_dir / d / subdir
                with umask(~0o755):
                    dst.mkdir(parents=True, exist_ok=True)

                def sandbox(
                    *,
                    binary: Optional[PathString],
                    vartmp: bool = False,
                    mounts: Sequence[Mount] = (),
                    extra: Sequence[PathString] = (),
                ) -> AbstractContextManager[list[PathString]]:
                    return context.sandbox(binary=binary, vartmp=vartmp, mounts=[*mounts, *exclude], extra=extra)

                copy_tree(
                    src, dst,
                    preserve=False,
                    sandbox=sandbox,
                )

@contextlib.contextmanager
def createrepo(context: Context) -> Iterator[None]:
    st = context.repository.stat()
    try:
        yield
    finally:
        if context.repository.stat().st_mtime_ns != st.st_mtime_ns:
            with complete_step("Rebuilding local package repository"):
                context.config.distribution.createrepo(context)


def build_image(context: Context) -> None:
    manifest = Manifest(context) if context.config.manifest_format else None

    install_package_manager_trees(context)

    with mount_base_trees(context):
        install_base_trees(context)
        cached = reuse_cache(context)
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

        copy_repository_metadata(context)

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

        if context.config.output_format == OutputFormat.none:
            finalize_staging(context)
            rmtree(context.root)
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
        stub, kver, kimg, microcode = save_uki_components(context)

        remove_packages(context)

        if manifest:
            manifest.record_packages()

        clean_package_manager_metadata(context)
        remove_files(context)
        run_selinux_relabel(context)
        run_finalize_scripts(context)

    normalize_mtime(context.root, context.config.source_date_epoch)
    partitions = make_disk(context, skip=("esp", "xbootldr"), tabs=True, msg="Generating disk image")
    install_kernel(context, partitions)
    normalize_mtime(context.root, context.config.source_date_epoch, directory=Path("boot"))
    normalize_mtime(context.root, context.config.source_date_epoch, directory=Path("efi"))
    partitions = make_disk(context, msg="Formatting ESP/XBOOTLDR partitions")
    grub_bios_setup(context, partitions)

    if context.config.split_artifacts:
        make_disk(context, split=True, msg="Extracting partitions")

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
        assert stub and kver and kimg
        make_uki(context, stub, kver, kimg, microcode, context.staging / context.config.output_split_uki)
        make_esp(context, context.staging / context.config.output_split_uki)
    elif context.config.output_format.is_extension_image():
        make_extension_image(context, context.staging / context.config.output_with_format)
    elif context.config.output_format == OutputFormat.directory:
        context.root.rename(context.staging / context.config.output_with_format)

    if context.config.output_format not in (OutputFormat.uki, OutputFormat.esp):
        maybe_compress(context, context.config.compress_output,
                       context.staging / context.config.output_with_format,
                       context.staging / context.config.output_with_compression)

    calculate_sha256sum(context)
    calculate_signature(context)
    save_manifest(context, manifest)

    output_base = context.staging / context.config.output
    if not output_base.exists() or output_base.is_symlink():
        output_base.unlink(missing_ok=True)
        output_base.symlink_to(context.config.output_with_compression)

    run_postoutput_scripts(context)
    finalize_staging(context)
    rmtree(context.root)

    print_output_size(context.config.output_dir_or_cwd() / context.config.output_with_compression)


def setfacl(config: Config, root: Path, uid: int, allow: bool) -> None:
    run(
        [
            "setfacl",
            "--physical",
            "--modify" if allow else "--remove",
            f"user:{uid}:rwx" if allow else f"user:{uid}",
            "-",
        ],
        # Supply files via stdin so we don't clutter --debug run output too much
        input="\n".join([str(root), *(os.fspath(p) for p in root.rglob("*") if p.is_dir())]),
        sandbox=config.sandbox(binary="setfacl", mounts=[Mount(root, root)]),
    )


@contextlib.contextmanager
def acl_maybe_toggle(config: Config, root: Path, uid: int, *, always: bool) -> Iterator[None]:
    if not config.acl:
        yield
        return

    # getfacl complains about absolute paths so make sure we pass a relative one.
    if root.exists():
        sandbox = config.sandbox(binary="getfacl", mounts=[Mount(root, root)], options=["--chdir", root])
        has_acl = f"user:{uid}:rwx" in run(["getfacl", "-n", "."], sandbox=sandbox, stdout=subprocess.PIPE).stdout

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
def acl_toggle_build(config: Config, uid: int) -> Iterator[None]:
    if not config.acl:
        yield
        return

    extras = [t.source for t in config.extra_trees]
    skeletons = [t.source for t in config.skeleton_trees]

    with contextlib.ExitStack() as stack:
        for p in (*config.base_trees, *extras, *skeletons):
            if p and p.is_dir():
                stack.enter_context(acl_maybe_toggle(config, p, uid, always=False))

        for p in (config.cache_dir, config.build_dir):
            if p:
                stack.enter_context(acl_maybe_toggle(config, p, uid, always=True))

        if config.output_format == OutputFormat.directory:
            stack.enter_context(acl_maybe_toggle(config, config.output_dir_or_cwd() / config.output, uid, always=True))

        yield


@contextlib.contextmanager
def acl_toggle_boot(config: Config, uid: int) -> Iterator[None]:
    if not config.acl or config.output_format != OutputFormat.directory:
        yield
        return

    with acl_maybe_toggle(config, config.output_dir_or_cwd() / config.output, uid, always=False):
        yield


def run_shell(args: Args, config: Config) -> None:
    opname = "acquire shell in" if args.verb == Verb.shell else "boot"
    if config.output_format in (OutputFormat.tar, OutputFormat.cpio):
        die(f"Sorry, can't {opname} a {config.output_format} archive.")
    if config.output_format.use_outer_compression() and config.compress_output:
        die(f"Sorry, can't {opname} a compressed image.")

    cmdline: list[PathString] = ["systemd-nspawn", "--quiet", "--link-journal=no"]

    if config.runtime_network == Network.user:
        cmdline += ["--resolv-conf=auto"]
    elif config.runtime_network == Network.interface:
        if os.getuid() != 0:
            die("RuntimeNetwork=interface requires root privileges")

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

    for k, v in config.credentials.items():
        cmdline += [f"--set-credential={k}:{v}"]

    with contextlib.ExitStack() as stack:
        # Make sure the latest nspawn settings are always used.
        if config.nspawn_settings:
            if not (config.output_dir_or_cwd() / f"{name}.nspawn").exists():
                stack.callback(lambda: (config.output_dir_or_cwd() / f"{name}.nspawn").unlink(missing_ok=True))
            shutil.copy2(config.nspawn_settings, config.output_dir_or_cwd() / f"{name}.nspawn")

        if config.ephemeral:
            fname = stack.enter_context(copy_ephemeral(config, config.output_dir_or_cwd() / config.output))
        else:
            fname = stack.enter_context(flock_or_die(config.output_dir_or_cwd() / config.output))

        if config.output_format == OutputFormat.disk and args.verb == Verb.boot:
            run(
                [
                    "systemd-repart",
                    "--image", fname,
                    *([f"--size={config.runtime_size}"] if config.runtime_size else []),
                    "--no-pager",
                    "--dry-run=no",
                    "--offline=no",
                    "--pretty=no",
                    fname,
                ],
                stdin=sys.stdin,
                env=config.environment,
                sandbox=config.sandbox(
                    binary="systemd-repart",
                    network=True,
                    devices=True,
                    vartmp=True,
                    mounts=[Mount(fname, fname)],
                ),
            )

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]

            owner = os.stat(fname).st_uid
            if owner != 0:
                cmdline += [f"--private-users={str(owner)}"]
        else:
            cmdline += ["--image", fname]

        if config.runtime_build_sources:
            with finalize_source_mounts(config, ephemeral=False) as mounts:
                for mount in mounts:
                    uidmap = "rootidmap" if Path(mount.src).stat().st_uid == INVOKING_USER.uid else "noidmap"
                    cmdline += ["--bind", f"{mount.src}:{mount.dst}:norbind,{uidmap}"]

            if config.build_dir:
                cmdline += ["--bind", f"{config.build_dir}:/work/build:norbind,noidmap"]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or "")
            # We add norbind because very often RuntimeTrees= will be used to mount the source directory into the
            # container and the output directory from which we're running will very likely be a subdirectory of the
            # source directory which would mean we'd be mounting the container root directory as a subdirectory in
            # itself which tends to lead to all kinds of weird issues, which we avoid by not doing a recursive mount
            # which means the container root directory mounts will be skipped.
            uidmap = "rootidmap" if tree.source.stat().st_uid == INVOKING_USER.uid else "noidmap"
            cmdline += ["--bind", f"{tree.source}:{target}:norbind,{uidmap}"]

        if config.runtime_scratch == ConfigFeature.enabled or (
            config.runtime_scratch == ConfigFeature.auto and
            config.output_format == OutputFormat.disk
        ):
            scratch = stack.enter_context(tempfile.TemporaryDirectory(dir="/var/tmp"))
            os.chmod(scratch, 0o1777)
            cmdline += ["--bind", f"{scratch}:/var/tmp"]

        if args.verb == Verb.boot and config.forward_journal:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                addr = Path(os.getenv("TMPDIR", "/tmp")) / f"mkosi-journal-remote-unix-{uuid.uuid4().hex[:16]}"
                sock.bind(os.fspath(addr))
                sock.listen()
                if config.output_format == OutputFormat.directory and (stat := os.stat(fname)).st_uid != 0:
                    os.chown(addr, stat.st_uid, stat.st_gid)
                stack.enter_context(start_journal_remote(config, sock.fileno()))
                cmdline += [
                    "--bind", f"{addr}:/run/host/journal/socket",
                    "--set-credential=journal.forward_to_socket:/run/host/journal/socket",
                ]

        for p in config.unit_properties:
            cmdline += ["--property", p]

        if args.verb == Verb.boot:
            # Add nspawn options first since systemd-nspawn ignores all options after the first argument.
            argv = args.cmdline

            # When invoked by the kernel, all unknown arguments are passed as environment variables to pid1. Let's
            # mimick the same behavior when we invoke nspawn as a container.
            for arg in itertools.chain(config.kernel_command_line, config.kernel_command_line_extra):
                name, sep, value = arg.partition("=")

                # If there's a '.' in the argument name, it's not considered an environment variable by the kernel.
                if sep and "." not in name:
                    cmdline += ["--setenv", f"{name.replace('-', '_')}={value}"]
                else:
                    # kernel cmdline config of the form systemd.xxx= get interpreted by systemd when running in nspawn
                    # as well.
                    argv += [arg]

            cmdline += argv
        elif args.cmdline:
            cmdline += ["--"]
            cmdline += args.cmdline

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | config.environment,
            log=False,
            sandbox=config.sandbox(binary="systemd-nspawn", devices=True, network=True, relaxed=True),
        )


def run_systemd_tool(tool: str, args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.directory) and not config.forward_journal:
        die(f"{config.output_format} images cannot be inspected with {tool}")

    if (
        args.verb in (Verb.journalctl, Verb.coredumpctl)
        and config.output_format == OutputFormat.disk
        and not config.forward_journal
        and os.getuid() != 0
    ):
        die(f"Must be root to run the {args.verb} command")

    if (tool_path := config.find_binary(tool)) is None:
        die(f"Failed to find {tool}")

    if config.ephemeral and not config.forward_journal:
        die(f"Images booted in ephemeral mode cannot be inspected with {tool}")

    output = config.output_dir_or_cwd() / config.output

    if config.forward_journal and not config.forward_journal.exists():
        die(f"Journal directory/file configured with ForwardJournal= does not exist, cannot inspect with {tool}")
    elif not output.exists():
        die(f"Output {config.output_dir_or_cwd() / config.output} does not exist, cannot inspect with {tool}")

    cmd: list[PathString] = [tool_path]

    if config.forward_journal:
        cmd += ["--directory" if config.forward_journal.is_dir() else "--file", config.forward_journal]
    else:
        cmd += ["--root" if output.is_dir() else "--image", output]

    run(
        [*cmd, *args.cmdline],
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ | config.environment,
        log=False,
        preexec_fn=become_root if not config.forward_journal else None,
        sandbox=config.sandbox(
            binary=tool_path,
            network=True,
            devices=config.output_format == OutputFormat.disk,
            relaxed=True,
        ),
    )


def run_journalctl(args: Args, config: Config) -> None:
    run_systemd_tool("journalctl", args, config)


def run_coredumpctl(args: Args, config: Config) -> None:
    run_systemd_tool("coredumpctl", args, config)


def run_serve(args: Args, config: Config) -> None:
    """Serve the output directory via a tiny HTTP server"""

    run(
        [python_binary(config, binary=None), "-m", "http.server", "8081"],
        stdin=sys.stdin, stdout=sys.stdout,
        sandbox=config.sandbox(
            binary=python_binary(config, binary=None),
            network=True,
            relaxed=True,
            options=["--chdir", config.output_dir_or_cwd()],
        ),
    )


def generate_key_cert_pair(args: Args) -> None:
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
            "-keyout", "mkosi.key",
            "-out", "mkosi.crt",
            "-days", str(args.genkey_valid_days),
            "-subj", f"/CN={cn}/",
            "-nodes"
        ],
        env=dict(OPENSSL_CONF="/dev/null"),
    )


def bump_image_version() -> None:
    """Write current image version plus one to mkosi.version"""

    version_file = Path("mkosi.version")
    if not version_file.exists():
        die(f"Cannot bump image version, '{version_file}' not found")

    if os.access(version_file, os.X_OK):
        die(f"Cannot bump image version, '{version_file}' is executable")

    version = version_file.read_text().strip()
    v = version.split(".")

    try:
        v[-1] = str(int(v[-1]) + 1)
    except ValueError:
        v += ["2"]
        logging.warning("Last component of current version is not a decimal integer, appending '.2'")

    new_version = ".".join(v)

    logging.info(f"Bumping version: '{version}' → '{new_version}'")
    version_file.write_text(f"{new_version}\n")
    os.chown(version_file, INVOKING_USER.uid, INVOKING_USER.gid)


def show_docs(args: Args, *, resources: Path) -> None:
    if args.doc_format == DocFormat.auto:
        formats = [DocFormat.man, DocFormat.pandoc, DocFormat.markdown, DocFormat.system]
    else:
        formats = [args.doc_format]

    while formats:
        form = formats.pop(0)
        try:
            if form == DocFormat.man:
                man = resources / "mkosi.1"
                if not man.exists():
                    raise FileNotFoundError()
                run(["man", "--local-file", man])
                return
            elif form == DocFormat.pandoc:
                if not find_binary("pandoc"):
                    logging.error("pandoc is not available")
                pandoc = run(["pandoc", "-t", "man", "-s", resources / "mkosi.md"], stdout=subprocess.PIPE)
                run(["man", "--local-file", "-"], input=pandoc.stdout)
                return
            elif form == DocFormat.markdown:
                page((resources / "mkosi.md").read_text(), args.pager)
                return
            elif form == DocFormat.system:
                run(["man", "mkosi"])
                return
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            if not formats:
                if isinstance(e, FileNotFoundError):
                    die("The mkosi package does not contain the man page.")
                raise e


def expand_specifier(s: str) -> str:
    return s.replace("%u", INVOKING_USER.name())


@contextlib.contextmanager
def prepend_to_environ_path(config: Config) -> Iterator[None]:
    if not config.extra_search_paths:
        yield
        return

    with tempfile.TemporaryDirectory(prefix="mkosi.path-") as d:

        for path in config.extra_search_paths:
            if not path.is_dir():
                (Path(d) / path.name).symlink_to(path.absolute())

        news = [os.fspath(path) for path in [Path(d), *config.extra_search_paths] if path.is_dir()]
        olds = os.getenv("PATH", "").split(":")
        os.environ["PATH"] = ":".join(news + olds)

        try:
            yield
        finally:
            os.environ["PATH"] = ":".join(olds)


def finalize_default_tools(args: Args, config: Config, *, resources: Path) -> Config:
    if not config.tools_tree_distribution:
        die(f"{config.distribution} does not have a default tools tree distribution",
            hint="use ToolsTreeDistribution= to set one explicitly")

    cmdline = [
        "--directory", "",
        "--distribution", str(config.tools_tree_distribution),
        *(["--release", config.tools_tree_release] if config.tools_tree_release else []),
        *(["--mirror", config.tools_tree_mirror] if config.tools_tree_mirror else []),
        "--repositories", ",".join(config.tools_tree_repositories),
        "--package-manager-tree", ",".join(str(t) for t in config.tools_tree_package_manager_trees),
        "--repository-key-check", str(config.repository_key_check),
        "--repository-key-fetch", str(config.repository_key_fetch),
        "--cache-only", str(config.cacheonly),
        *(["--output-dir", str(config.output_dir)] if config.output_dir else []),
        *(["--workspace-dir", str(config.workspace_dir)] if config.workspace_dir else []),
        *(["--cache-dir", str(config.cache_dir)] if config.cache_dir else []),
        *(["--package-cache-dir", str(config.package_cache_dir)] if config.package_cache_dir else []),
        "--incremental", str(config.incremental),
        "--acl", str(config.acl),
        *([f"--package={package}" for package in config.tools_tree_packages]),
        "--output", f"{config.tools_tree_distribution}-tools",
        *(["--source-date-epoch", str(config.source_date_epoch)] if config.source_date_epoch is not None else []),
        *([f"--environment={k}='{v}'" for k, v in config.environment.items()]),
        *([f"--extra-search-path={p}" for p in config.extra_search_paths]),
        *(["--proxy-url", config.proxy_url] if config.proxy_url else []),
        *([f"--proxy-exclude={host}" for host in config.proxy_exclude]),
        *(["--proxy-peer-certificate", str(p)] if (p := config.proxy_peer_certificate) else []),
        *(["--proxy-client-certificate", str(p)] if (p := config.proxy_client_certificate) else []),
        *(["--proxy-client-key", str(p)] if (p := config.proxy_client_key) else []),
        *(["-f"] * args.force),
    ]

    _, [tools] = parse_config(
        cmdline + ["--include=mkosi-tools", "build"],
        resources=resources,
    )

    tools = dataclasses.replace(tools, image=f"{config.tools_tree_distribution}-tools")

    return tools


def check_workspace_directory(config: Config) -> None:
    wd = config.workspace_dir_or_default()

    for tree in config.build_sources:
        if wd.is_relative_to(tree.source):
            die(f"The workspace directory ({wd}) cannot be a subdirectory of any source directory ({tree.source})",
                hint="Set BuildSources= to the empty string or use WorkspaceDirectory= to configure a different "
                     "workspace directory")


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
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
    )

    if config.profile:
        env["PROFILE"] = config.profile

    with (
        finalize_source_mounts(config, ephemeral=False) as sources,
        finalize_config_json(config) as json,
    ):
        for script in config.clean_scripts:
            with complete_step(f"Running clean script {script}…"):
                run(
                    ["/work/clean"],
                    env=env | config.environment,
                    sandbox=config.sandbox(
                        binary=None,
                        vartmp=True,
                        tools=False,
                        mounts=[
                            *sources,
                            Mount(script, "/work/clean", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            *([Mount(o, "/work/out")] if (o := config.output_dir_or_cwd()).exists() else []),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src", "--dir", "/work/out"]
                    ),
                    stdin=sys.stdin,
                )


def needs_clean(args: Args, config: Config, force: int = 1) -> bool:
    return (
        args.verb == Verb.clean or
        args.force >= force or
        not (config.output_dir_or_cwd() / config.output_with_compression).exists() or
        # When the output is a directory, its name is the same as the symlink we create that points to the actual
        # output when not building a directory. So if the full output path exists, we have to check that it's not
        # a symlink as well.
        (config.output_dir_or_cwd() / config.output_with_compression).is_symlink()
    )


def run_clean(args: Args, config: Config, *, resources: Path) -> None:
    become_root()

    # We remove any cached images if either the user used --force twice, or he/she called "clean" with it
    # passed once. Let's also remove the downloaded package cache if the user specified one additional
    # "--force".

    if args.verb == Verb.clean:
        remove_output_dir = config.output_format != OutputFormat.none
        remove_build_cache = args.force > 0 or args.wipe_build_dir
        remove_image_cache = args.force > 0
        remove_package_cache = args.force > 1
    else:
        remove_output_dir = config.output_format != OutputFormat.none or args.force > 0
        remove_build_cache = args.force > 1 or args.wipe_build_dir
        remove_image_cache = args.force > 1
        remove_package_cache = args.force > 2

    if remove_output_dir:
        outputs = {
            config.output_dir_or_cwd() / output
            for output in config.outputs
            if (config.output_dir_or_cwd() / output).exists() or (config.output_dir_or_cwd() / output).is_symlink()
        }

        # Make sure we resolve the symlink we create in the output directory and remove its target as well as it might
        # not be in the list of outputs anymore if the compression or output format was changed.
        outputs |= {o.resolve() for o in outputs}

        if outputs:
            with (
                complete_step(f"Removing output files of {config.name()} image…"),
                flock_or_die(config.output_dir_or_cwd() / config.output)
                if (config.output_dir_or_cwd() / config.output).exists()
                else contextlib.nullcontext()
            ):
                rmtree(*outputs)

    if remove_build_cache and config.build_dir and config.build_dir.exists() and any(config.build_dir.iterdir()):
        with complete_step(f"Clearing out build directory of {config.name()} image…"):
            rmtree(*config.build_dir.iterdir())

    if remove_image_cache and config.cache_dir:
        initrd = (
            cache_tree_paths(finalize_default_initrd(args, config, resources=resources))
            if config.distribution != Distribution.custom
            else []
        )

        if any(p.exists() for p in itertools.chain(cache_tree_paths(config), initrd)):
            with complete_step(f"Removing cache entries of {config.name()} image…"):
                rmtree(*(p for p in itertools.chain(cache_tree_paths(config), initrd) if p.exists()))

    if remove_package_cache and any(config.package_cache_dir_or_default().glob("*")):
        subdir = config.distribution.package_manager(config).subdir(config)

        with (
            complete_step(f"Clearing out package cache of {config.name()} image…"),
            lock_repository_metadata(config),
        ):
            rmtree(
                *(
                    config.package_cache_dir_or_default() / d / subdir
                    for d in ("cache", "lib")
                ),
            )

    run_clean_scripts(config)


@contextlib.contextmanager
def rchown_package_manager_dirs(config: Config) -> Iterator[None]:
    try:
        yield
    finally:
        if INVOKING_USER.is_regular_user():
            with complete_step("Fixing ownership of package manager cache directory"):
                subdir = config.distribution.package_manager(config).subdir(config)
                for d in ("cache", "lib"):
                    INVOKING_USER.rchown(config.package_cache_dir_or_default() / d / subdir)


def sync_repository_metadata(context: Context) -> None:
    if (
        context.config.cacheonly != Cacheonly.never and
        (have_cache(context.config) or context.config.cacheonly != Cacheonly.auto)
    ):
        return

    with (
        complete_step(f"Syncing package manager metadata for {context.config.name()} image"),
        lock_repository_metadata(context.config),
    ):
        context.config.distribution.package_manager(context.config).sync(
            context,
            force=context.args.force > 1 or context.config.cacheonly == Cacheonly.never,
        )


def run_sync(args: Args, config: Config, *, resources: Path) -> None:
    if os.getuid() == 0:
        os.setgroups(INVOKING_USER.extra_groups())
        os.setresgid(INVOKING_USER.gid, INVOKING_USER.gid, INVOKING_USER.gid)
        os.setresuid(INVOKING_USER.uid, INVOKING_USER.uid, INVOKING_USER.uid)

    if not (p := config.package_cache_dir_or_default()).exists():
        p.mkdir(parents=True, exist_ok=True)

    subdir = config.distribution.package_manager(config).subdir(config)

    for d in ("cache", "lib"):
        (config.package_cache_dir_or_default() / d / subdir).mkdir(parents=True, exist_ok=True)

    with (
        prepend_to_environ_path(config),
        setup_workspace(args, config) as workspace,
    ):
        context = Context(
            args,
            config,
            workspace=workspace,
            resources=resources,
            package_cache_dir=config.package_cache_dir_or_default(),
        )

        install_package_manager_trees(context)
        context.config.distribution.setup(context)

        sync_repository_metadata(context)

        src = config.package_cache_dir_or_default() / "cache" / subdir
        for p in config.distribution.package_manager(config).cache_subdirs(src):
            p.mkdir(parents=True, exist_ok=True)

        run_sync_scripts(context)


def run_build(args: Args, config: Config, *, resources: Path, package_dir: Optional[Path] = None) -> None:
    if (uid := os.getuid()) != 0:
        become_root()
    unshare(CLONE_NEWNS)
    if uid == 0:
        run(["mount", "--make-rslave", "/"])

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
        INVOKING_USER.chown(p)

    if config.build_dir:
        # Make sure the build directory is owned by root (in the user namespace) so that the correct uid-mapping is
        # applied if it is used in RuntimeTrees=
        os.chown(config.build_dir, os.getuid(), os.getgid())

        # Discard setuid/setgid bits as these are inherited and can leak into the image.
        config.build_dir.chmod(stat.S_IMODE(config.build_dir.stat().st_mode) & ~(stat.S_ISGID|stat.S_ISUID))

    # For extra safety when running as root, remount a bunch of stuff read-only.
    # Because some build systems use output directories in /usr, we only remount
    # /usr read-only if the output directory is not relative to it.
    if INVOKING_USER.invoked_as_root:
        remount = ["/etc", "/opt", "/boot", "/efi", "/media"]
        if not config.output_dir_or_cwd().is_relative_to("/usr"):
            remount += ["/usr"]

        for d in remount:
            if Path(d).exists():
                options = "ro" if d in ("/usr", "/opt") else "ro,nosuid,nodev,noexec"
                run(["mount", "--rbind", d, d, "--options", options])

    with (
        complete_step(f"Building {config.name()} image"),
        prepend_to_environ_path(config),
        acl_toggle_build(config, INVOKING_USER.uid),
        rchown_package_manager_dirs(config),
        setup_workspace(args, config) as workspace,
    ):
        build_image(Context(args, config, workspace=workspace, resources=resources, package_dir=package_dir))


def ensure_root_is_mountpoint() -> None:
    """
    bubblewrap uses pivot_root() which doesn't work in the initramfs as pivot_root() requires / to be a mountpoint
    which is not the case in the initramfs. So, to make sure mkosi works from within the initramfs, let's make / a
    mountpoint by recursively bind-mounting / (the directory) to another location and then switching root into the bind
    mount directory.
    """
    fstype = run(
        ["findmnt", "--target", "/", "--output", "FSTYPE", "--noheadings"],
        stdout=subprocess.PIPE,
    ).stdout.strip()

    if fstype != "rootfs":
        return

    if os.getuid() != 0:
        die("mkosi can only be run as root from the initramfs")

    unshare(CLONE_NEWNS)
    run(["mount", "--make-rslave", "/"])
    mountpoint = Path("/run/mkosi/mkosi-root")
    mountpoint.mkdir(parents=True, exist_ok=True)
    run(["mount", "--rbind", "/", mountpoint])
    os.chdir(mountpoint)
    run(["mount", "--move", ".", "/"])
    os.chroot(".")


def run_verb(args: Args, images: Sequence[Config], *, resources: Path) -> None:
    images = list(images)

    if args.verb.needs_root() and os.getuid() != 0:
        die(f"Must be root to run the {args.verb} command")

    if args.verb == Verb.completion:
        return print_completion(args, resources=resources)

    if args.verb == Verb.documentation:
        return show_docs(args, resources=resources)

    if args.verb == Verb.genkey:
        return generate_key_cert_pair(args)

    if args.verb == Verb.bump:
        return bump_image_version()

    if args.verb == Verb.dependencies:
        _, [deps] = parse_config(
            ["--directory", "", "--repositories", "", "--include=mkosi-tools", "build"],
            resources=resources,
        )

        for p in deps.packages:
            print(p)

        return

    if all(config == Config.default() for config in images):
        die("No configuration found",
            hint="Make sure you're running mkosi from a directory with configuration files")

    if args.verb == Verb.summary:
        if args.json:
            text = json.dumps(
                {"Images": [config.to_dict() for config in images]},
                cls=JsonEncoder,
                indent=4,
                sort_keys=True
            )
        else:
            text = "\n".join(summary(config) for config in images)

        page(text, args.pager)
        return

    ensure_root_is_mountpoint()

    if args.verb in (Verb.journalctl, Verb.coredumpctl, Verb.ssh):
        # We don't use a tools tree for verbs that don't need an image build.
        last = dataclasses.replace(images[-1], tools_tree=None)
        return {
            Verb.ssh: run_ssh,
            Verb.journalctl: run_journalctl,
            Verb.coredumpctl: run_coredumpctl,
        }[args.verb](args, last)

    assert args.verb.needs_build() or args.verb == Verb.clean

    for config in images:
        if args.verb == Verb.build and not args.force:
            check_outputs(config)

    last = images[-1]

    if last.tools_tree and last.tools_tree == Path("default"):
        tools = finalize_default_tools(args, last, resources=resources)

        # If we're doing an incremental build and the cache is not out of date, don't clean up the tools tree
        # so that we can reuse the previous one.
        if (
            not tools.incremental or
            ((args.verb == Verb.build or args.force > 0) and not have_cache(tools)) or
            needs_clean(args, tools, force=2)
        ):
            fork_and_wait(run_clean, args, tools, resources=resources)
    else:
        tools = None

    # First, process all directory removals because otherwise if different images share directories a later
    # image build could end up deleting the output generated by an earlier image build.
    for config in images:
        if needs_clean(args, config) or args.wipe_build_dir:
            fork_and_wait(run_clean, args, config, resources=resources)

    if args.verb == Verb.clean:
        return

    for config in images:
        if (minversion := config.minimum_version) and minversion > __version__:
            die(f"mkosi {minversion} or newer is required to build this configuration (found {__version__})")

        if not config.repart_offline and os.getuid() != 0:
            die(f"Must be root to build {config.name()} image configured with RepartOffline=no")

        check_workspace_directory(config)

    if tools and not (tools.output_dir_or_cwd() / tools.output).exists():
        if args.verb == Verb.build or args.force > 0:
            check_tools(tools, Verb.build)
            fork_and_wait(run_sync, args, tools, resources=resources)
            fork_and_wait(run_build, args, tools, resources=resources)
        else:
            die(f"Default tools tree requested for image '{last.name()}' but it has not been built yet",
                hint="Make sure to build the image first with 'mkosi build' or use '--force'")

    build = False

    with tempfile.TemporaryDirectory(dir=last.workspace_dir_or_default(), prefix="mkosi-packages-") as package_dir:
        for i, config in enumerate(images):
            images[i] = config = dataclasses.replace(
                config,
                tools_tree=(
                    tools.output_dir_or_cwd() / tools.output
                    if tools and config.tools_tree == Path("default")
                    else config.tools_tree
                )
            )

            check_tools(config, args.verb)
            images[i] = config = run_configure_scripts(config)

            if args.verb != Verb.build and args.force == 0:
                continue

            if (
                config.output_format != OutputFormat.none and
                (config.output_dir_or_cwd() / config.output_with_compression).exists()
            ):
                continue

            # If the output format is "none" and there are no build scripts, there's nothing to do so exit early.
            if config.output_format == OutputFormat.none and not config.build_scripts:
                return

            if args.verb != Verb.build:
                check_tools(config, Verb.build)

            check_inputs(config)
            fork_and_wait(run_sync, args, config, resources=resources)
            fork_and_wait(run_build, args, config, resources=resources, package_dir=Path(package_dir))

            build = True

    if build and args.auto_bump:
        bump_image_version()

    if args.verb == Verb.build:
        return

    # The images array has been modified so we need to reevaluate last again.
    last = images[-1]

    if not (last.output_dir_or_cwd() / last.output_with_compression).exists():
        die(f"Image '{last.name()}' has not been built yet",
            hint="Make sure to build the image first with 'mkosi build' or use '--force'")

    with prepend_to_environ_path(last):
        with (
            acl_toggle_boot(last, INVOKING_USER.uid)
            if args.verb in (Verb.shell, Verb.boot)
            else contextlib.nullcontext()
        ):
            run_vm = {
                Vmm.qemu: run_qemu,
                Vmm.vmspawn: run_vmspawn,
            }[last.vmm]

            {
                Verb.shell: run_shell,
                Verb.boot: run_shell,
                Verb.qemu: run_vm,
                Verb.serve: run_serve,
                Verb.burn: run_burn,
            }[args.verb](args, last)
