# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import dataclasses
import datetime
import hashlib
import io
import itertools
import json
import logging
import os
import resource
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import uuid
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Optional, TextIO, Union, cast

from mkosi.archive import extract_tar, make_cpio, make_tar
from mkosi.burn import run_burn
from mkosi.config import (
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
from mkosi.kmod import gen_required_kernel_modules, process_kernel_modules
from mkosi.log import ARG_DEBUG, complete_step, die, log_notice, log_step
from mkosi.manifest import Manifest
from mkosi.mounts import finalize_source_mounts, mount_overlay
from mkosi.pager import page
from mkosi.partition import Partition, finalize_root, finalize_roothash
from mkosi.qemu import KernelType, copy_ephemeral, run_qemu, run_ssh
from mkosi.run import (
    find_binary,
    fork_and_wait,
    log_process_failure,
    run,
)
from mkosi.sandbox import Mount, chroot_cmd, finalize_crypto_mounts, finalize_passwd_mounts
from mkosi.tree import copy_tree, move_tree, rmtree
from mkosi.types import PathString
from mkosi.user import CLONE_NEWNS, INVOKING_USER, become_root, unshare
from mkosi.util import (
    flatten,
    flock,
    flock_or_die,
    format_rlimit,
    make_executable,
    one_zero,
    read_env_file,
    read_os_release,
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

            if path.is_dir():
                bases += [path]
            elif path.suffix == ".tar":
                extract_tar(path, d, tools=context.config.tools(), sandbox=context.sandbox)
                bases += [d]
            elif path.suffix == ".raw":
                run(["systemd-dissect", "-M", path, d])
                stack.callback(lambda: run(["systemd-dissect", "-U", d]))
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
        for pattern in context.config.remove_files:
            rmtree(*context.root.glob(pattern.lstrip("/")), tools=context.config.tools(), sandbox=context.sandbox)


def install_distribution(context: Context) -> None:
    if context.config.base_trees:
        if not context.config.packages:
            return

        with complete_step(f"Installing extra packages for {str(context.config.distribution).capitalize()}"):
            context.config.distribution.install_packages(context, context.config.packages)
    else:
        with complete_step(f"Installing {str(context.config.distribution).capitalize()}"):
            context.config.distribution.install(context)

            if not context.config.overlay:
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

    for candidate in ["usr/lib/os-release", "etc/os-release", "usr/lib/initrd-release", "etc/initrd-release"]:
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

    osrelease = read_os_release(context.root)
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
            f.write(f"{prefix}_SCOPE=initrd system portable\n")

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
        configure_autologin_service(context, "serial-getty@ttyS0.service",
                                    "--keep-baud 115200,57600,38400,9600 -")

        if context.config.architecture.default_serial_tty() != "ttyS0":
            configure_autologin_service(context,
                                        f"serial-getty@{context.config.architecture.default_serial_tty()}.service",
                                        "--keep-baud 115200,57600,38400,9600 -")


@contextlib.contextmanager
def mount_cache_overlay(context: Context) -> Iterator[None]:
    if not context.config.incremental or not context.config.base_trees or context.config.overlay:
        yield
        return

    d = context.workspace / "cache-overlay"
    with umask(~0o755):
        d.mkdir(exist_ok=True)

    with mount_overlay([context.root], d, context.root):
        yield


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
def finalize_scripts(scripts: Mapping[str, Sequence[PathString]], root: Path) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="mkosi-scripts") as d:
        # Make sure than when mkosi-as-caller is used the scripts can still be accessed.
        os.chmod(d, 0o755)

        for name, script in scripts.items():
            # Make sure we don't end up in a recursive loop when we name a script after the binary it execs
            # by removing the scripts directory from the PATH when we execute a script.
            with (Path(d) / name).open("w") as f:
                f.write("#!/bin/sh\n")

                if find_binary(name, root=root):
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


GIT_COMMAND = (
    "git",
    "-c", "safe.directory=*",
)


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
) -> contextlib.AbstractContextManager[Path]:
    scripts: dict[str, Sequence[PathString]] = {}
    if find_binary("git", root=context.config.tools()):
        scripts["git"] = GIT_COMMAND
    for binary in ("useradd", "groupadd"):
        if find_binary(binary, root=context.config.tools()):
            scripts[binary] = (binary, "--root", "/buildroot")
    return finalize_scripts(scripts | dict(helpers), root=context.config.tools())


def finalize_chroot_scripts(context: Context) -> contextlib.AbstractContextManager[Path]:
    scripts: dict[str, Sequence[PathString]] = {}
    if find_binary("git", root=context.config.tools()):
        scripts["git"] = GIT_COMMAND
    return finalize_scripts(scripts, root=context.root)


@contextlib.contextmanager
def finalize_config_json(config: Config) -> Iterator[Path]:
    with tempfile.NamedTemporaryFile(mode="w") as f:
        f.write(config.to_json())
        yield Path(f.name)


def run_sync_scripts(context: Context) -> None:
    if not context.config.sync_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
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
                *finalize_crypto_mounts(context.config.tools()),
                Mount(script, "/work/sync", ro=True),
                Mount(json, "/work/config.json", ro=True),
            ]

            if (p := INVOKING_USER.home()).exists():
                # We use a writable mount here to keep git worktrees working which encode absolute paths to the parent
                # git repository and might need to modify the git config in the parent git repository when submodules
                # are in use as well.
                mounts += [Mount(p, p)]
            if (p := Path(f"/run/user/{INVOKING_USER.uid}")).exists():
                mounts += [Mount(p, p, ro=True)]

            with complete_step(f"Running sync script {script}…"):
                run(
                    ["/work/sync", "final"],
                    env=env | context.config.environment,
                    stdin=sys.stdin,
                    sandbox=context.sandbox(
                        network=True,
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
        BUILDROOT="/buildroot",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        SCRIPT="/work/prepare",
        CHROOT_SCRIPT="/work/prepare",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    with (
        mount_build_overlay(context) if build else contextlib.nullcontext(),
        finalize_chroot_scripts(context) as cd,
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
    ):
        if build:
            step_msg = "Running prepare script {} in build overlay…"
            arg = "build"
        else:
            step_msg = "Running prepare script {}…"
            arg = "final"

        for script in context.config.prepare_scripts:
            chroot = chroot_cmd(resolve=True)

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
                        network=True,
                        mounts=[
                            *sources,
                            Mount(script, "/work/prepare", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(cd, "/work/scripts", ro=True),
                            Mount(context.root, "/buildroot"),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                    ) + (chroot if script.suffix == ".chroot" else []),
                )


def run_build_scripts(context: Context) -> None:
    if not context.config.build_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        BUILDROOT="/buildroot",
        DESTDIR="/work/dest",
        CHROOT_DESTDIR="/work/dest",
        OUTPUTDIR="/work/out",
        CHROOT_OUTPUTDIR="/work/out",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        SCRIPT="/work/build-script",
        CHROOT_SCRIPT="/work/build-script",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
        WITH_DOCS=one_zero(context.config.with_docs),
        WITH_NETWORK=one_zero(context.config.with_network),
        WITH_TESTS=one_zero(context.config.with_tests),
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
        finalize_chroot_scripts(context) as cd,
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
    ):
        for script in context.config.build_scripts:
            chroot = chroot_cmd(resolve=context.config.with_network)

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
                        network=context.config.with_network,
                        mounts=[
                            *sources,
                            Mount(script, "/work/build-script", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(cd, "/work/scripts", ro=True),
                            Mount(context.root, "/buildroot"),
                            Mount(context.install_dir, "/work/dest"),
                            Mount(context.staging, "/work/out"),
                            *(
                                [Mount(context.config.build_dir, "/work/build")]
                                if context.config.build_dir
                                else []
                            ),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                    ) + (chroot if script.suffix == ".chroot" else []),
                )

    if context.want_local_repo():
        with complete_step("Rebuilding local package repository"):
            context.config.distribution.createrepo(context)


def run_postinst_scripts(context: Context) -> None:
    if not context.config.postinst_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        BUILDROOT="/buildroot",
        OUTPUTDIR="/work/out",
        CHROOT_OUTPUTDIR="/work/out",
        SCRIPT="/work/postinst",
        CHROOT_SCRIPT="/work/postinst",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    with (
        finalize_chroot_scripts(context) as cd,
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
    ):
        for script in context.config.postinst_scripts:
            chroot = chroot_cmd(resolve=context.config.with_network)

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
                        network=context.config.with_network,
                        mounts=[
                            *sources,
                            Mount(script, "/work/postinst", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(cd, "/work/scripts", ro=True),
                            Mount(context.root, "/buildroot"),
                            Mount(context.staging, "/work/out"),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                    ) + (chroot if script.suffix == ".chroot" else []),
                )


def run_finalize_scripts(context: Context) -> None:
    if not context.config.finalize_scripts:
        return

    env = dict(
        DISTRIBUTION=str(context.config.distribution),
        RELEASE=context.config.release,
        ARCHITECTURE=str(context.config.architecture),
        BUILDROOT="/buildroot",
        OUTPUTDIR="/work/out",
        CHROOT_OUTPUTDIR="/work/out",
        SRCDIR="/work/src",
        CHROOT_SRCDIR="/work/src",
        PACKAGEDIR="/work/packages",
        SCRIPT="/work/finalize",
        CHROOT_SCRIPT="/work/finalize",
        MKOSI_UID=str(INVOKING_USER.uid),
        MKOSI_GID=str(INVOKING_USER.gid),
        MKOSI_CONFIG="/work/config.json",
    )

    if context.config.profile:
        env["PROFILE"] = context.config.profile

    with (
        finalize_chroot_scripts(context) as cd,
        finalize_source_mounts(context.config, ephemeral=context.config.build_sources_ephemeral) as sources,
    ):
        for script in context.config.finalize_scripts:
            chroot = chroot_cmd(resolve=context.config.with_network)

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
                        network=context.config.with_network,
                        mounts=[
                            *sources,
                            Mount(script, "/work/finalize", ro=True),
                            Mount(json, "/work/config.json", ro=True),
                            Mount(cd, "/work/scripts", ro=True),
                            Mount(context.root, "/buildroot"),
                            Mount(context.staging, "/work/out"),
                            *context.config.distribution.package_manager(context.config).mounts(context),
                        ],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        scripts=hd,
                    ) + (chroot if script.suffix == ".chroot" else []),
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
        sandbox=context.sandbox(mounts=[Mount(certificate, certificate, ro=True)]),
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
        find_binary("sbsign", root=context.config.tools()) is not None
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
                    mounts=mounts,
                    devices=context.config.secure_boot_key_source.type != KeySource.Type.file,
                )
            )
            output.unlink(missing_ok=True)
            os.link(f.name, output)
    elif (
        context.config.secure_boot_sign_tool == SecureBootSignTool.pesign or
        context.config.secure_boot_sign_tool == SecureBootSignTool.auto and
        find_binary("pesign", root=context.config.tools()) is not None
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

    if not find_binary("bootctl", root=context.config.tools()):
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
            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]),
        )

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


def find_grub_binary(binary: str, root: Path = Path("/")) -> Optional[Path]:
    assert "grub" not in binary
    return find_binary(f"grub-{binary}", f"grub2-{binary}", root=root)


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
        if find_grub_binary(binary, root=context.config.tools()):
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
    mkimage = find_grub_binary("mkimage", root=context.config.tools())
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

    setup = find_grub_binary("bios-setup", root=context.config.tools())
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
                "sh", "-c", f"mount --bind {mountinfo.name} /proc/$$/mountinfo && exec $0 \"$@\"",
                setup,
                "--directory", "/grub",
                context.staging / context.config.output_with_format,
            ],
            sandbox=context.sandbox(
                mounts=[
                    Mount(directory, "/grub"),
                    Mount(context.staging, context.staging),
                    Mount(mountinfo.name, mountinfo.name),
                ],
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
            tools=config.tools(),
            sandbox=config.sandbox,
        )

    if src.is_dir() or (src.is_file() and target):
        copy()
    elif src.suffix == ".tar":
        extract_tar(src, t, tools=config.tools(), sandbox=config.sandbox)
    elif src.suffix == ".raw":
        run(
            ["systemd-dissect", "--copy-from", src, "/", t],
            sandbox=config.sandbox(
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
            tools=context.config.tools(),
            sandbox=context.config.sandbox,
        )

    if not context.config.package_manager_trees:
        return

    with complete_step("Copying in package manager file trees…"):
        for tree in context.config.package_manager_trees:
            install_tree(context.config, tree.source, context.pkgmngr, target=tree.target, preserve=False)


def install_package_directories(context: Context) -> None:
    if not context.config.package_directories:
        return

    with complete_step("Copying in extra packages…"):
        for d in context.config.package_directories:
            copy_tree(
                d, context.packages,
                use_subvolumes=context.config.use_subvolumes,
                tools=context.config.tools(),
                sandbox=context.sandbox,
            )

    if context.want_local_repo():
        with complete_step("Building local package repository"):
            context.config.distribution.createrepo(context)


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
            tools=context.config.tools(),
            sandbox=context.sandbox,
        )


def gzip_binary(context: Context) -> str:
    return "pigz" if find_binary("pigz", root=context.config.tools()) else "gzip"


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
        # UKI on Fedora is named vmlinuz-virt.efi.
        for kimg in kver.glob("vmlinuz*"):
            if KernelType.identify(context.config, kimg) != KernelType.uki:
                yield kver.name, kimg
                break


def want_initrd(context: Context) -> bool:
    if context.config.bootable == ConfigFeature.disabled:
        return False

    if context.config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        return False

    if not any(gen_kernel_images(context)):
        return False

    return True


def finalize_default_initrd(
    args: Args,
    config: Config,
    *,
    resources: Path,
    output_dir: Optional[Path] = None,
    package_dir: Optional[Path] = None,
) -> Config:
    if config.root_password:
        password, hashed = config.root_password
        rootpwopt = f"hashed:{password}" if hashed else password
    else:
        rootpwopt = None

    # Default values are assigned via the parser so we go via the argument parser to construct
    # the config for the initrd.
    cmdline = [
        "--directory", "",
        "--distribution", str(config.distribution),
        "--release", config.release,
        "--architecture", str(config.architecture),
        *(["--mirror", config.mirror] if config.mirror else []),
        "--repository-key-check", str(config.repository_key_check),
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
        *(["--package-directory", str(package_dir)] if package_dir else []),
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
        *(["-f"] * args.force),
    ]

    cmdline += ["--include", os.fspath(resources / "mkosi-initrd")]

    for include in config.initrd_include:
        cmdline += ["--include", os.fspath(include)]

    _, [config] = parse_config(cmdline + ["build"], resources=resources)

    make_executable(
        *config.prepare_scripts,
        *config.postinst_scripts,
        *config.finalize_scripts,
        *config.build_scripts,
    )

    return dataclasses.replace(config, image="default-initrd")


def build_default_initrd(context: Context) -> Path:
    if context.config.distribution == Distribution.custom:
        die("Building a default initrd is not supported for custom distributions")

    config = finalize_default_initrd(
        context.args,
        context.config,
        resources=context.resources,
        output_dir=context.workspace,
        package_dir=context.packages,
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
        if (ucode := (uroot / f"{family:02x}-{model:02x}-{stepping:02x}")).exists():
            return (Path(f"{vendor_id}.bin"), ucode)
        if (ucode := (uroot / f"{family:02x}-{model:02x}-{stepping:02x}.initramfs")).exists():
            return (Path(f"{vendor_id}.bin"), ucode)

    return (Path(f"{vendor_id}.bin"), None)


def build_microcode_initrd(context: Context) -> Optional[Path]:
    if not context.config.architecture.is_x86_variant():
        return None

    microcode = context.workspace / "microcode.initrd"
    if microcode.exists():
        return microcode

    amd = context.root / "usr/lib/firmware/amd-ucode"
    intel = context.root / "usr/lib/firmware/intel-ucode"

    if not amd.exists() and not intel.exists():
        logging.warning("/usr/lib/firmware/{amd-ucode,intel-ucode} not found, not adding microcode")
        return None

    root = context.workspace / "microcode-root"
    destdir = root / "kernel/x86/microcode"

    with umask(~0o755):
        destdir.mkdir(parents=True, exist_ok=True)

    if context.config.microcode_host:
        vendorfile, ucodefile = identify_cpu(context.root)
        if vendorfile is None or ucodefile is None:
            logging.warning("Unable to identify CPU for MicrocodeHostonly=")
            return None
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

    make_cpio(root, microcode, tools=context.config.tools(), sandbox=context.sandbox)

    return microcode


def build_kernel_modules_initrd(context: Context, kver: str) -> Path:
    kmods = context.workspace / f"kernel-modules-{kver}.initrd"
    if kmods.exists():
        return kmods

    make_cpio(
        context.root, kmods,
        files=gen_required_kernel_modules(
            context.root, kver,
            include=context.config.kernel_modules_initrd_include,
            exclude=context.config.kernel_modules_initrd_exclude,
            host=context.config.kernel_modules_initrd_include_host,
            sandbox=context.sandbox,
        ),
        tools=context.config.tools(),
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


def python_binary(config: Config) -> str:
    # If there's no tools tree, prefer the interpreter from MKOSI_INTERPRETER. If there is a tools
    # tree, just use the default python3 interpreter.
    return "python3" if config.tools_tree else os.getenv("MKOSI_INTERPRETER", "python3")


def extract_pe_section(context: Context, binary: Path, section: str, output: Path) -> Path:
    # When using a tools tree, we want to use the pefile module from the tools tree instead of requiring that
    # python-pefile is installed on the host. So we execute python as a subprocess to make sure we load
    # pefile from the tools tree if one is used.

    # TODO: Use ignore_padding=True instead of length once we can depend on a newer pefile.
    pefile = textwrap.dedent(
        f"""\
        import pefile
        import sys
        from pathlib import Path
        pe = pefile.PE("{binary}", fast_load=True)
        section = {{s.Name.decode().strip("\\0"): s for s in pe.sections}}["{section}"]
        sys.stdout.buffer.write(section.get_data(length=section.Misc_VirtualSize))
        """
    )

    with open(output, "wb") as f:
        run(
            [python_binary(context.config)],
            input=pefile,
            stdout=f,
            sandbox=context.sandbox(mounts=[Mount(binary, binary, ro=True)])
        )

    return output


def want_signed_pcrs(config: Config) -> bool:
    return (
        config.sign_expected_pcr == ConfigFeature.enabled or
        (
            config.sign_expected_pcr == ConfigFeature.auto and
            find_binary("systemd-measure", "/usr/lib/systemd/systemd-measure", root=config.tools()) is not None
        )
    )


def build_uki(
    context: Context,
    stub: Path,
    kver: str,
    kimg: Path,
    initrds: Sequence[Path],
    cmdline: Sequence[str],
    output: Path,
) -> None:
    # Older versions of systemd-stub expect the cmdline section to be null terminated. We can't embed
    # nul terminators in argv so let's communicate the cmdline via a file instead.
    (context.workspace / "cmdline").write_text(f"{' '.join(cmdline).strip()}\x00")

    if not (arch := context.config.architecture.to_efi()):
        die(f"Architecture {context.config.architecture} does not support UEFI")

    cmd: list[PathString] = [
        find_binary("ukify", root=context.config.tools()) or "/usr/lib/systemd/ukify",
        "--cmdline", f"@{context.workspace / 'cmdline'}",
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
                "--pcr-banks", "sha1,sha256",
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

    for initrd in initrds:
        cmd += ["--initrd", initrd]
        mounts += [Mount(initrd, initrd, ro=True)]

    with complete_step(f"Generating unified kernel image for kernel version {kver}"):
        run(
            cmd,
            sandbox=context.sandbox(
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


def want_uki(context: Context) -> bool:
    return want_efi(context.config) and (
            context.config.bootloader == Bootloader.uki or
            context.config.unified_kernel_images == ConfigFeature.enabled or (
                context.config.unified_kernel_images == ConfigFeature.auto and
                systemd_stub_binary(context).exists() and
                find_binary("ukify", "/usr/lib/systemd/ukify", root=context.config.tools()) is not None
            )
    )


def find_entry_token(context: Context) -> str:
    if (
        "--version" not in run(["kernel-install", "--help"],
                               stdout=subprocess.PIPE, sandbox=context.sandbox()).stdout or
        systemd_tool_version(context.config, "kernel-install") < "255.1"
    ):
        return context.config.image_id or context.config.distribution.name

    output = json.loads(run(["kernel-install", "--root=/buildroot", "--json=pretty", "inspect"],
                            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot", ro=True)]),
                            stdout=subprocess.PIPE,
                            env={"SYSTEMD_ESP_PATH": "/efi", "SYSTEMD_XBOOTLDR_PATH": "/boot"}).stdout)
    logging.debug(json.dumps(output, indent=4))
    return cast(str, output["EntryToken"])


def finalize_cmdline(context: Context, roothash: Optional[str]) -> list[str]:
    if (context.root / "etc/kernel/cmdline").exists():
        cmdline = [(context.root / "etc/kernel/cmdline").read_text().strip()]
    elif (context.root / "usr/lib/kernel/cmdline").exists():
        cmdline = [(context.root / "usr/lib/kernel/cmdline").read_text().strip()]
    else:
        cmdline = []

    if roothash:
        cmdline += [roothash]

    return cmdline + context.config.kernel_command_line


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

    microcode = build_microcode_initrd(context)
    kmods = build_kernel_modules_initrd(context, kver)
    cmdline = finalize_cmdline(context, finalize_roothash(partitions))

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

        initrds = [Path(shutil.copy2(microcode, dst.parent / "microcode.initrd"))] if microcode else []
        initrds += [
            Path(shutil.copy2(initrd, dst.parent / initrd.name))
            for initrd in (context.config.initrds or [build_default_initrd(context)])
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

        root = finalize_root(partitions)
        assert root

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
                        linux /{kimg.relative_to(context.root / "boot")} {root} {" ".join(cmdline)}
                        initrd {" ".join(os.fspath(Path("/") / i.relative_to(context.root / "boot")) for i in initrds)}
                    }}
                    """
                )
            )

            f.write("fi\n")


def install_uki(context: Context, kver: str, kimg: Path, token: str, partitions: Sequence[Partition]) -> None:
    roothash = finalize_roothash(partitions)

    boot_count = ""
    if (context.root / "etc/kernel/tries").exists():
        boot_count = f'+{(context.root / "etc/kernel/tries").read_text().strip()}'

    if context.config.bootloader == Bootloader.uki:
        if context.config.shim_bootloader != ShimBootloader.none:
            boot_binary = context.root / shim_second_stage_binary(context)
        else:
            boot_binary = context.root / efi_boot_binary(context)
    else:
        if roothash:
            _, _, h = roothash.partition("=")
            boot_binary = context.root / f"boot/EFI/Linux/{token}-{kver}-{h}{boot_count}.efi"
        else:
            boot_binary = context.root / f"boot/EFI/Linux/{token}-{kver}{boot_count}.efi"

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
        microcode = build_microcode_initrd(context)

        initrds = [microcode] if microcode else []
        initrds += context.config.initrds or [build_default_initrd(context)]

        if context.config.kernel_modules_initrd:
            initrds += [build_kernel_modules_initrd(context, kver)]

        build_uki(
            context,
            systemd_stub_binary(context),
            kver,
            context.root / kimg,
            initrds,
            finalize_cmdline(context, roothash),
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

    if context.config.bootable == ConfigFeature.enabled and not gen_kernel_images(context):
        die("A bootable image was requested but no kernel was found")

    token = find_entry_token(context)

    for kver, kimg in gen_kernel_images(context):
        if want_uki(context):
            install_uki(context, kver, kimg, token, partitions)
        if not want_uki(context) or want_grub_bios(context, partitions):
            install_type1(context, kver, kimg, token, partitions)

        if context.config.bootloader == Bootloader.uki:
            break


def make_uki(context: Context, stub: Path, kver: str, kimg: Path, microcode: Optional[Path], output: Path) -> None:
    make_cpio(context.root, context.workspace / "initrd", tools=context.config.tools(), sandbox=context.sandbox)
    maybe_compress(context, context.config.compress_output, context.workspace / "initrd", context.workspace / "initrd")

    initrds = [microcode] if microcode else []
    initrds += [context.workspace / "initrd"]

    build_uki(context, stub, kver, kimg, initrds, context.config.kernel_command_line, output)
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
                tools=context.config.tools(),
                sandbox=context.sandbox,
            )
        return

    if not dst:
        dst = src.parent / f"{src.name}{compression.extension()}"

    with complete_step(f"Compressing {src} with {compression}"):
        with src.open("rb") as i:
            src.unlink() # if src == dst, make sure dst doesn't truncate the src file but creates a new file.

            with dst.open("wb") as o:
                run(compressor_command(context, compression), stdin=i, stdout=o, sandbox=context.sandbox())


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
        microcode = build_microcode_initrd(context)
        initrds = [microcode] if microcode else []
        initrds += context.config.initrds or [build_default_initrd(context)]
        if context.config.kernel_modules_initrd:
            kver = next(gen_kernel_images(context))[0]
            initrds += [build_kernel_modules_initrd(context, kver)]
        join_initrds(initrds, context.staging / context.config.output_split_initrd)
        break


def hash_file(of: TextIO, path: Path) -> None:
    bs = 16 * 1024**2
    h = hashlib.sha256()

    with path.open("rb") as sf:
        while (buf := sf.read(bs)):
            h.update(buf)

    of.write(h.hexdigest() + " *" + path.name + "\n")


def calculate_sha256sum(context: Context) -> None:
    if not context.config.checksum:
        return

    if context.config.output_format == OutputFormat.directory:
        return

    with complete_step("Calculating SHA256SUMS…"):
        with open(context.workspace / context.config.output_checksum, "w") as f:
            for p in context.staging.iterdir():
                hash_file(f, p)

        (context.workspace / context.config.output_checksum).rename(context.staging / context.config.output_checksum)


def calculate_signature(context: Context) -> None:
    if not context.config.sign or not context.config.checksum:
        return

    if context.config.output_format == OutputFormat.directory:
        return

    # GPG messes with the user's home directory so we run it as the invoking user.

    cmdline: list[PathString] = [
        "setpriv",
        f"--reuid={INVOKING_USER.uid}",
        f"--regid={INVOKING_USER.gid}",
        "--clear-groups",
        "gpg",
        "--detach-sign",
    ]

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
        run(cmdline, env=env, stdin=i, stdout=o, sandbox=context.sandbox(mounts=mounts, options=options))


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

    if config.tools_tree and not config.tools_tree.exists():
        die(f"Tools tree {config.tools_tree} not found")

    for name, trees in (("Skeleton", config.skeleton_trees),
                        ("Package manager", config.package_manager_trees),
                        ("Extra", config.extra_trees)):
        for tree in trees:
            if not tree.source.exists():
                die(f"{name} tree {tree.source} not found")

    if config.bootable != ConfigFeature.disabled:
        for p in config.initrds:
            if not p.exists():
                die(f"Initrd {p} not found")
            if not p.is_file():
                die(f"Initrd {p} is not a file")

    for script in itertools.chain(
        config.prepare_scripts,
        config.build_scripts,
        config.postinst_scripts,
        config.finalize_scripts,
    ):
        if not os.access(script, os.X_OK):
            die(f"{script} is not executable")


def check_outputs(config: Config) -> None:
    for f in (
        config.output_with_compression,
        config.output_checksum if config.checksum else None,
        config.output_signature if config.sign else None,
        config.output_nspawn_settings if config.nspawn_settings else None,
    ):
        if f and (config.output_dir_or_cwd() / f).exists():
            die(f"Output path {f} exists already. (Consider invocation with --force.)")


def check_tool(config: Config, *tools: PathString, reason: str, hint: Optional[str] = None) -> Path:
    tool = find_binary(*tools, root=config.tools())
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

    v = systemd_tool_version(config, tool)
    if v < version:
        die(f"Found '{tool}' with version {v} but version {version} or newer is required to {reason}.",
            hint=f"Use ToolsTree=default to get a newer version of '{tools[0]}'.")


def check_tools(config: Config, verb: Verb) -> None:
    if verb == Verb.build:
        if want_efi(config) and config.unified_kernel_images == ConfigFeature.enabled:
            check_systemd_tool(
                config,
                "ukify", "/usr/lib/systemd/ukify",
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
            check_systemd_tool(
                config,
                "ukify", "/usr/lib/systemd/ukify",
                version="256~devel",
                reason="sign Unified Kernel Image with OpenSSL engine",
            )

            if want_signed_pcrs(config):
                check_systemd_tool(
                    config,
                    "systemd-measure",
                    version="256~devel",
                    reason="sign PCR hashes with OpenSSL engine",
                )

        if config.verity_key_source.type != KeySource.Type.file:
            check_systemd_tool(
                config,
                "systemd-repart",
                version="256~devel",
                reason="sign verity roothash signature with OpenSSL engine",
            )

    if verb == Verb.boot:
        check_systemd_tool(config, "systemd-nspawn", version="254", reason="boot images")

    if verb == Verb.qemu and config.vmm == Vmm.vmspawn:
        check_systemd_tool(config, "systemd-vmspawn", version="256~devel", reason="boot images with vmspawn")


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
    if context.config.overlay or context.config.output_format.is_extension_image():
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
                include=context.config.kernel_modules_include,
                exclude=context.config.kernel_modules_exclude,
                host=context.config.kernel_modules_include_host,
                sandbox=context.sandbox,
            )

        with complete_step(f"Running depmod for {kver}"):
            run(["depmod", "--all", "--basedir", "/buildroot", kver],
                sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]))


def run_sysusers(context: Context) -> None:
    if not find_binary("systemd-sysusers", root=context.config.tools()):
        logging.warning("systemd-sysusers is not installed, not generating system users")
        return

    with complete_step("Generating system users"):
        run(["systemd-sysusers", "--root=/buildroot"],
            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]))


def run_tmpfiles(context: Context) -> None:
    if not find_binary("systemd-tmpfiles", root=context.config.tools()):
        logging.warning("systemd-tmpfiles is not installed, not generating volatile files")
        return

    with complete_step("Generating volatile files"):
        cmdline = [
            "systemd-tmpfiles",
            "--root=/buildroot",
            "--boot",
            "--create",
            "--remove",
            # Exclude APIVFS and temporary files directories.
            *(f"--exclude-prefix={d}" for d in ("/tmp", "/var/tmp", "/run", "/proc", "/sys", "/dev")),
        ]

        sandbox = context.sandbox(
            mounts=[
                Mount(context.root, "/buildroot"),
                # systemd uses acl.h to parse ACLs in tmpfiles snippets which uses the host's passwd so we have to
                # mount the image's passwd over it to make ACL parsing work.
                *finalize_passwd_mounts(context.root)
            ],
        )

        result = run(
            cmdline,
            sandbox=sandbox,
            env={"SYSTEMD_TMPFILES_FORCE_SUBVOL": "0"},
            check=False,
        )
        # systemd-tmpfiles can exit with DATAERR or CANTCREAT in some cases which are handled as success by the
        # systemd-tmpfiles service so we handle those as success as well.
        if result.returncode not in (0, 65, 73):
            log_process_failure([str(s) for s in sandbox], cmdline, result.returncode)
            raise subprocess.CalledProcessError(result.returncode, cmdline)


def run_preset(context: Context) -> None:
    if not find_binary("systemctl", root=context.config.tools()):
        logging.warning("systemctl is not installed, not applying presets")
        return

    with complete_step("Applying presets…"):
        run(["systemctl", "--root=/buildroot", "preset-all"],
            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]))
        run(["systemctl", "--root=/buildroot", "--global", "preset-all"],
            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]))


def run_hwdb(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    if not find_binary("systemd-hwdb", root=context.config.tools()):
        logging.warning("systemd-hwdb is not installed, not generating hwdb")
        return

    with complete_step("Generating hardware database"):
        run(["systemd-hwdb", "--root=/buildroot", "--usr", "--strict", "update"],
            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]))

    # Remove any existing hwdb in /etc in favor of the one we just put in /usr.
    (context.root / "etc/udev/hwdb.bin").unlink(missing_ok=True)


def run_firstboot(context: Context) -> None:
    if context.config.overlay or context.config.output_format.is_extension_image():
        return

    if not find_binary("systemd-firstboot", root=context.config.tools()):
        logging.warning("systemd-firstboot is not installed, not applying first boot settings")
        return

    password, hashed = context.config.root_password or (None, False)
    if password and not hashed:
        password = run(["openssl", "passwd", "-stdin", "-6"],
                       sandbox=context.sandbox(), input=password, stdout=subprocess.PIPE).stdout.strip()

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
            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]))

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

    policy, fc, binpolicy = selinux

    with complete_step(f"Relabeling files using {policy} policy"):
        run(["setfiles", "-mFr", "/buildroot", "-c", binpolicy, fc, "/buildroot"],
            sandbox=context.sandbox(mounts=[Mount(context.root, "/buildroot")]),
            check=context.config.selinux_relabel == ConfigFeature.enabled)


def need_build_overlay(config: Config) -> bool:
    return bool(config.build_scripts and (config.build_packages or config.prepare_scripts))


def save_cache(context: Context) -> None:
    if not context.config.incremental or context.config.overlay:
        return

    final, build, manifest = cache_tree_paths(context.config)

    with complete_step("Installing cache copies"):
        rmtree(final, tools=context.config.tools(), sandbox=context.sandbox)

        # We only use the cache-overlay directory for caching if we have a base tree, otherwise we just
        # cache the root directory.
        if (context.workspace / "cache-overlay").exists():
            move_tree(
                context.workspace / "cache-overlay", final,
                use_subvolumes=context.config.use_subvolumes,
                tools=context.config.tools(),
                sandbox=context.sandbox,
            )
        else:
            move_tree(
                context.root, final,
                use_subvolumes=context.config.use_subvolumes,
                sandbox=context.sandbox,
            )

        if need_build_overlay(context.config) and (context.workspace / "build-overlay").exists():
            rmtree(build, tools=context.config.tools(), sandbox=context.sandbox)
            move_tree(
                context.workspace / "build-overlay", build,
                use_subvolumes=context.config.use_subvolumes,
                tools=context.config.tools(),
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
    if not config.incremental or config.overlay:
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
                    sandbox=config.sandbox(mounts=[Mount(manifest, manifest)]))

            return False
    else:
        logging.info(f"{manifest} does not exist, not reusing cached images")
        return False

    # Either we're running as root and the cache is owned by root or we're running unprivileged inside a user
    # namespace and we'll think the cache is owned by root. However, if we're running as root and the cache was
    # generated by an unprivileged build, the cache will not be owned by root and we should not use it.
    for p in (final, build):
        if p.exists() and os.getuid() == 0 and p.stat().st_uid != 0:
            logging.info("Running as root but cached images were not built as root, not reusing cached images")
            return False

    return True


def reuse_cache(context: Context) -> bool:
    if not have_cache(context.config):
        return False

    final, build, _ = cache_tree_paths(context.config)

    with complete_step("Copying cached trees"):
        copy_tree(
            final, context.root,
            use_subvolumes=context.config.use_subvolumes,
            tools=context.config.tools(),
            sandbox=context.sandbox,
        )

        if need_build_overlay(context.config):
            (context.workspace / "build-overlay").symlink_to(build)

    return True


def save_uki_components(context: Context) -> tuple[Optional[Path], Optional[str], Optional[Path], Optional[Path]]:
    if context.config.output_format not in (OutputFormat.uki, OutputFormat.esp):
        return None, None, None, None

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
    if tabs and systemd_tool_version(context.config, "systemd-repart") >= 256:
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
                    devices=(
                        not context.config.repart_offline or
                        context.config.verity_key_source.type != KeySource.Type.file
                    ),
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
    cmdline: list[PathString] = [
        "systemd-repart",
        "--root=/buildroot",
        "--dry-run=no",
        "--no-pager",
        f"--offline={yes_no(context.config.repart_offline)}",
        "--seed", str(context.config.seed) if context.config.seed else "random",
        "--empty=create",
        "--size=auto",
        output,
    ]
    mounts = [
        Mount(output.parent, output.parent),
        Mount(context.root, "/buildroot", ro=True),
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

    env = {
        option: value
        for option, value in context.config.environment.items()
        if option.startswith("SYSTEMD_REPART_MKFS_OPTIONS_") or option == "SOURCE_DATE_EPOCH"
    }

    with complete_step(f"Building {context.config.output_format} extension image"):
        r = context.resources / f"repart/definitions/{context.config.output_format}.repart.d"
        mounts += [Mount(r, r, ro=True)]
        run(
            cmdline + ["--definitions", r],
            env=env,
            sandbox=context.sandbox(
                devices=(
                    not context.config.repart_offline or
                    context.config.verity_key_source.type != KeySource.Type.file
                ),
                mounts=mounts,
            ),
        )


def finalize_staging(context: Context) -> None:
    # Our output unlinking logic removes everything prefixed with the name of the image, so let's make
    # sure that everything we put into the output directory is prefixed with the name of the output.
    for f in context.staging.iterdir():
        # Skip the symlink we create without the version that points to the output with the version.
        if f.name.startswith(context.config.output) and f.is_symlink():
            continue

        name = f.name
        if not name.startswith(context.config.output):
            name = f"{context.config.output}-{name}"
        if name != f.name:
            f.rename(context.staging / name)

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
            tools=context.config.tools(),
            sandbox=context.sandbox,
        )


def normalize_mtime(root: Path, mtime: Optional[int], directory: Optional[Path] = None) -> None:
    if mtime is None:
        return

    directory = directory or Path("")

    if not (root / directory).exists():
        return

    with complete_step(f"Normalizing modification times of /{directory}"):
        os.utime(root / directory, (mtime, mtime), follow_symlinks=False)
        for p in (root / directory).rglob("*"):
            os.utime(p, (mtime, mtime), follow_symlinks=False)


@contextlib.contextmanager
def setup_workspace(args: Args, config: Config) -> Iterator[Path]:
    with contextlib.ExitStack() as stack:
        workspace = Path(tempfile.mkdtemp(dir=config.workspace_dir_or_default(), prefix="mkosi-workspace"))
        stack.callback(lambda: rmtree(workspace, tools=config.tools(), sandbox=config.sandbox))
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
    if have_cache(context.config):
        return

    subdir = context.config.distribution.package_manager(context.config).subdir(context.config)

    # Don't copy anything if the repository metadata directories are already populated.
    if (
        any((context.package_cache_dir / "cache" / subdir).glob("*")) or
        any((context.package_cache_dir / "lib" / subdir).glob("*"))
    ):
        logging.debug(f"Found repository metadata in {context.package_cache_dir}, not copying repository metadata")
        return

    with lock_repository_metadata(context.config):
        for d in ("cache", "lib"):
            src = context.config.package_cache_dir_or_default() / d / subdir
            if not src.exists():
                logging.debug(f"{src} does not exist, not copying repository metadata from it")
                continue

            if d == "cache":
                caches = context.config.distribution.package_manager(context.config).cache_subdirs(src)
            else:
                caches = []

            with tempfile.TemporaryDirectory() as tmp:
                os.chmod(tmp, 0o755)

                # cp doesn't support excluding directories but we can imitate it by bind mounting an empty directory
                # over the directories we want to exclude.
                exclude = [Mount(tmp, p, ro=True) for p in caches]

                dst = context.package_cache_dir / d / subdir
                with umask(~0o755):
                    dst.mkdir(parents=True, exist_ok=True)

                def sandbox(*, mounts: Sequence[Mount] = ()) -> list[PathString]:
                    return context.sandbox(mounts=[*mounts, *exclude])

                copy_tree(
                    src, dst,
                    tools=context.config.tools(),
                    preserve=False,
                    sandbox=sandbox,
                )


def build_image(context: Context) -> None:
    manifest = Manifest(context) if context.config.manifest_format else None

    install_package_manager_trees(context)

    with mount_base_trees(context):
        install_base_trees(context)
        cached = reuse_cache(context)

        if not cached:
            with mount_cache_overlay(context):
                copy_repository_metadata(context)

        context.config.distribution.setup(context)
        install_package_directories(context)

        if not cached:
            with mount_cache_overlay(context):
                install_skeleton_trees(context)
                install_distribution(context)
                run_prepare_scripts(context, build=False)
                install_build_packages(context)
                run_prepare_scripts(context, build=True)
                run_depmod(context, cache=True)

            save_cache(context)
            reuse_cache(context)

        check_root_populated(context)
        run_build_scripts(context)

        if context.config.output_format == OutputFormat.none:
            # Touch an empty file to indicate the image was built.
            (context.staging / context.config.output).touch()
            finalize_staging(context)
            return

        install_build_dest(context)
        install_extra_trees(context)
        run_postinst_scripts(context)

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
        make_tar(
            context.root, context.staging / context.config.output_with_format,
            tools=context.config.tools(),
            sandbox=context.sandbox,
        )
    elif context.config.output_format == OutputFormat.cpio:
        make_cpio(
            context.root, context.staging / context.config.output_with_format,
            tools=context.config.tools(),
            sandbox=context.sandbox,
        )
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

    finalize_staging(context)

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
        sandbox=config.sandbox(mounts=[Mount(root, root)]),
    )


@contextlib.contextmanager
def acl_maybe_toggle(config: Config, root: Path, uid: int, *, always: bool) -> Iterator[None]:
    if not config.acl:
        yield
        return

    # getfacl complains about absolute paths so make sure we pass a relative one.
    if root.exists():
        sandbox = config.sandbox(mounts=[Mount(root, root)], options=["--chdir", root])
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
    name = config.name().replace("_", "-")
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
                    fname,
                ],
                stdin=sys.stdin,
                env=config.environment,
                sandbox=config.sandbox(network=True, devices=True, mounts=[Mount(fname, fname)]),
            )

        if config.output_format == OutputFormat.directory:
            cmdline += ["--directory", fname]

            owner = os.stat(fname).st_uid
            if owner != 0:
                cmdline += [f"--private-users={str(owner)}"]
        else:
            cmdline += ["--image", fname]

        for tree in config.runtime_trees:
            target = Path("/root/src") / (tree.target or tree.source.name)
            # We add norbind because very often RuntimeTrees= will be used to mount the source directory into the
            # container and the output directory from which we're running will very likely be a subdirectory of the
            # source directory which would mean we'd be mounting the container root directory as a subdirectory in
            # itself which tends to lead to all kinds of weird issues, which we avoid by not doing a recursive mount
            # which means the container root directory mounts will be skipped.
            cmdline += ["--bind", f"{tree.source}:{target}:norbind,rootidmap"]

        if config.runtime_scratch == ConfigFeature.enabled or (
            config.runtime_scratch == ConfigFeature.auto and
            config.output_format == OutputFormat.disk
        ):
            scratch = stack.enter_context(tempfile.TemporaryDirectory(dir="/var/tmp"))
            os.chmod(scratch, 0o1777)
            cmdline += ["--bind", f"{scratch}:/var/tmp"]

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

        run(
            cmdline,
            stdin=sys.stdin,
            stdout=sys.stdout,
            env=os.environ | config.environment,
            log=False,
            sandbox=config.sandbox(devices=True, network=True, relaxed=True),
        )


def run_systemd_tool(tool: str, args: Args, config: Config) -> None:
    if config.output_format not in (OutputFormat.disk, OutputFormat.directory):
        die(f"{config.output_format} images cannot be inspected with {tool}")

    if (
        args.verb in (Verb.journalctl, Verb.coredumpctl)
        and config.output_format == OutputFormat.disk
        and os.getuid() != 0
    ):
        die(f"Must be root to run the {args.verb} command")

    if (tool_path := find_binary(tool, root=config.tools())) is None:
        die(f"Failed to find {tool}")

    if config.ephemeral:
        die(f"Images booted in ephemeral mode cannot be inspected with {tool}")

    image_arg_name = "root" if config.output_format == OutputFormat.directory else "image"
    run(
        [
            tool_path,
            f"--{image_arg_name}={config.output_dir_or_cwd() / config.output}",
            *args.cmdline
        ],
        stdin=sys.stdin,
        stdout=sys.stdout,
        env=os.environ | config.environment,
        log=False,
        preexec_fn=become_root,
        sandbox=config.sandbox(network=True, devices=config.output_format == OutputFormat.disk, relaxed=True),
    )


def run_journalctl(args: Args, config: Config) -> None:
    run_systemd_tool("journalctl", args, config)


def run_coredumpctl(args: Args, config: Config) -> None:
    run_systemd_tool("coredumpctl", args, config)


def run_serve(args: Args, config: Config) -> None:
    """Serve the output directory via a tiny HTTP server"""

    run([python_binary(config), "-m", "http.server", "8081"],
        stdin=sys.stdin, stdout=sys.stdout,
        sandbox=config.sandbox(network=True, relaxed=True, options=["--chdir", config.output_dir_or_cwd()]))


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
    version = Path("mkosi.version").read_text().strip()
    v = version.split(".")

    try:
        m = int(v[-1])
    except ValueError:
        new_version = version + ".2"
        logging.info(
            "Last component of current version is not a decimal integer, "
            f"appending '.2', bumping '{version}' → '{new_version}'."
        )
    else:
        new_version = ".".join(v[:-1] + [str(m + 1)])
        logging.info(f"Increasing last component of version by one, bumping '{version}' → '{new_version}'.")

    Path("mkosi.version").write_text(f"{new_version}\n")
    os.chown("mkosi.version", INVOKING_USER.uid, INVOKING_USER.gid)


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
    if config.tools_tree or not config.extra_search_paths:
        yield
        return

    with tempfile.TemporaryDirectory(prefix="mkosi.path") as d:

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
        *(["-f"] * args.force),
    ]

    _, [tools] = parse_config(
        cmdline + ["--include", os.fspath(resources / "mkosi-tools"), "build"],
        resources=resources,
    )

    make_executable(
        *tools.prepare_scripts,
        *tools.postinst_scripts,
        *tools.finalize_scripts,
        *tools.build_scripts,
    )

    tools = dataclasses.replace(tools, image=f"{config.tools_tree_distribution}-tools")

    return tools


def check_workspace_directory(config: Config) -> None:
    wd = config.workspace_dir_or_default()

    if wd.is_relative_to(Path.cwd()):
        die(f"The workspace directory ({wd}) must be located outside the current working directory ({Path.cwd()})",
            hint="Use WorkspaceDirectory= to configure a different workspace directory")

    for tree in config.build_sources:
        if wd.is_relative_to(tree.source):
            die(f"The workspace directory ({wd}) cannot be a subdirectory of any source directory ({tree.source})",
                hint="Use WorkspaceDirectory= to configure a different workspace directory")


def needs_clean(args: Args, config: Config) -> bool:
    return (
        args.verb == Verb.clean or
        args.force > 0 or
        not (config.output_dir_or_cwd() / config.output_with_compression).exists() or
        # When the output is a directory, its name is the same as the symlink we create that points to the actual
        # output when not building a directory. So if the full output path exists, we have to check that it's not
        # a symlink as well.
        (config.output_dir_or_cwd() / config.output_with_compression).is_symlink()
    )


def run_clean(args: Args, config: Config, *, resources: Path) -> None:
    if not needs_clean(args, config):
        return

    become_root()

    # We remove any cached images if either the user used --force twice, or he/she called "clean" with it
    # passed once. Let's also remove the downloaded package cache if the user specified one additional
    # "--force".

    if args.verb == Verb.clean:
        remove_build_cache = args.force > 0
        remove_package_cache = args.force > 1
    else:
        remove_build_cache = args.force > 1
        remove_package_cache = args.force > 2

    if outputs := list(config.output_dir_or_cwd().glob(f"{config.output}*")):
        with (
            complete_step(f"Removing output files of {config.name()} image…"),
            flock_or_die(config.output_dir_or_cwd() / config.output)
            if (config.output_dir_or_cwd() / config.output).exists()
            else contextlib.nullcontext()
        ):
            rmtree(*outputs)

    if remove_build_cache:
        if config.cache_dir:
            initrd = (
                cache_tree_paths(finalize_default_initrd(args, config, resources=resources))
                if config.distribution != Distribution.custom
                else []
            )

            if any(p.exists() for p in itertools.chain(cache_tree_paths(config), initrd)):
                with complete_step(f"Removing cache entries of {config.name()} image…"):
                    rmtree(*(p for p in itertools.chain(cache_tree_paths(config), initrd) if p.exists()))

        if config.build_dir and config.build_dir.exists() and any(config.build_dir.iterdir()):
            with complete_step(f"Clearing out build directory of {config.name()} image…"):
                rmtree(*config.build_dir.iterdir())

    if (
        remove_package_cache and
        any(config.package_cache_dir_or_default().glob("*"))
    ):
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
    if have_cache(context.config) or context.config.cacheonly != Cacheonly.none:
        return

    with (
        complete_step(f"Syncing package manager metadata for {context.config.name()} image"),
        lock_repository_metadata(context.config),
    ):
        context.config.distribution.package_manager(context.config).sync(context)


def run_sync(args: Args, config: Config, *, resources: Path) -> None:
    if os.getuid() == 0:
        os.setgroups(INVOKING_USER.extra_groups())
        os.setgid(INVOKING_USER.gid)
        os.setuid(INVOKING_USER.uid)

    for script in config.sync_scripts:
        if not os.access(script, os.X_OK):
            die(f"{script} is not executable")

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


def run_build(args: Args, config: Config, *, resources: Path) -> None:
    check_inputs(config)

    if (uid := os.getuid()) != 0:
        become_root()
    unshare(CLONE_NEWNS)
    if uid == 0:
        run(["mount", "--make-rslave", "/"])

    # For extra safety when running as root, remount a bunch of stuff read-only.
    # Because some build systems use output directories in /usr, we only remount
    # /usr read-only if the output directory is not relative to it.
    remount = ["/etc", "/opt", "/boot", "/efi", "/media"]
    if not config.output_dir_or_cwd().is_relative_to("/usr"):
        remount += ["/usr"]

    for d in remount:
        if Path(d).exists():
            run(["mount", "--rbind", d, d, "--options", "ro"])

    with (
        complete_step(f"Building {config.name()} image"),
        prepend_to_environ_path(config),
    ):
        check_tools(config, Verb.build)

        for p in (
            config.output_dir,
            config.cache_dir,
            config.package_cache_dir_or_default(),
            config.build_dir,
            config.workspace_dir,
        ):
            if p and not p.exists():
                INVOKING_USER.mkdir(p)

        with (
            acl_toggle_build(config, INVOKING_USER.uid),
            rchown_package_manager_dirs(config),
            setup_workspace(args, config) as workspace,
        ):
            build_image(Context(args, config, workspace=workspace, resources=resources))


def run_verb(args: Args, images: Sequence[Config], *, resources: Path) -> None:
    images = list(images)

    if args.verb.needs_root() and os.getuid() != 0:
        die(f"Must be root to run the {args.verb} command")

    if args.verb == Verb.documentation:
        return show_docs(args, resources=resources)

    if args.verb == Verb.genkey:
        return generate_key_cert_pair(args)

    if all(config == Config.default() for config in images):
        die("No configuration found",
            hint="Make sure you're running mkosi from a directory with configuration files")

    if args.verb == Verb.bump:
        return bump_image_version()

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

    # First, process all directory removals because otherwise if different images share directories a later
    # image build could end up deleting the output generated by an earlier image build.
    for config in images:
        if config.tools_tree and config.tools_tree == Path("default"):
            fork_and_wait(
                run_clean,
                args,
                finalize_default_tools(args, config, resources=resources),
                resources=resources,
            )

        fork_and_wait(run_clean, args, config, resources=resources)

    if args.verb == Verb.clean:
        return

    for config in images:
        if (minversion := config.minimum_version) and minversion > __version__:
            die(f"mkosi {minversion} or newer is required to build this configuration (found {__version__})")

        if not config.repart_offline and os.getuid() != 0:
            die(f"Must be root to build {config.name()} image configured with RepartOffline=no")

        check_workspace_directory(config)

    build = False

    for i, config in enumerate(images):
        tools = (
            finalize_default_tools(args, config, resources=resources)
            if config.tools_tree and config.tools_tree == Path("default")
            else None
        )

        images[i] = config = dataclasses.replace(
            config,
            tools_tree=tools.output_dir_or_cwd() / tools.output if tools else config.tools_tree,
        )

        if tools and not (tools.output_dir_or_cwd() / tools.output_with_compression).exists():
            fork_and_wait(run_sync, args, tools, resources=resources)
            fork_and_wait(run_build, args, tools, resources=resources)

        if (config.output_dir_or_cwd() / config.output_with_compression).exists():
            continue

        fork_and_wait(run_sync, args, config, resources=resources)
        fork_and_wait(run_build, args, config, resources=resources)

        build = True

    if build and args.auto_bump:
        bump_image_version()

    if args.verb == Verb.build:
        return

    last = images[-1]

    with prepend_to_environ_path(last):
        check_tools(last, args.verb)

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
