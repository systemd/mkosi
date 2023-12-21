# SPDX-License-Identifier: LGPL-2.1+
import enum
import logging
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Optional

from mkosi.log import ARG_DEBUG_SHELL
from mkosi.mounts import finalize_passwd_mounts
from mkosi.run import find_binary, log_process_failure, run
from mkosi.state import MkosiState
from mkosi.types import _FILE, CompletedProcess, PathString
from mkosi.util import flatten, one_zero


# https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h
class Capability(enum.Enum):
    CAP_NET_ADMIN = 12


def have_effective_cap(capability: Capability) -> bool:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("CapEff:"):
            hexcap = line.removeprefix("CapEff:").strip()
            break
    else:
        logging.warning(f"\"CapEff:\" not found in /proc/self/status, assuming we don't have {capability}")
        return False

    return (int(hexcap, 16) & (1 << capability.value)) != 0


def finalize_mounts(state: MkosiState) -> list[PathString]:
    mounts = [
        ((state.config.tools_tree or Path("/")) / subdir, Path("/") / subdir, True)
        for subdir in (
            Path("etc/pki"),
            Path("etc/ssl"),
            Path("etc/crypto-policies"),
            Path("etc/ca-certificates"),
            Path("etc/pacman.d"),
            Path("var/lib/ca-certificates"),
        )
        if ((state.config.tools_tree or Path("/")) / subdir).exists()
    ]

    mounts += [
        (d, d, False)
        for d in (state.workspace, state.config.cache_dir, state.config.output_dir, state.config.build_dir)
        if d
    ]

    return flatten(
        ["--ro-bind" if readonly else "--bind", src, target]
        for src, target, readonly
        in sorted(set(mounts), key=lambda s: s[1])
    )


def bwrap(
    state: MkosiState,
    cmd: Sequence[PathString],
    *,
    network: bool = False,
    devices: bool = False,
    options: Sequence[PathString] = (),
    log: bool = True,
    scripts: Optional[Path] = None,
    env: Mapping[str, str] = {},
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    input: Optional[str] = None,
    check: bool = True,
) -> CompletedProcess:
    cmdline: list[PathString] = [
        "bwrap",
        "--ro-bind", "/usr", "/usr",
        "--bind", "/var/tmp", "/var/tmp",
        "--bind", "/tmp", "/tmp",
        "--bind", Path.cwd(), Path.cwd(),
        "--chdir", Path.cwd(),
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-cgroup",
        *(["--unshare-net"] if not network and have_effective_cap(Capability.CAP_NET_ADMIN) else []),
        "--die-with-parent",
        "--proc", "/proc",
        "--setenv", "SYSTEMD_OFFLINE", one_zero(network),
    ]

    if devices:
        cmdline += [
            "--bind", "/sys", "/sys",
            "--dev-bind", "/dev", "/dev",
        ]
    else:
        cmdline += ["--dev", "/dev"]

    for p in Path("/").iterdir():
        if p.is_symlink():
            cmdline += ["--symlink", p.readlink(), p]

    if network:
        cmdline += ["--bind", "/etc/resolv.conf", "/etc/resolv.conf"]

    cmdline += finalize_mounts(state) + [
        "--setenv", "PATH", f"{scripts or ''}:{os.environ['PATH']}",
        *options,
        "sh", "-c", "chmod 1777 /dev/shm && exec $0 \"$@\"",
    ]

    if setpgid := find_binary("setpgid"):
        cmdline += [setpgid, "--foreground", "--"]

    try:
        result = run(
            [*cmdline, *cmd],
            env=env,
            log=False,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            input=input,
            check=check,
        )
    except subprocess.CalledProcessError as e:
        if log:
            log_process_failure([os.fspath(s) for s in cmd], e.returncode)
        if ARG_DEBUG_SHELL.get():
            run([*cmdline, "sh"], stdin=sys.stdin, check=False, env=env, log=False)
        raise e

    return result


def apivfs_cmd(root: Path) -> list[PathString]:
    cmdline: list[PathString] = [
        "bwrap",
        "--dev-bind", "/", "/",
        "--chdir", Path.cwd(),
        "--tmpfs", root / "run",
        "--tmpfs", root / "tmp",
        "--bind", os.getenv("TMPDIR", "/var/tmp"), root / "var/tmp",
        "--proc", root / "proc",
        "--dev", root / "dev",
        # APIVFS generally means chrooting is going to happen so unset TMPDIR just to be safe.
        "--unsetenv", "TMPDIR",
    ]

    if (root / "etc/machine-id").exists():
        # Make sure /etc/machine-id is not overwritten by any package manager post install scripts.
        cmdline += ["--ro-bind", root / "etc/machine-id", root / "etc/machine-id"]

    cmdline += finalize_passwd_mounts(root)

    if setpgid := find_binary("setpgid"):
        cmdline += [setpgid, "--foreground", "--"]

    chmod = f"chmod 1777 {root / 'tmp'} {root / 'var/tmp'} {root / 'dev/shm'}"
    # Make sure anything running in the root directory thinks it's in a container. $container can't always be
    # accessed so we write /run/host/container-manager as well which is always accessible.
    container = f"mkdir {root}/run/host && echo mkosi >{root}/run/host/container-manager"

    cmdline += ["sh", "-c", f"{chmod} && {container} && exec $0 \"$@\""]

    return cmdline


def chroot_cmd(root: Path, *, resolve: bool = False, options: Sequence[PathString] = ()) -> list[PathString]:
    cmdline: list[PathString] = [
        "sh", "-c",
        # No exec here because we need to clean up the /work directory afterwards.
        f"trap 'rm -rf {root / 'work'}' EXIT && mkdir -p {root / 'work'} && chown 777 {root / 'work'} && $0 \"$@\"",
        "bwrap",
        "--dev-bind", root, "/",
        "--setenv", "container", "mkosi",
        "--setenv", "HOME", "/",
        "--setenv", "PATH", "/work/scripts:/usr/bin:/usr/sbin",
    ]

    if resolve:
        p = Path("etc/resolv.conf")
        if (root / p).is_symlink():
            # For each component in the target path, bubblewrap will try to create it if it doesn't exist
            # yet. If a component in the path is a dangling symlink, bubblewrap will end up calling
            # mkdir(symlink) which obviously fails if multiple components of the dangling symlink path don't
            # exist yet. As a workaround, we resolve the symlink ourselves so that bubblewrap will correctly
            # create all missing components in the target path.
            p = p.parent / (root / p).readlink()

        cmdline += ["--ro-bind", "/etc/resolv.conf", Path("/") / p]

    cmdline += [*options]

    if setpgid := find_binary("setpgid", root=root):
        cmdline += [setpgid, "--foreground", "--"]

    return apivfs_cmd(root) + cmdline
