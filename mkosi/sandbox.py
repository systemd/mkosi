# SPDX-License-Identifier: LGPL-2.1+
import enum
import logging
import os
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Optional, Protocol

from mkosi.types import PathString
from mkosi.user import INVOKING_USER
from mkosi.util import flatten, one_zero


class SandboxProtocol(Protocol):
    def __call__(self, *, options: Sequence[PathString]) -> list[PathString]: ...


def nosandbox(*, options: Sequence[PathString]) -> list[PathString]:
    return []


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


def finalize_passwd_mounts(root: Path) -> list[PathString]:
    """
    If passwd or a related file exists in the apivfs directory, bind mount it over the host files while we
    run the command, to make sure that the command we run uses user/group information from the apivfs
    directory instead of from the host.
    """
    options: list[PathString] = []

    for f in ("passwd", "group", "shadow", "gshadow"):
        options += ["--ro-bind-try", root / "etc" / f, f"/etc/{f}"]

    return options


def finalize_crypto_mounts(tools: Path = Path("/")) -> list[PathString]:
    mounts = [
        (tools / subdir, Path("/") / subdir)
        for subdir in (
            Path("etc/pki"),
            Path("etc/ssl"),
            Path("etc/crypto-policies"),
            Path("etc/ca-certificates"),
            Path("etc/pacman.d/gnupg"),
            Path("var/lib/ca-certificates"),
        )
        if (tools / subdir).exists()
    ]

    return flatten(
        ["--ro-bind", src, target]
        for src, target
        in sorted(set(mounts), key=lambda s: s[1])
    )


def sandbox_cmd(
    *,
    network: bool = False,
    devices: bool = False,
    scripts: Optional[Path] = None,
    tools: Path = Path("/"),
    relaxed: bool = False,
    options: Sequence[PathString] = (),
) -> list[PathString]:
    cmdline: list[PathString] = []

    if not relaxed:
        # We want to use an empty subdirectory in the host's temporary directory as the sandbox's /var/tmp. To make
        # sure it only gets created when we run the sandboxed command and cleaned up when the sandboxed command exits,
        # we create it using shell.
        vartmp = Path(os.getenv("TMPDIR", "/var/tmp")) / f"mkosi-var-tmp-{uuid.uuid4().hex[:16]}"
        cmdline += ["sh", "-c", f"trap 'rm -rf {vartmp}' EXIT && mkdir --mode 1777 {vartmp} && $0 \"$@\""]
    else:
        vartmp = None

    cmdline += [
        "bwrap",
        "--ro-bind", tools / "usr", "/usr",
        *(["--unshare-net"] if not network and have_effective_cap(Capability.CAP_NET_ADMIN) else []),
        "--die-with-parent",
        "--proc", "/proc",
        "--setenv", "SYSTEMD_OFFLINE", one_zero(network),
        # We mounted a subdirectory of TMPDIR to /var/tmp so we unset TMPDIR so that /tmp or /var/tmp are used instead.
        "--unsetenv", "TMPDIR",
    ]

    if relaxed:
        cmdline += ["--bind", "/tmp", "/tmp"]
    else:
        cmdline += [
            "--tmpfs", "/tmp",
            "--unshare-ipc",
        ]

    if (tools / "nix/store").exists():
        cmdline += ["--bind", tools / "nix/store", "/nix/store"]

    if devices or relaxed:
        cmdline += [
            "--bind", "/sys", "/sys",
            "--bind", "/run", "/run",
            "--dev-bind", "/dev", "/dev",
        ]
    else:
        cmdline += ["--dev", "/dev"]

    if relaxed:
        dirs = ("/etc", "/opt", "/srv", "/media", "/mnt", "/var", os.fspath(INVOKING_USER.home()))

        for d in dirs:
            if Path(d).exists():
                cmdline += ["--bind", d, d]

        if len(Path.cwd().parents) >= 2:
            # `Path.parents` only supports slices and negative indexing from Python 3.10 onwards.
            # TODO: Remove list() when we depend on Python 3.10 or newer.
            d = os.fspath(list(Path.cwd().parents)[-2])
        elif len(Path.cwd().parents) == 1:
            d = os.fspath(Path.cwd())
        else:
            d = ""

        if d and d not in (*dirs, "/home", "/usr", "/nix", "/tmp"):
            cmdline += ["--bind", d, d]

    if vartmp:
        cmdline += ["--bind", vartmp, "/var/tmp"]

    for d in ("bin", "sbin", "lib", "lib32", "lib64"):
        if (p := tools / d).is_symlink():
            cmdline += ["--symlink", p.readlink(), Path("/") / p.relative_to(tools)]
        elif p.is_dir():
            cmdline += ["--ro-bind", p, Path("/") / p.relative_to(tools)]

    path = "/usr/bin:/usr/sbin" if tools != Path("/") else os.environ["PATH"]

    cmdline += [
        "--setenv", "PATH", f"{scripts or ''}:{path}",
        *options,
    ]

    if not relaxed:
        cmdline += ["--symlink", "../proc/self/mounts", "/etc/mtab"]

    # If we're using /usr from a tools tree, we have to use /etc/alternatives from the tools tree as well if it
    # exists since that points directly back to /usr. Apply this after the options so the caller can mount
    # something else to /etc without overriding this mount. In relaxed mode, we only do this if /etc/alternatives
    # already exists on the host as otherwise we'd modify the host's /etc by creating the mountpoint ourselves (or
    # fail when trying to create it).
    if (tools / "etc/alternatives").exists() and (not relaxed or Path("/etc/alternatives").exists()):
        cmdline += ["--ro-bind", tools / "etc/alternatives", "/etc/alternatives"]

    if scripts:
        cmdline += ["--ro-bind", scripts, scripts]

    if network and not relaxed:
        cmdline += ["--bind", "/etc/resolv.conf", "/etc/resolv.conf"]

    # bubblewrap creates everything with a restricted mode so relax stuff as needed.
    ops = []
    if not devices:
        ops += ["chmod 1777 /dev/shm"]
    if not relaxed:
        ops += ["chmod 755 /etc"]
    ops += ["exec $0 \"$@\""]

    cmdline += ["sh", "-c", " && ".join(ops)]

    return cmdline


def apivfs_cmd(root: Path) -> list[PathString]:
    return [
        "bwrap",
        "--dev-bind", "/", "/",
        "--tmpfs", root / "run",
        "--tmpfs", root / "tmp",
        "--bind", "/var/tmp", root / "var/tmp",
        "--proc", root / "proc",
        "--dev", root / "dev",
        # Make sure /etc/machine-id is not overwritten by any package manager post install scripts.
        "--ro-bind-try", root / "etc/machine-id", root / "etc/machine-id",
        *finalize_passwd_mounts(root),
        "sh", "-c",
        f"chmod 1777 {root / 'tmp'} {root / 'var/tmp'} {root / 'dev/shm'} && "
        f"chmod 755 {root / 'run'} && "
        # Make sure anything running in the root directory thinks it's in a container. $container can't always be
        # accessed so we write /run/host/container-manager as well which is always accessible.
        f"mkdir -m 755 {root}/run/host && echo mkosi >{root}/run/host/container-manager && "
        "exec $0 \"$@\"",
    ]


def chroot_cmd(root: Path, *, resolve: bool = False, options: Sequence[PathString] = ()) -> list[PathString]:
    cmdline: list[PathString] = [
        "sh", "-c",
        f"trap 'rm -rf {root / 'work'}' EXIT && "
        # /etc/resolv.conf can be a dangling symlink to /run/systemd/resolve/stub-resolv.conf. Bubblewrap tries to call
        # mkdir() on each component of the path which means it will try to call
        # mkdir(/run/systemd/resolve/stub-resolv.conf) which will fail unless /run/systemd/resolve exists already so
        # we make sure that it already exists.
        f"mkdir -p -m 755 {root / 'work'} {root / 'run/systemd'} {root / 'run/systemd/resolve'} && "
        # No exec here because we need to clean up the /work directory afterwards.
        f"$0 \"$@\"",
        "bwrap",
        "--dev-bind", root, "/",
        "--setenv", "container", "mkosi",
        "--setenv", "HOME", "/",
        "--setenv", "PATH", "/work/scripts:/usr/bin:/usr/sbin",
    ]

    if resolve:
        cmdline += ["--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"]

    cmdline += options

    return apivfs_cmd(root) + cmdline
