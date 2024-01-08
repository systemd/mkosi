# SPDX-License-Identifier: LGPL-2.1+
import enum
import logging
import os
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from mkosi.run import find_binary
from mkosi.types import PathString
from mkosi.util import INVOKING_USER, flatten, one_zero


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
    directory instead of from the host. If the file doesn't exist yet, mount over /dev/null instead.
    """
    options: list[PathString] = []

    for f in ("passwd", "group", "shadow", "gshadow"):
        if not (Path("/etc") / f).exists():
            continue
        p = root / "etc" / f
        if p.exists():
            options += ["--bind", p, f"/etc/{f}"]
        else:
            options += ["--bind", "/dev/null", f"/etc/{f}"]

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
        # We want to use an empty subdirectory in the host's /var/tmp as the sandbox's /var/tmp. To make sure it only
        # gets created when we run the sandboxed command and cleaned up when the sandboxed command exits, we create it
        # using shell.
        vartmp = f"/var/tmp/mkosi-var-tmp-{uuid.uuid4().hex[:16]}"
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
    ]

    if relaxed:
        cmdline += ["--bind", "/tmp", "/tmp"]
    else:
        cmdline += ["--tmpfs", "/tmp"]

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

        # `Path.parents` only supports slices and negative indexing from Python 3.10 onwards.
        # TODO: Remove list() when we depend on Python 3.10 or newer.
        if (d := os.fspath(list(Path.cwd().parents)[-2])) not in (*dirs, "/home", "/usr", "/nix", "/tmp"):
            cmdline += ["--bind", d, d]

    if vartmp:
        cmdline += ["--bind", vartmp, "/var/tmp"]

    for d in ("bin", "sbin", "lib", "lib32", "lib64"):
        if (p := tools / d).is_symlink():
            cmdline += ["--symlink", p.readlink(), Path("/") / p.relative_to(tools)]

    path = "/usr/bin:/usr/sbin" if tools != Path("/") else os.environ["PATH"]

    cmdline += [
        "--setenv", "PATH", f"{scripts or ''}:{path}",
        *options,
    ]

    # If we're using /usr from a tools tree, we have to use /etc/alternatives from the tools tree as well if it
    # exists since that points directly back to /usr. Apply this after the options so the caller can mount
    # something else to /etc without overriding this mount.
    if (tools / "etc/alternatives").exists():
        cmdline += ["--ro-bind", tools / "etc/alternatives", "/etc/alternatives"]

    if scripts:
        cmdline += ["--ro-bind", scripts, scripts]

    if network and not relaxed:
        cmdline += ["--bind", "/etc/resolv.conf", "/etc/resolv.conf"]

    if devices:
        shm = ":"
    else:
        shm = "chmod 1777 /dev/shm"

    cmdline += ["sh", "-c", f"{shm} && exec $0 \"$@\""]

    if setpgid := find_binary("setpgid", root=tools):
        cmdline += [setpgid, "--foreground", "--"]

    return cmdline


def apivfs_cmd(root: Path, *, tools: Path = Path("/")) -> list[PathString]:
    cmdline: list[PathString] = [
        "bwrap",
        "--dev-bind", "/", "/",
        "--tmpfs", root / "run",
        "--tmpfs", root / "tmp",
        "--bind", "/var/tmp", root / "var/tmp",
        "--proc", root / "proc",
        "--dev", root / "dev",
        # APIVFS generally means chrooting is going to happen so unset TMPDIR just to be safe.
        "--unsetenv", "TMPDIR",
    ]

    if (root / "etc/machine-id").exists():
        # Make sure /etc/machine-id is not overwritten by any package manager post install scripts.
        cmdline += ["--ro-bind", root / "etc/machine-id", root / "etc/machine-id"]

    cmdline += finalize_passwd_mounts(root)

    if setpgid := find_binary("setpgid", root=tools):
        cmdline += [setpgid, "--foreground", "--"]

    chmod = f"chmod 1777 {root / 'tmp'} {root / 'var/tmp'} {root / 'dev/shm'}"
    # Make sure anything running in the root directory thinks it's in a container. $container can't always be
    # accessed so we write /run/host/container-manager as well which is always accessible.
    container = f"mkdir {root}/run/host && echo mkosi >{root}/run/host/container-manager"

    cmdline += ["sh", "-c", f"{chmod} && {container} && exec $0 \"$@\""]

    return cmdline


def chroot_cmd(
    root: Path,
    *,
    resolve: bool = False,
    tools: Path = Path("/"),
    options: Sequence[PathString] = (),
) -> list[PathString]:
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

    return apivfs_cmd(root, tools=tools) + cmdline
