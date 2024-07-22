# SPDX-License-Identifier: LGPL-2.1-or-later
import contextlib
import dataclasses
import enum
import logging
import os
import shutil
import uuid
from collections.abc import Iterator, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Optional, Protocol

from mkosi.types import PathString
from mkosi.user import INVOKING_USER
from mkosi.util import flatten, one_zero, startswith


@dataclasses.dataclass(frozen=True)
class Mount:
    src: PathString
    dst: PathString
    devices: bool = False
    ro: bool = False
    required: bool = True

    def __hash__(self) -> int:
        return hash((Path(self.src), Path(self.dst), self.devices, self.ro, self.required))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mount):
            return False

        return self.__hash__() == other.__hash__()

    def options(self) -> list[str]:
        if self.devices:
            opt = "--dev-bind" if self.required else "--dev-bind-try"
        elif self.ro:
            opt = "--ro-bind" if self.required else "--ro-bind-try"
        else:
            opt = "--bind" if self.required else "--bind-try"

        return [opt, os.fspath(self.src), os.fspath(self.dst)]


class SandboxProtocol(Protocol):
    def __call__(
        self,
        *,
        binary: Optional[PathString],
        vartmp: bool = False,
        mounts: Sequence[Mount] = (),
        extra: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]: ...


def nosandbox(
    *,
    binary: Optional[PathString],
    vartmp: bool = False,
    mounts: Sequence[Mount] = (),
    extra: Sequence[PathString] = (),
) -> AbstractContextManager[list[PathString]]:
    return contextlib.nullcontext([])


# https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h
class Capability(enum.Enum):
    CAP_NET_ADMIN = 12


def have_effective_cap(capability: Capability) -> bool:
    for line in Path("/proc/self/status").read_text().splitlines():
        if rhs := startswith(line, "CapEff:"):
            hexcap = rhs.strip()
            break
    else:
        logging.warning(f"\"CapEff:\" not found in /proc/self/status, assuming we don't have {capability}")
        return False

    return (int(hexcap, 16) & (1 << capability.value)) != 0


def finalize_passwd_mounts(root: PathString) -> list[Mount]:
    """
    If passwd or a related file exists in the apivfs directory, bind mount it over the host files while we
    run the command, to make sure that the command we run uses user/group information from the apivfs
    directory instead of from the host.
    """
    return [
        Mount(Path(root) / "etc" / f, f"/etc/{f}", ro=True, required=False)
        for f in ("passwd", "group", "shadow", "gshadow")
    ]


def finalize_mounts(mounts: Sequence[Mount]) -> list[PathString]:
    mounts = list(set(mounts))

    mounts = [
        m for m in mounts
        if not any(
            m != n and
            m.devices == n.devices and
            m.ro == n.ro and
            m.required == n.required and
            Path(m.src).is_relative_to(n.src) and
            Path(m.dst).is_relative_to(n.dst) and
            Path(m.src).relative_to(n.src) == Path(m.dst).relative_to(n.dst)
            for n in mounts
        )
    ]

    mounts = sorted(mounts, key=lambda m: (Path(m.dst), m.devices, not m.ro, m.required, Path(m.src)))

    return flatten(m.options() for m in mounts)


@contextlib.contextmanager
def sandbox_cmd(
    *,
    network: bool = False,
    devices: bool = False,
    vartmp: bool = False,
    scripts: Optional[Path] = None,
    tools: Path = Path("/"),
    relaxed: bool = False,
    mounts: Sequence[Mount] = (),
    options: Sequence[PathString] = (),
    setup: Sequence[PathString] = (),
    extra: Sequence[PathString] = (),
) -> Iterator[list[PathString]]:
    cmdline: list[PathString] = []
    mounts = list(mounts)

    if vartmp and not relaxed:
        # We want to use an empty subdirectory in the host's temporary directory as the sandbox's /var/tmp.
        vartmpdir = Path(os.getenv("TMPDIR", "/var/tmp")) / f"mkosi-var-tmp-{uuid.uuid4().hex[:16]}"
    else:
        vartmpdir = None

    cmdline += [
        *setup,
        "bwrap",
        *(
            ["--unshare-net"]
            if not network and (os.getuid() != 0 or have_effective_cap(Capability.CAP_NET_ADMIN))
            else []
        ),
        "--die-with-parent",
        "--proc", "/proc",
        "--setenv", "SYSTEMD_OFFLINE", one_zero(network),
        # We mounted a subdirectory of TMPDIR to /var/tmp so we unset TMPDIR so that /tmp or /var/tmp are used instead.
        "--unsetenv", "TMPDIR",
    ]
    mounts += [Mount(tools / "usr", "/usr", ro=True)]

    if relaxed:
        mounts += [Mount("/tmp", "/tmp")]
    else:
        cmdline += ["--dir", "/tmp", "--dir", "/var/tmp", "--unshare-ipc"]

    if (tools / "nix/store").exists():
        mounts += [Mount(tools / "nix/store", "/nix/store")]

    if devices or relaxed:
        mounts += [
            Mount("/sys", "/sys"),
            Mount("/run", "/run"),
            Mount("/dev", "/dev", devices=True),
        ]
    else:
        cmdline += ["--dev", "/dev"]

    if relaxed:
        dirs = ("/etc", "/opt", "/srv", "/media", "/mnt", "/var", os.fspath(INVOKING_USER.home()))

        for d in dirs:
            if Path(d).exists():
                mounts += [Mount(d, d)]

        if len(Path.cwd().parents) >= 2:
            # `Path.parents` only supports slices and negative indexing from Python 3.10 onwards.
            # TODO: Remove list() when we depend on Python 3.10 or newer.
            d = os.fspath(list(Path.cwd().parents)[-2])
        elif len(Path.cwd().parents) == 1:
            d = os.fspath(Path.cwd())
        else:
            d = ""

        if d and d not in (*dirs, "/home", "/usr", "/nix", "/tmp"):
            mounts += [Mount(d, d)]

    if vartmpdir:
        mounts += [Mount(vartmpdir, "/var/tmp")]

    for d in ("bin", "sbin", "lib", "lib32", "lib64"):
        if (p := tools / d).is_symlink():
            cmdline += ["--symlink", p.readlink(), Path("/") / p.relative_to(tools)]
        elif p.is_dir():
            mounts += [Mount(p, Path("/") / p.relative_to(tools), ro=True)]

    path = "/usr/bin:/usr/sbin" if tools != Path("/") else os.environ["PATH"]

    cmdline += ["--setenv", "PATH", f"/scripts:{path}", *options]

    # If we're using /usr from a tools tree, we have to use /etc/alternatives from the tools tree as well if it
    # exists since that points directly back to /usr. Apply this after the options so the caller can mount
    # something else to /etc without overriding this mount. In relaxed mode, we only do this if /etc/alternatives
    # already exists on the host as otherwise we'd modify the host's /etc by creating the mountpoint ourselves (or
    # fail when trying to create it).
    if (tools / "etc/alternatives").exists() and (not relaxed or Path("/etc/alternatives").exists()):
        mounts += [Mount(tools / "etc/alternatives", "/etc/alternatives", ro=True)]

    if scripts:
        mounts += [Mount(scripts, "/scripts", ro=True)]

    if network and not relaxed and Path("/etc/resolv.conf").exists():
        mounts += [Mount("/etc/resolv.conf", "/etc/resolv.conf")]

    cmdline += finalize_mounts(mounts)

    if not any(Path(m.dst) == Path("/etc") for m in mounts):
        cmdline += ["--symlink", "../proc/self/mounts", "/etc/mtab"]

    # bubblewrap creates everything with a restricted mode so relax stuff as needed.
    ops = []
    if not relaxed:
        ops += ["chmod 1777 /tmp"]
        if not devices:
            ops += ["chmod 1777 /dev/shm"]
    if vartmpdir:
        ops += ["chmod 1777 /var/tmp"]
    if relaxed and INVOKING_USER.home().exists() and len(INVOKING_USER.home().parents) > 1:
        # We might mount a subdirectory of /home so /home will be created with the wrong permissions by bubblewrap so
        # we need to fix up the permissions.
        ops += [f"chmod 755 {list(INVOKING_USER.home().parents)[-1]}"]
    else:
        ops += ["chmod 755 /etc"]
    ops += ["exec $0 \"$@\""]

    cmdline += ["sh", "-c", " && ".join(ops), *extra]

    if vartmpdir:
        vartmpdir.mkdir(mode=0o1777)

    try:
        yield cmdline
    finally:
        if vartmpdir:
            shutil.rmtree(vartmpdir)


def apivfs_cmd() -> list[PathString]:
    return [
        "bwrap",
        "--dev-bind", "/", "/",
        "--tmpfs", "/buildroot/run",
        "--tmpfs", "/buildroot/tmp",
        "--bind", "/var/tmp", "/buildroot/var/tmp",
        "--proc", "/buildroot/proc",
        "--dev", "/buildroot/dev",
        # Make sure /etc/machine-id is not overwritten by any package manager post install scripts.
        "--ro-bind-try", "/buildroot/etc/machine-id", "/buildroot/etc/machine-id",
        # Nudge gpg to create its sockets in /run by making sure /run/user/0 exists.
        "--dir", "/buildroot/run/user/0",
        *flatten(mount.options() for mount in finalize_passwd_mounts("/buildroot")),
        "sh", "-c",
        " && ".join(
            [
                "chmod 1777 /buildroot/tmp /buildroot/var/tmp /buildroot/dev/shm",
                "chmod 755 /buildroot/run",
                # Make sure anything running in the root directory thinks it's in a container. $container can't always
                # be accessed so we write /run/host/container-manager as well which is always accessible.
                "mkdir -m 755 /buildroot/run/host",
                "echo mkosi >/buildroot/run/host/container-manager",
                "exec $0 \"$@\"",
            ]
        ),
    ]


def chroot_cmd(*, resolve: bool = False, work: bool = False) -> list[PathString]:
    workdir = "/buildroot/work" if work else ""

    return apivfs_cmd() + [
        "sh", "-c",
        " && ".join(
            [
                *([f"trap 'rm -rf {workdir}' EXIT"] if work else []),
                # /etc/resolv.conf can be a dangling symlink to /run/systemd/resolve/stub-resolv.conf. Bubblewrap tries
                # to call mkdir() on each component of the path which means it will try to call
                # mkdir(/run/systemd/resolve/stub-resolv.conf) which will fail unless /run/systemd/resolve exists
                # already so we make sure that it already exists.
                f"mkdir -p -m 755 {workdir} /buildroot/run/systemd /buildroot/run/systemd/resolve",
                # No exec here because we need to clean up the /work directory afterwards.
                "$0 \"$@\"",
            ]
        ),
        "bwrap",
        "--dev-bind", "/buildroot", "/",
        "--setenv", "container", "mkosi",
        "--setenv", "HOME", "/",
        "--setenv", "PATH", "/work/scripts:/usr/bin:/usr/sbin",
        *(["--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"] if resolve else []),
        *(["--bind", "/work", "/work", "--chdir", "/work/src"] if work else []),
        "--setenv", "BUILDROOT", "/",
        # Start an interactive bash shell if we're not given any arguments.
        "sh", "-c", '[ "$0" = "sh" ] && [ $# -eq 0 ] && exec bash -i || exec $0 "$@"',
    ]

