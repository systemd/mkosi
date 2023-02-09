import ctypes
import ctypes.util
import multiprocessing
import os
import pwd
import shlex
import shutil
import signal
import subprocess
import sys
import traceback
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Mapping, Optional, Sequence, Type, TypeVar

from mkosi.backend import MkosiState
from mkosi.log import ARG_DEBUG, MkosiPrinter, die
from mkosi.types import (
    _FILE,
    CommandArgument,
    CommandLine,
    CompletedProcess,
    PathString,
    Popen,
)

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000

SUBRANGE = 65536

T = TypeVar("T")


def unshare(flags: int) -> None:
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        die("Could not find libc")
    libc = ctypes.CDLL(libc_name, use_errno=True)

    if libc.unshare(ctypes.c_int(flags)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def read_subrange(path: Path) -> int:
    uid = str(os.getuid())
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = None

    for line in path.read_text().splitlines():
        name, start, count = line.split(":")

        if name == uid or name == user:
            break
    else:
        die(f"No mapping found for {user or uid} in {path}")

    if int(count) < SUBRANGE:
        die(f"subuid/subgid range length must be at least {SUBRANGE}, got {count} for {user or uid} from line '{line}'")

    return int(start)


def become_root() -> tuple[int, int]:
    """
    Set up a new user namespace mapping using /etc/subuid and /etc/subgid.

    The current user will be mapped to root and 65436 will be mapped to the UID/GID of the invoking user.
    The other IDs will be mapped through.

    The function returns the UID-GID pair of the invoking user in the namespace (65436, 65436).
    """
    subuid = read_subrange(Path("/etc/subuid"))
    subgid = read_subrange(Path("/etc/subgid"))

    event = multiprocessing.Event()
    pid = os.getpid()

    child = os.fork()
    if child == 0:
        event.wait()

        # We map the private UID range configured in /etc/subuid and /etc/subgid into the container using
        # newuidmap and newgidmap. On top of that, we also make sure to map in the user running mkosi so that
        # we can run still chown stuff to that user or run stuff as that user which will make sure any
        # generated files are owned by that user. We don't map to the last user in the range as the last user
        # is sometimes used in tests as a default value and mapping to that user might break those tests.
        newuidmap = [
            "newuidmap", pid,
            0, subuid, SUBRANGE - 100,
            SUBRANGE - 100, os.getuid(), 1,
            SUBRANGE - 100 + 1, subuid + SUBRANGE - 100 + 1, 99
        ]
        run([str(x) for x in newuidmap])

        newgidmap = [
            "newgidmap", pid,
            0, subgid, SUBRANGE - 100,
            SUBRANGE - 100, os.getgid(), 1,
            SUBRANGE - 100 + 1, subgid + SUBRANGE - 100 + 1, 99
        ]
        run([str(x) for x in newgidmap])

        sys.stdout.flush()
        sys.stderr.flush()

        os._exit(0)

    unshare(CLONE_NEWUSER)
    event.set()
    os.waitpid(child, 0)

    # By default, we're root in the user namespace because if we were our current user by default, we
    # wouldn't be able to chown stuff to be owned by root while the reverse is possible.
    os.setresuid(0, 0, 0)
    os.setresgid(0, 0, 0)
    os.setgroups([0])

    return SUBRANGE - 100, SUBRANGE - 100


def init_mount_namespace() -> None:
    unshare(CLONE_NEWNS)
    run(["mount", "--make-rslave", "/"])


def foreground() -> None:
    """
    If we're connected to a terminal, put the process in a new process group and make that the foreground
    process group so that only this process receives SIGINT.
    """
    if sys.stdin.isatty():
        os.setpgrp()
        old = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        os.tcsetpgrp(0, os.getpgrp())
        signal.signal(signal.SIGTTOU, old)


class RemoteException(Exception):
    """
    Stores the exception from a subprocess along with its traceback. We have to do this explicitly because
    the original traceback object cannot be pickled. When stringified, produces the subprocess stacktrace
    plus the exception message.
    """
    def __init__(self, e: BaseException, tb: traceback.StackSummary):
        self.exception = e
        self.tb = tb

    def __str__(self) -> str:
        return f"Traceback (most recent call last):\n{''.join(self.tb.format()).strip()}\n{type(self.exception).__name__}: {self.exception}"


def excepthook(exctype: Type[BaseException], exc: BaseException, tb: Optional[TracebackType]) -> None:
    """Attach to sys.excepthook to automically format exceptions with a RemoteException attached correctly."""
    if isinstance(exc.__cause__, RemoteException):
        print(exc.__cause__, file=sys.stderr)
    else:
        sys.__excepthook__(exctype, exc, tb)


def fork_and_wait(target: Callable[[], T]) -> T:
    """Run the target function in the foreground in a child process and collect its backtrace if there is one."""
    pout, pin = multiprocessing.Pipe(duplex=False)

    pid = os.fork()
    if pid == 0:
        foreground()

        try:
            result = target()
        except BaseException as e:
            # Just getting the stacktrace from the traceback doesn't get us the parent frames for some reason
            # so we have to attach those manually.
            tb = traceback.StackSummary.from_list(traceback.extract_stack()[:-1] + traceback.extract_tb(e.__traceback__))
            pin.send(RemoteException(e, tb))
        else:
            pin.send(result)
        finally:
            pin.close()

        sys.stdout.flush()
        sys.stderr.flush()

        os._exit(0)

    os.waitpid(pid, 0)
    result = pout.recv()
    if isinstance(result, RemoteException):
        # Reraise the original exception and attach the remote exception with full traceback as the cause.
        raise result.exception from result

    return result


def _stringify(x: CommandArgument) -> str:
    """Stringify pathlike objects via their protocol and everything else via str()."""
    # os.fspath(foo) can actually be bytes if foo.__fspath__ returns bytes (or
    # whatever else it might return), but in our case all paths are instantiated
    # from strings and will thus return strings.
    # No cast is needed because mypy enforced the result will be string
    # through CommandArgument.
    return os.fspath(x) if isinstance(x, os.PathLike) else str(x)


def run(
    cmdline: CommandLine,
    check: bool = True,
    stdout: _FILE = None,
    stderr: _FILE = None,
    env: Mapping[str, PathString] = {},
    **kwargs: Any,
) -> CompletedProcess:
    cmd = [_stringify(x) for x in cmdline]

    if "run" in ARG_DEBUG:
        MkosiPrinter.info(f"+ {shlex.join(cmd)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    env = dict(
        PATH=os.environ["PATH"],
        TERM=os.getenv("TERM", "vt220"),
        LANG="C.UTF-8",
    ) | env

    if env["PATH"] == "":
        del env["PATH"]

    try:
        return subprocess.run(cmd, check=check, stdout=stdout, stderr=stderr, env=env, **kwargs,
                              preexec_fn=foreground)
    except FileNotFoundError:
        die(f"{cmd[0]} not found in PATH.")


def spawn(
    cmdline: CommandLine,
    stdout: _FILE = None,
    stderr: _FILE = None,
    **kwargs: Any,
) -> Popen:
    if "run" in ARG_DEBUG:
        MkosiPrinter.info(f"+ {shlex.join(str(s) for s in cmdline)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    try:
        cmd = [_stringify(x) for x in cmdline]
        return subprocess.Popen(cmd, stdout=stdout, stderr=stderr, **kwargs, preexec_fn=foreground)
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")


def run_with_apivfs(
    state: MkosiState,
    cmd: Sequence[PathString],
    bwrap_params: Sequence[PathString] = tuple(),
    stdout: _FILE = None,
    env: Mapping[str, PathString] = {},
) -> CompletedProcess:
    cmdline: list[PathString] = [
        "bwrap",
        # Required to make chroot detection via /proc/1/root work properly.
        "--unshare-pid",
        "--dev-bind", "/", "/",
        "--tmpfs", state.root / "run",
        "--tmpfs", state.root / "tmp",
        "--proc", state.root / "proc",
        "--dev", state.root / "dev",
        "--ro-bind", "/sys", state.root / "sys",
        "--bind", state.var_tmp, state.root / "var/tmp",
        *bwrap_params,
        "sh", "-c",
    ]

    env = env | state.environment

    template = f"chmod 1777 {state.root / 'tmp'} {state.root / 'var/tmp'} {state.root / 'dev/shm'} && exec {{}} || exit $?"

    try:
        return run([*cmdline, template.format(shlex.join(str(s) for s in cmd))],
                   text=True, stdout=stdout, env=env)
    except subprocess.CalledProcessError as e:
        if "run" in ARG_DEBUG:
            run([*cmdline, template.format("sh")], check=False, env=env)
        die(f"\"{shlex.join(str(s) for s in cmd)}\" returned non-zero exit code {e.returncode}.")


def run_workspace_command(
    state: MkosiState,
    cmd: Sequence[PathString],
    bwrap_params: Sequence[PathString] = tuple(),
    network: bool = False,
    stdout: _FILE = None,
    env: Mapping[str, PathString] = {},
) -> CompletedProcess:
    cmdline: list[PathString] = [
        "bwrap",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-cgroup",
        "--bind", state.root, "/",
        "--tmpfs", "/run",
        "--tmpfs", "/tmp",
        "--dev", "/dev",
        "--proc", "/proc",
        "--ro-bind", "/sys", "/sys",
        "--bind", state.var_tmp, "/var/tmp",
        *bwrap_params,
    ]

    resolve = state.root.joinpath("etc/resolv.conf")

    if network:
        # Bubblewrap does not mount over symlinks and /etc/resolv.conf might be a symlink. Deal with this by
        # temporarily moving the file somewhere else.
        if resolve.is_symlink():
            shutil.move(resolve, state.workspace / "resolv.conf")

        # If we're using the host network namespace, use the same resolver
        cmdline += ["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]
    else:
        cmdline += ["--unshare-net"]

    cmdline += ["sh", "-c"]

    env = dict(
        container="mkosi",
        SYSTEMD_OFFLINE=str(int(network)),
        HOME="/",
        # Make sure the default PATH of the distro shell is used.
        PATH="",
    ) | env | state.environment

    template = "chmod 1777 /tmp /var/tmp /dev/shm && PATH=$PATH:/usr/bin:/usr/sbin exec {} || exit $?"

    try:
        return run([*cmdline, template.format(shlex.join(str(s) for s in cmd))],
                   text=True, stdout=stdout, env=env)
    except subprocess.CalledProcessError as e:
        if "run" in ARG_DEBUG:
            run([*cmdline, template.format("sh")], check=False, env=env)
        die(f"\"{shlex.join(str(s) for s in cmd)}\" returned non-zero exit code {e.returncode}.")
    finally:
        if state.workspace.joinpath("resolv.conf").is_symlink():
            shutil.move(state.workspace.joinpath("resolv.conf"), resolve)
