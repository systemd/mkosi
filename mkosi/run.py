# SPDX-License-Identifier: LGPL-2.1+

import asyncio
import asyncio.tasks
import contextlib
import ctypes
import ctypes.util
import logging
import multiprocessing
import os
import pwd
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import traceback
from pathlib import Path
from types import TracebackType
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterator,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
)

from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, die
from mkosi.types import _FILE, CompletedProcess, PathString, Popen
from mkosi.util import InvokingUser

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
    if os.getuid() == 0:
        return InvokingUser.uid_gid()

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

    unshare(CLONE_NEWUSER|CLONE_NEWNS)
    event.set()
    os.waitpid(child, 0)

    # By default, we're root in the user namespace because if we were our current user by default, we
    # wouldn't be able to chown stuff to be owned by root while the reverse is possible.
    os.setresuid(0, 0, 0)
    os.setresgid(0, 0, 0)
    os.setgroups([0])

    return SUBRANGE - 100, SUBRANGE - 100


def foreground(*, new_process_group: bool = True) -> None:
    """
    If we're connected to a terminal, put the process in a new process group and make that the foreground
    process group so that only this process receives SIGINT.
    """
    STDERR_FILENO = 2
    if os.isatty(STDERR_FILENO):
        if new_process_group:
            os.setpgrp()
        old = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        os.tcsetpgrp(STDERR_FILENO, os.getpgrp())
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


def ensure_exc_info() -> Tuple[Type[BaseException], BaseException, TracebackType]:
    exctype, exc, tb = sys.exc_info()
    assert exctype
    assert exc
    assert tb
    return (exctype, exc, tb)


def excepthook(exctype: Type[BaseException], exc: BaseException, tb: Optional[TracebackType]) -> None:
    """Attach to sys.excepthook to automatically format exceptions with a RemoteException attached correctly."""
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

    try:
        os.waitpid(pid, 0)
    finally:
        foreground(new_process_group=False)

    result = pout.recv()
    if isinstance(result, RemoteException):
        # Reraise the original exception and attach the remote exception with full traceback as the cause.
        raise result.exception from result

    return result

def run(
    cmdline: Sequence[PathString],
    check: bool = True,
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    input: Optional[str] = None,
    text: bool = True,
    env: Mapping[str, PathString] = {},
    log: bool = True,
) -> CompletedProcess:
    if ARG_DEBUG.get():
        logging.info(f"+ {' '.join(str(s) for s in cmdline)}")

    cmdline = [os.fspath(x) for x in cmdline]

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

    if ARG_DEBUG.get():
        env["SYSTEMD_LOG_LEVEL"] = "debug"

    if input is not None:
        assert stdin is None  # stdin and input cannot be specified together
    elif stdin is None:
        stdin = subprocess.DEVNULL

    try:
        return subprocess.run(
            cmdline,
            check=check,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            input=input,
            text=True,
            env=env,
            preexec_fn=foreground,
        )
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")
    except subprocess.CalledProcessError as e:
        if log:
            logging.error(f"\"{' '.join(str(s) for s in cmdline)}\" returned non-zero exit code {e.returncode}.")
        raise e
    finally:
        foreground(new_process_group=False)


def spawn(
    cmdline: Sequence[PathString],
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    text: bool = True,
) -> Popen:
    if ARG_DEBUG.get():
        logging.info(f"+ {' '.join(str(s) for s in cmdline)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    try:
        return subprocess.Popen(
            cmdline,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            text=text,
            preexec_fn=foreground,
        )
    except FileNotFoundError:
        die(f"{cmdline[0]} not found in PATH.")
    except subprocess.CalledProcessError as e:
        logging.error(f"\"{' '.join(str(s) for s in cmdline)}\" returned non-zero exit code {e.returncode}.")
        raise e


@contextlib.contextmanager
def bwrap_cmd(
    *,
    tools: Optional[Path] = None,
    apivfs: Optional[Path] = None,
) -> Iterator[list[PathString]]:
    cmdline: list[PathString] = [
        "bwrap",
        "--dev-bind", "/", "/",
        "--chdir", Path.cwd(),
        "--die-with-parent",
        "--ro-bind", (tools or Path("/")) / "usr", "/usr",
    ]

    for d in ("/etc", "/opt", "/srv", "/boot", "/efi"):
        if Path(d).exists():
            cmdline += ["--ro-bind", d, d]

    if apivfs:
        if not (apivfs / "etc/machine-id").exists():
            # Uninitialized means we want it to get initialized on first boot.
            (apivfs / "etc/machine-id").write_text("uninitialized\n")
            (apivfs / "etc/machine-id").chmod(0o0444)

        cmdline += [
            "--tmpfs", apivfs / "run",
            "--tmpfs", apivfs / "tmp",
            "--proc", apivfs / "proc",
            "--dev", apivfs / "dev",
            "--ro-bind", "/sys", apivfs / "sys",
        ]

        # If passwd or a related file exists in the apivfs directory, bind mount it over the host files while
        # we run the command, to make sure that the command we run uses user/group information from the
        # apivfs directory instead of from the host. If the file doesn't exist yet, mount over /dev/null
        # instead.
        for f in ("passwd", "group", "shadow", "gshadow"):
            p = apivfs / "etc" / f
            if p.exists():
                cmdline += ["--bind", p, f"/etc/{f}"]
            else:
                cmdline += ["--bind", "/dev/null", f"/etc/{f}"]

    if apivfs:
        chmod = f"chmod 1777 {apivfs / 'tmp'} {apivfs / 'var/tmp'} {apivfs / 'dev/shm'}"
    else:
        chmod = ":"

    with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="mkosi-var-tmp") as var_tmp:
        if apivfs:
            cmdline += [
                "--bind", var_tmp, apivfs / "var/tmp",
                # Make sure /etc/machine-id is not overwritten by any package manager post install scripts.
                "--ro-bind", apivfs / "etc/machine-id", apivfs / "etc/machine-id",
            ]

        cmdline += ["sh", "-c", f"{chmod} && exec $0 \"$@\" || exit $?"]

        try:
            yield cmdline
        finally:
            # Clean up some stuff that might get written by package manager post install scripts.
            if apivfs:
                for f in ("var/lib/systemd/random-seed", "var/lib/systemd/credential.secret", "etc/machine-info"):
                    # Using missing_ok=True still causes an OSError if the mount is read-only even if the
                    # file doesn't exist so do an explicit exists() check first.
                    if (apivfs / f).exists():
                        (apivfs / f).unlink()


def bwrap(
    cmd: Sequence[PathString],
    *,
    tools: Optional[Path] = None,
    apivfs: Optional[Path] = None,
    log: bool = True,
    extra: Sequence[PathString] = (),
    # The following arguments are passed directly to run().
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    input: Optional[str] = None,
    check: bool = True,
    env: Mapping[str, PathString] = {},
) -> CompletedProcess:
    with bwrap_cmd(tools=tools, apivfs=apivfs) as bwrap:
        if tools:
            # If a tools tree is specified, we should ignore any local modifications made to PATH as any of
            # those binaries might not work anymore when /usr is replaced wholesale. We also make sure that
            # both /usr/bin and /usr/sbin/ are searched so that e.g. if the host is Arch and the root is
            # Debian we don't ignore the binaries from /usr/sbin in the Debian root.
            env = dict(PATH="/usr/bin:/usr/sbin") | env

        try:
            result = run(
                [*bwrap, *extra, *cmd],
                text=True,
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
                logging.error(f"\"{' '.join(str(s) for s in cmd)}\" returned non-zero exit code {e.returncode}.")
            if ARG_DEBUG_SHELL.get():
                run(
                    [*bwrap, *extra, "sh"],
                    stdin=sys.stdin,
                    check=False,
                    env=env,
                    log=False,
                )
            raise e

        return result


def chroot_cmd(root: Path, *, options: Sequence[PathString] = (), network: bool = False) -> Sequence[PathString]:
    cmdline: list[PathString] = [
        "bwrap",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-cgroup",
        "--dev-bind", root, "/",
        "--die-with-parent",
        "--setenv", "container", "mkosi",
        "--setenv", "SYSTEMD_OFFLINE", str(int(network)),
        "--setenv", "HOME", "/",
        "--setenv", "PATH", "/usr/bin:/usr/sbin",
        *options,
    ]

    if network:
        resolve = Path("etc/resolv.conf")
        if (root / resolve).is_symlink():
            # For each component in the target path, bubblewrap will try to create it if it doesn't exist
            # yet. If a component in the path is a dangling symlink, bubblewrap will end up calling
            # mkdir(symlink) which obviously fails if multiple components of the dangling symlink path don't
            # exist yet. As a workaround, we resolve the symlink ourselves so that bubblewrap will correctly
            # create all missing components in the target path.
            resolve = (root / resolve).readlink()

        # If we're using the host network namespace, use the same resolver.
        cmdline += ["--ro-bind", "/etc/resolv.conf", Path("/") / resolve]
    else:
        cmdline += ["--unshare-net"]

    return cmdline


class MkosiAsyncioThread(threading.Thread):
    """
    The default threading.Thread() is not interruptable, so we make our own version by using the concurrency
    feature in python that is interruptable, namely asyncio.

    Additionally, we store any exception that the coroutine raises and re-raise it in join() if no other
    exception was raised before.
    """

    def __init__(self, target: Awaitable[Any], *args: Any, **kwargs: Any) -> None:
        self.target = target
        self.loop: queue.SimpleQueue[asyncio.AbstractEventLoop] = queue.SimpleQueue()
        self.exc: queue.SimpleQueue[BaseException] = queue.SimpleQueue()
        super().__init__(*args, **kwargs)

    def run(self) -> None:
        async def wrapper() -> None:
            self.loop.put(asyncio.get_running_loop())
            await self.target

        try:
            asyncio.run(wrapper())
        except asyncio.CancelledError:
            pass
        except BaseException as e:
            self.exc.put(e)

    def cancel(self) -> None:
        loop = self.loop.get()

        for task in asyncio.tasks.all_tasks(loop):
            loop.call_soon_threadsafe(task.cancel)

    def __enter__(self) -> "MkosiAsyncioThread":
        self.start()
        return self

    def __exit__(
        self,
        type: Optional[Type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.cancel()
        self.join()

        if type is None:
            try:
                raise self.exc.get_nowait()
            except queue.Empty:
                pass
