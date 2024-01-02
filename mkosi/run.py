# SPDX-License-Identifier: LGPL-2.1+

import asyncio
import asyncio.tasks
import contextlib
import ctypes
import ctypes.util
import errno
import fcntl
import logging
import os
import pwd
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import threading
from collections.abc import Awaitable, Collection, Iterator, Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, NoReturn, Optional

from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, die
from mkosi.types import _FILE, CompletedProcess, PathString, Popen
from mkosi.util import INVOKING_USER, flock

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000

SUBRANGE = 65536


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
        die(
            f"subuid/subgid range length must be at least {SUBRANGE}, "
            f"got {count} for {user or uid} from line '{line}'"
        )

    return int(start)


def become_root() -> None:
    """
    Set up a new user namespace mapping using /etc/subuid and /etc/subgid.

    The current user will be mapped to root and 65436 will be mapped to the UID/GID of the invoking user.
    The other IDs will be mapped through.

    The function modifies the uid, gid of the INVOKING_USER object to the uid, gid of the invoking user in the user
    namespace.
    """
    if os.getuid() == 0:
        return

    subuid = read_subrange(Path("/etc/subuid"))
    subgid = read_subrange(Path("/etc/subgid"))

    pid = os.getpid()

    # We map the private UID range configured in /etc/subuid and /etc/subgid into the container using
    # newuidmap and newgidmap. On top of that, we also make sure to map in the user running mkosi so that
    # we can run still chown stuff to that user or run stuff as that user which will make sure any
    # generated files are owned by that user. We don't map to the last user in the range as the last user
    # is sometimes used in tests as a default value and mapping to that user might break those tests.
    newuidmap = [
        "flock", "--exclusive", "--no-fork", "/etc/subuid", "newuidmap", pid,
        0, subuid, SUBRANGE - 100,
        SUBRANGE - 100, os.getuid(), 1,
        SUBRANGE - 100 + 1, subuid + SUBRANGE - 100 + 1, 99
    ]

    newgidmap = [
        "flock", "--exclusive", "--no-fork", "/etc/subuid", "newgidmap", pid,
        0, subgid, SUBRANGE - 100,
        SUBRANGE - 100, os.getgid(), 1,
        SUBRANGE - 100 + 1, subgid + SUBRANGE - 100 + 1, 99
    ]

    newuidmap = [str(x) for x in newuidmap]
    newgidmap = [str(x) for x in newgidmap]

    # newuidmap and newgidmap have to run from outside the user namespace to be able to assign a uid mapping
    # to the process in the user namespace. The mapping can only be assigned after the user namespace has
    # been unshared. To make this work, we first lock /etc/subuid, then spawn the newuidmap and newgidmap
    # processes, which we execute using flock so they don't execute before they can get a lock on /etc/subuid,
    # then we unshare the user namespace and finally we unlock /etc/subuid, which allows the newuidmap and
    # newgidmap processes to execute. we then wait for the processes to finish before continuing.
    with flock(Path("/etc/subuid")) as fd, spawn(newuidmap) as uidmap, spawn(newgidmap) as gidmap:
        unshare(CLONE_NEWUSER)
        fcntl.flock(fd, fcntl.LOCK_UN)
        uidmap.wait()
        gidmap.wait()

    # By default, we're root in the user namespace because if we were our current user by default, we
    # wouldn't be able to chown stuff to be owned by root while the reverse is possible.
    os.setresuid(0, 0, 0)
    os.setresgid(0, 0, 0)
    os.setgroups([0])

    INVOKING_USER.uid = SUBRANGE - 100
    INVOKING_USER.gid = SUBRANGE - 100


def init_mount_namespace() -> None:
    unshare(CLONE_NEWNS)
    run(["mount", "--make-rslave", "/"])


def make_foreground_process(*, new_process_group: bool = True) -> None:
    """
    If we're connected to a terminal, put the process in a new process group and make that the foreground
    process group so that only this process receives SIGINT.
    """
    STDERR_FILENO = 2
    if os.isatty(STDERR_FILENO):
        if new_process_group:
            os.setpgrp()
        old = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        try:
            os.tcsetpgrp(STDERR_FILENO, os.getpgrp())
        except OSError as e:
            if e.errno != errno.ENOTTY:
                raise e
        signal.signal(signal.SIGTTOU, old)


def ensure_exc_info() -> tuple[type[BaseException], BaseException, TracebackType]:
    exctype, exc, tb = sys.exc_info()
    assert exctype
    assert exc
    assert tb
    return (exctype, exc, tb)


@contextlib.contextmanager
def uncaught_exception_handler(exit: Callable[[int], NoReturn] = sys.exit) -> Iterator[None]:
    rc = 0
    try:
        yield
    except SystemExit as e:
        if ARG_DEBUG.get():
            sys.excepthook(*ensure_exc_info())

        rc = e.code if isinstance(e.code, int) else 1
    except KeyboardInterrupt:
        if ARG_DEBUG.get():
            sys.excepthook(*ensure_exc_info())
        else:
            logging.error("Interrupted")

        rc = 1
    except subprocess.CalledProcessError as e:
        # Failures from qemu, ssh and systemd-nspawn are expected and we won't log stacktraces for those.
        # Failures from self come from the forks we spawn to build images in a user namespace. We've already done all
        # the logging for those failures so we don't log stacktraces for those either.
        if (
            ARG_DEBUG.get() and
            e.cmd and
            e.cmd[0] not in ("self", "ssh", "systemd-nspawn") and
            not e.cmd[0].startswith("qemu")
        ):
            sys.excepthook(*ensure_exc_info())

        # We always log when subprocess.CalledProcessError is raised, so we don't log again here.
        rc = e.returncode
    except BaseException:
        sys.excepthook(*ensure_exc_info())
        rc = 1
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        exit(rc)


def fork_and_wait(target: Callable[[], None]) -> None:
    pid = os.fork()
    if pid == 0:
        with uncaught_exception_handler(exit=os._exit):
            make_foreground_process()
            target()

    try:
        _, status = os.waitpid(pid, 0)
    except BaseException:
        os.kill(pid, signal.SIGTERM)
        _, status = os.waitpid(pid, 0)
    finally:
        make_foreground_process(new_process_group=False)

    rc = os.waitstatus_to_exitcode(status)

    if rc != 0:
        raise subprocess.CalledProcessError(rc, ["self"])


@contextlib.contextmanager
def sigkill_to_sigterm() -> Iterator[None]:
    old = signal.SIGKILL
    signal.SIGKILL = signal.SIGTERM

    try:
        yield
    finally:
        signal.SIGKILL = old


def log_process_failure(cmdline: Sequence[str], returncode: int) -> None:
    if returncode < 0:
        logging.error(f"Interrupted by {signal.Signals(-returncode).name} signal")
    else:
        logging.error(f"\"{shlex.join(cmdline)}\" returned non-zero exit code {returncode}.")


def run(
    cmdline: Sequence[PathString],
    check: bool = True,
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    input: Optional[str] = None,
    user: Optional[int] = None,
    group: Optional[int] = None,
    env: Mapping[str, str] = {},
    cwd: Optional[Path] = None,
    log: bool = True,
    preexec_fn: Optional[Callable[[], None]] = None,
    sandbox: Sequence[PathString] = (),
) -> CompletedProcess:
    sandbox = [os.fspath(x) for x in sandbox]
    cmdline = [os.fspath(x) for x in cmdline]

    if ARG_DEBUG.get():
        logging.info(f"+ {shlex.join(sandbox + cmdline)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    env = {
        "PATH": os.environ["PATH"],
        "TERM": os.getenv("TERM", "vt220"),
        "LANG": "C.UTF-8",
        **env,
    }

    if "TMPDIR" in os.environ:
        env["TMPDIR"] = os.environ["TMPDIR"]

    if ARG_DEBUG.get():
        env["SYSTEMD_LOG_LEVEL"] = "debug"

    if input is not None:
        assert stdin is None  # stdin and input cannot be specified together
    elif stdin is None:
        stdin = subprocess.DEVNULL

    def preexec() -> None:
        make_foreground_process()
        if preexec_fn:
            preexec_fn()

    try:
        # subprocess.run() will use SIGKILL to kill processes when an exception is raised.
        # We'd prefer it to use SIGTERM instead but since this we can't configure which signal
        # should be used, we override the constant in the signal module instead before we call
        # subprocess.run().
        with sigkill_to_sigterm():
            return subprocess.run(
                sandbox + cmdline,
                check=check,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                input=input,
                text=True,
                user=user,
                group=group,
                env=env,
                cwd=cwd,
                preexec_fn=preexec,
            )
    except FileNotFoundError as e:
        die(f"{e.filename} not found.")
    except subprocess.CalledProcessError as e:
        if ARG_DEBUG_SHELL.get():
            subprocess.run(
                [*sandbox, "sh"],
                check=False,
                stdin=sys.stdin,
                text=True,
                user=user,
                group=group,
                env=env,
                cwd=cwd,
                preexec_fn=preexec,
            )
        if log:
            log_process_failure(cmdline, e.returncode)
        # Remove the sandboxing stuff from the command line to show a more readable error to users.
        e.cmd = cmdline
        raise
    finally:
        make_foreground_process(new_process_group=False)


@contextlib.contextmanager
def spawn(
    cmdline: Sequence[PathString],
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    user: Optional[int] = None,
    group: Optional[int] = None,
    pass_fds: Collection[int] = (),
    env: Mapping[str, str] = {},
    log: bool = True,
    foreground: bool = False,
    preexec_fn: Optional[Callable[[], None]] = None,
    sandbox: Sequence[PathString] = (),
) -> Iterator[Popen]:
    sandbox = [os.fspath(x) for x in sandbox]
    cmdline = [os.fspath(x) for x in cmdline]

    if ARG_DEBUG.get():
        logging.info(f"+ {shlex.join(sandbox + cmdline)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    env = {
        "PATH": os.environ["PATH"],
        "TERM": os.getenv("TERM", "vt220"),
        "LANG": "C.UTF-8",
        **env,
    }

    def preexec() -> None:
        if foreground:
            make_foreground_process()
        if preexec_fn:
            preexec_fn()

    try:
        with subprocess.Popen(
            sandbox + cmdline,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            text=True,
            user=user,
            group=group,
            pass_fds=pass_fds,
            env=env,
            preexec_fn=preexec,
        ) as proc:
            yield proc
    except FileNotFoundError as e:
        die(f"{e.filename} not found.")
    except subprocess.CalledProcessError as e:
        if log:
            log_process_failure(cmdline, e.returncode)
        raise e
    finally:
        if foreground:
            make_foreground_process(new_process_group=False)


def find_binary(*names: PathString, root: Path = Path("/")) -> Optional[Path]:
    if root != Path("/"):
        path = ":".join(os.fspath(p) for p in (root / "usr/bin", root / "usr/sbin"))
    else:
        path = os.environ["PATH"]

    for name in names:
        if Path(name).is_absolute():
            name = root / Path(name).relative_to("/")
        elif "/" in str(name):
            name = root / name

        if (binary := shutil.which(name, path=path)):
            if root != Path("/") and not Path(binary).is_relative_to(root):
                return Path(binary)
            else:
                return Path("/") / Path(binary).relative_to(root)

    return None


class AsyncioThread(threading.Thread):
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

    def __enter__(self) -> "AsyncioThread":
        self.start()
        return self

    def __exit__(
        self,
        type: Optional[type[BaseException]],
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
