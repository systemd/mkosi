# SPDX-License-Identifier: LGPL-2.1+

import asyncio
import asyncio.tasks
import contextlib
import errno
import fcntl
import itertools
import logging
import os
import queue
import shlex
import shutil
import signal
import subprocess
import sys
import threading
from collections.abc import Awaitable, Collection, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, NoReturn, Optional

from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, die
from mkosi.types import _FILE, CompletedProcess, PathString, Popen

SD_LISTEN_FDS_START = 3


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


def fork_and_wait(target: Callable[..., None], *args: Any, **kwargs: Any) -> None:
    pid = os.fork()
    if pid == 0:
        with uncaught_exception_handler(exit=os._exit):
            make_foreground_process()
            target(*args, **kwargs)

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


def log_process_failure(sandbox: Sequence[str], cmdline: Sequence[str], returncode: int) -> None:
    if returncode < 0:
        logging.error(f"Interrupted by {signal.Signals(-returncode).name} signal")
    else:
        logging.error(
            f"\"{shlex.join([*sandbox, *cmdline] if ARG_DEBUG.get() else cmdline)}\" returned non-zero exit code "
            f"{returncode}."
        )


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
    foreground: bool = True,
    preexec_fn: Optional[Callable[[], None]] = None,
    success_exit_status: Sequence[int] = (0,),
    sandbox: AbstractContextManager[Sequence[PathString]] = contextlib.nullcontext([]),
    scope: Sequence[str] = (),
) -> CompletedProcess:
    if input is not None:
        assert stdin is None  # stdin and input cannot be specified together
        stdin = subprocess.PIPE

    try:
        with spawn(
            cmdline,
            check=check,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            user=user,
            group=group,
            env=env,
            cwd=cwd,
            log=log,
            foreground=foreground,
            preexec_fn=preexec_fn,
            success_exit_status=success_exit_status,
            sandbox=sandbox,
            scope=scope,
            innerpid=False,
        ) as (process, _):
            out, err = process.communicate(input)
    except FileNotFoundError:
        return CompletedProcess(cmdline, 1)

    return CompletedProcess(cmdline, process.returncode, out, err)


@contextlib.contextmanager
def spawn(
    cmdline: Sequence[PathString],
    check: bool = True,
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    user: Optional[int] = None,
    group: Optional[int] = None,
    pass_fds: Collection[int] = (),
    env: Mapping[str, str] = {},
    cwd: Optional[Path] = None,
    log: bool = True,
    foreground: bool = False,
    preexec_fn: Optional[Callable[[], None]] = None,
    success_exit_status: Sequence[int] = (0,),
    sandbox: AbstractContextManager[Sequence[PathString]] = contextlib.nullcontext([]),
    scope: Sequence[str] = (),
    innerpid: bool = True,
) -> Iterator[tuple[Popen, int]]:
    assert sorted(set(pass_fds)) == list(pass_fds)

    cmdline = [os.fspath(x) for x in cmdline]

    if ARG_DEBUG.get():
        logging.info(f"+ {shlex.join(cmdline)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess
        # output on stderr, since we do so as well for mkosi's own
        # output.
        stdout = sys.stderr

    if stdin is None:
        stdin = subprocess.DEVNULL

    env = {
        "PATH": os.environ["PATH"],
        "TERM": os.getenv("TERM", "vt220"),
        "LANG": "C.UTF-8",
        **env,
    }

    if "TMPDIR" in os.environ:
        env["TMPDIR"] = os.environ["TMPDIR"]

    if scope:
        if not find_binary("systemd-run"):
            scope = []
        elif os.getuid() != 0 and "DBUS_SESSION_BUS_ADDRESS" in os.environ and "XDG_RUNTIME_DIR" in os.environ:
            env["DBUS_SESSION_BUS_ADDRESS"] = os.environ["DBUS_SESSION_BUS_ADDRESS"]
            env["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
        elif os.getuid() == 0 and "DBUS_SYSTEM_ADDRESS" in os.environ:
            env["DBUS_SYSTEM_ADDRESS"] = os.environ["DBUS_SYSTEM_ADDRESS"]
        else:
            scope = []

    if scope:
        user = group = None

    for e in ("SYSTEMD_LOG_LEVEL", "SYSTEMD_LOG_LOCATION"):
        if e in os.environ:
            env[e] = os.environ[e]

    if "HOME" not in env:
        env["HOME"] = "/"

    def preexec() -> None:
        if foreground:
            make_foreground_process()
        if preexec_fn:
            preexec_fn()

        if not pass_fds:
            return

        # The systemd socket activation interface requires any passed file descriptors to start at '3' and
        # incrementally increase from there. The file descriptors we got from the caller might be arbitrary, so we need
        # to move them around to make sure they start at '3' and incrementally increase.
        for i, fd in enumerate(pass_fds):
            # Don't do anything if the file descriptor is already what we need it to be.
            if fd == SD_LISTEN_FDS_START + i:
                continue

            # Close any existing file descriptor that occupies the id that we want to move to. This is safe because
            # using pass_fds implies using close_fds as well, except that file descriptors are closed by python after
            # running the preexec function, so we have to close a few of those manually here to make room if needed.
            try:
                os.close(SD_LISTEN_FDS_START + i)
            except OSError as e:
                if e.errno != errno.EBADF:
                    raise

            nfd = fcntl.fcntl(fd, fcntl.F_DUPFD, SD_LISTEN_FDS_START + i)
            # fcntl.F_DUPFD uses the closest available file descriptor ID, so make sure it actually picked the ID we
            # expect it to pick.
            assert nfd == SD_LISTEN_FDS_START + i

    with sandbox as sbx:
        prefix = [os.fspath(x) for x in sbx]

        # First, check if the sandbox works at all before executing the command.
        if prefix and (rc := subprocess.run(prefix + ["true"]).returncode) != 0:
            log_process_failure(prefix, cmdline, rc)
            raise subprocess.CalledProcessError(rc, prefix + cmdline)

        if subprocess.run(
            prefix + ["sh", "-c", f"command -v {cmdline[0]}"],
            stdout=subprocess.DEVNULL,
        ).returncode != 0:
            if check:
                die(f"{cmdline[0]} not found.", hint=f"Is {cmdline[0]} installed on the host system?")

            # We can't really return anything in this case, so we raise a specific exception that we can catch in
            # run().
            logging.debug(f"{cmdline[0]} not found, not running {shlex.join(cmdline)}")
            raise FileNotFoundError(cmdline[0])

        if (
            foreground and
            prefix and
            subprocess.run(prefix + ["sh", "-c", "command -v setpgid"], stdout=subprocess.DEVNULL).returncode == 0
        ):
            prefix += ["setpgid", "--foreground", "--"]

        if pass_fds:
            # We don't know the PID before we start the process and we can't modify the environment in preexec_fn so we
            # have to spawn a temporary shell to set the necessary environment variables before spawning the actual
            # command.
            prefix += ["sh", "-c", f"LISTEN_FDS={len(pass_fds)} LISTEN_PID=$$ exec $0 \"$@\""]

        if prefix and innerpid:
            r, w = os.pipe2(os.O_CLOEXEC)
            # Make sure that the write end won't be overridden in preexec() when we're moving fds forward.
            q = fcntl.fcntl(w, fcntl.F_DUPFD_CLOEXEC, SD_LISTEN_FDS_START + len(pass_fds) + 1)
            os.close(w)
            w = q
            # dash doesn't support working with file descriptors higher than 9 so make sure we use bash.
            prefix += ["bash", "-c", f"echo $$ >&{w} && exec {w}>&- && exec $0 \"$@\""]
        else:
            r, w = (None, None)

        try:
            with subprocess.Popen(
                [*scope, *prefix, *cmdline],
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                text=True,
                user=user,
                group=group,
                # pass_fds only comes into effect after python has invoked the preexec function, so we make sure that
                # pass_fds contains the file descriptors to keep open after we've done our transformation in preexec().
                pass_fds=[SD_LISTEN_FDS_START + i for i in range(len(pass_fds))] + ([w] if w else []),
                env=env,
                cwd=cwd,
                preexec_fn=preexec,
            ) as proc:
                if w:
                    os.close(w)
                pid = proc.pid
                try:
                    if r:
                        with open(r) as f:
                            s = f.read()
                            if s:
                                pid = int(s)

                    yield proc, pid
                except BaseException:
                    kill(proc, pid, signal.SIGTERM)
                    raise
                finally:
                    returncode = proc.wait()

                if check and returncode not in success_exit_status:
                    if log:
                        log_process_failure(prefix, cmdline, returncode)
                    if ARG_DEBUG_SHELL.get():
                        subprocess.run(
                            [*scope, *prefix, "bash"],
                            check=False,
                            stdin=sys.stdin,
                            text=True,
                            user=user,
                            group=group,
                            env=env,
                            cwd=cwd,
                            preexec_fn=preexec,
                        )
                    raise subprocess.CalledProcessError(returncode, cmdline)
        except FileNotFoundError as e:
            die(f"{e.filename} not found.")
        finally:
            if foreground:
                make_foreground_process(new_process_group=False)


def find_binary(*names: PathString, root: Path = Path("/"), extra: Sequence[Path] = ()) -> Optional[Path]:
    if root != Path("/"):
        path = ":".join(
            itertools.chain(
                (os.fspath(p) for p in extra),
                (os.fspath(p) for p in (root / "usr/bin", root / "usr/sbin")),
            )
        )
    else:
        path = os.environ["PATH"]

    for name in names:
        if any(Path(name).is_relative_to(d) for d in extra):
            pass
        elif Path(name).is_absolute():
            name = root / Path(name).relative_to("/")
        elif "/" in str(name):
            name = root / name

        if binary := shutil.which(name, path=path):
            if root != Path("/") and not Path(binary).is_relative_to(root):
                return Path(binary)
            else:
                return Path("/") / Path(binary).relative_to(root)

    return None


def kill(process: Popen, innerpid: int, signal: int) -> None:
    process.poll()
    if process.returncode is not None:
        return

    try:
        os.kill(innerpid, signal)
    # Handle the race condition where the process might exit between us calling poll() and us calling os.kill().
    except ProcessLookupError:
        pass


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
