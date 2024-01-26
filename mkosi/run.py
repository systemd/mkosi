# SPDX-License-Identifier: LGPL-2.1+

import asyncio
import asyncio.tasks
import contextlib
import errno
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
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, NoReturn, Optional

from mkosi.log import ARG_DEBUG, ARG_DEBUG_SHELL, die
from mkosi.types import _FILE, CompletedProcess, PathString, Popen


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

    if (
        sandbox and
        subprocess.run(sandbox + ["sh", "-c", "command -v setpgid"], stdout=subprocess.DEVNULL).returncode == 0
    ):
        cmdline = ["setpgid", "--foreground", "--"] + cmdline

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
        if log:
            log_process_failure(cmdline, e.returncode)
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

    if (
        foreground and
        sandbox and
        subprocess.run(sandbox + ["sh", "-c", "command -v setpgid"], stdout=subprocess.DEVNULL).returncode == 0
    ):
        cmdline = ["setpgid", "--foreground", "--"] + cmdline

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

        if binary := shutil.which(name, path=path):
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
