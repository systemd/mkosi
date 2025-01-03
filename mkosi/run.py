# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import errno
import fcntl
import functools
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
import uuid
from collections.abc import Awaitable, Collection, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, NoReturn, Optional, Protocol

import mkosi.sandbox
from mkosi.log import ARG_DEBUG, ARG_DEBUG_SANDBOX, ARG_DEBUG_SHELL, die
from mkosi.sandbox import acquire_privileges, joinpath, umask
from mkosi.types import _FILE, CompletedProcess, PathString, Popen
from mkosi.util import current_home_dir, flatten, one_zero

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
        rc = e.code if isinstance(e.code, int) else 1

        if ARG_DEBUG.get():
            sys.excepthook(*ensure_exc_info())
    except KeyboardInterrupt:
        rc = 1

        if ARG_DEBUG.get():
            sys.excepthook(*ensure_exc_info())
        else:
            logging.error("Interrupted")
    except subprocess.CalledProcessError as e:
        # We always log when subprocess.CalledProcessError is raised, so we don't log again here.
        rc = e.returncode

        # Failures from qemu, ssh and systemd-nspawn are expected and we won't log stacktraces for those.
        # Failures from self come from the forks we spawn to build images in a user namespace. We've already
        # done all the logging for those failures so we don't log stacktraces for those either.
        if (
            ARG_DEBUG.get()
            and e.cmd
            and str(e.cmd[0]) not in ("self", "ssh", "systemd-nspawn")
            and "qemu-system" not in str(e.cmd[0])
        ):
            sys.excepthook(*ensure_exc_info())
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
    elif returncode == 127:
        logging.error(f"{cmdline[0]} not found.")
    else:
        logging.error(
            f'"{shlex.join([*sandbox, *cmdline] if ARG_DEBUG.get() else cmdline)}"'
            f" returned non-zero exit code {returncode}."
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
    log: bool = True,
    foreground: bool = True,
    success_exit_status: Sequence[int] = (0,),
    sandbox: AbstractContextManager[Sequence[PathString]] = contextlib.nullcontext([]),
) -> CompletedProcess:
    if input is not None:
        assert stdin is None  # stdin and input cannot be specified together
        stdin = subprocess.PIPE

    with spawn(
        cmdline,
        check=check,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        user=user,
        group=group,
        env=env,
        log=log,
        foreground=foreground,
        success_exit_status=success_exit_status,
        sandbox=sandbox,
    ) as process:
        out, err = process.communicate(input)

    return CompletedProcess(cmdline, process.returncode, out, err)


def fd_move_above(fd: int, above: int) -> int:
    dup = fcntl.fcntl(fd, fcntl.F_DUPFD, above)
    os.close(fd)
    return dup


def preexec(
    *,
    foreground: bool,
    preexec_fn: Optional[Callable[[], None]],
    pass_fds: Collection[int],
) -> None:
    if foreground:
        make_foreground_process()
    if preexec_fn:
        preexec_fn()

    if not pass_fds:
        return

    # The systemd socket activation interface requires any passed file descriptors to start at '3' and
    # incrementally increase from there. The file descriptors we got from the caller might be arbitrary,
    # so we need to move them around to make sure they start at '3' and incrementally increase.
    for i, fd in enumerate(pass_fds):
        # Don't do anything if the file descriptor is already what we need it to be.
        if fd == SD_LISTEN_FDS_START + i:
            continue

        # Close any existing file descriptor that occupies the id that we want to move to. This is safe
        # because using pass_fds implies using close_fds as well, except that file descriptors are closed
        # by python after running the preexec function, so we have to close a few of those manually here
        # to make room if needed.
        try:
            os.close(SD_LISTEN_FDS_START + i)
        except OSError as e:
            if e.errno != errno.EBADF:
                raise

        nfd = fcntl.fcntl(fd, fcntl.F_DUPFD, SD_LISTEN_FDS_START + i)
        # fcntl.F_DUPFD uses the closest available file descriptor ID, so make sure it actually picked
        # the ID we expect it to pick.
        assert nfd == SD_LISTEN_FDS_START + i


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
    log: bool = True,
    foreground: bool = False,
    preexec_fn: Optional[Callable[[], None]] = None,
    success_exit_status: Sequence[int] = (0,),
    sandbox: AbstractContextManager[Sequence[PathString]] = contextlib.nullcontext([]),
) -> Iterator[Popen]:
    assert sorted(set(pass_fds)) == list(pass_fds)

    cmd = [os.fspath(x) for x in cmdline]

    if ARG_DEBUG.get():
        logging.info(f"+ {shlex.join(cmd)}")

    if not stdout and not stderr:
        # Unless explicit redirection is done, print all subprocess output on stderr, since we do so as well
        # for mkosi's own output.
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

    for e in ("SYSTEMD_LOG_LEVEL", "SYSTEMD_LOG_LOCATION"):
        if e in os.environ:
            env[e] = os.environ[e]

    if "HOME" not in env:
        env["HOME"] = "/"

    # sandbox.py takes care of setting $LISTEN_PID
    if pass_fds:
        env["LISTEN_FDS"] = str(len(pass_fds))

    with sandbox as sbx:
        prefix = [os.fspath(x) for x in sbx]

        if prefix:
            prfd, pwfd = os.pipe2(os.O_CLOEXEC)

            # Make sure the write end of the pipe (which we pass to the subprocess) is higher than all the
            # file descriptors we'll pass to the subprocess, so that it doesn't accidentally get closed by
            # the logic in preexec().
            if pass_fds:
                pwfd = fd_move_above(pwfd, list(pass_fds)[-1])

            exec_prefix = ["--exec-fd", f"{SD_LISTEN_FDS_START + len(pass_fds)}", "--"]
            pass_fds = [*pass_fds, pwfd]
        else:
            exec_prefix = []
            prfd, pwfd = None, None

        try:
            with subprocess.Popen(
                [*prefix, *exec_prefix, *cmdline],
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                text=True,
                user=user,
                group=group,
                # pass_fds only comes into effect after python has invoked the preexec function, so we make
                # sure that pass_fds contains the file descriptors to keep open after we've done our
                # transformation in preexec().
                pass_fds=[SD_LISTEN_FDS_START + i for i in range(len(pass_fds))],
                env=env,
                preexec_fn=functools.partial(
                    preexec,
                    foreground=foreground,
                    preexec_fn=preexec_fn,
                    pass_fds=pass_fds,
                ),
            ) as proc:
                if pwfd is not None:
                    os.close(pwfd)

                if prfd is not None:
                    os.read(prfd, 1)
                    os.close(prfd)

                def failed() -> bool:
                    return check and (rc := proc.poll()) is not None and rc not in success_exit_status

                try:
                    # Don't bother yielding if we've already failed by the time we get here. We'll raise an
                    # exception later on so it's not a problem that we don't yield at all.
                    if not failed():
                        yield proc
                except BaseException:
                    proc.terminate()
                    raise
                finally:
                    returncode = proc.wait()

                if failed():
                    if log:
                        log_process_failure(prefix, cmd, returncode)
                    if ARG_DEBUG_SHELL.get():
                        subprocess.run(
                            [*prefix, "bash"],
                            check=False,
                            stdin=sys.stdin,
                            text=True,
                            user=user,
                            group=group,
                            env=env,
                            preexec_fn=functools.partial(
                                preexec,
                                foreground=True,
                                preexec_fn=preexec_fn,
                                pass_fds=tuple(),
                            ),
                        )
                    raise subprocess.CalledProcessError(returncode, cmdline)
        except FileNotFoundError as e:
            die(f"{e.filename} not found.")
        finally:
            if foreground:
                make_foreground_process(new_process_group=False)


def find_binary(
    *names: PathString,
    root: Optional[Path] = None,
    extra: Sequence[Path] = (),
) -> Optional[Path]:
    root = root or Path("/")

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


class AsyncioThread(threading.Thread):
    """
    The default threading.Thread() is not interruptible, so we make our own version by using the concurrency
    feature in python that is interruptible, namely asyncio.

    Additionally, we store any exception that the coroutine raises and re-raise it in join() if no other
    exception was raised before.
    """

    def __init__(self, target: Awaitable[Any], *args: Any, **kwargs: Any) -> None:
        import asyncio

        self.target = target
        self.loop: queue.SimpleQueue[asyncio.AbstractEventLoop] = queue.SimpleQueue()
        self.exc: queue.SimpleQueue[BaseException] = queue.SimpleQueue()
        super().__init__(*args, **kwargs)

    def run(self) -> None:
        import asyncio

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
        import asyncio.tasks

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


class SandboxProtocol(Protocol):
    def __call__(
        self,
        *,
        options: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]: ...


def nosandbox(
    *,
    options: Sequence[PathString] = (),
) -> AbstractContextManager[list[PathString]]:
    return contextlib.nullcontext([])


def workdir(path: Path, sandbox: Optional[SandboxProtocol] = None) -> str:
    subdir = "/" if sandbox and sandbox == nosandbox else "/work"
    return joinpath(subdir, str(path))


def finalize_passwd_symlinks(root: PathString) -> list[PathString]:
    """
    If passwd or a related file exists in the apivfs directory, bind mount it over the host files while we
    run the command, to make sure that the command we run uses user/group information from the apivfs
    directory instead of from the host.
    """
    return flatten(
        ("--symlink", Path(root) / "etc" / f, f"/etc/{f}") for f in ("passwd", "group", "shadow", "gshadow")
    )


def network_options(*, network: bool) -> list[PathString]:
    return [
        "--setenv", "SYSTEMD_OFFLINE", one_zero(network),
        *(["--unshare-net"] if not network else []),
    ]  # fmt: skip


@contextlib.contextmanager
def vartmpdir() -> Iterator[Path]:
    # We want to use an empty subdirectory in the host's temporary directory as the sandbox's /var/tmp.
    d = Path(os.getenv("TMPDIR", "/var/tmp")) / f"mkosi-var-tmp-{uuid.uuid4().hex[:16]}"
    d.mkdir()

    try:
        yield d
    finally:
        # A directory that's used as an overlayfs workdir will contain a "work" subdirectory after the
        # overlayfs is unmounted. This "work" subdirectory will have permissions 000 and as such can't be
        # opened or searched unless the user has the CAP_DAC_OVERRIDE capability. shutil.rmtree() will try to
        # search the "work" subdirectory to remove anything in it which will fail with a permission error. To
        # circumvent this, if the work directory exists and is not empty, let's fork off a subprocess where
        # we acquire extra privileges and then invoke shutil.rmtree(). If the work directory exists but is
        # empty, let's just delete the "work" subdirectory first and then invoke shutil.rmtree(). Deleting
        # the subdirectory when it is empty is not a problem because deleting a subdirectory depends on the
        # permissions of the parent directory and not the directory itself.
        try:
            (d / "work").rmdir()
        except OSError as e:
            if e.errno == errno.ENOTEMPTY:

                def remove() -> None:
                    acquire_privileges()
                    shutil.rmtree(d)

                fork_and_wait(remove)
                return
            elif e.errno != errno.ENOENT:
                raise

        shutil.rmtree(d)


@contextlib.contextmanager
def sandbox_cmd(
    *,
    network: bool = False,
    devices: bool = False,
    scripts: Optional[Path] = None,
    tools: Path = Path("/"),
    relaxed: bool = False,
    overlay: Optional[Path] = None,
    options: Sequence[PathString] = (),
    setup: Sequence[PathString] = (),
) -> Iterator[list[PathString]]:
    assert not (overlay and relaxed)

    cmdline: list[PathString] = [
        *setup,
        *(["strace", "--detach-on=execve"] if ARG_DEBUG_SANDBOX.get() else []),
        sys.executable, "-SI", mkosi.sandbox.__file__,
        "--proc", "/proc",
        # We mounted a subdirectory of TMPDIR to /var/tmp so we unset TMPDIR so that /tmp or /var/tmp are
        # used instead.
        "--unsetenv", "TMPDIR",
        *network_options(network=network),
    ]  # fmt: skip

    if overlay and (overlay / "usr").exists():
        cmdline += [
            "--overlay-lowerdir", tools / "usr",
            "--overlay-lowerdir", overlay / "usr",
            "--overlay", "/usr",
        ]  # fmt: skip
    else:
        cmdline += ["--ro-bind", tools / "usr", "/usr"]

    for d in ("bin", "sbin", "lib", "lib32", "lib64"):
        if (p := tools / d).is_symlink():
            cmdline += ["--symlink", p.readlink(), Path("/") / p.relative_to(tools)]
        elif p.is_dir():
            cmdline += ["--ro-bind", p, Path("/") / p.relative_to(tools)]

    # If we're using /usr from a tools tree, we have to use /etc/alternatives and /etc/ld.so.cache from the
    # tools tree as well if they exists since those are directly related to /usr. In relaxed mode, we only do
    # this if the mountpoint already exists on the host as otherwise we'd modify the host's /etc by creating
    # the mountpoint ourselves (or fail when trying to create it).
    for p in (Path("etc/alternatives"), Path("etc/ld.so.cache")):
        if (tools / p).exists() and (not relaxed or (Path("/") / p).exists()):
            cmdline += ["--ro-bind", tools / p, Path("/") / p]

    if (tools / "nix/store").exists():
        cmdline += ["--bind", tools / "nix/store", "/nix/store"]

    if relaxed:
        for p in Path("/").iterdir():
            if p not in (
                Path("/home"),
                Path("/proc"),
                Path("/usr"),
                Path("/nix"),
                Path("/bin"),
                Path("/sbin"),
                Path("/lib"),
                Path("/lib32"),
                Path("/lib64"),
            ):
                if p.is_symlink():
                    cmdline += ["--symlink", p.readlink(), p]
                else:
                    cmdline += ["--bind", p, p]

            # /etc might be full of symlinks to /usr/share/factory, so make sure we use /usr/share/factory
            # from the host and not from the tools tree.
            if tools != Path("/") and (factory := Path("/usr/share/factory")).exists():
                cmdline += ["--bind", factory, factory]

        if home := current_home_dir():
            cmdline += ["--bind", home, home]
    else:
        cmdline += [
            "--dir", "/var/tmp",
            "--dir", "/var/log",
            "--unshare-ipc",
            # apivfs_script_cmd() and chroot_script_cmd() are executed from within the sandbox, but they
            # still use sandbox.py, so we make sure it is available inside the sandbox so it can be executed
            # there as well.
            "--ro-bind", Path(mkosi.sandbox.__file__), "/sandbox.py",
        ]  # fmt: skip

        if devices:
            cmdline += ["--bind", "/sys", "/sys", "--bind", "/dev", "/dev"]
        else:
            cmdline += ["--dev", "/dev"]

        if network:
            for p in (Path("/etc/resolv.conf"), Path("/run/systemd/resolve")):
                if p.exists():
                    cmdline += ["--ro-bind", p, p]

        home = None

    # We leak most of the $PATH from the host into the non-relaxed sandbox as well but this shouldn't be a
    # problem in practice as the directories themselves won't be in the sandbox and so we shouldn't
    # accidentally pick up anything from them.

    path = []
    if scripts:
        path += ["/scripts"]
    if tools != Path("/"):
        path += [
            s
            for s in os.environ["PATH"].split(":")
            if s in ("/usr/bin", "/usr/sbin") or not s.startswith("/usr")
        ]

        # Make sure that /usr/bin and /usr/sbin are always in $PATH.
        path += [s for s in ("/usr/bin", "/usr/sbin") if s not in path]
    else:
        path += os.environ["PATH"].split(":")

    cmdline += ["--setenv", "PATH", ":".join(path)]

    if scripts:
        cmdline += ["--ro-bind", scripts, "/scripts"]

    with contextlib.ExitStack() as stack:
        tmp: Optional[Path]

        if not overlay and not relaxed:
            tmp = stack.enter_context(vartmpdir())
            yield [*cmdline, "--bind", tmp, "/var/tmp", "--dir", "/tmp", "--dir", "/run", *options]
            return

        for d in ("etc", "opt"):
            if overlay and (overlay / d).exists():
                cmdline += ["--ro-bind", overlay / d, Path("/") / d]
            else:
                cmdline += ["--dir", Path("/") / d]

        for d in ("srv", "media", "mnt", "var", "run", "tmp"):
            tmp = None
            if d not in ("run", "tmp"):
                with umask(~0o755):
                    tmp = stack.enter_context(vartmpdir())

            if overlay and (overlay / d).exists():
                work = None
                if tmp:
                    with umask(~0o755):
                        work = stack.enter_context(vartmpdir())

                cmdline += [
                    "--overlay-lowerdir", overlay / d,
                    "--overlay-upperdir", tmp or "tmpfs",
                    *(["--overlay-workdir", str(work)] if work else []),
                    "--overlay", Path("/") / d,
                ]  # fmt: skip
            elif not relaxed:
                if tmp:
                    cmdline += ["--bind", tmp, Path("/") / d]
                else:
                    cmdline += ["--dir", Path("/") / d]

        # If we put an overlayfs on /var, and /var/tmp is not in the sandbox tree, make sure /var/tmp is a
        # bind mount of a regular empty directory instead of the overlays so tools like systemd-repart can
        # use the underlying filesystem features from btrfs when using /var/tmp.
        if overlay and not (overlay / "var/tmp").exists():
            tmp = stack.enter_context(vartmpdir())
            cmdline += ["--bind", tmp, "/var/tmp"]

        yield [*cmdline, *options]


def apivfs_options(*, root: Path = Path("/buildroot")) -> list[PathString]:
    return [
        "--tmpfs", root / "run",
        "--tmpfs", root / "tmp",
        "--proc", root / "proc",
        "--dev", root / "dev",
        # Nudge gpg to create its sockets in /run by making sure /run/user/0 exists.
        "--dir", root / "run/user/0",
        # Make sure anything running in the root directory thinks it's in a container. $container can't
        # always be accessed so we write /run/host/container-manager as well which is always accessible.
        "--write", "mkosi", root / "run/host/container-manager",
    ]  # fmt: skip


def chroot_options() -> list[PathString]:
    return [
        # Let's always run as (fake) root when we chroot inside the image as tools executed within the image
        # could have builtin assumptions about files being owned by root.
        "--become-root",
        # Unshare IPC namespace so any tests that exercise IPC related features don't fail with permission
        # errors as --become-root implies unsharing a user namespace which won't have access to the parent's
        # IPC namespace anymore.
        "--unshare-ipc",
        "--setenv", "container", "mkosi",
        "--setenv", "HOME", "/",
        "--setenv", "PATH", "/usr/bin:/usr/sbin",
        "--setenv", "BUILDROOT", "/",
    ]  # fmt: skip


@contextlib.contextmanager
def chroot_cmd(
    *,
    root: Path,
    network: bool = False,
    options: Sequence[PathString] = (),
) -> Iterator[list[PathString]]:
    cmdline: list[PathString] = [
        sys.executable, "-SI", mkosi.sandbox.__file__,
        "--bind", root, "/",
        # We mounted a subdirectory of TMPDIR to /var/tmp so we unset TMPDIR so that /tmp or /var/tmp are
        # used instead.
        "--unsetenv", "TMPDIR",
        *network_options(network=network),
        *apivfs_options(root=Path("/")),
        *chroot_options(),
    ]  # fmt: skip

    if network:
        for p in (Path("/etc/resolv.conf"), Path("/run/systemd/resolve")):
            if p.exists():
                cmdline += ["--ro-bind", p, p]

    with vartmpdir() as dir:
        yield [*cmdline, "--bind", dir, "/var/tmp", *options]


def finalize_interpreter(tools: bool) -> str:
    if tools:
        return "python3"

    exe = sys.executable
    if Path(exe).is_relative_to("/usr"):
        return exe

    return "python3"
