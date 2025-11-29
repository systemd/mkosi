# SPDX-License-Identifier: LGPL-2.1-or-later

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
import uuid
from collections.abc import Awaitable, Collection, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Callable, Generic, NoReturn, Optional, Protocol, TypeVar

from mkosi.log import ARG_DEBUG, ARG_DEBUG_SANDBOX, ARG_DEBUG_SHELL, die
from mkosi.sandbox import acquire_privileges, joinpath, umask
from mkosi.util import _FILE, PathString, flatten, one_zero, resource_path, unique

# These types are only generic during type checking and not at runtime, leading
# to a TypeError during compilation.
# Let's be as strict as we can with the description for the usage we have.
if TYPE_CHECKING:
    CompletedProcess = subprocess.CompletedProcess[str]
    Popen = subprocess.Popen[str]
else:
    CompletedProcess = subprocess.CompletedProcess
    Popen = subprocess.Popen


T = TypeVar("T")


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
            target(*args, **kwargs)

    try:
        _, status = os.waitpid(pid, 0)
    except KeyboardInterrupt:
        os.kill(pid, signal.SIGINT)
        _, status = os.waitpid(pid, 0)
    except BaseException:
        os.kill(pid, signal.SIGTERM)
        _, status = os.waitpid(pid, 0)

    rc = os.waitstatus_to_exitcode(status)

    if rc != 0:
        raise subprocess.CalledProcessError(rc, ["self"])


def log_process_failure(sandbox: Sequence[str], cmdline: Sequence[str], returncode: int) -> None:
    if -returncode in (signal.SIGINT, signal.SIGTERM):
        logging.error(f"Interrupted by {signal.Signals(-returncode).name} signal")
    elif returncode < 0:
        logging.error(
            f'"{shlex.join([*sandbox, *cmdline] if ARG_DEBUG.get() else cmdline)}"'
            f" was killed by {signal.Signals(-returncode).name} signal."
        )
    elif returncode == 127 and cmdline[0] != "mkosi":
        # Anything invoked beneath /work is a script that we mount into place (so we know it exists). If one
        # of these scripts fails with exit code 127, it's either because the script interpreter was not
        # installed or because one of the commands in the script failed with exit code 127.
        if cmdline[0].startswith("/work"):
            logging.error(f"{cmdline[0]} failed with non-zero exit code 127")
            logging.info(
                "(Maybe a program was not found or the script interpreter (e.g. bash) is not installed?)"
            )
        else:
            logging.error(f"{cmdline[0]} not found.")
    else:
        logging.error(f'"{shlex.join([*sandbox, *cmdline])}" returned non-zero exit code {returncode}.')


def run(
    cmdline: Sequence[PathString],
    check: bool = True,
    stdin: _FILE = None,
    stdout: _FILE = None,
    stderr: _FILE = None,
    input: Optional[str] = None,
    env: Mapping[str, str] = {},
    log: bool = True,
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
        env=env,
        log=log,
        success_exit_status=success_exit_status,
        sandbox=sandbox,
    ) as process:
        out, err = process.communicate(input)

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
    log: bool = True,
    preexec: Optional[Callable[[], None]] = None,
    success_exit_status: Sequence[int] = (0,),
    sandbox: AbstractContextManager[Sequence[PathString]] = contextlib.nullcontext([]),
) -> Iterator[Popen]:
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
        **{k: v for k, v in env.items() if k != "LANG" and not k.startswith("LC_")},
    }

    if "TMPDIR" in os.environ:
        env["TMPDIR"] = os.environ["TMPDIR"]

    for e in ("SYSTEMD_LOG_LEVEL", "SYSTEMD_LOG_LOCATION"):
        if e in os.environ:
            env[e] = os.environ[e]

    if "HOME" not in env:
        env["HOME"] = "/"

    with sandbox as sbx:
        prefix = [os.fspath(x) for x in sbx]

        try:
            proc = subprocess.Popen(
                [*prefix, *cmdline],
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                text=True,
                user=user,
                group=group,
                pass_fds=pass_fds,
                env=env,
                preexec_fn=preexec,
            )
        except FileNotFoundError as e:
            die(f"{e.filename} not found.")

        try:
            yield proc
            proc.wait()
        except KeyboardInterrupt:
            proc.send_signal(signal.SIGINT)
            raise
        except BaseException:
            proc.terminate()
            raise
        finally:
            # Make sure any SIGINT/SIGTERM signal we sent is actually processed.
            proc.send_signal(signal.SIGCONT)
            returncode = proc.wait()

        if check and returncode is not None and returncode not in success_exit_status:
            if log:
                log_process_failure(prefix, cmd, returncode)
            if ARG_DEBUG_SHELL.get():
                subprocess.run(
                    # --suspend will freeze the debug shell with no way to unfreeze it so strip it from the
                    # sandbox if it's there.
                    [s for s in prefix if s != "--suspend"] + ["bash"],
                    check=False,
                    stdin=sys.stdin,
                    text=True,
                    user=user,
                    group=group,
                    env=env,
                    preexec_fn=preexec,
                )
            raise subprocess.CalledProcessError(returncode, cmdline)


def finalize_path(
    root: Optional[Path] = None,
    extra: Sequence[Path] = (),
    prefix_usr: bool = False,
    relaxed: bool = False,
) -> str:
    root = root or Path("/")
    path = [os.fspath(p) for p in extra]

    if relaxed:
        path += [
            s
            for s in os.environ["PATH"].split(":")
            if s in ("/usr/bin", "/usr/sbin") or not s.startswith("/usr")
        ]

        # Make sure that /usr/bin and /usr/sbin are always in $PATH.
        path += [s for s in ("/usr/bin", "/usr/sbin") if s not in path]
    else:
        path += ["/usr/bin", "/usr/sbin"]

    if prefix_usr:
        path = [os.fspath(root / s.lstrip("/")) if s in ("/usr/bin", "/usr/sbin") else s for s in path]

    return ":".join(unique(path))


def find_binary(
    *names: PathString,
    root: Optional[Path] = None,
    extra: Sequence[Path] = (),
) -> Optional[Path]:
    root = root or Path("/")
    path = finalize_path(root=root, extra=extra, prefix_usr=True)

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


class AsyncioThread(threading.Thread, Generic[T]):
    """
    The default threading.Thread() is not interruptible, so we make our own version by using the concurrency
    feature in python that is interruptible, namely asyncio.

    Additionally, we store any exception that the coroutine raises and re-raise it in join() if no other
    exception was raised before.
    """

    def __init__(
        self, target: Callable[[queue.SimpleQueue[T]], Awaitable[Any]], *args: Any, **kwargs: Any
    ) -> None:
        import asyncio

        self.target = target
        self.loop: queue.SimpleQueue[asyncio.AbstractEventLoop] = queue.SimpleQueue()
        self.exc: queue.SimpleQueue[BaseException] = queue.SimpleQueue()
        self.queue: queue.SimpleQueue[T] = queue.SimpleQueue()
        self.messages: list[T] = []
        super().__init__(*args, **kwargs)

    def run(self) -> None:
        import asyncio

        async def wrapper() -> None:
            self.loop.put(asyncio.get_running_loop())
            await self.target(self.queue)

        try:
            asyncio.run(wrapper())
        except asyncio.CancelledError:
            pass
        except BaseException as e:
            self.exc.put(e)

    def process(self) -> list[T]:
        while not self.queue.empty():
            self.messages += [self.queue.get()]

        return self.messages

    def wait_for(self, expected: T) -> None:
        while (message := self.queue.get()) != expected:
            self.messages += [message]

    def cancel(self) -> None:
        import asyncio.tasks

        loop = self.loop.get()

        for task in asyncio.tasks.all_tasks(loop):
            loop.call_soon_threadsafe(task.cancel)

    def __enter__(self) -> "AsyncioThread[T]":
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
        self.process()

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
    return joinpath(subdir, os.fspath(path))


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
            if (p := d / "work").exists():
                p.rmdir()
        except OSError as e:
            if e.errno == errno.ENOTEMPTY:

                def remove() -> None:
                    acquire_privileges()
                    shutil.rmtree(d)

                fork_and_wait(remove)
            else:
                raise
        else:
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
    extra: Sequence[Path] = (),
) -> Iterator[list[PathString]]:
    assert not (overlay and relaxed)

    with contextlib.ExitStack() as stack:
        module = stack.enter_context(resource_path(sys.modules[__package__ or __name__]))

        cmdline: list[PathString] = [
            *setup,
            *(["strace", "--detach-on=execve"] if ARG_DEBUG_SANDBOX.get() else []),
            sys.executable, "-SI", module / "sandbox.py",
            "--proc", "/proc",
            # We mounted a subdirectory of TMPDIR to /var/tmp so we unset TMPDIR so that /tmp or /var/tmp are
            # used instead.
            "--unsetenv", "TMPDIR",
            *network_options(network=network),
        ]  # fmt: skip

        for d in ("usr", "opt"):
            if not (tools / d).exists():
                continue

            if overlay and (overlay / d).exists():
                cmdline += [
                    "--overlay-lowerdir", tools / d,
                    "--overlay-lowerdir", overlay / d,
                    "--overlay", Path("/") / d,
                ]  # fmt: skip
            else:
                cmdline += ["--ro-bind", tools / d, Path("/") / d]

        for d in ("bin", "sbin", "lib", "lib32", "lib64"):
            if (p := tools / d).is_symlink():
                cmdline += ["--symlink", p.readlink(), Path("/") / p.relative_to(tools)]
            elif p.is_dir():
                cmdline += ["--ro-bind", p, Path("/") / p.relative_to(tools)]

        if (tools / "nix/store").exists():
            cmdline += ["--bind", tools / "nix/store", "/nix/store"]

        if relaxed:
            for p in Path("/").iterdir():
                if p not in (
                    Path("/proc"),
                    Path("/usr"),
                    Path("/opt"),
                    Path("/nix"),
                    Path("/bin"),
                    Path("/sbin"),
                    Path("/lib"),
                    Path("/lib32"),
                    Path("/lib64"),
                    Path("/etc"),
                ):
                    if p.is_symlink():
                        cmdline += ["--symlink", p.readlink(), p]
                    else:
                        cmdline += ["--bind", p, p]

            cmdline += ["--ro-bind", tools / "etc", "/etc"]

            if tools != Path("/"):
                for f in ("passwd", "group", "shadow", "gshadow", "nsswitch.conf", "machine-id"):
                    if Path(f"/etc/{f}").exists() and (tools / "etc" / f).exists():
                        cmdline += ["--ro-bind", f"/etc/{f}", f"/etc/{f}"]
        else:
            cmdline += [
                "--dir", "/var/tmp",
                "--dir", "/var/log",
                "--unshare-ipc",
                # apivfs_script_cmd() and chroot_script_cmd() are executed from within the sandbox, but they
                # still use sandbox.py, so we make sure it is available inside the sandbox so it can be
                # executed there as well.
                "--ro-bind", module / "sandbox.py", "/sandbox.py",
            ]  # fmt: skip

            if devices:
                cmdline += ["--bind", "/sys", "/sys", "--bind", "/dev", "/dev"]
            else:
                cmdline += ["--dev", "/dev"]

            # If we're using /usr from a tools tree, we have to use /etc/alternatives and /etc/ld.so.cache
            # from the tools tree as well if they exists since those are directly related to /usr.
            for p in (Path("etc/alternatives"), Path("etc/ld.so.cache")):
                if (tools / p).exists():
                    cmdline += ["--ro-bind", tools / p, Path("/") / p]

            if network and (p := Path("/run/systemd/resolve")).exists():
                cmdline += ["--ro-bind", p, p]

        if network and (p := Path("/etc/resolv.conf")).exists():
            cmdline += ["--ro-bind", p, p]

        path = finalize_path(
            root=tools,
            extra=[Path("/scripts"), *extra] if scripts else extra,
            relaxed=relaxed,
        )
        cmdline += ["--setenv", "PATH", path]

        if scripts:
            cmdline += ["--ro-bind", scripts, "/scripts"]

        tmp: Optional[Path]

        if not overlay and not relaxed:
            tmp = stack.enter_context(vartmpdir())
            yield [
                *cmdline,
                "--bind", tmp, "/var/tmp",
                "--dir", "/etc",
                "--dir", "/var",
                "--dir", "/tmp",
                "--dir", "/run",
                *options,
            ]  # fmt: skip
            return

        if overlay and (overlay / "etc").exists():
            cmdline += ["--ro-bind", overlay / "etc", "/etc"]
        else:
            cmdline += ["--dir", "/etc"]

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
                    *(["--overlay-workdir", os.fspath(work)] if work else []),
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
    root: Callable[[PathString], list[str]],
    network: bool = False,
    options: Sequence[PathString] = (),
) -> Iterator[list[PathString]]:
    with vartmpdir() as dir, resource_path(sys.modules[__package__ or __name__]) as module:
        cmdline: list[PathString] = [
            sys.executable, "-SI", module / "sandbox.py",
            *root("/"),
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

        yield [*cmdline, "--bind", dir, "/var/tmp", *options]


def finalize_interpreter(tools: bool) -> str:
    if tools:
        return "python3"

    exe = sys.executable
    if Path(exe).is_relative_to("/usr"):
        return exe

    return "python3"


def glob_in_sandbox(
    *globs: str,
    sandbox: AbstractContextManager[Sequence[PathString]] = contextlib.nullcontext([]),
) -> list[Path]:
    return [
        Path(s)
        for s in run(
            [
                "bash",
                "-c",
                rf"shopt -s nullglob && printf '%s\n' {' '.join(globs)} | xargs -r readlink -f",
            ],
            sandbox=sandbox,
            stdout=subprocess.PIPE,
        )
        .stdout.strip()
        .splitlines()
    ]


def exists_in_sandbox(
    path: PathString,
    sandbox: AbstractContextManager[Sequence[PathString]] = contextlib.nullcontext([]),
) -> bool:
    return (
        run(
            ["bash", "-c", rf"test -e {path}"],
            sandbox=sandbox,
            check=False,
        ).returncode
        == 0
    )
