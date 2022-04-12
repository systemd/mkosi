# SPDX-License-Identifier: LGPL-2.1+

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import unittest
from textwrap import dedent
from typing import Any, Iterator, Optional, Sequence, TextIO, Union

import pexpect  # type: ignore

from . import (
    MKOSI_COMMANDS_SUDO,
    CompletedProcess,
    build_stuff,
    check_native,
    check_output,
    check_root,
    init_namespace,
    load_args,
    needs_build,
    parse_args,
    parse_boolean,
    prepend_to_environ_path,
    run_command_image,
    run_qemu_cmdline,
    run_shell_cmdline,
    unlink_output,
)
from .backend import MkosiArgs, MkosiNotSupportedException, Verb, die


class Machine:
    def __init__(self, args: Sequence[str] = []) -> None:
        # Remains None until image is built and booted, then receives pexpect process.
        self._serial: Optional[pexpect.spawn] = None
        self.exit_code: int = -1
        self.stack = contextlib.ExitStack()
        self.args: MkosiArgs

        tmp = parse_args(args)["default"]

        # By default, Mkosi makes Verb = build.
        # But we want to know if a test class passed args without a Verb.
        # If so, we'd like to assign default values or the environment's variable value.
        if tmp.verb == Verb.build and Verb.build.name not in args:
            verb = os.getenv("MKOSI_TEST_DEFAULT_VERB")
            # This way, if environment variable is not set, we assign nspawn by default to test classes with no Verb.
            if verb in (Verb.boot.name, None):
                tmp.verb = Verb.boot
            elif verb == Verb.qemu.name:
                tmp.verb = Verb.qemu
            elif verb == Verb.shell.name:
                tmp.verb = Verb.shell
            else:
                die("No valid verb was entered.")

        # Add the arguments in the machine class itself, rather than typing this for every testing function.
        tmp.force = 1
        tmp.autologin = True
        tmp.ephemeral = True
        if tmp.verb == Verb.qemu:
            tmp.bootable = True
            tmp.qemu_headless = True
            tmp.netdev = True
            tmp.ssh = True
            tmp.ssh_timeout = 240
        elif tmp.verb not in (Verb.shell, Verb.boot):
            die("No valid verb was entered.")

        self.args = load_args(tmp)

    @property
    def serial(self) -> pexpect.spawn:
        if self._serial is None:
            raise ValueError(
                        dedent(
                            """\
                            Trying to access serial console before machine boot or after machine shutdown.
                            In order to boot the machine properly, use it as a context manager.
                            Then, a Mkosi image will be booted in the __enter__ method.
                            """
                        )
                    )
        return self._serial

    def _ensure_booted(self) -> None:
        # Try to access the serial console which will raise an exception if the machine is not currently booted.
        assert self._serial is not None or self.args.verb == Verb.shell

    def build(self) -> None:
        if self.args.verb in MKOSI_COMMANDS_SUDO:
            check_root()
            unlink_output(self.args)

        if self.args.verb == Verb.build:
            check_output(self.args)

        if needs_build(self.args):
            check_root()
            check_native(self.args)
            init_namespace(self.args)
            build_stuff(self.args)

    def __enter__(self) -> Machine:
        self.build()
        self.boot()

        return self

    def boot(self) -> None:
        if self.args.verb == Verb.shell:
            return

        with contextlib.ExitStack() as stack:
            prepend_to_environ_path(self.args.extra_search_paths)

            if self.args.verb == Verb.boot:
                cmdline = run_shell_cmdline(self.args)
            elif self.args.verb == Verb.qemu:
                # We must keep the temporary file opened at run_qemu_cmdline accessible, hence the context stack.
                cmdline = stack.enter_context(run_qemu_cmdline(self.args))
            else:
                die("No valid verb was entered.")

            cmd = " ".join(str(x) for x in cmdline)

            # Here we have something equivalent to the command lines used on spawn() and run() from backend.py.
            # We use pexpect to boot an image that we will be able to interact with in the future.
            # Then we tell the process to look for the # sign, which indicates the CLI for that image is active.
            # Once we've build/boot an image the CLI will prompt "root@image ~]# ".
            # Then, when pexpects finds the '#' it means we're ready to interact with the process.
            self._serial = pexpect.spawnu(cmd, logfile=sys.stdout, timeout=240)
            self._serial.expect("#")
            self.stack = stack.pop_all()

    def run(
        self,
        commands: Sequence[str],
        timeout: int = 900,
        check: bool = True,
        capture_output: bool = False,
    ) -> CompletedProcess:
        self._ensure_booted()

        stdout: Union[int, TextIO] = subprocess.PIPE if capture_output else sys.stdout
        stderr: Union[int, TextIO] = subprocess.PIPE if capture_output else sys.stderr

        return run_command_image(self.args, commands, timeout, check, stdout, stderr)

    def kill(self) -> None:
        self.__exit__(None, None, None)

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        if self._serial:
            self._serial.kill(signal.SIGTERM)
            self.exit_code = self._serial.wait()
            self._serial = None
        self.stack.__exit__(*args, **kwargs)


@contextlib.contextmanager
def skip_not_supported() -> Iterator[None]:
    """See if load_args() raises exception about args and added configurations on __init__()."""
    try:
        yield
    except MkosiNotSupportedException as exception:
        raise unittest.SkipTest(str(exception))


class MkosiMachineTest(unittest.TestCase):
    args: Sequence[str]
    machine: Machine

    def __init_subclass__(cls, args: Sequence[str] = []) -> None:
        cls.args = args

    @classmethod
    def setUpClass(cls) -> None:
        with skip_not_supported():
            cls.machine = Machine(cls.args)

        verb = cls.machine.args.verb
        no_nspawn = parse_boolean(os.getenv("MKOSI_TEST_NO_NSPAWN", "0"))
        no_qemu = parse_boolean(os.getenv("MKOSI_TEST_NO_QEMU", "0"))

        if no_nspawn and verb == Verb.boot:
            raise unittest.SkipTest("Nspawn test skipped due to environment variable.")
        if no_qemu and verb == Verb.qemu:
            raise unittest.SkipTest("Qemu test skipped due to environment variable.")

        cls.machine.build()

    def setUp(self) -> None:
        # Replacing underscores which makes name invalid.
        # Necessary for shell otherwise racing conditions to the disk image will happen.
        test_name = self.id().split(".")[3]
        self.machine.args.hostname = test_name.replace("_", "-")
        self.machine.boot()

    def tearDown(self) -> None:
        self.machine.kill()
