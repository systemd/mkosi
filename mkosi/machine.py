# SPDX-License-Identifier: LGPL-2.1+

from __future__ import annotations

import contextlib
import signal
import subprocess
from textwrap import dedent
from typing import Any, Optional, Sequence

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
    prepend_to_environ_path,
    run_command_image,
    run_qemu_cmdline,
    run_shell_cmdline,
    unlink_output,
)
from .backend import MkosiArgs, Verb, die


class Machine:
    def __init__(self, args: Optional[Sequence[str]] = None, debug: bool = False) -> None:
        # Remains None until image is built and booted, then receives pexpect process
        self._serial: Optional[pexpect.spawn] = None
        self.exit_code: int = -1
        self.debug = debug
        self.stack = contextlib.ExitStack()
        self.args: MkosiArgs

        # We make sure to add the arguments in the machine class itself, rather than typing this for every testing function.
        tmp = parse_args(args)["default"]
        tmp.force = 1
        tmp.autologin = True
        if tmp.verb == Verb.qemu:
            tmp.bootable = True
            tmp.qemu_headless = True
            tmp.hostonly_initrd = True
            tmp.netdev = True
            tmp.ssh = True
        elif tmp.verb == Verb.boot:
            pass
        else:
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

    def ensure_booted(self) -> None:
        # Try to access the serial console which will raise an exception if the machine is not currently booted.
        assert self._serial is not None

    def __enter__(self) -> Machine:
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

        with contextlib.ExitStack() as stack:
            prepend_to_environ_path(self.args.extra_search_paths)

            if self.args.verb in (Verb.shell, Verb.boot):
                cmdline = run_shell_cmdline(self.args)
            elif self.args.verb == Verb.qemu:
                # We must keep the temporary file opened at run_qemu_cmdline accessible, hence the context stack.
                cmdline = stack.enter_context(run_qemu_cmdline(self.args))
            else:
                die("No valid verb was entered.")

            cmd = " ".join(str(x) for x in cmdline)

            # Here we have something equivalent to the command lines used on spawn() and run() from backend.py
            # We use pexpect to boot an image that we will be able to interact with in the future
            # Then we tell the process to look for the # sign, which indicates the CLI for that image is active
            # Once we've build/boot an image the CLI will prompt "root@image ~]# "
            # Then, when pexpects finds the '#' it means we're ready to interact with the process
            self._serial = pexpect.spawnu(cmd, logfile=None, timeout=240)
            self._serial.expect("#")
            self.stack = stack.pop_all()

        return self

    def run(self, commands: Sequence[str], timeout: int = 900, check: bool = True) -> CompletedProcess:
        self.ensure_booted()

        process = run_command_image(self.args, commands, timeout, check, subprocess.PIPE, subprocess.PIPE)
        if self.debug:
            print(f"Stdout:\n {process.stdout}")
            print(f"Stderr:\n {process.stderr}")

        return process

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        if self._serial:
            self._serial.kill(signal.SIGTERM)
            self.exit_code = self._serial.wait()
            self._serial = None
        self.stack.__exit__(*args, **kwargs)
