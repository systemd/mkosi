# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, NamedTuple, Optional

import pytest

from mkosi.config import Architecture, finalize_term
from mkosi.distributions import Distribution
from mkosi.run import run
from mkosi.types import _FILE, CompletedProcess, PathString
from mkosi.user import INVOKING_USER


class Image:
    class Config(NamedTuple):
        distribution: Distribution
        release: str
        tools_tree_distribution: Optional[Distribution]
        tools_tree_release: Optional[str]
        debug_shell: bool

    def __init__(self, config: Config, options: Sequence[PathString] = []) -> None:
        self.options = options
        self.config = config

    def __enter__(self) -> "Image":
        self.output_dir = Path(os.getenv("TMPDIR", "/var/tmp")) / uuid.uuid4().hex[:16]

        return self

    def __exit__(
        self,
        type: Optional[type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.mkosi("clean", user=INVOKING_USER.uid, group=INVOKING_USER.gid)

    def mkosi(
        self,
        verb: str,
        options: Sequence[PathString] = (),
        args: Sequence[str] = (),
        stdin: _FILE = None,
        user: Optional[int] = None,
        group: Optional[int] = None,
        check: bool = True,
    ) -> CompletedProcess:
        kcl = [
            f"console={Architecture.native().default_serial_tty()}",
            f"TERM={finalize_term()}",
            "loglevel=6",
            "systemd.crash_shell",
            "systemd.log_level=debug",
            "udev.log_level=info",
            "systemd.log_ratelimit_kmsg=0",
            "systemd.show_status=false",
            "systemd.journald.forward_to_console",
            "systemd.journald.max_level_console=info",
            "printk.devkmsg=on",
            "systemd.early_core_pattern=/core",
        ]

        return run([
            "python3", "-m", "mkosi",
            "--distribution", str(self.config.distribution),
            "--release", self.config.release,
            *(["--tools-tree=default"] if self.config.tools_tree_distribution else []),
            *(
                ["--tools-tree-distribution", str(self.config.tools_tree_distribution)]
                if self.config.tools_tree_distribution
                else []
            ),
            *(["--tools-tree-release", self.config.tools_tree_release] if self.config.tools_tree_release else []),
            *self.options,
            *options,
            "--output-dir", self.output_dir,
            # Some tests ignore the default image config but we still want them to reuse the cache directory for the
            # tools tree cache.
            "--cache-dir", "mkosi.cache",
            *(f"--kernel-command-line={i}" for i in kcl),
            "--qemu-vsock=yes",
            # TODO: Drop once both Hyper-V bugs are fixed in Github Actions.
            "--qemu-args=-cpu max,pcid=off",
            "--qemu-mem=2G",
            verb,
            *args,
        ], check=check, stdin=stdin, stdout=sys.stdout, user=user, group=group)

    def build(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi(
            "build",
            [*options, "--debug", "--force", *(["--debug-shell"] if self.config.debug_shell else [])],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            user=INVOKING_USER.uid,
            group=INVOKING_USER.gid,
        )

    def boot(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        result = self.mkosi(
            "boot",
            [*options, "--debug"],
            args, stdin=sys.stdin if sys.stdin.isatty() else None,
            check=False,
        )

        if result.returncode != 123:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

        return result

    def qemu(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        result = self.mkosi(
            "qemu",
            [*options, "--debug"],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            user=INVOKING_USER.uid,
            group=INVOKING_USER.gid,
            check=False,
        )

        rc = 0 if self.config.distribution.is_centos_variant() else 123

        if result.returncode != rc:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

        return result

    def vmspawn(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        result = self.mkosi(
            "vmspawn",
            [*options, "--debug"],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            check=False,
        )

        rc = 0 if self.config.distribution.is_centos_variant() else 123

        if result.returncode != rc:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

        return result

    def summary(self, options: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi("summary", options, user=INVOKING_USER.uid, group=INVOKING_USER.gid)

    def genkey(self) -> CompletedProcess:
        return self.mkosi("genkey", ["--force"], user=INVOKING_USER.uid, group=INVOKING_USER.gid)


@pytest.fixture(scope="session", autouse=True)
def suspend_capture_stdin(pytestconfig: Any) -> Iterator[None]:
    """
    When --capture=no (or -s) is specified, pytest will still intercept stdin. Let's explicitly make it not capture
    stdin when --capture=no is specified so we can debug image boot failures by logging into the emergency shell.
    """

    capmanager: Any = pytestconfig.pluginmanager.getplugin("capturemanager")

    if pytestconfig.getoption("capture") == "no":
        capmanager.suspend_global_capture(in_=True)

    yield

    if pytestconfig.getoption("capture") == "no":
        capmanager.resume_global_capture()


@contextlib.contextmanager
def ci_group(s: str) -> Iterator[None]:
    github_actions = os.getenv("GITHUB_ACTIONS")
    if github_actions:
        print(f"\n::group::{s}", flush=True)
    try:
        yield
    finally:
        if github_actions:
            print("\n::endgroup::", flush=True)
