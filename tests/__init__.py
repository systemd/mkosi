# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import dataclasses
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, Optional

import pytest

from mkosi.distributions import Distribution
from mkosi.run import CompletedProcess, fork_and_wait, run
from mkosi.sandbox import acquire_privileges
from mkosi.tree import rmtree
from mkosi.user import INVOKING_USER
from mkosi.util import _FILE, PathString


@dataclasses.dataclass(frozen=True)
class ImageConfig:
    distribution: Distribution
    release: str
    debug_shell: bool
    tools: Optional[Path]


class Image:
    def __init__(self, config: ImageConfig) -> None:
        self.config = config

    def __enter__(self) -> "Image":
        if (cache := INVOKING_USER.cache_dir()) and os.access(cache, os.W_OK):
            tmpdir = cache
        else:
            tmpdir = Path("/var/tmp")

        self.output_dir = Path(os.getenv("TMPDIR", tmpdir)) / uuid.uuid4().hex[:16]

        return self

    def __exit__(
        self,
        type: Optional[type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        def clean() -> None:
            acquire_privileges()
            rmtree(self.output_dir)

        fork_and_wait(clean)

    def mkosi(
        self,
        verb: str,
        options: Sequence[PathString] = (),
        args: Sequence[str] = (),
        stdin: _FILE = None,
        check: bool = True,
        env: Mapping[str, str] = {},
    ) -> CompletedProcess:
        return run(
            [
                "python3", "-m", "mkosi",
                *(["--tools-tree", os.fspath(self.config.tools)] if self.config.tools else []),
                "--debug",
                *options,
                verb,
                *args,
            ],
            check=check,
            stdin=stdin,
            stdout=sys.stdout,
            env=os.environ | env,
        )  # fmt: skip

    def build(
        self,
        options: Sequence[PathString] = (),
        args: Sequence[str] = (),
        env: Mapping[str, str] = {},
    ) -> CompletedProcess:
        kcl = [
            "loglevel=6",
            "systemd.log_level=debug",
            "udev.log_level=info",
            "systemd.show_status=false",
            "systemd.journald.forward_to_console",
            "systemd.journald.max_level_console=info",
            "systemd.firstboot=no",
            "systemd.unit=mkosi-check-and-shutdown.service",
        ]

        opt: list[PathString] = [
            "--distribution", str(self.config.distribution),
            "--release", self.config.release,
            *(f"--kernel-command-line={i}" for i in kcl),
            "--force",
            "--incremental=strict",
            "--output-directory", self.output_dir,
            *(["--debug-shell"] if self.config.debug_shell else []),
            *options,
        ]  # fmt: skip

        self.mkosi("summary", opt, env=env)

        return self.mkosi(
            "build",
            opt,
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            env=env,
        )

    def boot(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        result = self.mkosi(
            "boot",
            [
                "--runtime-build-sources=no",
                "--ephemeral=yes",
                "--register=no",
                *options,
            ],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            check=False,
        )

        if result.returncode != 123:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

        return result

    def vm(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        result = self.mkosi(
            "vm",
            [
                "--runtime-build-sources=no",
                "--vsock=yes",
                # TODO: Drop once both Hyper-V bugs are fixed in Github Actions.
                "--qemu-args=-cpu max,pcid=off",
                "--ram=2G",
                "--ephemeral=yes",
                "--register=no",
                *options,
            ],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            check=False,
        )

        if result.returncode != 123:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

        return result

    def genkey(self) -> CompletedProcess:
        return self.mkosi("genkey", ["--force"])


@pytest.fixture(scope="session", autouse=True)
def suspend_capture_stdin(pytestconfig: Any) -> Iterator[None]:
    """
    When --capture=no (or -s) is specified, pytest will still intercept
    stdin. Let's explicitly make it not capture stdin when --capture=no is
    specified so we can debug image boot failures by logging into the emergency
    shell.
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
