# SPDX-License-Identifier: LGPL-2.1-or-later

import asyncio
import dataclasses
import os
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import TracebackType
from typing import Optional

from barrage import Singleton

import mkosi.resources
from mkosi.config import parse_config
from mkosi.distribution import Distribution
from mkosi.run import CompletedProcess, run
from mkosi.tree import rmtree
from mkosi.user import INVOKING_USER
from mkosi.util import _FILE, PathString, resource_path


@dataclasses.dataclass(frozen=True)
class ImageConfig:
    distribution: Distribution
    release: str
    debug_shell: bool


class ImageConfigManager(Singleton):
    """Provide the integration test ImageConfig

    The distribution and release are read from mkosi.local.conf as written by
    tools/integration-test-setup.sh.
    """

    config: ImageConfig

    async def __aenter__(self) -> "ImageConfigManager":
        if not Path("mkosi.local.conf").exists():
            raise RuntimeError(
                "mkosi.local.conf not found: run 'tools/integration-test-setup.sh "
                "<distribution> <tools-tree-distribution>' to configure and build the image before "
                "running the integration tests."
            )

        with resource_path(mkosi.resources) as resources:
            config = parse_config(resources=resources)[2][0]
        self.config = ImageConfig(
            distribution=config.distribution,
            release=config.release,
            debug_shell=bool(os.getenv("TEST_DEBUG_SHELL")),
        )
        return self


class Image:
    def __init__(self, config: ImageConfig) -> None:
        self.config = config

    def __enter__(self) -> "Image":
        if (cache := INVOKING_USER.cache_dir() / "mkosi") and os.access(cache, os.W_OK):
            tmpdir = cache
        else:
            tmpdir = Path("/var/tmp")

        token = uuid.uuid4().hex[:16]
        self.output_dir = Path(os.getenv("TMPDIR", tmpdir)) / token
        # Unique VM name to support parallel runs; CID name is derived from machine name
        self.machine = f"mkosi-{token}"

        return self

    def __exit__(
        self,
        type: Optional[type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        rmtree(self.output_dir)

    async def mkosi(
        self,
        verb: str,
        options: Sequence[PathString] = (),
        args: Sequence[str] = (),
        stdin: _FILE = None,
        check: bool = True,
        env: Mapping[str, str] = {},
    ) -> CompletedProcess:
        # mkosi.run.run() is synchronous, so run it in a worker thread.
        # Safe because the test-level invocation uses no sandbox (and thus no preexec_fn) and installs no
        # signal handlers; all sandboxing happens inside the spawned mkosi subprocess.
        return await asyncio.to_thread(
            run,
            [
                "python3", "-m", "mkosi",
                "--debug",
                *options,
                verb,
                *args,
            ],
            check=check,
            stdin=stdin,
            stdout=sys.stdout,
            env={**os.environ, **env},
        )  # fmt: skip

    async def build(
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

        await self.mkosi("summary", opt, env=env)

        return await self.mkosi(
            "build",
            opt,
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            env=env,
        )

    async def boot(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        result = await self.mkosi(
            "boot",
            [
                "--runtime-build-sources=no",
                "--ephemeral=yes",
                "--register=no",
                "--machine",
                self.machine,
                "--output-directory",
                self.output_dir,
                *options,
            ],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            check=False,
        )

        if result.returncode != 123:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

        return result

    async def vm(
        self, options: Sequence[str] = (), args: Sequence[str] = (), ram: str = "1536M"
    ) -> CompletedProcess:
        need_hyperv_workaround = os.uname().machine == "x86_64"

        result = await self.mkosi(
            "vm",
            [
                "--runtime-build-sources=no",
                "--vsock=yes",
                # TODO: Drop once both Hyper-V bugs are fixed in Github Actions.
                *(["--qemu-args=-cpu max,pcid=off"] if need_hyperv_workaround else []),
                f"--ram={ram}",
                "--ephemeral=yes",
                "--register=no",
                "--machine",
                self.machine,
                "--output-directory",
                self.output_dir,
                *options,
            ],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            check=False,
        )

        if result.returncode != 123:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

        return result
