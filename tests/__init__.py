# SPDX-License-Identifier: LGPL-2.1+

import os
import sys
import tempfile
from collections.abc import Sequence
from types import TracebackType
from typing import Optional

from mkosi.distributions import Distribution, detect_distribution
from mkosi.log import die
from mkosi.run import run
from mkosi.types import _FILE, CompletedProcess, PathString
from mkosi.util import INVOKING_USER


class Image:
    def __init__(self, options: Sequence[PathString] = []) -> None:
        self.options = options

        if d := os.getenv("MKOSI_TEST_DISTRIBUTION"):
            self.distribution = Distribution(d)
        elif detected := detect_distribution()[0]:
            self.distribution = detected
        else:
            die("Cannot detect host distribution, please set $MKOSI_TEST_DISTRIBUTION to be able to run the tests")

        if r := os.getenv("MKOSI_TEST_RELEASE"):
            self.release = r
        else:
            self.release = self.distribution.default_release()

    def __enter__(self) -> "Image":
        self.output_dir = tempfile.TemporaryDirectory(dir="/var/tmp")
        os.chown(self.output_dir.name, INVOKING_USER.uid, INVOKING_USER.gid)

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
    ) -> CompletedProcess:
        return run([
            "python3", "-m", "mkosi",
            "--distribution", str(self.distribution),
            "--release", self.release,
            *self.options,
            *options,
            "--output-dir", self.output_dir.name,
            "--cache-dir", "mkosi.cache",
            "--kernel-command-line=console=ttyS0",
            "--kernel-command-line=systemd.log_target=console",
            "--kernel-command-line=systemd.default_standard_output=journal+console",
            "--qemu-vsock=yes",
            "--qemu-mem=4G",
            verb,
            *args,
        ], stdin=stdin, stdout=sys.stdout, user=user, group=group)

    def build(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi(
            "build",
            [*options, "--debug", "--force"],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            user=INVOKING_USER.uid,
            group=INVOKING_USER.gid,
        )

    def boot(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi("boot", [*options, "--debug"], args, stdin=sys.stdin if sys.stdin.isatty() else None)

    def qemu(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi(
            "qemu",
            [*options, "--debug"],
            args,
            stdin=sys.stdin if sys.stdin.isatty() else None,
            user=INVOKING_USER.uid,
            group=INVOKING_USER.gid,
        )

    def summary(self, options: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi("summary", options, user=INVOKING_USER.uid, group=INVOKING_USER.gid)
