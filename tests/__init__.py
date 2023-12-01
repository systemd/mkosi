# SPDX-License-Identifier: LGPL-2.1+

import os
import tempfile
from collections.abc import Sequence
from types import TracebackType
from typing import Optional

from mkosi.distributions import Distribution, detect_distribution
from mkosi.log import die
from mkosi.run import run
from mkosi.types import CompletedProcess
from mkosi.util import INVOKING_USER


class Image:
    def __init__(self, options: Sequence[str] = []) -> None:
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
        options: Sequence[str] = (),
        args: Sequence[str] = (),
        user: Optional[int] = None,
        group: Optional[int] = None,
    ) -> CompletedProcess:
        return run([
            "python3", "-m", "mkosi",
            *self.options,
            *options,
            "--output-dir", self.output_dir.name,
            "--cache-dir", "mkosi.cache",
            "--debug",
            "--distribution", str(self.distribution),
            "--release", self.release,
            verb,
            *args,
        ], user=user, group=group)

    def build(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi("build", [*options, "--force"], args, user=INVOKING_USER.uid, group=INVOKING_USER.gid)

    def boot(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi("boot", options, args)

    def qemu(self, options: Sequence[str] = (), args: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi("qemu", options, args, user=INVOKING_USER.uid, group=INVOKING_USER.gid)

    def summary(self, options: Sequence[str] = ()) -> CompletedProcess:
        return self.mkosi("summary", options, user=INVOKING_USER.uid, group=INVOKING_USER.gid)
