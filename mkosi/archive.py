# SPDX-License-Identifier: LGPL-2.1+

import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Optional

from mkosi.log import log_step
from mkosi.run import find_binary, run
from mkosi.types import PathString


def tar_binary(*, tools: Path = Path("/")) -> str:
    # Some distros (Mandriva) install BSD tar as "tar", hence prefer
    # "gtar" if it exists, which should be GNU tar wherever it exists.
    # We are interested in exposing same behaviour everywhere hence
    # it's preferable to use the same implementation of tar
    # everywhere. In particular given the limited/different SELinux
    # support in BSD tar and the different command line syntax
    # compared to GNU tar.
    return "gtar" if find_binary("gtar", root=tools) else "tar"


def cpio_binary(*, tools: Path = Path("/")) -> str:
    return "gcpio" if find_binary("gcpio", root=tools) else "cpio"


def tar_exclude_apivfs_tmp() -> list[str]:
    return [
        "--exclude", "./dev/*",
        "--exclude", "./proc/*",
        "--exclude", "./sys/*",
        "--exclude", "./tmp/*",
        "--exclude", "./run/*",
        "--exclude", "./var/tmp/*",
    ]


def make_tar(src: Path, dst: Path, *, tools: Path = Path("/"), sandbox: Sequence[PathString] = ()) -> None:
    log_step(f"Creating tar archive {dst}…")

    with dst.open("wb") as f:
        run(
            [
                tar_binary(tools=tools),
                "--create",
                "--file", "-",
                "--directory", src,
                "--acls",
                "--selinux",
                # --xattrs implies --format=pax
                "--xattrs",
                # PAX format emits additional headers for atime, ctime and mtime
                # that would make the archive non-reproducible.
                "--pax-option=delete=atime,delete=ctime,delete=mtime",
                "--sparse",
                "--force-local",
                *tar_exclude_apivfs_tmp(),
                ".",
            ],
            stdout=f,
            sandbox=sandbox,
        )


def extract_tar(
    src: Path,
    dst: Path,
    *,
    log: bool = True,
    tools: Path = Path("/"),
    sandbox: Sequence[PathString] = (),
) -> None:
    if log:
        log_step(f"Extracting tar archive {src}…")

    with src.open("rb") as f:
        run(
            [
                tar_binary(tools=tools),
                "--extract",
                "--file", "-",
                "--directory", dst,
                "--keep-directory-symlink",
                "--no-overwrite-dir",
                "--same-permissions",
                "--same-owner" if (dst / "etc/passwd").exists() else "--numeric-owner",
                "--same-order",
                "--acls",
                "--selinux",
                "--xattrs",
                "--force-local",
                *tar_exclude_apivfs_tmp(),
            ],
            stdin=f,
            sandbox=sandbox,
        )


def make_cpio(
    src: Path,
    dst: Path,
    *,
    files: Optional[Iterable[Path]] = None,
    tools: Path = Path("/"),
    sandbox: Sequence[PathString] = (),
) -> None:
    if not files:
        files = src.rglob("*")
    files = sorted(files)

    log_step(f"Creating cpio archive {dst}…")

    with dst.open("wb") as f:
        run(
            [
                cpio_binary(tools=tools),
                "--create",
                "--reproducible",
                "--null",
                "--format=newc",
                "--quiet",
                "--directory", src,
            ],
            input="\0".join(os.fspath(f.relative_to(src)) for f in files),
            stdout=f,
            # Make sure cpio uses user/group information from the root directory instead of the host.
            sandbox=sandbox,
        )
