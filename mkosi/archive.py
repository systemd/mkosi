# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Optional

from mkosi.log import log_step
from mkosi.run import SandboxProtocol, finalize_passwd_mounts, nosandbox, run, workdir
from mkosi.sandbox import umask
from mkosi.types import PathString
from mkosi.util import chdir


def tar_exclude_apivfs_tmp() -> list[str]:
    return [
        "--exclude", "./dev/*",
        "--exclude", "./proc/*",
        "--exclude", "./sys/*",
        "--exclude", "./tmp/*",
        "--exclude", "./run/*",
        "--exclude", "./var/tmp/*",
    ]  # fmt: skip


def make_tar(src: Path, dst: Path, *, sandbox: SandboxProtocol = nosandbox) -> None:
    log_step(f"Creating tar archive {dst}…")

    with dst.open("wb") as f:
        run(
            [
                "tar",
                "--create",
                "--file", "-",
                "--directory", workdir(src),
                "--acls",
                "--selinux",
                # --xattrs implies --format=pax
                "--xattrs",
                # PAX format emits additional headers for atime, ctime and mtime
                # that would make the archive non-reproducible.
                "--pax-option=delete=atime,delete=ctime,delete=mtime",
                "--sparse",
                "--force-local",
                *(["--owner=root:0"] if os.getuid() != 0 else []),
                *(["--group=root:0"] if os.getuid() != 0 else []),
                *tar_exclude_apivfs_tmp(),
                ".",
            ],
            stdout=f,
            # Make sure tar uses user/group information from the root directory instead of the host.
            sandbox=sandbox(
                binary="tar",
                options=["--ro-bind", src, workdir(src), *finalize_passwd_mounts(src)],
            ),
        )  # fmt: skip


def can_extract_tar(src: Path) -> bool:
    return ".tar" in src.suffixes[-2:]


def extract_tar(
    src: Path,
    dst: Path,
    *,
    log: bool = True,
    options: Sequence[PathString] = (),
    sandbox: SandboxProtocol = nosandbox,
) -> None:
    if log:
        log_step(f"Extracting tar archive {src}…")

    with umask(~0o755):
        dst.mkdir(exist_ok=True)

    run(
        [
            "tar",
            "--extract",
            "--file", workdir(src),
            "--directory", workdir(dst),
            "--keep-directory-symlink",
            "--no-overwrite-dir",
            "--same-permissions",
            "--same-owner" if (dst / "etc/passwd").exists() and os.getuid() == 0 else "--numeric-owner",
            "--same-order",
            "--acls",
            "--selinux",
            "--xattrs",
            "--force-local",
            *tar_exclude_apivfs_tmp(),
            *options,
        ],
        sandbox=sandbox(
            binary="tar",
            # Make sure tar uses user/group information from the root directory instead of the host.
            options=[
                "--ro-bind", src, workdir(src),
                "--bind", dst, workdir(dst),
                *finalize_passwd_mounts(dst),
            ],
        ),
    )  # fmt: skip


def make_cpio(
    src: Path,
    dst: Path,
    *,
    files: Optional[Iterable[Path]] = None,
    sandbox: SandboxProtocol = nosandbox,
) -> None:
    if not files:
        with chdir(src):
            files = sorted(Path(".").rglob("*"))
    else:
        files = sorted(files)

    log_step(f"Creating cpio archive {dst}…")

    with dst.open("wb") as f:
        run(
            [
                "cpio",
                "--create",
                "--reproducible",
                "--renumber-inodes",
                "--null",
                "--format=newc",
                "--quiet",
                "--directory", workdir(src),
                *(["--owner=0:0"] if os.getuid() != 0 else []),
            ],
            input="\0".join(os.fspath(f) for f in files),
            stdout=f,
            sandbox=sandbox(
                binary="cpio",
                options=["--ro-bind", src, workdir(src), *finalize_passwd_mounts(src)],
            ),
        )  # fmt: skip
