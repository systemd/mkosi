# SPDX-License-Identifier: LGPL-2.1+

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from mkosi.log import log_step
from mkosi.run import run
from mkosi.sandbox import Mount, SandboxProtocol, finalize_passwd_mounts, nosandbox
from mkosi.util import umask


def tar_exclude_apivfs_tmp() -> list[str]:
    return [
        "--exclude", "./dev/*",
        "--exclude", "./proc/*",
        "--exclude", "./sys/*",
        "--exclude", "./tmp/*",
        "--exclude", "./run/*",
        "--exclude", "./var/tmp/*",
    ]


def make_tar(src: Path, dst: Path, *, sandbox: SandboxProtocol = nosandbox) -> None:
    log_step(f"Creating tar archive {dst}…")

    with dst.open("wb") as f:
        run(
            [
                "tar",
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
            # Make sure tar uses user/group information from the root directory instead of the host.
            sandbox=sandbox(mounts=[Mount(src, src, ro=True), *finalize_passwd_mounts(src)]),
        )


def extract_tar(
    src: Path,
    dst: Path,
    *,
    log: bool = True,
    sandbox: SandboxProtocol = nosandbox,
) -> None:
    if log:
        log_step(f"Extracting tar archive {src}…")

    with umask(~0o755):
        dst.mkdir(exist_ok=True)

    with src.open("rb") as f:
        run(
            [
                "tar",
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
            sandbox=sandbox(
                # Make sure tar uses user/group information from the root directory instead of the host.
                mounts=[Mount(src, src, ro=True), Mount(dst, dst), *finalize_passwd_mounts(dst)]
            ),
        )


def make_cpio(
    src: Path,
    dst: Path,
    *,
    files: Optional[Iterable[Path]] = None,
    sandbox: SandboxProtocol = nosandbox,
) -> None:
    if not files:
        files = src.rglob("*")
    files = sorted(files)

    log_step(f"Creating cpio archive {dst}…")

    with dst.open("wb") as f:
        run(
            [
                "cpio",
                "--create",
                "--reproducible",
                "--null",
                "--format=newc",
                "--quiet",
                "--directory", src,
            ],
            input="\0".join(os.fspath(f.relative_to(src)) for f in files),
            stdout=f,
            sandbox=sandbox(mounts=[Mount(src, src, ro=True), *finalize_passwd_mounts(src)]),
        )
