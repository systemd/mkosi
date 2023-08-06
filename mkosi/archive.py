# SPDX-License-Identifier: LGPL-2.1+

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from mkosi.log import log_step
from mkosi.run import bwrap, finalize_passwd_mounts
from mkosi.util import tar_binary


def tar_exclude_apivfs_tmp() -> list[str]:
    return [
        "--exclude", "./dev/*",
        "--exclude", "./proc/*",
        "--exclude", "./sys/*",
        "--exclude", "./tmp/*",
        "--exclude", "./run/*",
        "--exclude", "./var/tmp/*",
    ]


def make_tar(src: Path, dst: Path) -> None:
    log_step(f"Creating tar archive {dst}…")
    bwrap(
        [
            tar_binary(),
            "--create",
            "--file", dst,
            "--directory", src,
            "--acls",
            "--selinux",
            "--xattrs",
            "--sparse",
            "--force-local",
            *tar_exclude_apivfs_tmp(),
            ".",
        ],
        # Make sure tar uses user/group information from the root directory instead of the host.
        options=finalize_passwd_mounts(src) if (src / "etc/passwd").exists() else [],
    )


def extract_tar(src: Path, dst: Path) -> None:
    log_step(f"Extracting tar archive {src}…")
    bwrap(
        [
            tar_binary(),
            "--extract",
            "--file", src,
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
        # Make sure tar uses user/group information from the root directory instead of the host.
        options=finalize_passwd_mounts(dst) if (dst / "etc/passwd").exists() else [],
    )


def make_cpio(src: Path, dst: Path, files: Optional[Iterable[Path]] = None) -> None:
    if not files:
        files = src.rglob("*")

    log_step(f"Creating cpio archive {dst}…")
    bwrap(
        [
            "cpio",
            "--create",
            "--reproducible",
            "--null",
            "--format=newc",
            "--quiet",
            "--directory", src,
            "-O", dst,
        ],
        input="\0".join(os.fspath(f.relative_to(src)) for f in files),
        # Make sure tar uses user/group information from the root directory instead of the host.
        options=finalize_passwd_mounts(dst),
    )
