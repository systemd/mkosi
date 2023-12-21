# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from mkosi.bubblewrap import bwrap
from mkosi.log import log_step
from mkosi.mounts import finalize_passwd_mounts
from mkosi.state import MkosiState


def tar_binary() -> str:
    # Some distros (Mandriva) install BSD tar as "tar", hence prefer
    # "gtar" if it exists, which should be GNU tar wherever it exists.
    # We are interested in exposing same behaviour everywhere hence
    # it's preferable to use the same implementation of tar
    # everywhere. In particular given the limited/different SELinux
    # support in BSD tar and the different command line syntax
    # compared to GNU tar.
    return "gtar" if shutil.which("gtar") else "tar"


def cpio_binary() -> str:
    return "gcpio" if shutil.which("gcpio") else "cpio"


def tar_exclude_apivfs_tmp() -> list[str]:
    return [
        "--exclude", "./dev/*",
        "--exclude", "./proc/*",
        "--exclude", "./sys/*",
        "--exclude", "./tmp/*",
        "--exclude", "./run/*",
        "--exclude", "./var/tmp/*",
    ]


def make_tar(state: MkosiState, src: Path, dst: Path) -> None:
    log_step(f"Creating tar archive {dst}…")
    bwrap(
        state,
        [
            tar_binary(),
            "--create",
            "--file", dst,
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
        # Make sure tar uses user/group information from the root directory instead of the host.
        options=finalize_passwd_mounts(src) if (src / "etc/passwd").exists() else [],
    )


def extract_tar(state: MkosiState, src: Path, dst: Path, log: bool = True) -> None:
    if log:
        log_step(f"Extracting tar archive {src}…")
    bwrap(
        state,
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


def make_cpio(state: MkosiState, src: Path, dst: Path, files: Optional[Iterable[Path]] = None) -> None:
    if not files:
        files = src.rglob("*")
    files = sorted(files)

    log_step(f"Creating cpio archive {dst}…")
    bwrap(
        state,
        [
            cpio_binary(),
            "--create",
            "--reproducible",
            "--null",
            "--format=newc",
            "--quiet",
            "--directory", src,
            "-O", dst,
        ],
        input="\0".join(os.fspath(f.relative_to(src)) for f in files),
        # Make sure cpio uses user/group information from the root directory instead of the host.
        options=finalize_passwd_mounts(dst),
    )
