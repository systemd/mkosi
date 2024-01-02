# SPDX-License-Identifier: LGPL-2.1+

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Optional

from mkosi.context import Context
from mkosi.log import log_step
from mkosi.run import find_binary, run
from mkosi.sandbox import finalize_passwd_mounts


def tar_binary(context: Context) -> str:
    # Some distros (Mandriva) install BSD tar as "tar", hence prefer
    # "gtar" if it exists, which should be GNU tar wherever it exists.
    # We are interested in exposing same behaviour everywhere hence
    # it's preferable to use the same implementation of tar
    # everywhere. In particular given the limited/different SELinux
    # support in BSD tar and the different command line syntax
    # compared to GNU tar.
    return "gtar" if find_binary("gtar", root=context.config.tools()) else "tar"


def cpio_binary(context: Context) -> str:
    return "gcpio" if find_binary("gcpio", root=context.config.tools()) else "cpio"


def tar_exclude_apivfs_tmp() -> list[str]:
    return [
        "--exclude", "./dev/*",
        "--exclude", "./proc/*",
        "--exclude", "./sys/*",
        "--exclude", "./tmp/*",
        "--exclude", "./run/*",
        "--exclude", "./var/tmp/*",
    ]


def make_tar(context: Context, src: Path, dst: Path) -> None:
    log_step(f"Creating tar archive {dst}…")
    run(
        [
            tar_binary(context),
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
        sandbox=context.sandbox(
            options=[
                "--bind", dst.parent, dst.parent,
                "--ro-bind", src, src,
                *(finalize_passwd_mounts(src) if (src / "etc/passwd").exists() else []),
            ],
        ),
    )


def extract_tar(context: Context, src: Path, dst: Path, log: bool = True) -> None:
    if log:
        log_step(f"Extracting tar archive {src}…")
    run(
        [
            tar_binary(context),
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
        sandbox=context.sandbox(
            options=[
                "--bind", dst, dst,
                "--ro-bind", src, src,
                *(finalize_passwd_mounts(dst) if (dst / "etc/passwd").exists() else []),
            ],
        ),
    )


def make_cpio(context: Context, src: Path, dst: Path, files: Optional[Iterable[Path]] = None) -> None:
    if not files:
        files = src.rglob("*")
    files = sorted(files)

    log_step(f"Creating cpio archive {dst}…")
    run(
        [
            cpio_binary(context),
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
        sandbox=context.sandbox(
            options=[
                "--bind", dst.parent, dst.parent,
                "--ro-bind", src, src,
                *finalize_passwd_mounts(dst),
            ],
        ),
    )
