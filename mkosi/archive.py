# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Optional

from mkosi.log import log_step
from mkosi.run import SandboxProtocol, finalize_passwd_symlinks, nosandbox, run, workdir
from mkosi.sandbox import umask
from mkosi.util import PathString, chdir


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
                "--directory", workdir(src, sandbox),
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
                options=[
                    "--ro-bind", src, workdir(src, sandbox),
                    *finalize_passwd_symlinks(workdir(src, sandbox)),
                ],
            ),
        )  # fmt: skip


def can_extract_tar(src: Path) -> bool:
    return ".tar" in src.suffixes[-2:]


def extract_tar(
    src: Path,
    dst: Path,
    *,
    log: bool = True,
    dirs: Sequence[PathString] = (),
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
            "--file", workdir(src, sandbox),
            "--directory", workdir(dst, sandbox),
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
            *dirs,
        ],
        sandbox=sandbox(
            # Make sure tar uses user/group information from the root directory instead of the host.
            options=[
                "--ro-bind", src, workdir(src, sandbox),
                "--bind", dst, workdir(dst, sandbox),
                *finalize_passwd_symlinks(workdir(dst, sandbox)),
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
                "--directory", workdir(src, sandbox),
                *(["--owner=0:0"] if os.getuid() != 0 else []),
            ],
            input="\0".join(os.fspath(f) for f in files),
            stdout=f,
            sandbox=sandbox(
                options=[
                    "--ro-bind", src, workdir(src, sandbox),
                    *finalize_passwd_symlinks(workdir(src, sandbox))
                ],
            ),
        )  # fmt: skip
