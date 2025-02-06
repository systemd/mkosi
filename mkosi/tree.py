# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import errno
import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

from mkosi.config import ConfigFeature
from mkosi.log import ARG_DEBUG, die
from mkosi.run import SandboxProtocol, nosandbox, run, workdir
from mkosi.sandbox import BTRFS_SUPER_MAGIC, OVERLAYFS_SUPER_MAGIC, statfs
from mkosi.util import PathString, flatten
from mkosi.versioncomp import GenericVersion


def is_subvolume(path: Path) -> bool:
    return path.is_dir() and path.stat().st_ino == 256 and statfs(str(path)) == BTRFS_SUPER_MAGIC


def cp_version(*, sandbox: SandboxProtocol = nosandbox) -> GenericVersion:
    return GenericVersion(
        run(
            ["cp", "--version"],
            sandbox=sandbox(),
            stdout=subprocess.PIPE,
        )
        .stdout.splitlines()[0]
        .split()[3]
    )


def make_tree(
    path: Path,
    *,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    sandbox: SandboxProtocol = nosandbox,
) -> Path:
    path = path.absolute()

    if statfs(str(path.parent)) != BTRFS_SUPER_MAGIC:
        if use_subvolumes == ConfigFeature.enabled:
            die(f"Subvolumes requested but {path} is not located on a btrfs filesystem")

        path.mkdir()
        return path

    if use_subvolumes != ConfigFeature.disabled:
        result = run(
            ["btrfs", "subvolume", "create", workdir(path, sandbox)],
            sandbox=sandbox(options=["--bind", path.parent, workdir(path.parent, sandbox)]),
            check=use_subvolumes == ConfigFeature.enabled,
        ).returncode
    else:
        result = 1

    if result != 0:
        path.mkdir()

    return path


@contextlib.contextmanager
def preserve_target_directories_stat(src: Path, dst: Path) -> Iterator[None]:
    dirs = [p for d in src.glob("**/") if (dst / (p := d.relative_to(src))).exists()]

    with tempfile.TemporaryDirectory() as tmp:
        for d in dirs:
            (tmp / d).mkdir(exist_ok=True)
            shutil.copystat(dst / d, tmp / d)

        yield

        for d in dirs:
            shutil.copystat(tmp / d, dst / d)


def copy_tree(
    src: Path,
    dst: Path,
    *,
    preserve: bool = True,
    dereference: bool = False,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    sandbox: SandboxProtocol = nosandbox,
) -> Path:
    src = src.absolute()
    dst = dst.absolute()

    options: list[PathString] = [
        "--ro-bind", src, workdir(src, sandbox),
        "--bind", dst.parent, workdir(dst.parent, sandbox),
    ]  # fmt: skip

    attrs = "mode,links"
    if preserve:
        attrs += ",timestamps,ownership"

        # Trying to copy selinux xattrs to overlayfs fails with "Operation not supported" in containers.
        if statfs(os.fspath(dst.parent)) != OVERLAYFS_SUPER_MAGIC or "security.selinux" not in os.listxattr(
            src
        ):
            attrs += ",xattr"

    def copy() -> None:
        cmdline: list[PathString] = [
            "cp",
            "--recursive",
            "--dereference" if dereference else "--no-dereference",
            f"--preserve={attrs}",
            "--reflink=auto",
            "--copy-contents",
            workdir(src, sandbox),
            workdir(dst, sandbox),
        ]

        if dst.exists() and dst.is_dir() and any(dst.iterdir()) and cp_version(sandbox=sandbox) >= "9.5":
            cmdline += ["--keep-directory-symlink"]

        # If the source and destination are both directories, we want to merge the source directory with the
        # destination directory. If the source if a file and the destination is a directory, we want to copy
        # the source inside the directory.
        if src.is_dir():
            cmdline += ["--no-target-directory"]

        run(cmdline, sandbox=sandbox(options=options))

    # Subvolumes always have inode 256 so we can use that to check if a directory is a subvolume.
    if (
        use_subvolumes == ConfigFeature.disabled
        or not preserve
        or not is_subvolume(src)
        or statfs(str(dst.parent)) != BTRFS_SUPER_MAGIC
        or (dst.exists() and (not dst.is_dir() or any(dst.iterdir())))
    ):
        with preserve_target_directories_stat(src, dst) if not preserve else contextlib.nullcontext():
            copy()

        return dst

    # btrfs can't snapshot to an existing directory so make sure the destination does not exist.
    if dst.exists():
        dst.rmdir()

    result = run(
        ["btrfs", "subvolume", "snapshot", workdir(src, sandbox), workdir(dst, sandbox)],
        check=use_subvolumes == ConfigFeature.enabled,
        sandbox=sandbox(options=options),
    ).returncode

    if result != 0:
        with preserve_target_directories_stat(src, dst) if not preserve else contextlib.nullcontext():
            copy()

    return dst


def rmtree(*paths: Path, sandbox: SandboxProtocol = nosandbox) -> None:
    if not paths:
        return

    paths = tuple(p.absolute() for p in paths)

    if subvolumes := sorted({p for p in paths if p.exists() and is_subvolume(p)}):
        # Silence and ignore failures since when not running as root, this will fail with a permission error
        # unless the btrfs filesystem is mounted with user_subvol_rm_allowed.
        run(
            ["btrfs", "subvolume", "delete", *(workdir(p, sandbox) for p in subvolumes)],
            check=False,
            sandbox=sandbox(
                options=flatten(("--bind", p.parent, workdir(p.parent, sandbox)) for p in subvolumes),
            ),
            stdout=subprocess.DEVNULL if not ARG_DEBUG.get() else None,
            stderr=subprocess.DEVNULL if not ARG_DEBUG.get() else None,
        )

    filtered = sorted({p for p in paths if p.exists() or p.is_symlink()})
    if filtered:
        run(
            ["rm", "-rf", "--", *(workdir(p, sandbox) for p in filtered)],
            sandbox=sandbox(
                options=flatten(("--bind", p.parent, workdir(p.parent, sandbox)) for p in filtered),
            ),
        )


def move_tree(
    src: Path,
    dst: Path,
    *,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    sandbox: SandboxProtocol = nosandbox,
) -> Path:
    src = src.absolute()
    dst = dst.absolute()

    if src == dst:
        return dst

    if dst.is_dir():
        dst = dst / src.name

    try:
        src.rename(dst)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise e

        logging.info(
            f"Could not rename {src} to {dst} as they are located on different devices, "
            "falling back to copying"
        )
        copy_tree(src, dst, use_subvolumes=use_subvolumes, sandbox=sandbox)
        rmtree(src, sandbox=sandbox)

    return dst
