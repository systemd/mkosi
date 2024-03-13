# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import errno
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

from mkosi.config import ConfigFeature
from mkosi.log import ARG_DEBUG, die
from mkosi.run import find_binary, run
from mkosi.sandbox import SandboxProtocol, nosandbox
from mkosi.types import PathString
from mkosi.util import flatten
from mkosi.versioncomp import GenericVersion


def statfs(path: Path, *, sandbox: SandboxProtocol = nosandbox) -> str:
    return run(["stat", "--file-system", "--format", "%T", path],
               sandbox=sandbox(options=["--ro-bind", path, path]), stdout=subprocess.PIPE).stdout.strip()


def is_subvolume(path: Path, *, sandbox: SandboxProtocol = nosandbox) -> bool:
    return path.is_dir() and path.stat().st_ino == 256 and statfs(path, sandbox=sandbox) == "btrfs"


def cp_version(*, sandbox: SandboxProtocol = nosandbox) -> GenericVersion:
    return GenericVersion(
        run(["cp", "--version"], sandbox=sandbox(), stdout=subprocess.PIPE).stdout.splitlines()[0].split()[3]
    )


def make_tree(
    path: Path,
    *,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    tools: Path = Path("/"),
    sandbox: SandboxProtocol = nosandbox,
) -> Path:
    if use_subvolumes == ConfigFeature.enabled and not find_binary("btrfs", root=tools):
        die("Subvolumes requested but the btrfs command was not found")

    if statfs(path.parent, sandbox=sandbox) != "btrfs":
        if use_subvolumes == ConfigFeature.enabled:
            die(f"Subvolumes requested but {path} is not located on a btrfs filesystem")

        path.mkdir()
        return path

    if use_subvolumes != ConfigFeature.disabled and find_binary("btrfs", root=tools) is not None:
        result = run(["btrfs", "subvolume", "create", path],
                     sandbox=sandbox(options=["--bind", path.parent, path.parent]),
                     check=use_subvolumes == ConfigFeature.enabled).returncode
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
    tools: Path = Path("/"),
    sandbox: SandboxProtocol = nosandbox,
) -> Path:
    subvolume = (use_subvolumes == ConfigFeature.enabled or
                 use_subvolumes == ConfigFeature.auto and find_binary("btrfs", root=tools) is not None)

    if use_subvolumes == ConfigFeature.enabled and not find_binary("btrfs", root=tools):
        die("Subvolumes requested but the btrfs command was not found")

    copy: list[PathString] = [
        "cp",
        "--recursive",
        "--dereference" if dereference else "--no-dereference",
        f"--preserve=mode,links{',timestamps,ownership,xattr' if preserve else ''}",
        "--reflink=auto",
        "--copy-contents",
        src, dst,
    ]
    if cp_version(sandbox=sandbox) >= "9.5":
        copy += ["--keep-directory-symlink"]

    options: list[PathString] = ["--ro-bind", src, src, "--bind", dst.parent, dst.parent]

    # If the source and destination are both directories, we want to merge the source directory with the
    # destination directory. If the source if a file and the destination is a directory, we want to copy
    # the source inside the directory.
    if src.is_dir():
        copy += ["--no-target-directory"]

    # Subvolumes always have inode 256 so we can use that to check if a directory is a subvolume.
    if (
        not subvolume or
        not preserve or
        not is_subvolume(src, sandbox=sandbox) or
        not find_binary("btrfs", root=tools) or
        (dst.exists() and any(dst.iterdir()))
    ):
        with (
            preserve_target_directories_stat(src, dst)
            if not preserve
            else contextlib.nullcontext()
        ):
            run(copy, sandbox=sandbox(options=options))
        return dst

    # btrfs can't snapshot to an existing directory so make sure the destination does not exist.
    if dst.exists():
        dst.rmdir()

    result = run(["btrfs", "subvolume", "snapshot", src, dst],
                 check=use_subvolumes == ConfigFeature.enabled, sandbox=sandbox(options=options)).returncode
    if result != 0:
        with (
            preserve_target_directories_stat(src, dst)
            if not preserve
            else contextlib.nullcontext()
        ):
            run(copy, sandbox=sandbox(options=options))

    return dst


def rmtree(*paths: Path, tools: Path = Path("/"), sandbox: SandboxProtocol = nosandbox) -> None:
    if not paths:
        return

    if find_binary("btrfs", root=tools) and (subvolumes := [p for p in paths if is_subvolume(p)]):
        parents = sorted(set(p.parent for p in subvolumes))
        parents = [p for p in parents if all(p == q or not p.is_relative_to(q) for q in parents)]

        # Silence and ignore failures since when not running as root, this will fail with a permission error unless the
        # btrfs filesystem is mounted with user_subvol_rm_allowed.
        run(["btrfs", "subvolume", "delete", *subvolumes],
            check=False,
            sandbox=sandbox(options=flatten(["--bind", p, p] for p in parents)),
            stdout=subprocess.DEVNULL if not ARG_DEBUG.get() else None,
            stderr=subprocess.DEVNULL if not ARG_DEBUG.get() else None)

    paths = tuple(p for p in paths if p.exists())
    if paths:
        parents = sorted(set(p.parent for p in paths))
        parents = [p for p in parents if all(p == q or not p.is_relative_to(q) for q in parents)]
        run(["rm", "-rf", "--", *paths],
            sandbox=sandbox(options=flatten(["--bind", p, p] for p in parents)))


def move_tree(
    src: Path,
    dst: Path,
    *,
    use_subvolumes: ConfigFeature = ConfigFeature.disabled,
    tools: Path = Path("/"),
    sandbox: SandboxProtocol = nosandbox
) -> Path:
    if src == dst:
        return dst

    if dst.is_dir():
        dst = dst / src.name

    try:
        src.rename(dst)
    except OSError as e:
        if e.errno != errno.EXDEV:
            raise e

        copy_tree(src, dst, use_subvolumes=use_subvolumes, tools=tools, sandbox=sandbox)
        rmtree(src, tools=tools, sandbox=sandbox)

    return dst
