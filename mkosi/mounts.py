# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import platform
import stat
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Optional

from mkosi.config import Config
from mkosi.run import run
from mkosi.types import PathString
from mkosi.util import umask
from mkosi.versioncomp import GenericVersion


def stat_is_whiteout(st: os.stat_result) -> bool:
    return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0


def delete_whiteout_files(path: Path) -> None:
    """Delete any char(0,0) device nodes underneath @path

    Overlayfs uses such files to mark "whiteouts" (files present in
    the lower layers, but removed in the upper one).
    """
    for entry in path.rglob("*"):
        # TODO: Use Path.stat() once we depend on Python 3.10+.
        if stat_is_whiteout(os.stat(entry, follow_symlinks=False)):
            entry.unlink()


@contextlib.contextmanager
def mount(
    what: PathString,
    where: Path,
    operation: Optional[str] = None,
    options: Sequence[str] = (),
    type: Optional[str] = None,
    read_only: bool = False,
    lazy: bool = False,
    umount: bool = True,
) -> Iterator[Path]:
    if not where.exists():
        with umask(~0o755):
            where.mkdir(parents=True)

    if read_only:
        options = ["ro", *options]

    cmd: list[PathString] = ["mount", "--no-mtab"]

    if operation:
        cmd += [operation]

    cmd += [what, where]

    if type:
        cmd += ["--types", type]

    if options:
        cmd += ["--options", ",".join(options)]

    try:
        run(cmd)
        yield where
    finally:
        if umount:
            run(["umount", "--no-mtab", *(["--lazy"] if lazy else []), where])


@contextlib.contextmanager
def mount_overlay(
    lowerdirs: Sequence[Path],
    upperdir: Optional[Path] = None,
    where: Optional[Path] = None,
    lazy: bool = False,
) -> Iterator[Path]:
    with contextlib.ExitStack() as stack:
        if upperdir is None:
            upperdir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="volatile-overlay")))
            st = lowerdirs[-1].stat()
            os.chmod(upperdir, st.st_mode)
            os.chown(upperdir, st.st_uid, st.st_gid)

        workdir = Path(
            stack.enter_context(tempfile.TemporaryDirectory(dir=upperdir.parent, prefix=f"{upperdir.name}-workdir"))
        )

        if where is None:
            where = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(dir=upperdir.parent, prefix=f"{upperdir.name}-mountpoint")
                )
            )

        options = [
            f"lowerdir={':'.join(os.fspath(p) for p in reversed(lowerdirs))}",
            f"upperdir={upperdir}",
            f"workdir={workdir}",
            # Disable the inodes index and metacopy (only copy metadata upwards if possible)
            # options. If these are enabled (e.g., if the kernel enables them by default),
            # the mount will fail if the upper directory has been earlier used with a different
            # lower directory, such as with a build overlay that was generated on top of a
            # different temporary root.
            # See https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html#sharing-and-copying-layers
            # and https://github.com/systemd/mkosi/issues/1841.
            "index=off",
            "metacopy=off"
        ]

        # userxattr is only supported on overlayfs since kernel 5.11
        if GenericVersion(platform.release()) >= GenericVersion("5.11"):
            options.append("userxattr")

        try:
            with mount("overlay", where, options=options, type="overlay", lazy=lazy):
                yield where
        finally:
            delete_whiteout_files(upperdir)


def finalize_source_mounts(config: Config) -> list[PathString]:
    mounts = {t.with_prefix(Path("/work/src")) for t in config.build_sources}

    options: list[PathString] = ["--dir", "/work/src"]
    for src, target in sorted(mounts, key=lambda s: s[1]):
        options += ["--ro-bind", src, target]

    return options


@contextlib.contextmanager
def finalize_ephemeral_source_mounts(config: Config) -> Iterator[list[PathString]]:
    with contextlib.ExitStack() as stack:
        mounts = (
            (stack.enter_context(mount_overlay([source])) if config.build_sources_ephemeral else source, target)
            for source, target
            in {t.with_prefix(Path("/work/src")) for t in config.build_sources}
        )

        options: list[PathString] = ["--dir", "/work/src"]
        for src, target in sorted(mounts, key=lambda s: s[1]):
            options += ["--bind", src, target]

        yield options
