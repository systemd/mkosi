# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import platform
import stat
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Optional

from mkosi.log import complete_step
from mkosi.run import run
from mkosi.types import PathString
from mkosi.util import InvokingUser, umask
from mkosi.versioncomp import GenericVersion


def stat_is_whiteout(st: os.stat_result) -> bool:
    return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0


def delete_whiteout_files(path: Path) -> None:
    """Delete any char(0,0) device nodes underneath @path

    Overlayfs uses such files to mark "whiteouts" (files present in
    the lower layers, but removed in the upper one).
    """

    with complete_step("Removing overlay whiteout files…"):
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
        run(["umount", "--no-mtab", *(["--lazy"] if lazy else []), where])


@contextlib.contextmanager
def mount_overlay(lowerdirs: Sequence[Path], upperdir: Path, where: Path) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(dir=upperdir.parent, prefix=f"{upperdir.name}-workdir") as workdir:
        options = [f"lowerdir={lower}" for lower in lowerdirs] + [
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
            with mount("overlay", where, options=options, type="overlay"):
                yield where
        finally:
            with complete_step("Cleaning up overlayfs"):
                delete_whiteout_files(upperdir)


@contextlib.contextmanager
def mount_usr(tree: Optional[Path]) -> Iterator[None]:
    if not tree:
        yield
        return

    # If we replace /usr, we should ignore any local modifications made to PATH as any of those binaries
    # might not work anymore when /usr is replaced wholesale. We also make sure that both /usr/bin and
    # /usr/sbin/ are searched so that e.g. if the host is Arch and the root is Debian we don't ignore the
    # binaries from /usr/sbin in the Debian root.
    old = os.environ["PATH"]
    os.environ["PATH"] = "/usr/bin:/usr/sbin"

    try:
        # If we mounted over /usr, trying to use umount will fail with "target is busy", because umount is
        # being called from /usr, which we're trying to unmount. To work around this issue, we do a lazy
        # unmount.
        with mount(
            what=tree / "usr",
            where=Path("/usr"),
            operation="--bind",
            read_only=True,
            lazy=True,
        ):
            yield
    finally:
        os.environ["PATH"] = old


@contextlib.contextmanager
def mount_passwd(root: Path = Path("/")) -> Iterator[None]:
    """
    ssh looks up the running user in /etc/passwd and fails if it can't find the running user. To trick it, we
    mount over /etc/passwd with our own file containing our user in the user namespace.
    """
    with tempfile.NamedTemporaryFile(prefix="mkosi.passwd", mode="w") as passwd:
        passwd.write("root:x:0:0:root:/root:/bin/sh\n")
        if InvokingUser.uid != 0:
            name = InvokingUser.name
            passwd.write(f"{name}:x:{InvokingUser.uid}:{InvokingUser.gid}:{name}:/home/{name}:/bin/sh\n")
        passwd.flush()
        os.fchown(passwd.file.fileno(), InvokingUser.uid, InvokingUser.gid)

        with mount(passwd.name, root / "etc/passwd", operation="--bind"):
            yield
