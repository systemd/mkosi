# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import platform
import stat
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Optional

from mkosi.run import run
from mkosi.types import PathString
from mkosi.util import INVOKING_USER, umask
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
            with mount("overlay", where, options=options, type="overlay"):
                yield where
        finally:
            delete_whiteout_files(upperdir)


@contextlib.contextmanager
def mount_usr(tree: Optional[Path], umount: bool = True) -> Iterator[None]:
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
            umount=umount,
        ):
            yield
    finally:
        os.environ["PATH"] = old


@contextlib.contextmanager
def mount_passwd() -> Iterator[None]:
    with tempfile.NamedTemporaryFile(prefix="mkosi.passwd", mode="w") as passwd:
        passwd.write("root:x:0:0:root:/root:/bin/sh\n")
        if INVOKING_USER.uid != 0:
            name = INVOKING_USER.name()
            home = INVOKING_USER.home()
            passwd.write(f"{name}:x:{INVOKING_USER.uid}:{INVOKING_USER.gid}:{name}:{home}:/bin/sh\n")
        passwd.flush()
        os.fchown(passwd.file.fileno(), INVOKING_USER.uid, INVOKING_USER.gid)

        with mount(passwd.name, Path("/etc/passwd"), operation="--bind"):
            yield


def finalize_passwd_mounts(root: Path) -> list[PathString]:
    """
    If passwd or a related file exists in the apivfs directory, bind mount it over the host files while we
    run the command, to make sure that the command we run uses user/group information from the apivfs
    directory instead of from the host. If the file doesn't exist yet, mount over /dev/null instead.
    """
    options: list[PathString] = []

    for f in ("passwd", "group", "shadow", "gshadow"):
        if not (Path("/etc") / f).exists():
            continue
        p = root / "etc" / f
        if p.exists():
            options += ["--bind", p, f"/etc/{f}"]
        else:
            options += ["--bind", "/dev/null", f"/etc/{f}"]

    return options
