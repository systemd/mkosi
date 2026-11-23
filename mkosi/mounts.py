# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import stat
import tempfile
from collections.abc import Generator, Sequence
from pathlib import Path
from typing import Optional, Union

from mkosi.config import BuildSourcesEphemeral, Config
from mkosi.log import die
from mkosi.sandbox import OVERLAYFS_SUPER_MAGIC, OverlayOperation, statfs
from mkosi.util import PathString, flatten


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


def finalize_volatile_tmpdir() -> Path:
    if tempfile.tempdir and statfs(tempfile.tempdir) != OVERLAYFS_SUPER_MAGIC:
        return Path(tempfile.tempdir)

    for path in ("/var/tmp", "/tmp", "/dev/shm"):
        if Path(path).exists() and statfs(path) != OVERLAYFS_SUPER_MAGIC:
            return Path(path)

    die(
        "Cannot find temporary directory for volatile overlayfs upperdir",
        hint="Either /var/tmp, /tmp or /dev/shm must exist and not be located on overlayfs",
    )


@contextlib.contextmanager
def mount_overlay(
    lowerdirs: Sequence[Path],
    dst: Path,
    *,
    upperdir: Optional[Path] = None,
) -> Generator[Path]:
    with contextlib.ExitStack() as stack:
        if upperdir is None:
            upperdir = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(
                        prefix="volatile-overlay.",
                        dir=finalize_volatile_tmpdir(),
                    )
                )
            )
            st = lowerdirs[-1].stat()
            os.chmod(upperdir, st.st_mode)

        workdir = Path(
            stack.enter_context(
                tempfile.TemporaryDirectory(dir=upperdir.parent, prefix=f"{upperdir.name}-workdir")
            )
        )

        try:
            with OverlayOperation(
                tuple(os.fspath(p) for p in lowerdirs),
                os.fspath(upperdir),
                os.fspath(workdir),
                os.fspath(dst),
            ):
                yield dst
        finally:
            delete_whiteout_files(upperdir)


# Directories and files below /work that mkosi mounts something on top of itself. Gitdirs
# must not be mounted below any of those: the ones backed by a host directory would leave
# empty directories behind in the host directory they're backed by, and the ones backed by a
# file cannot contain a gitdir at all. Build sources are mounted below /work/src and are
# taken into account separately.
WORK_MOUNTS = (
    Path("/work/out"),
    Path("/work/artifacts"),
    Path("/work/packages"),
    Path("/work/build"),
    Path("/work/dest"),
    Path("/work/config.json"),
    Path("/work/prepare"),
    Path("/work/build-script"),
    Path("/work/postinst"),
    Path("/work/finalize"),
    Path("/work/sync"),
    Path("/work/configure"),
    Path("/work/clean"),
    Path("/work/postoutput"),
)

# System directories that are mounted into the sandbox from the tools tree. Mount points
# cannot be created below those when a tools tree is used.
TOOLS_TREE_DIRS = (
    "/usr",
    "/opt",
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/nix/store",
)


def gitdir_mountable(location: Path, destinations: Sequence[Path], tools: Path) -> bool:
    """Check whether a gitdir can be mounted at its location in the sandbox"""
    location = Path(os.path.normpath(location))

    if any(location.is_relative_to(d) for d in destinations):
        return False

    # /work itself is where all the other work mounts live below.
    if location == Path("/work") or any(location.is_relative_to(d) for d in WORK_MOUNTS):
        return False

    # The system directories are mounted read-only from the tools tree, so mount points
    # cannot be created below those when a tools tree is used.
    return tools == Path("/") or not any(location.is_relative_to(d) for d in TOOLS_TREE_DIRS)


def gitdir_mounts(config: Config, *, ephemeral: bool) -> list[PathString]:
    """Return mounts for the gitdirs of git worktree checkouts

    In a git worktree, .git is a file pointing at the gitdir in the main repository, which
    lives outside the source tree and is therefore not mounted into the sandbox together
    with the source. Bind the gitdir (and its commondir) into the sandbox so that git keeps
    working on the mounted source.

    Git resolves a relative gitdir against the directory containing the .git file, which is
    the sandbox destination rather than the host source directory, so relative gitdirs are
    mounted relative to the destination as well.

    The gitdir is mounted read-only if the sources are ephemeral, so that writes don't leak
    into the host repository.
    """
    destinations = [t.with_prefix("/work/src")[1] for t in config.build_sources]
    options: list[PathString] = []

    for t in config.build_sources:
        src, dst = t.with_prefix("/work/src")

        gitfile = src / ".git"
        if not gitfile.is_file():
            continue

        content = gitfile.read_text().strip()
        if not content.startswith("gitdir:"):
            continue

        gitdir = Path(content.removeprefix("gitdir:").strip())
        if gitdir.is_absolute():
            host_gitdir = sandbox_gitdir = gitdir
        else:
            host_gitdir, sandbox_gitdir = src / gitdir, dst / gitdir

        if not host_gitdir.is_dir():
            continue

        commondir = host_gitdir / "commondir"
        if not commondir.is_file():
            # Submodule checkouts have no commondir and record their worktree location
            # relative to the gitdir in core.worktree, which cannot be remapped into the
            # sandbox, so those are not supported.
            continue

        commondir = Path(commondir.read_text().strip())
        if commondir.is_absolute():
            host_commondir = sandbox_commondir = commondir
        else:
            host_commondir, sandbox_commondir = host_gitdir / commondir, sandbox_gitdir / commondir

        if not host_commondir.is_dir() or host_commondir == host_gitdir:
            continue

        if not (
            gitdir_mountable(sandbox_gitdir, destinations, config.tools())
            and gitdir_mountable(sandbox_commondir, destinations, config.tools())
        ):
            continue

        bind = "--ro-bind" if ephemeral else "--bind"
        options += [bind, host_gitdir, sandbox_gitdir, bind, host_commondir, sandbox_commondir]

    return options


@contextlib.contextmanager
def finalize_source_mounts(
    config: Config,
    *,
    ephemeral: Union[BuildSourcesEphemeral, bool],
) -> Generator[list[PathString]]:
    with contextlib.ExitStack() as stack:
        options: list[PathString] = []

        for t in config.build_sources:
            src, dst = t.with_prefix("/work/src")

            if ephemeral:
                if ephemeral == BuildSourcesEphemeral.buildcache:
                    if config.build_dir is None:
                        die(
                            "BuildSourcesEphemeral=buildcache was configured, but no build directory exists.",  # noqa: E501
                            hint="Configure BuildDirectory= or create mkosi.builddir.",
                        )

                    upperdir = config.build_subdir / f"mkosi.buildovl.{src.name}"
                    upperdir.mkdir(mode=src.stat().st_mode, exist_ok=True)
                else:
                    upperdir = Path(
                        stack.enter_context(
                            tempfile.TemporaryDirectory(
                                prefix="volatile-overlay.",
                                dir=finalize_volatile_tmpdir(),
                            )
                        )
                    )
                    os.chmod(upperdir, src.stat().st_mode)

                workdir = Path(
                    stack.enter_context(
                        tempfile.TemporaryDirectory(dir=upperdir.parent, prefix=f"{upperdir.name}-workdir.")
                    )
                )

                options += [
                    "--overlay-lowerdir", src,
                    "--overlay-upperdir", upperdir,
                    "--overlay-workdir", workdir,
                    "--overlay", dst,
                ]  # fmt: skip
            else:
                options += ["--bind", src, dst]

        yield options


def finalize_certificate_mounts(config: Config, relaxed: bool = False) -> list[PathString]:
    mounts = []
    root = config.tools() if config.tools_tree_certificates else Path("/")

    if not relaxed or root != Path("/"):
        subdirs = [Path("var/lib/ca-certificates")]
        if not relaxed:
            subdirs += [
                Path("etc/pki/ca-trust"),
                Path("etc/pki/tls"),
                Path("etc/ssl"),
                Path("etc/ca-certificates"),
            ]

        mounts += [
            (root / subdir, Path("/") / subdir)
            for subdir in subdirs
            if (root / subdir).exists() and any(p for p in (root / subdir).rglob("*") if not p.is_dir())
        ]

    return flatten(("--ro-bind", src, target) for src, target in sorted(set(mounts), key=lambda s: s[1]))
