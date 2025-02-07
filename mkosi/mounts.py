# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import stat
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Optional, Union

from mkosi.config import BuildSourcesEphemeral, Config
from mkosi.log import die
from mkosi.sandbox import OverlayOperation
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


@contextlib.contextmanager
def mount_overlay(
    lowerdirs: Sequence[Path],
    dst: Path,
    *,
    upperdir: Optional[Path] = None,
) -> Iterator[Path]:
    with contextlib.ExitStack() as stack:
        if upperdir is None:
            upperdir = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="volatile-overlay")))
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


@contextlib.contextmanager
def finalize_source_mounts(
    config: Config,
    *,
    ephemeral: Union[BuildSourcesEphemeral, bool],
) -> Iterator[list[PathString]]:
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

                    upperdir = config.build_dir / f"mkosi.buildovl.{src.name}"
                    upperdir.mkdir(mode=src.stat().st_mode, exist_ok=True)
                else:
                    upperdir = Path(
                        stack.enter_context(tempfile.TemporaryDirectory(prefix="volatile-overlay."))
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
        mounts += [
            (root / subdir, Path("/") / subdir)
            for subdir in (
                Path("etc/pki"),
                Path("etc/ssl"),
                Path("etc/ca-certificates"),
                Path("var/lib/ca-certificates"),
            )
            if (root / subdir).exists() and any(p for p in (root / subdir).rglob("*") if not p.is_dir())
        ]

    return flatten(("--ro-bind", src, target) for src, target in sorted(set(mounts), key=lambda s: s[1]))
