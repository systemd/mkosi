# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import stat
from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Optional

from mkosi.config import Args, Config
from mkosi.sandbox import chase
from mkosi.util import PathString, flatten


class Context:
    """State related properties."""

    def __init__(
        self,
        args: Args,
        config: Config,
        *,
        workspace: Path,
        resources: Path,
        keyring_dir: Path,
        metadata_dir: Path,
        package_dir: Optional[Path] = None,
    ) -> None:
        self.args = args
        self.config = config
        self.workspace = workspace
        self.resources = resources
        self.keyring_dir = keyring_dir
        self.metadata_dir = metadata_dir
        self.package_dir = package_dir or (self.workspace / "packages")
        self.lowerdirs: list[PathString] = []
        self.upperdir: Optional[PathString] = None
        self.workdir: Optional[PathString] = None
        self.overlay_package_files: set[Path] = set()

        self.package_dir.mkdir(exist_ok=True)
        self.staging.mkdir()
        self.sandbox_tree.mkdir()
        self.repository.mkdir()
        self.artifacts.mkdir()
        self.install_dir.mkdir()

    @property
    def root(self) -> Path:
        return self.workspace / "root"

    def record_overlay_package_files(self, files: Sequence[str], *, copy_up: bool = False) -> None:
        # File lists can use e.g. /bin on a merged-/usr image. Resolve parent directories in the
        # image, but not the last component: a packaged symlink is itself part of the payload.
        for name in files:
            path = Path(chase(os.fspath(self.root), os.fspath(Path("/") / name), nofollow=True))
            if copy_up:
                # Some package managers leave identical files (especially conffiles) in place.
                # Trigger overlayfs copy-up without changing their timestamps or following symlinks.
                try:
                    st = path.lstat()
                except FileNotFoundError:
                    continue
                if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                    continue
                os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)

            self.overlay_package_files.add(path.relative_to(self.root))

    def rootoptions(self, dst: PathString = "/buildroot", *, readonly: bool = False) -> list[str]:
        if self.lowerdirs or self.upperdir:
            return [
                "--overlay-lowerdir", os.fspath(self.root),
                *flatten(["--overlay-lowerdir", os.fspath(lowerdir)] for lowerdir in self.lowerdirs),
                *(
                    ["--overlay-lowerdir" if readonly else "--overlay-upperdir", os.fspath(self.upperdir)]
                    if self.upperdir
                    else []
                ),
                *(["--overlay-workdir", os.fspath(self.workdir)] if self.workdir and not readonly else []),
                "--overlay", os.fspath(dst),
            ]  # fmt: skip
        else:
            return ["--ro-bind" if readonly else "--bind", os.fspath(self.root), os.fspath(dst)]

    @property
    def staging(self) -> Path:
        return self.workspace / "staging"

    @property
    def sandbox_tree(self) -> Path:
        return self.workspace / "sandbox"

    @property
    def repository(self) -> Path:
        return self.workspace / "repository"

    @property
    def artifacts(self) -> Path:
        return self.workspace / "artifacts"

    @property
    def install_dir(self) -> Path:
        return self.workspace / "dest"

    def sandbox(
        self,
        *,
        network: bool = False,
        devices: bool = False,
        scripts: Optional[Path] = None,
        options: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]:
        return self.config.sandbox(
            network=network,
            devices=devices,
            scripts=scripts,
            overlay=self.sandbox_tree,
            options=options,
        )
