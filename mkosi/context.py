# SPDX-License-Identifier: LGPL-2.1-or-later

import os
from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path

from mkosi.config import Args, Config
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
        package_dir: Path | None = None,
    ) -> None:
        self.args = args
        self.config = config
        self.workspace = workspace
        self.resources = resources
        self.keyring_dir = keyring_dir
        self.metadata_dir = metadata_dir
        self.package_dir = package_dir or (self.workspace / "packages")
        self.lowerdirs: list[PathString] = []
        self.upperdir: PathString | None = None
        self.workdir: PathString | None = None

        self.package_dir.mkdir(exist_ok=True)
        self.staging.mkdir()
        self.sandbox_tree.mkdir()
        self.repository.mkdir()
        self.artifacts.mkdir()
        self.install_dir.mkdir()

    @property
    def root(self) -> Path:
        return self.workspace / "root"

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
        scripts: Path | None = None,
        options: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]:
        return self.config.sandbox(
            network=network,
            devices=devices,
            scripts=scripts,
            overlay=self.sandbox_tree,
            options=options,
        )
