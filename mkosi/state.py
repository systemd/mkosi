# SPDX-License-Identifier: LGPL-2.1+

import tempfile
from pathlib import Path
from types import TracebackType
from typing import Optional, Type

from mkosi.config import MkosiArgs, MkosiConfig
from mkosi.tree import make_tree


class MkosiState:
    """State related properties."""

    def __init__(self, args: MkosiArgs, config: MkosiConfig) -> None:
        self.args = args
        self.config = config

    def __enter__(self) -> "MkosiState":
        self._workspace = tempfile.TemporaryDirectory(dir=self.config.workspace_dir or Path.cwd(), prefix=".mkosi.tmp")
        make_tree(self.config, self.root, mode=0o755)
        self.staging.mkdir()
        self.pkgmngr.mkdir()
        self.install_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        traceback: Optional[TracebackType]
    ) -> None:
        self._workspace.cleanup()

    @property
    def workspace(self) -> Path:
        return Path(self._workspace.name)

    @property
    def root(self) -> Path:
        return self.workspace / "root"

    @property
    def staging(self) -> Path:
        return self.workspace / "staging"

    @property
    def pkgmngr(self) -> Path:
        return self.workspace / "pkgmngr"

    @property
    def cache_dir(self) -> Path:
        return self.config.cache_dir or self.workspace / f"cache/{self.config.distribution}~{self.config.release}"

    @property
    def install_dir(self) -> Path:
        return self.workspace / "dest"
