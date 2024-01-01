# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path

from mkosi.config import Args, Config
from mkosi.tree import make_tree
from mkosi.util import umask


class Context:
    """State related properties."""

    def __init__(self, args: Args, config: Config, workspace: Path) -> None:
        self.args = args
        self.config = config
        self.workspace = workspace

        with umask(~0o755):
            # Using a btrfs subvolume as the upperdir in an overlayfs results in EXDEV so make sure we create
            # the root directory as a regular directory if the Overlay= option is enabled.
            if config.overlay:
                self.root.mkdir()
            else:
                make_tree(self.root, use_subvolumes=self.config.use_subvolumes)

        self.staging.mkdir()
        self.pkgmngr.mkdir()
        self.install_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

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
        return self.config.cache_dir or (self.workspace / "cache")

    @property
    def install_dir(self) -> Path:
        return self.workspace / "dest"
