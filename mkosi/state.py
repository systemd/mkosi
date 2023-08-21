# SPDX-License-Identifier: LGPL-2.1+

import shutil
import subprocess
from pathlib import Path

from mkosi.config import ConfigFeature, MkosiArgs, MkosiConfig
from mkosi.log import die
from mkosi.util import umask


# This function bares resemblance to the one in mkosi/tree.py because there
# would be a circular import otherwise.
def make_tree(config: MkosiConfig, path: Path) -> None:
    on_btrfs = subprocess.run(
        ["stat", "--file-system", "--format", "%T", path.parent],
        stdout=subprocess.PIPE
    ).stdout.strip() == b"btrfs"

    if not on_btrfs:
        if config.use_subvolumes == ConfigFeature.enabled:
            die(f"Subvolumes requested but {path} is not located on a btrfs filesystem")

        path.mkdir()
        return

    if config.use_subvolumes != ConfigFeature.disabled and shutil.which("btrfs") is not None:
        result = subprocess.run(["btrfs", "subvolume", "create", path],
                     check=config.use_subvolumes == ConfigFeature.enabled).returncode
    else:
        result = 1

    if result != 0:
        path.mkdir()


class MkosiState:
    """State related properties."""

    def __init__(self, args: MkosiArgs, config: MkosiConfig, workspace: Path) -> None:
        self.args = args
        self.config = config
        self.workspace = workspace

        with umask(~0o755):
            make_tree(self.config, self.root)
        self.staging.mkdir()
        self.pkgmngr.mkdir()
        self.install_dir.mkdir(exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # This is the list of directories to mount as overlay base directories
        # when config.overlay_as_copy is used
        self.overlay_as_copy_dirs : list[Path] = list()

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


class MkosiBasicState:
    """Used when an MkosiState object is required but there is no workspace."""

    def __init__(self, config: MkosiConfig) -> None:
        self.config = config

    @property
    def overlay_as_copy_dirs(self) -> list[Path]:
        return list()

    @property
    def root(self) -> Path:
        return Path("/")
