# SPDX-License-Identifier: LGPL-2.1+

import importlib
import tempfile
from pathlib import Path

from mkosi.btrfs import btrfs_maybe_make_subvolume
from mkosi.config import MkosiArgs, MkosiConfig
from mkosi.distributions import DistributionInstaller
from mkosi.log import die


class MkosiState:
    """State related properties."""

    def __init__(self, args: MkosiArgs, config: MkosiConfig, uid: int, gid: int) -> None:
        self.args = args
        self.config = config
        self.uid = uid
        self.gid = gid

        self._workspace = tempfile.TemporaryDirectory(dir=config.workspace_dir or Path.cwd(), prefix=".mkosi.tmp")

        self.environment = self.config.environment.copy()
        if self.config.image_id is not None:
            self.environment['IMAGE_ID'] = self.config.image_id
        if self.config.image_version is not None:
            self.environment['IMAGE_VERSION'] = self.config.image_version

        try:
            distro = str(self.config.distribution)
            mod = importlib.import_module(f"mkosi.distributions.{distro}")
            installer = getattr(mod, f"{distro.title().replace('_','')}Installer")
            instance = installer() if issubclass(installer, DistributionInstaller) else None
        except (ImportError, AttributeError):
            instance = None
        if instance is None:
            die("No installer for this distribution.")
        self.installer = instance

        btrfs_maybe_make_subvolume(self.config, self.root, mode=0o755)
        self.workdir.mkdir()
        self.staging.mkdir()

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.install_dir.mkdir(parents=True, exist_ok=True)

    @property
    def workspace(self) -> Path:
        return Path(self._workspace.name)

    @property
    def root(self) -> Path:
        return self.workspace / "root"

    @property
    def workdir(self) -> Path:
        return self.workspace / "workdir"

    @property
    def staging(self) -> Path:
        return self.workspace / "staging"

    @property
    def cache_dir(self) -> Path:
        return self.config.cache_dir or self.workspace / f"cache/{self.config.distribution}~{self.config.release}"

    @property
    def install_dir(self) -> Path:
        return self.config.install_dir or self.workspace / "dest"
