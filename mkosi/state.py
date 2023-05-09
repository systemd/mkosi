# SPDX-License-Identifier: LGPL-2.1+

import dataclasses
import importlib
from pathlib import Path

from mkosi.btrfs import btrfs_maybe_make_subvolume
from mkosi.config import MkosiArgs, MkosiConfig
from mkosi.distributions import DistributionInstaller
from mkosi.log import die


@dataclasses.dataclass
class MkosiState:
    """State related properties."""

    uid: int
    gid: int
    args: MkosiArgs
    config: MkosiConfig
    workspace: Path
    cache: Path
    environment: dict[str, str] = dataclasses.field(init=False)
    installer: DistributionInstaller = dataclasses.field(init=False)

    def __post_init__(self) -> None:
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

    @property
    def root(self) -> Path:
        return self.workspace / "root"

    @property
    def workdir(self) -> Path:
        return self.workspace / "workdir"

    @property
    def staging(self) -> Path:
        return self.workspace / "staging"
