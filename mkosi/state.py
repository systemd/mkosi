# SPDX-License-Identifier: LGPL-2.1+

import dataclasses
import importlib
from pathlib import Path

from mkosi.config import MkosiConfig
from mkosi.distributions import DistributionInstaller
from mkosi.log import die
from mkosi.util import OutputFormat


@dataclasses.dataclass
class MkosiState:
    """State related properties."""

    uid: int
    gid: int
    config: MkosiConfig
    workspace: Path
    cache: Path
    output_format: OutputFormat
    environment: dict[str, str] = dataclasses.field(init=False)
    installer: DistributionInstaller = dataclasses.field(init=False)
    btrfs_snapshot: bool = False

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

        self.root.mkdir(exist_ok=True, mode=0o755)
        self.build_overlay.mkdir(exist_ok=True, mode=0o755)
        self.cache_overlay.mkdir(exist_ok=True, mode=0o755)
        self.workdir.mkdir(exist_ok=True)
        self.staging.mkdir(exist_ok=True)

    @property
    def root(self) -> Path:
        return self.workspace / "root"

    @property
    def cache_overlay(self) -> Path:
        return self.workspace / "cache-overlay"

    @property
    def build_overlay(self) -> Path:
        return self.workspace / "build-overlay"

    @property
    def workdir(self) -> Path:
        return self.workspace / "workdir"

    @property
    def staging(self) -> Path:
        return self.workspace / "staging"
