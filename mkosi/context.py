# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Optional

from mkosi.config import Args, Config
from mkosi.types import PathString


class Context:
    """State related properties."""

    def __init__(
        self,
        args: Args,
        config: Config,
        *,
        workspace: Path,
        resources: Path,
        package_cache_dir: Optional[Path] = None,
        package_dir: Optional[Path] = None,
    ) -> None:
        self.args = args
        self.config = config
        self.workspace = workspace
        self.resources = resources
        self.package_cache_dir = package_cache_dir or (self.root / "var")
        self.package_dir = package_dir or (self.workspace / "packages")

        self.package_dir.mkdir(exist_ok=True)
        self.staging.mkdir()
        self.pkgmngr.mkdir()
        self.repository.mkdir()
        self.artifacts.mkdir()
        self.install_dir.mkdir()

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
        binary: Optional[PathString],
        network: bool = False,
        devices: bool = False,
        vartmp: bool = False,
        scripts: Optional[Path] = None,
        options: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]:
        return self.config.sandbox(
            binary=binary,
            network=network,
            devices=devices,
            vartmp=vartmp,
            scripts=scripts,
            usroverlaydirs=[self.pkgmngr / "usr"] if (self.pkgmngr / "usr").exists() else [],
            options=[
                *options,
                # This mount is writable so we can create extra directories or symlinks inside of it as needed.
                # This isn't a problem as the package manager directory is created by mkosi and thrown away when the
                # build finishes.
                "--bind", self.pkgmngr / "etc", "/etc",
                "--bind", self.pkgmngr / "var/log", "/var/log",
            ],
        )
