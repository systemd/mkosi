# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Optional

from mkosi.config import Args, Config
from mkosi.sandbox import Mount
from mkosi.tree import make_tree
from mkosi.types import PathString
from mkosi.util import umask


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
    ) -> None:
        self.args = args
        self.config = config
        self.workspace = workspace
        self.resources = resources
        self.package_cache_dir = package_cache_dir or (self.root / "var")

        with umask(~0o755):
            # Using a btrfs subvolume as the upperdir in an overlayfs results in EXDEV so make sure we create
            # the root directory as a regular directory if the Overlay= option is enabled.
            if config.overlay:
                self.root.mkdir()
            else:
                make_tree(
                    self.root,
                    use_subvolumes=self.config.use_subvolumes,
                    sandbox=config.sandbox,
                )

        self.staging.mkdir()
        self.pkgmngr.mkdir()
        self.repository.mkdir()
        self.packages.mkdir()
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
    def packages(self) -> Path:
        return self.workspace / "packages"

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
        mounts: Sequence[Mount] = (),
        options: Sequence[PathString] = (),
        extra: Sequence[PathString] = (),
    ) -> AbstractContextManager[list[PathString]]:
        if (self.pkgmngr / "usr").exists():
            extra = [
                "sh",
                "-c",
                f"mount -t overlay -o lowerdir={self.pkgmngr / 'usr'}:/usr overlayfs /usr && exec $0 \"$@\"",
                *extra,
            ]

        return self.config.sandbox(
            binary=binary,
            network=network,
            devices=devices,
            vartmp=vartmp,
            scripts=scripts,
            mounts=[
                # This mount is writable so bubblewrap can create extra directories or symlinks inside of it as needed.
                # This isn't a problem as the package manager directory is created by mkosi and thrown away when the
                # build finishes.
                Mount(self.pkgmngr / "etc", "/etc"),
                Mount(self.pkgmngr / "var/log", "/var/log"),
                *([Mount(p, p, ro=True)] if (p := self.pkgmngr / "usr").exists() else []),
                *mounts,
            ],
            options=[
                "--uid", "0",
                "--gid", "0",
                "--cap-add", "ALL",
                *options,
            ],
            extra=extra,
        )
