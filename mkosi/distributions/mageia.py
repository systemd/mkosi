# SPDX-License-Identifier: LGPL-2.1+

import shutil
from collections.abc import Sequence
from pathlib import Path

from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, invoke_dnf, setup_dnf
from mkosi.state import MkosiState


class MageiaInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @staticmethod
    def repositories(state: MkosiState) -> list[Repo]:
        release = state.config.release.strip("'")

        if state.config.local_mirror:
            release_url = f"baseurl={state.config.local_mirror}"
            updates_url = None
        elif state.config.mirror:
            baseurl = f"{state.config.mirror}/distrib/{release}/{state.config.architecture}/media/core/"
            release_url = f"baseurl={baseurl}/release/"
            if release == "cauldron":
                updates_url = None
            else:
                updates_url = f"baseurl={baseurl}/updates/"
        else:
            baseurl = f"https://www.mageia.org/mirrorlist/?release={release}&arch={state.config.architecture}&section=core"
            release_url = f"mirrorlist={baseurl}&repo=release"
            if release == "cauldron":
                updates_url = None
            else:
                updates_url = f"mirrorlist={baseurl}&repo=updates"

        gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-Mageia")

        repos = [Repo(f"mageia-{release}", release_url, gpgpath)]
        if updates_url is not None:
            repos += [Repo(f"mageia-{release}-updates", updates_url, gpgpath)]

        return repos

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        repos = cls.repositories(state)
        setup_dnf(state, repos)
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def install_package_files(cls, state: MkosiState, dir: Path) -> None:
        repos = cls.repositories(state)
        setup_dnf(state, repos)

        file_paths : list[str] = [
            str(state.root / "packages" / p.name)
            for p in dir.iterdir()
            if p.name.endswith('.rpm')
        ]

        if (shutil.which('dnf5') or shutil.which('dnf') or 'yum') == 'yum':
            verb = "localinstall"
        else:
            verb = "install"

        if file_paths:
            invoke_dnf(state, verb, file_paths)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)
