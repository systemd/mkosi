# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

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

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
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

        gpgurl = f"https://mirrors.kernel.org/mageia/distrib/{release}/{state.config.architecture}/media/core/release/media_info/pubkey"

        repos = [Repo(f"mageia-{release}", release_url, gpgurl)]
        if updates_url is not None:
            repos += [Repo(f"mageia-{release}-updates", updates_url, gpgurl)]

        setup_dnf(state, repos)
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)
