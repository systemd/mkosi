# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, invoke_dnf, setup_dnf
from mkosi.state import MkosiState


class OpenmandrivaInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"])

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        release = state.config.release.strip("'")

        if release[0].isdigit():
            release_model = "rock"
        elif release == "cooker":
            release_model = "cooker"
        else:
            release_model = release

        if state.config.local_mirror:
            release_url = f"baseurl={state.config.local_mirror}"
            updates_url = None
        elif state.config.mirror:
            baseurl = f"{state.config.mirror}/{release_model}/repository/{state.config.architecture}/main"
            release_url = f"baseurl={baseurl}/release/"
            updates_url = f"baseurl={baseurl}/updates/"
        else:
            baseurl = f"http://mirrors.openmandriva.org/mirrors.php?platform={release_model}&arch={state.config.architecture}&repo=main"
            release_url = f"mirrorlist={baseurl}&release=release"
            updates_url = f"mirrorlist={baseurl}&release=updates"

        gpgurl = "https://raw.githubusercontent.com/OpenMandrivaAssociation/openmandriva-repos/master/RPM-GPG-KEY-OpenMandriva"

        repos = [Repo("openmandriva", release_url, gpgurl)]
        if updates_url is not None:
            repos += [Repo("updates", updates_url, gpgurl)]

        setup_dnf(state, repos)
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)
