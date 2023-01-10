# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path
from typing import List

from mkosi.backend import MkosiState, add_packages, complete_step
from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, install_packages_dnf, invoke_dnf, setup_dnf


class OpenmandrivaInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> List[str]:
        return ["var/cache/dnf"]

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        return install_openmandriva(state)

    @classmethod
    def remove_packages(cls, state: MkosiState, remove: List[str]) -> None:
        invoke_dnf(state, 'remove', remove)


@complete_step("Installing OpenMandriva…")
def install_openmandriva(state: MkosiState) -> None:
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

    gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-OpenMandriva")

    repos = [Repo("openmandriva", release_url, gpgpath)]
    if updates_url is not None:
        repos += [Repo("updates", updates_url, gpgpath)]

    setup_dnf(state, repos)

    packages = {*state.config.packages}
    # well we may use basesystem here, but that pulls lot of stuff
    add_packages(state.config, packages, "basesystem-minimal", "systemd", "dnf")
    if not state.do_run_build_script and state.config.bootable:
        add_packages(state.config, packages, "systemd-boot", "systemd-cryptsetup", conditional="systemd")
        add_packages(state.config, packages, "kernel-release-server", "dracut", "timezone")
    if state.config.netdev:
        add_packages(state.config, packages, "systemd-networkd", conditional="systemd")

    if state.do_run_build_script:
        packages.update(state.config.build_packages)
    install_packages_dnf(state, packages)
