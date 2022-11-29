# SPDX-License-Identifier: LGPL-2.1+

from pathlib import Path
from typing import List

from mkosi.backend import MkosiState, add_packages, complete_step, disable_pam_securetty
from mkosi.distributions import DistributionInstaller
from mkosi.distributions.fedora import Repo, install_packages_dnf, invoke_dnf, setup_dnf


class MageiaInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> List[str]:
        return ["var/cache/dnf"]

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        return install_mageia(state)

    @classmethod
    def remove_packages(cls, state: MkosiState, remove: List[str]) -> None:
        invoke_dnf(state, 'remove', remove)


@complete_step("Installing Mageia…")
def install_mageia(state: MkosiState) -> None:
    if state.config.local_mirror:
        release_url = f"baseurl={state.config.local_mirror}"
        updates_url = None
    elif state.config.mirror:
        baseurl = f"{state.config.mirror}/distrib/{state.config.release}/x86_64/media/core/"
        release_url = f"baseurl={baseurl}/release/"
        updates_url = f"baseurl={baseurl}/updates/"
    else:
        baseurl = f"https://www.mageia.org/mirrorlist/?release={state.config.release}&arch=x86_64&section=core"
        release_url = f"mirrorlist={baseurl}&repo=release"
        updates_url = f"mirrorlist={baseurl}&repo=updates"

    gpgpath = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-Mageia")

    repos = [Repo("mageia", release_url, gpgpath)]
    if updates_url is not None:
        repos += [Repo("updates", updates_url, gpgpath)]

    setup_dnf(state, repos)

    packages = {*state.config.packages}
    add_packages(state.config, packages, "basesystem-minimal", "dnf")
    if not state.do_run_build_script and state.config.bootable:
        add_packages(state.config, packages, "kernel-server-latest", "dracut")
        # Mageia ships /etc/50-mageia.conf that omits systemd from the initramfs and disables hostonly.
        # We override that again so our defaults get applied correctly on Mageia as well.
        state.root.joinpath("etc/dracut.conf.d/51-mkosi-override-mageia.conf").write_text(
            'hostonly=no\n'
            'omit_dracutmodules=""\n'
        )

    if state.do_run_build_script:
        packages.update(state.config.build_packages)
    install_packages_dnf(state, packages)

    disable_pam_securetty(state.root)
