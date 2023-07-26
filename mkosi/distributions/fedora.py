# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller
from mkosi.installer.dnf import Repo, invoke_dnf, setup_dnf
from mkosi.log import die
from mkosi.state import MkosiState


class FedoraInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        release_url = updates_url = appstream_url = baseos_url = extras_url = crb_url = None

        if state.config.local_mirror:
            release_url = f"baseurl={state.config.local_mirror}"
        elif state.config.release == "eln":
            assert state.config.mirror
            appstream_url = f"baseurl={state.config.mirror}/AppStream/$basearch/os"
            baseos_url = f"baseurl={state.config.mirror}/BaseOS/$basearch/os"
            extras_url = f"baseurl={state.config.mirror}/Extras/$basearch/os"
            crb_url = f"baseurl={state.config.mirror}/CRB/$basearch/os"
        elif state.config.mirror:
            directory = "development" if state.config.release == "rawhide" else "releases"
            release_url = f"baseurl={state.config.mirror}/{directory}/$releasever/Everything/$basearch/os/"
            updates_url = f"baseurl={state.config.mirror}/updates/$releasever/Everything/$basearch/"
        else:
            release_url = f"metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-{state.config.release}&arch=$basearch"
            updates_url = (
                "metalink=https://mirrors.fedoraproject.org/metalink?"
                f"repo=updates-released-f{state.config.release}&arch=$basearch"
            )

        if state.config.release == "rawhide":
            # On rawhide, the "updates" repo is the same as the "fedora" repo.
            # In other versions, the "fedora" repo is frozen at release, and "updates" provides any new packages.
            updates_url = None

        # See: https://fedoraproject.org/security/
        gpgurl = "https://fedoraproject.org/fedora.gpg"

        repos = []
        for name, url in (("fedora",    release_url),
                          ("updates",   updates_url),
                          ("appstream", appstream_url),
                          ("baseos",    baseos_url),
                          ("extras",    extras_url),
                          ("crb",       crb_url)):
            if url:
                repos += [Repo(name, url, (gpgurl,))]

        setup_dnf(state, repos)
        invoke_dnf(state, "install", packages, apivfs=apivfs,
                   filelists=fedora_release_at_least(state.config.release, "38"))

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.arm64     : "aarch64",
            Architecture.ia64      : "ia64",
            Architecture.mips64_le : "mips64el",
            Architecture.mips_le   : "mipsel",
            Architecture.parisc    : "parisc64",
            Architecture.ppc64_le  : "ppc64le",
            Architecture.riscv64   : "riscv64",
            Architecture.s390x     : "s390x",
            Architecture.x86_64    : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Fedora")

        return a


def fedora_release_at_least(release: str, threshold: str) -> bool:
    if release in ("rawhide", "eln"):
        return True
    if threshold in ("rawhide", "eln"):
        return False
    # If neither is 'rawhide', both must be integers
    return int(release) >= int(threshold)
