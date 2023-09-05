# SPDX-License-Identifier: LGPL-2.1+

import urllib.parse
from collections.abc import Sequence

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller, PackageType
from mkosi.installer.dnf import Repo, invoke_dnf, setup_dnf
from mkosi.log import die
from mkosi.state import MkosiState


class FedoraInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        # See: https://fedoraproject.org/security/
        gpgurls = ("https://fedoraproject.org/fedora.gpg",)
        repos = []

        if state.config.local_mirror:
            repos += [Repo("fedora", f"baseurl={state.config.mirror}", gpgurls)]
        elif state.config.release == "eln":
            assert state.config.mirror
            for repo in ("Appstream", "BaseOS", "Extras", "CRB"):
                url = f"baseurl={urllib.parse.urljoin(state.config.mirror, repo)}"
                repos += [
                    Repo(repo.lower(), f"{url}/$basearch/os", gpgurls),
                    Repo(repo.lower(), f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                    Repo(repo.lower(), f"{url}/source/tree", gpgurls, enabled=False),
                ]
        elif state.config.mirror:
            directory = "development" if state.config.release == "rawhide" else "releases"
            url = f"baseurl={urllib.parse.urljoin(state.config.mirror, f'{directory}/$releasever/Everything')}"
            repos += [
                Repo("fedora", f"{url}/$basearch/os", gpgurls),
                Repo("fedora-debuginfo", f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                Repo("fedora-source", f"{url}/source/tree", gpgurls, enabled=False),
            ]

            if state.config.release != "rawhide":
                url = f"baseurl={urllib.parse.urljoin(state.config.mirror, 'updates/$releasever/Everything')}"
                repos += [
                    Repo("updates", f"{url}/$basearch", gpgurls),
                    Repo("updates-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False),
                    Repo("updates-source", f"{url}/SRPMS", gpgurls, enabled=False),
                ]
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"
            repos += [
                Repo("fedora", f"{url}&repo=fedora-$releasever", gpgurls),
                Repo("fedora-debuginfo", f"{url}&repo=fedora-debug-$releasever", gpgurls, enabled=False),
                Repo("fedora-source", f"{url}&repo=fedora-source-$releasever", gpgurls, enabled=False),
            ]

            if state.config.release != "rawhide":
                repos += [
                    Repo("updates", f"{url}&repo=updates-released-f$releasever", gpgurls),
                    Repo("updates-debuginfo", f"{url}&repo=updates-released-debug-f$releasever", gpgurls, enabled=False),
                    Repo("updates-source", f"{url}&repo=updates-released-source-f$releasever", gpgurls, enabled=False),
                ]

        # TODO: Use `filelists=True` when F37 goes EOL.
        setup_dnf(state, repos, filelists=fedora_release_at_most(state.config.release, "37"))

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(state, ["install"], packages, apivfs=apivfs)

    @classmethod
    def download_packages(cls, state: MkosiState) -> None:
        invoke_dnf(state, ["install", "--downloadonly"], ["filesystem"], apivfs=False) #TODO: apivfs=True?

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, ["remove"], packages)

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


def fedora_release_at_most(release: str, threshold: str) -> bool:
    if release in ("rawhide", "eln"):
        return False
    if threshold in ("rawhide", "eln"):
        return True
    # If neither is 'rawhide', both must be integers
    return int(release) <= int(threshold)
