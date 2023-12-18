# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import invoke_dnf, setup_dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die
from mkosi.state import MkosiState


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Fedora Linux"

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def default_release(cls) -> str:
        return "39"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.fedora

    @classmethod
    def setup(cls, state: MkosiState) -> None:
        gpgurls = (
            find_rpm_gpgkey(
                state,
                key=f"RPM-GPG-KEY-fedora-{state.config.release}-primary",
                url="https://fedoraproject.org/fedora.gpg",
            ),
        )

        repos = []

        if state.config.local_mirror:
            repos += [RpmRepository("fedora", f"baseurl={state.config.local_mirror}", gpgurls)]
        elif state.config.release == "eln":
            mirror = state.config.mirror or "https://odcs.fedoraproject.org/composes/production/latest-Fedora-ELN/compose"
            for repo in ("Appstream", "BaseOS", "Extras", "CRB"):
                url = f"baseurl={join_mirror(mirror, repo)}"
                repos += [
                    RpmRepository(repo.lower(), f"{url}/$basearch/os", gpgurls),
                    RpmRepository(repo.lower(), f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                    RpmRepository(repo.lower(), f"{url}/source/tree", gpgurls, enabled=False),
                ]
        elif state.config.mirror:
            directory = "development" if state.config.release == "rawhide" else "releases"
            url = f"baseurl={join_mirror(state.config.mirror, f'{directory}/$releasever/Everything')}"
            repos += [
                RpmRepository("fedora", f"{url}/$basearch/os", gpgurls),
                RpmRepository("fedora-debuginfo", f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                RpmRepository("fedora-source", f"{url}/source/tree", gpgurls, enabled=False),
            ]

            if state.config.release != "rawhide":
                url = f"baseurl={join_mirror(state.config.mirror, 'updates/$releasever/Everything')}"
                repos += [
                    RpmRepository("updates", f"{url}/$basearch", gpgurls),
                    RpmRepository("updates-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False),
                    RpmRepository("updates-source", f"{url}/source/tree", gpgurls, enabled=False),
                ]

                url = f"baseurl={join_mirror(state.config.mirror, 'updates/testing/$releasever/Everything')}"
                repos += [
                    RpmRepository("updates-testing", f"{url}/$basearch", gpgurls, enabled=False),
                    RpmRepository("updates-testing-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False),
                    RpmRepository("updates-testing-source", f"{url}/source/tree", gpgurls, enabled=False)
                ]
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"
            repos += [
                RpmRepository("fedora", f"{url}&repo=fedora-$releasever", gpgurls),
                RpmRepository("fedora-debuginfo", f"{url}&repo=fedora-debug-$releasever", gpgurls, enabled=False),
                RpmRepository("fedora-source", f"{url}&repo=fedora-source-$releasever", gpgurls, enabled=False),
            ]

            if state.config.release != "rawhide":
                repos += [
                    RpmRepository("updates", f"{url}&repo=updates-released-f$releasever", gpgurls),
                    RpmRepository(
                        "updates-debuginfo",
                        f"{url}&repo=updates-released-debug-f$releasever",
                        gpgurls,
                        enabled=False,
                    ),
                    RpmRepository(
                        "updates-source",
                        f"{url}&repo=updates-released-source-f$releasever",
                        gpgurls,
                        enabled=False
                    ),
                    RpmRepository(
                        "updates-testing",
                        f"{url}&repo=updates-testing-f$releasever",
                        gpgurls,
                        enabled=False
                    ),
                    RpmRepository(
                        "updates-testing-debuginfo",
                        f"{url}&repo=updates-testing-debug-f$releasever",
                        gpgurls,
                        enabled=False,
                    ),
                    RpmRepository(
                        "updates-testing-source",
                        f"{url}&repo=updates-testing-source-f$releasever",
                        gpgurls,
                        enabled=False,
                    ),
                ]

        # TODO: Use `filelists=True` when F37 goes EOL.
        setup_dnf(state, repos, filelists=fedora_release_at_most(state.config.release, "37"))

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_dnf(state, "remove", packages)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
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
