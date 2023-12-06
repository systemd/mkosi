# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.architecture import Architecture
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import Repo, find_rpm_gpgkey, invoke_dnf, setup_dnf
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
    def tools_tree_packages(cls) -> list[str]:
        packages = [
            "apt",
            "archlinux-keyring",
            "bash",
            "btrfs-progs",
            "bubblewrap",
            "ca-certificates",
            "coreutils",
            "cpio",
            "curl-minimal",
            "debian-keyring",
            "distribution-gpg-keys",
            "dnf5",
            "dosfstools",
            "e2fsprogs",
            "erofs-utils",
            "mtools",
            "openssh-clients",
            "openssl",
            "pacman",
            "python3-cryptography",
            "qemu-kvm-core",
            "shadow-utils",
            "socat",
            "squashfs-tools",
            "strace",
            "swtpm",
            "systemd-container",
            "systemd-udev",
            "systemd-ukify",
            "systemd",
            "tar",
            "util-linux",
            "virtiofsd",
            "xfsprogs",
            "xz",
            "zstd",
            "zypper",
        ]

        if Architecture.native() in (Architecture.x86_64, Architecture.arm64):
            packages += [
                "edk2-ovmf",
                "pesign",
                "sbsigntools",
            ]

        return packages

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
            repos += [Repo("fedora", f"baseurl={state.config.local_mirror}", gpgurls)]
        elif state.config.release == "eln":
            mirror = state.config.mirror or "https://odcs.fedoraproject.org/composes/production/latest-Fedora-ELN/compose"
            for repo in ("Appstream", "BaseOS", "Extras", "CRB"):
                url = f"baseurl={join_mirror(mirror, repo)}"
                repos += [
                    Repo(repo.lower(), f"{url}/$basearch/os", gpgurls),
                    Repo(repo.lower(), f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                    Repo(repo.lower(), f"{url}/source/tree", gpgurls, enabled=False),
                ]
        elif state.config.mirror:
            directory = "development" if state.config.release == "rawhide" else "releases"
            url = f"baseurl={join_mirror(state.config.mirror, f'{directory}/$releasever/Everything')}"
            repos += [
                Repo("fedora", f"{url}/$basearch/os", gpgurls),
                Repo("fedora-debuginfo", f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                Repo("fedora-source", f"{url}/source/tree", gpgurls, enabled=False),
            ]

            if state.config.release != "rawhide":
                url = f"baseurl={join_mirror(state.config.mirror, 'updates/$releasever/Everything')}"
                repos += [
                    Repo("updates", f"{url}/$basearch", gpgurls),
                    Repo("updates-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False),
                    Repo("updates-source", f"{url}/SRPMS", gpgurls, enabled=False),
                ]

                url = f"baseurl={join_mirror(state.config.mirror, 'updates/testing/$releasever/Everything')}"
                repos += [
                    Repo("updates-testing", f"{url}/$basearch", gpgurls, enabled=False),
                    Repo("updates-testing-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False),
                    Repo("updates-testing-source", f"{url}/source/tree", gpgurls, enabled=False)
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
                    Repo(
                        "updates-debuginfo",
                        f"{url}&repo=updates-released-debug-f$releasever",
                        gpgurls,
                        enabled=False,
                    ),
                    Repo("updates-source", f"{url}&repo=updates-released-source-f$releasever", gpgurls, enabled=False),
                    Repo("updates-testing", f"{url}&repo=updates-testing-f$releasever", gpgurls, enabled=False),
                    Repo(
                        "updates-testing-debuginfo",
                        f"{url}&repo=updates-testing-debug-f$releasever",
                        gpgurls,
                        enabled=False,
                    ),
                    Repo(
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
