# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import createrepo_dnf, invoke_dnf, setup_dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die


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
    def grub_prefix(cls) -> str:
        return "grub2"

    @classmethod
    def createrepo(cls, context: Context) -> None:
        return createrepo_dnf(context)

    @classmethod
    def setup(cls, context: Context) -> None:
        gpgurls = (
            find_rpm_gpgkey(
                context,
                key=f"RPM-GPG-KEY-fedora-{context.config.release}-primary",
                url="https://fedoraproject.org/fedora.gpg",
            ),
        )

        repos = []

        if context.config.local_mirror:
            repos += [RpmRepository("fedora", f"baseurl={context.config.local_mirror}", gpgurls)]
        elif context.config.release == "eln":
            mirror = context.config.mirror or "https://odcs.fedoraproject.org/composes/production/latest-Fedora-ELN/compose"
            for repo in ("Appstream", "BaseOS", "Extras", "CRB"):
                url = f"baseurl={join_mirror(mirror, repo)}"
                repos += [
                    RpmRepository(repo.lower(), f"{url}/$basearch/os", gpgurls),
                    RpmRepository(repo.lower(), f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                    RpmRepository(repo.lower(), f"{url}/source/tree", gpgurls, enabled=False),
                ]
        elif context.config.mirror:
            directory = "development" if context.config.release == "rawhide" else "releases"
            url = f"baseurl={join_mirror(context.config.mirror, f'fedora/{directory}/$releasever/Everything')}"
            repos += [
                RpmRepository("fedora", f"{url}/$basearch/os", gpgurls),
                RpmRepository("fedora-debuginfo", f"{url}/$basearch/debug/tree", gpgurls, enabled=False),
                RpmRepository("fedora-source", f"{url}/source/tree", gpgurls, enabled=False),
            ]

            if context.config.release != "rawhide":
                url = f"baseurl={join_mirror(context.config.mirror, 'updates/$releasever/Everything')}"
                repos += [
                    RpmRepository("updates", f"{url}/$basearch", gpgurls),
                    RpmRepository("updates-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False),
                    RpmRepository("updates-source", f"{url}/source/tree", gpgurls, enabled=False),
                ]

                url = f"baseurl={join_mirror(context.config.mirror, 'updates/testing/$releasever/Everything')}"
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

            if context.config.release != "rawhide":
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

        setup_dnf(context, repos)

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_dnf(context, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        invoke_dnf(context, "remove", packages)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm64     : "aarch64",
            Architecture.mips64_le : "mips64el",
            Architecture.mips_le   : "mipsel",
            Architecture.ppc64_le  : "ppc64le",
            Architecture.riscv64   : "riscv64",
            Architecture.s390x     : "s390x",
            Architecture.x86_64    : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Fedora")

        return a
