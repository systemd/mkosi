# SPDX-License-Identifier: LGPL-2.1-or-later

import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer import PackageManager
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.log import die
from mkosi.util import listify, startswith, tuplify


@tuplify
def find_fedora_rpm_gpgkeys(context: Context) -> Iterable[str]:
    key1 = find_rpm_gpgkey(context, key=f"RPM-GPG-KEY-fedora-{context.config.release}-primary")
    key2 = find_rpm_gpgkey(context, key=f"RPM-GPG-KEY-fedora-{context.config.release}-secondary")

    if key1:
        # During branching, there is always a kerfuffle with the key transition.
        # For Rawhide, try to load the N+1 key, just in case our local configuration
        # still indicates that Rawhide==N, but really Rawhide==N+1.
        if context.config.release == "rawhide" and (rhs := startswith(key1, "file://")):
            path = Path(rhs).resolve()
            if m := re.match(r"RPM-GPG-KEY-fedora-(\d+)-(primary|secondary)", path.name):
                version = int(m.group(1))
                if key3 := find_rpm_gpgkey(context, key=f"RPM-GPG-KEY-fedora-{version + 1}-primary"):
                    # We yield the resolved path for key1, to make it clear that it's
                    # for version N, and the other key is for version N+1.
                    key1 = path.as_uri()
                    yield key3

        yield key1
    if key2:
        yield key2
    if not key1 and not key2:
        yield "https://fedoraproject.org/fedora.gpg"


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
        return "40"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.fedora

    @classmethod
    def grub_prefix(cls) -> str:
        return "grub2"

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        return Dnf

    @classmethod
    def setup(cls, context: Context) -> None:
        Dnf.setup(context, cls.repositories(context), filelists=False)
        setup_rpm(context)

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["basesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        Dnf.invoke(context, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        Dnf.invoke(context, "remove", packages, apivfs=True)

    @classmethod
    @listify
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        gpgurls = find_fedora_rpm_gpgkeys(context)

        if context.config.local_mirror:
            yield RpmRepository("fedora", f"baseurl={context.config.local_mirror}", gpgurls)
            return

        if context.config.release == "eln":
            mirror = context.config.mirror or "https://odcs.fedoraproject.org/composes/production/latest-Fedora-ELN/compose"
            for repo in ("Appstream", "BaseOS", "Extras", "CRB"):
                url = f"baseurl={join_mirror(mirror, repo)}"
                yield RpmRepository(repo.lower(), f"{url}/$basearch/os", gpgurls)
                yield RpmRepository(repo.lower(), f"{url}/$basearch/debug/tree", gpgurls, enabled=False)
                yield RpmRepository(repo.lower(), f"{url}/source/tree", gpgurls, enabled=False)
        elif (m := context.config.mirror):
            directory = "development" if context.config.release == "rawhide" else "releases"
            url = f"baseurl={join_mirror(m, f'linux/{directory}/$releasever/Everything')}"
            yield RpmRepository("fedora", f"{url}/$basearch/os", gpgurls)
            yield RpmRepository("fedora-debuginfo", f"{url}/$basearch/debug/tree", gpgurls, enabled=False)
            yield RpmRepository("fedora-source", f"{url}/source/tree", gpgurls, enabled=False)

            if context.config.release != "rawhide":
                url = f"baseurl={join_mirror(m, 'linux/updates/$releasever/Everything')}"
                yield RpmRepository("updates", f"{url}/$basearch", gpgurls)
                yield RpmRepository("updates-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False)
                yield RpmRepository("updates-source", f"{url}/source/tree", gpgurls, enabled=False)

                url = f"baseurl={join_mirror(m, 'linux/updates/testing/$releasever/Everything')}"
                yield RpmRepository("updates-testing", f"{url}/$basearch", gpgurls, enabled=False)
                yield RpmRepository("updates-testing-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False)
                yield RpmRepository("updates-testing-source", f"{url}/source/tree", gpgurls, enabled=False)
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"
            yield RpmRepository("fedora", f"{url}&repo=fedora-$releasever", gpgurls)
            yield RpmRepository("fedora-debuginfo", f"{url}&repo=fedora-debug-$releasever", gpgurls, enabled=False)
            yield RpmRepository("fedora-source", f"{url}&repo=fedora-source-$releasever", gpgurls, enabled=False)

            if context.config.release != "rawhide":
                yield RpmRepository("updates", f"{url}&repo=updates-released-f$releasever", gpgurls)
                yield RpmRepository(
                    "updates-debuginfo",
                    f"{url}&repo=updates-released-debug-f$releasever",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    "updates-source",
                    f"{url}&repo=updates-released-source-f$releasever",
                    gpgurls,
                    enabled=False
                )
                yield RpmRepository(
                    "updates-testing",
                    f"{url}&repo=updates-testing-f$releasever",
                    gpgurls,
                    enabled=False
                )
                yield RpmRepository(
                    "updates-testing-debuginfo",
                    f"{url}&repo=updates-testing-debug-f$releasever",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    "updates-testing-source",
                    f"{url}&repo=updates-testing-source-f$releasever",
                    gpgurls,
                    enabled=False,
                )

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
