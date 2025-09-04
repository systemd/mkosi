# SPDX-License-Identifier: LGPL-2.1-or-later

import re
import subprocess
import tempfile
from collections.abc import Iterable
from pathlib import Path

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distributions import (
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.log import die
from mkosi.util import tuplify

DISTRIBUTION_GPG_KEYS_UPSTREAM = (
    "https://raw.githubusercontent.com/rpm-software-management/distribution-gpg-keys/main/keys/fedora"
)


def read_remote_rawhide_key_symlink(context: Context) -> str:
    # https://fedoraproject.org/fedora.gpg is always outdated when the rawhide key changes. Instead,
    # let's fetch it from distribution-gpg-keys on github if necessary, which is generally up-to-date.
    with tempfile.TemporaryDirectory() as d:
        # The rawhide key is a symlink and github doesn't redirect those to the actual file for some reason
        curl(context.config, f"{DISTRIBUTION_GPG_KEYS_UPSTREAM}/RPM-GPG-KEY-fedora-rawhide-primary", Path(d))
        return (Path(d) / "RPM-GPG-KEY-fedora-rawhide-primary").read_text()


@tuplify
def find_fedora_rpm_gpgkeys(context: Context) -> Iterable[str]:
    versionre = re.compile(r"RPM-GPG-KEY-fedora-(\d+)-primary")
    # ELN uses the rawhide GPG keys.
    release = "rawhide" if context.config.release == "eln" else context.config.release

    if release == "rawhide" and context.config.repository_key_fetch:
        # Rawhide is a moving target and signed with a different GPG key every time a new Fedora release is
        # done. In distribution-gpg-keys this is modeled by a symlink that is continuously updated to point
        # to the current GPG key for rawhide. Of course, this symlink gets outdated when using a locally
        # installed distribution-gpg-keys package. If we're allowed to look up GPG keys remotely, look up the
        # current rawhide version remotely and use the associated remote key.
        key = read_remote_rawhide_key_symlink(context)
        if not (rawhide_will_be := versionre.match(key)):
            die(f"Missing Fedora version in remote rawhide key {key} from distribution-gpg-keys")

        version = int(rawhide_will_be.group(1))
        yield f"{DISTRIBUTION_GPG_KEYS_UPSTREAM}/RPM-GPG-KEY-fedora-{version}-primary"

        # Also use the N+1 key if it exists to avoid issues when rawhide has been moved to the next key but
        # the rawhide symlink in distribution-gpg-keys hasn't been updated yet.
        try:
            with tempfile.TemporaryDirectory() as d:
                curl(
                    context.config,
                    f"{DISTRIBUTION_GPG_KEYS_UPSTREAM}/RPM-GPG-KEY-fedora-{version + 1}-primary",
                    Path(d),
                    log=False,
                )

            yield f"{DISTRIBUTION_GPG_KEYS_UPSTREAM}/RPM-GPG-KEY-fedora-{version + 1}-primary"
        except subprocess.CalledProcessError:
            pass

        return

    key = find_rpm_gpgkey(
        context,
        key=f"RPM-GPG-KEY-fedora-{release}-primary",
        fallback=f"{DISTRIBUTION_GPG_KEYS_UPSTREAM}/RPM-GPG-KEY-fedora-{release}-primary",
    )

    yield key

    if release == "rawhide" and (rawhide_will_be := versionre.match(Path(key).name)):
        # When querying the rawhide version remotely, we add the N+1 key as the symlink might not have been
        # updated yet. We do expect the symlink update to happen in reasonable time so we only add the N+1
        # key. When using a locally installed distribution-gpg-keys package on older Fedora versions, there's
        # a non-zero chance that rawhide might already be using the N+2 key. So let's play it safe and add
        # all newer keys in this case.
        version = int(rawhide_will_be.group(1))

        i = 1
        while newerkey := find_rpm_gpgkey(
            context,
            key=f"RPM-GPG-KEY-fedora-{version + i}-primary",
            required=False,
        ):
            yield newerkey
            i += 1


class Installer(DistributionInstaller):
    _default_release = "rawhide"
    _releasemap = {
        "adams": ("42", "42"),
        "rawhide": ("99", "rawhide"),
    }

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
    def grub_prefix(cls) -> str:
        return "grub2"

    @classmethod
    def package_manager(cls, config: Config) -> type[Dnf]:
        return Dnf

    @classmethod
    def setup(cls, context: Context) -> None:
        setup_rpm(context)
        Dnf.setup(
            context,
            list(cls.repositories(context)),
            filelists=False,
            metadata_expire="6h" if context.config.release in ("eln", "rawhide") else None,
        )

    @classmethod
    def install(cls, context: Context) -> None:
        Dnf.install(context, ["basesystem"], apivfs=False)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        gpgurls = find_fedora_rpm_gpgkeys(context)

        if context.config.local_mirror:
            yield RpmRepository("fedora", f"baseurl={context.config.local_mirror}", gpgurls)
            return

        if context.config.release == "eln":
            mirror = context.config.mirror or "https://dl.fedoraproject.org/pub/eln/1/"

            for repo in ("AppStream", "BaseOS", "Extras", "CRB"):
                url = f"baseurl={join_mirror(mirror, repo)}"
                yield RpmRepository(repo.lower(), f"{url}/$basearch/os", gpgurls)
                yield RpmRepository(
                    f"{repo.lower()}-debuginfo", f"{url}/$basearch/debug/tree", gpgurls, enabled=False
                )
                yield RpmRepository(f"{repo.lower()}-source", f"{url}/source/tree", gpgurls, enabled=False)
        elif m := context.config.mirror:
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
                yield RpmRepository(
                    "updates-testing-debuginfo", f"{url}/$basearch/debug", gpgurls, enabled=False
                )
                yield RpmRepository("updates-testing-source", f"{url}/source/tree", gpgurls, enabled=False)
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"
            yield RpmRepository("fedora", f"{url}&repo=fedora-$releasever", gpgurls)
            yield RpmRepository(
                "fedora-debuginfo", f"{url}&repo=fedora-debug-$releasever", gpgurls, enabled=False
            )
            yield RpmRepository(
                "fedora-source", f"{url}&repo=fedora-source-$releasever", gpgurls, enabled=False
            )

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
                    enabled=False,
                )
                yield RpmRepository(
                    "updates-testing", f"{url}&repo=updates-testing-f$releasever", gpgurls, enabled=False
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
            Architecture.arm64:     "aarch64",
            Architecture.mips64_le: "mips64el",
            Architecture.mips_le:   "mipsel",
            Architecture.ppc64_le:  "ppc64le",
            Architecture.riscv64:   "riscv64",
            Architecture.s390x:     "s390x",
            Architecture.x86_64:    "x86_64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by Fedora")

        return a
