# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import fedora, join_mirror
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.log import die


class Installer(fedora.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Amazon Linux"

    @classmethod
    def default_release(cls) -> str:
        return "latest"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def setup(cls, context: Context) -> None:
        setup_rpm(context, dbpath="/var/lib/rpm")
        Dnf.setup(context, list(cls.repositories(context)), filelists=False)

    @classmethod
    def install(cls, context: Context) -> None:
        Dnf.install(context, ["filesystem"], apivfs=False)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        gpgurls = (
            find_rpm_gpgkey(
                context,
                "RPM-GPG-KEY-amazon-linux-2023",
                "https://raw.githubusercontent.com/rpm-software-management/distribution-gpg-keys/refs/heads/main/keys/amazon-linux/RPM-GPG-KEY-amazon-linux-2023",
            ),
        )
        if context.config.local_mirror:
            yield RpmRepository("base", f"baseurl={context.config.local_mirror}", gpgurls)
            return

        if context.config.mirror:
            url = f"baseurl={join_mirror(context.config.mirror, 'core/mirrors/$releasever')}"
            yield RpmRepository("base", f"{url}/$basearch", gpgurls)
            yield RpmRepository("debug", f"{url}/debuginfo/$basearch", gpgurls, enabled=False)
            yield RpmRepository("source", f"{url}/SRPMS", gpgurls, enabled=False)
        else:
            url = "mirrorlist=https://cdn.amazonlinux.com/al2023/core/mirrors/$releasever"
            yield RpmRepository("base", f"{url}/$basearch/mirror.list", gpgurls)
            yield RpmRepository("debug", f"{url}/debuginfo/$basearch/mirror.list", gpgurls, enabled=False)
            yield RpmRepository("source", f"{url}/SRPMS/mirror.list", gpgurls, enabled=False)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm64:  "aarch64",
            Architecture.x86_64: "x86_64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a
