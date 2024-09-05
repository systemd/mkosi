# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import fedora, join_mirror
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die


class Installer(fedora.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Mageia"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def default_release(cls) -> str:
        return "cauldron"

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem"], apivfs=False)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        gpgurls = (
            find_rpm_gpgkey(
                context,
                "RPM-GPG-KEY-Mageia",
                "https://mirrors.kernel.org/mageia/distrib/$releasever/$basearch/media/core/release/media_info/pubkey",
            ),
        )

        if context.config.local_mirror:
            yield RpmRepository("core-release", f"baseurl={context.config.local_mirror}", gpgurls)
            return

        if context.config.mirror:
            url = f"baseurl={join_mirror(context.config.mirror, 'distrib/$releasever/$basearch/media/core/')}"
            yield RpmRepository("core-release", f"{url}/release", gpgurls)
            yield RpmRepository("core-updates", f"{url}/updates/", gpgurls)
        else:
            url = "mirrorlist=https://www.mageia.org/mirrorlist/?release=$releasever&arch=$basearch&section=core"
            yield RpmRepository("core-release", f"{url}&repo=release", gpgurls)
            yield RpmRepository("core-updates", f"{url}&repo=updates", gpgurls)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
            Architecture.arm64  : "aarch64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Mageia")

        return a
