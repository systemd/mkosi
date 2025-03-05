# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import fedora, join_mirror
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey
from mkosi.log import die


class Installer(fedora.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "OpenMandriva"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def default_release(cls) -> str:
        return "cooker"

    @classmethod
    def install(cls, context: Context) -> None:
        Dnf.install(context, ["filesystem"], apivfs=False)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        mirror = context.config.mirror or "http://mirror.openmandriva.org"

        gpgurls = (
            find_rpm_gpgkey(
                context,
                "RPM-GPG-KEY-OpenMandriva",
                "https://raw.githubusercontent.com/OpenMandrivaAssociation/openmandriva-repos/master/RPM-GPG-KEY-OpenMandriva",
            ),
        )

        if context.config.local_mirror:
            yield RpmRepository("main-release", f"baseurl={context.config.local_mirror}", gpgurls)
            return

        url = f"baseurl={join_mirror(mirror, '$releasever/repository/$basearch/main')}"
        yield RpmRepository("main-release", f"{url}/release", gpgurls)
        yield RpmRepository("main-updates", f"{url}/updates", gpgurls)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64:  "x86_64",
            Architecture.arm64:   "aarch64",
            Architecture.riscv64: "riscv64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by OpenMandriva")

        return a
