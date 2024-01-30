# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Iterable

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import debian
from mkosi.installer.apt import Apt


class Installer(debian.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Ubuntu"

    @classmethod
    def default_release(cls) -> str:
        return "lunar"

    @staticmethod
    def repositories(context: Context, local: bool = True) -> Iterable[Apt.Repository]:
        types = ("deb", "deb-src")

        # From kinetic onwards, the usr-is-merged package is available in universe and is required by
        # mkosi to set up a proper usr-merged system so we add the universe repository unconditionally.
        components = ["main"] + (["universe"] if context.config.release not in ("focal", "jammy") else [])
        components = (*components, *context.config.repositories)

        if context.config.local_mirror and local:
            yield Apt.Repository(
                types=("deb",),
                url=context.config.local_mirror,
                suite=context.config.release,
                components=("main",),
                signedby=None,
            )
            return

        if context.want_local_repo():
            yield Apt.localrepo(context)

        if context.config.architecture in (Architecture.x86, Architecture.x86_64):
            mirror = context.config.mirror or "http://archive.ubuntu.com/ubuntu"
        else:
            mirror = context.config.mirror or "http://ports.ubuntu.com"

        signedby = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"

        yield Apt.Repository(
            types=types,
            url=mirror,
            suite=context.config.release,
            components=components,
            signedby=signedby,
        )

        yield Apt.Repository(
            types=types,
            url=mirror,
            suite=f"{context.config.release}-updates",
            components=components,
            signedby=signedby,
        )

        # Security updates repos are never mirrored. But !x86 are on the ports server.
        if context.config.architecture in [Architecture.x86, Architecture.x86_64]:
            mirror = "http://security.ubuntu.com/ubuntu/"
        else:
            mirror = "http://ports.ubuntu.com/"

        yield Apt.Repository(
            types=types,
            url=mirror,
            suite=f"{context.config.release}-security",
            components=components,
            signedby=signedby,
        )

