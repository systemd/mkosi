# SPDX-License-Identifier: LGPL-2.1+

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import debian


class Installer(debian.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Ubuntu"

    @classmethod
    def default_release(cls) -> str:
        return "lunar"

    @staticmethod
    def repositories(context: Context, local: bool = True) -> list[str]:
        if context.config.local_mirror and local:
            return [f"deb [trusted=yes] {context.config.local_mirror} {context.config.release} main"]

        archives = ("deb", "deb-src")

        if context.config.architecture in (Architecture.x86, Architecture.x86_64):
            mirror = context.config.mirror or "http://archive.ubuntu.com/ubuntu"
        else:
            mirror = context.config.mirror or "http://ports.ubuntu.com"

        signedby = "[signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg]"

        # From kinetic onwards, the usr-is-merged package is available in universe and is required by
        # mkosi to set up a proper usr-merged system so we add the universe repository unconditionally.
        components = ["main"] + (["universe"] if context.config.release not in ("focal", "jammy") else [])
        components = ' '.join((*components, *context.config.repositories))

        repos = [
            f"{archive} {signedby} {mirror} {context.config.release} {components}"
            for archive in archives
        ]

        repos += [
            f"{archive} {signedby} {mirror} {context.config.release}-updates {components}"
            for archive in archives
        ]

        # Security updates repos are never mirrored. But !x86 are on the ports server.
        if context.config.architecture in [Architecture.x86, Architecture.x86_64]:
            mirror = "http://security.ubuntu.com/ubuntu/"
        else:
            mirror = "http://ports.ubuntu.com/"

        repos += [
            f"{archive} {signedby} {mirror} {context.config.release}-security {components}"
            for archive in archives
        ]

        return repos
