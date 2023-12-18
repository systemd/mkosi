# SPDX-License-Identifier: LGPL-2.1+

from mkosi.config import Architecture
from mkosi.distributions import debian
from mkosi.state import MkosiState


class Installer(debian.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Ubuntu"

    @classmethod
    def default_release(cls) -> str:
        return "lunar"

    @staticmethod
    def repositories(state: MkosiState, local: bool = True) -> list[str]:
        if state.config.local_mirror and local:
            return [f"deb [trusted=yes] {state.config.local_mirror} {state.config.release} main"]

        archives = ("deb", "deb-src")

        if state.config.architecture in (Architecture.x86, Architecture.x86_64):
            mirror = state.config.mirror or "http://archive.ubuntu.com/ubuntu"
        else:
            mirror = state.config.mirror or "http://ports.ubuntu.com"

        # From kinetic onwards, the usr-is-merged package is available in universe and is required by
        # mkosi to set up a proper usr-merged system so we add the universe repository unconditionally.
        components = ["main"] + (["universe"] if state.config.release not in ("focal", "jammy") else [])
        components = ' '.join((*components, *state.config.repositories))

        repos = [
            f"{archive} {mirror} {state.config.release} {components}"
            for archive in archives
        ]

        repos += [
            f"{archive} {mirror} {state.config.release}-updates {components}"
            for archive in archives
        ]

        # Security updates repos are never mirrored. But !x86 are on the ports server.
        if state.config.architecture in [Architecture.x86, Architecture.x86_64]:
            mirror = "http://security.ubuntu.com/ubuntu/"
        else:
            mirror = "http://ports.ubuntu.com/"

        repos += [
            f"{archive} {mirror} {state.config.release}-security {components}"
            for archive in archives
        ]

        return repos
