# SPDX-License-Identifier: LGPL-2.1+

from mkosi.architecture import Architecture
from mkosi.distributions.debian import DebianInstaller
from mkosi.state import MkosiState


class UbuntuInstaller(DebianInstaller):
    @staticmethod
    def repositories(state: MkosiState, local: bool = True) -> list[str]:
        repos = ["main"]
        if state.config.release not in ("focal", "jammy"):
            # From kinetic onwards, the usr-is-merged package is available in universe and is required by
            # mkosi to set up a proper usr-merged system so we add the universe repository unconditionally.
            repos += ["universe"]

        repos = ' '.join((*repos, *state.config.repositories))

        if state.config.local_mirror and local:
            return [f"deb [trusted=yes] {state.config.local_mirror} {state.config.release} {repos}"]

        main = f"deb {state.config.mirror} {state.config.release} {repos}"
        updates = f"deb {state.config.mirror} {state.config.release}-updates {repos}"

        # Security updates repos are never mirrored. But !x86 are on the ports server.
        if state.config.architecture in [Architecture.x86, Architecture.x86_64]:
            security = f"deb http://security.ubuntu.com/ubuntu/ {state.config.release}-security {repos}"
        else:
            security = f"deb http://ports.ubuntu.com/ {state.config.release}-security {repos}"

        return [main, updates, security]
