# SPDX-License-Identifier: LGPL-2.1+

from mkosi.architecture import Architecture
from mkosi.distributions.debian import DebianInstaller
from mkosi.state import MkosiState


class UbuntuInstaller(DebianInstaller):
    @staticmethod
    def repositories(state: MkosiState) -> list[str]:
        repos = ' '.join(("main", *state.config.repositories))

        main = f"deb {state.config.mirror} {state.config.release} {repos}"
        updates = f"deb {state.config.mirror} {state.config.release}-updates {repos}"

        # Security updates repos are never mirrored. But !x86 are on the ports server.
        if state.config.architecture in [Architecture.x86, Architecture.x86_64]:
            security = f"deb http://security.ubuntu.com/ubuntu/ {state.config.release}-security {repos}"
        else:
            security = f"deb http://ports.ubuntu.com/ {state.config.release}-security {repos}"

        return [main, updates, security]
