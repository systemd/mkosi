# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable
from pathlib import Path

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import Distribution, debian
from mkosi.installer.apt import AptRepository
from mkosi.log import die


class Installer(debian.Installer):
    @classmethod
    def pretty_name(cls) -> str:
        return "Kali Linux"

    @classmethod
    def default_release(cls) -> str:
        return "kali-rolling"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.kali

    @classmethod
    def repositories(cls, context: Context, local: bool = True) -> Iterable[AptRepository]:
        if context.config.snapshot:
            die(f"Snapshot= is not supported for {cls.pretty_name()}")

        if context.config.local_mirror and local:
            yield AptRepository(
                types=("deb",),
                url=context.config.local_mirror,
                suite=context.config.release,
                components=("main",),
                signedby=None,
            )
            return

        yield AptRepository(
            types=("deb", "deb-src"),
            url=context.config.mirror or "http://http.kali.org/kali",
            suite=context.config.release,
            components=("main", *context.config.repositories),
            signedby=Path("/usr/share/keyrings/kali-archive-keyring.gpg"),
        )

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm64: "arm64",
            Architecture.arm: "armhf",
            Architecture.x86_64: "amd64",
            Architecture.x86: "i386",
        }.get(arch)

        if not a:
            die(f"Architecture {arch} is not supported by {cls.pretty_name()}")

        return a
