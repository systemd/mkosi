# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable
from pathlib import Path

from mkosi.context import Context
from mkosi.distributions import Distribution, debian
from mkosi.installer.apt import AptRepository


class Installer(debian.Installer):
    _default_release = "noble"
    _releasemap = {
        "20.04": ("20.04", "focal"),
        "focal": ("20.04", "focal"),
        "focal fossa": ("20.04", "focal"),
        "22.04": ("22.04", "jammy"),
        "jammy": ("22.04", "jammy"),
        "jammy jellyfish": ("22.04", "jammy"),
        "24.04": ("24.04", "noble"),
        "noble": ("24.04", "noble"),
        "noble numbat": ("24.04", "noble"),
        "24.10": ("24.10", "oracular"),
        "oracular": ("24.10", "oracular"),
        "oracular oriole": ("24.10", "oracular"),
        "25.04": ("25.04", "plucky"),
        "plucky": ("25.04", "plucky"),
        "plucky puffin": ("25.04", "plucky"),
    }

    @classmethod
    def pretty_name(cls) -> str:
        return "Ubuntu"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.debian

    @classmethod
    def repositories(cls, context: Context, local: bool = True) -> Iterable[AptRepository]:
        types = ("deb", "deb-src")

        components = (
            "main",
            *context.config.repositories,
        )

        if context.config.local_mirror and local:
            yield AptRepository(
                types=("deb",),
                url=context.config.local_mirror,
                suite=str(context.config.release),
                components=("main",),
                signedby=None,
            )
            return

        if context.config.architecture.is_x86_variant():
            mirror = context.config.mirror or "http://archive.ubuntu.com/ubuntu"
        else:
            mirror = context.config.mirror or "http://ports.ubuntu.com"

        signedby = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")

        yield AptRepository(
            types=types,
            url=mirror,
            suite=str(context.config.release),
            components=components,
            signedby=signedby,
        )

        yield AptRepository(
            types=types,
            url=mirror,
            suite=f"{context.config.release}-updates",
            components=components,
            signedby=signedby,
        )

        # Security updates repos are never mirrored. But !x86 are on the ports server.
        if context.config.architecture.is_x86_variant():
            mirror = "http://security.ubuntu.com/ubuntu"
        else:
            mirror = "http://ports.ubuntu.com"

        yield AptRepository(
            types=types,
            url=mirror,
            suite=f"{context.config.release}-security",
            components=components,
            signedby=signedby,
        )
