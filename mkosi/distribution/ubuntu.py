# SPDX-License-Identifier: LGPL-2.1-or-later

import datetime
import locale
from collections.abc import Iterable
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distribution import Distribution, debian, join_mirror
from mkosi.installer.apt import AptRepository
from mkosi.log import die
from mkosi.util import startswith


class Installer(debian.Installer, distribution=Distribution.ubuntu):
    @classmethod
    def pretty_name(cls) -> str:
        return "Ubuntu"

    @classmethod
    def default_release(cls) -> str:
        return "devel"

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
                suite=context.config.release,
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
            suite=context.config.release,
            components=components,
            signedby=signedby,
            snapshot=context.config.snapshot,
        )

        yield AptRepository(
            types=types,
            url=mirror,
            suite=f"{context.config.release}-updates",
            components=components,
            signedby=signedby,
            snapshot=context.config.snapshot,
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
            snapshot=context.config.snapshot,
        )

    @classmethod
    def latest_snapshot(cls, config: Config) -> str:
        mirror = config.mirror or "http://snapshot.ubuntu.com"
        release = curl(config, join_mirror(mirror, f"ubuntu/dists/{config.release}-updates/Release"))

        for line in release.splitlines():
            if date := startswith(line, "Date: "):
                # %a and %b parse the abbreviated day of the week and the abbreviated month which are both
                # locale-specific so set the locale to C explicitly to make sure we try to parse the english
                # abbreviations used in the Release file.
                lc = locale.setlocale(locale.LC_TIME)
                try:
                    locale.setlocale(locale.LC_TIME, "C")
                    return datetime.datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %Z").strftime(
                        "%Y%m%dT%H%M%SZ"
                    )
                finally:
                    locale.setlocale(locale.LC_TIME, lc)

        die("Release file is missing Date field")

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        return package.startswith("linux-")
