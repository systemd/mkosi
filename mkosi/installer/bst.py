# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Sequence
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.run import run
from mkosi.log import die


class BST(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "bst"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("bst")

    @classmethod
    def architecture(cls, context: Context) -> str:
        return context.config.distribution.installer.architecture(context.config.architecture)

    @classmethod
    def setup(cls, context: Context) -> None:
        if len(context.config.packages) > 1:
            die("Only a single element can be specified in Packages= when using bst")

    @classmethod
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        options = [
            "--same-dir",
            *context.rootoptions(),
            # bst might need to lookup files/paths across the user's home directory so make sure it is
            # available.
            "--bind", Path.home(), Path.home(),
            "--setenv", "HOME", Path.home(),
        ]

        # We don't really want to run bst as (fake) root but it uses bubblewrap which stubbornly refuses to
        # run when invoked unprivileged but with capabilities. We get around this by running as fake root but
        # still setting $HOME to the user's home to reuse the buildstream cache directory.
        run(
            ["bst", "build", *packages],
            sandbox=cls.sandbox(context, apivfs=apivfs, options=options),
            env=cls.finalize_environment(context),
        )
        run(
            ["bst", "artifact", "checkout", "--force", "--directory=/buildroot", *packages],
            sandbox=cls.sandbox(context, apivfs=apivfs, options=options),
            env=cls.finalize_environment(context),
        )

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        die("Removing packages is not supported for bst")

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        pass

    @classmethod
    def createrepo(cls, context: Context) -> None:
        die("Creating package repositories is not supported for bst")
