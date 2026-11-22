# SPDX-License-Identifier: LGPL-2.1-or-later

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Optional

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.log import die
from mkosi.run import run
from mkosi.util import PathString


class BST(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "bst"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("bst")

    @classmethod
    def setup(cls, context: Context) -> None:
        if len(context.config.packages) > 1:
            die("Only a single element can be specified in Packages= when using BuildStream")
        if context.config.build_packages:
            die("BuildPackages= are not supported when using BuildStream")
        if context.config.volatile_packages:
            die("VolatilePackages= are not supported when using BuildStream")

    @classmethod
    def project_options(cls, context: Context) -> list[PathString]:
        return [
            "--same-dir",
            *context.rootoptions(),
            # bst will need write access to the current directory as it might write to .bst
            "--bind", Path.cwd(), Path.cwd(),
            # bst might need to lookup files/paths across the user's home directory so make sure it is
            # available.
            "--bind", Path.home(), Path.home(),
            "--setenv", "HOME", Path.home(),
        ]  # fmt: skip

    @classmethod
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
        reinstall: bool = False,
    ) -> None:
        options = cls.project_options(context)
        # We don't really want to run bst as (fake) root but it uses bubblewrap which stubbornly refuses to
        # run when invoked unprivileged but with capabilities. We get around this by running as fake root but
        # still setting $HOME to the user's home to reuse the buildstream cache directory.
        run(
            [cls.executable(context.config), "build", *packages],
            sandbox=cls.sandbox(context, apivfs=apivfs, options=options),
            env=cls.finalize_environment(context),
        )
        run(
            [
                cls.executable(context.config),
                "artifact",
                "checkout",
                "--force",
                "--directory=/buildroot",
                *packages,
            ],
            sandbox=cls.sandbox(context, apivfs=apivfs, options=options),
            env=cls.finalize_environment(context),
        )

        if reinstall:
            cls.collect_overlay_package_files(context, packages, options=options)

    @classmethod
    def collect_overlay_package_files(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        options: Optional[Sequence[PathString]] = None,
        **kwargs: Any,
    ) -> None:
        if options is None:
            options = cls.project_options(context)

        # checkout --force already overwrites files. Keep the explicit element's contents, not
        # those of all the runtime dependencies staged by checkout.
        result = run(
            [cls.executable(context.config), "artifact", "list-contents", *packages],
            sandbox=cls.sandbox(context, apivfs=False, options=options),
            env=cls.finalize_environment(context),
            stdout=subprocess.PIPE,
        )
        context.record_overlay_package_files(
            [line[1:] for line in result.stdout.splitlines() if line.startswith("\t")]
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
