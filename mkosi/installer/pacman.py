# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import os
import shutil
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.mounts import finalize_source_mounts
from mkosi.run import run
from mkosi.sandbox import Mount, apivfs_cmd
from mkosi.types import _FILE, CompletedProcess, PathString
from mkosi.util import umask
from mkosi.versioncomp import GenericVersion


@dataclasses.dataclass(frozen=True)
class PacmanRepository:
    id: str
    url: str


class Pacman(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "pacman"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("pacman")

    @classmethod
    def cache_subdirs(cls, cache: Path) -> list[Path]:
        return [cache / "pkg"]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "pacman": apivfs_cmd() + cls.env_cmd(context) + cls.cmd(context),
            "mkosi-install"  : ["pacman", "--sync", "--needed"],
            "mkosi-upgrade"  : ["pacman", "--sync", "--sysupgrade", "--needed"],
            "mkosi-remove"   : ["pacman", "--remove", "--recursive", "--nosave"],
            "mkosi-reinstall": ["pacman", "--sync"],
        }

    @classmethod
    def mounts(cls, context: Context) -> list[Mount]:
        mounts = [
            *super().mounts(context),
            # pacman writes downloaded packages to the first writable cache directory. We don't want it to write to our
            # local repository directory so we expose it as a read-only directory to pacman.
            Mount(context.repository, "/var/cache/pacman/mkosi", ro=True),
        ]

        if (context.root / "var/lib/pacman/local").exists():
            # pacman reuses the same directory for the sync databases and the local database containing the list of
            # installed packages. The former should go in the cache directory, the latter should go in the image, so we
            # bind mount the local directory from the image to make sure that happens.
            mounts += [Mount(context.root / "var/lib/pacman/local", "/var/lib/pacman/local")]

        return mounts

    @classmethod
    def setup(cls, context: Context, repositories: Iterable[PacmanRepository]) -> None:
        if context.config.repository_key_check:
            sig_level = "Required DatabaseOptional"
        else:
            # If we are using a single local mirror built on the fly there
            # will be no signatures
            sig_level = "Never"

        with umask(~0o755):
            (context.root / "var/lib/pacman/local").mkdir(parents=True, exist_ok=True)

        (context.pkgmngr / "etc/mkosi-local.conf").touch()

        config = context.pkgmngr / "etc/pacman.conf"
        if config.exists():
            return

        config.parent.mkdir(exist_ok=True, parents=True)

        with config.open("w") as f:
            f.write(
                textwrap.dedent(
                    f"""\
                    [options]
                    SigLevel = {sig_level}
                    LocalFileSigLevel = Optional
                    ParallelDownloads = 5
                    Architecture = {context.config.distribution.architecture(context.config.architecture)}

                    """
                )
            )

            if not context.config.with_docs:
                f.write(
                    textwrap.dedent(
                        """\
                        NoExtract = usr/share/doc/*
                        NoExtract = usr/share/man/*
                        NoExtract = usr/share/groff/*
                        NoExtract = usr/share/gtk-doc/*
                        NoExtract = usr/share/info/*
                        """
                    )
                )

            # This has to go first so that our local repository always takes precedence over any other ones.
            f.write("Include = /etc/mkosi-local.conf\n")

            for repo in repositories:
                f.write(
                    textwrap.dedent(
                        f"""\

                        [{repo.id}]
                        Server = {repo.url}
                        """
                    )
                )

            if any((context.pkgmngr / "etc/pacman.d/").glob("*.conf")):
                f.write(
                    textwrap.dedent(
                        """\

                        Include = /etc/pacman.d/*.conf
                        """
                    )
                )

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        return [
            "pacman",
            "--root=/buildroot",
            "--logfile=/dev/null",
            "--dbpath=/var/lib/pacman",
            # Make sure pacman looks at our local repository first by putting it as the first cache directory. We mount
            # it read-only so the second directory will still be used for writing new cache entries.
            "--cachedir=/var/cache/pacman/mkosi",
            "--cachedir=/var/cache/pacman/pkg",
            "--hookdir=/buildroot/etc/pacman.d/hooks",
            "--arch", context.config.distribution.architecture(context.config.architecture),
            "--color", "auto",
            "--noconfirm",
        ]

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        arguments: Sequence[str] = (),
        *,
        apivfs: bool = False,
        stdout: _FILE = None,
    ) -> CompletedProcess:
        with finalize_source_mounts(
            context.config,
            ephemeral=os.getuid() == 0 and context.config.build_sources_ephemeral,
        ) as sources:
            return run(
                cls.cmd(context) + [operation, *arguments],
                sandbox=(
                    context.sandbox(
                        binary="pacman",
                        network=True,
                        vartmp=True,
                        mounts=[Mount(context.root, "/buildroot"), *cls.mounts(context), *sources],
                        options=["--dir", "/work/src", "--chdir", "/work/src"],
                        extra=apivfs_cmd() if apivfs else [],
                    )
                ),
                env=context.config.environment | cls.finalize_environment(context),
                stdout=stdout,
            )

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        cls.invoke(context, "--sync", ["--refresh", *(["--refresh"] if force else [])])

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(
            [
                "repo-add",
                "--quiet",
                context.repository / "mkosi.db.tar",
                *sorted(context.repository.glob("*.pkg.tar*"), key=lambda p: GenericVersion(Path(p).name))
            ],
            sandbox=context.sandbox(binary="repo-add", mounts=[Mount(context.repository, context.repository)]),
        )

        (context.pkgmngr / "etc/mkosi-local.conf").write_text(
            textwrap.dedent(
                """\
                [mkosi]
                Server = file:///i/dont/exist
                SigLevel = Never
                Usage = Install Search Upgrade
                """
            )
        )

        # pacman can't sync a single repository, so we go behind its back and do it ourselves.
        shutil.move(
            context.repository / "mkosi.db.tar",
            context.package_cache_dir / "lib/pacman/sync/mkosi.db"
        )
