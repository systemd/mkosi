# SPDX-License-Identifier: LGPL-2.1+
import shutil
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NamedTuple

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import CompletedProcess, PathString
from mkosi.util import sort_packages, umask
from mkosi.versioncomp import GenericVersion


class Pacman(PackageManager):
    class Repository(NamedTuple):
        id: str
        url: str

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
            "pacman": apivfs_cmd(context.root) + cls.cmd(context),
            "mkosi-install"  : apivfs_cmd(context.root) + cls.cmd(context) + ["--sync", "--needed"],
            "mkosi-upgrade"  : apivfs_cmd(context.root) + cls.cmd(context) + ["--sync", "--sysupgrade", "--needed"],
            "mkosi-remove"   : apivfs_cmd(context.root) + cls.cmd(context) + ["--remove", "--recursive", "--nosave"],
            "mkosi-reinstall": apivfs_cmd(context.root) + cls.cmd(context) + ["--sync"],
        }

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        mounts: list[PathString] = [
            *super().mounts(context),
            # pacman writes downloaded packages to the first writable cache directory. We don't want it to write to our
            # local repository directory so we expose it as a read-only directory to pacman.
            "--ro-bind", context.packages, "/var/cache/pacman/mkosi",
        ]

        if (context.root / "var/lib/pacman/local").exists():
            # pacman reuses the same directory for the sync databases and the local database containing the list of
            # installed packages. The former should go in the cache directory, the latter should go in the image, so we
            # bind mount the local directory from the image to make sure that happens.
            mounts += ["--bind", context.root / "var/lib/pacman/local", "/var/lib/pacman/local"]

        if (
            (context.config.tools() / "etc/makepkg.conf").exists() and
            not (context.pkgmngr / "etc/makepkg.conf").exists()
        ):
            mounts += ["--ro-bind", context.config.tools() / "etc/makepkg.conf", "/etc/makepkg.conf"]

        return mounts

    @classmethod
    def setup(cls, context: Context, repositories: Iterable[Repository]) -> None:
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

                    # This has to go first so that our local repository always takes precedence over any other ones.
                    Include = /etc/mkosi-local.conf
                    """
                )
            )

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
            "--root", context.root,
            "--logfile=/dev/null",
            "--dbpath=/var/lib/pacman",
            # Make sure pacman looks at our local repository first by putting it as the first cache directory. We mount
            # it read-only so the second directory will still be used for writing new cache entries.
            "--cachedir=/var/cache/pacman/mkosi",
            "--cachedir=/var/cache/pacman/pkg",
            "--hookdir", context.root / "etc/pacman.d/hooks",
            "--arch", context.config.distribution.architecture(context.config.architecture),
            "--color", "auto",
            "--noconfirm",
        ]

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        options: Sequence[str] = (),
        packages: Sequence[str] = (),
        apivfs: bool = False,
    ) -> CompletedProcess:
        with finalize_ephemeral_source_mounts(context.config) as sources:
            return run(
                cls.cmd(context) + [operation, *options, *sort_packages(packages)],
                sandbox=(
                    context.sandbox(
                        network=True,
                        options=[
                            "--bind", context.root, context.root,
                            *cls.mounts(context),
                            *sources,
                            "--chdir", "/work/src",
                        ],
                    ) + (apivfs_cmd(context.root) if apivfs else [])
                ),
                env=context.config.environment,
            )

    @classmethod
    def sync(cls, context: Context) -> None:
        cls.invoke(context, "--sync", ["--refresh"])

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(["repo-add", "--quiet", context.packages / "mkosi.db.tar",
            *sorted(context.packages.glob("*.pkg.tar*"), key=lambda p: GenericVersion(Path(p).name))])

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
            context.packages / "mkosi.db.tar",
            context.package_cache_dir / "lib/pacman/sync/mkosi.db"
        )
