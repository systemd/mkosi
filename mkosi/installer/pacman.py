# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import shutil
import textwrap
from collections.abc import Sequence
from contextlib import AbstractContextManager
from pathlib import Path

from mkosi.config import Config
from mkosi.context import Context
from mkosi.distribution import detect_distribution
from mkosi.installer import PackageManager
from mkosi.log import complete_step
from mkosi.run import CompletedProcess, run, workdir
from mkosi.sandbox import umask
from mkosi.tree import copy_tree
from mkosi.util import _FILE, PathString
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
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        return [(Path("pkg"), Path("pkg"))]

    @classmethod
    def package_globs(cls) -> list[str]:
        return ["*.pkg.tar*"]

    @classmethod
    def state_subdirs(cls) -> list[Path]:
        return [Path("sync")]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "pacman": cls.apivfs_script_cmd(context) + cls.env_cmd(context) + cls.cmd(context),
            "mkosi-install":   ["pacman", "--sync", "--needed"],
            "mkosi-upgrade":   ["pacman", "--sync", "--sysupgrade", "--needed"],
            "mkosi-remove":    ["pacman", "--remove", "--recursive", "--nosave"],
            "mkosi-reinstall": ["pacman", "--sync"],
        }  # fmt: skip

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        mounts = [
            *super().mounts(context),
            # pacman writes downloaded packages to the first writable cache directory. We don't want it to
            # write to our local repository directory so we expose it as a read-only directory to pacman.
            "--ro-bind", context.repository, "/var/cache/pacman/mkosi",
        ]  # fmt: skip

        if context.keyring_dir.exists() and any(context.keyring_dir.iterdir()):
            mounts += ["--ro-bind", context.keyring_dir, "/etc/pacman.d/gnupg"]

        if (context.root / "var/lib/pacman/local").exists():
            # pacman reuses the same directory for the sync databases and the local database containing the
            # list of installed packages. The former should go in the cache directory, the latter should go
            # in the image, so we bind mount the local directory from the image to make sure that happens. We
            # make sure to bind mount directly from the mounted /buildroot directly instead of from the host
            # root directory since /buildroot might be an overlay mount and we want to make sure any writes
            # are done to the upperdir of the overlay mount.
            mounts += ["--bind", "+/buildroot/var/lib/pacman/local", "/var/lib/pacman/local"]

        return mounts

    @classmethod
    def setup(cls, context: Context, repositories: Sequence[PacmanRepository]) -> None:
        if context.config.repository_key_check:
            sig_level = "Required DatabaseOptional"
        else:
            # If we are using a single local mirror built on the fly there
            # will be no signatures
            sig_level = "Never"

        (context.sandbox_tree / "etc/mkosi-local.conf").touch()

        config = context.sandbox_tree / "etc/pacman.conf"
        if config.exists():
            # If DownloadUser is specified, remove it as the user won't be available in the sandbox.
            lines = config.read_text().splitlines()
            lines = [line for line in lines if not line.strip().startswith("DownloadUser")]
            config.write_text("\n".join(lines))
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
                    Architecture = {cls.architecture(context)}

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

            if any((context.sandbox_tree / "etc/pacman.d/").glob("*.conf")):
                f.write(
                    textwrap.dedent(
                        """\

                        Include = /etc/pacman.d/*.conf
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

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        return [
            "pacman",
            "--root=/buildroot",
            "--logfile=/dev/null",
            "--dbpath=/var/lib/pacman",
            # Make sure pacman looks at our local repository first by putting it as the first cache
            # directory. We mount it read-only so the second directory will still be used for writing new
            # cache entries.
            "--cachedir=/var/cache/pacman/mkosi",
            "--cachedir=/var/cache/pacman/pkg",
            "--hookdir=/buildroot/etc/pacman.d/hooks",
            "--arch", cls.architecture(context),
            "--color", "auto",
            "--noconfirm",
        ]  # fmt: skip

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
        with umask(~0o755):
            (context.root / "var/lib/pacman/local").mkdir(parents=True, exist_ok=True)
            (context.root / "etc/pacman.d/hooks").mkdir(parents=True, exist_ok=True)
            (
                context.config.package_cache_dir_or_default() / "cache" / cls.subdir(context.config) / "pkg"
            ).mkdir(parents=True, exist_ok=True)

        return run(
            cls.cmd(context) + [operation, *arguments],
            sandbox=cls.sandbox(context, apivfs=apivfs),
            env=cls.finalize_environment(context),
            stdout=stdout,
        )

    @classmethod
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
        options: Sequence[str] = (),
    ) -> None:
        arguments = ["--needed", "--assume-installed", "initramfs"]

        if allow_downgrade:
            arguments += ["--sysupgrade", "--sysupgrade"]

        arguments += [*options, *packages]

        cls.invoke(context, "--sync", arguments, apivfs=apivfs)

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        installed = {
            cls.parse_pkg_desc(i)[0] for i in (context.root / "var/lib/pacman/local").glob("*/desc")
        }
        remove = [p for p in packages if p in installed]
        if remove:
            cls.invoke(context, "--remove", ["--nosave", "--recursive", *remove], apivfs=True)

    @classmethod
    def keyring(cls, context: Context) -> None:
        def sandbox() -> AbstractContextManager[list[PathString]]:
            return cls.sandbox(
                context,
                apivfs=False,
                # By default the keyring is mounted read-only so we override the read-only mount with a
                # writable mount to make it writable for the following pacman-key commands.
                options=["--bind", context.keyring_dir, "/etc/pacman.d/gnupg"],
            )

        if (
            (d := detect_distribution(context.config.tools())[0])
            and d.is_apt_distribution()
            and (context.sandbox_tree / "usr/share/pacman/keyrings").exists()
        ):
            # pacman on Debian/Ubuntu looks for keyrings in /usr/share/keyrings so make sure all sandbox
            # trees keyrings are available in that location as well.
            (context.sandbox_tree / "usr/share").mkdir(parents=True, exist_ok=True)
            copy_tree(
                context.sandbox_tree / "usr/share/pacman/keyrings",
                context.sandbox_tree / "usr/share/keyrings",
                dereference=True,
                sandbox=context.sandbox,
            )

        context.keyring_dir.mkdir(parents=True, exist_ok=True)

        with complete_step("Populating pacman keyring"):
            run(["pacman-key", "--init"], sandbox=sandbox())
            run(["pacman-key", "--populate"], sandbox=sandbox())

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        cls.invoke(context, "--sync", ["--refresh", *(["--refresh"] if force else [])])

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(
            [
                "repo-add",
                "--quiet",
                workdir(context.repository / "mkosi.db.tar"),
                *sorted(
                    (workdir(p) for p in context.repository.glob("*.pkg.tar*")),
                    key=lambda p: GenericVersion(Path(p).name),
                ),
            ],
            sandbox=context.sandbox(options=["--bind", context.repository, workdir(context.repository)]),
        )

        (context.sandbox_tree / "etc/mkosi-local.conf").write_text(
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
        shutil.move(context.repository / "mkosi.db.tar", context.metadata_dir / "lib/pacman/sync/mkosi.db")

    @classmethod
    def parse_pkg_desc(cls, path: Path) -> tuple[str, str, str, str]:
        name = version = base = arch = ""

        with path.open() as desc:
            for line in desc:
                line = line.strip()
                if line == "%NAME%":
                    name = next(desc).strip()
                elif line == "%VERSION%":
                    version = next(desc).strip()
                elif line == "%BASE%":
                    base = next(desc).strip()
                elif line == "%ARCH%":
                    arch = next(desc).strip()
                    break

        return name, version, base, arch
