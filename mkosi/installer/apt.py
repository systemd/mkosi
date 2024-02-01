# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NamedTuple, Optional

from mkosi.config import Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import find_binary, run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import PathString
from mkosi.util import sort_packages, umask


class Apt(PackageManager):
    class Repository(NamedTuple):
        types: tuple[str, ...]
        url: str
        suite: str
        components: tuple[str, ...]
        signedby: Optional[str]

        def __str__(self) -> str:
            return textwrap.dedent(
                f"""\
                Types: {" ".join(self.types)}
                URIs: {self.url}
                Suites: {self.suite}
                Components: {" ".join(self.components)}
                {"Signed-By" if self.signedby else "Trusted"}: {self.signedby or "yes"}

                """
            )

    @classmethod
    def executable(cls, config: Config) -> str:
        return "apt"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("apt")

    @classmethod
    def cache_subdirs(cls, cache: Path) -> list[Path]:
        return [cache / "archives"]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            command: apivfs_cmd(context.root) + cls.cmd(context, command) for command in (
                "apt",
                "apt-cache",
                "apt-cdrom",
                "apt-config",
                "apt-extracttemplates",
                "apt-get",
                "apt-key",
                "apt-mark",
                "apt-sortpkgs",
            )
        }

    @classmethod
    def setup(cls, context: Context, repos: Iterable[Repository]) -> None:
        (context.pkgmngr / "etc/apt").mkdir(exist_ok=True, parents=True)
        (context.pkgmngr / "etc/apt/apt.conf.d").mkdir(exist_ok=True, parents=True)
        (context.pkgmngr / "etc/apt/preferences.d").mkdir(exist_ok=True, parents=True)
        (context.pkgmngr / "etc/apt/sources.list.d").mkdir(exist_ok=True, parents=True)

        with umask(~0o755):
            # TODO: Drop once apt 2.5.4 is widely available.
            (context.root / "var/lib/dpkg").mkdir(parents=True, exist_ok=True)
            (context.root / "var/lib/dpkg/status").touch()

        # We have a special apt.conf outside of pkgmngr dir that only configures "Dir::Etc" that we pass to APT_CONFIG
        # to tell apt it should read config files from /etc/apt in case this is overridden by distributions. This is
        # required because apt parses CLI configuration options after parsing its configuration files and as such we
        # can't use CLI options to tell apt where to look for configuration files.
        config = context.pkgmngr / "etc/apt.conf"
        if not config.exists():
            config.write_text(
                textwrap.dedent(
                    """\
                    Dir::Etc "etc/apt";
                    """
                )
            )

        sources = context.pkgmngr / "etc/apt/sources.list.d/mkosi.sources"
        if not sources.exists():
            with sources.open("w") as f:
                for repo in repos:
                    f.write(str(repo))

    @classmethod
    def cmd(cls, context: Context, command: str) -> list[PathString]:
        debarch = context.config.distribution.architecture(context.config.architecture)

        cmdline: list[PathString] = [
            "env",
            "APT_CONFIG=/etc/apt.conf",
            "DEBIAN_FRONTEND=noninteractive",
            "DEBCONF_INTERACTIVE_SEEN=true",
            "INITRD=No",
            command,
            "-o", f"APT::Architecture={debarch}",
            "-o", f"APT::Architectures={debarch}",
            "-o", f"APT::Install-Recommends={str(context.config.with_recommends).lower()}",
            "-o", "APT::Immediate-Configure=off",
            "-o", "APT::Get::Assume-Yes=true",
            "-o", "APT::Get::AutomaticRemove=true",
            "-o", "APT::Get::Allow-Change-Held-Packages=true",
            "-o", "APT::Get::Allow-Remove-Essential=true",
            "-o", "APT::Sandbox::User=root",
            "-o", "Dir::Cache=/var/cache/apt",
            "-o", "Dir::State=/var/lib/apt",
            "-o", f"Dir::State::Status={context.root / 'var/lib/dpkg/status'}",
            "-o", f"Dir::Log={context.workspace}",
            "-o", f"Dir::Bin::DPkg={find_binary('dpkg', root=context.config.tools())}",
            "-o", "Debug::NoLocking=true",
            "-o", f"DPkg::Options::=--root={context.root}",
            "-o", "DPkg::Options::=--force-unsafe-io",
            "-o", "DPkg::Options::=--force-architecture",
            "-o", "DPkg::Options::=--force-depends",
            "-o", "DPkg::Options::=--no-debsig",
            "-o", "DPkg::Use-Pty=false",
            "-o", "DPkg::Install::Recursive::Minimum=1000",
            "-o", "pkgCacheGen::ForceEssential=,",
        ]

        if not context.config.repository_key_check:
            cmdline += [
                "-o", "Acquire::AllowInsecureRepositories=true",
                "-o", "Acquire::AllowDowngradeToInsecureRepositories=true",
                "-o", "APT::Get::AllowUnauthenticated=true",
            ]

        if not context.config.with_docs:
            cmdline += [
                "-o", "DPkg::Options::=--path-exclude=/usr/share/doc/*",
                "-o", "DPkg::Options::=--path-include=/usr/share/doc/*/copyright",
                "-o", "DPkg::Options::=--path-exclude=/usr/share/man/*",
                "-o", "DPkg::Options::=--path-exclude=/usr/share/groff/*",
                "-o", "DPkg::Options::=--path-exclude=/usr/share/info/*",
            ]

        return cmdline

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        packages: Sequence[str] = (),
        *,
        options: Sequence[str] = (),
        apivfs: bool = True,
        mounts: Sequence[PathString] = (),
    ) -> None:
        with finalize_ephemeral_source_mounts(context.config) as sources:
            run(
                cls.cmd(context, "apt-get") + [operation, *options, *sort_packages(packages)],
                sandbox=(
                    context.sandbox(
                        network=True,
                        options=[
                            "--bind", context.root, context.root,
                            *cls.mounts(context),
                            *sources,
                            *mounts,
                            "--chdir", "/work/src",
                        ],
                    ) + (apivfs_cmd(context.root) if apivfs else [])
                ),
                env=context.config.environment,
            )

    @classmethod
    def sync(cls, context: Context) -> None:
        cls.invoke(context, "update")

    @classmethod
    def createrepo(cls, context: Context) -> None:
        with (context.packages / "Packages").open("wb") as f:
            run(
                ["dpkg-scanpackages", "."],
                stdout=f,
                sandbox=context.sandbox(
                    options=[
                        "--ro-bind", context.packages, context.packages,
                        "--chdir", context.packages,
                    ],
                ),
            )

        (context.pkgmngr / "etc/apt/sources.list.d").mkdir(parents=True, exist_ok=True)
        (context.pkgmngr / "etc/apt/sources.list.d/mkosi-local.sources").write_text(
            textwrap.dedent(
                """\
                Enabled: yes
                Types: deb
                URIs: file:///work/packages
                Suites: ./
                Trusted: yes
                """
            )
        )

        cls.invoke(
            context,
            "update",
            options=[
                "-o", "Dir::Etc::sourcelist=sources.list.d/mkosi-local.sources",
                "-o", "Dir::Etc::sourceparts=-",
                "-o", "APT::Get::List-Cleanup=0",
            ],
            apivfs=False,
        )
