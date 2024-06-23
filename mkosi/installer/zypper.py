# SPDX-License-Identifier: LGPL-2.1+
import hashlib
import os
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Cacheonly, Config, yes_no
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.installer.rpm import RpmRepository, rpm_cmd
from mkosi.mounts import finalize_source_mounts
from mkosi.run import run
from mkosi.sandbox import Mount, apivfs_cmd
from mkosi.types import _FILE, CompletedProcess, PathString


class Zypper(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "zypper"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("zypp")

    @classmethod
    def cache_subdirs(cls, cache: Path) -> list[Path]:
        return [cache / "packages"]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        install: list[PathString] = [
            "zypper",
            "install",
            "--download", "in-advance",
            "--recommends" if context.config.with_recommends else "--no-recommends",
        ]

        return {
            "zypper": apivfs_cmd() + cls.env_cmd(context) + cls.cmd(context),
            "rpm"   : apivfs_cmd() + rpm_cmd(),
            "mkosi-install"  : install,
            "mkosi-upgrade"  : ["zypper", "update"],
            "mkosi-remove"   : ["zypper", "remove", "--clean-deps"],
            "mkosi-reinstall": install + ["--force"],
        }

    @classmethod
    def setup(cls, context: Context, repos: Iterable[RpmRepository]) -> None:
        config = context.pkgmngr / "etc/zypp/zypp.conf"
        config.parent.mkdir(exist_ok=True, parents=True)

        # rpm.install.excludedocs can only be configured in zypp.conf so we append
        # to any user provided config file. Let's also bump the refresh delay to
        # the same default as dnf which is 48 hours.
        with config.open("a") as f:
            f.write(
                textwrap.dedent(
                    f"""
                    [main]
                    rpm.install.excludedocs = {yes_no(not context.config.with_docs)}
                    repo.refresh.delay = {48 * 60}
                    """
                )
            )

        repofile = context.pkgmngr / "etc/zypp/repos.d/mkosi.repo"
        if not repofile.exists():
            repofile.parent.mkdir(exist_ok=True, parents=True)
            with repofile.open("w") as f:
                for repo in repos:
                    # zypper uses the repo ID as its cache key which is unsafe so add a hash of the url used to it to
                    # make sure a unique cache is used for each repository. We use roughly the same algorithm here that
                    # dnf uses as well.
                    key = hashlib.sha256(repo.url.encode()).hexdigest()[:16]

                    f.write(
                        textwrap.dedent(
                            f"""\
                            [{repo.id}-{key}]
                            name={repo.id}
                            {repo.url}
                            gpgcheck=1
                            enabled={int(repo.enabled)}
                            autorefresh=0
                            keeppackages=1
                            """
                        )
                    )

                    if repo.priority:
                        f.write(f"priority={repo.priority}\n")

                    for i, url in enumerate(repo.gpgurls):
                        f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                        f.write(f"{url}\n")

                    f.write("\n")

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        return super().finalize_environment(context) | {"ZYPP_CONF": "/etc/zypp/zypp.conf"}

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        return [
            "zypper",
            "--installroot=/buildroot",
            "--cache-dir=/var/cache/zypp",
            "--gpg-auto-import-keys" if context.config.repository_key_check else "--no-gpg-checks",
            "--non-interactive",
            "--no-refresh",
            *([f"--plus-content={repo}" for repo in context.config.repositories]),
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
                        binary="zypper",
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
    def sync(cls, context: Context) -> None:
        cls.invoke(
            context,
            "refresh",
            ["--force"] if context.args.force > 1 or context.config.cacheonly == Cacheonly.never else []
        )

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(["createrepo_c", context.packages],
            sandbox=context.sandbox(binary="createrepo_c", mounts=[Mount(context.packages, context.packages)]))

        (context.pkgmngr / "etc/zypp/repos.d/mkosi-local.repo").write_text(
            textwrap.dedent(
                """\
                [mkosi]
                name=mkosi
                baseurl=file:///work/packages
                gpgcheck=0
                autorefresh=0
                keeppackages=0
                priority=10
                """
            )
        )

        cls.invoke(context, "refresh", ["mkosi"])
