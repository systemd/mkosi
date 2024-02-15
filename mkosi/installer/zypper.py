# SPDX-License-Identifier: LGPL-2.1+
import hashlib
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Config, yes_no
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.installer.rpm import RpmRepository, fixup_rpmdb_location, rpm_cmd, setup_rpm
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import PathString
from mkosi.util import sort_packages


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
            "install",
            "--download", "in-advance",
            "--recommends" if context.config.with_recommends else "--no-recommends",
        ]

        return {
            "zypper": apivfs_cmd(context.root) + cls.cmd(context),
            "rpm"   : apivfs_cmd(context.root) + rpm_cmd(context),
            "mkosi-install"  : apivfs_cmd(context.root) + cls.cmd(context) + install,
            "mkosi-upgrade"  : apivfs_cmd(context.root) + cls.cmd(context) + ["update"],
            "mkosi-remove"   : apivfs_cmd(context.root) + cls.cmd(context) + ["remove", "--clean-deps"],
            "mkosi-reinstall": apivfs_cmd(context.root) + cls.cmd(context) + install + ["--force"],
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

                    for i, url in enumerate(repo.gpgurls):
                        f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                        f.write(f"{url}\n")

                    f.write("\n")

        setup_rpm(context)

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        return [
            "env",
            "ZYPP_CONF=/etc/zypp/zypp.conf",
            "HOME=/",
            "zypper",
            f"--installroot={context.root}",
            "--cache-dir=/var/cache/zypp",
            "--gpg-auto-import-keys" if context.config.repository_key_check else "--no-gpg-checks",
            "--non-interactive",
            "--no-refresh",
        ]

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        packages: Sequence[str] = (),
        *,
        options: Sequence[str] = (),
        apivfs: bool = True,
    ) -> None:
        with finalize_ephemeral_source_mounts(context.config) as sources:
            run(
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

        fixup_rpmdb_location(context)

    @classmethod
    def sync(cls, context: Context) -> None:
        cls.invoke(context, "refresh", apivfs=False)

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(["createrepo_c", context.packages],
            sandbox=context.sandbox(options=["--bind", context.packages, context.packages]))

        (context.pkgmngr / "etc/zypp/repos.d/mkosi-local.repo").write_text(
            textwrap.dedent(
                """\
                [mkosi]
                name=mkosi
                baseurl=file:///work/packages
                gpgcheck=0
                autorefresh=0
                keeppackages=0
                priority=50
                """
            )
        )

        cls.invoke(context, "refresh", ["mkosi"], apivfs=False)
