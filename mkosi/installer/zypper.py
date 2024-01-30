# SPDX-License-Identifier: LGPL-2.1+
import hashlib
import textwrap
from collections.abc import Iterable, Sequence

from mkosi.config import yes_no
from mkosi.context import Context
from mkosi.installer import PackageManager, finalize_package_manager_mounts
from mkosi.installer.rpm import RpmRepository, fixup_rpmdb_location, rpm_cmd, setup_rpm
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import PathString
from mkosi.util import sort_packages


class Zypper(PackageManager):
    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "zypper": apivfs_cmd(context.root) + cls.cmd(context),
            "rpm"   : apivfs_cmd(context.root) + rpm_cmd(context),
        }

    @classmethod
    def setup(cls, context: Context, repos: Iterable[RpmRepository]) -> None:
        config = context.pkgmngr / "etc/zypp/zypp.conf"
        config.parent.mkdir(exist_ok=True, parents=True)

        (context.cache_dir / "cache/zypp").mkdir(exist_ok=True, parents=True)

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
                            gpgcheck={int(repo.gpgcheck)}
                            enabled={int(repo.enabled)}
                            autorefresh=1
                            keeppackages=1
                            """
                        )
                    )

                    if repo.priority is not None:
                        f.write(f"priority={repo.priority}\n")

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
                            *finalize_package_manager_mounts(context),
                            *sources,
                            "--chdir", "/work/src",
                        ],
                    ) + (apivfs_cmd(context.root) if apivfs else [])
                ),
                env=context.config.environment,
            )

        fixup_rpmdb_location(context)

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(["createrepo_c", context.packages],
            sandbox=context.sandbox(options=["--bind", context.packages, context.packages]))

    @classmethod
    def localrepo(cls) -> RpmRepository:
        return RpmRepository(
            id="mkosi-packages",
            url="baseurl=file:///work/packages",
            gpgcheck=False,
            gpgurls=(),
            priority=50,
        )
