# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Iterable, Sequence

from mkosi.config import yes_no
from mkosi.context import Context
from mkosi.installer import finalize_package_manager_mounts
from mkosi.installer.rpm import RpmRepository, fixup_rpmdb_location, setup_rpm
from mkosi.mounts import finalize_ephemeral_source_mounts
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd
from mkosi.types import PathString
from mkosi.user import INVOKING_USER
from mkosi.util import sort_packages


def setup_zypper(context: Context, repos: Iterable[RpmRepository]) -> None:
    config = context.pkgmngr / "etc/zypp/zypp.conf"
    config.parent.mkdir(exist_ok=True, parents=True)

    INVOKING_USER.mkdir(context.config.package_cache_dir_or_default() / "zypp")

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
                f.write(
                    textwrap.dedent(
                        f"""\
                        [{repo.id}]
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

    setup_rpm(context)


def zypper_cmd(context: Context) -> list[PathString]:
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


def invoke_zypper(
    context: Context,
    verb: str,
    packages: Sequence[str],
    options: Sequence[str] = (),
    apivfs: bool = True,
) -> None:
    with finalize_ephemeral_source_mounts(context.config) as sources:
        run(
            zypper_cmd(context) + [verb, *options, *sort_packages(packages)],
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


def createrepo_zypper(context: Context) -> None:
    run(["createrepo_c", context.packages],
        sandbox=context.sandbox(options=["--bind", context.packages, context.packages]))


def localrepo_zypper() -> RpmRepository:
    return RpmRepository(
        id="mkosi-packages",
        url="baseurl=file:///work/packages",
        gpgcheck=False,
        gpgurls=(),
        priority=50,
    )
