# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Sequence

from mkosi.config import yes_no
from mkosi.context import Context
from mkosi.installer.rpm import RpmRepository, fixup_rpmdb_location, setup_rpm
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd, finalize_crypto_mounts
from mkosi.types import PathString
from mkosi.util import sort_packages


def setup_zypper(context: Context, repos: Sequence[RpmRepository]) -> None:
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
                f.write(
                    textwrap.dedent(
                        f"""\
                        [{repo.id}]
                        name={repo.id}
                        {repo.url}
                        gpgcheck=1
                        enabled={int(repo.enabled)}
                        autorefresh=1
                        keeppackages=1
                        """
                    )
                )

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
        f"--cache-dir={context.cache_dir / 'cache/zypp'}",
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
    run(
        zypper_cmd(context) + [verb, *options, *sort_packages(packages)],
        sandbox=(
            context.sandbox(
                network=True,
                options=[
                    "--bind", context.root, context.root,
                    "--bind", context.cache_dir, context.cache_dir,
                    *finalize_crypto_mounts(tools=context.config.tools()),
                ],
            ) + (apivfs_cmd(context.root, tools=context.config.tools()) if apivfs else [])
        ),
        env=context.config.environment,
    )

    fixup_rpmdb_location(context)
