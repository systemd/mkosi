# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Sequence

from mkosi.bubblewrap import apivfs_cmd, bwrap
from mkosi.config import yes_no
from mkosi.installer.rpm import RpmRepository, fixup_rpmdb_location, setup_rpm
from mkosi.state import MkosiState
from mkosi.types import PathString
from mkosi.util import sort_packages


def setup_zypper(state: MkosiState, repos: Sequence[RpmRepository]) -> None:
    config = state.pkgmngr / "etc/zypp/zypp.conf"
    config.parent.mkdir(exist_ok=True, parents=True)

    # rpm.install.excludedocs can only be configured in zypp.conf so we append
    # to any user provided config file. Let's also bump the refresh delay to
    # the same default as dnf which is 48 hours.
    with config.open("a") as f:
        f.write(
            textwrap.dedent(
                f"""
                [main]
                rpm.install.excludedocs = {yes_no(not state.config.with_docs)}
                repo.refresh.delay = {48 * 60}
                """
            )
        )

    repofile = state.pkgmngr / "etc/zypp/repos.d/mkosi.repo"
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

    setup_rpm(state)


def zypper_cmd(state: MkosiState) -> list[PathString]:
    return [
        "env",
        "ZYPP_CONF=/etc/zypp/zypp.conf",
        "HOME=/",
        "zypper",
        f"--installroot={state.root}",
        f"--cache-dir={state.cache_dir / 'cache/zypp'}",
        "--gpg-auto-import-keys" if state.config.repository_key_check else "--no-gpg-checks",
        "--non-interactive",
    ]


def invoke_zypper(
    state: MkosiState,
    verb: str,
    packages: Sequence[str],
    options: Sequence[str] = (),
    apivfs: bool = True,
) -> None:
    cmd = apivfs_cmd(state.root) if apivfs else []
    bwrap(state, cmd + zypper_cmd(state) + [verb, *options, *sort_packages(packages)],
          network=True, env=state.config.environment)

    fixup_rpmdb_location(state.root)
