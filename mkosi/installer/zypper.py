# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Sequence

from mkosi.installer.dnf import Repo, fixup_rpmdb_location
from mkosi.run import bwrap
from mkosi.state import MkosiState


def setup_zypper(state: MkosiState, repos: Sequence[Repo]) -> None:
    config = state.pkgmngr / "etc/zypp/zypp.conf"
    if not config.exists():
        config.parent.mkdir(exist_ok=True, parents=True)
        with config.open("w") as f:
            f.write(
                textwrap.dedent(
                    f"""\
                    [main]
                    rpm.install.excludedocs = {"no" if state.config.with_docs else "yes"}
                    solver.onlyRequires = yes
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
                        autorefresh=0
                        keeppackages=1
                        """
                    )
                )

                for i, url in enumerate(repo.gpgurls):
                    f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                    f.write(f"{url}\n")


def zypper_cmd(state: MkosiState) -> list[str]:
    return [
        "env",
        f"ZYPP_CONF={state.pkgmngr / 'etc/zypp/zypp.conf'}",
        "zypper",
        f"--root={state.root}",
        f"--cache-dir={state.cache_dir}",
        f"--reposd-dir={state.pkgmngr / 'etc/zypp/repos.d'}",
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
    bwrap(zypper_cmd(state) + [verb, *packages, *options],
          apivfs=state.root if apivfs else None,
          env=dict(KERNEL_INSTALL_BYPASS="1") | state.config.environment)

    fixup_rpmdb_location(state.root)
