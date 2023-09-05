# SPDX-License-Identifier: LGPL-2.1+
import os
import shutil
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import NamedTuple

from mkosi.run import apivfs_cmd, bwrap
from mkosi.state import MkosiState
from mkosi.tree import rmtree
from mkosi.types import PathString
from mkosi.util import sort_packages


class Repo(NamedTuple):
    id: str
    url: str
    gpgurls: tuple[str, ...]
    enabled: bool = True


def dnf_executable(state: MkosiState) -> str:
    # dnf5 does not support building for foreign architectures yet (missing --forcearch)
    dnf = shutil.which("dnf5") if state.config.architecture.is_native() else None
    dnf = dnf or shutil.which("dnf") or "yum"
    return dnf


def setup_dnf(state: MkosiState, repos: Sequence[Repo], filelists: bool = True) -> None:
    (state.pkgmngr / "etc/dnf/vars").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "etc/yum.repos.d").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "var/lib/dnf").mkdir(exist_ok=True, parents=True)

    config = state.pkgmngr / "etc/dnf/dnf.conf"

    if not config.exists():
        config.parent.mkdir(exist_ok=True, parents=True)
        with config.open("w") as f:
            f.write(
                textwrap.dedent(
                    """\
                    [main]
                    install_weak_deps=0
                    """
                )
            )

            # Make sure we download filelists so all dependencies can be resolved.
            # See https://bugzilla.redhat.com/show_bug.cgi?id=2180842
            if dnf_executable(state).endswith("dnf5") and filelists:
                f.write("optional_metadata_types=filelists\n")

    repofile = state.pkgmngr / "etc/yum.repos.d/mkosi.repo"
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
                        """
                    )
                )

                for i, url in enumerate(repo.gpgurls):
                    f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                    f.write(f"{url}\n")


def dnf_cmd(state: MkosiState) -> list[PathString]:
    dnf = dnf_executable(state)

    cmdline: list[PathString] = [
        dnf,
        "--assumeyes",
        f"--config={state.pkgmngr / 'etc/dnf/dnf.conf'}",
        "--best",
        f"--releasever={state.config.release}",
        f"--installroot={state.root}",
        "--setopt=keepcache=1",
        f"--setopt=cachedir={state.cache_dir}",
        f"--setopt=reposdir={state.pkgmngr / 'etc/yum.repos.d'}",
        f"--setopt=varsdir={state.pkgmngr / 'etc/dnf/vars'}",
        f"--setopt=persistdir={state.pkgmngr / 'var/lib/dnf'}",
        "--setopt=check_config_file_age=0",
        "--disableplugin=*",
        "--enableplugin=builddep",
    ]

    if not state.config.repository_key_check:
        cmdline += ["--nogpgcheck"]

    if state.config.repositories:
        opt = "--enable-repo" if dnf.endswith("dnf5") else "--enablerepo"
        cmdline += [f"{opt}={repo}" for repo in state.config.repositories]

    # TODO: this breaks with a local, offline repository created with 'createrepo'
    if state.config.cache_only and not state.config.local_mirror:
        cmdline += ["--cacheonly"]

    if not state.config.architecture.is_native():
        cmdline += [f"--forcearch={state.config.distribution.architecture(state.config.architecture)}"]

    if not state.config.with_docs:
        cmdline += ["--no-docs" if dnf.endswith("dnf5") else "--nodocs"]

    return cmdline


def invoke_dnf(state: MkosiState, commands: Sequence[str], packages: Iterable[str], apivfs: bool = True) -> None:
    cmd = apivfs_cmd(state.root) if apivfs else []
    bwrap(cmd + dnf_cmd(state) + [*commands, *sort_packages(packages)],
          network=True, env=state.config.environment)

    fixup_rpmdb_location(state.root)

    # The log directory is always interpreted relative to the install root so there's nothing we can do but
    # to remove the log files from the install root afterwards.
    for p in (state.root / "var/log").iterdir():
        if any(p.name.startswith(prefix) for prefix in ("dnf", "hawkey", "yum")):
            p.unlink()


def fixup_rpmdb_location(root: Path) -> None:
    # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/ so it needs to be copied back in the
    # right location, otherwise the rpmdb will be broken. See: https://bugs.debian.org/1004863. We also
    # replace it with a symlink so that any further rpm operations immediately use the correct location.
    rpmdb_home = root / "root/.rpmdb"
    if not rpmdb_home.exists() or rpmdb_home.is_symlink():
        return

    # Take into account the new location in F36
    rpmdb = root / "usr/lib/sysimage/rpm"
    if not rpmdb.exists():
        rpmdb = root / "var/lib/rpm"
    rmtree(rpmdb)
    shutil.move(rpmdb_home, rpmdb)
    rpmdb_home.symlink_to(os.path.relpath(rpmdb, start=rpmdb_home.parent))
