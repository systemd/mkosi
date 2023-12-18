# SPDX-License-Identifier: LGPL-2.1+
import shutil
import textwrap
from collections.abc import Iterable

from mkosi.installer.rpm import RpmRepository, fixup_rpmdb_location, setup_rpm
from mkosi.run import apivfs_cmd, bwrap
from mkosi.state import MkosiState
from mkosi.types import PathString
from mkosi.util import sort_packages


def dnf_executable(state: MkosiState) -> str:
    # Allow the user to override autodetection with an environment variable
    dnf = state.config.environment.get("MKOSI_DNF")

    return dnf or shutil.which("dnf5") or shutil.which("dnf") or "yum"


def setup_dnf(state: MkosiState, repositories: Iterable[RpmRepository], filelists: bool = True) -> None:
    (state.pkgmngr / "etc/dnf/vars").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "etc/yum.repos.d").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "var/lib/dnf").mkdir(exist_ok=True, parents=True)

    config = state.pkgmngr / "etc/dnf/dnf.conf"

    if not config.exists():
        config.parent.mkdir(exist_ok=True, parents=True)
        with config.open("w") as f:
            # Make sure we download filelists so all dependencies can be resolved.
            # See https://bugzilla.redhat.com/show_bug.cgi?id=2180842
            if dnf_executable(state).endswith("dnf5") and filelists:
                f.write("[main]\noptional_metadata_types=filelists\n")

    repofile = state.pkgmngr / "etc/yum.repos.d/mkosi.repo"
    if not repofile.exists():
        repofile.parent.mkdir(exist_ok=True, parents=True)
        with repofile.open("w") as f:
            for repo in repositories:
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

                if repo.sslcacert:
                    f.write(f"sslcacert={repo.sslcacert}\n")
                if repo.sslclientcert:
                    f.write(f"sslclientcert={repo.sslclientcert}\n")
                if repo.sslclientkey:
                    f.write(f"sslclientkey={repo.sslclientkey}\n")

                for i, url in enumerate(repo.gpgurls):
                    f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                    f.write(f"{url}\n")

                f.write("\n")

    setup_rpm(state)


def dnf_cmd(state: MkosiState) -> list[PathString]:
    dnf = dnf_executable(state)

    cmdline: list[PathString] = [
        "env",
        "HOME=/", # Make sure rpm doesn't pick up ~/.rpmmacros and ~/.rpmrc.
        f"RPM_CONFIGDIR={state.pkgmngr / 'usr/lib/rpm'}",
        dnf,
        "--assumeyes",
        f"--config={state.pkgmngr / 'etc/dnf/dnf.conf'}",
        "--best",
        f"--releasever={state.config.release}",
        f"--installroot={state.root}",
        "--setopt=keepcache=1",
        f"--setopt=cachedir={state.cache_dir / ('libdnf5' if dnf.endswith('dnf5') else 'dnf')}",
        f"--setopt=reposdir={state.pkgmngr / 'etc/yum.repos.d'}",
        f"--setopt=varsdir={state.pkgmngr / 'etc/dnf/vars'}",
        f"--setopt=persistdir={state.pkgmngr / 'var/lib/dnf'}",
        f"--setopt=install_weak_deps={int(state.config.with_recommends)}",
        "--setopt=check_config_file_age=0",
        "--disable-plugin=*" if dnf.endswith("dnf5") else "--disableplugin=*",
        "--enable-plugin=builddep" if dnf.endswith("dnf5") else "--enableplugin=builddep",
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


def invoke_dnf(state: MkosiState, command: str, packages: Iterable[str], apivfs: bool = True) -> None:
    cmd = apivfs_cmd(state.root) if apivfs else []
    bwrap(cmd + dnf_cmd(state) + [command, *sort_packages(packages)],
          network=True, env=state.config.environment)

    fixup_rpmdb_location(state.root)

    # The log directory is always interpreted relative to the install root so there's nothing we can do but
    # to remove the log files from the install root afterwards.
    for p in (state.root / "var/log").iterdir():
        if any(p.name.startswith(prefix) for prefix in ("dnf", "hawkey", "yum")):
            p.unlink()
