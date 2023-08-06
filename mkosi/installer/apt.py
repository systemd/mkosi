# SPDX-License-Identifier: LGPL-2.1+
import shutil
import textwrap
from collections.abc import Sequence

from mkosi.run import apivfs_cmd, bwrap
from mkosi.state import MkosiState
from mkosi.types import PathString
from mkosi.util import flatten, sort_packages, umask


def setup_apt(state: MkosiState, repos: Sequence[str]) -> None:
    (state.pkgmngr / "etc/apt").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "etc/apt/apt.conf.d").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "etc/apt/preferences.d").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "etc/apt/sources.list.d").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "var/log/apt").mkdir(exist_ok=True, parents=True)
    (state.pkgmngr / "var/lib/apt").mkdir(exist_ok=True, parents=True)

    # TODO: Drop once apt 2.5.4 is widely available.
    with umask(~0o755):
        (state.root / "var/lib/dpkg").mkdir(parents=True, exist_ok=True)
        (state.root / "var/lib/dpkg/status").touch()

    # We have a special apt.conf outside of pkgmngr dir that only configures "Dir" that we pass to
    # APT_CONFIG to tell apt it should read config files in pkgmngr instead of in its usual locations. This
    # is required because apt parses CLI configuration options after parsing its configuration files and as
    # such we can't use CLI options to tell apt where to look for configuration files.
    config = state.workspace / "apt.conf"
    if not config.exists():
        config.write_text(
            textwrap.dedent(
                f"""\
                Dir "{state.pkgmngr}";
                """
            )
        )

    config = state.pkgmngr / "etc/apt/apt.conf"
    if not config.exists():
        # Anything that users can override with dropins is written into the config file.
        config.write_text(
            textwrap.dedent(
                """\
                APT::Install-Recommends "false";
                """
            )
        )

    sources = state.pkgmngr / "etc/apt/sources.list"
    if not sources.exists():
        with sources.open("w") as f:
            for repo in repos:
                f.write(f"{repo}\n")


def apt_cmd(state: MkosiState, command: str) -> list[PathString]:
    debarch = state.config.distribution.architecture(state.config.architecture)

    trustedkeys = state.pkgmngr / "etc/apt/trusted.gpg"
    trustedkeys = trustedkeys if trustedkeys.exists() else f"/usr/share/keyrings/{state.config.distribution}-archive-keyring.gpg"
    trustedkeys_dir = state.pkgmngr / "etc/apt/trusted.gpg.d"
    trustedkeys_dir = trustedkeys_dir if trustedkeys_dir.exists() else "/usr/share/keyrings"

    return [
        "env",
        f"APT_CONFIG={state.workspace / 'apt.conf'}",
        "DEBIAN_FRONTEND=noninteractive",
        "DEBCONF_INTERACTIVE_SEEN=true",
        "INITRD=No",
        command,
        "-o", f"APT::Architecture={debarch}",
        "-o", f"APT::Architectures={debarch}",
        "-o", "APT::Immediate-Configure=off",
        "-o", "APT::Get::Assume-Yes=true",
        "-o", "APT::Get::AutomaticRemove=true",
        "-o", "APT::Get::Allow-Change-Held-Packages=true",
        "-o", "APT::Get::Allow-Remove-Essential=true",
        "-o", "APT::Sandbox::User=root",
        "-o", f"Dir::Cache={state.cache_dir}",
        "-o", f"Dir::State={state.pkgmngr / 'var/lib/apt'}",
        "-o", f"Dir::State::status={state.root / 'var/lib/dpkg/status'}",
        "-o", f"Dir::Etc::trusted={trustedkeys}",
        "-o", f"Dir::Etc::trustedparts={trustedkeys_dir}",
        "-o", f"Dir::Log={state.pkgmngr / 'var/log/apt'}",
        "-o", f"Dir::Bin::dpkg={shutil.which('dpkg')}",
        "-o", "Debug::NoLocking=true",
        "-o", f"DPkg::Options::=--root={state.root}",
        "-o", f"DPkg::Options::=--log={state.pkgmngr / 'var/log/apt/dpkg.log'}",
        "-o", "DPkg::Options::=--force-unsafe-io",
        "-o", "DPkg::Options::=--force-architecture",
        "-o", "DPkg::Options::=--force-depends",
        "-o", "Dpkg::Use-Pty=false",
        "-o", "DPkg::Install::Recursive::Minimum=1000",
        "-o", "pkgCacheGen::ForceEssential=,",
    ]


def invoke_apt(
    state: MkosiState,
    command: str,
    operation: str,
    packages: Sequence[str] = (),
    apivfs: bool = True,
) -> None:
    cmd = apivfs_cmd(state.root) if apivfs else []
    bwrap(cmd + apt_cmd(state, command) + [operation, *sort_packages(packages)],
          options=flatten(["--bind", d, d] for d in (state.config.workspace_dir, state.config.cache_dir) if d),
          env=state.config.environment)
