# SPDX-License-Identifier: LGPL-2.1+
import shutil
import textwrap
from collections.abc import Sequence

from mkosi.bubblewrap import apivfs_cmd, bwrap
from mkosi.context import Context
from mkosi.types import PathString
from mkosi.util import sort_packages, umask


def setup_apt(context: Context, repos: Sequence[str]) -> None:
    (context.pkgmngr / "etc/apt").mkdir(exist_ok=True, parents=True)
    (context.pkgmngr / "etc/apt/apt.conf.d").mkdir(exist_ok=True, parents=True)
    (context.pkgmngr / "etc/apt/preferences.d").mkdir(exist_ok=True, parents=True)
    (context.pkgmngr / "etc/apt/sources.list.d").mkdir(exist_ok=True, parents=True)

    # TODO: Drop once apt 2.5.4 is widely available.
    with umask(~0o755):
        (context.root / "var/lib/dpkg").mkdir(parents=True, exist_ok=True)
        (context.root / "var/lib/dpkg/status").touch()

    (context.cache_dir / "lib/apt").mkdir(exist_ok=True, parents=True)
    (context.cache_dir / "cache/apt").mkdir(exist_ok=True, parents=True)

    # We have a special apt.conf outside of pkgmngr dir that only configures "Dir::Etc" that we pass to APT_CONFIG to
    # tell apt it should read config files from /etc/apt in case this is overridden by distributions. This is required
    # because apt parses CLI configuration options after parsing its configuration files and as such we can't use CLI
    # options to tell apt where to look for configuration files.
    config = context.workspace / "apt.conf"
    if not config.exists():
        config.write_text(
            textwrap.dedent(
                """\
                Dir::Etc "etc/apt";
                """
            )
        )

    sources = context.pkgmngr / "etc/apt/sources.list"
    if not sources.exists():
        with sources.open("w") as f:
            for repo in repos:
                f.write(f"{repo}\n")


def apt_cmd(context: Context, command: str) -> list[PathString]:
    debarch = context.config.distribution.architecture(context.config.architecture)

    cmdline: list[PathString] = [
        "env",
        f"APT_CONFIG={context.workspace / 'apt.conf'}",
        "DEBIAN_FRONTEND=noninteractive",
        "DEBCONF_INTERACTIVE_SEEN=true",
        "INITRD=No",
        command,
        "-o", f"APT::Architecture={debarch}",
        "-o", f"APT::Architectures={debarch}",
        "-o", f"APT::Install-Recommends={str(context.config.with_recommends).lower()}",
        "-o", "APT::Immediate-Configure=off",
        "-o", "APT::Get::Assume-Yes=true",
        "-o", "APT::Get::AutomaticRemove=true",
        "-o", "APT::Get::Allow-Change-Held-Packages=true",
        "-o", "APT::Get::Allow-Remove-Essential=true",
        "-o", "APT::Sandbox::User=root",
        "-o", f"Dir::Cache={context.cache_dir / 'cache/apt'}",
        "-o", f"Dir::State={context.cache_dir / 'lib/apt'}",
        "-o", f"Dir::State::Status={context.root / 'var/lib/dpkg/status'}",
        "-o", f"Dir::Log={context.workspace}",
        "-o", f"Dir::Bin::DPkg={shutil.which('dpkg')}",
        "-o", "Debug::NoLocking=true",
        "-o", f"DPkg::Options::=--root={context.root}",
        "-o", "DPkg::Options::=--force-unsafe-io",
        "-o", "DPkg::Options::=--force-architecture",
        "-o", "DPkg::Options::=--force-depends",
        "-o", "DPkg::Options::=--no-debsig",
        "-o", "DPkg::Use-Pty=false",
        "-o", "DPkg::Install::Recursive::Minimum=1000",
        "-o", "pkgCacheGen::ForceEssential=,",
    ]

    if not context.config.with_docs:
        cmdline += [
            "-o", "DPkg::Options::=--path-exclude=/usr/share/doc/*",
            "-o", "DPkg::Options::=--path-include=/usr/share/doc/*/copyright",
            "-o", "DPkg::Options::=--path-exclude=/usr/share/man/*",
            "-o", "DPkg::Options::=--path-exclude=/usr/share/groff/*",
            "-o", "DPkg::Options::=--path-exclude=/usr/share/info/*",
        ]

    return cmdline


def invoke_apt(
    context: Context,
    command: str,
    operation: str,
    packages: Sequence[str] = (),
    apivfs: bool = True,
) -> None:
    cmd = apivfs_cmd(context.root) if apivfs else []
    bwrap(context, cmd + apt_cmd(context, command) + [operation, *sort_packages(packages)],
          network=True, env=context.config.environment)
