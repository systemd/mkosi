# SPDX-License-Identifier: LGPL-2.1+
import textwrap
from collections.abc import Iterable
from pathlib import Path

from mkosi.context import Context
from mkosi.installer.rpm import RpmRepository, fixup_rpmdb_location, setup_rpm
from mkosi.mounts import finalize_source_mounts
from mkosi.run import find_binary, run
from mkosi.sandbox import apivfs_cmd, finalize_crypto_mounts
from mkosi.types import PathString
from mkosi.util import sort_packages


def dnf_executable(context: Context) -> str:
    # Allow the user to override autodetection with an environment variable
    dnf = context.config.environment.get("MKOSI_DNF")
    root = context.config.tools()

    return Path(dnf or find_binary("dnf5", root=root) or find_binary("dnf", root=root) or "yum").name


def dnf_subdir(context: Context) -> str:
    dnf = dnf_executable(context)
    return "libdnf5" if dnf.endswith("dnf5") else "dnf"


def setup_dnf(context: Context, repositories: Iterable[RpmRepository], filelists: bool = True) -> None:
    (context.pkgmngr / "etc/dnf/vars").mkdir(exist_ok=True, parents=True)
    (context.pkgmngr / "etc/yum.repos.d").mkdir(exist_ok=True, parents=True)

    (context.cache_dir / "cache" / dnf_subdir(context)).mkdir(exist_ok=True, parents=True)
    (context.cache_dir / "lib" / dnf_subdir(context)).mkdir(exist_ok=True, parents=True)

    config = context.pkgmngr / "etc/dnf/dnf.conf"

    if not config.exists():
        config.parent.mkdir(exist_ok=True, parents=True)
        with config.open("w") as f:
            # Make sure we download filelists so all dependencies can be resolved.
            # See https://bugzilla.redhat.com/show_bug.cgi?id=2180842
            if dnf_executable(context).endswith("dnf5") and filelists:
                f.write("[main]\noptional_metadata_types=filelists\n")

    repofile = context.pkgmngr / "etc/yum.repos.d/mkosi.repo"
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

    setup_rpm(context)


def dnf_cmd(context: Context) -> list[PathString]:
    dnf = dnf_executable(context)

    cmdline: list[PathString] = [
        "env",
        "HOME=/", # Make sure rpm doesn't pick up ~/.rpmmacros and ~/.rpmrc.
        dnf,
        "--assumeyes",
        "--best",
        f"--releasever={context.config.release}",
        f"--installroot={context.root}",
        "--setopt=keepcache=1",
        f"--setopt=cachedir={context.cache_dir / 'cache' / dnf_subdir(context)}",
        f"--setopt=persistdir={context.cache_dir / 'lib' / dnf_subdir(context)}",
        f"--setopt=install_weak_deps={int(context.config.with_recommends)}",
        "--setopt=check_config_file_age=0",
        "--disable-plugin=*" if dnf.endswith("dnf5") else "--disableplugin=*",
        "--enable-plugin=builddep" if dnf.endswith("dnf5") else "--enableplugin=builddep",
    ]

    if not context.config.repository_key_check:
        cmdline += ["--nogpgcheck"]

    if context.config.repositories:
        opt = "--enable-repo" if dnf.endswith("dnf5") else "--enablerepo"
        cmdline += [f"{opt}={repo}" for repo in context.config.repositories]

    # TODO: this breaks with a local, offline repository created with 'createrepo'
    if context.config.cache_only and not context.config.local_mirror:
        cmdline += ["--cacheonly"]

    if not context.config.architecture.is_native():
        cmdline += [f"--forcearch={context.config.distribution.architecture(context.config.architecture)}"]

    if not context.config.with_docs:
        cmdline += ["--no-docs" if dnf.endswith("dnf5") else "--nodocs"]

    if dnf.endswith("dnf5"):
        cmdline += ["--use-host-config"]
    else:
        cmdline += [
            "--config=/etc/dnf/dnf.conf",
            "--setopt=reposdir=/etc/yum.repos.d",
            "--setopt=varsdir=/etc/dnf/vars",
        ]

    return cmdline


def invoke_dnf(context: Context, command: str, packages: Iterable[str], apivfs: bool = True) -> None:
    run(
        dnf_cmd(context) + [command, *sort_packages(packages)],
        sandbox=(
            context.sandbox(
                network=True,
                options=[
                    "--bind", context.root, context.root,
                    "--bind",
                    context.cache_dir / "cache" / dnf_subdir(context),
                    context.cache_dir / "cache" / dnf_subdir(context),
                    "--bind",
                    context.cache_dir / "lib" / dnf_subdir(context),
                    context.cache_dir / "lib" / dnf_subdir(context),
                    *finalize_crypto_mounts(tools=context.config.tools()),
                    *finalize_source_mounts(context.config),
                    "--chdir", "/work/src",
                ],
            ) + (apivfs_cmd(context.root) if apivfs else [])
        ),
        env=context.config.environment,
    )

    fixup_rpmdb_location(context)

    # The log directory is always interpreted relative to the install root so there's nothing we can do but
    # to remove the log files from the install root afterwards.
    for p in (context.root / "var/log").iterdir():
        if any(p.name.startswith(prefix) for prefix in ("dnf", "hawkey", "yum")):
            p.unlink()
