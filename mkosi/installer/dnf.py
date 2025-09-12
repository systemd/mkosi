# SPDX-License-Identifier: LGPL-2.1-or-later
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import Optional

from mkosi.config import Cacheonly, Config
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.installer.rpm import RpmRepository, rpm_cmd
from mkosi.log import ARG_DEBUG
from mkosi.run import CompletedProcess, run, workdir
from mkosi.util import _FILE, PathString


class Dnf(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        # Allow the user to override autodetection with an environment variable
        dnf = config.finalize_environment().get("MKOSI_DNF")
        return Path(dnf or config.find_binary("dnf5") or "dnf").name

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("libdnf5" if cls.executable(config) == "dnf5" else "dnf")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        dirs = [p for p in cache.iterdir() if p.is_dir() and "-" in p.name and "mkosi" not in p.name]
        return [
            (
                # If the package cache directory is set to /var, we need to make sure we look up packages
                # where they were stored by dnf, so don't do any special handling in that case.
                d.relative_to(cache) / "packages"
                if cache.parent == Path("/var/cache")
                # Cache directories look like <repo-id>-<baseurl-hash> so let's strip off the hash to reuse
                # the same package cache directory regardless of baseurl.
                else Path("packages") / d.name[: d.name.rfind("-")],
                d.relative_to(cache) / "packages",
            )
            for d in dirs
        ]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "dnf": cls.apivfs_script_cmd(context) + cls.env_cmd(context) + cls.cmd(context),
            "rpm": cls.apivfs_script_cmd(context) + rpm_cmd(),
            "mkosi-install":   ["dnf", "install"],
            "mkosi-upgrade":   ["dnf", "upgrade"],
            "mkosi-remove":    ["dnf", "remove"],
            "mkosi-reinstall": ["dnf", "reinstall"],
        }  # fmt: skip

    @classmethod
    def setup(
        cls,
        context: Context,
        repositories: Sequence[RpmRepository],
        filelists: bool = True,
        metadata_expire: Optional[str] = None,
    ) -> None:
        (context.sandbox_tree / "etc/dnf/vars").mkdir(parents=True, exist_ok=True)
        (context.sandbox_tree / "etc/yum.repos.d").mkdir(parents=True, exist_ok=True)

        config = context.sandbox_tree / "etc/dnf/dnf.conf"

        if not config.exists():
            config.parent.mkdir(exist_ok=True, parents=True)
            with config.open("w") as f:
                # Make sure we download filelists so all dependencies can be resolved.
                # See https://bugzilla.redhat.com/show_bug.cgi?id=2180842
                if cls.executable(context.config) == "dnf5" and filelists:
                    f.write("[main]\noptional_metadata_types=filelists\n")

        # The CentOS Hyperscale ships a COW plugin for dnf that's disabled by default. Let's enable it so we
        # can take advantage of faster rpm package installations.
        reflink = context.sandbox_tree / "etc/dnf/plugins/reflink.conf"
        if not reflink.exists():
            reflink.parent.mkdir(parents=True, exist_ok=True)
            reflink.write_text(
                textwrap.dedent(
                    """\
                    [main]
                    enabled=1
                    """
                )
            )

        # The versionlock plugin will fail if enabled without a configuration file so lets' write a noop
        # configuration file to make it happy which can be overridden by users.
        versionlock = context.sandbox_tree / "etc/dnf/plugins/versionlock.conf"
        if not versionlock.exists():
            versionlock.parent.mkdir(parents=True, exist_ok=True)
            versionlock.write_text(
                textwrap.dedent(
                    """\
                    [main]
                    enabled=0
                    locklist=/dev/null
                    """
                )
            )

        repofile = context.sandbox_tree / "etc/yum.repos.d/mkosi.repo"
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
                    if repo.priority:
                        f.write(f"priority={repo.priority}\n")
                    if metadata_expire:
                        f.write(f"metadata_expire={metadata_expire}\n")

                    for i, url in enumerate(repo.gpgurls):
                        f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                        f.write(f"{url}\n")

                    f.write("\n")

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        return super().finalize_environment(context) | {
            "RPM_FORCE_DEBIAN": "1",
        }

    @classmethod
    def cmd(
        cls,
        context: Context,
        cached_metadata: bool = True,
    ) -> list[PathString]:
        dnf = cls.executable(context.config)

        cmdline: list[PathString] = [
            dnf,
            "--assumeyes",
            "--best",
            f"--releasever={context.config.release}",
            "--installroot=/buildroot",
            "--setopt=keepcache=1",
            "--setopt=logdir=/var/log",
            f"--setopt=cachedir=/var/cache/{cls.subdir(context.config)}",
            f"--setopt=install_weak_deps={int(context.config.with_recommends)}",
            "--setopt=check_config_file_age=0",
            "--setopt=persistdir=/buildroot/var/lib/dnf",
        ]

        if ARG_DEBUG.get():
            cmdline += ["--setopt=debuglevel=10"]

        if not context.config.repository_key_check:
            cmdline += ["--nogpgcheck"]

        if context.config.repositories:
            opt = "--enable-repo" if dnf == "dnf5" else "--enablerepo"
            cmdline += [f"{opt}={repo}" for repo in context.config.repositories]

        if context.config.cacheonly == Cacheonly.always:
            cmdline += ["--cacheonly"]
        elif cached_metadata:
            cmdline += ["--setopt=metadata_expire=never"]
            if dnf == "dnf5":
                cmdline += ["--setopt=cacheonly=metadata"]

        if not context.config.architecture.is_native():
            cmdline += [
                f"--forcearch={context.config.distribution.architecture(context.config.architecture)}"
            ]

        if not context.config.with_docs:
            cmdline += ["--no-docs" if dnf == "dnf5" else "--nodocs"]

        if dnf == "dnf5":
            cmdline += ["--use-host-config"]
        else:
            cmdline += [
                "--config=/etc/dnf/dnf.conf",
                "--setopt=reposdir=/etc/yum.repos.d",
                "--setopt=varsdir=/etc/dnf/vars",
            ]

        if context.config.proxy_url:
            cmdline += [f"--setopt=proxy={context.config.proxy_url}"]
        if context.config.proxy_peer_certificate:
            cmdline += ["--setopt=proxy_sslcacert=/proxy.cacert"]
        if context.config.proxy_client_certificate:
            cmdline += ["--setopt=proxy_sslclientcert=/proxy.clientcert"]
        if context.config.proxy_client_key:
            cmdline += ["--setopt=proxy_sslclientkey=/proxy.clientkey"]

        return cmdline

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        arguments: Sequence[str] = (),
        *,
        apivfs: bool = False,
        stdout: _FILE = None,
        cached_metadata: bool = True,
    ) -> CompletedProcess:
        try:
            return run(
                cls.cmd(context, cached_metadata=cached_metadata) + [operation, *arguments],
                sandbox=cls.sandbox(context, apivfs=apivfs),
                env=cls.finalize_environment(context),
                stdout=stdout,
            )
        finally:
            # dnf interprets the log directory relative to the install root so there's nothing we can do but
            # to remove the log files from the install root afterwards.
            if (context.root / "var/log").exists():
                for p in (context.root / "var/log").iterdir():
                    if any(p.name.startswith(prefix) for prefix in ("dnf", "hawkey", "yum")):
                        p.unlink()

    @classmethod
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        arguments = []

        if allow_downgrade and Dnf.executable(context.config) == "dnf5":
            arguments += ["--allow-downgrade"]

        arguments += [*packages]

        cls.invoke(context, "install", arguments, apivfs=apivfs)

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "remove", packages, apivfs=True)

    @classmethod
    def sync(cls, context: Context, force: bool, arguments: Sequence[str] = ()) -> None:
        cls.invoke(
            context,
            "makecache",
            arguments=[*(["--refresh"] if force else []), *arguments],
            cached_metadata=False,
        )

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(
            ["createrepo_c", workdir(context.repository)],
            sandbox=context.sandbox(options=["--bind", context.repository, workdir(context.repository)]),
        )

        (context.sandbox_tree / "etc/yum.repos.d/mkosi-local.repo").write_text(
            textwrap.dedent(
                """\
                [mkosi]
                name=mkosi
                baseurl=file:///repository
                gpgcheck=0
                metadata_expire=never
                priority=10
                """
            )
        )

        cls.sync(context, force=True, arguments=["--disablerepo=*", "--enablerepo=mkosi"])
