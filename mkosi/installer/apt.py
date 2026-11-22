# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import subprocess
import textwrap
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, Optional

from mkosi.config import Config, ConfigFeature
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.log import die
from mkosi.run import CompletedProcess, run, workdir
from mkosi.sandbox import umask
from mkosi.util import _FILE, PathString


@dataclasses.dataclass(frozen=True)
class AptRepository:
    types: tuple[str, ...]
    url: str
    suite: str
    components: tuple[str, ...]
    signedby: Optional[Path]
    snapshot: Optional[str] = None

    def __str__(self) -> str:
        return textwrap.dedent(
            f"""\
            Types: {" ".join(self.types)}
            URIs: {self.url}
            Suites: {self.suite}
            Components: {" ".join(self.components)}
            {"Signed-By" if self.signedby else "Trusted"}: {self.signedby or "yes"}
            {f"Snapshot: {self.snapshot}" if self.snapshot else ""}

            """
        )


class Apt(PackageManager):
    documentation_exclude_globs: Final[list[str]] = [
        "usr/share/doc/*",
        "usr/share/man/*",
        "usr/share/groff/*",
        "usr/share/gtk-doc/*",
        "usr/share/info/*",
    ]

    @classmethod
    def executable(cls, config: Config) -> str:
        return "apt-get"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("apt")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        return [(Path("archives"), Path("archives"))]

    @classmethod
    def package_globs(cls) -> list[str]:
        return ["*.deb", "*.ddeb"]

    @classmethod
    def state_subdirs(cls) -> list[Path]:
        return [Path("lists")]

    @classmethod
    def dpkg_cmd(cls, command: str) -> list[PathString]:
        return [
            command,
            "--admindir=/buildroot/var/lib/dpkg",
            "--root=/buildroot",
        ]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        cmd = cls.apivfs_script_cmd(context)

        return {
            **{
                command: cmd + cls.env_cmd(context) + cls.cmd(context, command)
                for command in (
                    "apt",
                    "apt-cache",
                    "apt-cdrom",
                    "apt-config",
                    "apt-extracttemplates",
                    "apt-get",
                    "apt-key",
                    "apt-mark",
                    "apt-sortpkgs",
                )
            },
            **{
                command: cmd + cls.dpkg_cmd(command)
                for command in (
                    "dpkg",
                    "dpkg-query",
                )
            },
            "mkosi-install":   ["apt-get", "install"],
            "mkosi-upgrade":   ["apt-get", "upgrade"],
            "mkosi-remove":    ["apt-get", "purge"],
            "mkosi-reinstall": ["apt-get", "install", "--reinstall"],
        }  # fmt: skip

    @classmethod
    def options(cls, *, root: PathString, apivfs: bool = True) -> list[PathString]:
        return super().options(root=root, apivfs=apivfs) + ["--dir", "/var/lib/apt/lists/partial"]

    @classmethod
    def setup(cls, context: Context, repositories: Sequence[AptRepository]) -> None:
        (context.sandbox_tree / "etc/apt").mkdir(exist_ok=True, parents=True)
        (context.sandbox_tree / "etc/apt/apt.conf.d").mkdir(exist_ok=True, parents=True)
        (context.sandbox_tree / "etc/apt/preferences.d").mkdir(exist_ok=True, parents=True)
        (context.sandbox_tree / "etc/apt/sources.list.d").mkdir(exist_ok=True, parents=True)

        # We have a special apt.conf outside of the sandbox tree that only configures "Dir::Etc" that we pass
        # to APT_CONFIG to tell apt it should read config files from /etc/apt in case this is overridden by
        # distributions.  This is required because apt parses CLI configuration options after parsing its
        # configuration files and as such we can't use CLI options to tell apt where to look for
        # configuration files.
        config = context.sandbox_tree / "etc/apt.conf"
        if not config.exists():
            config.write_text(
                textwrap.dedent(
                    """\
                    Dir::Etc "/etc/apt";
                    """
                )
            )

        sources = context.sandbox_tree / "etc/apt/sources.list.d/mkosi.sources"
        if not sources.exists():
            for repo in repositories:
                if repo.signedby and not (context.config.tools() / str(repo.signedby).lstrip("/")).exists():
                    die(
                        f"Keyring for repo {repo.url} not found at {repo.signedby}",
                        hint="Make sure the right keyring package (e.g. debian-archive-keyring, "
                        "kali-archive-keyring or ubuntu-keyring) is installed",
                    )

            with sources.open("w") as f:
                for repo in repositories:
                    f.write(str(repo))

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        env = {
            "APT_CONFIG": "/etc/apt.conf",
            "DEBIAN_FRONTEND": "noninteractive",
            "DEBCONF_INTERACTIVE_SEEN": "true",
        }

        if (
            "INITRD" not in context.config.finalize_environment()
            and context.config.bootable != ConfigFeature.disabled
        ):
            env["INITRD"] = "No"

        return super().finalize_environment(context) | env

    @classmethod
    def cmd(cls, context: Context, command: str = "apt-get") -> list[PathString]:
        cmdline: list[PathString] = [
            command,
            "-o", f"APT::Architecture={cls.architecture(context)}",
            "-o", f"APT::Architectures={cls.architecture(context)}",
            "-o", f"APT::Install-Recommends={str(context.config.with_recommends).lower()}",
            "-o", "APT::Immediate-Configure=off",
            "-o", "APT::Get::Assume-Yes=true",
            "-o", "APT::Get::AutomaticRemove=true",
            "-o", "APT::Get::Allow-Change-Held-Packages=true",
            "-o", "APT::Get::Allow-Remove-Essential=true",
            "-o", "APT::Sandbox::User=root",
            "-o", "Acquire::AllowReleaseInfoChange=true",
            "-o", "Acquire::Check-Valid-Until=false",
            "-o", "Dir::Cache=/var/cache/apt",
            "-o", "Dir::State=/buildroot/var/lib/apt",
            "-o", "Dir::State::lists=/var/lib/apt/lists/",
            "-o", "Dir::Log=/var/log/apt",
            "-o", "Dir::State::Status=/buildroot/var/lib/dpkg/status",
            "-o", f"Dir::Bin::DPkg={context.config.find_binary('dpkg')}",
            "-o", "Debug::NoLocking=true",
            "-o", "DPkg::Options::=--root=/buildroot",
            "-o", "DPkg::Options::=--force-unsafe-io",
            "-o", "DPkg::Options::=--force-architecture",
            "-o", "DPkg::Options::=--force-depends",
            "-o", "DPkg::Options::=--no-debsig",
            "-o", "DPkg::Use-Pty=false",
            "-o", "DPkg::Install::Recursive::Minimum=1000",
            "-o", "pkgCacheGen::ForceEssential=,",
        ]  # fmt: skip

        if not context.config.repository_key_check:
            cmdline += [
                "-o", "Acquire::AllowInsecureRepositories=true",
                "-o", "Acquire::AllowDowngradeToInsecureRepositories=true",
                "-o", "APT::Get::AllowUnauthenticated=true",
            ]  # fmt: skip

        if not context.config.with_docs:
            cmdline += [
                f"--option=DPkg::Options::=--path-exclude=/{glob}"
                for glob in cls.documentation_exclude_globs
            ]
            cmdline += ["--option=DPkg::Options::=--path-include=/usr/share/doc/*/copyright"]

        if context.config.proxy_url:
            cmdline += [
                "-o", f"Acquire::http::Proxy={context.config.proxy_url}",
                "-o", f"Acquire::https::Proxy={context.config.proxy_url}",
            ]  # fmt: skip

        return cmdline

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        arguments: Sequence[str] = (),
        *,
        apivfs: bool = False,
        options: Sequence[PathString] = (),
        stdout: _FILE = None,
    ) -> CompletedProcess:
        with umask(~0o755):
            # TODO: Drop once apt 2.5.4 is widely available.
            (context.root / "var/lib/dpkg").mkdir(parents=True, exist_ok=True)
            (context.root / "var/lib/dpkg/status").touch(exist_ok=True)

            (context.root / "var/lib/dpkg/available").touch(exist_ok=True)

        return run(
            cls.cmd(context) + [operation, *arguments],
            sandbox=cls.sandbox(context, apivfs=apivfs, options=options),
            env=cls.finalize_environment(context),
            stdout=stdout,
        )

    @classmethod
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
        reinstall: bool = False,
    ) -> None:
        # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones
        # to start. Let's install one that denies all daemon startups.
        # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
        # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be
        # managed by the admin.
        policyrcd = context.root / "usr/sbin/policy-rc.d"
        with umask(~0o755):
            policyrcd.parent.mkdir(parents=True, exist_ok=True)
        with umask(~0o644):
            policyrcd.write_text("#!/bin/sh\nexit 101\n")

        arguments = []

        if reinstall:
            arguments += ["--reinstall"]

        if allow_downgrade:
            arguments += ["--allow-downgrades"]

        arguments += [*packages]

        cls.invoke(context, "install", arguments, apivfs=apivfs)

        if reinstall:
            downloadable, unavailable = cls.installed_targets(context, arguments)
            cls.collect_overlay_package_files(context, downloadable)
            cls.collect_overlay_package_files(context, unavailable, copy_up=True)

        policyrcd.unlink()

        # systemd-gpt-auto-generator is disabled by default in Ubuntu:
        # https://git.launchpad.net/ubuntu/+source/systemd/tree/debian/systemd.links?h=ubuntu/noble-proposed.
        # Let's make sure it is enabled by default in our images.
        (context.root / "etc/systemd/system-generators/systemd-gpt-auto-generator").unlink(missing_ok=True)

    @classmethod
    def installed_targets(
        cls,
        context: Context,
        install_arguments: Sequence[str],
    ) -> tuple[list[str], list[str]]:
        # With dependencies satisfied, a simulated reinstall lists just the requested packages,
        # with apt having resolved virtual names, version constraints and architecture qualifiers.
        result = cls.invoke(
            context,
            "install",
            ["--simulate", "--quiet=1", *install_arguments],
            options=["--setenv", "LC_ALL", "C"],
            stdout=subprocess.PIPE,
        )
        lines = result.stdout.splitlines()
        downloadable = [line.split()[1] for line in lines if line.startswith("Inst ")]
        # APT reports undownloadable packages separately rather than emitting an Inst line.
        # Their installed files must be copied up because dpkg did not unpack them again.
        unavailable = [line.split()[2] for line in lines if line.startswith("Reinstallation of ")]
        return downloadable, unavailable

    @classmethod
    def collect_overlay_package_files(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        copy_up: bool = False,
        **kwargs: Any,
    ) -> None:
        if not packages:
            return

        files = run(
            [*cls.dpkg_cmd("dpkg-query"), "--listfiles", *packages],
            sandbox=context.sandbox(options=context.rootoptions(readonly=True)),
            stdout=subprocess.PIPE,
        )
        context.record_overlay_package_files(
            [p for p in files.stdout.splitlines() if p.startswith("/")], copy_up=copy_up
        )

        if not copy_up:
            conffiles = run(
                [*cls.dpkg_cmd("dpkg-query"), "--show", r"--showformat=${Conffiles}\n", *packages],
                sandbox=context.sandbox(options=context.rootoptions(readonly=True)),
                stdout=subprocess.PIPE,
            )
            context.record_overlay_package_files(
                [
                    line.lstrip().rsplit(" ", maxsplit=1)[0]
                    for line in conffiles.stdout.splitlines()
                    if line and not line.endswith((" obsolete", " remove-on-upgrade"))
                ],
                copy_up=True,
            )

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "purge", packages, apivfs=True)

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        cls.invoke(context, "update")

    @classmethod
    def createrepo(cls, context: Context) -> None:
        names = [d.name for glob in cls.package_globs() for d in context.repository.glob(glob)]
        if not names:
            return

        with (context.repository / "Packages").open("wb") as f:
            run(
                ["apt-ftparchive", "packages", "."],
                stdout=f,
                sandbox=context.sandbox(
                    options=[
                        "--ro-bind", context.repository, workdir(context.repository),
                        "--chdir", workdir(context.repository),
                    ],
                ),
            )  # fmt: skip

        (context.sandbox_tree / "etc/apt/sources.list.d").mkdir(parents=True, exist_ok=True)
        (context.sandbox_tree / "etc/apt/sources.list.d/mkosi-local.sources").write_text(
            textwrap.dedent(
                """\
                Enabled: yes
                Types: deb
                URIs: file:///repository
                Suites: ./
                Trusted: yes
                """
            )
        )

        (context.sandbox_tree / "etc/apt/preferences.d").mkdir(parents=True, exist_ok=True)
        (context.sandbox_tree / "etc/apt/preferences.d/mkosi-local.pref").write_text(
            textwrap.dedent(
                """\
                Package: *
                Pin: origin ""
                Pin-Priority: 1100
                """
            )
        )

        cls.invoke(
            context,
            "update",
            arguments=[
                "-o", "Dir::Etc::sourcelist=sources.list.d/mkosi-local.sources",
                "-o", "Dir::Etc::sourceparts=-",
                "-o", "APT::Get::List-Cleanup=0",
            ],
        )  # fmt: skip
