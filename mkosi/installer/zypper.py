# SPDX-License-Identifier: LGPL-2.1-or-later
import hashlib
import textwrap
from collections.abc import Sequence
from pathlib import Path

from mkosi.config import Config, yes_no
from mkosi.context import Context
from mkosi.installer import PackageManager
from mkosi.installer.rpm import RpmRepository, rpm_cmd
from mkosi.run import run, workdir
from mkosi.types import _FILE, CompletedProcess, PathString


class Zypper(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "zypper"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("zypp")

    @classmethod
    def cache_subdirs(cls, cache: Path) -> list[Path]:
        return [cache / "packages"]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        install: list[PathString] = [
            "zypper",
            "install",
            "--download", "in-advance",
            "--recommends" if context.config.with_recommends else "--no-recommends",
        ]  # fmt: skip

        return {
            "zypper": cls.apivfs_script_cmd(context) + cls.env_cmd(context) + cls.cmd(context),
            "rpm":    cls.apivfs_script_cmd(context) + rpm_cmd(),
            "mkosi-install":   install,
            "mkosi-upgrade":   ["zypper", "update"],
            "mkosi-remove":    ["zypper", "remove", "--clean-deps"],
            "mkosi-reinstall": install + ["--force"],
        }  # fmt: skip

    @classmethod
    def setup(cls, context: Context, repositories: Sequence[RpmRepository]) -> None:
        config = context.sandbox_tree / "etc/zypp/zypp.conf"
        config.parent.mkdir(exist_ok=True, parents=True)

        # rpm.install.excludedocs can only be configured in zypp.conf so we append to any user provided
        # config file. Let's also bump the refresh delay to the same default as dnf which is 48 hours.
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

        repofile = context.sandbox_tree / "etc/zypp/repos.d/mkosi.repo"
        if not repofile.exists():
            repofile.parent.mkdir(exist_ok=True, parents=True)
            with repofile.open("w") as f:
                for repo in repositories:
                    # zypper uses the repo ID as its cache key which is unsafe so add a hash of the url used
                    # to it to make sure a unique cache is used for each repository. We use roughly the same
                    # algorithm here that dnf uses as well.
                    key = hashlib.sha256(repo.url.encode()).hexdigest()[:16]

                    f.write(
                        textwrap.dedent(
                            f"""\
                            [{repo.id}-{key}]
                            name={repo.id}
                            {repo.url}
                            gpgcheck=1
                            enabled={int(repo.enabled)}
                            autorefresh=0
                            keeppackages=1
                            """
                        )
                    )

                    if repo.priority:
                        f.write(f"priority={repo.priority}\n")

                    for i, url in enumerate(repo.gpgurls):
                        f.write("gpgkey=" if i == 0 else len("gpgkey=") * " ")
                        f.write(f"{url}\n")

                    f.write("\n")

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        return super().finalize_environment(context) | {
            "ZYPP_CONF": "/etc/zypp/zypp.conf",
            "RPM_FORCE_DEBIAN": "1",
        }

    @classmethod
    def cmd(cls, context: Context) -> list[PathString]:
        return [
            "zypper",
            "--installroot=/buildroot",
            "--cache-dir=/var/cache/zypp",
            "--non-interactive",
            "--no-refresh",
            *(["--gpg-auto-import-keys"] if context.config.repository_key_fetch else []),
            *(["--no-gpg-checks"] if not context.config.repository_key_check else []),
            *([f"--plus-content={repo}" for repo in context.config.repositories]),
        ]

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        arguments: Sequence[str] = (),
        *,
        apivfs: bool = False,
        stdout: _FILE = None,
    ) -> CompletedProcess:
        return run(
            cls.cmd(context) + [operation, *arguments],
            sandbox=cls.sandbox(context, apivfs=apivfs),
            env=cls.finalize_environment(context),
            stdout=stdout,
        )

    @classmethod
    def sync(cls, context: Context, force: bool, arguments: Sequence[str] = ()) -> None:
        cls.invoke(context, "refresh", [*(["--force"] if force else []), *arguments])

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(
            ["createrepo_c", workdir(context.repository)],
            sandbox=context.sandbox(
                binary="createrepo_c",
                options=["--bind", context.repository, workdir(context.repository)],
            ),
        )

        (context.sandbox_tree / "etc/zypp/repos.d/mkosi-local.repo").write_text(
            textwrap.dedent(
                """\
                [mkosi]
                name=mkosi
                baseurl=file:///repository
                gpgcheck=0
                autorefresh=0
                keeppackages=0
                priority=10
                """
            )
        )

        cls.sync(context, force=True, arguments=["mkosi"])
