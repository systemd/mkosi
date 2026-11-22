# SPDX-License-Identifier: LGPL-2.1-or-later

import subprocess
import textwrap
from collections.abc import Mapping, Sequence
from pathlib import Path
from xml.etree import ElementTree

from mkosi.config import Config, yes_no
from mkosi.context import Context
from mkosi.installer.rpm import RpmPackageManager, RpmRepository, rpm_cmd
from mkosi.log import ARG_DEBUG
from mkosi.run import CompletedProcess, run, workdir
from mkosi.util import _FILE, PathString


class Zypper(RpmPackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "zypper"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("zypp")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        return [(Path("packages"), Path("packages"))]

    @classmethod
    def package_globs(cls) -> list[str]:
        return ["*.rpm"]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        install: list[PathString] = [
            "zypper",
            "install",
            "--download", "in-advance",
            "--recommends" if context.config.with_recommends else "--no-recommends",
            "--force-resolution",
        ]  # fmt: skip

        return {
            "zypper": cls.apivfs_script_cmd(context) + cls.env_cmd(context) + cls.cmd(context),
            "rpm":    cls.apivfs_script_cmd(context) + rpm_cmd(),
            "mkosi-install":   install,
            "mkosi-upgrade":   ["zypper", "update"],
            "mkosi-remove":    ["zypper", "--ignore-unknown", "remove", "--clean-deps"],
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
            f"--releasever={context.config.release}",
            *(["--no-gpg-checks"] if not context.config.repository_key_check else []),
            *([f"--plus-content={repo}" for repo in context.config.repositories]),
            *(["-vv"] if ARG_DEBUG.get() else []),
        ]

    @classmethod
    def invoke(
        cls,
        context: Context,
        operation: str,
        arguments: Sequence[str] = (),
        *,
        options: Sequence[str] = (),
        apivfs: bool = False,
        env: Mapping[str, str] = {},
        stdout: _FILE = None,
    ) -> CompletedProcess:
        return run(
            cls.cmd(context) + [*options, operation, *arguments],
            sandbox=cls.sandbox(context, apivfs=apivfs),
            env={**cls.finalize_environment(context), **env},
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
        arguments = [
            "--download", "in-advance",
            "--recommends" if context.config.with_recommends else "--no-recommends",
            "--force-resolution",
        ]  # fmt: skip

        if allow_downgrade:
            arguments += ["--allow-downgrade", "--oldpackage"]

        before: set[str] = set()
        if reinstall:
            result = run(
                [*rpm_cmd(), "--query", "--all", "--queryformat", r"%{NEVRA}\n"],
                sandbox=context.sandbox(options=context.rootoptions(readonly=True)),
                stdout=subprocess.PIPE,
            )
            before.update(result.stdout.splitlines())

        cls.invoke(context, "install", [*arguments, *packages], apivfs=apivfs)

        if reinstall:
            pinned, installed = cls.reinstall_targets(context, packages, arguments, before)
            if pinned:
                cls.invoke(context, "install", ["--force", *arguments, *pinned], apivfs=apivfs)
            cls.collect_overlay_package_files(context, installed)

    @classmethod
    def reinstall_targets(
        cls,
        context: Context,
        packages: Sequence[str],
        arguments: Sequence[str],
        before: set[str],
    ) -> tuple[list[str], list[str]]:
        # Let the normal install select versions first. --force on the original requests could
        # downgrade an installed package or switch its architecture or vendor.
        result = cls.invoke(
            context,
            "install",
            ["--dry-run", "--force", *arguments, *packages],
            options=["--xmlout"],
            env={"LANGUAGE": "C"},
            stdout=subprocess.PIPE,
        )
        plan = ElementTree.fromstring(result.stdout)
        new_vendor = {p.attrib["name"] for p in plan.findall("install-summary/to-change-vendor/solvable")}
        local: dict[str, str] = {}
        if rpms := [spec for spec in packages if spec.endswith(".rpm")]:
            result = run(
                [*rpm_cmd(), "--query", "--package", "--queryformat", r"%{NEVRA}\n", *rpms],
                sandbox=cls.sandbox(context, apivfs=False),
                stdout=subprocess.PIPE,
            )
            local = dict(zip(result.stdout.splitlines(), rpms))

        pinned: set[str] = set()
        installed: set[str] = set()
        forced: set[str] = set()
        for msg in plan.findall("message[@type='info']"):
            text = msg.text or ""
            if text.startswith("Forcing installation of '"):
                forced.add(text.split("'")[1])
            elif text.startswith("Package '") and "' is not available in your repositories." in text:
                installed.add(text.split("'")[1])
            elif "' providing '" in text and text.endswith("' is already installed."):
                installed.add(text.split("'")[1])

        for p in plan.findall("install-summary/*/solvable[@type='package'][@edition-old]"):
            name, arch, edition = p.attrib["name"], p.attrib["arch"], p.attrib["edition"]
            nevra = f"{name}-{edition}.{arch}"
            old = f"{name}-{p.attrib['edition-old']}.{p.attrib['arch-old']}"
            if old != nevra and nevra not in forced:
                continue  # A dependency change in the hypothetical transaction.

            installed.add(old)
            if old == nevra and nevra in before and name not in new_vendor:
                repo = p.attrib["repository"]
                # Zypper's temporary repository for command-line RPMs won't survive the dry run.
                source = local[nevra] if repo == "_tmpRPMcache_" else f"{repo}:{name}.{arch}={edition}"
                pinned.add(source)

        return sorted(pinned), sorted(installed)

    @classmethod
    def remove(cls, context: Context, packages: Sequence[str]) -> None:
        cls.invoke(context, "remove", ["--clean-deps", *packages], apivfs=True, options=["--ignore-unknown"])

    @classmethod
    def sync(cls, context: Context, force: bool, arguments: Sequence[str] = ()) -> None:
        cls.invoke(
            context,
            "refresh",
            [*(["--force"] if force else []), *arguments],
            options=["--gpg-auto-import-keys"] if context.config.repository_key_fetch else [],
        )

    @classmethod
    def createrepo(cls, context: Context) -> None:
        run(
            ["createrepo_c", workdir(context.repository)],
            sandbox=context.sandbox(options=["--bind", context.repository, workdir(context.repository)]),
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
