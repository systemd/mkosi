# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Union
from xml.etree import ElementTree

from mkosi.config import Architecture, Config, parse_ini
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distribution import Distribution, DistributionInstaller, PackageType, join_mirror
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.installer.zypper import Zypper
from mkosi.log import die
from mkosi.mounts import finalize_certificate_mounts
from mkosi.run import run, workdir
from mkosi.util import flatten
from mkosi.versioncomp import GenericVersion


class Installer(DistributionInstaller, distribution=Distribution.opensuse):
    @classmethod
    def pretty_name(cls) -> str:
        return "openSUSE"

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def default_release(cls) -> str:
        return "tumbleweed"

    @classmethod
    def grub_prefix(cls) -> str:
        return "grub2"

    @classmethod
    def package_manager(cls, config: Config) -> Union[type[Dnf], type[Zypper]]:
        if config.find_binary("zypper"):
            return Zypper
        else:
            return Dnf

    @classmethod
    def setup(cls, context: Context) -> None:
        setup_rpm(context, dbbackend="ndb")
        cls.package_manager(context.config).setup(context, list(cls.repositories(context)))

        if cls.package_manager(context.config) is Zypper and (gpgkeys := fetch_gpgkeys(context)):
            run(
                ["rpm", "--root=/buildroot", "--import", *(workdir(key) for key in gpgkeys)],
                sandbox=context.sandbox(
                    options=[
                        *context.rootoptions(),
                        *finalize_certificate_mounts(context.config),
                        *flatten(["--ro-bind", os.fspath(key), workdir(key)] for key in gpgkeys),
                    ],
                ),
            )

    @classmethod
    def install(cls, context: Context) -> None:
        packages = ["filesystem"]
        if not any(p.endswith("-release") for p in context.config.packages):
            if context.config.release in ("current", "stable", "leap") or (
                context.config.release != "tumbleweed" and GenericVersion(context.config.release) >= 16
            ):
                packages += ["Leap-release"]
            else:
                packages += ["openSUSE-release"]

        cls.install_packages(context, packages, apivfs=False)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(id="local-mirror", url=f"baseurl={context.config.local_mirror}", gpgurls=())
            return

        zypper = cls.package_manager(context.config) is Zypper
        mirror = context.config.mirror or "https://download.opensuse.org"

        if context.config.release == "tumbleweed":
            gpgkeys = tuple(
                p
                for key in ("RPM-GPG-KEY-openSUSE-Tumbleweed", "RPM-GPG-KEY-openSUSE")
                if (p := find_rpm_gpgkey(context, key, required=not context.config.repository_key_fetch))
            )

            if context.config.snapshot:
                if context.config.architecture != Architecture.x86_64:
                    die(f"Snapshot= is only supported for x86-64 on {cls.pretty_name()}")

                subdir = f"history/{context.config.snapshot}"
            else:
                if context.config.architecture == Architecture.x86_64:
                    subdir = ""
                elif context.config.architecture == Architecture.arm64:
                    subdir = "ports/aarch64"
                elif context.config.architecture == Architecture.arm:
                    subdir = "ports/armv7hl"
                elif context.config.architecture in (
                    Architecture.ppc64_le,
                    Architecture.ppc64,
                    Architecture.ppc,
                ):
                    subdir = "ports/ppc"
                elif context.config.architecture in (Architecture.s390x, Architecture.s390):
                    subdir = "ports/zsystems"
                elif context.config.architecture == Architecture.riscv64:
                    subdir = "ports/riscv"
                else:
                    die(f"{context.config.architecture} not supported by openSUSE Tumbleweed")

            for repo in ("oss", "non-oss"):
                url = join_mirror(mirror, f"{subdir}/tumbleweed/repo/{repo}")
                yield RpmRepository(
                    id=repo,
                    url=f"baseurl={url}",
                    gpgurls=gpgkeys or (fetch_gpgurls(context, url) if not zypper else ()),
                    enabled=repo == "oss",
                )

                if not context.config.snapshot:
                    for d in ("debug", "source"):
                        if repo == "non-oss" and d == "debug":
                            continue
                        url = join_mirror(mirror, f"{subdir}/{d}/tumbleweed/repo/{repo}")
                        yield RpmRepository(
                            id=f"{repo}-{d}",
                            url=f"baseurl={url}",
                            gpgurls=gpgkeys or (fetch_gpgurls(context, url) if not zypper else ()),
                            enabled=False,
                        )

            if not context.config.snapshot:
                url = join_mirror(mirror, f"{subdir}/update/tumbleweed")
                yield RpmRepository(
                    id="oss-update",
                    url=f"baseurl={url}",
                    gpgurls=gpgkeys or (fetch_gpgurls(context, url) if not zypper else ()),
                )

                url = join_mirror(mirror, f"{subdir}/update/tumbleweed-non-oss")
                yield RpmRepository(
                    id="non-oss-update",
                    url=f"baseurl={url}",
                    gpgurls=gpgkeys or (fetch_gpgurls(context, url) if not zypper else ()),
                    enabled=False,
                )
        else:
            if context.config.snapshot:
                die(f"Snapshot= is only supported for Tumbleweed on {cls.pretty_name()}")

            if (
                context.config.release in ("current", "stable", "leap")
                and context.config.architecture != Architecture.x86_64
            ):
                die(
                    f"{cls.pretty_name()} only supports current and stable releases "
                    "for the x86-64 architecture",
                    hint="Specify either tumbleweed or a specific leap release such as 15.6",
                )

            if context.config.release in ("current", "stable", "leap"):
                release = "openSUSE-current"
            else:
                release = f"leap/{context.config.release}"

            if context.config.architecture == Architecture.x86_64:
                subdir = ""
            elif context.config.architecture == Architecture.arm64:
                subdir = "ports/aarch64"
            elif context.config.architecture == Architecture.arm:
                subdir = "ports/armv7hl"
            elif context.config.architecture in (
                Architecture.ppc64_le,
                Architecture.ppc64,
                Architecture.ppc,
            ):
                subdir = "ports/ppc"
            elif context.config.architecture in (Architecture.s390x, Architecture.s390):
                subdir = "ports/zsystems"
            else:
                die(f"{context.config.architecture} not supported by openSUSE {context.config.release}")

            for repo in ("oss", "non-oss"):
                url = join_mirror(mirror, f"{subdir}/distribution/{release}/repo/{repo}")
                yield RpmRepository(
                    id=repo,
                    url=f"baseurl={url}",
                    gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                    enabled=repo == "oss",
                )

            for d in ("debug", "source"):
                for repo in ("oss", "non-oss"):
                    url = join_mirror(mirror, f"{subdir}/{d}/distribution/{release}/repo/{repo}")
                    yield RpmRepository(
                        id=f"{repo}-{d}",
                        url=f"baseurl={url}",
                        gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                        enabled=False,
                    )

            if (
                context.config.release in ("current", "stable", "leap")
                or GenericVersion(context.config.release) >= 16
            ):
                subdir += f"distribution/{release}/repo"
            else:
                subdir += f"update/{release}"

            for repo in ("oss", "non-oss"):
                url = join_mirror(mirror, f"{subdir}/{repo}")
                yield RpmRepository(
                    id=f"{repo}-update",
                    url=f"baseurl={url}",
                    gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                    enabled=repo == "oss",
                )

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "x86_64",
            Architecture.arm64:  "aarch64",
            Architecture.ppc64_le: "ppc64le",
            Architecture.riscv64: "riscv64",
            Architecture.s390x:  "s390x",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by openSUSE")

        return a

    @classmethod
    def latest_snapshot(cls, config: Config) -> str:
        url = join_mirror(config.mirror or "https://download.opensuse.org", "history/latest")
        return curl(config, url).strip()

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        return package in ("kernel-default", "kernel-kvmsmall")


def fetch_gpgkeys(context: Context) -> list[Path]:
    files = set()

    for p in (context.sandbox_tree / "etc/zypp/repos.d").iterdir():
        for _, name, value in parse_ini(p):
            if name != "gpgkey":
                continue

            keys = value.splitlines()
            for key in keys:
                if key.startswith("file://"):
                    path = key.removeprefix("file://").lstrip("/")
                    if not (context.config.tools() / path).exists():
                        die(f"Local repository GPG key specified ({key}) but not found at /{path}")

                    files.add(context.config.tools() / path)
                elif key.startswith("https://") and context.config.repository_key_fetch:
                    (context.workspace / "keys").mkdir(parents=True, exist_ok=True)
                    curl(context.config, key, output_dir=context.workspace / "keys")
                    files.add(context.workspace / "keys" / Path(key).name)
                else:
                    die(
                        f"Remote repository GPG key specified ({key}) but RepositoryKeyFetch= is disabled",
                        hint="Enable RepositoryKeyFetch= or provide local keys",
                    )

    return sorted(files)


def fetch_gpgurls(context: Context, repourl: str) -> tuple[str, ...]:
    gpgurls = [f"{repourl}/repodata/repomd.xml.key"]

    with tempfile.TemporaryDirectory() as d:
        curl(context.config, f"{repourl}/repodata/repomd.xml", output_dir=Path(d))
        xml = (Path(d) / "repomd.xml").read_text()

    root = ElementTree.fromstring(xml)

    tags = root.find("{http://linux.duke.edu/metadata/repo}tags")
    if tags is None:
        die("repomd.xml missing <tags> element")

    for child in tags.iter("{http://linux.duke.edu/metadata/repo}content"):
        if child.text and child.text.startswith("gpg-pubkey"):
            gpgkey = child.text.partition("?")[0]
            gpgurls += [f"{repourl}{gpgkey}"]

    return tuple(gpgurls)
