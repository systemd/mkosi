# SPDX-License-Identifier: LGPL-2.1+

import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path
from xml.etree import ElementTree

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType, join_mirror
from mkosi.installer import PackageManager
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.installer.zypper import Zypper
from mkosi.log import die
from mkosi.mounts import finalize_crypto_mounts
from mkosi.run import run
from mkosi.sandbox import Mount
from mkosi.util import listify, sort_packages


class Installer(DistributionInstaller):
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
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.opensuse

    @classmethod
    def grub_prefix(cls) -> str:
        return "grub2"

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        if config.find_binary("zypper"):
            return Zypper
        else:
            return Dnf

    @classmethod
    def createrepo(cls, context: Context) -> None:
        if context.config.find_binary("zypper"):
            Zypper.createrepo(context)
        else:
            Dnf.createrepo(context)

    @classmethod
    def setup(cls, context: Context) -> None:
        zypper = context.config.find_binary("zypper")
        if zypper:
            Zypper.setup(context, cls.repositories(context))
        else:
            Dnf.setup(context, cls.repositories(context))

        setup_rpm(context)

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        if context.config.find_binary("zypper"):
            Zypper.invoke(
                context,
                "install",
                [
                    "--download", "in-advance",
                    "--recommends" if context.config.with_recommends else "--no-recommends",
                    *sort_packages(packages),
                ],
                apivfs=apivfs)
        else:
            Dnf.invoke(context, "install", sort_packages(packages), apivfs=apivfs)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        if context.config.find_binary("zypper"):
            Zypper.invoke(context, "remove", ["--clean-deps", *sort_packages(packages)], apivfs=True)
        else:
            Dnf.invoke(context, "remove", packages, apivfs=True)

    @classmethod
    @listify
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(id="local-mirror", url=f"baseurl={context.config.local_mirror}", gpgurls=())
            return

        zypper = context.config.find_binary("zypper")
        mirror = context.config.mirror or "https://download.opensuse.org"

        if context.config.release == "tumbleweed" or context.config.release.isdigit():
            gpgurls = (
                *([p] if (p := find_rpm_gpgkey(context, key="RPM-GPG-KEY-openSUSE-Tumbleweed")) else []),
                *([p] if (p := find_rpm_gpgkey(context, key="RPM-GPG-KEY-openSUSE")) else []),
            )

            if context.config.release == "tumbleweed":
                subdir = "tumbleweed"
            else:
                subdir = f"history/{context.config.release}/tumbleweed"

            for repo in ("oss", "non-oss", "debug", "src-oss", "src-non-oss"):
                url = join_mirror(mirror, f"{subdir}/repo/{repo}")
                yield RpmRepository(
                    id=repo,
                    url=f"baseurl={url}",
                    gpgurls=gpgurls or (fetch_gpgurls(context, url) if not zypper else ()),
                    enabled=repo == "oss",
                )

            if context.config.release == "tumbleweed":
                url = join_mirror(mirror, "update/tumbleweed")
                yield RpmRepository(
                    id="oss-updates",
                    url=f"baseurl={url}",
                    gpgurls=gpgurls or (fetch_gpgurls(context, url) if not zypper else ()),
                    enabled=True,
                )

                url = join_mirror(mirror, "update/tumbleweed-non-oss")
                yield RpmRepository(
                    id="non-oss-updates",
                    url=f"baseurl={url}",
                    gpgurls=gpgurls or (fetch_gpgurls(context, url) if not zypper else ()),
                )
        else:
            if context.config.release in ("current", "stable", "leap"):
                subdir = "openSUSE-current"
            else:
                subdir = f"leap/{context.config.release}"

            for repo in ("oss", "non-oss"):
                url = join_mirror(mirror, f"distribution/{subdir}/repo/{repo}")
                yield RpmRepository(
                    id=repo,
                    url=f"baseurl={url}",
                    gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                    enabled=repo == "oss",
                )

            if context.config.release in ("current", "stable", "leap"):
                url = join_mirror(mirror, "update/openSUSE-current")
                yield RpmRepository(
                    id="oss-updates",
                    url=f"baseurl={url}",
                    gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                    enabled=True,
                )

                url = join_mirror(mirror, "update/openSUSE-non-oss-current")
                yield RpmRepository(
                    id="non-oss-updates",
                    url=f"baseurl={url}",
                    gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                )
            else:
                for repo in ("oss", "non-oss"):
                    url = join_mirror(mirror, f"update/{subdir}/{repo}")
                    yield RpmRepository(
                        id=repo,
                        url=f"baseurl={url}",
                        gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                        enabled=repo == "oss",
                    )

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by OpenSUSE")

        return a


def fetch_gpgurls(context: Context, repourl: str) -> tuple[str, ...]:
    gpgurls = [f"{repourl}/repodata/repomd.xml.key"]

    with tempfile.TemporaryDirectory() as d:
        run(
            [
                "curl",
                "--location",
                "--output-dir", d,
                "--remote-name",
                "--no-progress-meter",
                "--fail",
                *(["--proxy", context.config.proxy_url] if context.config.proxy_url else []),
                *(["--noproxy", ",".join(context.config.proxy_exclude)] if context.config.proxy_exclude else []),
                *(["--proxy-capath", "/proxy.cacert"] if context.config.proxy_peer_certificate else []),
                *(["--proxy-cert", "/proxy.clientcert"] if context.config.proxy_client_certificate else []),
                *(["--proxy-key", "/proxy.clientkey"] if context.config.proxy_client_key else []),
                f"{repourl}/repodata/repomd.xml",
            ],
            sandbox=context.sandbox(
                binary="curl",
                network=True,
                mounts=[Mount(d, d), *finalize_crypto_mounts(context.config)],
            ),
        )
        xml = (Path(d) / "repomd.xml").read_text()

    root = ElementTree.fromstring(xml)

    tags = root.find("{http://linux.duke.edu/metadata/repo}tags")
    if not tags:
        die("repomd.xml missing <tags> element")

    for child in tags.iter("{http://linux.duke.edu/metadata/repo}content"):
        if child.text and child.text.startswith("gpg-pubkey"):
            gpgkey = child.text.partition("?")[0]
            gpgurls += [f"{repourl}{gpgkey}"]

    return tuple(gpgurls)
