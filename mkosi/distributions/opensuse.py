# SPDX-License-Identifier: LGPL-2.1+

import tempfile
import xml.etree.ElementTree as ElementTree
from collections.abc import Sequence
from pathlib import Path

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer.dnf import invoke_dnf, setup_dnf
from mkosi.installer.rpm import RpmRepository
from mkosi.installer.zypper import invoke_zypper, setup_zypper
from mkosi.log import die
from mkosi.run import find_binary, run
from mkosi.sandbox import finalize_crypto_mounts


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
    def setup(cls, context: Context) -> None:
        release = context.config.release
        if release == "leap":
            release = "stable"

        mirror = context.config.mirror or "https://download.opensuse.org"

        # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy
        # (14.x won't ever appear). For anything else, let's default to Leap.
        if context.config.local_mirror:
            release_url = f"{context.config.local_mirror}"
            updates_url = None
        if release.isdigit() or release == "tumbleweed":
            release_url = f"{mirror}/tumbleweed/repo/oss/"
            updates_url = f"{mirror}/update/tumbleweed/"
        elif release in ("current", "stable"):
            release_url = f"{mirror}/distribution/openSUSE-{release}/repo/oss/"
            updates_url = f"{mirror}/update/openSUSE-{release}/"
        else:
            release_url = f"{mirror}/distribution/leap/{release}/repo/oss/"
            updates_url = f"{mirror}/update/leap/{release}/oss/"

        zypper = find_binary("zypper", root=context.config.tools())

        # If we need to use a local mirror, create a temporary repository definition
        # that doesn't get in the image, as it is valid only at image build time.
        if context.config.local_mirror:
            repos = [RpmRepository(id="local-mirror", url=f"baseurl={context.config.local_mirror}", gpgurls=())]
        else:
            repos = [
                RpmRepository(
                    id="repo-oss",
                    url=f"baseurl={release_url}",
                    gpgurls=fetch_gpgurls(context, release_url) if not zypper else (),
                ),
            ]
            if updates_url is not None:
                repos += [
                    RpmRepository(
                        id="repo-update",
                        url=f"baseurl={updates_url}",
                        gpgurls=fetch_gpgurls(context, updates_url) if not zypper else (),
                    )
                ]

        if zypper:
            setup_zypper(context, repos)
        else:
            setup_dnf(context, repos)

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem", "distribution-release"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        if find_binary("zypper", root=context.config.tools()):
            options = [
                "--download", "in-advance",
                "--recommends" if context.config.with_recommends else "--no-recommends",
            ]
            invoke_zypper(context, "install", packages, options, apivfs=apivfs)
        else:
            invoke_dnf(context, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        if find_binary("zypper", root=context.config.tools()):
            invoke_zypper(context, "remove", packages, ["--clean-deps"])
        else:
            invoke_dnf(context, "remove", packages)

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
                f"{repourl}/repodata/repomd.xml",
            ],
            sandbox=context.sandbox(
                network=True,
                options=["--bind", d, d, *finalize_crypto_mounts(context.config.tools())],
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
