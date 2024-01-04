# SPDX-License-Identifier: LGPL-2.1+

import shutil
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
from mkosi.run import run


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

        zypper = shutil.which("zypper")

        # If we need to use a local mirror, create a temporary repository definition
        # that doesn't get in the image, as it is valid only at image build time.
        if context.config.local_mirror:
            repos = [RpmRepository("local-mirror", f"baseurl={context.config.local_mirror}", ())]
        else:
            repos = [
                RpmRepository("repo-oss", f"baseurl={release_url}", fetch_gpgurls(release_url) if not zypper else ()),
            ]
            if updates_url is not None:
                repos += [
                    RpmRepository(
                        "repo-update",
                        f"baseurl={updates_url}",
                        fetch_gpgurls(updates_url) if not zypper else (),
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
        if shutil.which("zypper"):
            options = [
                "--download", "in-advance",
                "--recommends" if context.config.with_recommends else "--no-recommends",
            ]
            invoke_zypper(context, "install", packages, options, apivfs=apivfs)
        else:
            invoke_dnf(context, "install", packages, apivfs=apivfs)

        # Leap doesn't put its kernel images in /usr/lib/modules so copy them over if needed.
        for d in context.root.glob("boot/vmlinuz-*"):
            kver = d.name.removeprefix("vmlinuz-")
            vmlinuz = context.root / "usr/lib/modules" / kver / "vmlinuz"
            if not vmlinuz.exists():
                shutil.copy2(d, vmlinuz)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        if shutil.which("zypper"):
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


def fetch_gpgurls(repourl: str) -> tuple[str, ...]:
    gpgurls = [f"{repourl}/repodata/repomd.xml.key"]

    with tempfile.TemporaryDirectory() as d:
        run([
            "curl",
            "--location",
            "--output-dir", d,
            "--remote-name",
            "--no-progress-meter",
            "--fail",
            f"{repourl}/repodata/repomd.xml",
        ])
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
