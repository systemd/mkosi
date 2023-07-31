# SPDX-License-Identifier: LGPL-2.1+

import shutil
import urllib.request
import xml.etree.ElementTree as ElementTree
from collections.abc import Sequence

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller, PackageType
from mkosi.installer.dnf import Repo, invoke_dnf, setup_dnf
from mkosi.installer.zypper import invoke_zypper, setup_zypper
from mkosi.log import die
from mkosi.state import MkosiState


class OpensuseInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def install(cls, state: MkosiState) -> None:
        cls.install_packages(state, ["filesystem"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        release = state.config.release
        if release == "leap":
            release = "stable"

        # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy
        # (14.x won't ever appear). For anything else, let's default to Leap.
        if state.config.local_mirror:
            release_url = f"{state.config.local_mirror}"
            updates_url = None
        if release.isdigit() or release == "tumbleweed":
            release_url = f"{state.config.mirror}/tumbleweed/repo/oss/"
            updates_url = f"{state.config.mirror}/update/tumbleweed/"
        elif release in ("current", "stable"):
            release_url = f"{state.config.mirror}/distribution/openSUSE-{release}/repo/oss/"
            updates_url = f"{state.config.mirror}/update/openSUSE-{release}/"
        else:
            release_url = f"{state.config.mirror}/distribution/leap/{release}/repo/oss/"
            updates_url = f"{state.config.mirror}/update/leap/{release}/oss/"

        zypper = shutil.which("zypper")

        # If we need to use a local mirror, create a temporary repository definition
        # that doesn't get in the image, as it is valid only at image build time.
        if state.config.local_mirror:
            repos = [Repo("local-mirror", f"baseurl={state.config.local_mirror}", ())]
        else:
            repos = [Repo("repo-oss", f"baseurl={release_url}", fetch_gpgurls(release_url) if not zypper else ())]
            if updates_url is not None:
                repos += [Repo("repo-update", f"baseurl={updates_url}", fetch_gpgurls(updates_url) if not zypper else ())]

        if zypper:
            setup_zypper(state, repos)
            invoke_zypper(state, "install", packages, apivfs=apivfs)
        else:
            setup_dnf(state, repos)
            invoke_dnf(state, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        if shutil.which("zypper"):
            invoke_zypper(state, "remove", packages, ["--clean-deps"])
        else:
            invoke_dnf(state, "remove", packages)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "x86_64",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by OpenSUSE")

        return a


def fetch_gpgurls(repourl: str) -> tuple[str, ...]:
    gpgurls = [f"{repourl}/repodata/repomd.xml.key"]

    with urllib.request.urlopen(f"{repourl}/repodata/repomd.xml") as f:
        xml = f.read().decode()
        root = ElementTree.fromstring(xml)

        tags = root.find("{http://linux.duke.edu/metadata/repo}tags")
        if not tags:
            die("repomd.xml missing <tags> element")

        for child in tags.iter("{http://linux.duke.edu/metadata/repo}content"):
            if child.text and child.text.startswith("gpg-pubkey"):
                gpgkey = child.text.partition("?")[0]
                gpgurls += [f"{repourl}{gpgkey}"]

    return tuple(gpgurls)
