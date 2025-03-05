# SPDX-License-Identifier: LGPL-2.1-or-later

import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path
from xml.etree import ElementTree

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distributions import DistributionInstaller, PackageType, join_mirror
from mkosi.installer import PackageManager
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.installer.zypper import Zypper
from mkosi.log import die
from mkosi.mounts import finalize_certificate_mounts
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
    def grub_prefix(cls) -> str:
        return "grub2"

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        if config.find_binary("zypper"):
            return Zypper
        else:
            return Dnf

    @classmethod
    def setup(cls, context: Context) -> None:
        setup_rpm(context, dbbackend="ndb")

        zypper = context.config.find_binary("zypper")
        if zypper:
            Zypper.setup(context, list(cls.repositories(context)))
        else:
            Dnf.setup(context, list(cls.repositories(context)))

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
                    *packages,
                ],
                apivfs=apivfs,
            )  # fmt: skip
        else:
            Dnf.invoke(context, "install", packages, apivfs=apivfs)

    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        if context.config.find_binary("zypper"):
            Zypper.invoke(context, "remove", ["--clean-deps", *packages], apivfs=True)
        else:
            Dnf.invoke(context, "remove", packages, apivfs=True)

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(id="local-mirror", url=f"baseurl={context.config.local_mirror}", gpgurls=())
            return

        zypper = context.config.find_binary("zypper")
        mirror = context.config.mirror or "https://download.opensuse.org"

        if context.config.release == "tumbleweed" or context.config.release.isdigit():
            gpgkeys = tuple(
                p
                for key in ("RPM-GPG-KEY-openSUSE-Tumbleweed", "RPM-GPG-KEY-openSUSE")
                if (p := find_rpm_gpgkey(context, key, required=False))
            )

            if not gpgkeys and not context.config.repository_key_fetch:
                die(
                    "openSUSE GPG keys not found in /usr/share/distribution-gpg-keys",
                    hint="Make sure the distribution-gpg-keys package is installed",
                )

            if zypper and gpgkeys:
                run(
                    [
                        "rpm",
                        "--root=/buildroot",
                        "--import",
                        *(key.removeprefix("file://") for key in gpgkeys),
                    ],
                    sandbox=context.sandbox(
                        options=[
                            *context.rootoptions(),
                            *finalize_certificate_mounts(context.config),
                        ],
                    ),
                )  # fmt: skip

            if context.config.release == "tumbleweed":
                if context.config.architecture == Architecture.x86_64:
                    subdir = ""
                else:
                    subdir = f"ports/{cls.architecture(context.config.architecture)}"
            else:
                if context.config.architecture != Architecture.x86_64:
                    die(f"Old snapshots are only supported for x86-64 on {cls.pretty_name()}")

                subdir = f"history/{context.config.release}"

            for repo in ("oss", "non-oss"):
                url = join_mirror(mirror, f"{subdir}/tumbleweed/repo/{repo}")
                yield RpmRepository(
                    id=repo,
                    url=f"baseurl={url}",
                    gpgurls=gpgkeys or (fetch_gpgurls(context, url) if not zypper else ()),
                    enabled=repo == "oss",
                )

                if context.config.release == "tumbleweed":
                    for d in ("debug", "source"):
                        url = join_mirror(mirror, f"{subdir}/{d}/tumbleweed/repo/{repo}")
                        yield RpmRepository(
                            id=f"{repo}-{d}",
                            url=f"baseurl={url}",
                            gpgurls=gpgkeys or (fetch_gpgurls(context, url) if not zypper else ()),
                            enabled=False,
                        )

            if context.config.release == "tumbleweed":
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
            else:
                subdir = f"ports/{cls.architecture(context.config.architecture)}"

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

            if context.config.release in ("current", "stable", "leap"):
                url = join_mirror(mirror, f"{subdir}/update/openSUSE-current")
                yield RpmRepository(
                    id="oss-update",
                    url=f"baseurl={url}",
                    gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                )

                url = join_mirror(mirror, f"{subdir}/update/openSUSE-non-oss-current")
                yield RpmRepository(
                    id="non-oss-update",
                    url=f"baseurl={url}",
                    gpgurls=fetch_gpgurls(context, url) if not zypper else (),
                    enabled=False,
                )
            else:
                for repo in ("oss", "non-oss"):
                    url = join_mirror(mirror, f"{subdir}/update/{release}/{repo}")
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
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by openSUSE")

        return a


def fetch_gpgurls(context: Context, repourl: str) -> tuple[str, ...]:
    gpgurls = [f"{repourl}/repodata/repomd.xml.key"]

    with tempfile.TemporaryDirectory() as d:
        curl(context.config, f"{repourl}/repodata/repomd.xml", Path(d))
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
