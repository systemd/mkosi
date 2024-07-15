# SPDX-License-Identifier: LGPL-2.1-or-later

import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.archive import extract_tar
from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.apt import Apt, AptRepository
from mkosi.log import die
from mkosi.run import run
from mkosi.sandbox import Mount
from mkosi.util import listify, umask


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Debian"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.deb

    @classmethod
    def default_release(cls) -> str:
        return "testing"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.debian

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        return Apt

    @staticmethod
    @listify
    def repositories(context: Context, local: bool = True) -> Iterable[AptRepository]:
        types = ("deb", "deb-src")
        components = ("main", *context.config.repositories)

        if context.config.local_mirror and local:
            yield AptRepository(
                types=("deb",),
                url=context.config.local_mirror,
                suite=context.config.release,
                components=("main",),
                signedby=None,
            )
            return

        mirror = context.config.mirror or "http://deb.debian.org/debian"
        signedby = Path("/usr/share/keyrings/debian-archive-keyring.gpg")

        yield AptRepository(
            types=types,
            url=mirror,
            suite=context.config.release,
            components=components,
            signedby=signedby,
        )

        # Debug repos are typically not mirrored.
        url = "http://deb.debian.org/debian-debug"

        yield AptRepository(
            types=types,
            url=url,
            suite=f"{context.config.release}-debug",
            components=components,
            signedby=signedby,
        )

        if context.config.release in ("unstable", "sid"):
            return

        yield AptRepository(
            types=types,
            url=mirror,
            suite=f"{context.config.release}-updates",
            components=components,
            signedby=signedby,
        )

        yield AptRepository(
            types=types,
            # Security updates repos are never mirrored.
            url="http://security.debian.org/debian-security",
            suite=f"{context.config.release}-security",
            components=components,
            signedby=signedby,
        )

    @classmethod
    def setup(cls, context: Context) -> None:
        Apt.setup(context, cls.repositories(context))

    @classmethod
    def install(cls, context: Context) -> None:
        # Instead of using debootstrap, we replicate its core functionality here. Because dpkg does not have
        # an option to delay running pre-install maintainer scripts when it installs a package, it's
        # impossible to use apt directly to bootstrap a Debian chroot since dpkg will try to run a maintainer
        # script which depends on some basic tool to be available in the chroot from a deb which hasn't been
        # unpacked yet, causing the script to fail. To avoid these issues, we have to extract all the
        # essential debs first, and only then run the maintainer scripts for them.

        # First, we set up merged usr.
        # This list is taken from https://salsa.debian.org/installer-team/debootstrap/-/blob/master/functions#L1369.
        subdirs = ["bin", "sbin", "lib"] + {
            "amd64"       : ["lib32", "lib64", "libx32"],
            "i386"        : ["lib64", "libx32"],
            "mips"        : ["lib32", "lib64"],
            "mipsel"      : ["lib32", "lib64"],
            "mips64el"    : ["lib32", "lib64", "libo32"],
            "loongarch64" : ["lib32", "lib64"],
            "powerpc"     : ["lib64"],
            "ppc64"       : ["lib32", "lib64"],
            "ppc64el"     : ["lib64"],
            "s390x"       : ["lib32"],
            "sparc"       : ["lib64"],
            "sparc64"     : ["lib32", "lib64"],
            "x32"         : ["lib32", "lib64", "libx32"],
        }.get(context.config.distribution.architecture(context.config.architecture), [])

        with umask(~0o755):
            for d in subdirs:
                (context.root / d).symlink_to(f"usr/{d}")
                (context.root / f"usr/{d}").mkdir(parents=True, exist_ok=True)

        # Next, we invoke apt-get install to download all the essential packages. With DPkg::Pre-Install-Pkgs,
        # we specify a shell command that will receive the list of packages that will be installed on stdin.
        # By configuring Debug::pkgDpkgPm=1, apt-get install will not actually execute any dpkg commands, so
        # all it does is download the essential debs and tell us their full in the apt cache without actually
        # installing them.
        with tempfile.NamedTemporaryFile(mode="r") as f:
            Apt.invoke(
                context,
                "install",
                [
                    "-oDebug::pkgDPkgPm=1",
                    f"-oDPkg::Pre-Install-Pkgs::=cat >{f.name}",
                    "?essential",
                    "?exact-name(usr-is-merged)",
                    "base-files",
                ],
                mounts=[Mount(f.name, f.name)],
            )

            essential = f.read().strip().splitlines()

        # Now, extract the debs to the chroot by first extracting the sources tar file out of the deb and
        # then extracting the tar file into the chroot.

        for deb in essential:
            # If a deb path is in the form of "/var/cache/apt/<deb>", we transform it to the corresponding path in
            # mkosi's package cache directory. If it's relative to /repository, we transform it to the corresponding
            # path in mkosi's local package repository. Otherwise, we use the path as is.
            if Path(deb).is_relative_to("/var/cache"):
                path = context.config.package_cache_dir_or_default() / Path(deb).relative_to("/var")
            elif Path(deb).is_relative_to("/repository"):
                path = context.repository / Path(deb).relative_to("/repository")
            else:
                path = Path(deb)

            with open(path, "rb") as i, tempfile.NamedTemporaryFile() as o:
                run(
                    ["dpkg-deb", "--fsys-tarfile", "/dev/stdin"],
                    stdin=i,
                    stdout=o,
                    sandbox=context.sandbox(binary="dpkg-deb"),
                )
                extract_tar(
                    Path(o.name),
                    context.root,
                    log=False,
                    options=(
                        [f"--exclude=./{glob}" for glob in Apt.documentation_exclude_globs]
                        if not context.config.with_docs
                        else []
                    ),
                    sandbox=context.sandbox
                )

        # Finally, run apt to properly install packages in the chroot without having to worry that maintainer
        # scripts won't find basic tools that they depend on.

        cls.install_packages(context, [Path(deb).name.partition("_")[0].removesuffix(".deb") for deb in essential])

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        # Debian policy is to start daemons by default. The policy-rc.d script can be used choose which ones to
        # start. Let's install one that denies all daemon startups.
        # See https://people.debian.org/~hmh/invokerc.d-policyrc.d-specification.txt for more information.
        # Note: despite writing in /usr/sbin, this file is not shipped by the OS and instead should be managed by
        # the admin.
        policyrcd = context.root / "usr/sbin/policy-rc.d"
        with umask(~0o755):
            policyrcd.parent.mkdir(parents=True, exist_ok=True)
        with umask(~0o644):
            policyrcd.write_text("#!/bin/sh\nexit 101\n")

        Apt.invoke(context, "install", packages, apivfs=apivfs)
        install_apt_sources(context, cls.repositories(context, local=False))

        policyrcd.unlink()

        # systemd-gpt-auto-generator is disabled by default in Ubuntu:
        # https://git.launchpad.net/ubuntu/+source/systemd/tree/debian/systemd.links?h=ubuntu/noble-proposed.
        # Let's make sure it is enabled by default in our images.
        (context.root / "etc/systemd/system-generators/systemd-gpt-auto-generator").unlink(missing_ok=True)


    @classmethod
    def remove_packages(cls, context: Context, packages: Sequence[str]) -> None:
        Apt.invoke(context, "purge", packages, apivfs=True)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm64       : "arm64",
            Architecture.arm         : "armhf",
            Architecture.alpha       : "alpha",
            Architecture.x86_64      : "amd64",
            Architecture.x86         : "i386",
            Architecture.ia64        : "ia64",
            Architecture.loongarch64 : "loongarch64",
            Architecture.mips64_le   : "mips64el",
            Architecture.mips_le     : "mipsel",
            Architecture.parisc      : "hppa",
            Architecture.ppc64_le    : "ppc64el",
            Architecture.ppc64       : "ppc64",
            Architecture.riscv64     : "riscv64",
            Architecture.s390x       : "s390x",
            Architecture.s390        : "s390",
        }.get(arch)

        if not a:
            die(f"Architecture {arch} is not supported by Debian")

        return a


def install_apt_sources(context: Context, repos: Iterable[AptRepository]) -> None:
    if not (context.root / "usr/bin/apt").exists():
        return

    sources = context.root / f"etc/apt/sources.list.d/{context.config.release}.sources"
    if not sources.exists():
        with sources.open("w") as f:
            for repo in repos:
                f.write(str(repo))
