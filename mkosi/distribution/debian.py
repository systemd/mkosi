# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import cast

from mkosi.archive import extract_tar
from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distribution import Distribution, DistributionInstaller, PackageType, join_mirror
from mkosi.installer.apt import Apt, AptRepository
from mkosi.log import die
from mkosi.run import run, workdir
from mkosi.sandbox import umask


class Installer(DistributionInstaller, distribution=Distribution.debian):
    _default_release = "testing"
    _releasemap = {
        "11": ("11", "bullseye"),
        "bullseye": ("11", "bullseye"),
        "12": ("12", "bookworm"),
        "bookworm": ("12", "bookworm"),
        "13": ("13", "trixie"),
        "trixie": ("13", "trixie"),
        "14": ("14", "forky"),
        "forky": ("14", "forky"),
        "15": ("15", "duke"),
        "duke": ("15", "duke"),
        "sid": ("9999", "sid"),
        "stable": ("12", "stable"),
        "testing": ("13", "testing"),
        "unstable": ("9999", "sid"),
    }

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
    def package_manager(cls, config: Config) -> type[Apt]:
        return Apt

    @classmethod
    def repositories(cls, context: Context, for_image: bool = False) -> Iterable[AptRepository]:
        types = ("deb", "deb-src")
        components = ("main", *context.config.repositories)
        mirror = None if for_image else context.config.mirror
        snapshot = None if for_image else context.config.snapshot

        if context.config.local_mirror and not for_image:
            yield AptRepository(
                types=("deb",),
                url=context.config.local_mirror,
                suite=context.config.release,
                components=("main",),
                signedby=None,
            )
            return

        if mirror:
            pass
        elif snapshot:
            mirror = "https://snapshot.debian.org"
        else:
            mirror = "http://deb.debian.org"

        if snapshot:
            url = join_mirror(mirror, f"archive/debian/{snapshot}")
        else:
            url = join_mirror(mirror, "debian")

        signedby = Path("/usr/share/keyrings/debian-archive-keyring.gpg")

        yield AptRepository(
            types=types,
            url=url,
            suite=context.config.release,
            components=components,
            signedby=signedby,
        )

        # Debug repos are typically not mirrored.
        if snapshot:
            url = join_mirror(mirror, f"archive/debian-debug/{snapshot}")
        else:
            url = join_mirror(mirror, "debian-debug")

        yield AptRepository(
            types=types,
            url=url,
            suite=f"{context.config.release}-debug",
            components=components,
            signedby=signedby,
        )

        if context.config.release in ("unstable", "sid"):
            return

        if not snapshot:
            yield AptRepository(
                types=types,
                url=join_mirror(mirror, "debian"),
                suite=f"{context.config.release}-updates",
                components=components,
                signedby=signedby,
            )

        # Security updates repos are never mirrored.
        if snapshot:
            url = join_mirror(mirror, f"archive/debian-security/{snapshot}")
        else:
            url = join_mirror(mirror, "debian-security")

        yield AptRepository(
            types=types,
            url=url,
            suite=f"{context.config.release}-security",
            components=components,
            signedby=signedby,
        )

    @classmethod
    def setup(cls, context: Context) -> None:
        Apt.setup(context, list(cls.repositories(context)))

    @classmethod
    def install(cls, context: Context) -> None:
        # Instead of using debootstrap, we replicate its core functionality here. Because dpkg does not have
        # an option to delay running pre-install maintainer scripts when it installs a package, it's
        # impossible to use apt directly to bootstrap a Debian chroot since dpkg will try to run a maintainer
        # script which depends on some basic tool to be available in the chroot from a deb which hasn't been
        # unpacked yet, causing the script to fail. To avoid these issues, we have to extract all the
        # essential debs first, and only then run the maintainer scripts for them.

        # First, we set up merged usr.  This list is taken from
        # https://salsa.debian.org/installer-team/debootstrap/-/blob/master/functions#L1369.
        subdirs = ["bin", "sbin", "lib"] + {
            "amd64"       : ["lib32", "lib64", "libx32"],
            "i386"        : ["lib64", "libx32"],
            "mips"        : ["lib32", "lib64"],
            "mipsel"      : ["lib32", "lib64"],
            "mips64el"    : ["lib32", "lib64", "libo32"],
            "loong64"     : ["lib32", "lib64"],
            "powerpc"     : ["lib64"],
            "ppc64"       : ["lib32", "lib64"],
            "ppc64el"     : ["lib64"],
            "s390x"       : ["lib32"],
            "sparc"       : ["lib64"],
            "sparc64"     : ["lib32", "lib64"],
            "x32"         : ["lib32", "lib64", "libx32"],
        }.get(
            context.config.distribution.installer.architecture(context.config.architecture), []
        )  # fmt: skip

        with umask(~0o755):
            for d in subdirs:
                (context.root / d).symlink_to(f"usr/{d}")
                (context.root / f"usr/{d}").mkdir(parents=True, exist_ok=True)

        # Next, we invoke apt-get install to download all the essential packages. With
        # DPkg::Pre-Install-Pkgs, we specify a shell command that will receive the list of packages that will
        # be installed on stdin.  By configuring Debug::pkgDpkgPm=1, apt-get install will not actually
        # execute any dpkg commands, so all it does is download the essential debs and tell us their full in
        # the apt cache without actually installing them.
        with tempfile.NamedTemporaryFile(mode="r") as f:
            Apt.invoke(
                context,
                "install",
                [
                    "-oDebug::pkgDPkgPm=1",
                    f"-oDPkg::Pre-Install-Pkgs::=cat >{workdir(Path(f.name))}",
                    "?essential",
                    "base-files",
                ],
                options=["--bind", f.name, workdir(Path(f.name))],
            )

            essential = f.read().strip().splitlines()

        # Now, extract the debs to the chroot by first extracting the sources tar file out of the deb and
        # then extracting the tar file into the chroot.

        for deb in essential:
            # If a deb path is in the form of "/var/cache/apt/<deb>", we transform it to the corresponding
            # path in mkosi's package cache directory. If it's relative to /repository, we transform it to
            # the corresponding path in mkosi's local package repository. Otherwise, we use the path as is.
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
                    sandbox=context.sandbox(),
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
                    sandbox=context.sandbox,
                )

        # Finally, run apt to properly install packages in the chroot without having to worry that maintainer
        # scripts won't find basic tools that they depend on.

        cls.install_packages(
            context, [Path(deb).name.partition("_")[0].removesuffix(".deb") for deb in essential]
        )

        fixup_os_release(context)

    @classmethod
    def install_packages(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        super().install_packages(context, packages, apivfs=apivfs, allow_downgrade=allow_downgrade)

        if "apt" in packages:
            install_apt_sources(context, cls.repositories(context, for_image=True))

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.arm64:       "arm64",
            Architecture.arm:         "armhf",
            Architecture.alpha:       "alpha",
            Architecture.x86_64:      "amd64",
            Architecture.x86:         "i386",
            Architecture.ia64:        "ia64",
            Architecture.loongarch64: "loong64",
            Architecture.mips64_le:   "mips64el",
            Architecture.mips_le:     "mipsel",
            Architecture.parisc:      "hppa",
            Architecture.ppc64_le:    "ppc64el",
            Architecture.ppc64:       "ppc64",
            Architecture.riscv64:     "riscv64",
            Architecture.s390x:       "s390x",
            Architecture.s390:        "s390",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {arch} is not supported by {cls.pretty_name()}")

        return a

    @classmethod
    def latest_snapshot(cls, config: Config) -> str:
        url = join_mirror(config.mirror or "https://snapshot.debian.org", "mr/timestamp")
        return cast(str, json.loads(curl(config, url))["result"]["debian"][-1])

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        return package.startswith("linux-image-")


def install_apt_sources(context: Context, repos: Iterable[AptRepository]) -> None:
    sources = context.root / f"etc/apt/sources.list.d/{context.config.release}.sources"
    if not sources.exists():
        with umask(~0o755):
            sources.parent.mkdir(parents=True, exist_ok=True)
        with umask(~0o644), sources.open("w") as f:
            for repo in repos:
                f.write(str(repo))


def fixup_os_release(context: Context) -> None:
    if context.config.release not in ("unstable", "sid"):
        return

    # Debian being Debian means we need to special case handling os-release. Fix the content to actually
    # match what we are building, and set up a diversion so that dpkg doesn't overwrite it on package
    # updates.  Upstream bug report: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1008735.
    for candidate in ["etc/os-release", "usr/lib/os-release", "usr/lib/initrd-release"]:
        osrelease = context.root / candidate
        newosrelease = osrelease.with_suffix(".new")

        if not osrelease.is_file():
            continue

        if osrelease.is_symlink() and candidate != "etc/os-release":
            continue

        with osrelease.open("r") as old, newosrelease.open("w") as new:
            for line in old.readlines():
                if line.startswith("VERSION_CODENAME="):
                    new.write("VERSION_CODENAME=sid\n")
                else:
                    new.write(line)

        # On dpkg distributions we cannot simply overwrite /etc/os-release as it is owned by a package.  We
        # need to set up a diversion first, so that it is not overwritten by package updates.  We do this for
        # /etc/os-release as that will be overwritten on package updates and has precedence over
        # /usr/lib/os-release, and ignore the latter and assume that if an usr-only image is built then the
        # package manager will not run on it.
        if candidate == "etc/os-release":
            run(
                [
                    "dpkg-divert",
                    "--quiet",
                    "--root=/buildroot",
                    "--local",
                    "--add",
                    "--rename",
                    "--divert",
                    f"/{candidate}.dpkg",
                    f"/{candidate}",
                ],
                sandbox=context.sandbox(options=context.rootoptions()),
            )

        newosrelease.rename(osrelease)
