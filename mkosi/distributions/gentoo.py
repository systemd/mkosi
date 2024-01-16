# SPDX-License-Identifier: LGPL-2.1+

import os
import re
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path

from mkosi.archive import extract_tar
from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.log import ARG_DEBUG, complete_step, die
from mkosi.run import run
from mkosi.sandbox import apivfs_cmd, chroot_cmd
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString
from mkosi.util import sort_packages


def invoke_emerge(context: Context, packages: Sequence[str] = (), apivfs: bool = True) -> None:
    run(
        apivfs_cmd(context.root) + [
            # We can't mount the stage 3 /usr using `options`, because bwrap isn't available in the stage 3
            # tarball which is required by apivfs_cmd(), so we have to mount /usr from the tarball later
            # using another bwrap exec.
            "bwrap",
            "--dev-bind", "/", "/",
            "--bind", context.cache_dir / "stage3/usr", "/usr",
            "emerge",
            "--buildpkg=y",
            "--usepkg=y",
            "--getbinpkg=y",
            "--binpkg-respect-use=y",
            "--jobs",
            "--load-average",
            "--root-deps=rdeps",
            "--with-bdeps=n",
            "--verbose-conflicts",
            "--noreplace",
            *(["--verbose", "--quiet=n", "--quiet-fail=n"] if ARG_DEBUG.get() else ["--quiet-build", "--quiet"]),
            f"--root={context.root}",
            *sort_packages(packages),
        ],
        sandbox=context.sandbox(
            network=True,
            options=[
                # TODO: Get rid of as many of these as possible.
                "--bind", context.cache_dir / "stage3/etc", "/etc",
                "--bind", context.cache_dir / "stage3/var", "/var",
                "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
                "--bind", context.cache_dir / "repos", "/var/db/repos",
            ],
        ),
        env=dict(
            PKGDIR=str(context.cache_dir / "binpkgs"),
            DISTDIR=str(context.cache_dir / "distfiles"),
        ) | ({"USE": "build"} if not apivfs else {}) | context.config.environment,
    )


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "Gentoo"

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.ebuild

    @classmethod
    def default_release(cls) -> str:
        return "17.1"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.gentoo

    @classmethod
    def setup(cls, context: Context) -> None:
        pass

    @classmethod
    def install(cls, context: Context) -> None:
        arch = context.config.distribution.architecture(context.config.architecture)

        mirror = context.config.mirror or "https://distfiles.gentoo.org"
        # http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3.txt
        stage3tsf_path_url = join_mirror(
            mirror.partition(" ")[0],
            f"releases/{arch}/autobuilds/latest-stage3.txt",
        )

        with urllib.request.urlopen(stage3tsf_path_url) as r:
            # e.g.: 20230108T161708Z/stage3-amd64-nomultilib-systemd-mergedusr-20230108T161708Z.tar.xz
            regexp = rf"^[0-9]+T[0-9]+Z/stage3-{arch}-llvm-systemd-mergedusr-[0-9]+T[0-9]+Z\.tar\.xz"
            all_lines = r.readlines()
            for line in all_lines:
                if (m := re.match(regexp, line.decode("utf-8"))):
                    stage3_latest = Path(m.group(0))
                    break
            else:
                die("profile names changed upstream?")

        stage3_url = join_mirror(mirror, f"releases/{arch}/autobuilds/{stage3_latest}")
        stage3_tar = context.cache_dir / "stage3.tar"
        stage3 = context.cache_dir / "stage3"

        with complete_step("Fetching latest stage3 snapshot"):
            old = stage3_tar.stat().st_mtime if stage3_tar.exists() else 0

            cmd: list[PathString] = ["curl", "-L", "--progress-bar", "-o", stage3_tar, stage3_url]
            if stage3_tar.exists():
                cmd += ["--time-cond", stage3_tar]

            run(cmd, sandbox=context.sandbox())

            if stage3_tar.stat().st_mtime > old:
                rmtree(stage3)

        stage3.mkdir(exist_ok=True)

        if not any(stage3.iterdir()):
            with complete_step(f"Extracting {stage3_tar.name} to {stage3}"):
                extract_tar(
                    stage3_tar, stage3,
                    tools=context.config.tools(),
                    sandbox=context.sandbox(options=["--bind", context.root, context.root]),
                )

        for d in ("binpkgs", "distfiles", "repos/gentoo"):
            (context.cache_dir / d).mkdir(parents=True, exist_ok=True)

        copy_tree(context.pkgmngr, stage3, preserve=False, use_subvolumes=context.config.use_subvolumes)

        features = " ".join([
            # Disable sandboxing in emerge because we already do it in mkosi.
            "-sandbox",
            "-pid-sandbox",
            "-ipc-sandbox",
            "-network-sandbox",
            "-userfetch",
            "-userpriv",
            "-usersandbox",
            "-usersync",
            "-ebuild-locks",
            "parallel-install",
            *(["noman", "nodoc", "noinfo"] if context.config.with_docs else []),
        ])

        # Setting FEATURES via the environment variable does not seem to apply to ebuilds in portage, so we
        # append to /etc/portage/make.conf instead.
        with (stage3 / "etc/portage/make.conf").open("a") as f:
            f.write(f"\nFEATURES=\"${{FEATURES}} {features}\"\n")

        chroot = chroot_cmd(
            stage3,
            options=["--bind", context.cache_dir / "repos", "/var/db/repos"],
        )

        run(chroot + ["emerge-webrsync"], sandbox=context.sandbox(network=True))

        invoke_emerge(context, packages=["sys-apps/baselayout"], apivfs=False)

    @classmethod
    def install_packages(cls, context: Context, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_emerge(context, packages=packages, apivfs=apivfs)

        for d in context.root.glob("usr/src/linux-*"):
            kver = d.name.removeprefix("linux-")
            kimg = d / {
                Architecture.x86_64: "arch/x86/boot/bzImage",
                Architecture.arm64: "arch/arm64/boot/Image.gz",
                Architecture.arm: "arch/arm/boot/zImage",
            }[context.config.architecture]
            vmlinuz = context.root / "usr/lib/modules" / kver / "vmlinuz"
            if not vmlinuz.exists() and not vmlinuz.is_symlink():
                vmlinuz.symlink_to(os.path.relpath(kimg, start=vmlinuz.parent))

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "amd64",
            Architecture.arm64  : "arm64",
            Architecture.arm    : "arm",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Gentoo")

        return a
