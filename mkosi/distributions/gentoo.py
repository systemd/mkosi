# SPDX-License-Identifier: LGPL-2.1+

import re
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Mapping

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller
from mkosi.install import copy_path
from mkosi.log import ARG_DEBUG, complete_step, die
from mkosi.remove import unlink_try_hard
from mkosi.run import bwrap, chroot_cmd, run
from mkosi.state import MkosiState
from mkosi.types import PathString


def invoke_emerge(
    state: MkosiState,
    packages: Sequence[str] = (),
    options: Sequence[str] = (),
    env: Mapping[str, str] = {},
) -> None:
    bwrap(
        cmd=[
            "chroot",
            "emerge",
            *packages,
            "--update",
            "--deep",
            "--buildpkg=y",
            "--usepkg=y",
            "--keep-going=y",
            "--jobs",
            "--load-average",
            "--nospinner",
            "--root-deps=rdeps",
            "--with-bdeps=n",
            "--complete-graph-if-new-use=y",
            "--verbose-conflicts",
            "--changed-use",
            "--newuse",
            "--root=/tmp/mkosi-root",
            "--binpkg-respect-use",
            *(["--verbose", "--quiet=n", "--quiet-fail=n"] if ARG_DEBUG.get() else ["--quiet-build", "--quiet"]),
            *options,
        ],
        apivfs=state.cache_dir / "stage3",
        scripts=dict(
            chroot=chroot_cmd(
                root=state.cache_dir / "stage3",
                options=[
                    "--bind", state.root, "/tmp/mkosi-root",
                    "--bind", state.cache_dir / "binpkgs", "/var/cache/binpkgs",
                    "--bind", state.cache_dir / "distfiles", "/var/cache/distfiles",
                    "--bind", state.cache_dir / "repos", "/var/db/repos",
                ],
                network=True,
            ),
        ),
        env=dict(
            FEATURES=" ".join([
                "getbinpkg",
                "-candy",
                "parallel-install",
                *(["noman", "nodoc", "noinfo"] if state.config.with_docs else []),
            ]),
        ) | env | state.environment,
    )


class GentooInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @staticmethod
    def kernel_image(name: str, architecture: Architecture) -> Path:
        kimg_path = {
            Architecture.x86_64: "arch/x86/boot/bzImage",
            Architecture.arm64: "arch/arm64/boot/Image.gz",
            Architecture.arm: "arch/arm/boot/zImage",
        }[architecture]

        return Path(f"usr/src/linux-{name}") / kimg_path

    @classmethod
    def install(cls, state: MkosiState) -> None:
        arch = state.installer.architecture(state.config.architecture)

        assert state.config.mirror
        # http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3.txt
        stage3tsf_path_url = urllib.parse.urljoin(
            state.config.mirror.partition(" ")[0],
            f"releases/{arch}/autobuilds/latest-stage3.txt",
        )

        with urllib.request.urlopen(stage3tsf_path_url) as r:
            # e.g.: 20230108T161708Z/stage3-amd64-nomultilib-systemd-mergedusr-20230108T161708Z.tar.xz
            regexp = rf"^[0-9]+T[0-9]+Z/stage3-{arch}-nomultilib-systemd-mergedusr-[0-9]+T[0-9]+Z\.tar\.xz"
            all_lines = r.readlines()
            for line in all_lines:
                if (m := re.match(regexp, line.decode("utf-8"))):
                    stage3_latest = Path(m.group(0))
                    break
            else:
                die("profile names changed upstream?")

        stage3_url = urllib.parse.urljoin(state.config.mirror, f"releases/{arch}/autobuilds/{stage3_latest}")
        stage3_tar = state.cache_dir / "stage3.tar"
        stage3 = state.cache_dir / "stage3"

        with complete_step("Fetching latest stage3 snapshot"):
            old = stage3_tar.stat().st_mtime if stage3_tar.exists() else 0

            cmd: list[PathString] = ["curl", "-L", "--progress-bar", "-o", stage3_tar, stage3_url]
            if stage3_tar.exists():
                cmd += ["--time-cond", stage3_tar]

            run(cmd)

            if stage3_tar.stat().st_mtime > old:
                unlink_try_hard(stage3)

        stage3.mkdir(exist_ok=True)

        if not any(stage3.iterdir()):
            with complete_step(f"Extracting {stage3_tar.name} to {stage3}"):
                run(["tar",
                     "--numeric-owner",
                     "-C", stage3,
                     "--extract",
                     "--file", stage3_tar,
                     "--exclude", "./dev/*",
                     "--exclude", "./proc/*",
                     "--exclude", "./sys/*"])

        for d in ("binpkgs", "distfiles", "repos/gentoo"):
            (state.cache_dir / d).mkdir(parents=True, exist_ok=True)

        copy_path(state.pkgmngr, stage3, preserve_owner=False)

        bwrap(
            cmd=["chroot", "emerge-webrsync"],
            apivfs=stage3,
            scripts=dict(
                chroot=chroot_cmd(
                    stage3,
                    options=["--bind", state.cache_dir / "repos", "/var/db/repos"],
                    network=True,
                ),
            ),
        )

        invoke_emerge(state, packages=["sys-apps/baselayout"], env={"USE": "build"})

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_emerge(state, options=["--noreplace"], packages=packages)

    @staticmethod
    def architecture(arch: Architecture) -> str:
        a = {
            Architecture.x86_64 : "amd64",
            Architecture.arm64  : "arm64",
            Architecture.arm    : "arm",
        }.get(arch)

        if not a:
            die(f"Architecture {a} is not supported by Gentoo")

        return a
