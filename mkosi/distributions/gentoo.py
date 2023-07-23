# SPDX-License-Identifier: LGPL-2.1+

import os
import re
import textwrap
import urllib.request
from collections.abc import Sequence
from pathlib import Path

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller
from mkosi.log import ARG_DEBUG, complete_step, die
from mkosi.remove import unlink_try_hard
from mkosi.run import bwrap, run
from mkosi.state import MkosiState
from mkosi.types import PathString


def setup_emerge(state: MkosiState) -> None:
    # Set up a basic profile to trick emerge into proceeding (we don't care about the profile since we're
    # only installing binary packages). See https://bugs.gentoo.org/470006.
    make_profile = state.pkgmngr / "etc/portage/make.profile"
    make_profile.mkdir(parents=True, exist_ok=True)
    (make_profile / "make.defaults").write_text(
        textwrap.dedent(
            f"""\
            ARCH="{state.installer.architecture(state.config.architecture)}"
            ACCEPT_KEYWORDS="**"
            PORTAGE_USERNAME="root"
            PORTAGE_GRPNAME="root"
            PORTDIR="{state.cache_dir}"
            PKGDIR="{state.cache_dir / "binpkgs"}"
            """
        )
    )
    (make_profile / "parent").write_text("/var/empty")

    if state.config.mirror:
        (state.pkgmngr / "etc/portage/binrepos.conf").write_text(
            textwrap.dedent(
                f"""\
                [binhost]
                sync-uri = {state.config.mirror}
                priority = 10
                """
            )
        )


def invoke_emerge(state: MkosiState, packages: Sequence[str] = (), apivfs: bool = True) -> None:
    bwrap(
        cmd=[
            "emerge",
            "--tree",
            "--usepkgonly=y",
            "--getbinpkg=y",
            "--jobs",
            "--load-average",
            "--root-deps=rdeps",
            "--with-bdeps=n",
            "--verbose-conflicts",
            "--noreplace",
            *(["--verbose"] if ARG_DEBUG.get() else []),
            f"--root={state.root}",
            *packages,
        ],
        apivfs=state.root if apivfs else None,
        options=[
            # TODO: Get rid of as many of these as possible.
            "--bind", state.cache_dir / "stage3/usr", "/usr",
            # Bind /etc from the snapshot to get the /etc/portage mountpoint.
            "--bind", state.cache_dir / "stage3/etc", "/etc",
            "--bind", state.cache_dir / "stage3/var", "/var",
            "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
            "--bind", state.pkgmngr / "etc/portage", "/etc/portage",
        ],
        env=dict(PORTAGE_REPOSITORIES="") | state.config.environment,
    )


class GentooInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        arch = state.installer.architecture(state.config.architecture)

        assert state.config.mirror
        # http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3.txt
        stage3tsf_path_url = f"https://distfiles.gentoo.org/releases/{arch}/autobuilds/latest-stage3.txt"

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

        stage3_url = f"https://distfiles.gentoo.org/releases/{arch}/autobuilds/{stage3_latest}"
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

        setup_emerge(state)

        cls.install_packages(state, packages=["sys-apps/baselayout"], apivfs=False)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str], apivfs: bool = True) -> None:
        invoke_emerge(state, packages=packages, apivfs=apivfs)

        for d in state.root.glob("usr/src/linux-*"):
            kver = d.name.removeprefix("linux-")
            kimg = d / {
                Architecture.x86_64: "arch/x86/boot/bzImage",
                Architecture.arm64: "arch/arm64/boot/Image.gz",
                Architecture.arm: "arch/arm/boot/zImage",
            }[state.config.architecture]
            vmlinuz = state.root / "usr/lib/modules" / kver / "vmlinuz"
            if not vmlinuz.exists() and not vmlinuz.is_symlink():
                vmlinuz.symlink_to(os.path.relpath(kimg, start=vmlinuz.parent))

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
