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
from mkosi.log import ARG_DEBUG, complete_step, die, log_step
from mkosi.remove import unlink_try_hard
from mkosi.run import run, run_workspace_command
from mkosi.state import MkosiState
from mkosi.types import PathString


def invoke_emerge(
    state: MkosiState,
    packages: Sequence[str] = (),
    actions: Sequence[str] = (),
    options: Sequence[str] = (),
    env: Mapping[str, str] = {},
) -> None:
    print(f"{' '.join(state.config.repositories)}")
    run_workspace_command(
        state.cache_dir.joinpath("stage3"),
        cmd=[
            "emerge",
            *packages,
            "--update",
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
            f"--root={Path('/tmp/mkosi-root')}",
            *(["--verbose", "--quiet=n", "--quiet-fail=n"] if ARG_DEBUG.get() else ["--quiet-build", "--quiet"]),
            *options,
            *actions,
        ],
        bwrap_params=[
            "--bind", state.root, "/tmp/mkosi-root",
            "--bind", state.cache_dir / "binpkgs", "/var/cache/binpkgs",
            "--bind", state.cache_dir / "distfiles", "/var/cache/distfiles",
            "--bind", state.cache_dir / "repos", "/var/db/repos",
        ],
        network=True,
        env={
            'PORTAGE_BINHOST': ' '.join(state.config.repositories),
            'FEATURES': ' '.join([
                "getbinpkg",
                "-candy",
                'parallel-install',
                *(['noman', 'nodoc', 'noinfo'] if state.config.with_docs else []),
            ]),
            # gnuefi: for systemd
            # minimal: because we like minimals
            # initramfs, symlink for kernel
            'USE': 'gnuefi initramfs minimal symlink',
            **env,
        },
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
                    stage3_tar = Path(m.group(0))
                    break
            else:
                die("profile names changed upstream?")

        stage3_tar_path = state.cache_dir / stage3_tar

        stage3_url_path = urllib.parse.urljoin(
            state.config.mirror, f"releases/{arch}/autobuilds/{stage3_tar}",
        )

        stage3_cache = state.cache_dir.joinpath("stage3")

        config = stage3_cache / "etc/portage"
        vanilla_config = state.cache_dir / "vanilla-portage-config"
        vanilla_config.mkdir(exist_ok=True)
        pkgmngr_config = state.pkgmngr / "etc/portage"
        root_portage_cfg = state.root / "etc/portage"
        root_portage_cfg.mkdir(parents=True, exist_ok=True)

        if not stage3_tar_path.exists():
            if stage3_cache.exists():
                log_step('New stage3 is available , removing cache')
                unlink_try_hard(state.cache_dir.joinpath(stage3_tar).parent)
                unlink_try_hard(stage3_cache)
            if vanilla_config.exists():
                unlink_try_hard(vanilla_config)
            with complete_step(f"Fetching {stage3_url_path}"):
                stage3_tar_path.parent.mkdir(parents=True, exist_ok=True)
                urllib.request.urlretrieve(stage3_url_path, stage3_tar_path)
        stage3_cache.mkdir(parents=True, exist_ok=True)

        if next(stage3_cache.iterdir(), None) is None:
            with complete_step(f"Extracting {stage3_tar.name} to {stage3_cache}"):
                run([
                    "tar",
                    "--numeric-owner",
                    "-C", stage3_cache,
                    "--extract",
                    "--file", stage3_tar_path,
                    "--exclude", "./dev",
                    "--exclude", "./proc",
                ])
            copy_path(config, vanilla_config)

        # why can't we use --config-root or PORTAGE_CONFIGROOT via
        # invoke_emerge()?
        #
        # from emerge(1)
        # PORTAGE_CONFIGROOT is now superseded by the SYSROOT variable and
        # can only be given if its value matches SYSROOT or if ROOT=/.
        # Defaults to / .
        unlink_try_hard(config)
        if pkgmngr_config.exists():
            copy_path(pkgmngr_config, config)
        else:
            copy_path(vanilla_config, config)
        copy_path(config, root_portage_cfg)

        for d in ("binpkgs", "distfiles", "repos"):
            state.cache_dir.joinpath(d).mkdir(exist_ok=True)

        bwrap_params: list[PathString] = [
            "--bind", state.cache_dir / "repos", "/var/db/repos"
        ]
        run_workspace_command(stage3_cache, ["/usr/bin/emerge-webrsync"],
                              bwrap_params=bwrap_params, network=True)

        with complete_step("Layingout basic filesystem"):
            invoke_emerge(state, options=["--emptytree"],
                          packages=["sys-apps/baselayout"],
                          env={'USE': 'build'})

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
