# SPDX-License-Identifier: LGPL-2.1+

import os
import re
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent
from typing import Optional

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
    sysroot: Optional[Path] = None,
    root: Optional[Path] = None,
    bwrap_params: list[PathString] = [],
    pkgs: Sequence[str] = (),
    actions: Sequence[str] = (),
    opts: Sequence[str] = (),
    env: dict[str, str] = {},
) -> None:
    thread_counts = (os.cpu_count() or 1) * 2  # * 2 for hyperthreading
    bwrap: list[PathString] = []
    if sysroot is not None:
        # This is the mount-point inside our sysroot where we mount root
        target_root_mntp = "/tmp/mkosi-root"
        bwrap += ["--bind", state.root, target_root_mntp]
        root = Path(target_root_mntp)
    else:
        sysroot = state.root
        root = None

    emerge_default_opts = [
        "--buildpkg=y",
        "--usepkg=y",
        "--keep-going=y",
        f"--jobs={thread_counts}",
        f"--load-average={thread_counts+1}",
        "--nospinner",
        *([f"--root={root}"] if root else []),
    ]
    if ARG_DEBUG.get():
        emerge_default_opts += ["--verbose", "--quiet=n", "--quiet-fail=n"]
    else:
        emerge_default_opts += ["--quiet-build", "--quiet"]
    cmd = ["emerge", *pkgs, *emerge_default_opts, *opts, *actions]
    bwrap += [
        "--bind", state.cache_dir / "binpkgs", "/var/cache/binpkgs",
        "--bind", state.cache_dir / "distfiles", "/var/cache/distfiles",
        "--bind", state.cache_dir / "repos", "/var/db/repos",
        *bwrap_params
    ]
    run_workspace_command(sysroot, cmd, bwrap_params=bwrap, network=True,
                          env=env)


class GentooInstaller(DistributionInstaller):
    stage3_cache: Path

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
        BINREPOS_CONF_FILE = Path("etc/portage/binrepos.conf")
        EBUILD_SH_ENV_DIR = Path("etc/portage/env")
        USER_CONFIG_PATH = Path("etc/portage")

        """usrmerge tracker bug: https://bugs.gentoo.org/690294"""

        gentoo_mirrors = "http://distfiles.gentoo.org"
        if state.config.mirror:
            gentoo_mirrors = state.config.mirror
        # http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3.txt
        stage3tsf_path_url = urllib.parse.urljoin(
            gentoo_mirrors.partition(" ")[0],
            f"releases/{arch}/autobuilds/latest-stage3.txt",
        )

        ###########################################################
        # GENTOO_UPSTREAM: wait for fix upstream:
        # https://bugs.gentoo.org/690294
        # and more... so we can gladly escape all this hideousness!
        ###########################################################
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
        cls.stage3_cache = stage3_tar_path.with_name(stage3_tar.name).with_suffix(".tmp")

        user_config_path = cls.stage3_cache / USER_CONFIG_PATH

        emerge_vars = {
            "FEATURES": " ".join([
                    # -user* are required for access to USER_CONFIG_PATH
                    "-userfetch",
                    "-userpriv",
                    "-usersync",
                    "-usersandbox",
                    "-sandbox",
                    "-pid-sandbox",  # for cross-compile scenarios
                    "-network-sandbox",
                    "parallel-install",
                    "getbinpkg",
                    "-candy",
                    "noman",
                    "nodoc",
                    "noinfo",
            ]),
            "USE": "initramfs symlink"
        }

        for d in ("binpkgs", "distfiles", "repos"):
            state.cache_dir.joinpath(d).mkdir(exist_ok=True)

        stage3_url_path = urllib.parse.urljoin(
            gentoo_mirrors, f"releases/{arch}/autobuilds/{stage3_tar}",
        )
        if not stage3_tar_path.is_file():
            log_step(f"Fetching {stage3_url_path}")
            stage3_tar_path.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(stage3_url_path, stage3_tar_path)

        cls.stage3_cache.mkdir(parents=True, exist_ok=True)

        log_step(f"Extracting {stage3_tar.name} to {cls.stage3_cache}")
        run([
            "tar",
            "--numeric-owner",
            "-C", cls.stage3_cache,
            "--extract",
            "--file", stage3_tar_path,
            "--exclude", "./dev",
        ])
        unlink_try_hard(cls.stage3_cache.joinpath("dev"))
        unlink_try_hard(cls.stage3_cache.joinpath("proc"))
        unlink_try_hard(cls.stage3_cache.joinpath("sys"))

        package_use = user_config_path / "package.use"
        package_use.mkdir(exist_ok=True)

        package_use.joinpath("systemd").write_text(
            # repart for usronly
            dedent(
                """\
                # MKOSI: used during the image creation
                # "/usr/lib/systemd/boot/efi": No such file or directory
                sys-apps/systemd gnuefi
                sys-apps/systemd -cgroup-hybrid
                sys-apps/systemd elfutils # for coredump

                sys-apps/systemd homed cryptsetup -pkcs11
                # See: https://bugs.gentoo.org/832167
                sys-auth/pambase homed

                # MKOSI: usronly
                sys-apps/systemd repart
                # MKOSI: make sure we're init (no openrc)
                sys-apps/systemd sysv-utils
                """
            )
        )
        if state.config.make_initrd:
            package_use.joinpath("minimal").write_text(
                dedent(
                    """\
                    # MKOSI
                    */* minimal
                    """
                )
            )

        package_env = user_config_path / "package.env"
        package_env.mkdir(exist_ok=True)
        ebuild_sh_env_dir = cls.stage3_cache / EBUILD_SH_ENV_DIR
        ebuild_sh_env_dir.mkdir(exist_ok=True)

        # apply whatever we put in mkosi_conf to runs invocation of emerge
        package_env.joinpath("mkosi.conf").write_text("*/*    mkosi.conf\n")

        # we use this so we don't need to touch upstream files.
        # we also use this for documenting build environment.
        emerge_vars_str = ""
        emerge_vars_str += "\n".join(f'{k}="${{{k}}} {v}"' for k, v in emerge_vars.items())

        ebuild_sh_env_dir.joinpath("mkosi.conf").write_text(
            dedent(
                f"""\
                # MKOSI: these were used during image creation...
                # and some more! see under package.*/
                {emerge_vars_str}
                """
            )
        )

        repos_cfg = cls.stage3_cache / BINREPOS_CONF_FILE
        with repos_cfg.open(mode='a') as f:
            for repo in state.config.repositories:
                f.write(
                    dedent(
                        f"""\
                        # MKOSI
                        [binhost]
                        sync-uri = {repo}
                        """
                    )
                )

        root_portage_cfg = state.root
        root_portage_cfg /= user_config_path.relative_to(cls.stage3_cache)
        root_portage_cfg.mkdir(parents=True, exist_ok=True)
        copy_path(user_config_path, root_portage_cfg)

        bwrap_params: list[PathString] = [
            "--bind", state.cache_dir / "repos", "/var/db/repos"
        ]
        run_workspace_command(cls.stage3_cache, ["/usr/bin/emerge-webrsync"],
                              bwrap_params=bwrap_params, network=True)

        opts = [
            "--with-bdeps=n",
            "--complete-graph-if-new-use=y",
            "--verbose-conflicts",
            "--changed-use",
            "--newuse",
        ]
        env = {}
        env.update(emerge_vars)
        env.update({"USE": f"{emerge_vars['USE']} build"})
        with complete_step("merging stage2"):
            invoke_emerge(state, sysroot=cls.stage3_cache, opts=opts+["--emptytree", "--nodeps"],
                          pkgs=["sys-apps/baselayout", "sys-apps/util-linux"], env=env)
        opts += ["--noreplace", "--root-deps=rdeps"]
        with complete_step("Merging bare minimal atoms"):
            invoke_emerge(state, sysroot=cls.stage3_cache, opts=opts+["--exclude", "sys-devel/*"],
                          pkgs=["app-shells/bash", "sys-apps/systemd"], env=emerge_vars)
        with complete_step("Merging atoms required for boot"):
            invoke_emerge(state, sysroot=cls.stage3_cache, opts=opts,
                          pkgs=["sys-kernel/gentoo-kernel-bin"])
        if state.config.make_initrd:
            return

        invoke_emerge(state, sysroot=cls.stage3_cache, opts=opts,
                      pkgs=["@system"])

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_emerge(state, opts=["--noreplace"], sysroot=cls.stage3_cache,
                      pkgs=packages)

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
