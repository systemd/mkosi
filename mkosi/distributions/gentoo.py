# SPDX-License-Identifier: LGPL-2.1+

import logging
import os
import re
import urllib.parse
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import List, Optional

from mkosi.architecture import Architecture
from mkosi.distributions import DistributionInstaller
from mkosi.install import copy_path, flock
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
    jobs = os.cpu_count() or 1
    if sysroot is not None:
        target_root_mntp = "/tmp/mkosi-root"
        bwrap_params += ["--bind", state.root, target_root_mntp]
        root = Path(target_root_mntp)
    else:
        sysroot = state.root
        root = None

    emerge_default_opts = [
        "--buildpkg=y",
        "--usepkg=y",
        "--keep-going=y",
        f"--jobs={jobs}",
        f"--load-average={jobs+1}",
        "--nospinner",
        *([f"--root={root}"] if root else []),
    ]
    if ARG_DEBUG.get():
        emerge_default_opts += ["--verbose", "--quiet=n", "--quiet-fail=n"]
    else:
        emerge_default_opts += ["--quiet-build", "--quiet"]
    cmd = ["emerge", *pkgs, *emerge_default_opts, *opts, *actions]
    bwrap_params += [
        "--bind", state.cache / "binpkgs", "/var/cache/binpkgs",
        "--bind", state.cache / "distfiles", "/var/cache/distfiles",
        "--bind", state.cache / "repos", "/var/db/repos",
    ]
    run_workspace_command(sysroot, cmd, bwrap_params=bwrap_params,
                          network=True, env=env)


@dataclass
class GentooAtoms:
    stage2: List[str]
    bare_minimal: List[str]
    boot: List[str]
    system: List[str]


class Gentoo:
    arch_profile: Path
    arch: str
    emerge_vars: dict[str, str]
    portage_cfg_dir: Path
    root: Path
    stage3_cache: Path
    stage3_tar_path: Path
    pkgs: GentooAtoms = GentooAtoms(
        stage2=[
            "sys-apps/baselayout",
            "sys-apps/util-linux",
            "app-crypt/libb2",
        ],
        bare_minimal=[
            "app-alternatives/sh",
            "sys-apps/shadow",
            "app-admin/eselect",
            "net-misc/iputils",
            "sys-apps/coreutils",
            "sys-apps/portage",
        ],
        boot=[
            "sys-apps/systemd",
            "sys-kernel/dracut",
            "sys-kernel/gentoo-kernel-bin",
        ],
        system=["@system"]
    )

    EMERGE_UPDATE_OPTS = [
        "--update",
        "--changed-use",
        "--newuse",
        "--deep",
        "--with-bdeps=y",
        "--complete-graph-if-new-use=y",
        "--verbose-conflicts",
    ]

    portage_use_flags = [
        "initramfs",
        "symlink",  # for kernel
    ]

    # TODO: portage_features.add("ccache"), this shall expedite the builds
    portage_features = [
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
    ]

    @staticmethod
    def try_import_portage() -> dict[str, str]:
        NEED_PORTAGE_MSG = "You need portage(5) for Gentoo"
        PORTAGE_INSTALL_INSTRUCTIONS = """\
        # Following is known to work on most systemd-based systems:
        sudo tee /usr/lib/sysusers.d/acct-user-portage.conf > /dev/null <<- EOF
        # /usr/lib/sysusers.d/portage.conf
        u portage - "Portage system user" /var/lib/portage/home -
        EOF

        sudo systemd-sysusers --no-pager

        sudo install --owner=portage --group=portage --mode=0755 --directory /var/db/repos
        sudo install --owner=portage --group=portage --mode=0755 --directory /etc/portage/repos.conf
        sudo install --owner=portage --group=portage --mode=0755 --directory /var/cache/binpkgs

        sudo tee /etc/portage/repos.conf/eselect-repo.conf > /dev/null <<- EOF
        [gentoo]
        location = /var/db/repos/gentoo
        sync-type = git
        sync-uri = https://anongit.gentoo.org/git/repo/gentoo.git
        EOF

        git clone https://anongit.gentoo.org/git/proj/portage.git --depth=1
        cd portage
        tee setup.cfg > /dev/null <<- EOF
        [build_ext]
        portage-ext-modules=true
        EOF

        python setup.py build_ext --inplace --portage-ext-modules

        sudo python setup.py install

        sudo ln -s --relative \
            /var/db/repos/gentoo/profiles/default/linux/amd64/17.1/no-multilib/systemd/merged-usr \
            /etc/portage/make.profile
        """
        try:
            from portage.const import (  # type: ignore
                BINREPOS_CONF_FILE,
                EBUILD_SH_ENV_DIR,
                USER_CONFIG_PATH,
            )
        except ImportError as e:
            logging.warn(NEED_PORTAGE_MSG)
            logging.info(PORTAGE_INSTALL_INSTRUCTIONS)
            raise e

        return dict(ebuild_sh_env_dir=EBUILD_SH_ENV_DIR,
                    portage_cfg_dir=USER_CONFIG_PATH,
                    binrepos_conf_file=BINREPOS_CONF_FILE)

    @complete_step("Installing Gentoo…")
    def __init__(self, state: MkosiState) -> None:
        # TOCLEANUP: legacy namig, to be cleaned up
        self.state = state
        self.config = self.state.config
        self.root = self.state.root
        self.portage_consts = self.try_import_portage()

        from portage.package.ebuild.config import config as portage_cfg  # type: ignore

        self.portage_cfg = portage_cfg()

        PORTAGE_MISCONFIGURED_MSG = "Missing defaults for portage, bailing out"
        # we check for PORTDIR, but we could check for any other one
        if self.portage_cfg['PORTDIR'] is None:
            die(PORTAGE_MISCONFIGURED_MSG)

        self.arch, _ = state.installer.architecture(state.config.architecture)
        self.arch_profile = Path(f"default/linux/{self.arch}/{state.config.release}/no-multilib/systemd/merged-usr")
        self.get_current_stage3()

        self.portage_cfg_dir = self.stage3_cache / self.portage_consts["portage_cfg_dir"]

        self.emerge_vars = {
            "FEATURES": " ".join(self.portage_features),
            "USE": " ".join(self.portage_use_flags),
        }

        for d in ("binpkgs", "distfiles", "repos"):
            self.state.cache.joinpath(d).mkdir(exist_ok=True)

        self.fetch_fix_stage3()
        self.sync_profiles()
        self.get_snapshot_of_portage_tree()

        self.merge_system()

    def get_current_stage3(self) -> None:
        """usrmerge tracker bug: https://bugs.gentoo.org/690294"""

        # http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3.txt
        stage3tsf_path_url = urllib.parse.urljoin(
            self.portage_cfg["GENTOO_MIRRORS"].partition(" ")[0],
            f"releases/{self.arch}/autobuilds/latest-stage3.txt",
        )

        ###########################################################
        # GENTOO_UPSTREAM: wait for fix upstream:
        # https://bugs.gentoo.org/690294
        # and more... so we can gladly escape all this hideousness!
        ###########################################################
        with urllib.request.urlopen(stage3tsf_path_url) as r:
            # e.g.: 20230108T161708Z/stage3-amd64-nomultilib-systemd-mergedusr-20230108T161708Z.tar.xz
            regexp = rf"^[0-9]+T[0-9]+Z/stage3-{self.arch}-nomultilib-systemd-mergedusr-[0-9]+T[0-9]+Z\.tar\.xz"
            all_lines = r.readlines()
            for line in all_lines:
                if (m := re.match(regexp, line.decode("utf-8"))):
                    self.stage3_tar = Path(m.group(0))
                    break
            else:
                die("profile names changed upstream?")

        self.stage3_tar_path = self.state.cache_dir / self.stage3_tar
        self.stage3_cache = self.stage3_tar_path.with_name(self.stage3_tar.name).with_suffix(".tmp")

    def fetch_fix_stage3(self) -> None:
        stage3_url_path = urllib.parse.urljoin(
            self.portage_cfg["GENTOO_MIRRORS"],
            f"releases/{self.arch}/autobuilds/{self.stage3_tar}",
        )
        if not self.stage3_tar_path.is_file():
            log_step(f"Fetching {stage3_url_path}")
            self.stage3_tar_path.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(stage3_url_path, self.stage3_tar_path)

        self.stage3_cache.mkdir(parents=True, exist_ok=True)

        with flock(self.stage3_cache):
            if not self.stage3_cache.joinpath(".cache_isclean").exists():
                log_step(f"Extracting {self.stage3_tar.name} to {self.stage3_cache}")

                run([
                    "tar",
                    "--numeric-owner",
                    "-C", self.stage3_cache,
                    "--extract",
                    "--file", self.stage3_tar_path,
                    "--exclude", "./dev",
                ])

                unlink_try_hard(self.stage3_cache.joinpath("dev"))
                unlink_try_hard(self.stage3_cache.joinpath("proc"))
                unlink_try_hard(self.stage3_cache.joinpath("sys"))

                self.stage3_cache.joinpath(".cache_isclean").touch()

                self.set_useflags()
                self.mkosi_conf()

    def set_useflags(self) -> None:
        package_use = self.portage_cfg_dir / "package.use"
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
        if self.state.config.make_initrd:
            package_use.joinpath("minimal").write_text(
                dedent(
                    """\
                    # MKOSI
                    */* minimal
                    """
                )
            )

    def mkosi_conf(self) -> None:
        package_env = self.portage_cfg_dir / "package.env"
        package_env.mkdir(exist_ok=True)
        ebuild_sh_env_dir = self.stage3_cache / self.portage_consts["ebuild_sh_env_dir"]
        ebuild_sh_env_dir.mkdir(exist_ok=True)

        # apply whatever we put in mkosi_conf to runs invocation of emerge
        package_env.joinpath("mkosi.conf").write_text("*/*    mkosi.conf\n")

        # we use this so we don't need to touch upstream files.
        # we also use this for documenting build environment.
        emerge_vars_str = ""
        emerge_vars_str += "\n".join(f'{k}="${{{k}}} {v}"' for k, v in self.emerge_vars.items())

        ebuild_sh_env_dir.joinpath("mkosi.conf").write_text(
            dedent(
                f"""\
                # MKOSI: these were used during image creation...
                # and some more! see under package.*/
                {emerge_vars_str}
                """
            )
        )

        repos_cfg = self.stage3_cache / self.portage_consts["binrepos_conf_file"]
        with repos_cfg.open(mode='a') as f:
            for repo in self.config.repositories:
                f.write(
                    dedent(
                        f"""\
                        # MKOSI
                        [binhost]
                        sync-uri = {repo}
                        """
                    )
                )

    def sync_profiles(self) -> None:
        root_portage_cfg = self.root
        root_portage_cfg /= self.portage_cfg_dir.relative_to(self.stage3_cache)
        root_portage_cfg.mkdir(parents=True, exist_ok=True)
        copy_path(self.portage_cfg_dir, root_portage_cfg)

    def get_snapshot_of_portage_tree(self) -> None:
        bwrap_params: list[PathString] = ["--bind", self.state.cache / "repos", "/var/db/repos"]
        run_workspace_command(self.stage3_cache, ["/usr/bin/emerge-webrsync"],
                              bwrap_params=bwrap_params, network=True)

    def merge_system(self) -> None:
        opts = [
            "--with-bdeps=n",
            "--complete-graph-if-new-use=y",
            "--verbose-conflicts",
            "--changed-use",
            "--newuse",
        ]
        env = {}
        env.update(self.emerge_vars)
        env.update({"USE": f"{self.emerge_vars['USE']} build"})
        with complete_step("merging stage2"):
            invoke_emerge(self.state, sysroot=self.stage3_cache,
                          opts=opts+["--emptytree", "--nodeps"],
                          pkgs=self.pkgs.stage2, env=env)
        opts += ["--noreplace", "--root-deps=rdeps"]
        with complete_step("Merging bare minimal atoms"):
            invoke_emerge(self.state, sysroot=self.stage3_cache,
                          opts=opts+["--exclude", "sys-devel/*"],
                          pkgs=self.pkgs.bare_minimal, env=self.emerge_vars)
        with complete_step("Merging atoms required for boot"):
            invoke_emerge(self.state, sysroot=self.stage3_cache,
                          opts=opts+["--exclude", "sys-devel/*"],
                          pkgs=self.pkgs.boot)
        invoke_emerge(self.state, actions=["--config"],
                      pkgs=["sys-kernel/gentoo-kernel-bin"])
        if self.state.config.make_initrd:
            return

        invoke_emerge(self.state, sysroot=self.stage3_cache,
                      opts=opts+["--exclude", "sys-devel/*"],
                      pkgs=self.pkgs.system)


class GentooInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

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
        Gentoo(state)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_emerge(state, opts=["--noreplace"], pkgs=packages)

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
