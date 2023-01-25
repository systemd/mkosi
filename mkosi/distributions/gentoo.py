# SPDX-License-Identifier: LGPL-2.1+

import os
import re
import tarfile
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

from mkosi.backend import (
    ARG_DEBUG,
    MkosiException,
    MkosiPrinter,
    MkosiState,
    complete_step,
    die,
    run_workspace_command,
    safe_tar_extract,
)
from mkosi.distributions import DistributionInstaller
from mkosi.install import copy_path, flock
from mkosi.remove import unlink_try_hard

ARCHITECTURES = {
    "x86_64": ("amd64", "arch/x86/boot/bzImage"),
    # TODO:
    "aarch64": ("arm64", "arch/arm64/boot/Image.gz"),
    # TODO:
    "armv7l": ("arm", "arch/arm/boot/zImage"),
}


class Gentoo:
    arch_profile: Path
    arch: str
    custom_profile_path: Path
    DEFAULT_NSPAWN_PARAMS: list[str]
    ebuild_sh_env_dir: Path
    emerge_default_opts: list[str]
    emerge_vars: dict[str, str]
    portage_cfg_dir: Path
    profile_path: Path
    root: Path
    pkgs: dict[str, list[str]] = {}
    dracut_atom = "sys-kernel/dracut"

    EMERGE_UPDATE_OPTS = [
        "--update",
        "--tree",
        "--changed-use",
        "--newuse",
        "--deep",
        "--with-bdeps=y",
        "--complete-graph-if-new-use=y",
    ]

    portage_use_flags = [
        "initramfs",
        "git",  # for sync-type=git
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
        "buildpkg",
        "binpkg-multi-instance",
        "-binpkg-docompress",
        "getbinpkg",
        "-candy",
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
                CUSTOM_PROFILE_PATH,
                EBUILD_SH_ENV_DIR,
                PROFILE_PATH,
                USER_CONFIG_PATH,
            )
        except ImportError as e:
            MkosiPrinter.warn(NEED_PORTAGE_MSG)
            MkosiPrinter.info(PORTAGE_INSTALL_INSTRUCTIONS)
            raise MkosiException(e)

        return dict(profile_path=PROFILE_PATH,
                    custom_profile_path=CUSTOM_PROFILE_PATH,
                    ebuild_sh_env_dir=EBUILD_SH_ENV_DIR,
                    portage_cfg_dir=USER_CONFIG_PATH)

    @complete_step("Installing Gentoo…")
    def __init__(self, state: MkosiState) -> None:
        # TOCLEANUP: legacy namig, to be cleaned up
        self.state = state
        self.config = self.state.config
        self.root = self.state.root
        ret = self.try_import_portage()

        from portage.package.ebuild.config import config as portage_cfg  # type: ignore

        self.portage_cfg = portage_cfg(config_root=str(state.root),
                                       target_root=str(state.root),
                                       sysroot=str(state.root), eprefix=None)

        PORTAGE_MISCONFIGURED_MSG = "Missing defaults for portage, bailing out"
        # we check for PORTDIR, but we could check for any other one
        if self.portage_cfg['PORTDIR'] is None:
            die(PORTAGE_MISCONFIGURED_MSG)

        self.profile_path = state.root / ret["profile_path"]
        self.custom_profile_path = state.root / ret["custom_profile_path"]
        self.ebuild_sh_env_dir = state.root / ret["ebuild_sh_env_dir"]
        self.portage_cfg_dir = state.root / ret["portage_cfg_dir"]

        self.portage_cfg_dir.mkdir(parents=True, exist_ok=True)

        self.DEFAULT_NSPAWN_PARAMS = [
            "--capability=CAP_SYS_ADMIN,CAP_MKNOD",
            f"--bind={self.portage_cfg['PORTDIR']}",
            f"--bind={self.portage_cfg['DISTDIR']}",
            f"--bind={self.portage_cfg['PKGDIR']}",
        ]

        jobs = os.cpu_count() or 1
        self.emerge_default_opts = [
            "--buildpkg=y",
            "--usepkg=y",
            "--keep-going=y",
            f"--jobs={jobs}",
            f"--load-average={jobs+1}",
            "--nospinner",
        ]
        if "build-script" in ARG_DEBUG:
            self.emerge_default_opts += ["--verbose", "--quiet=n", "--quiet-fail=n"]
        else:
            self.emerge_default_opts += ["--quiet-build", "--quiet"]

        self.arch, _ = ARCHITECTURES[state.config.architecture or "x86_64"]
        self.arch_profile = Path(f"default/linux/{self.arch}/"
                                 f"{state.config.release}/no-multilib/systemd/merged-usr")
        self.pkgs['sys'] = ["@world"]

        self.pkgs['boot'] = [
            "sys-kernel/installkernel-systemd-boot",
            "sys-kernel/gentoo-kernel-bin",
        ]

        self.emerge_vars = {
            "FEATURES": " ".join(self.portage_features),
            "USE": " ".join(self.portage_use_flags),
        }

        self.sync_portage_tree()
        self.fetch_fix_stage3()
        self.set_default_repo()
        self.set_useflags()
        self.mkosi_conf()
        self.update_stage3()
        self.depclean()
        self.merge_user_pkgs()

    def sync_portage_tree(self) -> None:
        self.invoke_emerge(inside_stage3=False, actions=["--sync"])

    def fetch_fix_stage3(self) -> None:
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
                    stage3_tar = Path(m.group(0))
                    break
            else:
                die("profile names changed upstream?")

        stage3_url_path = urllib.parse.urljoin(
            self.portage_cfg["GENTOO_MIRRORS"],
            f"releases/{self.arch}/autobuilds/{stage3_tar}",
        )
        stage3_tar_path = self.portage_cfg["DISTDIR"] / stage3_tar
        stage3_tmp_extract = stage3_tar_path.with_name(stage3_tar.name + ".tmp")
        if not stage3_tar_path.is_file():
            MkosiPrinter.print_step(f"Fetching {stage3_url_path}")
            stage3_tar_path.parent.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(stage3_url_path, stage3_tar_path)

        stage3_tmp_extract.mkdir(parents=True, exist_ok=True)

        with flock(stage3_tmp_extract):
            if not stage3_tmp_extract.joinpath(".cache_isclean").exists():
                with tarfile.open(stage3_tar_path) as tfd:
                    MkosiPrinter.print_step(f"Extracting {stage3_tar.name} to "
                                            f"{stage3_tmp_extract}")
                    safe_tar_extract(tfd, stage3_tmp_extract, numeric_owner=True)

                unlink_try_hard(stage3_tmp_extract.joinpath("dev"))
                unlink_try_hard(stage3_tmp_extract.joinpath("proc"))
                unlink_try_hard(stage3_tmp_extract.joinpath("sys"))

                stage3_tmp_extract.joinpath(".cache_isclean").touch()

        MkosiPrinter.print_step(f"Copying {stage3_tmp_extract} to {self.root}")
        copy_path(stage3_tmp_extract, self.root)

    def set_default_repo(self) -> None:
        eselect_repo_conf = self.portage_cfg_dir / "repos.conf"
        eselect_repo_conf.mkdir(exist_ok=True)
        eselect_repo_conf.joinpath("eselect-repo.conf").write_text(
            dedent(
                f"""\
                [gentoo]
                location = {self.portage_cfg["PORTDIR"]}
                sync-uri = https://anongit.gentoo.org/git/repo/gentoo.git
                sync-type = git
                sync-dept = 1
                """
            )
        )

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

    def mkosi_conf(self) -> None:
        package_env = self.portage_cfg_dir / "package.env"
        package_env.mkdir(exist_ok=True)
        self.ebuild_sh_env_dir.mkdir(exist_ok=True)

        # apply whatever we put in mkosi_conf to runs invokation of emerge
        package_env.joinpath("mkosi.conf").write_text("*/*    mkosi.conf\n")

        # we use this so we don't need to touch upstream files.
        # we also use this for documenting build environment.
        emerge_vars_str = ""
        emerge_vars_str += "\n".join(f'{k}="${{{k}}} {v}"' for k, v in self.emerge_vars.items())

        self.ebuild_sh_env_dir.joinpath("mkosi.conf").write_text(
            dedent(
                f"""\
                # MKOSI: these were used during image creation...
                # and some more! see under package.*/
                {emerge_vars_str}
                """
            )
        )

    def update_stage3(self) -> None:
        self.invoke_emerge(opts=self.EMERGE_UPDATE_OPTS, pkgs=self.pkgs['boot'])
        self.invoke_emerge(opts=["--config"],
                           pkgs=["sys-kernel/gentoo-kernel-bin"])
        self.invoke_emerge(opts=self.EMERGE_UPDATE_OPTS,
                           pkgs=self.pkgs['sys'])

    def depclean(self) -> None:
        self.invoke_emerge(actions=["--depclean"])

    def merge_user_pkgs(self) -> None:
        if self.state.do_run_build_script:
            self.invoke_emerge(pkgs=self.state.config.build_packages)
        if self.state.config.packages:
            self.invoke_emerge(pkgs=self.state.config.packages, check=False)

    def invoke_emerge(
        self,
        check: bool = True,
        inside_stage3: bool = True,
        pkgs: Sequence[str] = (),
        actions: Sequence[str] = (),
        opts: Sequence[str] = (),
    ) -> None:
        if not inside_stage3:
            from _emerge.main import emerge_main  # type: ignore

            PREFIX_OPTS: list[str] = []
            if "--sync" not in actions:
                PREFIX_OPTS = [
                    f"--config-root={self.root.resolve()}",
                    f"--root={self.root.resolve()}",
                    f"--sysroot={self.root.resolve()}",
                ]

            MkosiPrinter.print_step(f"Invoking emerge(1) pkgs={pkgs} "
                                    f"actions={actions} outside stage3")
            emerge_main([*pkgs, *opts, *actions] + PREFIX_OPTS + self.emerge_default_opts)
        else:
            cmd = ["/usr/bin/emerge", *pkgs, *self.emerge_default_opts, *opts, *actions]

            MkosiPrinter.print_step("Invoking emerge(1) inside stage3"
                                    f"{self.root}")
            run_workspace_command(self.state, cmd, network=True, env=self.emerge_vars,
                                  nspawn_params=self.DEFAULT_NSPAWN_PARAMS,
                                  check=check)

    def _dbg(self, state: MkosiState) -> None:
        """this is for dropping into shell to see what's wrong"""

        cmd = ["/usr/bin/sh"]
        run_workspace_command(self.state, cmd, network=True,
                              nspawn_params=self.DEFAULT_NSPAWN_PARAMS)


class GentooInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> list[str]:
        return ["var/cache/binpkgs", "var/cache/distfiles"]

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @staticmethod
    def kernel_image(name: str, architecture: str) -> Path:
        _, kimg_path = ARCHITECTURES[architecture]
        return Path(f"usr/src/linux-{name}") / kimg_path

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        Gentoo(state)
