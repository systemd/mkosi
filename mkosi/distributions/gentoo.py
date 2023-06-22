# SPDX-License-Identifier: LGPL-2.1+

import re
import urllib.parse
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from textwrap import dedent

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
    sysroot: Path,
    packages: Sequence[str] = (),
    actions: Sequence[str] = (),
    options: Sequence[str] = (),
    env: dict[str, str] = {},
) -> None:
    # This is the mount-point inside our sysroot where we mount root
    run_workspace_command(
        sysroot,
        cmd=[
            "emerge",
            *packages,
            "--buildpkg=y",
            "--usepkg=y",
            "--keep-going=y",
            "--jobs",
            "--load-average",
            "--nospinner",
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
        env=env
    )


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
                    *(["noman", "nodoc", "noinfo"] if state.config.with_docs else []),
            ]),
            "USE": "initramfs minimal symlink"
        }
        arch = state.installer.architecture(state.config.architecture)

        assert state.config.mirror
        # http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3.txt
        stage3tsf_path_url = urllib.parse.urljoin(
            state.config.mirror.partition(" ")[0],
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

        stage3_url_path = urllib.parse.urljoin(
            state.config.mirror, f"releases/{arch}/autobuilds/{stage3_tar}",
        )

        cls.stage3_cache = state.cache_dir.joinpath("stage3")
        if not stage3_tar_path.is_file():
            if cls.stage3_cache.exists():
                log_step("New stage3 is available, removing the old one")
                unlink_try_hard(cls.stage3_cache)
            with complete_step(f"Fetching {stage3_url_path}"):
                stage3_tar_path.parent.mkdir(parents=True, exist_ok=True)
                urllib.request.urlretrieve(stage3_url_path, stage3_tar_path)
        cls.stage3_cache.mkdir(parents=True, exist_ok=True)
        if not cls.stage3_cache.joinpath(".cache_isclean").exists():
            with complete_step(f"Extracting {stage3_tar.name} to {cls.stage3_cache}"):
                run([
                    "tar",
                    "--numeric-owner",
                    "-C", cls.stage3_cache,
                    "--extract",
                    "--file", stage3_tar_path,
                    "--exclude", "./dev",
                    "--exclude", "./proc",
                ])

            cls.stage3_cache.joinpath(".cache_isclean").touch()

        for d in ("binpkgs", "distfiles", "repos"):
            state.cache_dir.joinpath(d).mkdir(exist_ok=True)

        config = state.pkgmngr / "etc/portage"

        package_use = config / "package.use"
        package_use.mkdir(parents=True, exist_ok=True)
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

        package_env = config / "package.env"
        package_env.mkdir(parents=True, exist_ok=True)
        # apply whatever we put in mkosi_conf to runs invocation of emerge
        package_env.joinpath("mkosi.conf").write_text("*/* mkosi.conf\n")

        if not (config / "binrepos.conf").exists():
            (config / "binrepos.conf").touch()
        with (config / "binrepos.conf").open(mode='a') as f:
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

        root_portage_cfg = state.root / "etc/portage"
        root_portage_cfg.mkdir(parents=True, exist_ok=True)
        copy_path(config, root_portage_cfg)
        copy_path(config, cls.stage3_cache / "etc/portage")

        bwrap_params: list[PathString] = [
            "--bind", state.cache_dir / "repos", "/var/db/repos"
        ]
        run_workspace_command(cls.stage3_cache, ["/usr/bin/emerge-webrsync"],
                              bwrap_params=bwrap_params, network=True)

        opts = [
            "--complete-graph-if-new-use=y",
            "--verbose-conflicts",
            "--changed-use",
            "--newuse",
            "--root-deps=rdeps",
            "--with-bdeps=n",
        ]
        with complete_step("Layingout basic filesystem"):
            invoke_emerge(state, sysroot=cls.stage3_cache,
                          options=opts+["--emptytree"],
                          packages=["sys-apps/baselayout"],
                          env={**emerge_vars, 'USE': 'build'})

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        invoke_emerge(state, options=["--noreplace"], sysroot=cls.stage3_cache,
                      packages=packages)

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
