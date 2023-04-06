# SPDX-License-Identifier: LGPL-2.1+

from collections.abc import Sequence
from textwrap import dedent

from mkosi.backend import MkosiState, add_packages, sort_packages
from mkosi.distributions import DistributionInstaller
from mkosi.log import complete_step
from mkosi.run import run_with_apivfs
from mkosi.types import PathString


class ArchInstaller(DistributionInstaller):
    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def install(cls, state: MkosiState) -> None:
        return install_arch(state)

    @classmethod
    def install_packages(cls, state: MkosiState, packages: Sequence[str]) -> None:
        return invoke_pacman(state, packages)


@complete_step("Installing Arch Linux…")
def install_arch(state: MkosiState) -> None:
    assert state.config.mirror

    if state.config.local_mirror:
        server = f"Server = {state.config.local_mirror}"
    else:
        if state.config.architecture == "aarch64":
            server = f"Server = {state.config.mirror}/$arch/$repo"
        else:
            server = f"Server = {state.config.mirror}/$repo/os/$arch"

    # Create base layout for pacman and pacman-key
    state.root.joinpath("var/lib/pacman").mkdir(mode=0o755, exist_ok=True, parents=True)

    pacman_conf = state.workspace / "pacman.conf"
    if state.config.repository_key_check:
        sig_level = "Required DatabaseOptional"
    else:
        # If we are using a single local mirror built on the fly there
        # will be no signatures
        sig_level = "Never"
    with pacman_conf.open("w") as f:
        f.write(
            dedent(
                f"""\
                [options]
                RootDir = {state.root}
                LogFile = /dev/null
                CacheDir = {state.cache}
                GPGDir = /etc/pacman.d/gnupg/
                HookDir = {state.root}/etc/pacman.d/hooks/
                HoldPkg = pacman glibc
                Architecture = {state.config.architecture}
                Color
                CheckSpace
                SigLevel = {sig_level}
                ParallelDownloads = 5

                [core]
                {server}
                """
            )
        )

        if not state.config.local_mirror:
            f.write(
                dedent(
                    f"""\

                    [extra]
                    {server}

                    [community]
                    {server}
                    """
                )
            )

        for d in state.config.repo_dirs:
            f.write(f"Include = {d}/*\n")

    packages = state.config.packages.copy()
    add_packages(state.config, packages, "filesystem")

    if state.config.bootable and not state.config.initrds:
        add_packages(state.config, packages, "dracut")

    official_kernel_packages = {
        "linux",
        "linux-lts",
        "linux-hardened",
        "linux-zen",
    }

    has_kernel_package = official_kernel_packages.intersection(state.config.packages)
    if state.config.bootable and not has_kernel_package:
        # No user-specified kernel
        add_packages(state.config, packages, "linux")

    if state.config.ssh:
        add_packages(state.config, packages, "openssh")

    invoke_pacman(state, packages)

    state.root.joinpath("etc/pacman.d/mirrorlist").write_text(f"Server = {state.config.mirror}/$repo/os/$arch\n")


def invoke_pacman(state: MkosiState, packages: Sequence[str]) -> None:
    cmdline: list[PathString] = [
        "pacman",
        "--config", state.workspace / "pacman.conf",
        "--noconfirm",
        "-Sy", *sort_packages(packages),
    ]

    if state.config.initrds:
        cmdline += ["--assume-installed", "initramfs"]

    run_with_apivfs(state, cmdline, env=dict(KERNEL_INSTALL_BYPASS="1"))
