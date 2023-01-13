# SPDX-License-Identifier: LGPL-2.1+

import os
from textwrap import dedent

from mkosi.backend import (
    MkosiPrinter,
    MkosiState,
    add_packages,
    complete_step,
    disable_pam_securetty,
    run,
    sort_packages,
)
from mkosi.distributions import DistributionInstaller
from mkosi.mounts import mount_api_vfs


class ArchInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> list[str]:
        return ["var/cache/pacman/pkg"]

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        return install_arch(state)


@complete_step("Installing Arch Linux…")
def install_arch(state: MkosiState) -> None:
    if state.config.release is not None:
        MkosiPrinter.info("Distribution release specification is not supported for Arch Linux, ignoring.")

    assert state.config.mirror

    if state.config.local_mirror:
        server = f"Server = {state.config.local_mirror}"
    else:
        if state.config.architecture == "aarch64":
            server = f"Server = {state.config.mirror}/$arch/$repo"
        else:
            server = f"Server = {state.config.mirror}/$repo/os/$arch"

    # Create base layout for pacman and pacman-key
    os.makedirs(state.root / "var/lib/pacman", 0o755, exist_ok=True)
    os.makedirs(state.root / "etc/pacman.d/gnupg", 0o755, exist_ok=True)

    # Permissions on these directories are all 0o777 because of 'mount --bind'
    # limitations but pacman expects them to be 0o755 so we fix them before
    # calling pacman (except /var/tmp which is 0o1777).
    fix_permissions_dirs = {
        "boot": 0o755,
        "etc": 0o755,
        "etc/pacman.d": 0o755,
        "var": 0o755,
        "var/lib": 0o755,
        "var/cache": 0o755,
        "var/cache/pacman": 0o755,
        "var/tmp": 0o1777,
        "run": 0o755,
    }

    for dir, permissions in fix_permissions_dirs.items():
        if (path := state.root / dir).exists():
            path.chmod(permissions)

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
                CacheDir = {state.root}/var/cache/pacman/pkg/
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

        if state.config.repositories:
            for repository in state.config.repositories:
                # repositories must be passed in the form <repo name>::<repo url>
                repository_name, repository_server = repository.split("::", 1)

                # note: for additional repositories, signature checking options are set to pacman's default values
                f.write(
                    dedent(
                        f"""\

                        [{repository_name}]
                        SigLevel = Optional TrustedOnly
                        Server = {repository_server}
                        """
                    )
                )

    packages: set[str] = set()
    add_packages(state.config, packages, "base")

    if not state.do_run_build_script and state.config.bootable:
        add_packages(state.config, packages, "dracut")

    packages.update(state.config.packages)

    official_kernel_packages = {
        "linux",
        "linux-lts",
        "linux-hardened",
        "linux-zen",
    }

    has_kernel_package = official_kernel_packages.intersection(state.config.packages)
    if not state.do_run_build_script and state.config.bootable and not has_kernel_package:
        # No user-specified kernel
        add_packages(state.config, packages, "linux")

    if state.do_run_build_script:
        packages.update(state.config.build_packages)

    if not state.do_run_build_script and state.config.ssh:
        add_packages(state.config, packages, "openssh")

    with mount_api_vfs(state.root):
        run(["pacman", "--config", pacman_conf, "--noconfirm", "-Sy", *sort_packages(packages)],
            env={"KERNEL_INSTALL_BYPASS": state.environment.get("KERNEL_INSTALL_BYPASS", "1")})

    state.root.joinpath("etc/pacman.d/mirrorlist").write_text(f"Server = {state.config.mirror}/$repo/os/$arch\n")

    # Arch still uses pam_securetty which prevents root login into
    # systemd-nspawn containers. See https://bugs.archlinux.org/task/45903.
    disable_pam_securetty(state.root)
