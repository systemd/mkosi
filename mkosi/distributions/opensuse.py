# SPDX-License-Identifier: LGPL-2.1+

import shutil
from typing import List

from mkosi.backend import (
    MkosiState,
    PathString,
    add_packages,
    complete_step,
    patch_file,
    run,
    sort_packages,
)
from mkosi.distributions import DistributionInstaller
from mkosi.mounts import mount_api_vfs


class OpensuseInstaller(DistributionInstaller):
    @classmethod
    def cache_path(cls) -> List[str]:
        return ["var/cache/zypp/packages"]

    @classmethod
    def filesystem(cls) -> str:
        return "btrfs"

    @classmethod
    def install(cls, state: "MkosiState") -> None:
        return install_opensuse(state)


@complete_step("Installing openSUSE…")
def install_opensuse(state: MkosiState) -> None:
    release = state.config.release.strip('"')

    # If the release looks like a timestamp, it's Tumbleweed. 13.x is legacy (14.x won't ever appear). For
    # anything else, let's default to Leap.
    if release.isdigit() or release == "tumbleweed":
        release_url = f"{state.config.mirror}/tumbleweed/repo/oss/"
        updates_url = f"{state.config.mirror}/update/tumbleweed/"
    elif release == "leap":
        release_url = f"{state.config.mirror}/distribution/leap/15.1/repo/oss/"
        updates_url = f"{state.config.mirror}/update/leap/15.1/oss/"
    elif release == "current":
        release_url = f"{state.config.mirror}/distribution/openSUSE-stable/repo/oss/"
        updates_url = f"{state.config.mirror}/update/openSUSE-current/"
    elif release == "stable":
        release_url = f"{state.config.mirror}/distribution/openSUSE-stable/repo/oss/"
        updates_url = f"{state.config.mirror}/update/openSUSE-stable/"
    else:
        release_url = f"{state.config.mirror}/distribution/leap/{release}/repo/oss/"
        updates_url = f"{state.config.mirror}/update/leap/{release}/oss/"

    # state.configure the repositories: we need to enable packages caching here to make sure that the package cache
    # stays populated after "zypper install".
    run(["zypper", "--root", state.root, "addrepo", "-ck", release_url, "repo-oss"])
    run(["zypper", "--root", state.root, "addrepo", "-ck", updates_url, "repo-update"])

    # If we need to use a local mirror, create a temporary repository definition
    # that doesn't get in the image, as it is valid only at image build time.
    if state.config.local_mirror:
        run(["zypper", "--reposd-dir", state.workspace / "zypper-repos.d", "--root", state.root, "addrepo", "-ck", state.config.local_mirror, "local-mirror"])

    if not state.config.with_docs:
        state.root.joinpath("etc/zypp/zypp.conf").write_text("rpm.install.excludedocs = yes\n")

    packages = {*state.config.packages}
    add_packages(state.config, packages, "systemd", "glibc-locale-base", "zypper")

    if release.startswith("42."):
        add_packages(state.config, packages, "patterns-openSUSE-minimal_base")
    else:
        add_packages(state.config, packages, "patterns-base-minimal_base")

    if not state.do_run_build_script and state.config.bootable:
        add_packages(state.config, packages, "kernel-default", "dracut")

    if state.config.netdev:
        add_packages(state.config, packages, "systemd-network")

    if state.do_run_build_script:
        packages.update(state.config.build_packages)

    if not state.do_run_build_script and state.config.ssh:
        add_packages(state.config, packages, "openssh-server")

    cmdline: List[PathString] = ["zypper"]
    # --reposd-dir needs to be before the verb
    if state.config.local_mirror:
        cmdline += ["--reposd-dir", state.workspace / "zypper-repos.d"]
    cmdline += [
        "--root",
        state.root,
        "--gpg-auto-import-keys" if state.config.repository_key_check else "--no-gpg-checks",
        "install",
        "-y",
        "--no-recommends",
        "--download-in-advance",
        *sort_packages(packages),
    ]

    with mount_api_vfs(state.root):
        run(cmdline)

    # Disable package caching in the image that was enabled previously to populate the package cache.
    run(["zypper", "--root", state.root, "modifyrepo", "-K", "repo-oss"])
    run(["zypper", "--root", state.root, "modifyrepo", "-K", "repo-update"])

    if state.config.password == "":
        if not state.root.joinpath("etc/pam.d/common-auth").exists():
            for prefix in ("lib", "etc"):
                if state.root.joinpath(f"usr/{prefix}/pam.d/common-auth").exists():
                    shutil.copy2(state.root / f"usr/{prefix}/pam.d/common-auth", state.root / "etc/pam.d/common-auth")
                    break

        def jj(line: str) -> str:
            if "pam_unix.so" in line:
                return f"{line.strip()} nullok"
            return line

        patch_file(state.root / "etc/pam.d/common-auth", jj)

    if state.config.autologin:
        # copy now, patch later (in configure_autologin())
        if not state.root.joinpath("etc/pam.d/login").exists():
            for prefix in ("lib", "etc"):
                if state.root.joinpath(f"usr/{prefix}/pam.d/login").exists():
                    shutil.copy2(state.root / f"usr/{prefix}/pam.d/login", state.root / "etc/pam.d/login")
                    break
