# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Sequence
from pathlib import Path

from mkosi.archive import extract_tar
from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.distribution import Distribution, DistributionInstaller, PackageType
from mkosi.installer import PackageManager
from mkosi.installer.emerge import Emerge, has_db_entry
from mkosi.log import complete_step, die
from mkosi.tree import rmtree
from mkosi.util import copyfile2

# Default bincache URL pattern for Flatcar nightly builds.
FLATCAR_BINCACHE_URL = "https://bincache.flatcar-linux.net/boards/{arch}/{release}/pkgs/"


class Installer(DistributionInstaller, distribution=Distribution.flatcar):
    @classmethod
    def pretty_name(cls) -> str:
        return "Flatcar Container Linux"

    @classmethod
    def filesystem(cls) -> str:
        return "ext4"

    @classmethod
    def grub_prefix(cls) -> str:
        return "flatcar/grub"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.none

    @classmethod
    def default_release(cls) -> str:
        return ""

    @classmethod
    def package_manager(cls, config: Config) -> type[PackageManager]:
        return Emerge

    @classmethod
    def setup(cls, context: Context) -> None:
        # Ensure ebuild repos are available before configuring portage
        cls.clone_repos(context)

        binhost = cls._binhost_url(context)

        repos_dir = cls._repos_dir(context)
        repos: list[Path] = []
        if repos_dir.exists():
            repos = sorted(p for p in repos_dir.iterdir() if p.is_dir())

        Emerge.setup(
            context,
            repos=repos,
            binhost=binhost,
        )

        provided_dir = context.sandbox_tree / "etc/portage/profile"
        provided_file = provided_dir / "package.provided"
        if not provided_file.exists():
            Emerge.generate_package_provided(context, binhost, provided_file)

    @classmethod
    def install(cls, context: Context) -> None:
        # Phase 1: Install baselayout (foundational filesystem layout)
        with complete_step("Installing baselayout"):
            Emerge.invoke(context, ["--nodeps", "sys-apps/baselayout"], apivfs=False)

        cls._set_lsb_release(context)
        cls._ensure_core_user(context)
        cls._fixup_kernel_location(context)

    @classmethod
    def _fixup_kernel_location(cls, context: Context) -> None:
        """Copy kernel images from Flatcar's /usr/boot/ to /usr/lib/modules/<kver>/.

        Flatcar installs the kernel to /usr/boot/vmlinuz-<kver> instead of the
        standard /boot/ or /usr/lib/modules/<kver>/ locations that mkosi expects."""
        usr_boot = context.root / "usr/boot"
        if not usr_boot.exists():
            return

        for kernel_type in ("vmlinuz", "vmlinux"):
            for src in usr_boot.glob(f"{kernel_type}-*"):
                if src.is_symlink():
                    continue
                kver = src.name.removeprefix(f"{kernel_type}-")
                dst = context.root / "usr/lib/modules" / kver / kernel_type
                if dst.exists():
                    continue
                dst.parent.mkdir(parents=True, exist_ok=True)
                copyfile2(src, dst)

    @classmethod
    def _ensure_core_user(cls, context: Context) -> None:
        """Ensure the 'core' user and group exist in the sysroot.

        Flatcar's default user is 'core' (UID/GID 500), created by baselayout's
        dumb-tmpfiles-proc.sh during pkg_preinst. With binary packages this may
        not run correctly, so we ensure the entries exist."""
        passwd = context.root / "etc/passwd"
        group = context.root / "etc/group"

        if passwd.exists() and not has_db_entry(passwd, "core"):
            with passwd.open("a") as f:
                f.write("core:x:500:500:CoreOS Admin:/home/core:/bin/bash\n")

        if group.exists() and not has_db_entry(group, "core"):
            with group.open("a") as f:
                f.write("core:x:500:\n")

    @classmethod
    def _set_lsb_release(cls, context: Context) -> None:
        # loosely inspired by build_library/set_lsb_release (Flatcar SDK)
        release = context.config.release or "unknown"
        # Extract version_id (e.g. "4669.0.0" from "4669.0.0+nightly-20260413-2100").
        # For releases without a "+" suffix, build_id intentionally mirrors the full
        # release string.
        version_id = release.split("+")[0] if "+" in release else release
        build_id = release.split("+")[1] if "+" in release else release

        board = cls._board(context.config.architecture)  # e.g. "amd64-usr"
        group = "developer"  # override as needed

        FLATCAR_OS_NAME = "Flatcar Container Linux by Kinvolk"
        FLATCAR_OS_ID_LIKE = "coreos"
        FLATCAR_OS_ID = "flatcar"
        FLATCAR_OS_HOME_URL = "https://flatcar.org"
        FLATCAR_OS_BUG_REPORT_URL = "https://issues.flatcar.org"
        FLATCAR_OS_SUPPORT_URL = "https://groups.google.com/forum/#!forum/flatcar-linux-user"
        FLATCAR_OS_PRETTY_NAME = f"{FLATCAR_OS_NAME} {release}"
        FLATCAR_APPID = "{e96281a6-d1af-4bde-9a0a-97b76e56dc57}"

        # --- /usr/share/flatcar/lsb-release (+ /etc/lsb-release symlink) ---
        # Upstream set_lsb_release also creates /etc/flatcar (drop-in dir for
        # coreos config); create it here so downstream tooling can rely on it.
        (context.root / "etc/flatcar").mkdir(parents=True, exist_ok=True)

        lsb_release = context.root / "usr/share/flatcar/lsb-release"
        lsb_release.parent.mkdir(parents=True, exist_ok=True)
        lsb_release.write_text(
            f'DISTRIB_ID="{FLATCAR_OS_NAME}"\n'
            f"DISTRIB_RELEASE={release}\n"
            f'DISTRIB_DESCRIPTION="{FLATCAR_OS_PRETTY_NAME}"\n'
        )

        etc_lsb_release = context.root / "etc/lsb-release"
        if not etc_lsb_release.exists():
            etc_lsb_release.parent.mkdir(parents=True, exist_ok=True)
            etc_lsb_release.symlink_to("../usr/share/flatcar/lsb-release")

        # --- /usr/lib/os-release (+ etc + /usr/share/flatcar symlinks) ---
        # https://www.freedesktop.org/software/systemd/man/os-release.html
        os_release = context.root / "usr/lib/os-release"
        os_release.parent.mkdir(parents=True, exist_ok=True)
        os_release.write_text(
            f'NAME="{FLATCAR_OS_NAME}"\n'
            f'ID="{FLATCAR_OS_ID}"\n'
            f'ID_LIKE="{FLATCAR_OS_ID_LIKE}"\n'
            f'VERSION="{release}"\n'
            f'VERSION_ID="{version_id}"\n'
            f'BUILD_ID="{build_id}"\n'
            f'SYSEXT_LEVEL="1.0"\n'
            f'PRETTY_NAME="{FLATCAR_OS_PRETTY_NAME}"\n'
            f'ANSI_COLOR="38;5;75"\n'
            f'HOME_URL="{FLATCAR_OS_HOME_URL}"\n'
            f'BUG_REPORT_URL="{FLATCAR_OS_BUG_REPORT_URL}"\n'
            f'SUPPORT_URL="{FLATCAR_OS_SUPPORT_URL}"\n'
            f'FLATCAR_BOARD="{board}"\n'
            f'CPE_NAME="cpe:2.3:o:{FLATCAR_OS_ID}-linux:{FLATCAR_OS_ID}_linux:{release}:*:*:*:*:*:*:*"\n'
        )

        etc_os_release = context.root / "etc/os-release"
        if not etc_os_release.exists():
            etc_os_release.parent.mkdir(parents=True, exist_ok=True)
            etc_os_release.symlink_to("../usr/lib/os-release")

        share_os_release = context.root / "usr/share/flatcar/os-release"
        if not share_os_release.exists():
            share_os_release.parent.mkdir(parents=True, exist_ok=True)
            share_os_release.symlink_to("../../lib/os-release")

        # Create the defaults for the coreos configuration files in the usr directory
        release_file = context.root / "usr/share/flatcar/release"
        release_file.parent.mkdir(parents=True, exist_ok=True)
        release_file.write_text(
            f"FLATCAR_RELEASE_VERSION={release}\n"
            f"FLATCAR_RELEASE_BOARD={board}\n"
            f"FLATCAR_RELEASE_APPID={FLATCAR_APPID}\n"
        )

        # update_engine settings
        update_conf = context.root / "usr/share/flatcar/update.conf"
        update_conf.parent.mkdir(parents=True, exist_ok=True)
        update_conf.write_text(
            "SERVER=https://public.update.flatcar-linux.net/v1/update/\n"
            f"GROUP={group}\n"
        )

    @classmethod
    def install_packages(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        Emerge.install(context, packages, apivfs=apivfs)
        cls._fixup_kernel_location(context)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "amd64",
            Architecture.arm64:  "arm64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {arch} is not supported by {cls.pretty_name()}")

        return a

    @classmethod
    def _board(cls, arch: Architecture) -> str:
        """Flatcar board name (e.g. 'amd64-usr'), as written to FLATCAR_BOARD.

        This is the architecture-derived board string with the '-usr' suffix
        Flatcar uses everywhere (os-release, release file, bincache paths) — not
        the bare arch name, and not the profile dir name (which is unsuffixed).
        """
        return f"{cls.architecture(arch)}-usr"

    @classmethod
    def is_kernel_package(cls, package: str) -> bool:
        return package.startswith("sys-kernel/")

    @classmethod
    def _binhost_url(cls, context: Context) -> str:
        """Resolve the binary package host URL."""
        if context.config.mirror:
            return context.config.mirror

        if not context.config.release:
            die(
                f"Release= must be set for {cls.pretty_name()}",
                hint="Set it to a Flatcar version string, e.g. '4643.0.0+nightly-20260318-2100'",
            )

        arch_board = cls._board(context.config.architecture)
        return FLATCAR_BINCACHE_URL.format(arch=arch_board, release=context.config.release)

    @classmethod
    def _repos_dir(cls, context: Context) -> Path:
        """Location of the cloned ebuild repos in the metadata dir.

        This is the state_subdirs() backing store (Emerge.subdir() == "portage",
        state subdir "repos"); the base class binds it into the sandbox at
        /var/lib/portage/repos.
        """
        subdir = Emerge.subdir(context.config)
        return context.metadata_dir / "lib" / subdir / "repos"

    @classmethod
    def clone_repos(cls, context: Context) -> None:
        """
        Fetch the Flatcar ebuild repositories (coreos-overlay, portage-stable)
        into the metadata directory for use during the build.
        """
        repos_dir = cls._repos_dir(context)

        if (repos_dir / "coreos-overlay").exists() and (repos_dir / "portage-stable").exists():
            return

        repos_dir.mkdir(parents=True, exist_ok=True)

        ref = cls._repo_ref(context)
        # /archive/<ref>.tar.gz resolves tags (releases), branches (the 'main'
        # fallback), and SHAs alike, so we don't need to know which kind it is.
        # Use the tarball (not the zip) so tar preserves the overlays' symlinks
        # (e.g. baselayout-3.6.8-r22.ebuild -> baselayout-9999.ebuild); Python's
        # zipfile writes symlinks out as plain files and portage then fails to
        # source them as ebuilds.
        url = f"https://github.com/flatcar/scripts/archive/{ref}.tar.gz"

        with complete_step(f"Downloading Flatcar ebuild repositories ({ref})"):
            # Use mkosi's canonical curl() so proxies, proxy certs and retries are
            # honoured. curl --remote-name lands the file as "<ref>.tar.gz".
            download_dir = repos_dir / ".download"
            if download_dir.exists():
                rmtree(download_dir)
            download_dir.mkdir(parents=True)
            curl(context.config, url, output_dir=download_dir)
            archive = download_dir / f"{ref}.tar.gz"

            # The archive's top-level dir is "scripts-<ref>/"; the repos live under
            # sdk_container/src/third_party/{coreos-overlay,portage-stable}. Extract
            # only those two subtrees, stripping the 4 leading path components so the
            # repos land directly in repos_dir/{coreos-overlay,portage-stable}.
            top = f"scripts-{ref}"
            third_party = f"{top}/sdk_container/src/third_party"
            extract_tar(
                archive,
                repos_dir,
                options=["--strip-components=4"],
                dirs=[f"{third_party}/coreos-overlay", f"{third_party}/portage-stable"],
            )

            rmtree(download_dir)

            # portage-stable's layout.conf doesn't declare masters — the Flatcar SDK
            # sets this dynamically. Patch it so portage doesn't complain.
            for repo_name, masters in (("portage-stable", "coreos-overlay"),):
                layout = repos_dir / repo_name / "metadata" / "layout.conf"
                if layout.exists() and "masters" not in layout.read_text():
                    with layout.open("a") as f:
                        f.write(f"masters = {masters}\n")

    @classmethod
    def _repo_ref(cls, context: Context) -> str:
        """Determine the git ref for the Flatcar scripts repo based on the release."""
        release = context.config.release
        if not release:
            return "main"

        # Flatcar git branches use hyphens, but release strings may contain '+' (e.g.
        # '4643.0.0+nightly-20260318-2100' -> branch 'main-4643.0.0-nightly-20260318-2100').
        return f"main-{release.replace('+', '-')}"
