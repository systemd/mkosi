# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import re
import shutil
import textwrap
from collections.abc import Sequence
from pathlib import Path

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.curl import curl
from mkosi.installer import PackageManager
from mkosi.log import ARG_DEBUG, complete_step
from mkosi.run import CompletedProcess, finalize_passwd_symlinks, run
from mkosi.sandbox import umask
from mkosi.util import _FILE, PathString

EMERGE_FEATURES = [
    "assume-digests",
    "binpkg-docompress",
    "binpkg-dostrip",
    "binpkg-logs",
    "binpkg-multi-instance",
    "buildpkg-live",
    "compress-index",
    "config-protect-if-modified",
    "distlocks",
    "ebuild-locks",
    "fixlafiles",
    "merge-sync",
    "merge-wait",
    "multilib-strict",
    "news",
    "parallel-fetch",
    "parallel-install",
    "pkgdir-index-trusted",
    "protect-owned",
    "qa-unresolved-soname-deps",
    "unknown-features-warn",
    "unmerge-logs",
    "unmerge-orphans",
    "-buildpkg-proactive",
    "-cgroup",
    "-ipc-sandbox",
    "-network-sandbox",
    "-pid-sandbox",
    "-preserve-libs",
    "-sandbox",
    "-strict",
    "-userfetch",
    "-userpriv",
    "-usersandbox",
    "-usersync",
    ]

FLATCAR_CHOST = {
    Architecture.x86_64: "x86_64-cros-linux-gnu",
    Architecture.arm64:  "aarch64-cros-linux-gnu",
}  # fmt: skip

FLATCAR_BOARD = {
    Architecture.x86_64: "amd64",
    Architecture.arm64:  "arm64",
}  # fmt: skip

# Where the ebuild repos are mounted inside the sandbox. This is the state_subdirs()
# location (metadata_dir/lib/portage/repos bound to /var/lib/portage/repos), not the
# /var/db/repos portage default — repos.conf and the profile symlinks point here.
REPOS_DIR = "/var/lib/portage/repos"

# Fallback parallelism when the CPU count can't be determined.
DEFAULT_NJOBS = 4


def _njobs() -> int:
    return os.cpu_count() or DEFAULT_NJOBS


def has_db_entry(path: Path, name: str) -> bool:
    """Whether a passwd/group-style file already has a line for the given user/group.

    Matches on a line-anchored "<name>:" prefix so a name can't be spuriously
    matched inside another entry's GECOS field or a longer username.
    """
    if not path.exists():
        return False
    prefix = f"{name}:"
    return any(line.startswith(prefix) for line in path.read_text().splitlines())


def _append_missing_entries(path: Path, entries: dict[str, str]) -> None:
    """Append passwd/group lines for any user/group not already present."""
    missing = [entry for name, entry in entries.items() if not has_db_entry(path, name)]
    if missing:
        with path.open("a") as f:
            f.write("".join(missing))


def _write_repos_conf(repos_conf_dir: Path, repos: Sequence[Path]) -> None:
    """Write a repos.conf/<name>.conf entry for each ebuild repository."""
    repos_conf_dir.mkdir(parents=True, exist_ok=True)
    for repo in repos:
        content = f"[{repo.name}]\nlocation = {REPOS_DIR}/{repo.name}\n"
        if repo.name == "portage-stable":
            content = f"[DEFAULT]\nmain-repo = {repo.name}\n\n" + content
        (repos_conf_dir / f"{repo.name}.conf").write_text(content)


def _symlink_profile(portage_dir: Path, target: str) -> None:
    """(Re)create the make.profile symlink pointing at a coreos profile."""
    profile = portage_dir / "make.profile"
    if profile.is_symlink():
        profile.unlink()
    profile.symlink_to(target)


class Emerge(PackageManager):
    @classmethod
    def executable(cls, config: Config) -> str:
        return "emerge"

    @classmethod
    def subdir(cls, config: Config) -> Path:
        return Path("portage")

    @classmethod
    def package_subdirs(cls, cache: Path) -> list[tuple[Path, Path]]:
        return [
            (Path("binpkgs"), Path("binpkgs")),
            (Path("distfiles"), Path("distfiles")),
        ]

    @classmethod
    def package_globs(cls) -> list[str]:
        return ["*.gpkg.tar", "*.tbz2", "*.xpak"]

    @classmethod
    def state_subdirs(cls) -> list[Path]:
        # The Flatcar ebuild repos are cloned into metadata_dir/lib/portage/repos
        # by the installer's setup() and mounted here at /var/lib/portage/repos.
        # repos.conf and the profile symlinks point portage at that location.
        return [Path("repos")]

    @classmethod
    def scripts(cls, context: Context) -> dict[str, list[PathString]]:
        return {
            "emerge":          cls.apivfs_script_cmd(context) + cls.env_cmd(context) + ["emerge"],
            "mkosi-install":   ["emerge", "--usepkgonly", "--getbinpkg"],
            "mkosi-upgrade":   ["emerge", "--usepkgonly", "--getbinpkg", "--update", "--deep", "--newuse"],
            "mkosi-remove":    ["emerge", "--depclean"],
            "mkosi-reinstall": ["emerge", "--usepkgonly", "--getbinpkg"],
        }  # fmt: skip

    @classmethod
    def setup(
        cls,
        context: Context,
        *,
        repos: Sequence[Path],
        binhost: str,
    ) -> None:
        # Some ebuilds (and autoconf-generated configure scripts) look up
        # `gtar` by name. Some distros don't provide the gtar->tar symlink
        if not context.config.find_binary("gtar"):
            gtar = context.sandbox_tree / "usr/bin/gtar"
            gtar.parent.mkdir(parents=True, exist_ok=True)
            gtar.write_text('#!/bin/sh\nexec tar "$@"\n')
            gtar.chmod(0o755)

        # Configure host/sandbox portage
        portage_dir = context.sandbox_tree / "etc/portage"
        portage_dir.mkdir(parents=True, exist_ok=True)

        njobs = _njobs()
        fetchcommand = r'FETCHCOMMAND="curl -Lo \"\${DISTDIR}/\${FILE}\" \"\${URI}\""'
        resumecommand = r'RESUMECOMMAND="curl -Lo \"\${DISTDIR}/\${FILE}\" \"\${URI}\""'
        # Use lbzip2 for parallel decompression of bzip2-compressed binary packages.
        bzip2_conf = ""
        if shutil.which("lbzip2"):
            bzip2_conf = 'PORTAGE_BZIP2_COMMAND="lbzip2"\nPORTAGE_BUNZIP2_COMMAND="lbzip2 -d"'

        (portage_dir / "make.conf").write_text(
            textwrap.dedent(
                f"""\
                # Generated by mkosi
                PORTAGE_TMPDIR="/var/tmp"
                PORT_LOGDIR="/var/tmp/portage-logs"

                PKGDIR="/var/cache/portage/binpkgs"
                DISTDIR="/var/cache/portage/distfiles"
                RPMDIR="/var/cache/portage/rpm"

                PORTAGE_BINHOST=" "
                PORTAGE_USERNAME="root"

                MAKEOPTS="--jobs={njobs} --load-average={njobs}"
                FEATURES="{' '.join(EMERGE_FEATURES)}"

                {fetchcommand}
                {resumecommand}
                {bzip2_conf}
                """
            )
        )

        # The SDK profile is amd64-only regardless of the target board — the
        # cross-toolchain that builds arm64 packages still runs on the amd64 SDK.
        _symlink_profile(portage_dir, f"{REPOS_DIR}/coreos-overlay/profiles/coreos/amd64/sdk")
        _write_repos_conf(portage_dir / "repos.conf", repos)

        chost = FLATCAR_CHOST.get(context.config.architecture)
        board = FLATCAR_BOARD.get(context.config.architecture)

        # configure portage in the buildroot (target)
        target_portage_dir = context.root / "etc/portage"
        target_portage_dir.mkdir(parents=True, exist_ok=True)
        (target_portage_dir / "make.conf").write_text(
            textwrap.dedent(
                f"""\
                # Generated by mkosi
                CBUILD="x86_64-pc-linux-gnu"
                CHOST="{chost}"
                HOSTCC="x86_64-pc-linux-gnu-gcc"

                ROOT="/buildroot"
                PORT_LOGDIR="/buildroot/var/log/portage"
                PORTAGE_TMPDIR="/buildroot/var/tmp"

                EMERGE_DEFAULT_OPTS="--oneshot --verbose"
                PORTAGE_USERNAME="root"

                PORTAGE_BINHOST=" {binhost}"

                GENERATE_SLSA_PROVENANCE="true"
                MAKEOPTS="--jobs={njobs} --load-average={njobs}"

                PKGDIR="/var/cache/portage/binpkgs"
                DISTDIR="/var/cache/portage/distfiles"
                RPMDIR="/var/cache/portage/rpm"

                FEATURES="{' '.join(EMERGE_FEATURES)}"

                {fetchcommand}
                {resumecommand}
                {bzip2_conf}
                """
            )
        )

        _symlink_profile(
            target_portage_dir,
            f"{REPOS_DIR}/coreos-overlay/profiles/coreos/{board}/generic",
        )
        _write_repos_conf(target_portage_dir / "repos.conf", repos)

    @classmethod
    def _ensure_portage_user_in_root(cls, context: Context) -> None:
        """Ensure portage user/group exist in the sysroot's passwd/group files.

        Since the sandbox symlinks /etc/passwd -> /buildroot/etc/passwd, portage
        resolves users from the sysroot — not the sandbox_tree. We must ensure
        the portage entries are present there too.
        """
        etc_dir = context.root / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)

        passwd = etc_dir / "passwd"
        _append_missing_entries(
            passwd,
            {
                "portage": "portage:x:250:250:portage:/var/tmp/portage:/bin/false\n",
                "root":    "root:x:0:0:root:/root:/bin/bash\n",
                "nobody":  "nobody:x:65534:65534:nobody:/:/bin/false\n",
            },
        )  # fmt: skip

        group = etc_dir / "group"
        _append_missing_entries(
            group,
            {
                "portage": "portage::250:portage\n",
                "root":    "root:x:0:\n",
                "nobody":  "nobody:x:65534:\n",
            },
        )  # fmt: skip

    @classmethod
    def options(cls, *, root: PathString, apivfs: bool = True) -> list[PathString]:
        # Always symlink passwd/group/shadow from the buildroot, even without apivfs.
        # Portage runs chown/chgrp during pkg_preinst using users/groups that were created
        # by earlier packages in the sysroot. Without these symlinks, the sandbox's /etc/passwd
        # doesn't contain those entries and chown fails.
        return [
            *super().options(root=root, apivfs=apivfs),
            *(finalize_passwd_symlinks("/buildroot") if not apivfs else []),
        ]

    @classmethod
    def finalize_environment(cls, context: Context) -> dict[str, str]:
        return super().finalize_environment(context) | {
            "PORTAGE_OVERRIDE_EPREFIX": "",
            "PORTAGE_CONFIGROOT": "/buildroot",
        }

    @classmethod
    def mounts(cls, context: Context) -> list[PathString]:
        mounts = [*super().mounts(context)]

        # Portage needs a writable /var/tmp on the host side for operations that run
        # outside of ROOT (e.g. pkg_setup, die_hooks), and /var/db for host-side package
        # tracking.
        mounts += [
            "--tmpfs", "/var/tmp",
            "--dir", "/var/db/pkg",
            "--dev", "/buildroot/dev",
            "--bind", "/proc", "/buildroot/proc",
        ]

        return mounts

    @classmethod
    def cmd(
        cls,
        context: Context,
        *,
        usepkgonly: bool = True,
    ) -> list[PathString]:
        njobs = _njobs()
        return [
            "emerge",
            "--root=/buildroot",
            "--sysroot=/buildroot",
            f"--jobs={njobs}",
            f"--load-average={njobs}",
            *(["--usepkgonly", "--getbinpkg"] if usepkgonly else []),
            "--ignore-built-slot-operator-deps=y",
            "--binpkg-changed-deps=n",
            "--with-bdeps=n",
            "--update",
            *(["--verbose", "--quiet=n"] if ARG_DEBUG.get() else ["--quiet-build", "--quiet"]),
            "--color", "y",
        ]  # fmt: skip

    @classmethod
    def invoke(
        cls,
        context: Context,
        arguments: Sequence[str] = (),
        *,
        apivfs: bool = False,
        usepkgonly: bool = True,
        stdout: _FILE = None,
    ) -> CompletedProcess:
        with umask(~0o755):
            # Directories inside the target sysroot (ROOT=/buildroot)
            (context.root / "var/tmp/portage").mkdir(parents=True, exist_ok=True)
            (context.root / "var/db/pkg").mkdir(parents=True, exist_ok=True)
            (context.root / "etc/portage").mkdir(parents=True, exist_ok=True)

            # Package cache directories (managed by mkosi's caching infrastructure,
            # mounted at /var/cache/portage/ by the base class)
            subdir = cls.subdir(context.config)
            cache_dir = context.config.package_cache_dir_or_default() / "cache" / subdir
            (cache_dir / "binpkgs").mkdir(parents=True, exist_ok=True)
            (cache_dir / "distfiles").mkdir(parents=True, exist_ok=True)
        cls._ensure_portage_user_in_root(context)

        return run(
            cls.cmd(context, usepkgonly=usepkgonly) + list(arguments),
            sandbox=cls.sandbox(context, apivfs=apivfs),
            env=cls.finalize_environment(context),
            stdout=stdout,
        )

    @classmethod
    def install(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        cls.invoke(
            context,
            [*packages],
            apivfs=apivfs,
        )

    @classmethod
    def sync(cls, context: Context, force: bool) -> None:
        # For Flatcar, repository sync is a no-op since we use pre-cloned repos
        # and binary packages from the bincache.
        pass

    @classmethod
    def generate_package_provided(cls, context: Context, binhost_url: str, output: Path) -> None:
        """
        Generate package.provided entries for ALL IDEPEND packages.

        When ROOT != /, portage resolves IDEPEND against the host (/). In a sandbox
        where the host is mostly read-only, this causes merge failures. By adding
        all IDEPEND packages to package.provided, portage treats them as already
        installed on the host and skips IDEPEND resolution entirely.
        """
        with complete_step("Generating package.provided for IDEPEND packages"):
            url = binhost_url.rstrip("/") + "/Packages"
            packages_data = curl(context.config, url)

            # Extract all IDEPEND cat/pn
            idepend_catpns: set[str] = set()
            for line in packages_data.splitlines():
                if line.startswith("IDEPEND: "):
                    for atom in line.removeprefix("IDEPEND: ").split():
                        if "/" in atom:
                            idepend_catpns.add(cls._atom_to_catpn(atom))

            # Provide ALL IDEPEND packages (mark them as installed on the host).
            # Use a synthetic high version (-999999999) so the provided entry
            # overrides any real version in the binhost — package.provided only
            # needs to satisfy the dependency, not match an exact CPV.
            provided = {f"{catpn}-999999999" for catpn in idepend_catpns}

            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("\n".join(sorted(provided)) + "\n")

    @staticmethod
    def _atom_to_catpn(atom: str) -> str:
        """Strip version operators, USE deps, and slot specs to get category/name."""
        # Strip leading version operators
        for prefix in (">=", "<=", "=", ">", "<", "~", "!!", "!"):
            atom = atom.removeprefix(prefix)

        # Strip trailing [use-deps] and :slot
        atom = atom.split("[")[0]
        atom = atom.split(":")[0]

        # Split into category/package-version and extract category/package
        cat, _, pnv = atom.partition("/")
        pn = pnv
        m = re.match(r"^(.*)-[0-9]", pnv)
        if m:
            pn = m.group(1)

        return f"{cat}/{pn}"
