# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple, Optional

from mkosi.run import run
from mkosi.state import MkosiState
from mkosi.tree import copy_tree, rmtree
from mkosi.types import PathString


class RpmRepository(NamedTuple):
    id: str
    url: str
    gpgurls: tuple[str, ...]
    enabled: bool = True
    sslcacert: Optional[Path] = None
    sslclientkey: Optional[Path] = None
    sslclientcert: Optional[Path] = None


def find_rpm_gpgkey(state: MkosiState, key: str, url: str) -> str:
    for gpgdir in ("usr/share/distribution-gpg-keys", "etc/pki/rpm-gpg"):
        for root in (state.pkgmngr, state.root, Path("/")):
            gpgpath = next((root / Path(gpgdir)).rglob(key), None)
            if gpgpath:
                return f"file://{gpgpath}"

    return url


def setup_rpm(state: MkosiState) -> None:
    macros = state.pkgmngr / "usr/lib/rpm/macros.d"
    macros.mkdir(parents=True, exist_ok=True)
    if not (macros / "macros.lang").exists() and state.config.locale:
        (macros / "macros.lang").write_text(f"%_install_langs {state.config.locale}")

    rpmplugindir = Path(run(["rpm", "--eval", "%{__plugindir}"], stdout=subprocess.PIPE).stdout.strip())
    if rpmplugindir.exists():
        with (macros / "macros.disable-plugins").open("w") as f:
            for plugin in rpmplugindir.iterdir():
                f.write(f"%__transaction_{plugin.stem} %{{nil}}\n")

    rpmconfigdir = Path(run(["rpm", "--eval", "%{_rpmconfigdir}"], stdout=subprocess.PIPE).stdout.strip())
    copy_tree(rpmconfigdir, state.pkgmngr / "usr/lib/rpm", clobber=False, use_subvolumes=state.config.use_subvolumes)


def fixup_rpmdb_location(root: Path) -> None:
    # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/ so it needs to be copied back in the
    # right location, otherwise the rpmdb will be broken. See: https://bugs.debian.org/1004863. We also
    # replace it with a symlink so that any further rpm operations immediately use the correct location.
    rpmdb_home = root / "root/.rpmdb"
    if not rpmdb_home.exists() or rpmdb_home.is_symlink():
        return

    # Take into account the new location in F36
    rpmdb = root / "usr/lib/sysimage/rpm"
    if not rpmdb.exists():
        rpmdb = root / "var/lib/rpm"
    rmtree(rpmdb)
    shutil.move(rpmdb_home, rpmdb)
    rpmdb_home.symlink_to(os.path.relpath(rpmdb, start=rpmdb_home.parent))


def rpm_cmd(state: MkosiState) -> list[PathString]:
    return ["env", "HOME=/", f"RPM_CONFIGDIR={state.pkgmngr / 'usr/lib/rpm'}", "rpm", "--root", state.root]
