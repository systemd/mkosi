# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple, Optional

from mkosi.context import Context
from mkosi.run import run
from mkosi.tree import rmtree
from mkosi.types import PathString


class RpmRepository(NamedTuple):
    id: str
    url: str
    gpgurls: tuple[str, ...]
    gpgcheck: bool = True
    enabled: bool = True
    sslcacert: Optional[Path] = None
    sslclientkey: Optional[Path] = None
    sslclientcert: Optional[Path] = None
    metadata_expire: Optional[int] = None
    priority: Optional[int] = None


def find_rpm_gpgkey(context: Context, key: str, url: str) -> str:
    gpgpath = next((context.config.tools() / "usr/share/distribution-gpg-keys").rglob(key), None)
    if gpgpath:
        return f"file://{Path('/') / gpgpath.relative_to(context.config.tools())}"

    gpgpath = next(Path(context.pkgmngr / "etc/pki/rpm-gpg").rglob(key), None)
    if gpgpath:
        return f"file://{Path('/') / gpgpath.relative_to(context.pkgmngr)}"

    return url


def setup_rpm(context: Context) -> None:
    confdir = context.pkgmngr / "etc/rpm"
    confdir.mkdir(parents=True, exist_ok=True)
    if not (confdir / "macros.lang").exists() and context.config.locale:
        (confdir / "macros.lang").write_text(f"%_install_langs {context.config.locale}")

    plugindir = Path(run(["rpm", "--eval", "%{__plugindir}"],
                         sandbox=context.sandbox(), stdout=subprocess.PIPE).stdout.strip())
    if (plugindir := context.config.tools() / plugindir.relative_to("/")).exists():
        with (confdir / "macros.disable-plugins").open("w") as f:
            for plugin in plugindir.iterdir():
                f.write(f"%__transaction_{plugin.stem} %{{nil}}\n")


def fixup_rpmdb_location(context: Context) -> None:
    # On Debian, rpm/dnf ship with a patch to store the rpmdb under ~/ so it needs to be copied back in the
    # right location, otherwise the rpmdb will be broken. See: https://bugs.debian.org/1004863. We also
    # replace it with a symlink so that any further rpm operations immediately use the correct location.
    rpmdb_home = context.root / "root/.rpmdb"
    if not rpmdb_home.exists() or rpmdb_home.is_symlink():
        return

    # Take into account the new location in F36
    rpmdb = context.root / "usr/lib/sysimage/rpm"
    if not rpmdb.exists():
        rpmdb = context.root / "var/lib/rpm"
    rmtree(rpmdb, sandbox=context.sandbox(options=["--bind", rpmdb.parent, rpmdb.parent]))
    shutil.move(rpmdb_home, rpmdb)
    rpmdb_home.symlink_to(os.path.relpath(rpmdb, start=rpmdb_home.parent))


def rpm_cmd(context: Context) -> list[PathString]:
    return ["env", "HOME=/", "rpm", "--root", context.root]
