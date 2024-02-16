# SPDX-License-Identifier: LGPL-2.1+

import subprocess
from pathlib import Path
from typing import NamedTuple, Optional

from mkosi.context import Context
from mkosi.run import run
from mkosi.types import PathString


class RpmRepository(NamedTuple):
    id: str
    url: str
    gpgurls: tuple[str, ...]
    enabled: bool = True
    sslcacert: Optional[Path] = None
    sslclientkey: Optional[Path] = None
    sslclientcert: Optional[Path] = None


def find_rpm_gpgkey(context: Context, key: str) -> Optional[str]:
    if gpgpath := next((context.config.tools() / "usr/share/distribution-gpg-keys").rglob(key), None):
        return ('/' / gpgpath.relative_to(context.config.tools())).as_uri()

    if gpgpath := next(Path(context.pkgmngr / "etc/pki/rpm-gpg").rglob(key), None):
        return ('/' / gpgpath.relative_to(context.pkgmngr)).as_uri()

    return None


def setup_rpm(context: Context, *, dbpath: str = "/usr/lib/sysimage/rpm") -> None:
    confdir = context.pkgmngr / "etc/rpm"
    confdir.mkdir(parents=True, exist_ok=True)
    if not (confdir / "macros.lang").exists() and context.config.locale:
        (confdir / "macros.lang").write_text(f"%_install_langs {context.config.locale}")

    if not (confdir / "macros.dbpath").exists():
        (confdir / "macros.dbpath").write_text(f"%_dbpath {dbpath}")

    plugindir = Path(run(["rpm", "--eval", "%{__plugindir}"],
                         sandbox=context.sandbox(), stdout=subprocess.PIPE).stdout.strip())
    if (plugindir := context.config.tools() / plugindir.relative_to("/")).exists():
        with (confdir / "macros.disable-plugins").open("w") as f:
            for plugin in plugindir.iterdir():
                f.write(f"%__transaction_{plugin.stem} %{{nil}}\n")


def rpm_cmd(context: Context) -> list[PathString]:
    return ["env", "HOME=/", "rpm", "--root", context.root]
