# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import textwrap
from pathlib import Path
from typing import Literal, Optional, overload

from mkosi.context import Context
from mkosi.distributions import Distribution
from mkosi.log import die
from mkosi.util import PathString


@dataclasses.dataclass(frozen=True)
class RpmRepository:
    id: str
    url: str
    gpgurls: tuple[str, ...]
    enabled: bool = True
    sslcacert: Optional[Path] = None
    sslclientkey: Optional[Path] = None
    sslclientcert: Optional[Path] = None
    priority: Optional[int] = None


@overload
def find_rpm_gpgkey(
    context: Context,
    key: str,
    fallback: Optional[str] = None,
    *,
    required: Literal[True] = True,
) -> str: ...


@overload
def find_rpm_gpgkey(
    context: Context,
    key: str,
    fallback: Optional[str] = None,
    *,
    required: bool,
) -> Optional[str]: ...


def find_rpm_gpgkey(
    context: Context,
    key: str,
    fallback: Optional[str] = None,
    *,
    required: bool = True,
) -> Optional[str]:
    # We assume here that GPG keys will only ever be relative symlinks and never absolute symlinks.

    if gpgpath := next((context.config.tools() / "usr/share/distribution-gpg-keys").rglob(key), None):
        return (Path("/") / gpgpath.resolve().relative_to(context.config.tools())).as_uri()

    # ToolsTreeCertificates= only applies to certificates but the rpm gpg keys in /etc are located within the
    # /etc/pki certificates directory so as a result the option has to apply to the rpm gpg keys in /etc as
    # well
    root = context.config.tools() if context.config.tools_tree_certificates else Path("/")

    if gpgpath := next(Path(root / "etc/pki/rpm-gpg").rglob(key), None):
        return (Path("/") / gpgpath.resolve().relative_to(root)).as_uri()

    if fallback and context.config.repository_key_fetch:
        return fallback

    if required:
        die(
            f"{key} GPG key not found in /usr/share/distribution-gpg-keys or /etc/pki/rpm-gpg",
            hint="Make sure the distribution-gpg-keys package is installed",
        )

    return None


def setup_rpm(
    context: Context,
    *,
    dbpath: str = "/usr/lib/sysimage/rpm",
    dbbackend: Optional[str] = None,
) -> None:
    confdir = context.sandbox_tree / "etc/rpm"
    confdir.mkdir(parents=True, exist_ok=True)
    if not (confdir / "macros.lang").exists() and context.config.locale:
        (confdir / "macros.lang").write_text(f"%_install_langs {context.config.locale}")

    if not (confdir / "macros.dbpath").exists():
        (confdir / "macros.dbpath").write_text(f"%_dbpath {dbpath}")

    if dbbackend:
        (confdir / "macros.db_backend").write_text(f"%_db_backend {dbbackend}")

    if context.config.distribution == Distribution.opensuse or (
        context.config.distribution.is_centos_variant() and context.config.release == "9"
    ):
        # Write an rpm sequoia policy that makes sure "sha1.second_preimage_resistance = always" is
        # configured and makes sure that a minimal config is in place to make sure builds succeed.
        # TODO: Remove when distributions GPG keys are accepted by the default rpm-sequoia config everywhere.

        p = context.sandbox_tree / "etc/crypto-policies/back-ends/rpm-sequoia.config"
        p.parent.mkdir(parents=True, exist_ok=True)
        prev = p.read_text() if p.exists() else ""

        with p.open("w") as f:
            for line in prev.splitlines(keepends=True):
                if line.startswith("sha1.second_preimage_resistance"):
                    f.write('sha1.second_preimage_resistance = "always"\n')
                else:
                    f.write(line)

            if not any(line.startswith("[hash_algorithms]") for line in prev.splitlines()):
                f.write(
                    textwrap.dedent(
                        """
                        [hash_algorithms]
                        sha1.second_preimage_resistance = "always"
                        sha224 = "always"
                        sha256 = "always"
                        sha384 = "always"
                        sha512 = "always"
                        default_disposition = "never"
                        """
                    )
                )


def rpm_cmd() -> list[PathString]:
    return ["env", "HOME=/", "rpm", "--root=/buildroot"]
