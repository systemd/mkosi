# SPDX-License-Identifier: LGPL-2.1+

import importlib.resources
from pathlib import Path
from typing import Optional

from mkosi.run import run
from mkosi.util import make_executable


def write_resource(
    where: Path, resource: str, key: str, *, executable: bool = False, mode: Optional[int] = None
) -> None:
    text = importlib.resources.read_text(resource, key)
    where.write_text(text)
    if mode is not None:
        where.chmod(mode)
    elif executable:
        make_executable(where)


def add_dropin_config_from_resource(
    root: Path, unit: str, name: str, resource: str, key: str
) -> None:
    dropin = root / f"usr/lib/systemd/system/{unit}.d/{name}.conf"
    dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    write_resource(dropin, resource, key, mode=0o644)


def copy_path(
    src: Path,
    dst: Path,
    *,
    dereference: bool = False,
    preserve_owner: bool = True,
) -> None:
    run([
        "cp",
        "--recursive",
        f"--{'' if dereference else 'no-'}dereference",
        f"--preserve=mode,timestamps,links,xattr{',ownership' if preserve_owner else ''}",
        "--no-target-directory",
        "--reflink=auto",
        src, dst,
    ])
