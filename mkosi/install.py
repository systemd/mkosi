# SPDX-License-Identifier: LGPL-2.1+

import importlib.resources
from pathlib import Path

from mkosi.util import make_executable, umask


def write_resource(where: Path, resource: str, key: str, *, executable: bool = False) -> None:
    text = importlib.resources.read_text(resource, key)
    where.write_text(text)
    if executable:
        make_executable(where)


def add_dropin_config_from_resource(
    root: Path, unit: str, name: str, resource: str, key: str
) -> None:
    dropin = root / f"usr/lib/systemd/system/{unit}.d/{name}.conf"
    with umask(~0o755):
        dropin.parent.mkdir(parents=True, exist_ok=True)
        write_resource(dropin, resource, key)

