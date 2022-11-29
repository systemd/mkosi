# SPDX-License-Identifier: LGPL-2.1+

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, cast

from mkosi.backend import PathString, run


def btrfs_subvol_delete(path: Path) -> None:
    # Extract the path of the subvolume relative to the filesystem
    c = run(["btrfs", "subvol", "show", path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    subvol_path = c.stdout.splitlines()[0]
    # Make the subvolume RW again if it was set RO by btrfs_subvol_delete
    run(["btrfs", "property", "set", path, "ro", "false"])
    # Recursively delete the direct children of the subvolume
    c = run(["btrfs", "subvol", "list", "-o", path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in c.stdout.splitlines():
        if not line:
            continue
        child_subvol_path = line.split(" ", 8)[-1]
        child_path = path / cast(str, os.path.relpath(child_subvol_path, subvol_path))
        btrfs_subvol_delete(child_path)
    # Delete the subvolume now that all its descendants have been deleted
    run(["btrfs", "subvol", "delete", path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def unlink_try_hard(path: Optional[PathString]) -> None:
    if path is None:
        return

    path = Path(path)
    try:
        path.unlink()
        return
    except FileNotFoundError:
        return
    except Exception:
        pass

    if shutil.which("btrfs"):
        try:
            btrfs_subvol_delete(path)
            return
        except Exception:
            pass

    shutil.rmtree(path)
