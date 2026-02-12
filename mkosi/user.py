# SPDX-License-Identifier: LGPL-2.1-or-later
import os
from pathlib import Path

from mkosi.run import find_binary
from mkosi.util import parents_below

SUBRANGE = 65536


class INVOKING_USER:
    @classmethod
    def is_regular_user(cls, uid: int) -> bool:
        return uid >= 1000

    @classmethod
    def cache_dir(cls) -> Path:
        if (env := os.getenv("XDG_CACHE_HOME")) or (env := os.getenv("CACHE_DIRECTORY")):
            cache = Path(env)
        elif cls.is_regular_user(os.getuid()) and Path.home() != Path("/"):
            cache = Path.home() / ".cache"
        else:
            cache = Path("/var/cache")

        return cache

    @classmethod
    def runtime_dir(cls) -> Path:
        if (env := os.getenv("XDG_RUNTIME_DIR")) or (env := os.getenv("RUNTIME_DIRECTORY")):
            d = Path(env)
        elif cls.is_regular_user(os.getuid()):
            d = Path(f"/run/user/{os.getuid()}")
        else:
            d = Path("/run")

        return d

    @classmethod
    def tmpfiles_dir(cls) -> Path:
        config = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))
        if config in (Path("/"), Path("/root")):
            return Path("/etc/tmpfiles.d")

        return config / "user-tmpfiles.d"

    @classmethod
    def chown(cls, path: Path) -> None:
        # If we created a file/directory in a parent directory owned by a regular user, make sure the path
        # and any parent directories are owned by the invoking user as well.

        if q := next((parent for parent in path.parents if cls.is_regular_user(parent.stat().st_uid)), None):
            st = q.stat()
            os.chown(path, st.st_uid, st.st_gid)

            for parent in parents_below(path, q):
                os.chown(parent, st.st_uid, st.st_gid)


def become_root_cmd() -> list[str]:
    if os.getuid() == 0:
        return []

    return ["run0"] if find_binary("run0") and Path("/run/systemd/system").exists() else ["sudo"]
