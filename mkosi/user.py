# SPDX-License-Identifier: LGPL-2.1-or-later
import fcntl
import functools
import os
import pwd
import tempfile
from pathlib import Path

from mkosi.log import die
from mkosi.run import spawn
from mkosi.sandbox import CLONE_NEWUSER, unshare
from mkosi.util import flock, parents_below

SUBRANGE = 65536


class INVOKING_USER:
    @classmethod
    @functools.lru_cache(maxsize=1)
    def name(cls) -> str:
        try:
            return pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            if os.getuid() == 0:
                return "root"

            if not (user := os.getenv("USER")):
                die(f"Could not find user name for UID {os.getuid()}")

            return user

    @classmethod
    @functools.lru_cache(maxsize=1)
    def home(cls) -> Path:
        if os.getuid() == 0 and Path.cwd().is_relative_to("/home") and len(Path.cwd().parents) > 2:
            return list(Path.cwd().parents)[-3]

        try:
            return Path(pwd.getpwuid(os.getuid()).pw_dir or "/")
        except KeyError:
            if not (home := os.getenv("HOME")):
                die(f"Could not find home directory for UID {os.getuid()}")

            return Path(home)

    @classmethod
    def is_regular_user(cls, uid: int) -> bool:
        return uid >= 1000

    @classmethod
    def cache_dir(cls) -> Path:
        if (env := os.getenv("XDG_CACHE_HOME")) or (env := os.getenv("CACHE_DIRECTORY")):
            cache = Path(env)
        elif cls.is_regular_user(os.getuid()) and cls.home() != Path("/"):
            cache = cls.home() / ".cache"
        else:
            cache = Path("/var/cache")

        return cache / "mkosi"

    @classmethod
    def runtime_dir(cls) -> Path:
        if (env := os.getenv("XDG_RUNTIME_DIR")) or (env := os.getenv("RUNTIME_DIRECTORY")):
            d = Path(env)
        elif cls.is_regular_user(os.getuid()):
            d = Path(f"/run/user/{os.getuid()}")
        else:
            d = Path("/run")

        return d / "mkosi"

    @classmethod
    def chown(cls, path: Path) -> None:
        # If we created a file/directory in a parent directory owned by a regular user, make sure the path and any
        # parent directories are owned by the invoking user as well.

        if (q := next((parent for parent in path.parents if cls.is_regular_user(parent.stat().st_uid)), None)):
            st = q.stat()
            os.chown(path, st.st_uid, st.st_gid)

            for parent in parents_below(path, q):
                os.chown(parent, st.st_uid, st.st_gid)


def read_subrange(path: Path) -> int:
    uid = str(os.getuid())
    try:
        user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        user = None

    for line in path.read_text().splitlines():
        name, start, count = line.split(":")

        if name == uid or name == user:
            break
    else:
        die(f"No mapping found for {user or uid} in {path}")

    if int(count) < SUBRANGE:
        die(
            f"subuid/subgid range length must be at least {SUBRANGE}, "
            f"got {count} for {user or uid} from line '{line}'"
        )

    return int(start)


def become_root_in_subuid_range() -> None:
    """
    Set up a new user namespace mapping using /etc/subuid and /etc/subgid.

    The current process becomes the root user in the new user namespace and the current user and group will be mapped
    to 65436. The other IDs will be mapped through.
    """
    if os.getuid() == 0:
        return

    subuid = read_subrange(Path("/etc/subuid"))
    subgid = read_subrange(Path("/etc/subgid"))

    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix="mkosi-uidmap-lock-") as lockfile:
        lock = Path(lockfile.name)

        # We map the private UID range configured in /etc/subuid and /etc/subgid into the user namespace using
        # newuidmap and newgidmap. On top of that, we also make sure to map in the user running mkosi so that
        # we can access files and directories from the current user from within the user namespace. We don't map to the
        # last user in the range as the last user is sometimes used in tests as a default value and mapping to that
        # user might break those tests.
        newuidmap = [
            "flock", "--exclusive", "--close", lock, "newuidmap", pid,
            0, subuid, SUBRANGE - 100,
            SUBRANGE - 100, os.getuid(), 1,
            SUBRANGE - 100 + 1, subuid + SUBRANGE - 100 + 1, 99
        ]

        newgidmap = [
            "flock", "--exclusive", "--close", lock, "newgidmap", pid,
            0, subgid, SUBRANGE - 100,
            SUBRANGE - 100, os.getgid(), 1,
            SUBRANGE - 100 + 1, subgid + SUBRANGE - 100 + 1, 99
        ]

        newuidmap = [str(x) for x in newuidmap]
        newgidmap = [str(x) for x in newgidmap]

        # newuidmap and newgidmap have to run from outside the user namespace to be able to assign a uid mapping to the
        # process in the user namespace. The mapping can only be assigned after the user namespace has been unshared.
        # To make this work, we first lock a temporary file, then spawn the newuidmap and newgidmap processes, which we
        # execute using flock so they don't execute before they can get a lock on the same temporary file, then we
        # unshare the user namespace and finally we unlock the temporary file, which allows the newuidmap and newgidmap
        # processes to execute. we then wait for the processes to finish before continuing.
        with flock(lock) as fd, spawn(newuidmap) as uidmap, spawn(newgidmap) as gidmap:
            unshare(CLONE_NEWUSER)
            fcntl.flock(fd, fcntl.LOCK_UN)
            uidmap.wait()
            gidmap.wait()

    # By default, we're root in the user namespace because if we were our current user by default, we
    # wouldn't be able to chown stuff to be owned by root while the reverse is possible.
    os.setresuid(0, 0, 0)
    os.setresgid(0, 0, 0)
    os.setgroups([0])


def become_root_in_subuid_range_cmd() -> list[str]:
    if os.getuid() == 0:
        return []

    subuid = read_subrange(Path("/etc/subuid"))
    subgid = read_subrange(Path("/etc/subgid"))

    cmd = [
        "unshare",
        "--setuid", "0",
        "--setgid", "0",
        "--map-users",  f"0:{subuid}:{SUBRANGE - 100}",
        "--map-users",  f"{SUBRANGE - 100}:{os.getuid()}:1",
        "--map-users",  f"{SUBRANGE - 100 + 1}:{subuid + SUBRANGE - 100 + 1}:99",
        "--map-groups", f"0:{subgid}:{SUBRANGE - 100}",
        "--map-groups", f"{SUBRANGE - 100}:{os.getgid()}:1",
        "--map-groups", f"{SUBRANGE - 100 + 1}:{subgid + SUBRANGE - 100 + 1}:99",
        "--keep-caps",
    ]

    return [str(x) for x in cmd]
