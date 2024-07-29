# SPDX-License-Identifier: LGPL-2.1-or-later
import ctypes
import ctypes.util
import fcntl
import functools
import logging
import os
import pwd
import tempfile
from collections.abc import Sequence
from pathlib import Path

from mkosi.log import die
from mkosi.run import run, spawn
from mkosi.util import flock, parents_below

SUBRANGE = 65536


class INVOKING_USER:
    uid = int(os.getenv("SUDO_UID") or os.getenv("PKEXEC_UID") or os.getuid())
    gid = int(os.getenv("SUDO_GID") or os.getgid())
    invoked_as_root = os.getuid() == 0

    @classmethod
    def init(cls) -> None:
        name = cls.name()
        home = cls.home()
        extra_groups = cls.extra_groups()
        logging.debug(
            f"Running as user '{name}' ({cls.uid}:{cls.gid}) with home {home} "
            f"and extra groups {extra_groups}."
        )

    @classmethod
    def is_running_user(cls) -> bool:
        return cls.uid == os.getuid()

    @classmethod
    @functools.lru_cache(maxsize=1)
    def name(cls) -> str:
        try:
            return pwd.getpwuid(cls.uid).pw_name
        except KeyError:
            if cls.uid == 0:
                return "root"

            if not (user := os.getenv("USER")):
                die(f"Could not find user name for UID {cls.uid}")

            return user

    @classmethod
    @functools.lru_cache(maxsize=1)
    def home(cls) -> Path:
        if cls.invoked_as_root and Path.cwd().is_relative_to("/home") and len(Path.cwd().parents) > 2:
            return list(Path.cwd().parents)[-3]

        try:
            return Path(pwd.getpwuid(cls.uid).pw_dir or "/")
        except KeyError:
            if not (home := os.getenv("HOME")):
                die(f"Could not find home directory for UID {cls.uid}")

            return Path(home)

    @classmethod
    @functools.lru_cache(maxsize=1)
    def extra_groups(cls) -> Sequence[int]:
        return os.getgrouplist(cls.name(), cls.gid)

    @classmethod
    def is_regular_user(cls) -> bool:
        return cls.uid >= 1000

    @classmethod
    def cache_dir(cls) -> Path:
        if (env := os.getenv("XDG_CACHE_HOME")) or (env := os.getenv("CACHE_DIRECTORY")):
            cache = Path(env)
        elif (
            cls.is_regular_user() and
            INVOKING_USER.home() != Path("/") and
            (Path.cwd().is_relative_to(INVOKING_USER.home()) or not cls.invoked_as_root)
        ):
            cache = INVOKING_USER.home() / ".cache"
        else:
            cache = Path("/var/cache")

        return cache / "mkosi"

    @classmethod
    def runtime_dir(cls) -> Path:
        if (env := os.getenv("XDG_RUNTIME_DIR")) or (env := os.getenv("RUNTIME_DIRECTORY")):
            d = Path(env)
        elif cls.is_regular_user():
            d = Path("/run/user") / str(cls.uid)
        else:
            d = Path("/run")

        return d / "mkosi"

    @classmethod
    def rchown(cls, path: Path) -> None:
        if cls.is_regular_user() and any(p.stat().st_uid == cls.uid for p in path.parents) and path.exists():
            run(["chown", "--recursive", f"{INVOKING_USER.uid}:{INVOKING_USER.gid}", path])

    @classmethod
    def chown(cls, path: Path) -> None:
        # If we created a file/directory in a parent directory owned by the invoking user, make sure the path and any
        # parent directories are owned by the invoking user as well.

        def is_valid_dir(path: Path) -> bool:
            return path.stat().st_uid == cls.uid or path in (Path("/tmp"), Path("/var/tmp"))

        if cls.is_regular_user() and (q := next((parent for parent in path.parents if is_valid_dir(parent)), None)):
            os.chown(path, INVOKING_USER.uid, INVOKING_USER.gid)

            for parent in parents_below(path, q):
                os.chown(parent, INVOKING_USER.uid, INVOKING_USER.gid)


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


CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000


def unshare(flags: int) -> None:
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        die("Could not find libc")
    libc = ctypes.CDLL(libc_name, use_errno=True)

    if libc.unshare(ctypes.c_int(flags)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def become_root() -> None:
    """
    Set up a new user namespace mapping using /etc/subuid and /etc/subgid.

    The current user will be mapped to root and 65436 will be mapped to the UID/GID of the invoking user.
    The other IDs will be mapped through.

    The function modifies the uid, gid of the INVOKING_USER object to the uid, gid of the invoking user in the user
    namespace.
    """
    if os.getuid() == 0:
        return

    subuid = read_subrange(Path("/etc/subuid"))
    subgid = read_subrange(Path("/etc/subgid"))

    pid = os.getpid()

    with tempfile.NamedTemporaryFile(prefix="mkosi-uidmap-lock-") as lockfile:
        lock = Path(lockfile.name)

        # We map the private UID range configured in /etc/subuid and /etc/subgid into the container using
        # newuidmap and newgidmap. On top of that, we also make sure to map in the user running mkosi so that
        # we can run still chown stuff to that user or run stuff as that user which will make sure any
        # generated files are owned by that user. We don't map to the last user in the range as the last user
        # is sometimes used in tests as a default value and mapping to that user might break those tests.
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
        with (
            flock(lock) as fd,
            spawn(newuidmap, innerpid=False) as (uidmap, _),
            spawn(newgidmap, innerpid=False) as (gidmap, _)
        ):
            unshare(CLONE_NEWUSER)
            fcntl.flock(fd, fcntl.LOCK_UN)
            uidmap.wait()
            gidmap.wait()

    # By default, we're root in the user namespace because if we were our current user by default, we
    # wouldn't be able to chown stuff to be owned by root while the reverse is possible.
    os.setresuid(0, 0, 0)
    os.setresgid(0, 0, 0)
    os.setgroups([0])

    INVOKING_USER.uid = SUBRANGE - 100
    INVOKING_USER.gid = SUBRANGE - 100


def become_root_cmd() -> list[str]:
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
