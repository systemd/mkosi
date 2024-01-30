# SPDX-License-Identifier: LGPL-2.1+
import ctypes
import ctypes.util
import fcntl
import functools
import logging
import os
import pwd
from pathlib import Path

from mkosi.log import die
from mkosi.run import run, spawn
from mkosi.util import flock

SUBRANGE = 65536


class INVOKING_USER:
    uid = int(os.getenv("SUDO_UID") or os.getenv("PKEXEC_UID") or os.getuid())
    gid = int(os.getenv("SUDO_GID") or os.getgid())
    invoked_as_root = uid == 0

    @classmethod
    def init(cls) -> None:
        name = cls.name()
        home = cls.home()
        logging.debug(f"Running as user '{name}' ({cls.uid}:{cls.gid}) with home {home}.")

    @classmethod
    def is_running_user(cls) -> bool:
        return cls.uid == os.getuid()

    @classmethod
    @functools.lru_cache(maxsize=1)
    def name(cls) -> str:
        return pwd.getpwuid(cls.uid).pw_name

    @classmethod
    @functools.lru_cache(maxsize=1)
    def home(cls) -> Path:
        return Path(f"~{cls.name()}").expanduser()

    @classmethod
    def is_regular_user(cls) -> bool:
        return cls.uid >= 1000

    @classmethod
    def cache_dir(cls) -> Path:
        if (env := os.getenv("XDG_CACHE_HOME")) or (env := os.getenv("CACHE_DIRECTORY")):
            cache = Path(env)
        elif cls.is_regular_user() and (Path.cwd().is_relative_to(INVOKING_USER.home()) or not cls.invoked_as_root):
            cache = INVOKING_USER.home() / ".cache"
        else:
            cache = Path("/var/cache")

        return cache / "mkosi"

    @classmethod
    def mkdir(cls, path: Path) -> Path:
        user = cls.uid if cls.is_regular_user() and path.is_relative_to(cls.home()) else os.getuid()
        group = cls.gid if cls.is_regular_user() and path.is_relative_to(cls.home()) else os.getgid()
        run(["mkdir", "--parents", path], user=user, group=group)
        return path


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

    # We map the private UID range configured in /etc/subuid and /etc/subgid into the container using
    # newuidmap and newgidmap. On top of that, we also make sure to map in the user running mkosi so that
    # we can run still chown stuff to that user or run stuff as that user which will make sure any
    # generated files are owned by that user. We don't map to the last user in the range as the last user
    # is sometimes used in tests as a default value and mapping to that user might break those tests.
    newuidmap = [
        "flock", "--exclusive", "--no-fork", "/etc/subuid", "newuidmap", pid,
        0, subuid, SUBRANGE - 100,
        SUBRANGE - 100, os.getuid(), 1,
        SUBRANGE - 100 + 1, subuid + SUBRANGE - 100 + 1, 99
    ]

    newgidmap = [
        "flock", "--exclusive", "--no-fork", "/etc/subuid", "newgidmap", pid,
        0, subgid, SUBRANGE - 100,
        SUBRANGE - 100, os.getgid(), 1,
        SUBRANGE - 100 + 1, subgid + SUBRANGE - 100 + 1, 99
    ]

    newuidmap = [str(x) for x in newuidmap]
    newgidmap = [str(x) for x in newgidmap]

    # newuidmap and newgidmap have to run from outside the user namespace to be able to assign a uid mapping
    # to the process in the user namespace. The mapping can only be assigned after the user namespace has
    # been unshared. To make this work, we first lock /etc/subuid, then spawn the newuidmap and newgidmap
    # processes, which we execute using flock so they don't execute before they can get a lock on /etc/subuid,
    # then we unshare the user namespace and finally we unlock /etc/subuid, which allows the newuidmap and
    # newgidmap processes to execute. we then wait for the processes to finish before continuing.
    with flock(Path("/etc/subuid")) as fd, spawn(newuidmap) as uidmap, spawn(newgidmap) as gidmap:
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
