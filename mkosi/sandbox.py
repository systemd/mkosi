# SPDX-License-Identifier: LGPL-2.1-or-later

"""
This is a standalone implementation of sandboxing which is used by mkosi. Note that this is
invoked many times while building the image and as a result, the performance of this script has a
substantial impact on the performance of mkosi itself. To keep the runtime of this script to a
minimum, please don't import any extra modules if it can be avoided.

"""

import ctypes
import os
import sys
import warnings  # noqa: F401 (loaded lazily by os.execvp() which happens too late)

__version__ = "25~devel"

# The following constants are taken from the Linux kernel headers.
AT_EMPTY_PATH = 0x1000
AT_FDCWD = -100
AT_NO_AUTOMOUNT = 0x800
AT_RECURSIVE = 0x8000
AT_SYMLINK_NOFOLLOW = 0x100
BTRFS_SUPER_MAGIC = 0x9123683E
CAP_NET_ADMIN = 12
CAP_SYS_ADMIN = 21
CLONE_NEWIPC = 0x08000000
CLONE_NEWNET = 0x40000000
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
EPERM = 1
ENOENT = 2
LINUX_CAPABILITY_U32S_3 = 2
LINUX_CAPABILITY_VERSION_3 = 0x20080522
MNT_DETACH = 2
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004
MOUNT_ATTR_NOEXEC = 0x00000008
MOUNT_ATTR_SIZE_VER0 = 32
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
MS_BIND = 4096
MS_MOVE = 8192
MS_REC = 16384
MS_SHARED = 1 << 20
MS_SLAVE = 1 << 19
NR_mount_setattr = 442
NR_move_mount = 429
NR_open_tree = 428
OPEN_TREE_CLOEXEC = os.O_CLOEXEC
OPEN_TREE_CLONE = 1
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
# These definitions are taken from the libseccomp headers
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000


class mount_attr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    ]


class cap_user_header_t(ctypes.Structure):
    # __user_cap_header_struct
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("pid", ctypes.c_int),
    ]


class cap_user_data_t(ctypes.Structure):
    # __user_cap_data_struct
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


libc = ctypes.CDLL(None, use_errno=True)

libc.syscall.restype = ctypes.c_long
libc.unshare.argtypes = (ctypes.c_int,)
libc.statfs.argtypes = (ctypes.c_char_p, ctypes.c_void_p)
libc.eventfd.argtypes = (ctypes.c_int, ctypes.c_int)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)
libc.pivot_root.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
libc.capget.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
libc.capset.argtypes = (ctypes.c_void_p, ctypes.c_void_p)


def oserror(filename: str = "") -> None:
    raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), filename or None)


def unshare(flags: int) -> None:
    if libc.unshare(flags) < 0:
        oserror()


def statfs(path: str) -> int:
    # struct statfs is 120 bytes, which equals 15 longs. Since we only care about the first field
    # and the first field is of type long, we avoid declaring the full struct by just passing an
    # array of 15 longs as the output argument.
    buffer = (ctypes.c_long * 15)()

    if libc.statfs(path.encode(), ctypes.byref(buffer)) < 0:
        oserror(path)

    return int(buffer[0])


def mount(src: str, dst: str, type: str, flags: int, options: str) -> None:
    srcb = src.encode() if src else None
    typeb = type.encode() if type else None
    optionsb = options.encode() if options else None
    if libc.mount(srcb, dst.encode(), typeb, flags, optionsb) < 0:
        oserror(dst)


def umount2(path: str, flags: int = 0) -> None:
    if libc.umount2(path.encode(), flags) < 0:
        oserror(path)


def cap_permitted_to_ambient() -> None:
    """
    When unsharing a user namespace and mapping the current user to itself, the user has a full
    set of capabilities in the user namespace. This allows the user to do mounts after unsharing a
    mount namespace for example. However, these capabilities are lost again when the user executes
    a subprocess. As we also want subprocesses invoked by the user to be able to mount stuff, we
    make sure the capabilities are inherited by adding all the user's capabilities to the inherited
    and ambient capabilities set, which makes sure that they are passed down to subprocesses.
    """
    header = cap_user_header_t(LINUX_CAPABILITY_VERSION_3, 0)
    payload = (cap_user_data_t * LINUX_CAPABILITY_U32S_3)()

    if libc.capget(ctypes.addressof(header), ctypes.byref(payload)) < 0:
        oserror()

    payload[0].inheritable = payload[0].permitted
    payload[1].inheritable = payload[1].permitted

    if libc.capset(ctypes.addressof(header), ctypes.byref(payload)) < 0:
        oserror()

    effective = payload[1].effective << 32 | payload[0].effective

    with open("/proc/sys/kernel/cap_last_cap", "rb") as f:
        last_cap = int(f.read())

    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)

    for cap in range(ctypes.sizeof(ctypes.c_uint64) * 8):
        if cap > last_cap:
            break

        if effective & (1 << cap) and libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) < 0:
            oserror()


def have_effective_cap(capability: int) -> bool:
    with open("/proc/self/status", "rb") as f:
        for line in f.readlines():
            if line.startswith(b"CapEff:"):
                return (int(line[7:], 16) & (1 << capability)) != 0

    return False


def seccomp_suppress_chown() -> None:
    """
    There's still a few files and directories left in distributions in /usr and /etc that are
    not owned by root. This causes package managers to fail to install the corresponding packages
    when run from a single uid user namespace. Unfortunately, non-root users can only create files
    owned by their own uid. To still allow non-root users to build images, if requested we install
    a seccomp filter that makes calls to chown() and friends a noop.
    """
    libseccomp = ctypes.CDLL("libseccomp.so.2")
    if libseccomp is None:
        raise FileNotFoundError("libseccomp.so.2")

    libseccomp.seccomp_init.argtypes = (ctypes.c_uint32,)
    libseccomp.seccomp_init.restype = ctypes.c_void_p
    libseccomp.seccomp_release.argtypes = (ctypes.c_void_p,)
    libseccomp.seccomp_release.restype = None
    libseccomp.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    libseccomp.seccomp_rule_add_exact.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    )
    libseccomp.seccomp_load.argtypes = (ctypes.c_void_p,)

    seccomp = libseccomp.seccomp_init(SCMP_ACT_ALLOW)

    try:
        for syscall in (b"chown", b"chown32", b"fchown", b"fchown32", b"fchownat", b"lchown", b"lchown32"):
            id = libseccomp.seccomp_syscall_resolve_name(syscall)
            libseccomp.seccomp_rule_add_exact(seccomp, SCMP_ACT_ERRNO, id, 0)

            libseccomp.seccomp_load(seccomp)
    finally:
        libseccomp.seccomp_release(seccomp)


def join_new_session_keyring() -> None:
    libkeyutils = ctypes.CDLL("libkeyutils.so.1")
    if libkeyutils is None:
        raise FileNotFoundError("libkeyutils.so.1")

    libkeyutils.keyctl_join_session_keyring.argtypes = (ctypes.c_char_p,)
    libkeyutils.keyctl_join_session_keyring.restype = ctypes.c_int32

    keyring = libkeyutils.keyctl_join_session_keyring(None)
    if keyring == -1:
        oserror()


def mount_rbind(src: str, dst: str, attrs: int = 0) -> None:
    """
    When using the old mount syscall to do a recursive bind mount, mount options are not
    applied recursively. Because we want to do recursive read-only bind mounts in some cases, we
    use the new mount API for that which does allow recursively changing mount options when doing
    bind mounts.
    """
    flags = AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLONE

    try:
        libc.open_tree.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        fd = libc.open_tree(AT_FDCWD, src.encode(), flags)
    except AttributeError:
        libc.syscall.argtypes = (ctypes.c_long, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        fd = libc.syscall(NR_open_tree, AT_FDCWD, src.encode(), flags)

    if fd < 0:
        oserror(src)

    try:
        attr = mount_attr()
        attr.attr_set = attrs

        flags = AT_EMPTY_PATH | AT_RECURSIVE

        try:
            libc.mount_setattr.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_size_t,
            )
            r = libc.mount_setattr(fd, b"", flags, ctypes.addressof(attr), MOUNT_ATTR_SIZE_VER0)
        except AttributeError:
            libc.syscall.argtypes = (
                ctypes.c_long,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
                ctypes.c_void_p,
                ctypes.c_size_t,
            )
            r = libc.syscall(NR_mount_setattr, fd, b"", flags, ctypes.addressof(attr), MOUNT_ATTR_SIZE_VER0)

        if r < 0:
            oserror(src)

        try:
            libc.move_mount.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            r = libc.move_mount(fd, b"", AT_FDCWD, dst.encode(), MOVE_MOUNT_F_EMPTY_PATH)
        except AttributeError:
            libc.syscall.argtypes = (
                ctypes.c_long,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            r = libc.syscall(NR_move_mount, fd, b"", AT_FDCWD, dst.encode(), MOVE_MOUNT_F_EMPTY_PATH)

        if r < 0:
            oserror(dst)
    finally:
        os.close(fd)


class umask:
    def __init__(self, mask: int) -> None:
        self.mask = mask

    def __enter__(self) -> None:
        self.mask = os.umask(self.mask)

    def __exit__(self, *args: object, **kwargs: object) -> None:
        os.umask(self.mask)


def become_user(uid: int, gid: int) -> None:
    """
    This function implements the required dance to unshare a user namespace and map the current
    user to itself or to root within it. The kernel only allows a process running outside of the
    unshared user namespace to write the necessary uid and gid mappings, so we fork off a child
    process, make it wait until the parent process has unshared a user namespace, and then writes
    the necessary uid and gid mappings.
    """
    ppid = os.getpid()

    event = libc.eventfd(0, 0)
    if event < 0:
        oserror()

    pid = os.fork()
    if pid == 0:
        try:
            os.read(event, ctypes.sizeof(ctypes.c_uint64))
            os.close(event)
            with open(f"/proc/{ppid}/setgroups", "wb") as f:
                f.write(b"deny\n")
            with open(f"/proc/{ppid}/gid_map", "wb") as f:
                f.write(f"{gid} {os.getgid()} 1\n".encode())
            with open(f"/proc/{ppid}/uid_map", "wb") as f:
                f.write(f"{uid} {os.getuid()} 1\n".encode())
        except OSError as e:
            os._exit(e.errno or 1)
        except BaseException:
            os._exit(1)
        else:
            os._exit(0)

    try:
        unshare(CLONE_NEWUSER)
    except OSError as e:
        if e.errno == EPERM:
            print(UNSHARE_EPERM_MSG, file=sys.stderr)
        raise
    finally:
        os.write(event, ctypes.c_uint64(1))
        os.close(event)
        _, status = os.waitpid(pid, 0)

    rc = os.waitstatus_to_exitcode(status)
    if rc != 0:
        raise OSError(rc, os.strerror(rc))


def acquire_privileges(*, become_root: bool = False) -> bool:
    if os.getuid() == 0 or (not become_root and have_effective_cap(CAP_SYS_ADMIN)):
        return False

    if become_root:
        become_user(0, 0)
    else:
        become_user(os.getuid(), os.getgid())
        cap_permitted_to_ambient()

    return True


def userns_has_single_user() -> bool:
    try:
        with open("/proc/self/uid_map", "rb") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return False

    return len(lines) == 1 and int(lines[0].split()[-1]) == 1


def chase(root: str, path: str) -> str:
    if root == "/":
        return os.path.realpath(path)

    cwd = os.getcwd()
    fd = os.open("/", os.O_CLOEXEC | os.O_PATH | os.O_DIRECTORY)

    try:
        os.chroot(root)
        os.chdir("/")
        return joinpath(root, os.path.realpath(path))
    finally:
        os.fchdir(fd)
        os.close(fd)
        os.chroot(".")
        os.chdir(cwd)


def splitpath(path: str) -> tuple[str, ...]:
    return tuple(p for p in path.split("/") if p)


def joinpath(path: str, *paths: str) -> str:
    return os.path.join(path, *[p.lstrip("/") for p in paths])


def is_relative_to(one: str, two: str) -> bool:
    return os.path.commonpath((one, two)) == two


class FSOperation:
    def __init__(self, dst: str) -> None:
        self.dst = dst

    def execute(self, oldroot: str, newroot: str) -> None:
        raise NotImplementedError()

    @classmethod
    def optimize(cls, fsops: list["FSOperation"]) -> list["FSOperation"]:
        binds = set()
        rest = []

        for fsop in fsops:
            if isinstance(fsop, BindOperation):
                binds.add(fsop)
            else:
                rest.append(fsop)

        # Drop all bind mounts that are mounted from beneath another bind mount to the same
        # location within the new rootfs.
        optimized = [
            m
            for m in binds
            if not any(
                m != n
                and m.readonly == n.readonly
                and m.required == n.required
                and is_relative_to(m.src, n.src)
                and is_relative_to(m.dst, n.dst)
                and os.path.relpath(m.src, n.src) == os.path.relpath(m.dst, n.dst)
                for n in binds
            )
        ]

        # Make sure bind mounts override other operations on the same destination by appending them
        # to the rest and depending on python's stable sort behavior.
        return sorted([*rest, *optimized], key=lambda fsop: splitpath(fsop.dst))


class BindOperation(FSOperation):
    def __init__(self, src: str, dst: str, *, readonly: bool, required: bool) -> None:
        self.src = src
        self.readonly = readonly
        self.required = required
        super().__init__(dst)

    def __hash__(self) -> int:
        return hash((splitpath(self.src), splitpath(self.dst), self.readonly, self.required))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BindOperation) and self.__hash__() == other.__hash__()

    def execute(self, oldroot: str, newroot: str) -> None:
        src = chase(oldroot, self.src)

        if not os.path.exists(src) and not self.required:
            return

        # If we're mounting a file on top of a symlink, mount directly on top of the symlink instead of
        # resolving it.
        dst = joinpath(newroot, self.dst)
        if not os.path.isdir(src) and os.path.islink(dst):
            return mount_rbind(src, dst, attrs=MOUNT_ATTR_RDONLY if self.readonly else 0)

        dst = chase(newroot, self.dst)
        if not os.path.exists(dst):
            isfile = os.path.isfile(src)

            with umask(~0o755):
                os.makedirs(os.path.dirname(dst), exist_ok=True)

            with umask(~0o644 if isfile else ~0o755):
                if isfile:
                    os.close(os.open(dst, os.O_CREAT | os.O_CLOEXEC | os.O_EXCL))
                else:
                    os.mkdir(dst)

        mount_rbind(src, dst, attrs=MOUNT_ATTR_RDONLY if self.readonly else 0)


class ProcOperation(FSOperation):
    def execute(self, oldroot: str, newroot: str) -> None:
        dst = chase(newroot, self.dst)
        with umask(~0o755):
            os.makedirs(dst, exist_ok=True)

        mount_rbind(joinpath(oldroot, "proc"), dst)


class DevOperation(FSOperation):
    def __init__(self, ttyname: str, dst: str) -> None:
        self.ttyname = ttyname
        super().__init__(dst)

    def execute(self, oldroot: str, newroot: str) -> None:
        # We don't put actual devices in /dev, just the API stuff in there that all manner of
        # things depend on, like /dev/null.
        dst = chase(newroot, self.dst)
        with umask(~0o755):
            os.makedirs(dst, exist_ok=True)

        # Note that the mode is crucial here. If the default mode (1777) is used, trying to access
        # /dev/null fails with EACCESS for unknown reasons.
        mount("tmpfs", dst, "tmpfs", 0, "mode=0755")

        for node in ("null", "zero", "full", "random", "urandom", "tty"):
            ndst = joinpath(dst, node)
            os.close(os.open(ndst, os.O_CREAT | os.O_CLOEXEC | os.O_EXCL))

            mount(joinpath(oldroot, "dev", node), ndst, "", MS_BIND, "")

        for i, node in enumerate(("stdin", "stdout", "stderr")):
            os.symlink(f"/proc/self/fd/{i}", joinpath(dst, node))

        os.symlink("/proc/self/fd", joinpath(dst, "fd"))
        os.symlink("/proc/kcore", joinpath(dst, "core"))

        with umask(~0o1777):
            os.mkdir(joinpath(dst, "shm"), mode=0o1777)
        with umask(~0o755):
            os.mkdir(joinpath(dst, "pts"))

        mount("devpts", joinpath(dst, "pts"), "devpts", 0, "newinstance,ptmxmode=0666,mode=620")

        os.symlink("pts/ptmx", joinpath(dst, "ptmx"))

        if self.ttyname:
            os.close(os.open(joinpath(dst, "console"), os.O_CREAT | os.O_CLOEXEC | os.O_EXCL))
            mount(joinpath(oldroot, self.ttyname), joinpath(dst, "console"), "", MS_BIND, "")


class TmpfsOperation(FSOperation):
    def execute(self, oldroot: str, newroot: str) -> None:
        dst = chase(newroot, self.dst)
        with umask(~0o755):
            os.makedirs(dst, exist_ok=True)

        options = "" if any(dst.endswith(suffix) for suffix in ("/tmp", "/var/tmp")) else "mode=0755"
        mount("tmpfs", dst, "tmpfs", 0, options)


class DirOperation(FSOperation):
    def execute(self, oldroot: str, newroot: str) -> None:
        dst = chase(newroot, self.dst)
        with umask(~0o755):
            os.makedirs(os.path.dirname(dst), exist_ok=True)

        mode = 0o1777 if any(dst.endswith(suffix) for suffix in ("/tmp", "/var/tmp")) else 0o755
        if not os.path.exists(dst):
            with umask(~mode):
                os.mkdir(dst, mode=mode)


class SymlinkOperation(FSOperation):
    def __init__(self, src: str, dst: str) -> None:
        self.src = src
        super().__init__(dst)

    def execute(self, oldroot: str, newroot: str) -> None:
        dst = joinpath(newroot, self.dst)
        try:
            return os.symlink(self.src, dst)
        except FileExistsError:
            if os.path.islink(dst) and os.readlink(dst) == self.src:
                return

            if os.path.isdir(dst):
                raise

        # If the target already exists and is not a directory, create the symlink somewhere else and mount
        # it over the existing file or symlink.
        os.symlink(self.src, "/symlink")
        mount_rbind("/symlink", dst)
        os.unlink("/symlink")


class WriteOperation(FSOperation):
    def __init__(self, data: str, dst: str) -> None:
        self.data = data
        super().__init__(dst)

    def execute(self, oldroot: str, newroot: str) -> None:
        dst = chase(newroot, self.dst)
        with umask(~0o755):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(self.data.encode())


class OverlayOperation(FSOperation):
    def __init__(self, lowerdirs: tuple[str, ...], upperdir: str, workdir: str, dst: str) -> None:
        self.lowerdirs = lowerdirs
        self.upperdir = upperdir
        self.workdir = workdir
        super().__init__(dst)

    # This supports being used as a context manager so we can reuse the logic for mount_overlay()
    # in mounts.py.
    def __enter__(self) -> None:
        self.execute("/", "/")

    def __exit__(self, *args: object, **kwargs: object) -> None:
        umount2(self.dst)

    def execute(self, oldroot: str, newroot: str) -> None:
        lowerdirs = tuple(chase(oldroot, p) for p in self.lowerdirs)
        upperdir = (
            chase(oldroot, self.upperdir) if self.upperdir and self.upperdir != "tmpfs" else self.upperdir
        )
        workdir = chase(oldroot, self.workdir) if self.workdir else None
        dst = chase(newroot, self.dst)

        with umask(~0o755):
            os.makedirs(os.path.dirname(dst), exist_ok=True)

        mode = 0o1777 if any(dst.endswith(suffix) for suffix in ("/tmp", "/var/tmp")) else 0o755
        if not os.path.exists(dst):
            with umask(~mode):
                os.mkdir(dst, mode=mode)

        options = [
            f"lowerdir={':'.join(lowerdirs)}",
            "userxattr",
            # Disable the inodes index and metacopy (only copy metadata upwards if possible)
            # options. If these are enabled (e.g., if the kernel enables them by default),
            # the mount will fail if the upper directory has been earlier used with a different
            # lower directory, such as with a build overlay that was generated on top of a
            # different temporary root.
            # See https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html#sharing-and-copying-layers
            # and https://github.com/systemd/mkosi/issues/1841.
            "index=off",
            "metacopy=off",
        ]

        if upperdir and upperdir == "tmpfs":
            mount("tmpfs", dst, "tmpfs", 0, "mode=0755")

            with umask(~mode):
                os.mkdir(f"{dst}/upper", mode=mode)
            with umask(~0o755):
                os.mkdir(f"{dst}/work")

            options += [f"upperdir={dst}/upper", f"workdir={dst}/work"]
        else:
            if upperdir:
                options += [f"upperdir={upperdir}"]
            if workdir:
                options += [f"workdir={workdir}"]

        mount("overlayfs", dst, "overlay", 0, ",".join(options))


ANSI_HIGHLIGHT = "\x1b[0;1;39m" if os.isatty(2) else ""
ANSI_NORMAL = "\x1b[0m" if os.isatty(2) else ""

HELP = f"""\
mkosi-sandbox [OPTIONS...] COMMAND [ARGUMENTS...]

{ANSI_HIGHLIGHT}Run the specified command in a custom sandbox.{ANSI_NORMAL}

  -h --help                       Show this help
     --version                    Show package version
     --tmpfs DST                  Mount a new tmpfs on DST
     --dev DST                    Mount dev on DST
     --proc DST                   Mount procfs on DST
     --dir DST                    Create a new directory at DST
     --bind SRC DST               Bind mount the host path SRC to DST
     --bind-try SRC DST           Bind mount the host path SRC to DST if it exists
     --ro-bind SRC DST            Bind mount the host path SRC to DST read-only
     --ro-bind-try SRC DST        Bind mount the host path SRC to DST read-only if it exists
     --symlink SRC DST            Create a symlink at DST pointing to SRC
     --write DATA DST             Write DATA to DST
     --overlay-lowerdir DIR       Add a lower directory for the next overlayfs mount
     --overlay-upperdir DIR       Set the upper directory for the next overlayfs mount
     --overlay-workdir DIR        Set the working directory for the next overlayfs mount
     --overlay DST                Mount an overlay filesystem at DST
     --unsetenv NAME              Unset the environment variable with name NAME
     --setenv NAME VALUE          Set the environment variable with name NAME to VALUE
     --chdir DIR                  Change the working directory in the sandbox to DIR
     --same-dir                   Change the working directory in the sandbox to $PWD
     --become-root                Map the current user/group to root:root in the sandbox
     --suppress-chown             Make chown() syscalls in the sandbox a noop
     --unshare-net                Unshare the network namespace if possible
     --unshare-ipc                Unshare the IPC namespace if possible

See the mkosi-sandbox(1) man page for details.\
"""


UNSHARE_EPERM_MSG = """
mkosi was forbidden to unshare namespaces.

This probably means your distribution has restricted unprivileged user namespaces.

Please consult the REQUIREMENTS section of the mkosi man page, e.g. via "mkosi
documentation", for workarounds.
"""


def main() -> None:
    # We don't use argparse as it takes +- 10ms to import and since this is purely for internal
    # use, it's not necessary to have good UX for this CLI interface so it's trivial to write
    # ourselves.
    argv = list(reversed(sys.argv[1:]))
    fsops: list[FSOperation] = []
    setenv = []
    unsetenv = []
    lowerdirs = []
    upperdir = ""
    workdir = ""
    chdir = None
    become_root = suppress_chown = unshare_net = unshare_ipc = False

    ttyname = os.ttyname(2) if os.isatty(2) else ""

    while argv:
        arg = argv.pop()

        if arg == "--":
            break

        if arg in ("-h", "--help"):
            print(HELP, file=sys.stderr)
            sys.exit(0)
        elif arg == "--version":
            print(__version__, file=sys.stderr)
            sys.exit(0)
        if arg == "--tmpfs":
            fsops.append(TmpfsOperation(argv.pop()))
        elif arg == "--dev":
            fsops.append(DevOperation(ttyname, argv.pop()))
        elif arg == "--proc":
            fsops.append(ProcOperation(argv.pop()))
        elif arg == "--dir":
            fsops.append(DirOperation(argv.pop()))
        elif arg in ("--bind", "--ro-bind", "--bind-try", "--ro-bind-try"):
            readonly = arg.startswith("--ro")
            required = not arg.endswith("-try")
            fsops.append(BindOperation(argv.pop(), argv.pop(), readonly=readonly, required=required))
        elif arg == "--symlink":
            fsops.append(SymlinkOperation(argv.pop(), argv.pop()))
        elif arg == "--write":
            fsops.append(WriteOperation(argv.pop(), argv.pop()))
        elif arg == "--overlay-lowerdir":
            lowerdirs.append(argv.pop())
        elif arg == "--overlay-upperdir":
            upperdir = argv.pop()
        elif arg == "--overlay-workdir":
            workdir = argv.pop()
        elif arg == "--overlay":
            fsops.append(OverlayOperation(tuple(reversed(lowerdirs)), upperdir, workdir, argv.pop()))
            upperdir = ""
            workdir = ""
            lowerdirs = []
        elif arg == "--unsetenv":
            unsetenv.append(argv.pop())
        elif arg == "--setenv":
            setenv.append((argv.pop(), argv.pop()))
        elif arg == "--chdir":
            chdir = argv.pop()
        elif arg == "--same-dir":
            chdir = os.getcwd()
        elif arg == "--become-root":
            become_root = True
        elif arg == "--suppress-chown":
            suppress_chown = True
        elif arg == "--unshare-net":
            unshare_net = True
        elif arg == "--unshare-ipc":
            unshare_ipc = True
        elif arg.startswith("-"):
            raise ValueError(f"Unrecognized option {arg}")
        else:
            argv.append(arg)
            break

    argv.reverse()

    argv = argv or ["bash"]

    # Make sure all destination paths are absolute.
    for fsop in fsops:
        if fsop.dst[0] != "/":
            raise ValueError(f"{fsop.dst} is not an absolute path")

    fsops = FSOperation.optimize(fsops)

    for k, v in setenv:
        os.environ[k] = v

    for e in unsetenv:
        if e in os.environ:
            del os.environ[e]

    # If $LISTEN_FDS is in the environment, let's automatically set $LISTEN_PID to the correct pid as well.
    if "LISTEN_FDS" in os.environ:
        os.environ["LISTEN_PID"] = str(os.getpid())

    namespaces = CLONE_NEWNS
    if unshare_net and have_effective_cap(CAP_NET_ADMIN):
        namespaces |= CLONE_NEWNET
    if unshare_ipc:
        namespaces |= CLONE_NEWIPC

    userns = acquire_privileges(become_root=become_root)

    # If we're root in a user namespace with a single user, we're still not going to be able to
    # chown() stuff, so check for that and apply the seccomp filter as well in that case.
    if suppress_chown and (userns or userns_has_single_user()):
        seccomp_suppress_chown()

    try:
        unshare(namespaces)
    except OSError as e:
        # This can happen here as well as in become_user, it depends on exactly
        # how the userns restrictions are implemented.
        if e.errno == EPERM:
            print(UNSHARE_EPERM_MSG, file=sys.stderr)
        raise

    # If we unshared the user namespace the mount propagation of root is changed to slave automatically.
    if not userns:
        mount("", "/", "", MS_SLAVE | MS_REC, "")

    # We need a workspace to setup the sandbox, the easiest way to do this in a tmpfs, since it's
    # automatically cleaned up. We need a mountpoint to put the workspace on and it can't be root,
    # so let's use /tmp which is almost guaranteed to exist.
    mount("tmpfs", "/tmp", "tmpfs", 0, "")

    os.chdir("/tmp")

    with umask(~0o755):
        # This is where we set up the sandbox rootfs
        os.mkdir("newroot")
        # This is the old rootfs which is used as the source for mounts in the new rootfs.
        os.mkdir("oldroot")

    # Make sure that newroot is a mountpoint.
    mount("newroot", "newroot", "", MS_BIND | MS_REC, "")

    # Make the workspace in /tmp / and put the old rootfs in oldroot.
    if libc.pivot_root(b".", b"oldroot") < 0:
        # pivot_root() can fail in the initramfs since / isn't a mountpoint there, so let's fall
        # back to MS_MOVE if that's the case.

        # First we move the old rootfs to oldroot.
        mount("/", "oldroot", "", MS_BIND | MS_REC, "")

        # Then we move the workspace (/tmp) to /.
        mount(".", "/", "", MS_MOVE, "")

        # chroot and chdir to fully make the workspace the new root.
        os.chroot(".")
        os.chdir(".")

        # When we use MS_MOVE we have to unmount oldroot/tmp manually to reveal the original /tmp
        # again as it might contain stuff that we want to mount into the sandbox.
        umount2("oldroot/tmp", MNT_DETACH)

    for fsop in fsops:
        fsop.execute("oldroot", "newroot")

    # Now that we're done setting up the sandbox let's pivot root into newroot to make it the new
    # root. We use the pivot_root(".", ".") process described in the pivot_root() man page.

    os.chdir("newroot")

    # We're guaranteed to have / be a mount when we get here, so pivot_root() won't fail anymore,
    # even if we're in the initramfs.
    if libc.pivot_root(b".", b".") < 0:
        oserror()

    # As documented in the pivot_root() man page, this will unmount the old rootfs.
    umount2(".", MNT_DETACH)

    # Avoid surprises by making sure the sandbox's mount propagation is shared. This doesn't
    # actually mean mounts get propagated into the host. Instead, a new mount propagation peer
    # group is set up.
    mount("", ".", "", MS_SHARED | MS_REC, "")

    if chdir:
        os.chdir(chdir)

    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        # Let's return a recognizable error when the binary we're going to execute is not found.
        # We use 127 as that's the exit code used by shells when a program to execute is not found.
        if e.errno == ENOENT:
            sys.exit(127)

        raise


if __name__ == "__main__":
    main()
