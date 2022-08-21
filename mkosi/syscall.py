# SPDX-License-Identifier: LGPL-2.1+

import ctypes
import errno
import fcntl
from typing import Optional

_IOC_NRBITS   =  8  # NOQA: E221,E222
_IOC_TYPEBITS =  8  # NOQA: E221,E222
_IOC_SIZEBITS = 14  # NOQA: E221,E222
_IOC_DIRBITS  =  2  # NOQA: E221,E222

_IOC_NRSHIFT   = 0  # NOQA: E221
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS  # NOQA: E221
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS  # NOQA: E221
_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS  # NOQA: E221

_IOC_NONE  = 0  # NOQA: E221
_IOC_WRITE = 1  # NOQA: E221
_IOC_READ  = 2  # NOQA: E221


def _IOC(dir_rw: int, type_drv: int, nr: int, argtype: Optional[str] = None) -> int:
    size = {"int": 4, "size_t": 8}[argtype] if argtype else 0
    return dir_rw << _IOC_DIRSHIFT | type_drv << _IOC_TYPESHIFT | nr << _IOC_NRSHIFT | size << _IOC_SIZESHIFT


def _IOW(type_drv: int, nr: int, size: str) -> int:
    return _IOC(_IOC_WRITE, type_drv, nr, size)


def _IO(type_drv: int, nr: int) -> int:
    return _IOC(_IOC_NONE, type_drv, nr)


BLKPG = _IO(0x12, 105)
BLKPG_ADD_PARTITION = 1
BLKPG_DEL_PARTITION = 2


class blkpg_ioctl_arg(ctypes.Structure):
    _fields_ = [
        ('op', ctypes.c_int),
        ('flags', ctypes.c_int),
        ('datalen', ctypes.c_int),
        ('data', ctypes.c_void_p),
    ]


class blkpg_partition(ctypes.Structure):
    _fields_ = [
        ('start', ctypes.c_longlong),
        ('length', ctypes.c_longlong),
        ('pno', ctypes.c_int),
        ('devname', ctypes.c_char * 64),
        ('volname', ctypes.c_char * 64),
    ]


def blkpg_add_partition(fd: int, nr: int, start: int, size: int) -> None:
    bp = blkpg_partition(pno=nr, start=start, length=size)
    ba = blkpg_ioctl_arg(op=BLKPG_ADD_PARTITION, data=ctypes.addressof(bp), datalen=ctypes.sizeof(bp))
    try:
        fcntl.ioctl(fd, BLKPG, ba)
    except OSError as e:
        # EBUSY means the kernel has already initialized the partition device.
        if e.errno != errno.EBUSY:
            raise


def blkpg_del_partition(fd: int, nr: int) -> None:
    bp = blkpg_partition(pno=nr)
    ba = blkpg_ioctl_arg(op=BLKPG_DEL_PARTITION, data=ctypes.addressof(bp), datalen=ctypes.sizeof(bp))
    try:
        fcntl.ioctl(fd, BLKPG, ba)
    except OSError as e:
        if e.errno != errno.EBUSY:
            raise


FICLONE = _IOW(0x94, 9, "int")


def reflink(oldfd: int, newfd: int) -> None:
    fcntl.ioctl(newfd, FICLONE, oldfd)
