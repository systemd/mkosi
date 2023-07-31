# SPDX-License-Identifier: LGPL-2.1+

import enum
import platform

from mkosi.log import die


class Architecture(enum.Enum):
    alpha       = enum.auto()
    arc         = enum.auto()
    arm         = enum.auto()
    arm64       = enum.auto()
    ia64        = enum.auto()
    loongarch64 = enum.auto()
    mips_le     = enum.auto()
    mips64_le   = enum.auto()
    parisc      = enum.auto()
    ppc         = enum.auto()
    ppc64       = enum.auto()
    ppc64_le    = enum.auto()
    riscv32     = enum.auto()
    riscv64     = enum.auto()
    s390        = enum.auto()
    s390x       = enum.auto()
    tilegx      = enum.auto()
    x86         = enum.auto()
    x86_64      = enum.auto()

    def __str__(self) -> str:
        return self.name.replace("_", "-")

    @staticmethod
    def from_uname(s: str) -> "Architecture":
        a = {
            "aarch64"     : Architecture.arm64,
            "aarch64_be"  : Architecture.arm64,
            "armv8l"      : Architecture.arm,
            "armv8b"      : Architecture.arm,
            "armv7ml"     : Architecture.arm,
            "armv7mb"     : Architecture.arm,
            "armv7l"      : Architecture.arm,
            "armv7b"      : Architecture.arm,
            "armv6l"      : Architecture.arm,
            "armv6b"      : Architecture.arm,
            "armv5tl"     : Architecture.arm,
            "armv5tel"    : Architecture.arm,
            "armv5tejl"   : Architecture.arm,
            "armv5tejb"   : Architecture.arm,
            "armv5teb"    : Architecture.arm,
            "armv5tb"     : Architecture.arm,
            "armv4tl"     : Architecture.arm,
            "armv4tb"     : Architecture.arm,
            "armv4l"      : Architecture.arm,
            "armv4b"      : Architecture.arm,
            "alpha"       : Architecture.alpha,
            "arc"         : Architecture.arc,
            "arceb"       : Architecture.arc,
            "x86_64"      : Architecture.x86_64,
            "i686"        : Architecture.x86,
            "i586"        : Architecture.x86,
            "i486"        : Architecture.x86,
            "i386"        : Architecture.x86,
            "ia64"        : Architecture.ia64,
            "parisc64"    : Architecture.parisc,
            "parisc"      : Architecture.parisc,
            "loongarch64" : Architecture.loongarch64,
            "mips64"      : Architecture.mips64_le,
            "mips"        : Architecture.mips_le,
            "ppc64le"     : Architecture.ppc64_le,
            "ppc64"       : Architecture.ppc64,
            "ppc"         : Architecture.ppc,
            "riscv64"     : Architecture.riscv64,
            "riscv32"     : Architecture.riscv32,
            "riscv"       : Architecture.riscv64,
            "s390x"       : Architecture.s390x,
            "s390"        : Architecture.s390,
            "tilegx"      : Architecture.tilegx,
        }.get(s)

        if not a:
            die(f"Architecture {a} is not supported")

        return a

    def to_efi(self) -> str:
        a = {
            Architecture.x86_64      : "x64",
            Architecture.x86         : "ia32",
            Architecture.arm64       : "aa64",
            Architecture.arm         : "arm",
            Architecture.riscv64     : "riscv64",
            Architecture.loongarch64 : "loongarch64",
        }.get(self)

        if not a:
            die(f"Architecture {self} does not support UEFI")

        return a

    def to_qemu(self) -> str:
        a = {
            Architecture.alpha: "alpha",
            Architecture.arm: "arm",
            Architecture.arm64: "aarch64",
            Architecture.loongarch64: "loongarch64",
            Architecture.mips64_le: "mips",
            Architecture.mips_le: "mips",
            Architecture.parisc: "hppa",
            Architecture.ppc: "ppc",
            Architecture.ppc64: "ppc",
            Architecture.ppc64_le: "ppc",
            Architecture.riscv32: "riscv32",
            Architecture.riscv64: "riscv64",
            Architecture.s390x: "s390x",
            Architecture.x86: "i386",
            Architecture.x86_64: "x86_64",
        }.get(self)

        if not a:
            die(f"Architecture {self} not supported by QEMU")

        return a

    def is_native(self) -> bool:
        return self == self.native()

    @classmethod
    def native(cls) -> "Architecture":
        return cls.from_uname(platform.machine())

