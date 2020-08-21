#!/usr/bin/env python3

import pexpect
import sys


def run() -> None:
    p = pexpect.spawnu(" ".join(sys.argv[1:]), logfile=sys.stdout, timeout=240)

    p.expect("to continue.:")
    p.sendline("")
    p.sendline("cat /run/initramfs/rdsosreport.txt")

    p.sendline("systemctl poweroff --force")

    p.expect(pexpect.EOF)


try:
    run()
except pexpect.EOF:
    print("UNEXPECTED EOF")
    sys.exit(1)
except pexpect.TIMEOUT:
    print("TIMED OUT")
    sys.exit(1)

