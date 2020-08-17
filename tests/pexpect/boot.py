#!/usr/bin/env python3

import pexpect
import sys


def run() -> None:
    p = pexpect.spawnu(" ".join(sys.argv[1:]), logfile=sys.stdout, timeout=240)

    p.expect("login:")
    p.sendline("root")

    p.expect("#")
    p.sendline("systemctl poweroff")

    p.expect(pexpect.EOF)


try:
    run()
except pexpect.EOF:
    print("UNEXPECTED EOF")
    sys.exit(1)
except pexpect.TIMEOUT:
    print("TIMED OUT")
    sys.exit(1)

