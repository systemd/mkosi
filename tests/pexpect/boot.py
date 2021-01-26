#!/usr/bin/env python3

import pexpect
import sys
import time


def run() -> None:
    p = pexpect.spawnu(" ".join(sys.argv[1:]), logfile=sys.stdout, timeout=240)

    p.expect("login:")
    p.sendline("root")

    time.sleep(15)

    s = pexpect.spawnu("mkosi ssh", logfile=sys.stdout)
    s.expect("#")

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
