# SPDX-License-Identifier: LGPL-2.1-or-later
# PYTHON_ARGCOMPLETE_OK

import faulthandler
import signal
import sys
from types import FrameType
from typing import Optional

import mkosi.resources
from mkosi import run_verb
from mkosi.config import parse_config
from mkosi.log import log_setup, stash_terminal_title
from mkosi.run import find_binary, run, uncaught_exception_handler
from mkosi.util import resource_path

INTERRUPTED = False


def onsignal(signal: int, frame: Optional[FrameType]) -> None:
    global INTERRUPTED
    if INTERRUPTED:
        return

    INTERRUPTED = True
    raise KeyboardInterrupt()


@uncaught_exception_handler()
def main() -> None:
    signal.signal(signal.SIGINT, onsignal)
    signal.signal(signal.SIGTERM, onsignal)
    signal.signal(signal.SIGHUP, onsignal)

    log_setup()

    with resource_path(mkosi.resources) as resources, stash_terminal_title():
        args, tools, images = parse_config(sys.argv[1:], resources=resources)

        if args.debug:
            faulthandler.enable()

        try:
            run_verb(args, tools, images, resources=resources)
        finally:
            if sys.stderr.isatty() and find_binary("tput"):
                run(["tput", "cnorm"], check=False)
                run(["tput", "smam"], check=False)


if __name__ == "__main__":
    main()
