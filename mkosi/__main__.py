# SPDX-License-Identifier: LGPL-2.1+
# PYTHON_ARGCOMPLETE_OK

import faulthandler
import signal
import sys
from types import FrameType
from typing import Optional

from mkosi import run_verb
from mkosi.config import parse_config
from mkosi.log import log_setup
from mkosi.run import find_binary, run, uncaught_exception_handler
from mkosi.util import INVOKING_USER


def onsigterm(signal: int, frame: Optional[FrameType]) -> None:
    raise KeyboardInterrupt()


@uncaught_exception_handler()
def main() -> None:
    signal.signal(signal.SIGTERM, onsigterm)

    log_setup()
    # Ensure that the name and home of the user we are running as are resolved as early as possible.
    INVOKING_USER.init()
    args, images = parse_config(sys.argv[1:])

    if args.debug:
        faulthandler.enable()

    try:
        run_verb(args, images)
    finally:
        if sys.stderr.isatty() and find_binary("tput"):
            run(["tput", "cnorm"], check=False)
            run(["tput", "smam"], check=False)


if __name__ == "__main__":
    main()
