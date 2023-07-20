# SPDX-License-Identifier: LGPL-2.1+
# PYTHON_ARGCOMPLETE_OK

import contextlib
import logging
import subprocess
import sys
from collections.abc import Iterator

from mkosi import run_verb
from mkosi.config import MkosiConfigParser
from mkosi.log import ARG_DEBUG, log_setup
from mkosi.run import ensure_exc_info


@contextlib.contextmanager
def propagate_failed_return() -> Iterator[None]:
    try:
        yield
    except SystemExit as e:
        if ARG_DEBUG.get():
            sys.excepthook(*ensure_exc_info())

        sys.exit(e.code)
    except KeyboardInterrupt:
        if ARG_DEBUG.get():
            sys.excepthook(*ensure_exc_info())
        else:
            logging.error("Interrupted")

        sys.exit(1)
    except subprocess.CalledProcessError as e:
        if ARG_DEBUG.get():
            sys.excepthook(*ensure_exc_info())

        # We always log when subprocess.CalledProcessError is raised, so we don't log again here.
        sys.exit(e.returncode)


@propagate_failed_return()
def main() -> None:
    log_setup()
    args, presets = MkosiConfigParser().parse()

    if ARG_DEBUG.get():
        logging.getLogger().setLevel(logging.DEBUG)

    run_verb(args, presets)


if __name__ == "__main__":
    main()
