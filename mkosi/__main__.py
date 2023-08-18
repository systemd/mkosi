# SPDX-License-Identifier: LGPL-2.1+
# PYTHON_ARGCOMPLETE_OK

import contextlib
import logging
import shutil
import subprocess
import sys
from collections.abc import Iterator

from mkosi import run_verb
from mkosi.config import MkosiConfigParser
from mkosi.log import ARG_DEBUG, log_setup
from mkosi.run import ensure_exc_info, run


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
        # Failures from qemu, ssh and systemd-nspawn are expected and we won't log stacktraces for those.
        if ARG_DEBUG.get() and e.cmd and e.cmd[0] not in ("qemu", "ssh", "systemd-nspawn"):
            sys.excepthook(*ensure_exc_info())

        # We always log when subprocess.CalledProcessError is raised, so we don't log again here.
        sys.exit(e.returncode)


@propagate_failed_return()
def main() -> None:
    log_setup()
    args, presets = MkosiConfigParser().parse()

    if ARG_DEBUG.get():
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        run_verb(args, presets)
    finally:
        if sys.stderr.isatty() and shutil.which("tput"):
            run(["tput", "cnorm"])
            run(["tput", "smam"])


if __name__ == "__main__":
    main()
