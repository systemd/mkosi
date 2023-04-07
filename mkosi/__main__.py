# SPDX-License-Identifier: LGPL-2.1+
# PYTHON_ARGCOMPLETE_OK

import contextlib
import os
import sys
from collections.abc import Iterator
from subprocess import CalledProcessError

from mkosi import parse_args, run_verb
from mkosi.log import MkosiException, die
from mkosi.run import excepthook


@contextlib.contextmanager
def propagate_failed_return() -> Iterator[None]:
    try:
        yield
    except MkosiException as e:
        cause = e.__cause__
        if cause and isinstance(cause, CalledProcessError):
            sys.exit(cause.returncode)
        sys.exit(1)


@propagate_failed_return()
def main() -> None:
    args = parse_args()

    if args.directory:
        if args.directory.isdir():
            os.chdir(args.directory)
        else:
            die(f"Error: {args.directory} is not a directory!")

    run_verb(args)


if __name__ == "__main__":
    sys.excepthook = excepthook
    main()
