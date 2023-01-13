# SPDX-License-Identifier: LGPL-2.1+
# PYTHON_ARGCOMPLETE_OK

import contextlib
import os
import sys
from collections.abc import Iterator
from subprocess import CalledProcessError

from mkosi import complete_step, parse_args, run_verb
from mkosi.backend import MkosiException, die


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

    for job_name, a in args.items():
        # Change working directory if --directory is passed
        if a.directory:
            work_dir = a.directory
            if os.path.isdir(work_dir):
                os.chdir(work_dir)
            else:
                die(f"Error: {work_dir} is not a directory!")
        if len(args) > 1:
            with complete_step(f"Processing {job_name}"):
                run_verb(a)
        else:
            run_verb(a)


if __name__ == "__main__":
    main()
