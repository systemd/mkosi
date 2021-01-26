# SPDX-License-Identifier: LGPL-2.1+
# PYTHON_ARGCOMPLETE_OK
import os
import sys

from . import parse_args, complete_step, run_verb, die, MkosiException


def main() -> None:
    try:
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
    except MkosiException:
        sys.exit(1)


if __name__ == "__main__":
    main()
