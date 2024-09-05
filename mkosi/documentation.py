# SPDX-License-Identifier: LGPL-2.1-or-later

import logging
import subprocess
from pathlib import Path

from mkosi.config import Args, DocFormat
from mkosi.log import die
from mkosi.pager import page
from mkosi.run import find_binary, run


def show_docs(args: Args, *, resources: Path) -> None:
    if args.doc_format == DocFormat.auto:
        formats = [DocFormat.man, DocFormat.pandoc, DocFormat.markdown, DocFormat.system]
    else:
        formats = [args.doc_format]

    manual = args.cmdline[0] if args.cmdline else "mkosi"

    while formats:
        form = formats.pop(0)
        try:
            if form == DocFormat.man:
                man = resources / f"man/{manual}.1"
                if not man.exists():
                    raise FileNotFoundError()
                run(["man", "--local-file", man])
                return
            elif form == DocFormat.pandoc:
                if not find_binary("pandoc"):
                    logging.error("pandoc is not available")
                pandoc = run(
                    ["pandoc", "-t", "man", "-s", resources / f"man/{manual}.md"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    log=False,
                )
                run(["man", "--local-file", "-"], input=pandoc.stdout)
                return
            elif form == DocFormat.markdown:
                page((resources / f"man/{manual}.md").read_text(), args.pager)
                return
            elif form == DocFormat.system:
                run(["man", manual], log=False)
                return
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            if not formats:
                if isinstance(e, FileNotFoundError):
                    die("The mkosi package does not contain the man page {manual:r}.")
                raise e
