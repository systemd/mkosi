# SPDX-License-Identifier: LGPL-2.1-or-later
# The __version__ generation here supports the following modes
# 1. The version is obtained from the environment variable MKOSI_VERSION, to trump all other e.g. for
#    debugging purposes
# 2. By default the version is obtained von the Python distribution's metadata on installed packages, unless
#    a. the installed version of mkosi lacks this file
#    b. the path of that file is not equal to the path of this particular file
# 3. If mkosi has not been installed as a Python package or the metadata pertains to a different mkosi than
#    is being called the version is
#    b. generated from the output of git describe
#    c. looked up in a static version file from resources
# 4. If no version can be found, it is set to "0"

import datetime
import importlib.metadata
import logging
import os
import subprocess
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from typing import Optional


def version_from_metadata() -> Optional[str]:
    try:
        dist = importlib.metadata.distribution("mkosi")

        this_file = dist.locate_file("mkosi/_version.py")
        # If the installed version is too old, it might not have the _version.py file
        if not this_file.exists():
            return None

        # If the file importlib.metadata thinks we are talking about is not this one, let's pretend we didn't
        # find anything at all and fall back
        if this_file != Path(__file__):
            return None

        return importlib.metadata.version("mkosi")
    except PackageNotFoundError:
        return None


def version_from_git() -> Optional[str]:
    try:
        p = subprocess.run(
            ["git", "describe"],
            cwd=Path(__file__).parent.parent,
            check=True,
            text=True,
            capture_output=True,
        )
        # output has form like v25.3-244-g8f491df9 when not on a tag, else just the tag
        tag, *rest = p.stdout.strip().split("-")
        tag = tag.lstrip("v")
        if rest:
            numcommits, commit = rest
            return f"{tag}.post1.dev{numcommits}+{commit}.d{datetime.datetime.now():%Y%m%d}"

        # we are exactly on a tag
        return tag
    except (subprocess.CalledProcessError, NotADirectoryError, FileNotFoundError):
        return None


def version_from_static() -> Optional[str]:
    try:
        import mkosi._staticversion

        return mkosi._staticversion.__version__
    except ImportError:
        return None


def version_fallback() -> str:
    logging.warning("Unable to determine mkosi version")
    return "0"


__version__ = (
    os.getenv("MKOSI_VERSION")
    or version_from_metadata()
    or version_from_git()
    or version_from_static()
    or version_fallback()
)
