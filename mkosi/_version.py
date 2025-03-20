# SPDX-License-Identifier: LGPL-2.1-or-later
# The __version__ generation here supports the following modes
# 1. By default the version is obtained von the Python distribution's metadata on installed packages
# 2. If mkosi has not been installed as a Python package or the metadata pertains to a different mkosi than
#    is being called the version is
#    a. obtained from the environment variable MKOSI_VERSION
#    b. generated from the output of git describe
#    c. looked up in a static version file from resources
# 3. If no version can be found, it is set to "0"

import datetime
import importlib.metadata
import importlib.resources
import logging
import os
import subprocess
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from typing import Optional


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


def version_from_resources() -> Optional[str]:
    try:
        import mkosi.resources
        from mkosi.util import resource_path

        with resource_path(mkosi.resources) as resources:
            return (resources / "staticversion").read_text().strip()
    except (ImportError, FileNotFoundError):
        return None


try:
    # If the file importlib.metadata things we are talking about is not this on, let's pretend we didn't find
    # anything at all and fall back
    mkosi_files = [p for p in importlib.metadata.files("mkosi") or [] if p.name == "_version.py"]
    if not mkosi_files or os.fspath(mkosi_files[0]) != __file__:
        raise PackageNotFoundError()

    __version__ = importlib.metadata.version("mkosi")
except PackageNotFoundError:
    # This branch means, that mkosi was not installed as a package as Python is aware, this is most likely
    # the case if mkosi was run via the bin/mkosi shim in mkosi's repository.

    fallback = os.getenv("MKOSI_VERSION") or version_from_git() or version_from_resources() or "0"

    if fallback == "0":
        logging.warning("Unable to determine mkosi version")

    __version__ = fallback
