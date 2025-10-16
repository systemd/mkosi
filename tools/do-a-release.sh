#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

if [ -z "$1" ] ; then
    echo "Version number not specified."
    exit 1
fi

VERSION="$1"

if ! git diff-index --quiet HEAD; then
    echo "Repo has modified files."
    exit 1
fi

printf '# SPDX-License-Identifier: LGPL-2.1-or-later\n__version__ = "%s"\n' \
       "${VERSION}.post0" \
       >mkosi/_staticversion.py

git add -p pyproject.toml mkosi

git commit -m "Release $VERSION"

git tag -s "v$VERSION" -m "mkosi $VERSION"

VERSION_MAJOR=${VERSION%%.*}
VERSION="$((VERSION_MAJOR + 1))~devel"

git add -p mkosi

git commit -m "Bump version to $VERSION"
