#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+

if [ -z "$1" ] ; then
    echo "Version number not specified."
    exit 1
fi

VERSION="$1"

if ! git diff-index --quiet HEAD; then
    echo "Repo has modified files."
    exit 1
fi

sed -r -i "s/^version = \".*\"$/version = \"$VERSION\"/" pyproject.toml
sed -r -i "s/^__version__ = \".*\"$/__version__ = \"$VERSION\"/" mkosi/config.py

git add -p pyproject.toml mkosi

git commit -m "Release $VERSION"

git tag -s "v$VERSION" -m "mkosi $VERSION"

VERSION="$((VERSION + 1))~devel"

sed -r -i "s/^version = \".*\"$/version = \"$VERSION\"/" pyproject.toml
sed -r -i "s/^__version__ = \".*\"$/__version__ = \"$VERSION\"/" mkosi/config.py
