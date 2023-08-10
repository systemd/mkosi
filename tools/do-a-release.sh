#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+

if [ -z "$1" ] ; then
    echo "Version number not specified."
    exit 1
fi

if ! git diff-index --quiet HEAD; then
    echo "Repo has modified files."
    exit 1
fi

sed -r -i "s/^version = \".*\"$/version = \"$1\"/" pyproject.toml
sed -r -i "s/^__version__ = \".*\"$/__version__ = \"$1\"/" mkosi/config.py

git add -p pyproject.toml mkosi

git commit -m "Bump version numbers for v$1"

git tag -s "v$1" -m "mkosi $1"
