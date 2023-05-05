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

sed -i 's/version=".*",/version="'"$1"'",/' setup.py
sed -i "s/__version__ = \".*\"/__version__ = \"$1\"/" mkosi/__init__.py

git add -p setup.py mkosi action.yaml

git commit -m "Bump version numbers for v$1"

git tag -s "v$1" -m "mkosi $1"
