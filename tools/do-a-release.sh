#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+

if [ x"$1" == x ] ; then
    echo "Version number not specified."
    exit 1
fi

sed -i 's/version=".*",/version="'"$1"'",/' setup.py
sed -i "s/__version__ = \".*\"/__version__ = \"$1\"/" mkosi/__init__.py
sed -i "s/MKOSI_TAG: '.*'/MKOSI_TAG: $1/" action.yaml

git add -p setup.py mkosi action.yaml

pandoc -t man -s -o man/mkosi.1 mkosi.md
git add man/mkosi.1

git commit -m "bump version numbers for v$1"

git tag -s "v$1" -m "mkosi $1"
