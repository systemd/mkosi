#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+

if [ x"$1" == x ] ; then
    echo "Version number not specified."
    exit 1
fi

sed -ie "s/__version__ = '.*'/__version__ = '$1'/" src/mkosi.py

git add -p src/mkosi.py

git commit -m "bump version numbers for v$1"

git tag -s "v$1" -m "mkosi $1"

mkdir -p build && python3 -m zipapp src -m mkosi:main -p "/usr/bin/env python3" -o build/mkosi
echo "Add build/mkosi as a release artifact to the release on Github!"
