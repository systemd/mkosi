#!/usr/bin/env bash

BUILDDIR=$(mktemp -d -q)
cleanup() {
    rm -rf "$BUILDDIR"
}
trap cleanup EXIT

mkdir -p builddir

cp -r mkosi "${BUILDDIR}/"

python3 -m zipapp \
        -p "/usr/bin/env python3" \
        -o builddir/mkosi \
        -m mkosi.__main__:main \
        "$BUILDDIR"
