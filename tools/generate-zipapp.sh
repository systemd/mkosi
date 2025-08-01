#!/bin/bash

BUILDDIR=$(mktemp -d -q)
cleanup() {
    rm -rf "$BUILDDIR"
}
trap cleanup EXIT

mkdir -p builddir

cp -r mkosi "${BUILDDIR}/"

# HACK: importlib metadata doesn't seem to be there in a zipapp even if
# properly installed via pip, so let's patch it in there manually.
mkosiversion="$(python3 -m mkosi --version)"
printf '# SPDX-License-Identifier: LGPL-2.1-or-later\n__version__ = "%s"\n' \
       "${mkosiversion#mkosi }" \
       >"${BUILDDIR}/mkosi/_staticversion.py"

python3 -m zipapp \
        -p "/usr/bin/env python3" \
        -o builddir/mkosi \
        -m mkosi.__main__:main \
        "$BUILDDIR"
