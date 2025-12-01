#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

MD_DIR=mkosi/resources/man
OUTPUT_DIR=mkosi/resources/man

for mdfile in "$MD_DIR"/*.?.md; do
    pandoc \
    --lua-filter=mkosi/resources/pandoc/md2man.lua \
    -s -t man \
    -o  "${OUTPUT_DIR}/$(basename "${mdfile}" .md)" \
    "${mdfile}"
done
