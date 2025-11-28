#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2086 # Allow word splitting on bare vars
set -ex

PANDOC_ARGS="--lua-filter=mkosi/resources/pandoc/md2man.lua -t man -s"
pandoc $PANDOC_ARGS -o mkosi/resources/man/mkosi.1 mkosi/resources/man/mkosi.1.md
pandoc $PANDOC_ARGS -o mkosi/resources/man/mkosi-addon.1 mkosi/resources/man/mkosi-addon.1.md
pandoc $PANDOC_ARGS -o mkosi/resources/man/mkosi-initrd.1 mkosi/resources/man/mkosi-initrd.1.md
pandoc $PANDOC_ARGS -o mkosi/resources/man/mkosi-sandbox.1 mkosi/resources/man/mkosi-sandbox.1.md
pandoc $PANDOC_ARGS -o mkosi/resources/man/mkosi.news.7 mkosi/resources/man/mkosi.news.7.md
