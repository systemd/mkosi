#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

pandoc -t man -s -o mkosi/resources/man/mkosi.1 mkosi/resources/man/mkosi.md
pandoc -t man -s -o mkosi/resources/man/mkosi-initrd.1 mkosi/resources/man/mkosi-initrd.md
pandoc -t man -s -o mkosi/resources/man/mkosi-sandbox.1 mkosi/resources/man/mkosi-sandbox.md
