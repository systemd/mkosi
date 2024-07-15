#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

pandoc -t man -s -o mkosi/resources/mkosi.1 mkosi/resources/mkosi.md
pandoc -t man -s -o mkosi/initrd/resources/mkosi-initrd.1 mkosi/initrd/resources/mkosi-initrd.md
