#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

pandoc -t man -s -o mkosi/resources/man/mkosi.1 mkosi/resources/man/mkosi.1.md
pandoc -t man -s -o mkosi/resources/man/mkosi-initrd.1 mkosi/resources/man/mkosi-initrd.1.md
pandoc -t man -s -o mkosi/resources/man/mkosi-sandbox.1 mkosi/resources/man/mkosi-sandbox.1.md
pandoc -t man -s -o mkosi/resources/man/mkosi.news.7 mkosi/resources/man/mkosi.news.7.md
