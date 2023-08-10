#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1+
set -ex

pandoc -t man -s -o mkosi/resources/mkosi.1 mkosi/resources/mkosi.md
