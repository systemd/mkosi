---
title: mkosi-addon(1)
category: Manuals
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# NAME

mkosi-addon — Build addons for unified kernel images for the current system
using mkosi

# SYNOPSIS

`mkosi-addon [options…]`

# DESCRIPTION

**mkosi-addon** is a wrapper on top of **mkosi** to simplify the generation of
PE addons containing customizations for unified kernel images specific to the
running or local system. Will include entries in `/etc/crypttab` marked with
`x-initrd.attach`, and `/etc/kernel/cmdline`. Kernel modules and firmwares for
the running hardware can be included if a local configuration with the option
`KernelModulesIncludeHost=` is provided.

# OPTIONS

`--kernel-version=`
:   Kernel version where to look for the kernel modules to include. Defaults to
    the kernel version of the running system (`uname -r`).

`--output=`, `-o`
:   Name to use for the generated output addon. Defaults to
    `mkosi-local.addon.efi`.

`--output-dir=`, `-O`
:   Path to a directory where to place all generated artifacts. Defaults to the
    current working directory.

`--debug`
:   Enable additional debugging output.

`--debug-shell`
:   Spawn debug shell in sandbox if a sandboxed command fails.

`--debug-sandbox`
:   Run **mkosi-sandbox** with **strace**.

`--version`
:   Show package version.

`--help`, `-h`
:   Show brief usage information.

# SEE ALSO
`mkosi(1)`
