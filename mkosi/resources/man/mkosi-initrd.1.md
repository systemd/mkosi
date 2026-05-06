---
title: mkosi-initrd(1)
category: Manuals
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# NAME

mkosi-initrd — Build initrds or unified kernel images for the current system
using mkosi

# SYNOPSIS

`mkosi-initrd [options…]`

# DESCRIPTION

**mkosi-initrd** is wrapper on top of **mkosi** to simplify the generation of
initrds and Unified Kernel Images for the current running system.

# OPTIONS

`--kernel-version=`, `-k`
:   Kernel version where to look for the kernel modules to include. Defaults to
    the kernel version of the running system (`uname -r`).

`--format=`, `-t`
:   Output format. One of `cpio` (CPIO archive), `uki` (a unified kernel image
    with the image in the `.initrd` PE section) or `directory` (for generating
    an image directly in a local directory). Defaults to `cpio`.

`--output=`, `-o`
:   Name to use for the generated output image file or directory. Defaults
    to `initrd`.

`--output-dir=`, `-O`
:   Path to a directory where to place all generated artifacts. Defaults to the
    current working directory.

`--generic`, `-g`
:   Build a generic initrd without host-specific kernel modules, which should
    allow the local system to boot on different hardware, although it's tied to
    the kernel version of the running system or set with `--kernel-version=`.

`--profile=`
:   Set the profiles to enable for the initrd. By default, all profiles are
    disabled.

    The `lvm` profile enables support for LVM.
    The `network` profile enables support for network via **systemd-networkd**.
    The `nfs` profile enables support for NFS. It requires networking in the
    initrd, using the `network` profile, or some other custom method.
    The `pkcs11` profile enables support for PKCS#11.
    The `plymouth` profile provides a graphical interface at boot (animation and
    password prompt).
    The `raid` profile enables support for RAID arrays.

`--debug`
:   Enable additional debugging output.

`--debug-shell`
:   Spawn debug shell in sandbox if a sandboxed command fails.

`--debug-sandbox`
:   Run **mkosi-sandbox** with **strace**.

`--show-documentation`, `-D`
:   Show the man page for mkosi-initrd.

`--show-summary`, `-S`
:   Show the summary of configuration.

`--version`
:   Show package version.

`--help`, `-h`
:   Show brief usage information.

# CONFIGURATION

Configuration for `mkosi-initrd` is read from
`/usr/lib`, `/usr/local/lib`, `/run`, `/etc`,
in increasing order of priority.
Under any of those directories,
`mkosi.conf.d/` can be used for config files,
`mkosi.extra/` can be used for extra files to include in the initrd,
and so on.
See the **Configuration Settings** and **FILES** sections in **mkosi**(1) for full details.

For configuration files, use drop-ins,
e.g. `/etc/mkosi-initrd/mkosi.conf.d/local.conf`.

# SEE ALSO
**mkosi**(1)
