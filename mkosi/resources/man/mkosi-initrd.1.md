% mkosi-initrd(1)
%
%

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

`--workspace-dir=`
:   Path to a directory where to store data required temporarily while
    building the image. Defaults to `/var/tmp`.

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

`--version`
:   Show package version.

`--help`, `-h`
:   Show brief usage information.

# SEE ALSO
`mkosi(1)`
