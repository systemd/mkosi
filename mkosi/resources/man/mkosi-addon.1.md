% mkosi-addon(1)
%
%

# NAME

mkosi-addon — Build addons for unified kernel images for the current system
using mkosi

# SYNOPSIS

`mkosi-addon [options…]`

# DESCRIPTION

`mkosi-addon` is wrapper on top of `mkosi` to simplify the generation of
addons containing customizations for a Unified Kernel Images specific for the
current running system. Will include entries in `/etc/crypttab` marked with
`x-initrd.attach`, `/etc/kernel/cmdline`, kernel modules, firmwares and microcode
for the running hardware.

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

`--debug=`
:   Enable additional debugging output.

`--debug-shell=`
:   Spawn debug shell in sandbox if a sandboxed command fails.

`--version`
:   Show package version.

`--help`, `-h`
:   Show brief usage information.

# SEE ALSO
`mkosi(1)`
