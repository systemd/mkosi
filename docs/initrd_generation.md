---
title: On initrd files in mkosi
category: Tutorials
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Introduction

To boot a Linux system, a kernel image and an initrd file are required. The initrd
provides the early userspace, including `init` and its supporting files, as
well as any kernel modules and firmware needed to mount the root filesystem and
continue the boot process. On modern systems, the initrd may be embedded into a
[UKI](https://wiki.archLinux.org/title/Unified_kernel_image) rather than provided
as a separate file.

When building a bootable image with `mkosi`, an initrd is generated as part of
the build. By default, `SplitArtifacts=` includes the `initrd` option, so a copy
of the final initrd is saved alongside other build artifacts.

If you inspect this initrd file using common tools such as `lsinitrd` or
`unmkinitramfs`, you may notice that kernel modules and firmware files do not
appear in the output. To understand why, it is necessary to examine the internal
structure of initrd files.

# Structure of initrd Files

Historically, an initrd file has consisted of multiple components. The first
component, commonly referred to as the *early cpio*, is an optional, uncompressed
cpio archive containing CPU microcode updates. The kernel attempts to locate and
apply these updates very early in the boot process.

The remainder of the initrd contains the early userspace, loadable kernel
modules, and firmware files. In early Linux systems, these files were stored
as a filesystem image, typically using ext2. This approach was later replaced
by the use of an initramfs, which stores files in one or more cpio archives
rather than in a filesystem image. The terms are often used interchangeably,
though strictly speaking initrd and initramfs are different formats used
for the same purpose. `mkosi` uses the term "initrd" universally to refer
these file, while some distros refer to as the initramfs file.


From the beginning, the
[kernel code](https://github.com/torvalds/Linux/blob/1da177e4c3f41524e886b7f1b8a0c1fc7321cac2/init/initramfs.c#L511)
responsible for extracting the initramfs has
[supported](https://www.kernel.org/doc/html/v6.18/driver-api/early-userspace/buffer-format.html)
multiple concatenated cpio archives, each optionally compressed. These
archives are unpacked sequentially to populate the in-memory `rootfs` used
during early boot.

`mkosi` uses this mechanism to split the initramfs into distinct parts:

* **Default initrd**: contains only the early userspace, primarily `init` and its
  supporting files. This archive is kernel-version independent.
* **Kernel Modules initrd**: contains kernel modules and firmware files, which
  are specific to a particular kernel version.

For historical reasons, commonly used initrd inspection tools such as
`lsinitrd`, `unmkinitramfs`, and even newer tools like `3cpio`, only process the
early cpio and the first cpio archive in the initrd. Any additional concatenated
archives are ignored.

As a result, kernel modules included in the "kmod initrd" do not appear when inspecting a
typical `mkosi`-generated initrd with these tools.

# Inspecting the Kernel Modules initrd

To work around the limitations of existing tools, `mkosi` provides the
`SplitArtifacts=kernel-modules-initrd` option. When enabled, `mkosi` saves the
"kmod initrd" as a separate file, making it directly inspectable.

The "kmod initrd" is a cpio archive, optionally compressed, and can be examined using
standard tools:

```console
# List contents using lsinitrd
$ lsinitrd my_image.kernel-modules-initrd

# Or inspect directly using cpio
$ cat my_image.kernel-modules-initrd | cpio -itv
```

# How mkosi Builds the initrd

There are some nuances to the way `mkosi` generates the "kmod initrd" which you should
familiarize yourself with.

The "default initrd" is built as a standalone image. In contrast, the "kmod initrd" is
generated as a sub-step of the main image build. During this step, `mkosi`
examines the filesystem of the main image to locate kernel modules and firmware
files to include in the "kmod initrd". Consequently, if required firmware packages are not
listed in the main configuration's `Packages=` option, they will not be present
in the "kmod initrd" and will be unavailable during early boot.

Kernel module selection is controlled by two options:

* `KernelModules=` determines which modules are included in the main image.
* `InitrdKernelModules=` determines which modules are included in the "kmod initrd".

Both options support glob patterns to specify inclusion and exclusion rules.
Module filtering is performed relative to the kernel modules present in the
main image filesystem. Module and firmware dependencies of selected modules
are resolved automatically and included as needed.

To reduce image size, `mkosi` removes unused kernel modules and firmware files.
Because `KernelModules=` is processed first, any modules not selected are deleted
after dependency resolution. When the "kmod initrd" build step later processes
`InitrdKernelModules=`, it can only select from modules that survived this earlier
pruning. As a result, the "kmod initrd" is limited to modules already included in
`KernelModules=`. This behavior is a known limitation and may be addressed in
future versions.

The "default initrd" configuration shipped with `mkosi` specifies a default set of
modules via `KernelModules=`. Although this configuration appears to belong to
the "default initrd", it actually determines which modules are included in the "kmod initrd"
Kernel modules are never included in the "default initrd" itself, as it is intended
to remain kernel-independent.

Firmware inclusion is controlled using the `FirmwareFiles=` option. At present,
this option applies uniformly to both the main image and the "kmod initrd"; you cannot
control the firmware they include for each separately.

After the "kmod initrd" is generated, it is saved as a standalone artifact if
`SplitArtifacts=kernel-modules-initrd` is enabled. If a Unified Kernel Image is
used, the "kmod initrd" is then embedded into the UKI.

# Additional Features

`mkosi` supports several other initrd-related features, including:

1. Secure Boot signing as part of a UKI
2. dm-verity support
3. Profiles
4. Custom initrd images
5. User-provided initrd files

Refer to the `mkosi` man page for detailed documentation.
