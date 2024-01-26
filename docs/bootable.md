---
title: Building a bootable image on different distros
category: Tutorials
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Building a bootable image on different distros

To build a bootable image, you'll need to install a list of packages that differs depending on the
distribution. We give an overview here of what's needed to generate a bootable image for some common
distributions:

## Arch

```conf
[Content]
Packages=linux
         systemd
```

## Fedora

```conf
[Content]
Packages=kernel
         systemd
         systemd-boot
         udev
         util-linux
```

## CentOS

```conf
[Content]
Packages=kernel
         systemd
         systemd-boot
         udev
```

## Debian

```conf
[Content]
Packages=linux-image-generic
         systemd
         systemd-boot
         systemd-sysv
         udev
         dbus
```

## Ubuntu

```conf
[Content]
Repositories=main,universe
Packages=linux-image-generic
         systemd
         systemd-sysv
         udev
         dbus
```

## Opensuse

```conf
[Content]
Packages=kernel-default
         systemd
         udev
```
