---
title: Building a bootable image on different distros
category: Tutorials
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Building a bootable image on different distros

To build a bootable image, you'll need to install a list of packages
that differs depending on the distribution. We give an overview here of
what's needed to generate a bootable image for some common
distributions:

## Arch

```conf
[Distribution]
Distribution=arch

[Content]
Bootable=yes
Packages=linux
         systemd
```

## Fedora

```conf
[Distribution]
Distribution=fedora

[Content]
Bootable=yes
Packages=kernel
         systemd
         systemd-boot
         udev
         util-linux
```

## CentOS

```conf
[Distribution]
Distribution=centos

[Content]
Bootable=yes
Packages=kernel
         systemd
         systemd-boot
         udev
```

## Debian

```conf
[Distribution]
Distribution=debian

[Content]
Bootable=yes
Packages=linux-image-generic
         systemd
         systemd-boot
         systemd-sysv
         udev
         dbus
```

## Kali

```conf
[Distribution]
Distribution=kali

[Content]
Bootable=yes
Packages=linux-image-generic
         systemd
         systemd-boot
         systemd-sysv
         udev
         dbus
```

## Ubuntu

```conf
[Distribution]
Distribution=ubuntu
Repositories=main,universe

[Content]
Bootable=yes
Packages=linux-image-generic
         systemd
         systemd-sysv
         udev
         dbus
```

## Opensuse

```conf
[Distribution]
Distribution=opensuse

[Content]
Bootable=yes
Packages=kernel-default
         systemd
         udev
```
