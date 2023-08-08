# Building a bootable image on different distros

To build a bootable image, you'll need to install a list of packages that differs depending on the
distribution. We give an overview here of what's needed to generate a bootable image for some common
distributions:

## Arch

```
[Content]
Packages=linux
         systemd
```

## Fedora

```
[Content]
Packages=kernel
         systemd
         systemd-boot
         udev
         util-linux
```

## CentOS

```
[Content]
Packages=kernel
         systemd
         systemd-boot
         udev
```

## Debian

```
[Content]
Packages=linux-image-generic
         systemd
         systemd-boot
         systemd-sysv
         udev
         dbus
```

## Ubuntu

```
[Content]
Repositories=main,universe
Packages=linux-image-generic
         systemd
         systemd-sysv
         udev
         dbus
```

## Opensuse

```
[Content]
Packages=kernel-default
         systemd
         udev
```
