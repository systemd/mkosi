# Building a bootable image on different distros

To build a bootable image, you'll need to install a list of packages that differs depending on the
distribution. We give an overview here of what's needed to generate a bootable image for some common
distributions:

## Arch

```
[Content]
Packages=linux
         systemd
         dracut
```

## Fedora

```
[Content]
Packages=kernel
         systemd
         systemd-boot
         systemd-udev
         dracut
         util-linux
```

## CentOS

```
[Content]
Packages=kernel
         systemd
         systemd-boot
         systemd-udev
         dracut
```

## Debian

```
[Content]
Packages=linux-image-generic
         systemd
         systemd-boot
         systemd-sysv
         udev
         dracut
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
         dracut
         dbus
```

## Opensuse

```
[Content]
Packages=kernel-default
         dracut
         systemd
         udev
```
