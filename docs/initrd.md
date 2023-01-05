# Building a custom initrd and using it in a mkosi image

To build an image with a mkosi-built initrd:
1. Build an initrd image. You can for example build a **compressed** `cpio`
archive with mkosi containing the packages `systemd` and `udev`. Here is a
configuration file to build such an image for `Fedora`:
```
[Distribution]
Distribution=fedora

[Output]
ImageId=initrd
Format=cpio
ManifestFormat=
CompressOutput=zstd

[Content]
Packages=
        systemd
        systemd-udev
```
2. Invoke `mkosi` passing the initrd image via the `--initrd` option:
```bash
mkosi --initrd=<path-to-initrd-image> ...
```
This will build an image using the provided initrd image.
mkosi will add the kernel modules found in the distribution image to this initrd.

