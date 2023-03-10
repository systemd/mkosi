# Building a custom initrd and using it in a mkosi image

Building an image with a mkosi-built initrd is a two step process, because you will build two images - the initrd and your distribution image.
1. Build an initrd image using the `cpio` output format with the same target distribtution as you want to use for your distribution image. mkosi compresses the `cpio` output format by default.
```
[Output]
Format=cpio

[Content]
Packages=systemd
         udev
         kmod
```
2. Invoke `mkosi` passing the initrd image via the `--initrd` option or add the `Initrd=` option to your mkosi config when building your distribution image.
```bash
mkosi --initrd=<path-to-initrd-image> ...
```
This will build an image using the provided initrd image.
mkosi will add the kernel modules found in the distribution image to this initrd.

