Title: A re-introduction to mkosi -- A Tool for Generating OS Images
Date: 2024-01-10

> This is a guest post written by Daan De Meyer, systemd and mkosi
> maintainer

Almost 7 years ago, Lennart first
[wrote](https://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html)
about `mkosi` on this blog. Some years ago, I took over development and
there's been a huge amount of changes and improvements since then. So I
figure this is a good time to re-introduce `mkosi`.

[`mkosi`](https://github.com/systemd/mkosi) stands for *Make Operating
System Image*. It generates OS images that can be used for a variety of
purposes.

If you prefer watching a video over reading a blog post, you can also
watch my [presentation](https://www.youtube.com/watch?v=6EelcbjbUa8) on
`mkosi` at All Systems Go 2023.

## What is mkosi?

`mkosi` was originally written as a tool to simplify hacking on systemd
and for experimenting with images using many of the new concepts being
introduced in systemd at the time. In the meantime, it has evolved into
a general purpose image builder that can be used in a multitude of
scenarios.

Instructions to install `mkosi` can be found in its
[readme](https://github.com/systemd/mkosi/blob/main/README.md). We
recommend running the latest version to take advantage of all the latest
features and bug fixes. You'll also need `bubblewrap` and the package
manager of your favorite distribution to get started.

At its core, the workflow of `mkosi` can be divided into 3 steps:

1. Generate an OS tree for some distribution by installing a set of
   packages.
2. Package up that OS tree in a variety of output formats.
3. (Optionally) Boot the resulting image in `qemu` or `systemd-nspawn`.

Images can be built for any of the following distributions:

- Fedora Linux
- Ubuntu
- OpenSUSE
- Debian
- Arch Linux
- CentOS Stream
- RHEL
- Rocky Linux
- Alma Linux

And the following output formats are supported:

- GPT disk images built with `systemd-repart`
- Tar archives
- CPIO archives (for building initramfs images)
- USIs (Unified System Images which are full OS images packed in a UKI)
- Sysext, confext and portable images
- Directory trees

For example, to build an Arch Linux GPT disk image and boot it in
`qemu`, you can run the following command:

```sh
$ mkosi -d arch -p systemd -p udev -p linux -t disk qemu
```

To instead boot the image in systemd-nspawn, replace `qemu` with `boot`:

```sh
$ mkosi -d arch -p systemd -p udev -p linux -t disk boot
```

The actual image can be found in the current working directory named
`image.raw`. However, using a separate output directory is recommended
which is as simple as running `mkdir mkosi.output`.

To rebuild the image after it's already been built once, add `-f` to the
command line before the verb to rebuild the image. Any arguments passed
after the verb are forwarded to either `systemd-nspawn` or `qemu`
itself. To build the image without booting it, pass `build` instead of
`boot` or `qemu` or don't pass a verb at all.

By default, the disk image will have an appropriately sized root
partition and an ESP partition, but the partition layout and contents
can be fully customized using `systemd-repart` by creating partition
definition files in `mkosi.repart/`. This allows you to customize the
partition as you see fit:

- The root partition can be encrypted.
- Partition sizes can be customized.
- Partitions can be protected with signed dm-verity.
- You can opt out of having a root partition and only have a /usr
  partition instead.
- You can add various other partitions, e.g. an XBOOTLDR partition or a
  swap partition.
- ...

As part of building the image, we'll run various tools such as
`systemd-sysusers`, `systemd-firstboot`, `depmod`, `systemd-hwdb` and
more to make sure the image is set up correctly.

## Configuring mkosi image builds

Naturally with extended use you don't want to specify all settings on
the command line every time, so `mkosi` supports configuration files
where the same settings that can be specified on the command line can be
written down.

For example, the command we used above can be written down in a
configuration file `mkosi.conf`:

```conf
[Distribution]
Distribution=arch

[Output]
Format=disk

[Content]
Packages=
        systemd
        udev
        linux
```

Like systemd, `mkosi` uses INI configuration files. We also support
dropins which can be placed in `mkosi.conf.d`. Configuration files can
also be conditionalized using the `[Match]` section. For example, to
only install a specific package on Arch Linux, you can write the
following to `mkosi.conf.d/10-arch.conf`:

```conf
[Match]
Distribution=arch

[Content]
Packages=pacman
```

Because not everything you need will be supported in `mkosi`, we support
running scripts at various points during the image build process where
all extra image customization can be done. For example, if it is found,
`mkosi.postinst` is called after packages have been installed. Scripts
are executed on the host system by default (in a sandbox), but can be
executed inside the image by suffixing the script with `.chroot`, so if
`mkosi.postinst.chroot` is found it will be executed inside the image.

To add extra files to the image, you can place them in `mkosi.extra` in
the source directory and they will be automatically copied into the
image after packages have been installed.

## Bootable images

If the necessary packages are installed, `mkosi` will automatically
generate a UEFI/BIOS bootable image. As `mkosi` is a systemd project, it
will always build
[UKIs](https://uapi-group.org/specifications/specs/unified_kernel_image/)
(Unified Kernel Images), except if the image is BIOS-only (since UKIs
cannot be used on BIOS). The initramfs is built like a regular image by
installing distribution packages and packaging them up in a CPIO archive
instead of a disk image. Specifically, we do not use `dracut`,
`mkinitcpio` or `initramfs-tools` to generate the initramfs from the
host system. `ukify` is used to assemble all the individual components
into a UKI.

If you don't want `mkosi` to generate a bootable image, you can set
`Bootable=no` to explicitly disable this logic.

## Using mkosi for development

The main requirements to use `mkosi` for development is that we can
build our source code against the image we're building and install it
into the image we're building. `mkosi` supports this via build scripts.
If a script named `mkosi.build` (or `mkosi.build.chroot`) is found,
we'll execute it as part of the build. Any files put by the build script
into `$DESTDIR` will be installed into the image. Required build
dependencies can be installed using the `BuildPackages=` setting. These
packages are installed into an overlay which is put on top of the image
when running the build script so the build packages are available when
running the build script but don't end up in the final image.

An example `mkosi.build.chroot` script for a project using `meson` could
look as follows:

```sh
#!/bin/sh
meson setup "$BUILDDIR" "$SRCDIR"
ninja -C "$BUILDDIR"
if ((WITH_TESTS)); then
    meson test -C "$BUILDDIR"
fi
meson install -C "$BUILDDIR"
```

Now, every time the image is built, the build script will be executed
and the results will be installed into the image.

The `$BUILDDIR` environment variable points to a directory that can be
used as the build directory for build artifacts to allow for incremental
builds if the build system supports it.

Of course, downloading all packages from scratch every time and
re-installing them again every time the image is built is rather slow,
so `mkosi` supports two modes of caching to speed things up.

The first caching mode caches all downloaded packages so they don't have
to be downloaded again on subsequent builds. Enabling this is as simple
as running `mkdir mkosi.cache`.

The second mode of caching caches the image after all packages have been
installed but before running the build script. On subsequent builds,
`mkosi` will copy the cache instead of reinstalling all packages from
scratch. This mode can be enabled using the `Incremental=` setting.
While there is some rudimentary cache invalidation, the cache can also
forcibly be rebuilt by specifying `-ff` on the command line instead of
`-f`.

Note that when running on a btrfs filesystem, `mkosi` will automatically
use subvolumes for the cached images which can be snapshotted on
subsequent builds for even faster rebuilds. We'll also use reflinks to
do copy-on-write copies where possible.

With this setup, by running `mkosi -f qemu` in the systemd repository,
it takes about 40 seconds to go from a source code change to a root
shell in a virtual machine running the latest systemd with your change
applied. This makes it very easy to test changes to systemd in a safe
environment without risk of breaking your host system.

Of course, while 40 seconds is not a very long time, it's still more
than we'd like, especially if all we're doing is modifying the kernel
command line. That's why we have the `KernelCommandLineExtra=` option to
configure kernel command line options that are passed to the container
or virtual machine at runtime instead of being embedded into the image.
These extra kernel command line options are picked up when the image is
booted with qemu's direct kernel boot (using `-append`), but also when
booting a disk image in UEFI mode (using SMBIOS). The same applies to
systemd credentials (using the `Credentials=` setting). These settings
allow configuring the image without having to rebuild it, which means
that you only have to run `mkosi qemu` or `mkosi boot` again afterwards
to apply the new settings.

## Building images without root privileges and loop devices

By using `newuidmap`/`newgidmap` and `systemd-repart`, `mkosi` is able to
build images without needing root privileges. As long as proper subuid
and subgid mappings are set up for your user in `/etc/subuid` and
`/etc/subgid`, you can run `mkosi` as your regular user without having
to switch to `root`.

Note that as of the writing of this blog post this only applies to the
`build` and `qemu` verbs. Booting the image in a `systemd-nspawn`
container with `mkosi boot` still needs root privileges. We're hoping to
fix this in an future systemd release.

Regardless of whether you're running `mkosi` with root or without root,
almost every tool we execute is invoked in a sandbox to isolate as much
of the build process from the host as possible. For example, `/etc` and
`/var` from the host are not available in this sandbox, to avoid host
configuration inadvertently affecting the build.

Because `systemd-repart` can build disk images without loop devices,
`mkosi` can run from almost any environment, including containers. All
that's needed is a UID range with 65536 UIDs available, either via
running as the root user or via `/etc/subuid` and `newuidmap`. In a
future systemd release, we're hoping to provide an alternative to
`newuidmap` and `/etc/subuid` to allow running `mkosi` from all
containers, even those with only a single UID available.

## Supporting older distributions

mkosi depends on very recent versions of various systemd tools (v254 or
newer). To support older distributions, we implemented so called tools
trees. In short, `mkosi` can first build a tools image for you that
contains all required tools to build the actual image. This can be
enabled by adding `ToolsTree=default` to your mkosi configuration.
Building a tools image does not require a recent version of systemd.

In the systemd mkosi configuration, we automatically use a tools tree if
we detect your distribution does not have the minimum required systemd
version installed.

## Configuring variants of the same image using profiles

Profiles can be defined in the `mkosi.profiles/` directory. The profile
to use can be selected using the `Profile=` setting (or `--profile=`) on
the command line. A profile allows you to bundle various settings behind
a single recognizable name. Profiles can also be matched on if you want
to apply some settings only to a few profiles.

For example, you could have a `bootable` profile that sets
`Bootable=yes`, adds the `linux` and `systemd-boot` packages and
configures `Format=disk` to end up with a bootable disk image when
passing `--profile bootable` on the kernel command line.

## Building system extension images

[System extension](https://uapi-group.org/specifications/specs/extension_image/)
images may – dynamically at runtime — extend the base system with an
overlay containing additional files.

To build system extensions with `mkosi`, we need a base image on top of
which we can build our extension.

To keep things manageable, we'll make use of `mkosi`'s support for
building multiple images so that we can build our base image and system
extension in one go.

We start by creating a temporary directory with a base configuration
file `mkosi.conf` with some shared settings:

```conf
[Output]
OutputDirectory=mkosi.output
CacheDirectory=mkosi.cache
```

Now let's continue with the base image definition by writing the
following to `mkosi.images/base/mkosi.conf`:

```conf
[Output]
Format=directory

[Content]
CleanPackageMetadata=no
Packages=systemd
         udev
```

We use the `directory` output format here instead of the `disk` output
so that we can build our extension without needing root privileges.

Now that we have our base image, we can define a sysext that builds on
top of it by writing the following to `mkosi.images/btrfs/mkosi.conf`:

```conf
[Config]
Dependencies=base

[Output]
Format=sysext
Overlay=yes

[Content]
BaseTrees=%O/base
Packages=btrfs-progs
```

`BaseTrees=` point to our base image and `Overlay=yes` instructs mkosi
to only package the files added on top of the base tree.

We can't sign the extension image without a key. We can generate one
by running `mkosi genkey` which will generate files that are
automatically picked up when building the image.

Finally, you can build the base image and the extensions by running
`mkosi -f`. You'll find `btrfs.raw` in `mkosi.output` which is the
extension image.

## Various other interesting features

- To sign any generated UKIs for secure boot, put your secure boot key
  and certificate in `mkosi.key` and `mkosi.crt` and enable the
  `SecureBoot=` setting. You can also run `mkosi genkey` to have `mkosi`
  generate a key and certificate itself.
- The `Ephemeral=` setting can be enabled to boot the image in an
  ephemeral copy that is thrown away when the container or virtual
  machine exits.
- `ShimBootloader=` and `BiosBootloader=` settings are available to
  configure shim and grub installation if needed.
- `mkosi` can boot directory trees in a virtual using `virtiofsd`. This
  is very useful for quickly rebuilding an image and booting it as the
  image does not have to be packed up as a disk image.
- ...

There's many more features that we won't go over in detail here in this
blog post. Learn more about those by reading the
[documentation](https://github.com/systemd/mkosi/blob/main/mkosi/resources/man/mkosi.1.md).

## Conclusion

I'll finish with a bunch of links to more information about `mkosi` and
related tooling:

- [Github repository](https://github.com/systemd/mkosi)
- [Building RHEL and RHEL UBI images with mkosi](https://fedoramagazine.org/create-images-directly-from-rhel-and-rhel-ubi-package-using-mkosi/)
- [My presentation on systemd-repart at ASG 2023](https://media.ccc.de/v/all-systems-go-2023-191-systemd-repart-building-discoverable-disk-images)
- [mkosi's Matrix channel](https://matrix.to/#/#mkosi:matrix.org).
- [systemd's mkosi configuration](https://raw.githubusercontent.com/systemd/systemd/main/mkosi.conf)
- [mkosi's mkosi configuration](https://github.com/systemd/systemd/tree/main/mkosi.conf.d)
