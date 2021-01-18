% mkosi(1)
% The mkosi Authors
% 2016-

# NAME

mkosi - Build Legacy-Free OS Images

# SYNOPSIS

`mkosi [options…] build`

`mkosi [options…] clean`

`mkosi [options…] summary`

`mkosi [options…] shell [command line…]`

`mkosi [options…] boot [nspawn settings…]`

`mkosi [options…] qemu`

# DESCRIPTION

`mkosi` is a tool for easily     building legacy-free OS images. It's a
fancy wrapper around `dnf --installroot`, `debootstrap`, `pacstrap`
and `zypper` that may generate disk images with a number of bells and
whistles.

## Supported output formats

The following output formats are supported:

* Raw *GPT* disk image, with ext4 as root (*gpt_ext4*)

* Raw *GPT* disk image, with xfs as root (*gpt_xfs*)

* Raw *GPT* disk image, with btrfs as root (*gpt_btrfs*)

* Raw *GPT* disk image, with squashfs as read-only root (*gpt_squashfs*)

* Plain squashfs image, without partition table, as read-only root
  (*plain_squashfs*)

* Plain directory, containing the *OS* tree (*directory*)

* btrfs subvolume, with separate subvolumes for `/var`, `/home`,
  `/srv`, `/var/tmp` (*subvolume*)

* Tarball (*tar*)

When a *GPT* disk image is created, the following additional
options are available:

* A swap partition may be added in

* The image may be made bootable on *EFI* and *BIOS* systems

* Separate partitions for `/srv` and `/home` may be added in

* The root, /srv and /home partitions may optionally be encrypted with
  LUKS.

* A dm-verity partition may be added in that adds runtime integrity
  data for the root partition

## Other features

* Optionally, create an *SHA256SUMS* checksum file for the result,
  possibly even signed via `gpg`.

* Optionally, place a specific `.nspawn` settings file along
  with the result.

* Optionally, build a local project's *source* tree in the image
  and add the result to the generated image (see below).

* Optionally, share *RPM*/*DEB* package cache between multiple runs,
  in order to optimize build speeds.

* Optionally, the resulting image may be compressed with *XZ*.

* Optionally, the resulting image may be converted into a *QCOW2* file
  suitable for `qemu` storage.

* Optionally, btrfs' read-only flag for the root subvolume may be
  set.

* Optionally, btrfs' compression may be enabled for all
  created subvolumes.

* By default images are created without all files marked as
  documentation in the packages, on distributions where the
  package manager supports this. Use the `--with-docs` flag to
  build an image with docs added.

## Command Line Verbs

The following command line verbs are known:

`build`

: This builds the image, based on the settings passed in on the
  command line or read from a `mkosi.default` file, see below. This
  verb is the default if no verb is explicitly specified. This command
  must be executed as `root`. Any arguments passed after `build` are
  passed as arguments to the build script (if there is one).

`clean`

: Remove build artifacts generated on a previous build. If combined
  with `-f`, also removes incremental build cache images. If `-f` is
  specified twice, also removes any package cache.

`summary`

: Outputs a human-readable summary of all options used for building an
  image. This will parse the command line and `mkosi.default` file as it
  would do on `build`, but only output what it is configured for and not
  actually build anything.`

`shell`

: This builds the image if it is not build yet, and then invokes
  `systemd-nspawn` to acquire an interactive shell prompt in it. If
  this verb is used an optional command line may be specified which is
  then invoked in place of the shell in the container. Combine this
  with `-f` in order to rebuild the image unconditionally before
  acquiring the shell, see below. This command must be executed as
  `root`.

`boot`

: Similar to `shell` but boots the image up using `systemd-nspawn`. If
  this verb is used an optional command line may be specified which is
  passed as "kernel command line" to the init system in the image.

`qemu`

: Similar to `boot` but uses `qemu` to boot up the image, i.e. instead
  of container virtualization VM virtualization is used. This verb is
  only supported on images that contain a boot loader, i.e. those
  built with `--bootable` (see below). This command must be executed
  as `root` unless the image already exists and `-f` is not specified.

`ssh`

: When the image is built with the `--ssh` option, this command connects
  to a booted (`boot`, `qemu` verbs) container/VM via SSH. Make sure to
  run `mkosi ssh` with the same config as `mkosi build` was run with so
  that it has the necessary information available to connect to the running
  container/VM via SSH.

`help`

: This verb is equivalent to the `--help` switch documented below: it
  shows a brief usage explanation.

## Command Line Parameters

The following command line parameters are understood. Note that many
of these parameters can also be set in the `mkosi.default` file, for
details see the table below.

`--distribution=`, `-d`
: The distribution to install in the image. Takes one of the following
  arguments: `fedora`, `debian`, `ubuntu`, `arch`, `opensuse`,
  `mageia`, `centos`, `clear`, `photon`, `openmandriva`. If not specified, defaults to the
  distribution of the host.

`--release=`, `-r`

: The release of the distribution to install in the image. The precise
  syntax of the argument this takes depends on the distribution used,
  and is either a numeric string (in case of Fedora, CentOS, …,
  e.g. `29`), or a distribution version name (in case of Debian,
  Ubuntu, …, e.g. `artful`). If neither this option, not
  `--distribution=` is specified, defaults to the distribution version
  of the host. If the distribution is specified, defaults to a recent
  version of it.

`--mirror=`, `-m`

: The mirror to use for downloading the distribution packages. Expects
  a mirror URL as argument.

`--repositories=`

: Additional package repositories to use during installation. Expects
  one or more URLs as argument, separated by commas. This option may
  be used multiple times, in which case the list of repositories to
  use is combined. Use "!\*" to remove all repositories from to the list
  or use e.g. "!repo-url" to remove just one specific repository. For Arch
  Linux, additional repositories must be passed in the form `<name>::<url>`
  (e.g. `myrepo::https://myrepo.net`).

`--architecture=`

: The architecture to build the image for. Note that this currently
  only works for architectures compatible with the host's
  architecture.

`--format=`, `-t`

: The image format type to generate. One of `directory` (for
  generating OS images inside a local directory), `subvolume`
  (similar, but as a btrfs subvolume), `tar` (similar, but a tarball
  of the image is generated), `gpt_ext4` (a block device image with an
  ext4 file system inside a GPT partition table), `gpt_xfs`
  (similar, but with an xfs file system), `gpt_btrfs` (similar, but
  with an btrfs file system), `gpt_squashfs` (similar, but with a
  squashfs file system), `plain_squashfs` (a plain squashfs file
  system without a partition table).

`--output=`, `-o`

: Path for the output image file to generate. Takes a relative or
  absolute path where the generated image will be placed. If neither
  this option nor `--output-dir=` is used (see below), the image is
  generated under the name `image`, but its name suffixed with an
  appropriate file suffix (e.g. `image.raw.xz` in case `gpt_ext4` is
  used in combination with `--xz`).

`--output-dir=`, `-O`

: Path to a directory where to place all generated artifacts (i.e. the
  `SHA256SUMS` file and similar). If this is not specified and a
  directory `mkosi.output/` exists in the local directory it is
  automatically used for this purpose. If this is not specified and
  such a directory does not exist, all output artifacts are placed
  adjacent to the output image file.

`--force`, `-f`

: Replace the output file if it already exists, when building an
  image. By default when building an image and an output artifact
  already exists `mkosi` will refuse operation. Specify `-f` to delete
  all build artifacts from a previous run before re-building the
  image. If incremental builds are enabled (see below), specifying
  this option twice will ensure the intermediary cache files are
  removed, too, before the re-build is initiated. If a package cache
  is used (see below), specifying this option thrice will ensure the
  package cache is removed too, before the re-build is initiated. For
  the `clean` operation `-f` has a slightly different effect: by
  default the verb will only remove build artifacts from a previous
  run, when specified once the incremental cache files are deleted
  too, and when specified twice the package cache is also removed.

`--gpt-first-lba`

: Override the first usable LBA (Logical Block Address) within the
  GPT header. This defaults to `2048` which is actually the desired value.
  However, some tools, e.g. the `prl_disk_tool` utility from the
  Parallels virtualization suite require this to be set to `34`, otherwise
  they might fail to resize the disk image and/or partitions inside it.

`--bootable`, `-b`

: Generate a bootable image. By default this will generate an image
  bootable on UEFI systems. Use `--boot-protocols=` to select support
  for a different boot protocol.

`--boot-protocols=`

: Pick one or more boot protocols to support when generating a
  bootable image, as enabled with `--bootable` above. Takes a
  comma-separated list of `uefi` or `bios`. May be specified more than
  once in which case the specified lists are merged. If `uefi` is
  specified the `sd-boot` UEFI boot loader is used, if `bios` is
  specified the GNU Grub boot loader is used. Use "!\*" to remove all
  previously added protocols or "!protocol" to remove one protocol.

`--kernel-command-line=`

: Use the specified kernel command line when building bootable
  images. By default command line arguments get appended. To remove all
  arguments from the current list pass "!\*". To remove specific arguments
  add a space separated list of "!" prefixed arguments.
  For example adding "!\* console=ttyS0 rw" to a mkosi.default file or the
  command line arguments passes "console=ttyS0 rw" to the kernel in any
  case. Just adding "console=ttyS0 rw" would append these two arguments
  to the kernel command line created by lower priority configuration
  files or previous --kernel-command-line command line arguments.

`--secure-boot`

: Sign the resulting kernel/initrd image for UEFI SecureBoot

`--secure-boot-key=`

: Path to the PEM file containing the secret key for signing the
  UEFI kernel image, if `--secure-boot` is used.

`--secure-boot-certificate=`

: Path to the X.509 file containing the certificate for the signed
  UEFI kernel image, if `--secure-boot` is used.

`--secure-boot-common-name=`

: Common name to be used when generating SecureBoot keys via mkosi's `genkey`
  command. Defaults to `mkosi of %u`, where `%u` expands to the username of the
  user invoking mkosi.

`--secure-boot-valid-days=`

: Number of days that the keys should remain valid when generating SecureBoot
  keys via mkosi's `genkey` command. Defaults to two years (730 days).

`--read-only`

: Make root file system read-only. Only applies to `gpt_ext4`,
  `gpt_xfs`, `gpt_btrfs`, `subvolume` output formats, and implied on
  `gpt_squashfs` and `plain_squashfs`.

`--minimize`

: Attempt to make the resulting root file system as small as possible by
  removing free space from the file system. Only
  supported for `gpt_ext4` and `gpt_btrfs`. For ext4 this relies on
  `resize2fs -M`, which reduces the free disk space but is not perfect
  and generally leaves some free space. For btrfs the
  results are optimal and no free space is left.

`--encrypt`

: Encrypt all partitions in the file system or just the root file
  system. Takes either `all` or `data` as argument. If `all` the root,
  `/home` and `/srv` file systems will be encrypted using
  dm-crypt/LUKS (with its default settings). If `data` the root file
  system will be left unencrypted, but `/home` and `/srv` will be
  encrypted. The passphrase to use is read from the `mkosi.passphrase`
  file in the current working directory (see below). Note that the
  UEFI System Partition (ESP) containing the boot loader and kernel to
  boot is never encrypted since it needs to be accessible by the
  firmware.

`--verity`

: Add an "Verity" integrity partition to the image. If enabled, the
  root partition is protected with `dm-verity` against off-line
  modification, the verification data is placed in an additional GPT
  partition. Implies `--read-only`.

`--compress=`

: Compress the generated file systems. Only applies to `gpt_btrfs`,
  `subvolume`, `gpt_squashfs`, `plain_squashfs`. Takes one of `zlib`,
  `lzo`, `zstd`, `lz4`, `xz` or a boolean value as argument. If the
  latter is used compression is enabled/disabled and the default
  algorithm is used. In case of the `squashfs` output formats
  compression is implied, however this option may be used to select
  the algorithm.

`--mksquashfs=`

: Set the path to the `mksquashfs` executable to use. This is useful
  in case the parameters for the tool shall be augmented, as the tool
  may be replaced by a script invoking it with the right parameters,
  this way.

`--xz`

: Compress the resulting image with `xz`. This only applies to
  `gpt_ext4`, `gpt_xfs`, `gpt_btrfs`, `gpt_squashfs` and is implied
  for `tar`. Note that when applied to the block device image types
  this means the image cannot be started directly but needs to be
  decompressed first. This also means that the `shell`, `boot`, `qemu`
  verbs are not available when this option is used.

`--qcow2`

: Encode the resulting image as QEMU QCOW2 image. This only applies to
  `gpt_ext4`, `gpt_xfs`, `gpt_btrfs`, `gpt_squashfs`. QCOW2 images can
  be read natively by `qemu`, but not by the Linux kernel. This means
  the `shell` and `boot` verbs are not available when this option is
  used, however `qemu` will work.

`--hostname=`

: Set the image's hostname to the specified name.

`--without-unified-kernel-images`

: If specified, mkosi does not build unified kernel images and instead installs kernels with a separate
  initrd and boot loader config to the efi or bootloader partition.

`--hostonly-initrd`

: If specified, mkosi will run the tool to create the initrd such that a non-generic initrd is created that
  will only be able to run on the system mkosi is run on. Currently mkosi uses dracut for all supported
  distributions except Clear Linux and this option translates to enabling dracut's hostonly option.

`--no-chown`

: By default, if `mkosi` is run inside a `sudo` environment all
  generated artifacts have their UNIX user/group ownership changed to
  the user which invoked `sudo`. With this option this may be turned
  off and all generated files are owned by `root`.

`--tar-strip-selinux-context`

: If running on a SELinux-enabled system (Fedora, CentOS), files inside
  the container are tagged with SELinux context extended attributes
  (`xattrs`), which may interfere with host SELinux rules in building
  or further container import stages.
  This option strips SELinux context attributes from the resulting
  tar archive.

`--incremental`, `-i`

: Enable incremental build mode. This only applies if the two-phase
  `mkosi.build` build script logic is used. In this mode, a copy of
  the OS image is created immediately after all OS packages are
  unpacked but before the `mkosi.build` script is invoked in the
  development container. Similar a copy of the final image is created
  immediately before the build artifacts from the `mkosi.build` script
  are copied in. On subsequent invocations of `mkosi` with the `-i`
  switch these cached images may be used to skip the OS package
  unpacking, thus drastically speeding up repetitive build times. Note
  that when this is used and a pair of cached incremental images
  exists they are not automatically regenerated, even if options such
  as `--packages=` are modified. In order to force rebuilding of these
  cached images, combined `-i` with `-ff`, which ensures the cached
  images are removed first, and then re-created.

`--package=`, `-p`

: Install the specified distribution packages (i.e. RPM, DEB, …) in
  the image. Takes a comma separated list of packages. This option may
  be used multiple times in which case the specified package list is
  combined. Packaged specified this way will be installed both in the
  development and the final image (see below). Use `--build-package=`
  (see below) to specify packages that shall only be used for the
  image generated in the build image, but that shall not appear in the
  final image.
  To remove a package e.g. added by a mkosi.default configuration file
  prepend the package name with a ! letter. For example -p "!apache2"
  would remove the apache2 package. To replace the apache2 package by
  the httpd package just add -p "!apache2,httpd" to the command line
  arguments. To remove all packages use "!\*".

`--with-docs`

: Include documentation in the image built. By default if the
  underlying distribution package manager supports it documentation is
  not included in the image built. The `$WITH_DOCS` environment
  variable passed to the `mkosi.build` script indicates whether this
  option was used or not, see below.

`--without-tests`, `-T`

: If set the `$WITH_TESTS` environment variable is set to `0` when the
  `mkosi.build` script is invoked. This is supposed to be used by the
  build script to bypass any unit or integration tests that are
  normally run during the source build process. Note that this option
  has no effect unless the `mkosi.build` build script honors it.

`--cache=`

: Takes a path to a directory to use as package cache for the
  distribution package manager used. If this option is not used, but a
  `mkosi.cache/` directory is found in the local directory it is
  automatically used for this purpose (also see below). The directory
  configured this way is mounted into both the development and the
  final image while the package manager is running.

`--extra-tree=`

: Takes a path to a directory to copy on top of the OS tree the
  package manager generated. Use this to override any default
  configuration files shipped with the distribution. If this option is
  not used, but the `mkosi.extra/` directory is found in the local
  directory it is automatically used for this purpose (also see
  below). Instead of a directory a `tar` file may be specified too. In
  this case it is unpacked into the OS tree before the package manager
  is invoked. This mode of operation allows setting permissions and
  file ownership explicitly, in particular for projects stored in a
  version control system such as `git` which does retain full file
  ownership and access mode metadata for committed files. If a tar file
  `mkosi.extra.tar` is found in the local directory it automatically
  used for this purpose.

`--skeleton-tree=`

: Takes a path to a directory to copy into the OS tree before invoking
  the package manager. Use this to insert files and directories into
  the OS tree before the package manager installs any packages. If
  this option is not used, but the `mkosi.skeleton/` directory is
  found in the local directory it is automatically used for this
  purpose (also see below). As with the extra tree logic above,
  instead of a directory a `tar` file may be used too, and
  `mkosi.skeleton.tar` is automatically used.

`--build-script=`

: Takes a path to an executable that is used as build script for this
  image. If this option is used the build process will be two-phased
  instead of single-phased (see below). The specified script is copied
  onto the development image and executed inside an `systemd-nspawn`
  container environment. If this option is not used, but the
  `mkosi.build` file found in the local directory it is automatically
  used for this purpose (also see below).

`--build-environment=`

: Adds environment variables to the environment that the build script
  is executed with. Takes a space-separated list of variable
  assignments. This option may be  specified more than once, in which
  case all listed variables will be set. If the same variable is set
  twice, the later setting will override the earlier setting.

`--build-sources=`

: Takes a path of a source tree to copy into the development image, if
  a build script is used. This only applies if a build script is used,
  and defaults to the local directory. Use `--source-file-transfer=`
  to configure how the files are transferred from the host to the
  container image.

`--build-dir=`

: Takes a path of a directory to use as build directory for build
  systems that support out-of-tree builds (such as Meson). The
  directory used this way is shared between repeated builds, and
  allows the build system to reuse artifacts (such as object files,
  executable, …) generated on previous invocations. This directory is
  mounted into the development image when the build script is
  invoked. The build script can find the path to this directory in the
  `$BUILDDIR` environment variable. If this option is not specified,
  but a directory `mkosi.builddir/` exists in the local directory it
  is automatically used for this purpose (also see below).

`--include-directory`

: Takes a path of a directory to use as the include directory. This
  directory is mounted at /usr/include when building the build image
  and when running the build script. This means all include files
  installed to /usr/include will be stored in this directory. This is
  useful to make include files available on the host system for use by
  language servers to provide code completion. If this option is not
  specified, but a directory `mkosi.includedir/` exists in the local
  directory, it is automatically used for this purpose (also see below).

`--install-directory`

: Takes a path of a directory to use as the install directory. The
  directory used this way is shared between builds and allows the
  build system to not have to reinstall files that were already
  installed by a previous build and didn't change. The build script
  can find the path to this directory in the `$DESTDIR` environment
  variable. If this option is not specified, but a directory
  `mkosi.installdir` exists in the local directory, it is automatically
  used for this purpose (also see below).

`--build-package=`

: Similar to `--package=`, but configures packages to install only in
  the first phase of the build, into the development image. This
  option should be used to list packages containing header files,
  compilers, build systems, linkers and other build tools the
  `mkosi.build` script requires to operate. Note that packages listed
  here are only included in the image created during the first phase
  of the build, and are absent in the final image. use `--package=` to
  list packages that shall be included in both.
  Packages are appended to the list. Packages prefixed with "!" are
  removed from the list. "!\*" removes all packages from the list.

`--skip-final-phase=`

: Causes the (second) final image build stage to be skipped. This is
  useful in combination with a build script, for when you care about
  the artifacts that were created locally in `$BUILDDIR`, but
  ultimately plan to discard the final image.

`--prepare-script=`

: Takes a path to an executable that is invoked inside the image
  right after installing the software packages. It is
  the last step before the image is cached (if incremental mode is
  enabled).
  This script is invoked inside a `systemd-nspawn` container
  environment, and thus does not have access to host resources.
  If this option is not used, but an executable script `mkosi.prepare`
  is found in the local directory, it is automatically used for this
  purpose (also see below).

`--postinst-script=`

: Takes a path to an executable that is invoked inside the final image
  right after copying in the build artifacts generated in the first
  phase of the build. This script is invoked inside a `systemd-nspawn`
  container environment, and thus does not have access to host
  resources. If this option is not used, but an executable
  `mkosi.postinst` is found in the local directory, it is
  automatically used for this purpose (also see below).

`--finalize-script=`

: Takes a path to an executable that is invoked outside the final
  image right after copying in the build artifacts generated in the
  first phase of the build, and after having executed the
  `mkosi.postinst` script (see above). This script is invoked directly
  in the host environment, and hence has full access to the host's
  resources. If this option is not used, but an executable
  `mkosi.finalize` is found in the local directory, it is
  automatically used for this purpose (also see below).

`--source-file-transfer=`

: Configures how the source file tree (as configured with
  `--build-sources=`) is transferred into the container image
  during the first phase of the build. Takes one of `copy-all` (to
  copy all files from the source tree), `copy-git-cached` (to copy
  only those files `git-ls-files --cached` lists), `copy-git-others`
  (to copy only those files `git-ls-files --others` lists), `mount` to
  bind mount the source tree directly. Defaults to `copy-git-cached`
  if a `git` source tree is detected, otherwise `copy-all`. When you
  specify `copy-git-more`, it is the same as `copy-git-cached`, except
  it also includes the `.git/` directory.

`--source-file-transfer-final=`

: Same as `--source-file-transfer` but for the final image instead of
  the build image. Takes the same values as `--source-file-transfer`
  except `mount`. By default, sources are not copied into the final
  image.

`--with-network`

: Enables network connectivity while the build script `mkosi.build` is
  invoked. By default, the build script runs with networking turned
  off. The `$WITH_NETWORK` environment variable is passed to the
  `mkosi.build` build script indicating whether the build is done with
  or without this option. If specified as `--with-network=never` the
  package manager is instructed not to contact the network for
  updating package data. This provides a minimal level of
  reproducibility, as long as the package data cache is already fully
  populated.

`--settings=`

: Specifies a `.nspawn` settings file for `systemd-nspawn` to use in
  the `boot` and `shell` verbs, and to place next to the generated
  image file. This is useful to configure the `systemd-nspawn`
  environment when the image is run. If this setting is not used but
  an `mkosi.nspawn` file found in the local directory it is
  automatically used for this purpose (also see below).

`--root-size=`

: Takes a size in bytes for the root file system. The specified
  numeric value may be suffixed with `K`, `M`, `G` to indicate kilo-,
  mega- and gigabytes (all to the base of 1024). This applies to
  output formats `gpt_ext4`, `gpt_xfs`, `gpt_btrfs`. Defaults to 1G,
  except for `gpt_xfs` where it defaults to 1.3G.

`--esp-size=`

: Similar, and configures the size of the UEFI System Partition
  (ESP). This is only relevant if the `--bootable` option is used to
  generate a bootable image. Defaults to 256M.

`--swap-size=`

: Similar, and configures the size of a swap partition on the
  image. If omitted no swap partition is created.

`--home-size=`

: Similar, and configures the size of the `/home` partition. If
  omitted no separate `/home` partition is created.

`--srv-size=`

: Similar, and configures the size of the `/srv` partition. If
  omitted no separate `/srv` partition is created.

`--checksum`

: Generate a `SHA256SUMS` file of all generated artifacts after the
  build is complete.

`--sign`

: Sign the generated `SHA256SUMS` using `gpg` after completion.

`--key=`

: Select the `gpg` key to use for signing `SHA256SUMS`. This key
  is required to exist in the `gpg` keyring already.

`--bmap`

: Generate a `bmap` file for usage with `bmaptool` from the generated
  image file.

`--password=`

: Set the password of the `root` user. By default the `root` account
  is locked. If this option is not used but a file `mkosi.rootpw` exists
  in the local directory the root password is automatically read from it.

`--password-is-hashed`

: Indicate that the password supplied for the `root` user has already been
  hashed, so that the string supplied with `--password` or `mkosi.rootpw` will
  be written to `/etc/shadow` literally.

`--autologin`

: Enable autologin for the `root` user on pts/0 (nspawn), tty1 (QEMU) and
  ttyS0 (QEMU with --qemu-headless) by patching /etc/pam.d/login.

`--extra-search-paths=`

: List of colon-separated paths to look for tools in, before using the
  regular `$PATH` search path.

`--directory=`, `-C`

: Takes a path to a directory. `mkosi` switches to this directory
  before doing anything. Note that the various `mkosi.*` files are
  searched for only after changing to this directory, hence using this
  option is an effective way to build a project located in a specific
  directory.

`--default=`

: Loads additional settings from the specified settings file. Most
  command line options may also be configured in a settings file. See
  the table below to see which command line options match which
  settings file option. If this option is not used, but a file
  `mkosi.default` is found in the local directory it is automatically
  used for this purpose. If a setting is configured both on the
  command line and in the settings file, the command line generally
  wins, except for options taking lists in which case both lists are
  combined.

`--all`, `-a`

: Iterate through all files `mkosi.*` in the `mkosi.files/`
  subdirectory, and build each as if `--default=mkosi.files/mkosi.…`
  was invoked. This is a quick way to build a large number of images
  in one go. Any additional specified command line arguments override
  the relevant options in all files processed this way.

`--all-directory=`

: If specified, overrides the directory the `--all` logic described
  above looks for settings files in. If unspecified, defaults to
  `mkosi.files/` in the current working directory (see above).

`--version`
: Show package version.

`--help`, `-h`
: Show brief usage information.

`--qemu-headless=`

: When used with the build verb, this option adds `console=ttyS0` to
  the image's kernel command line and sets the terminal type of the
  serial console in the image to the terminal type of the host (more
  specifically, the value of the TERM environment variable passed to
  mkosi). This makes sure that all terminal features such as colors
  and shortcuts still work as expected when connecting to the qemu
  VM over the serial console (for example via `-nographic`).

  When used with the qemu verb, this option adds the `-nographic`
  option to qemu's command line so qemu starts a headless vm and
  connects to its serial console from the current terminal instead
  of launching the VM in a separate window.

`--network-veth`
: When used with the boot or qemu verbs, this option creates a virtual
  ethernet link between the host and the container/VM. The host
  interface is automatically picked up by systemd-networkd as documented
  in systemd-nspawn's man page:
  https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html#-n

`--ephemeral`
: When used with the shell, boot or qemu verbs, this option runs the specified
  verb on a temporary snapshot of the output image that is removed immediately
  when the container terminates. Taking the temporary snapshot is more efficient
  on file systems that support subvolume snapshots or 'reflinks' natively ("btrfs"
  or new "xfs") than on more traditional file systems that do not ("ext4").

`--ssh`
: If specified, installs and enables sshd in the final image and generates
  a SSH keypair and adds the public key to root's authorized keys in the final
  image. The private key is stored in mkosi's output directory. When building
  with this  option and running the image using `mkosi boot` or `mkosi qemu`,
  the `mkosi ssh` command can be used to connect to the container/VM via SSH.

## Command Line Parameters and their Settings File Counterparts

Most command line parameters may also be placed in an `mkosi.default`
settings file (or any other file `--default=` is used on). The
following table shows which command lines parameters correspond with
which settings file options.

| Command Line Parameter            | `mkosi.default` section | `mkosi.default` setting       |
|-----------------------------------|-------------------------|-------------------------------|
| `--distribution=`, `-d`           | `[Distribution]`        | `Distribution=`               |
| `--release=`, `-r`                | `[Distribution]`        | `Release=`                    |
| `--repositories=`                 | `[Distribution]`        | `Repositories=`               |
| `--mirror=`, `-m`                 | `[Distribution]`        | `Mirror=`                     |
| `--architecture=`                 | `[Distribution]`        | `Architecture=`               |
| `--format=`, `-t`                 | `[Output]`              | `Format=`                     |
| `--output=`, `-o`                 | `[Output]`              | `Output=`                     |
| `--output-dir=`, `-O`             | `[Output]`              | `OutputDirectory=`            |
| `--force`, `-f`                   | `[Output]`              | `Force=`                      |
| `--bootable`, `-b`                | `[Output]`              | `Bootable=`                   |
| `--boot-protocols=`               | `[Output]`              | `BootProtocols=`              |
| `--gpt-first-lba=`                | `[Output]`              | `GPTFirstLBA=`                |
| `--kernel-command-line=`          | `[Output]`              | `KernelCommandLine=`          |
| `--secure-boot`                   | `[Output]`              | `SecureBoot=`                 |
| `--secure-boot-key=`              | `[Output]`              | `SecureBootKey=`              |
| `--secure-boot-certificate=`      | `[Output]`              | `SecureBootCertificate=`      |
| `--secure-boot-valid-days=`       | `[Output]`              | `SecureBootValidDays=`        |
| `--secure-boot-common-name=`      | `[Output]`              | `SecureBootCommonName=`       |
| `--read-only`                     | `[Output]`              | `ReadOnly=`                   |
| `--encrypt=`                      | `[Output]`              | `Encrypt=`                    |
| `--verity=`                       | `[Output]`              | `Verity=`                     |
| `--compress=`                     | `[Output]`              | `Compress=`                   |
| `--mksquashfs=`                   | `[Output]`              | `Mksquashfs=`                 |
| `--xz`                            | `[Output]`              | `XZ=`                         |
| `--qcow2`                         | `[Output]`              | `QCow2=`                      |
| `--no-chown`                      | `[Output]`              | `NoChown=`                    |
| `--tar-strip-selinux-context`     | `[Output]`              | `TarStripSELinuxContext=`     |
| `--hostname=`                     | `[Output]`              | `Hostname=`                   |
| `--without-unified-kernel-images` | `[Output]`              | `WithUnifiedKernelImages=`    |
| `--hostonly-initrd`               | `[Output]`              | `HostonlyInitrd=`             |
| `--package=`                      | `[Packages]`            | `Packages=`                   |
| `--with-docs`                     | `[Packages]`            | `WithDocs=`                   |
| `--without-tests`, `-T`           | `[Packages]`            | `WithTests=`                  |
| `--cache=`                        | `[Packages]`            | `Cache=`                      |
| `--extra-tree=`                   | `[Packages]`            | `ExtraTrees=`                 |
| `--skeleton-tree=`                | `[Packages]`            | `SkeletonTrees=`              |
| `--build-script=`                 | `[Packages]`            | `BuildScript=`                |
| `--build-environment=`            | `[Packages]`            | `BuildEnvironment=`           |
| `--build-sources=`                | `[Packages]`            | `BuildSources=`               |
| `--source-file-transfer=`         | `[Packages]`            | `SourceFileTransfer=`         |
| `--source-file-transfer-final=`   | `[Packages]`            | `SourceFileTransferFinal=`    |
| `--build-directory=`              | `[Packages]`            | `BuildDirectory=`             |
| `--include-directory=`            | `[Packages]`            | `IncludeDirectory=`           |
| `--install-directory=`            | `[Packages]`            | `InstallDirectory=`           |
| `--build-packages=`               | `[Packages]`            | `BuildPackages=`              |
| `--skip-final-phase=`             | `[Packages]`            | `SkipFinalPhase=`             |
| `--postinst-script=`              | `[Packages]`            | `PostInstallationScript=`     |
| `--finalize-script=`              | `[Packages]`            | `FinalizeScript=`             |
| `--with-network`                  | `[Packages]`            | `WithNetwork=`                |
| `--settings=`                     | `[Packages]`            | `NSpawnSettings=`             |
| `--root-size=`                    | `[Partitions]`          | `RootSize=`                   |
| `--esp-size=`                     | `[Partitions]`          | `ESPSize=`                    |
| `--swap-size=`                    | `[Partitions]`          | `SwapSize=`                   |
| `--home-size=`                    | `[Partitions]`          | `HomeSize=`                   |
| `--srv-size=`                     | `[Partitions]`          | `SrvSize=`                    |
| `--checksum`                      | `[Validation]`          | `CheckSum=`                   |
| `--sign`                          | `[Validation]`          | `Sign=`                       |
| `--key=`                          | `[Validation]`          | `Key=`                        |
| `--bmap`                          | `[Validation]`          | `BMap=`                       |
| `--password=`                     | `[Validation]`          | `Password=`                   |
| `--password-is-hashed`            | `[Validation]`          | `PasswordIsHashed=`           |
| `--autologin`                     | `[Validation]`          | `Autologin=`                  |
| `--extra-search-paths=`           | `[Host]`                | `ExtraSearchPaths=`           |
| `--qemu-headless`                 | `[Host]`                | `QemuHeadless=`               |
| `--network-veth`                  | `[Host]`                | `NetworkVeth=`                |
| `--ephemeral`                     | `[Host]`                | `Ephemeral=`                  |
| `--ssh`                           | `[Host]`                | `Ssh=`                        |

Command line options that take no argument are not suffixed with a `=`
in their long version in the table above. In the `mkosi.default` file
they are modeled as boolean option that take either `1`, `yes`,
`true` for enabling, and `0`, `no`, `false` for disabling.

## Supported distributions

Images may be created containing installations of the
following *OS*es.

* *Fedora*

* *Debian*

* *Ubuntu*

* *Arch Linux*

* *openSUSE*

* *Mageia*

* *CentOS*

* *Clear Linux*

* *Photon*

* *OpenMandriva*

In theory, any distribution may be used on the host for building
images containing any other distribution, as long as the necessary
tools are available. Specifically, any distribution that packages
`debootstrap` may be used to build *Debian* or *Ubuntu* images. Any
distribution that packages `dnf` may be used to build *Fedora*,
*Mageia* or *OpenMandriva* images. Any distro that packages `pacstrap` may be used to
build *Arch Linux* images. Any distribution that packages `zypper` may
be used to build *openSUSE* images. Any distribution that packages
`yum` (or the newer replacement `dnf`) may be used to build *CentOS*
images.

Currently, *Fedora* packages all relevant tools as of Fedora 28.

## Compatibility

Generated images are *legacy-free*. This means only *GPT* disk labels
(and no *MBR* disk labels) are supported, and only systemd based
images may be generated.

All generated *GPT* disk images may be booted in a local
container directly with:

```bash
systemd-nspawn -bi image.raw
```

Additionally, bootable *GPT* disk images (as created with the
`--bootable` flag) work when booted directly by *EFI* and *BIOS*
systems, for example in *KVM* via:

```bash
qemu-kvm -m 512 -smp 2 -bios /usr/share/edk2/ovmf/OVMF_CODE.fd -drive format=raw,file=image.raw
```

*EFI* bootable *GPT* images are larger than plain *GPT* images, as
they additionally carry an *EFI* system partition containing a
boot loader, as well as a kernel, kernel modules, udev and
more.

All directory or btrfs subvolume images may be booted directly
with:

```bash
systemd-nspawn -bD image
```

# FILES

To make it easy to build images for development versions of your
projects, mkosi can read configuration data from the local directory,
under the assumption that it is invoked from a *source*
tree. Specifically, the following files are used if they exist in the
local directory:

* `mkosi.default` may be used to configure mkosi's image building
  process. For example, you may configure the distribution to use
  (`fedora`, `ubuntu`, `debian`, `arch`, `opensuse`, `mageia`, `openmandriva`) for the
  image, or additional distribution packages to install. Note that all
  options encoded in this configuration file may also be set on the
  command line, and this file is hence little more than a way to make
  sure simply typing `mkosi` without further parameters in your
  *source* tree is enough to get the right image of your choice set
  up.  Additionally if a `mkosi.default.d` directory exists, each file
  in it is loaded in the same manner adding/overriding the values
  specified in `mkosi.default`. If `mkosi.default.d` contains a
  directory named after the distribution being built, each file in
  that directory is also processed. The file format is inspired by
  Windows`.ini` files and supports multi-line assignments: any line
  with initial whitespace is considered a continuation line of the line
  before. Command-line arguments, as shown in the help description,
  have to be included in a configuration block (e.g.  "[Packages]")
  corresponding to the argument group (e.g. "Packages"), and the
  argument gets converted as follows: "--with-network" becomes
  "WithNetwork=yes". For further details see the table above.

* `mkosi.extra/` or `mkosi.extra.tar` may be respectively a directory
  or archive. If any exist all files contained in it are copied over
  the directory tree of the image after the *OS* was installed. This
  may be used to add in additional files to an image, on top of what
  the distribution includes in its packages. When using a directory
  file ownership is not preserved: all files copied will be owned by
  root. To preserve ownership use a tar archive.

* `mkosi.skeleton/` or `mkosi.skeleton.tar` may be respectively a
  directory or archive, and they work in the same way as
  `mkosi.extra`/`mkosi.skeleton.tar`. However the files are copied
  before anything else so to have a skeleton tree for the OS. This
  allows to change the package manager and create files that need to
  be there before anything is installed. When using a directory file
  ownership is not preserved: all files copied will be owned by
  root. To preserve ownership use a tar archive.

* `mkosi.build` may be an executable script. If it exists the image
  will be built twice: the first iteration will be the *development*
  image, the second iteration will be the *final* image. The
  *development* image is used to build the project in the current
  working directory (the *source* tree). For that the whole directory
  is copied into the image, along with the mkosi.build build
  script. The script is then invoked inside the image (via
  `systemd-nspawn`), with `$SRCDIR` pointing to the *source*
  tree. `$DESTDIR` points to a directory where the script should place
  any files generated it would like to end up in the *final*
  image. Note that `make`/`automake`/`meson` based build systems
  generally honor `$DESTDIR`, thus making it very natural to build
  *source* trees from the build script. After the *development* image
  was built and the build script ran inside of it, it is removed
  again. After that the *final* image is built, without any *source*
  tree or build script copied in. However, this time the contents of
  `$DESTDIR` are added into the image.

  When the source tree is copied into the *build* image, all files are
  copied, except for `mkosi.builddir/`, `mkosi.cache/` and
  `mkosi.output/`. That said, `.gitignore` is respected if the source
  tree is a `git` checkout. If multiple different images shall be
  built from the same source tree it's essential to exclude their
  output files from this copy operation, as otherwise a version of an
  image built earlier might be included in a later build, which is
  usually not intended. An alternative to excluding these built images
  via `.gitignore` entries is making use of the `mkosi.output/`
  directory (see below), which is an easy way to exclude all build
  artifacts.

  The `MKOSI_DEFAULT` environment variable will be set inside of this
  script so that you know which `mkosi.default` (if any) was passed in.

* `mkosi.prepare` may be an executable script. If it exists it is
  invoked directly after the software packages are installed,
  from within the image context. It is once called for the *development*
  image (if this is enabled, see above) with the "build" command line
  parameter, right before copying the extra tree. It is called a second
  time for the *final* image with the "final" command line parameter.
  This script has network access and may be used to install packages
  from other sources than the distro's package manager (e.g. pip, npm, ...),
  after all software packages are installed but before the image is
  cached (if incremental mode is enabled). This script is executed within
  `$SRCDIR`. In contrast to a general purpose installation, it is safe to
  install packages to the system (`pip install`, `npm install -g`) instead
  of in `$SRCDIR` itself because the build image is only used for a single
  project and can easily be thrown away and rebuilt so there's no risk of
  conflicting dependencies and no risk of polluting the host system.

* `mkosi.postinst` may be an executable script. If it exists it is
  invoked as the penultimate step of preparing an image, from within
  the image context. It is once called for the *development* image (if
  this is enabled, see above) with the "build" command line parameter,
  right before invoking the build script. It is called a second time
  for the *final* image with the "final" command line parameter, right
  before the image is considered complete. This script may be used to
  alter the images without any restrictions, after all software
  packages and built sources have been installed. Note that this
  script is executed directly in the image context with the final root
  directory in place, without any `$SRCDIR`/`$DESTDIR` setup.

* `mkosi.finalize` may be an executable script. If it exists it is
  invoked as last step of preparing an image, from the host system.
  It is once called for the *development* image (if this is enabled,
  see above) with the "build" command line parameter, as the last step
  before invoking the build script, after the `mkosi.postinst` script
  is invoked.  It is called the second time with the "final" command
  line parameter as the last step before the image is considered
  complete. The environment variable `$BUILDROOT` points to the root
  directory of the installation image. Additional verbs may be added
  in the future, the script should be prepared for that. This script
  may be used to alter the images without any restrictions, after all
  software packages and built sources have been installed. This script
  is more flexible than `mkosi.postinst` in two regards: it has access
  to the host file system so it's easier to copy in additional files
  or to modify the image based on external configuration, and the
  script is run in the host, so it can be used even without emulation
  even if the image has a foreign architecture.

* `mkosi.mksquashfs-tool` may be an executable script. If it exists is
  is called instead of `mksquashfs`.

* `mkosi.nspawn` may be an nspawn settings file. If this exists it
  will be copied into the same place as the output image file. This is
  useful since nspawn looks for settings files next to image files it
  boots, for additional container runtime settings.

* `mkosi.cache/` may be a directory. If so, it is automatically used as
  package download cache, in order to speed repeated runs of the tool.

* `mkosi.builddir/` may be a directory. If so, it is automatically
  used as out-of-tree build directory, if the build commands in the
  `mkosi.build` script support it. Specifically, this directory will
  be mounted into the build container, and the `$BUILDDIR` environment
  variable will be set to it when the build script is invoked. The
  build script may then use this directory as build directory, for
  automake-style or ninja-style out-of-tree builds. This speeds up
  builds considerably, in particular when `mkosi` is used in
  incremental mode (`-i`): not only the disk images but also the build
  tree is reused between subsequent invocations. Note that if this
  directory does not exist the `$BUILDDIR` environment variable is not
  set, and it is up to build script to decide whether to do in in-tree
  or an out-of-tree build, and which build directory to use.

* `mkosi.includedir/` may be a directory. If so, it is automatically
  used as out-of-tree include directory. Specifically, this directory
  will be mounted into the build container at /usr/include when building
  the build image and when running the build script. After building the
  (cached) build image, this directory will contain all the files installed
  to /usr/include. Language servers or other tools can use these files to
  provide a better editing experience for developers working on a project.

* `mkosi.installdir/` may be a directory. If so, it is automatically
  used as the install directory. Specifically, this directory will be
  mounted into the container at /root/dest when running the build script.
  After running the build script, the contents of this directory are
  installed into the final image. This is useful to cache the install
  step of the build. If used, subsequent builds will only have to
  reinstall files that have changed since the previous build.

* `mkosi.rootpw` may be a file containing the password or hashed
  password (if `--password-is-hashed` is set) for the root user of the
  image to set. The password may optionally be followed by a newline
  character which is implicitly removed. The file must have an access
  mode of 0600 or less. If this file does not exist the distribution's
  default root password is set (which usually means access to the root
  user is blocked).

* `mkosi.passphrase` may be a passphrase file to use when LUKS
  encryption is selected. It should contain the passphrase literally,
  and not end in a newline character (i.e. in the same format as
  cryptsetup and /etc/crypttab expect the passphrase files). The file
  must have an access mode of 0600 or less. If this file does not
  exist and encryption is requested the user is queried instead.

* `mkosi.secure-boot.crt` and `mkosi.secure-boot.key` may contain an
  X.509 certificate and PEM private key to use when UEFI SecureBoot
  support is enabled. All EFI binaries included in the image's ESP are
  signed with this key, as a late step in the build process.

* `mkosi.output/` may be a directory. If it exists, and the image
  output path is not configured (i.e. no `--output=` setting
  specified), or configured to a filename (i.e. a path containing no
  `/` character) all build artifacts (that is: the image itself, the
  root hash file in case Verity is used, the checksum and its
  signature if that's enabled, and the nspawn settings file if there
  is any) are placed in this directory. Note that this directory is
  not used if the image output path contains at least one slash, and
  has no effect in that case. This setting is particularly useful if
  multiple different images shall be built from the same working
  directory, as otherwise the build result of a preceding run might be
  copied into a build image as part of the source tree (see above).

All these files are optional.

Note that the location of all these files may also be configured
during invocation via command line switches, and as settings in
`mkosi.default`, in case the default settings are not acceptable for a
project.

# BUILD PHASES

If no build script `mkosi.build` (see above) is used the build
consists of a single phase only: the final image is generated as the
combination of `mkosi.skeleton/` (see above), the unpacked
distribution packages and `mkosi.extra/`.

If a build script `mkosi.build` is used the build consists of two
phases: in the the first `development` phase an image that includes
necessary build tools (i.e. the combination of `Packages=` and
`BuildPackages=` is installed) is generated (i.e. the combination of
`mkosi.skeleton/` and unpacked distribution packages). Into this image
the source tree is copied and `mkosi.build` executed. The artifacts
the `mkosi.build` generates are saved. Then, the second `final` phase
starts: an image that excludes the build tools (i.e. only `Packages=`
is installed, `BuildPackages=` is not) is generated. This time the
build artifacts saved from the first phase are copied in, and
`mkosi.extra` copied on top, thus generating the final image.

The two-phased approach ensures that source tree is executed in a
clean and comprehensive environment, while at the same the final image
remains minimal and contains only those packages necessary at runtime,
but avoiding those necessary at build-time.

Note that only the package cache `mkosi.cache/` (see below) is shared
between the two phases. The distribution package manager is executed
exactly once in each phase, always starting from a directory tree that
is populated with `mkosi.skeleton` but nothing else.

# CACHING

`mkosi` supports three different caches for speeding up repetitive
re-building of images. Specifically:

1. The package cache of the distribution package manager may be cached
   between builds. This is configured with the `--cache=` option or
   the `mkosi.cache/` directory. This form of caching relies on the
   distribution's package manager, and caches distribution packages
   (RPM, DEB, …) after they are downloaded, but before they are
   unpacked.

2. If an `mkosi.build` script is used, by enabling incremental build
   mode with `--incremental` (see above) a cached copy of the
   development and final images can be made immediately before the
   build sources are copied in (for the development image) or the
   artifacts generated by `mkosi.build` are copied in (in case of the
   final image). This form of caching allows bypassing the
   time-consuming package unpacking step of the distribution package
   managers, but is only effective if the list of packages to use
   remains stable, but the build sources and its scripts change
   regularly. Note that this cache requires manual flushing: whenever
   the package list is modified the cached images need to be
   explicitly removed before the next re-build, using the `-f` switch.

3. Finally, between multiple builds the build artifact directory may
   be shared, using the `mkosi.builddir/` directory. This directory
   allows build systems such as Meson to reuse already compiled
   sources from a previous built, thus speeding up the build process
   of the `mkosi.build` build script.

The package cache (i.e. the first item above) is unconditionally
useful. The latter two caches only apply to uses of `mkosi` with a
source tree and build script. When all three are enabled together
turn-around times for complete image builds are minimal, as only
changed source files need to be recompiled: an OS image rebuilt will
be almost as quick to build the source tree only.

# ENVIRONMENT VARIABLES

The build script `mkosi.build` receives the following environment
variables:

* `$SRCDIR` contains the path to the sources to build.

* `$DESTDIR` is a directory into which any artifacts generated by the
  build script shall be placed.

* `$BUILDDIR` is only defined if `mkosi.builddir` and points to the
  build directory to use. This is useful for all build systems that
  support out-of-tree builds to reuse already built artifacts from
  previous runs.

* `$WITH_DOCS` is either `0` or `1` depending on whether a build
  without or with installed documentation was requested (see
  `--with-docs` above). The build script should suppress installation
  of any package documentation to `$DESTDIR` in case `$WITH_DOCS` is
  set to `0`.

* `$WITH_TESTS` is either `0`or `1` depending on whether a build
  without or with running the test suite was requested (see
  `--without-tests` above). The build script should avoid running any
  unit or integration tests in case `$WITH_TESTS` is `0`.

* `$WITH_NETWORK` is either `0`or `1` depending on whether a build
  without or with networking is being executed (see `--with-network`
  above). The build script should avoid any network communication in
  case `$WITH_NETWORK` is `0`.

# EXAMPLES

Create and run a raw *GPT* image with *ext4*, as `image.raw`:

```bash
# mkosi
# systemd-nspawn -b -i image.raw
```

Create and run a bootable btrfs *GPT* image, as `foobar.raw`:

```bash
# mkosi -t gpt_btrfs --bootable -o foobar.raw
# systemd-nspawn -b -i foobar.raw
# qemu-kvm -m 512 -smp 2 -bios /usr/share/edk2/ovmf/OVMF_CODE.fd -drive format=raw,file=foobar.raw
```

Create and run a *Fedora* image into a plain directory:

```bash
# mkosi -d fedora -t directory -o quux
# systemd-nspawn -b -D quux
```

Create a compressed image `image.raw.xz` and add a checksum file, and
install *SSH* into it:

```bash
# mkosi -d fedora -t gpt_squashfs --checksum --xz --package=openssh-clients
```

Inside the source directory of an `automake`-based project,
configure *mkosi* so that simply invoking `mkosi` without any
parameters builds an *OS* image containing a built version of
the project in its current state:

```bash
# cat > mkosi.default <<EOF
[Distribution]
Distribution=fedora
Release=24

[Output]
Format=gpt_btrfs
Bootable=yes

[Packages]
Packages=openssh-clients httpd
BuildPackages=make gcc libcurl-devel
EOF
# cat > mkosi.build <<EOF
#!/bin/sh
cd $SRCDIR
./autogen.sh
./configure --prefix=/usr
make -j `nproc`
make install
EOF
# chmod +x mkosi.build
# mkosi
# systemd-nspawn -bi image.raw
```

To create a *Fedora* image with hostname:
```bash
# mkosi -d fedora --hostname image
```

Also you could set hostname in configuration file:
```bash
# cat mkosi.default
...
[Output]
Hostname=image
...
```

# REQUIREMENTS

mkosi is packaged for various distributions: Debian, Ubuntu, Arch (in AUR), Fedora, OpenMandriva.
It is usually easiest to use the distribution package.

The current version requires systemd 233 (or actually, systemd-nspawn of it).

When not using distribution packages make sure to install the
necessary dependencies. For example, on *Fedora* you need:

```bash
dnf install arch-install-scripts btrfs-progs debootstrap dosfstools edk2-ovmf e2fsprogs squashfs-tools gnupg python3 tar veritysetup xfsprogs xz zypper sbsigntools
```

On Debian/Ubuntu it might be necessary to install the `ubuntu-keyring`,
`ubuntu-archive-keyring` and/or `debian-archive-keyring` packages explicitly,
in addition to `debootstrap`, depending on what kind of distribution images
you want to build. `debootstrap` on Debian only pulls in the Debian keyring
on its own, and the version on Ubuntu only the one from Ubuntu.

Note that the minimum required Python version is 3.6.

# REFERENCES
* [Primary mkosi git repository on GitHub](https://github.com/systemd/mkosi/)
* [mkosi — A Tool for Generating OS Images](http://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html) introductory blog post by Lennart Poettering
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN

# SEE ALSO
`systemd-nspawn(1)`, `dnf(8)`, `debootstrap(8)`
