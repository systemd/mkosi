# mkosi Changelog

## v13

- The `--network-veth` option has been renamed `--netdev`, since it implies usage of a virtual ethernet device, which is not what is done when booting images with qemu where a TUN/TAP device is used.
- The networkd config file installed by mkosi when the `--netdev`  option (what used to be `--network-veth`) is
  used (formerly `/etc/systemd/network/80-mkosi-network-veth.network` in the image) now only matches against network interfaces using the virtio_net driver.
  Please make sure you weren't relying on this file to configure any network
  interfaces other than the tun/tap virtio-net interface created by mkosi when
  booting the image in QEMU with the --netdev option. If you were relying
  on this config file to configure other interfaces, you'll have to re-create it
  with the correct match and a lower initial number in the filename to make sure networkd will keep configuring your
  interface, e.g. via the `mkosi.skeleton` or `mkosi.extra` trees or a `mkosi.postinst` script.
- The kernel-install script for building unified kernel images was removed. From v13 onwards, on systems using kernel-install,
  mkosi won't automatically build new unified kernel images anymore when a kernel is updated or installed. To keep this
  behavior, you can install the kernel-install script manually via a skeleton tree. The original script can be found
  [here](https://github.com/systemd/mkosi/blob/3798eb0c2ebcdf7dac207a559a3cb5a65cdb77b0/mkosi/resources/dracut_unified_kernel_install.sh).

## v12

- Fix handling of baselayout in Gentoo installations.


## v11

- Support for Rocky Linux, Alma Linux, and Gentoo has been added!
- A new `ManifestFormat=` option can be used to generate "manifest" files that
  describe what packages were installed. With `json`, a JSON file that shows
  the names and versions of all installed packages will be created. With
  `changelog`, a longer human-readable file that shows package descriptions and
  changelogs will be generated. This latter format should be considered
  experimental and likely to change in later versions.
- A new `RemovePackages=` option can be used to uninstall packages after the
  build and finalize scripts have been done. This is useful for the case where
  packages are required by the build scripts, or pulled in as dependencies
  for scriptlets of other packages, but are not necessary in the final image.
- A new `BaseImage=` option can be used to build "system extensions" a.k.a.
  "sysexts" — partial images which are mounted on top of an existing system
  to provide additional files under `/usr/`. See the
  [systemd-sysext man page](https://www.freedesktop.org/software/systemd/man/systemd-sysext.html)
  for more information.
- A new `CleanPackageMetadata=` option can be used to force or disable the
  removal of package manager files. When this option is not used, they are
  removed when the package manager is not installed in the final image.
- A new `UseHostRepositories=` option instructs mkosi to use repository
  configuration from the host system, instead of the internal list.
- A new `SshAgent=` option configures the path to the ssh agent.
- A new `SshPort=` option overrides the port used for ssh.
- The `Verity=` setting supports a new value `signed`. When set, verity data
  will be signed and the result inserted as an additional partition in the
  image. See https://systemd.io/DISCOVERABLE_PARTITIONS for details about
  signed disk images. This information is used by `systemd-nspawn`,
  `systemd-dissect`, `systemd-sysext`, `systemd-portabled` and `systemd`'s
  `RootImage=` setting (among others) to cryptographically validate the image
  file systems before use.
- The `--build-environment=` option was renamed to `--environment=` and
  extended to cover *all* invoked scripts, not just the `mkosi.build`.
  The old name is still understood.
- With `--with-network=never`, `dnf` is called with `--cacheonly`, so that the
  package lists are not refreshed. This gives a degree of reproducibility when
  doing repeated installs with the same package set (and also makes installs
  significantly faster).
- The `--debug=` option gained a new value `disk` to show information about disk
  sized and partition allocations.
- Some sections and settings have been renamed for clarity: [Packages] is now
  [Content], `Password=`, `PasswordIsHashed=`, and `Autologin=` are now in
  [Content]. The old names are still supported, but not documented.
- When `--prepare-script=`/`--build-script=`/`--finalize-script=` is used with
  an empty argument, the corresponding script will not be called.
- Python 3.7 is the minimal supported version.
- Note to packagers: the Python `cryptography` module is needed for signing
  of verity data.


## v10

- Minimum supported Python version is now 3.7.
- Automatic configuration of the network for Arch Linux was removed to bring
  different distros more in line with each other. To add it back, add a
  postinstall script to configure your network manager of choice.
- The `--default` option was changed to not affect the search location of
  `mkosi.default.d/`. mkosi now always searches for `mkosi.default.d/` in the
  working directory.
- `quiet` was dropped from the default kernel command line.
- `--source-file-transfer` and `--source-file-transfer-final` now accept an
  empty value as the argument which can be used to override a previous setting.
- A new command `mkosi serve` can be used to serve build artifacts using a
  small embedded HTTP server. This is useful for `machinectl pull-raw …` and
  `machinectl pull-tar …`.
- A new command `mkosi genkey` can be used to generate secure boot keys for
  use with mkosi's `--secure-boot` options. The number of days the keys should
  remain valid can be specified via `--secure-boot-valid-days=` and their CN via
  `--secure-boot-common-name=`.
- When booting images with `qemu`, firmware that supports Secure Boot will be
  used if available.
- `--source-resolve-symlinks` and `--source-resolve-symlinks-final` options are
  added to control how symlinks in the build sources are handled when
  `--source-file-transfer[-final]=copy-all` is used.
- `--build-environment=` option was added to set variables for the build script.
- `--usr-only` option was added to build images that comprise only the `/usr/`
  directory, instead of the whole root file system. This is useful for stateless
  systems where `/etc/` and `/var/` are populated by
  `systemd-tmpfiles`/`systemd-sysusers` and related calls at boot, or systems
  that are originally shipped without a root file system, but where
  `systemd-repart` adds one on the first boot.
- Support for "image versions" has been added. The version number can be set
  with `--version-number=`. It is included in the default output filename and
  passed as `$IMAGE_VERSION` to the build script. In addition, `mkosi bump` can
  be used to increase the version number by one, and `--auto-bump` can be used
  to increase it automatically after successful builds.
- Support for "image identifiers" has been added. The id can be set with
  `--image=id` and is passed to the build script as `$IMAGE_ID`.
- The list of packages to install can be configured with `--base-packages=`.
  With `--base-packages=no`, only packages specified with `--packages=` will be
  installed. With `--base-packages=conditional`, various packages will be
  installed "conditionally", i.e. only if some other package is otherwise
  pulled in. For example, `systemd-udev` may be installed only if `systemd`
  is listed in `--packages=`.
- CPIO output format has been added. This is useful for kernel initramfs images.
- Output compression can be configured with `--compress-fs=` and
  `--compress-output=`, and support for `zstd` has been added.
- `--ssh-key=` option was added to control the ssh key used to connect to the
  image.
- `--remove-files=` option was added to remove file from the generated images.
- Inline comments are now allowed in config files (anything from `#` until the
  end of the line will be ignored).
- The development branch was renamed from `master` to `main`.


## v9

### Highlighted Changes

- The mkosi Github action now defaults to the current release of mkosi instead
  of the tip of the master branch.
- Add a `ssh` verb and accompanying `--ssh` option. The latter sets up SSH keys
  for direct SSH access into a booted image, whereas the former can be used to
  start an SSH connection to the image.
- Allow for distribution specific `mkosi.*` files in subdirectories of
  `mkosi.default.d/`. These files are only processed if a subdirectory named
  after the target distribution of the image is found in `mkosi.default.d/`.
- The summary of used options for the image is now only printed when building
  the image for the first time or when the `summary` verb is used.
- All of mkosi's output, except for the build script, will now go to
  stderr. There was no clear policy on this before and this choice makes it
  easier to use images generated and booted via mkosi with language servers
  using stdin and stdout for communication.
- `--source-file-transfer` now defaults to `copy-git-others` to also include
  untracked files.
- [black](https://github.com/psf/black) is now used as a code style and
  conformance with it is checked in CI.
- Add a new `--ephemeral` option to boot into a temporary snapshot of the image
  that will be thrown away on shutdown.
- Add a new option `--network-veth` to set up a virtual Ethernet link between
  the host and the image for usage with nspawn or QEMU
- Add a new `--autologin` option to automatically log into the root account upon
  boot of the image. This is useful when using mkosi for boot tests.
- Add a new `--hostonly` option to generate host specific initrds. This is
  useful when using mkosi for boot tests.
- Add a new `--install-directory` option and special directory
  `mkosi.installdir/` that will be used as `$DESTDIR` for the build script, so
  that the contents of this directory can be shared between builds.
- Add a new `--include-directory` option and special directory
  `mkosi.includedir/` that will be mounted at `/usr/include` during the
  build. This way headers files installed during the build can be made available
  to the host system, which is useful for usage with language servers.
- Add a new `--source-file-transfer-final` option to complement
  `--source-file-transfer`. It does the same `--source-file-transfer` does for
  the build image, but for the final one.
- Add a new `--tar-strip-selinux-context` option to remove SELinux xattrs. This
  is useful when an image with a target distribution not using SELinux is
  generated on a host that is using it.
- Document the `--no-chown` option. Using this option, artifacts generated by
  mkosi are not chowned to the user invoking mkosi when it is invoked via
  sudo. It has been with as for a while, but hasn't been documented until now.

### Fixed Issues

- [#506](https://github.com/systemd/mkosi/issues/506)
- [#559](https://github.com/systemd/mkosi/issues/559)
- [#561](https://github.com/systemd/mkosi/issues/561)
- [#562](https://github.com/systemd/mkosi/issues/562)
- [#575](https://github.com/systemd/mkosi/issues/575)
- [#580](https://github.com/systemd/mkosi/issues/580)
- [#593](https://github.com/systemd/mkosi/issues/593)

### Authors

- Daan De Meyer
- Joerg Behrmann
- Luca Boccassi
- Peter Hutterer
- ValdikSS
