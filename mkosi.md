% mkosi(1)
%
%

# NAME

mkosi — Build Bespoke OS Images

# SYNOPSIS

`mkosi [options…] summary`

`mkosi [options…] build [script parameters…]`

`mkosi [options…] shell [command line…]`

`mkosi [options…] boot [nspawn settings…]`

`mkosi [options…] qemu [qemu parameters…]`

`mkosi [options…] ssh [command line…]`

`mkosi [options…] clean`

`mkosi [options…] serve`

`mkosi [options…] bump`

`mkosi [options…] genkey`

`mkosi [options…] help`

# DESCRIPTION

`mkosi` is a tool for easily building customized OS images. It's a
fancy wrapper around `dnf --installroot`, `apt`, `pacman` and `zypper`
that may generate disk images with a number of bells and whistles.

## Command Line Verbs

The following command line verbs are known:

`summary`

: Outputs a human-readable summary of all options used for building an
  image. This will parse the command line and `mkosi.conf` file as it
  would do on `build`, but only output what it is configured for and not
  actually build anything.`

`build`

: This builds the image based on the settings passed in on the command line or
  read from a `mkosi.conf` file. This command is the default if no verb is
  explicitly specified. This command must be executed as `root`. Any arguments
  passed after the `build` verb are passed as arguments to the build script (if
  there is one).

`shell`

: This builds the image if it is not built yet, and then invokes
  `systemd-nspawn` to acquire an interactive shell prompt in it. An optional
  command line may be specified after the `shell` verb, to be invoked in place
  of the shell in the container. Use `-f` in order to rebuild the image
  unconditionally before acquiring the shell, see below. This command must be
  executed as `root`.

`boot`

: Similar to `shell`, but boots the image using `systemd-nspawn`. An optional
  command line may be specified after the `boot` verb, which is then passed as
  the "kernel command line" to the init system in the image.

`qemu`

: Similar to `boot`, but uses `qemu` to boot up the image, i.e. instead of
  container virtualization virtual machine virtualization is used. This verb is
  only supported for disk images that contain a boot loader. Any arguments
  specified after the `qemu` verb are appended to the `qemu` invocation.

`ssh`

: When the image is built with the `Ssh=yes` option, this command connects
  to a booted (`boot`, `qemu` verbs) container or VM via SSH. Make sure to
  run `mkosi ssh` with the same config as `mkosi build` was run with so
  that it has the necessary information available to connect to the running
  container/VM via SSH. Any arguments passed after the `ssh` verb are passed as
  arguments to the `ssh` invocation.

`clean`

: Remove build artifacts generated on a previous build. If combined
  with `-f`, also removes incremental build cache images. If `-f` is
  specified twice, also removes any package cache.

`serve`

: This builds the image if it is not built yet, and then serves the
  output directory (i.e. usually `mkosi.output/`, see below) via a
  small embedded HTTP server, listening on port 8081. Combine with
  `-f` in order to rebuild the image unconditionally before serving
  it. This command is useful for testing network based acquisition of
  OS images, for example via `machinectl pull-raw …` and `machinectl
  pull-tar …`.

`bump`

: Bumps the image version from `mkosi.version` and writes the resulting
  version string to `mkosi.version`. This is useful for implementing a
  simple versioning scheme: each time this verb is called the version is
  bumped in preparation for the subsequent build. Note that
  `--auto-bump`/`-B` may be used to automatically bump the version
  after each successful build.

`genkey`

: Generate a pair of SecureBoot keys for usage with the
  `SecureBootKey=`/`--secure-boot-key=` and
  `SecureBootCertificate=`/`--secure-boot-certificate=` options.

`help`

: This verb is equivalent to the `--help` switch documented below: it
  shows a brief usage explanation.

## Execution Flow

Execution flow for `mkosi build`. Default values/calls are shown in parentheses.
When building with `--incremental` mkosi creates a cache of the distribution
installation if not already existing and replaces the distribution installation
in consecutive runs with data from the cached one.

* Copy skeleton trees (`mkosi.skeleton`) into image
* Install distribution and packages into image or use cache tree if available
* Install build packages in overlay if a build script is configured
* Run prepare script on image and on image + build overlay if a build script is configured (`mkosi.prepare`)
* Run build script on image + build overlay if a build script is configured (`mkosi.build`)
* Copy the build script outputs into the image
* Copy the extra trees into the image (`mkosi.extra`)
* Run `kernel-install`
* Install systemd-boot
* Run post-install script (`mkosi.postinst`)
* Run `systemctl preset-all`
* Remove packages and files (`RemovePackages=`, `RemoveFiles=`)
* Run finalize script (`mkosi.finalize`)
* Run SELinux relabel is a SELinux policy is installed
* Generate unified kernel image
* Generate final output format

## Supported output formats

The following output formats are supported:

* Raw *GPT* disk image, created using systemd-repart

* Plain directory, containing the OS tree (*directory*)

* btrfs subvolume

* Tar archive (*tar*)

* CPIO archive (*cpio*) in the format appropriate for a kernel initrd

When a *GPT* disk image is created, repart partition definition files
may be placed in `mkosi.repart/` to configure the generated disk image.

## Configuration Settings

The following settings can be set through configuration files (the
syntax with `SomeSetting=value`) and on the command line (the syntax
with `--some-setting=value`). For some command line parameters, a
single-letter shortcut is also allowed. In the configuration files,
the setting must be in the appropriate section, so the settings are
grouped by section below.

Configuration is parsed in the following order:

* The command line arguments are parsed
* `mkosi.conf` is parsed if it exists in the directory set with
  `--directory=` or the current working directory if `--directory=` is
  not used.
* `mkosi.conf.d/` is parsed in the same directory if it exists. Each
  directory and each file with the `.conf` extension in `mkosi.conf.d/`
  is parsed. Any directory in `mkosi.conf.d` is parsed as if it were
  a regular top level directory.
* Any default paths (depending on the option) are configured if the
  corresponding path exists.

If a setting is specified multiple times across the different sources
of configuration, the first assignment that is found is used. For example,
a setting specified on the command line will always take precedence over
the same setting configured in a config file. To override settings in a
dropin file, make sure your dropin file is alphanumerically ordered
before the config file that you're trying to override.

Settings that take a list of values are merged by prepending each value
to the previously configured values. If a value of a list setting is
prefixed with `!`, if any later assignment of that setting tries to add
the same value, that value is ignored. Values prefixed with `!` can be
globs to ignore more than one value.

To conditionally include configuration files, the `[Match]` section can
be used. A configuration file is only included if all the conditions in the
`[Match]` block are satisfied. If a condition in `[Match]` depends on a
setting and the setting has not been explicitly configured when the condition
is evaluated, the setting is assigned its default value.

Command line options that take no argument are shown without "=" in
their long version. In the config files, they should be specified with
a boolean argument: either "1", "yes", or "true" to enable, or "0",
"no", "false" to disable.

### [Match] Section.

`Distribution=`

: Matches against the configured distribution. Multiple distributions may
  be specified, separated by spaces. If multiple distributions are specified,
  the condition is satisfied if the current distribution equals any of the
  specified distributions.

`Release=`

: Matches against the configured distribution release. If this condition
  is used and no distribution has been explicitly configured yet, the
  host distribution and release are used. Multiple releases may be specified,
  separated by spaces. If multiple releases are specified, the condition is
  satisfied if the current release equals any of the specified releases.

`PathExists=`

: This condition is satisfied if the given path exists. Relative paths are
  interpreted relative to the parent directory of the config file that the
  condition is read from.

`ImageId=`

: Matches against the configured image ID, supporting globs. If this condition
  is used and no image ID has been explicitly configured yet, this condition
  fails. Multiple image IDs may be specified, separated by spaces. If multiple
  image IDs are specified, the condition is satisfied if the configured image ID
  equals any of the specified image IDs.

`ImageVersion=`

: Matches against the configured image version. Image versions can be prepended
  by the operators `==`, `!=`, `>=`, `<=`, `<`, `>` for rich version comparisons
  according to the UAPI group version format specification. If no operator is
  prepended, the equality operator is assumed by default If this condition is
  used and no image Version has be explicitly configured yet, this condition
  fails. Multiple image version constraints can be specified as a
  space-separated list. If multiple image version constraints are specified, all
  must be satisfied for the match to succeed.

| Matcher         | Multiple Values | Globs | Rich Comparisons | Default                 |
|-----------------|-----------------|-------|------------------|-------------------------|
| `Distribution=` | yes             | no    | no               | match host distribution |
| `Release=`      | yes             | no    | no               | match host release      |
| `PathExists=`   | no              | no    | no               | match fails             |
| `ImageId=`      | yes             | yes   | no               | match fails             |
| `ImageVersion=` | yes             | no    | yes              | match fails             |

### [Distribution] Section

`Distribution=`, `--distribution=`, `-d`

: The distribution to install in the image. Takes one of the following
  arguments: `fedora`, `debian`, `ubuntu`, `arch`, `opensuse`, `mageia`,
  `centos`, `openmandriva`, `rocky`, and `alma`. If not specified,
  defaults to the distribution of the host. Whenever a distribution is
  assigned, the release is reset to the default release configured
  for that distribution.

`Release=`, `--release=`, `-r`

: The release of the distribution to install in the image. The precise
  syntax of the argument this takes depends on the distribution used,
  and is either a numeric string (in case of Fedora Linux, CentOS, …,
  e.g. `29`), or a distribution version name (in case of Debian,
  Ubuntu, …, e.g. `artful`). Defaults to a recent version of the
  chosen distribution.

`Mirror=`, `--mirror=`, `-m`

: The mirror to use for downloading the distribution packages. Expects
  a mirror URL as argument.

`LocalMirror=`, `--local-mirror=`

: The mirror will be used as a local, plain and direct mirror instead
  of using it as a prefix for the full set of repositories normally supported
  by distributions. Useful for fully offline builds with a single repository.
  Supported on deb/rpm/arch based distributions. Overrides `--mirror=` but only
  for the local mkosi build, it will not be configured inside the final image,
  `--mirror=` (or the default repository) will be configured inside the final
  image instead.

`RepositoryKeyCheck=`, `--repository-key-check=`

: Controls signature/key checks when using repositories, enabled by default.
  Useful to disable checks when combined with `--local-mirror=` and using only
  a repository from a local filesystem. Not used for DNF-based distros yet.

`Repositories=`, `--repositories=`

: Additional package repositories to use during installation. Expects
  one or more URLs as argument, separated by commas. This option may
  be used multiple times, in which case the list of repositories to
  use is combined. Use "!\*" to remove all repositories from to the list
  or use e.g. "!repo-url" to remove just one specific repository. For Arch
  Linux, additional repositories must be passed in the form `<name>::<url>`
  (e.g. `myrepo::https://myrepo.net`).

`RepositoryDirectories`, `--repo-dir=`

: This option can (for now) only be used with RPM-based distributions,
  Debian-based distributions and Arch Linux. It takes a comma separated list of
  directories containing extra repository definitions that will be used when
  installing packages. The files are passed directly to the corresponding
  package manager and should be written in the format expected by the package
  manager of the image's distro.

`Architecture=`, `--architecture=`

: The architecture to build the image for. Note that this currently
  only works for architectures compatible with the host's
  architecture.

### [Output] Section

`Format=`, `--format=`, `-t`

: The image format type to generate. One of `directory` (for generating OS
  images inside a local directory), `subvolume` (similar, but as a btrfs
  subvolume), `subvolume_ro` (btrfs read-only subvolume),
  `tar` (similar, but a tarball of the image is generated), `cpio`
  (similar, but a cpio archive is generated), `disk` (a block device image
  with a GPT partition table).

`ManifestFormat=`, `--manifest-format=`

: The manifest format type or types to generate. A comma-delimited
  list consisting of `json` (the standard JSON output format that
  describes the packages installed), `changelog` (a human-readable
  text format designed for diffing). Defaults to `json`.

`Output=`, `--output=`, `-o`

: Path for the output image file to generate. Takes a relative or
  absolute path where the generated image will be placed. If neither
  this option nor `OutputDirectory=` is used, the image is
  generated under the name `image`, but its name suffixed with an
  appropriate file suffix (e.g. `image.raw.xz` in case `gpt_ext4` is
  used in combination with `xz` compression). If the `ImageId=` option
  is configured it is used instead of `image` in the default output
  name. If an image version is specified via `ImageVersion=`, it is
  included in the default name, e.g. a specified image version of
  `7.8` might result in an image file name of `image_7.8.raw.xz`.

`OutputDirectory=`, `--output-dir=`, `-O`

: Path to a directory where to place all generated artifacts (i.e. the
  generated image when an output path is not given, `SHA256SUMS` file,
  etc.). If this is not specified and the directory `mkosi.output/`
  exists in the local directory, it is automatically used for this
  purpose. If the setting is not used and `mkosi.output/` does not
  exist, all output artifacts are placed adjacent to the output image
  file. If an output directory is configured, mkosi will create
  `distro~release` subdirectories in it to store the artfifacts per
  distro, release combination that's built.

`WorkspaceDirectory=`, `--workspace-dir=`

: Path to a directory where to store data required temporarily while
  building the image. This directory should have enough space to store
  the full OS image, though in most modes the actually used disk space
  is smaller. If not specified, and `mkosi.workspace/` exists in the
  local directory, it is used for this purpose. Otherwise, hidden
  subdirectories of the current working directory are used.

: The data in this directory is removed automatically after each
  build. It's safe to manually remove the contents of this directory
  should an `mkosi` invocation be aborted abnormally (for example, due
  to reboot/power failure).

`CacheDirectory=`, `--cache-dir=`

: Takes a path to a directory to use as package cache for the
  distribution package manager used. If this option is not used, but a
  `mkosi.cache/` directory is found in the local directory it is
  automatically used for this purpose. The directory configured this
  way is mounted into both the development and the final image while
  the package manager is running.

`BuildDirectory=`, `--build-dir=`

: Takes a path of a directory to use as build directory for build
  systems that support out-of-tree builds (such as Meson). The
  directory used this way is shared between repeated builds, and
  allows the build system to reuse artifacts (such as object files,
  executable, …) generated on previous invocations. This directory is
  mounted into the development image when the build script is
  invoked. The build script can find the path to this directory in the
  `$BUILDDIR` environment variable. If this option is not specified,
  but a directory `mkosi.builddir/` exists in the local directory it
  is automatically used for this purpose (also see the "Files" section
  below).

`InstallDirectory=`, `--install-dir=`

: Takes a path of a directory to use as the install directory. The
  directory used this way is shared between builds and allows the
  build system to not have to reinstall files that were already
  installed by a previous build and didn't change. The build script
  can find the path to this directory in the `$DESTDIR` environment
  variable. If this option is not specified, but a directory
  `mkosi.installdir` exists in the local directory, it is automatically
  used for this purpose (also see the "Files" section below).

`Force=`, `--force`, `-f`

: Replace the output file if it already exists, when building an
  image. By default when building an image and an output artifact
  already exists `mkosi` will refuse operation. Specify this option
  once to delete all build artifacts from a previous run before
  re-building the image. If incremental builds are enabled,
  specifying this option twice will ensure the intermediary
  cache files are removed, too, before the re-build is initiated. If a
  package cache is used (also see the "Files" section below),
  specifying this option thrice will ensure the package cache is
  removed too, before the re-build is initiated. For the `clean`
  operation this option has a slightly different effect: by default
  the verb will only remove build artifacts from a previous run, when
  specified once the incremental cache files are deleted too, and when
  specified twice the package cache is also removed.

  <!--  FIXME: allow `Force=<n>` -->

`Bootable=`, `--bootable=`

: Takes a boolean or `auto`. Enables or disable generating of a bootable
  image. If enabled, mkosi will install systemd-boot, run kernel-install,
  generate unified kernel images for installed kernels and add an ESP
  partition when the disk image output is used. If systemd-boot is not
  installed or no kernel images can be found, the build will fail. `auto`
  behaves as if the option was enabled, but the build won't fail if either
  no kernel images or systemd-boot can't be found. If disabled, systemd-boot
  won't be installed even if found inside the image, kernel-install won't be
  executed, no unified kernel images will be generated and no ESP partition
  will be added to the image if the disk output format is used.

`KernelCommandLine=`, `--kernel-command-line=`

: Use the specified kernel command line when building images. By default
  command line arguments get appended. To remove all arguments from the
  current list pass "!\*". To remove specific arguments add a space
  separated list of "!" prefixed arguments. For example adding
  "!\* console=ttyS0 rw" to a `mkosi.conf` file or the command line
  arguments passes "console=ttyS0 rw" to the kernel in any case. Just
  adding "console=ttyS0 rw" would append these two arguments to the kernel
  command line created by lower priority configuration files or previous
  `KernelCommandLine=` command line arguments.

`SecureBoot=`, `--secure-boot`

: Sign the resulting kernel/initrd image for UEFI SecureBoot.

`SecureBootKey=`, `--secure-boot-key=`

: Path to the PEM file containing the secret key for signing the
  UEFI kernel image, if `SecureBoot=` is used.

`SecureBootCertificate=`, `--secure-boot-certificate=`

: Path to the X.509 file containing the certificate for the signed
  UEFI kernel image, if `SecureBoot=` is used.

[//]: # (Please add external tools to the list here.)

`SignExpectedPCR=`, `--sign-expected-pcr`

: Measure the components of the unified kernel image (UKI) using
  `systemd-measure` and embed the PCR signature into the unified kernel
  image. This option takes a boolean value or the special value `auto`,
  which is the default, which is equal to a true value if the
  [`cryptography`](https://cryptography.io/) module is importable and
  the `systemd-measure` binary is in `PATH`.

`CompressOutput=`, `--compress-output=`

: Configure compression for the resulting image or archive. The
  argument can be either a boolean or a compression algorithm (`xz`,
  `zstd`). `xz` compression is used by default. Note that when applied
  to block device image types this means the image cannot be started
  directly but needs to be decompressed first. This also means that
  the `shell`, `boot`, `qemu` verbs are not available when this option
  is used. Implied for `tar` and `cpio`.

`ImageVersion=`, `--image-version=`

: Configure the image version. This accepts any string, but it is
  recommended to specify a series of dot separated components. The
  version may also be configured in a file `mkosi.version` in which
  case it may be conveniently managed via the `bump` verb or the
  `--auto-bump` option. When specified the image version is included
  in the default output file name, i.e. instead of `image.raw` the
  default will be `image_0.1.raw` for version `0.1` of the image, and
  similar. The version is also passed via the `$IMAGE_VERSION` to any
  build scripts invoked (which may be useful to patch it into
  `/etc/os-release` or similar, in particular the `IMAGE_VERSION=`
  field of it).

`ImageId=`, `--image-id=`

: Configure the image identifier. This accepts a freeform string that
  shall be used to identify the image with. If set the default output
  file will be named after it (possibly suffixed with the version). If
  this option is used the root, `/usr/` and Verity partitions in the
  image will have their labels set to this (possibly suffixed by the
  image version). The identifier is also passed via the `$IMAGE_ID` to
  any build scripts invoked (which may be useful to patch it into
  `/etc/os-release` or similar, in particular the `IMAGE_ID=` field of
  it).

`SplitArtifacts=`, `--split-artifacts`

: If specified and building a disk image, pass `--split=yes` to systemd-repart
  to have it write out split partition files for each configured partition.
  Read the [man](https://www.freedesktop.org/software/systemd/man/systemd-repart.html#--split=BOOL)
  page for more information. This is useful in A/B update scenarios where
  an existing disk image shall be augmented with a new version of a
  root or `/usr` partition along with its Verity partition and unified
  kernel.

`RepartDirectory=`, `--repart-dir=`

: Path to a directory containing systemd-repart partition definition files that
  are used when mkosi invokes systemd-repart when building a disk image. If not
  specified and `mkosi.repart/` exists in the local directory, it will be used
  instead. Note that mkosi invokes repart with `--root=` set to the root of the
  image root, so any `CopyFiles=` source paths in partition definition files will
  be relative to the image root directory.

`Overlay=`, `--overlay`

: When used together with `BaseTrees=`, the output will consist only out of
  changes to the specified base trees. Each base tree is attached as a lower
  layer in an overlayfs structure, and the output becomes the upper layer,
  initially empty. Thus files that are not modified compared to the base trees
  will not be present in the final output.

: This option may be used to create systemd "system extensions" or
  portable services. See
  https://uapi-group.org/specifications/specs/extension_image for more
  information.

`TarStripSELinuxContext=`, `--tar-strip-selinux-context`

: If running on a SELinux-enabled system (Fedora Linux, CentOS, Rocky Linux,
  Alma Linux), files
  inside the container are tagged with SELinux context extended
  attributes (`xattrs`), which may interfere with host SELinux rules
  in building or further container import stages.  This option strips
  SELinux context attributes from the resulting tar archive.

### [Content] Section

`Packages=`, `--package=`, `-p`

: Install the specified distribution packages (i.e. RPM, DEB, …) in the
  image. Takes a comma separated list of package specifications. This option
  may be used multiple times in which case the specified package lists are
  combined. Packages specified this way will be installed both in the
  development and the final image. Use `BuildPackages=` to specify packages
  that shall only be used for the image generated in the build image, but that
  shall not appear in the final image.

: The types and syntax of "package specifications" that are allowed depend on
  the package installer (e.g. `dnf` or `yum` for `rpm`-based distros or `apt`
  for `deb`-based distros), but may include package names, package names with
  version and/or architecture, package name globs, paths to packages in the
  file system, package groups, and virtual provides, including file paths.

: To remove a package e.g. added by a `mkosi.conf` configuration
  file prepend the package name with `!`. For example -p "!apache2"
  would remove the apache2 package. To replace the apache2 package by
  the httpd package just add -p "!apache2,httpd" to the command line
  arguments. To remove all packages use "!\*".

: Example: when using an distro that uses `dnf`,
  `Packages=meson libfdisk-devel.i686 git-* prebuilt/rpms/systemd-249-rc1.local.rpm /usr/bin/ld @development-tools python3dist(mypy)`
  would install
  the `meson` package (in the latest version),
  the 32-bit version of the `libfdisk-devel` package,
  all available packages that start with the `git-` prefix,
  a `systemd` rpm from the local file system,
  one of the packages that provides `/usr/bin/ld`,
  the packages in the "Development Tools" group,
  and the package that contains the `mypy` python module.

`WithDocs=`, `--with-docs`

: Include documentation in the image built. By default if the
  underlying distribution package manager supports it documentation is
  not included in the image built. The `$WITH_DOCS` environment
  variable passed to the `mkosi.build` script indicates whether this
  option was used or not.

`WithTests=`, `--without-tests`, `-T`

: If set to false (or when the command-line option is used), the
  `$WITH_TESTS` environment variable is set to `0` when the
  `mkosi.build` script is invoked. This is supposed to be used by the
  build script to bypass any unit or integration tests that are
  normally run during the source build process. Note that this option
  has no effect unless the `mkosi.build` build script honors it.

`BaseTrees=`, `--base-tree=`

: Takes a colon separated pair of directories to use as base images. When
  used, these base images are each copied into the OS tree and form the
  base distribution instead of installing the distribution from scratch.
  Only extra packages are installed on top of the ones already installed
  in the base images. Note that for this to work properly, the base image
  still needs to contain the package manager metadata (see
  `CleanPackageMetadata=`).

: Instead of a directory, a tar file or a disk image may be provided. In
  this case it is unpacked into the OS tree. This mode of operation allows
  setting permissions and file ownership explicitly, in particular for projects
  stored in a version control system such as `git` which retain full file
  ownership and access mode metadata for committed files.

`SkeletonTrees=`, `--skeleton-tree=`

: Takes a colon separated pair of paths. The first path refers to a
  directory to copy into the OS tree before invoking the package
  manager. The second path refers to the target directory inside the
  image. If the second path is not provided, the directory is copied
  on top of the root directory of the image. Use this to insert files
  and directories into the OS tree before the package manager installs
  any packages. If this option is not used, but the `mkosi.skeleton/`
  directory is found in the local directory it is automatically used
  for this purpose with the root directory as target (also see the
  "Files" section below).

: As with the base tree logic above, instead of a directory, a tar
  file may be provided too. `mkosi.skeleton.tar` will be automatically
  used if found in the local directory.

`ExtraTrees=`, `--extra-tree=`

: Takes a colon separated pair of paths. The first path refers to a
  directory to copy from the host into the image. The second path refers
  to the target directory inside the image. If the second path is not
  provided, the directory is copied on top of the root directory of the
  image. Use this to override any default configuration files shipped
  with the distribution. If this option is not used, but the
  `mkosi.extra/` directory is found in the local directory it is
  automatically used for this purpose with the root directory as target.
  (also see the "Files" section below).

: As with the base tree logic above, instead of a directory, a tar
  file may be provided too. `mkosi.extra.tar` will be automatically
  used if found in the local directory.

`CleanPackageMetadata=`, `--clean-package-metadata=`

: Enable/disable removal of package manager databases, caches, and
  logs at the end of installation. Can be specified as true, false, or
  "`auto`" (the default). With "`auto`", files will be removed if the
  respective package manager executable is *not* present at the end of
  the installation.

`RemoveFiles=`, `--remove-files=`

: Takes a comma-separated list of globs. Files in the image matching
  the globs will be purged at the end.

`RemovePackages=`, `--remove-package=`

: Takes a comma-separated list of package specifications for removal, in the
  same format as `Packages=`. The removal will be performed as one of the last
  steps. This step is skipped if `CleanPackageMetadata=no` is used.

: This option is currently only implemented for distributions using `dnf`.

`Environment=`, `--environment=`

: Adds variables to the environment that the
  build/prepare/postinstall/finalize scripts are executed with. Takes
  a space-separated list of variable assignments or just variable
  names. In the latter case, the values of those variables will be
  passed through from the environment in which `mkosi` was invoked.
  This option may be specified more than once, in which case all
  listed variables will be set. If the same variable is set twice, the
  later setting overrides the earlier one.

`BuildSources=`, `--build-sources=`

: Takes a path to a source tree to mount into the development image, if
  the build script is used.

`BuildPackages=`, `--build-package=`

: Similar to `Packages=`, but configures packages to install only in
  the first phase of the build, into the development image. This
  option should be used to list packages containing header files,
  compilers, build systems, linkers and other build tools the
  `mkosi.build` script requires to operate. Note that packages listed
  here are only included in the image created during the first phase
  of the build, and are absent in the final image. Use `Packages=` to
  list packages that shall be included in both.

: Packages are appended to the list. Packages prefixed with "!" are
  removed from the list. "!\*" removes all packages from the list.

`Password=`, `--password=`

: Set the password of the `root` user. By default the `root` account
  is locked. If this option is not used, but a file `mkosi.rootpw`
  exists in the local directory, the root password is automatically
  read from it.

`PasswordIsHashed=`, `--password-is-hashed`

: Indicate that the password supplied for the `root` user has already been
  hashed, so that the string supplied with `Password=` or `mkosi.rootpw` will
  be written to `/etc/shadow` literally.

`Autologin=`, `--autologin`

: Enable autologin for the `root` user on `/dev/pts/0` (nspawn),
  `/dev/tty1` and `/dev/ttyS0`.

`BuildScript=`, `--build-script=`

: Takes a path to an executable that is used as build script for this
  image. The specified script is copied onto the development image and
  executed inside a namespaced chroot environment. If this option is not
  used, but the `mkosi.build` file found in the local directory it is
  automatically used for this purpose (also see the "Files" section below).
  Specify an empty value to disable automatic detection.

`PrepareScript=`, `--prepare-script=`

: Takes a path to an executable that is invoked inside the image right
  after installing the software packages. It is the last step before
  the image is cached (if incremental mode is enabled).  This script
  is invoked inside a namespaced chroot environment, and thus does not
  have access to host resources.  If this option is not used, but an
  executable script `mkosi.prepare` is found in the local directory, it
  is automatically used for this purpose. Specify an empty value to
  disable automatic detection.

`PostInstallationScript=`, `--postinst-script=`

: Takes a path to an executable that is invoked inside the final image
  right after copying in the build artifacts generated in the first
  phase of the build. This script is invoked inside a namespaced chroot
  environment, and thus does not have access to host resources. If this
  option is not used, but an executable `mkosi.postinst` is found in the
  local directory, it is automatically used for this purpose. Specify an
  empty value to disable automatic detection.

`FinalizeScript=`, `--finalize-script=`

: Takes a path to an executable that is invoked outside the final
  image right after copying in the build artifacts generated in the
  first phase of the build, and after having executed the
  `mkosi.postinst` script (see `PostInstallationScript=`). This script
  is invoked directly in the host environment, and hence has full
  access to the host's resources. If this option is not used, but an
  executable `mkosi.finalize` is found in the local directory, it is
  automatically used for this purpose. Specify an empty value to
  disable automatic detection.

`WithNetwork=`, `--with-network=`

: When true, enables network connectivity while the build script
  `mkosi.build` is invoked. By default, the build script runs with
  networking turned off. The `$WITH_NETWORK` environment variable is
  passed to the `mkosi.build` build script indicating whether the
  build is done with or without network.

`CacheOnly=`, `--cache-only=`

: If specified, the package manager is instructed not to contact the
  network for updating package data. This provides a minimal level of
  reproducibility, as long as the package data cache is already fully
  populated.

`Settings=`, `--settings=`

: Specifies a `.nspawn` settings file for `systemd-nspawn` to use in
  the `boot` and `shell` verbs, and to place next to the generated
  image file. This is useful to configure the `systemd-nspawn`
  environment when the image is run. If this setting is not used but
  an `mkosi.nspawn` file found in the local directory it is
  automatically used for this purpose.

`Initrd=`, `--initrd`

: Use user-provided initrd(s). Takes a comma separated list of paths to initrd
  files. This option may be used multiple times in which case the initrd lists
  are combined.

`MakeInitrd=`, `--make-initrd`

: Add `/etc/initrd-release` and `/init` to the image so that it can be
  used as an initramfs.

### [Validation] Section

`Checksum=`, `--checksum`

: Generate a `SHA256SUMS` file of all generated artifacts after the
  build is complete.

`Sign=`, `--sign`

: Sign the generated `SHA256SUMS` using `gpg` after completion.

`Key=`, `--key=`

: Select the `gpg` key to use for signing `SHA256SUMS`. This key must
  be already present in the `gpg` keyring.

### [Host] Section

`ExtraSearchPaths=`, `--extra-search-path=`

: List of colon-separated paths to look for tools in, before using the
  regular `$PATH` search path.

`QemuGui=`, `--qemu-gui=`

: If enabled, qemu is executed with its graphical interface instead of
  with a serial console.

`QemuSmp=`, `--qemu-smp=`

: When used with the `qemu` verb, this options sets `qemu`'s `-smp`
  argument which controls the number of guest's CPUs. Defaults to `2`.

`QemuMem=`, `--qemu-mem=`

: When used with the `qemu` verb, this options sets `qemu`'s `-m`
  argument which controls the amount of guest's RAM. Defaults to `1G`.

`QemuKvm=`, `--qemu-kvm=`

: When used with the `qemu` verb, this option specifies whether QEMU
  should use KVM acceleration. Defaults to yes if the host machine
  supports KVM acceleration, no otherwise.

`QemuArgs=`

: Space-delimited list of additional arguments to pass when invoking
  qemu.

`Ephemeral=`, `--ephemeral`

: When used with the `shell`, `boot`, or `qemu` verbs, this option
  runs the specified verb on a temporary snapshot of the output image
  that is removed immediately when the container terminates. Taking
  the temporary snapshot is more efficient on file systems that
  support subvolume snapshots or 'reflinks' natively ("btrfs" or new
  "xfs") than on more traditional file systems that do not ("ext4").

`Ssh=`, `--ssh`

: If specified, an sshd socket unit and matching service are installed in the final
  image that expose sshd over VSock. When building with this option and running the
  image using `mkosi qemu`, the `mkosi ssh` command can be used to connect to the
  container/VM via SSH. Note that you still have to make sure openssh is installed in
  the image to make this option behave correctly. Also note that mkosi doesn't provision
  a public SSH key into the image automatically. One way to do this is by setting the
  `ssh.authorized_keys.root` credential using the `Credential=` option or by copying it
  in using `ExtraTrees=`. To access images booted using `mkosi boot`, use `machinectl`.

`Credentials=`, `--credential=`

: Set credentials to be passed to systemd-nspawn or qemu respectively when
  `mkosi shell/boot` or `mkosi qemu` are used. This option takes a space separated
  list of key=value assignments.

`KernelCommandLineExtra=`, `--kernel-command-line-extra=`

: Set extra kernel command line entries that are appended to the kernel command
  line at runtime when booting the image. When booting in a container, these are
  passed as extra arguments to systemd. When booting in a VM, these are appended
  to the kernel command line via the SMBIOS io.systemd.stub.kernel-cmdline-extra
  OEM string. This will only be picked up by systemd-boot/systemd-stub versions
  newer than or equal to v254.

`Acl=`, `--acl=`

: If specified, ACLs will be set on any generated root filesystem directories that
  allow the user running mkosi to remove them without needing privileges.

### Commandline-only Options

Those settings cannot be configured in the configuration files.

`--directory=`, `-C`

: Takes a path to a directory. `mkosi` switches to this directory
  before doing anything. Note that the various `mkosi.*` files are
  searched for only after changing to this directory, hence using this
  option is an effective way to build a project located in a specific
  directory.

`--config=`

: Loads additional settings from the specified settings file. Most
  command line options may also be configured in a settings file. See
  the table below to see which command line options match which
  settings file option. If this option is not used, but a file
  `mkosi.conf` is found in the local directory it is automatically
  used for this purpose. If a setting is configured both on the
  command line and in the settings file, the command line generally
  wins, except for options taking lists in which case both lists are
  combined.

`--incremental`, `-i`

: Enable incremental build mode. This only applies if the two-phase
  `mkosi.build` build script logic is used. In this mode, a copy of
  the OS image is created immediately after all OS packages are
  unpacked but before the `mkosi.build` script is invoked in the
  development container. Similarly, a copy of the final image is
  created immediately before the build artifacts from the
  `mkosi.build` script are copied in. On subsequent invocations of
  `mkosi` with the `-i` switch these cached images may be used to skip
  the OS package unpacking, thus drastically speeding up repetitive
  build times. Note that when this is used and a pair of cached
  incremental images exists they are not automatically regenerated,
  even if options such as `Packages=` are modified. In order to force
  rebuilding of these cached images, combine `-i` with `-ff` to ensure
  cached images are first removed and then re-created.

`--debug=`

: Enable additional debugging output.

`--debug-shell=`

: When executing a command in the image fails, mkosi will start an interactive
  shell in the image allowing further debugging.

`--version`

: Show package version.

`--help`, `-h`

: Show brief usage information.

`--secure-boot-common-name=`

: Common name to be used when generating SecureBoot keys via mkosi's `genkey`
  command. Defaults to `mkosi of %u`, where `%u` expands to the username of the
  user invoking mkosi.

`--secure-boot-valid-days=`

: Number of days that the keys should remain valid when generating SecureBoot
  keys via mkosi's `genkey` command. Defaults to two years (730 days).

`--auto-bump=`, `-B`

: If specified, after each successful build the the version is bumped
  in a fashion equivalent to the `bump` verb, in preparation for the
  next build. This is useful for simple, linear version management:
  each build in a series will have a version number one higher then
  the previous one.

## Supported distributions

Images may be created containing installations of the
following operating systems:

* *Fedora Linux*

* *Debian*

* *Ubuntu*

* *Arch Linux*

* *openSUSE*

* *Mageia*

* *CentOS*

* *OpenMandriva*

* *Rocky Linux*

* *Alma Linux*

* *Gentoo*

In theory, any distribution may be used on the host for building
images containing any other distribution, as long as the necessary
tools are available. Specifically, any distribution that packages
`apt` may be used to build *Debian* or *Ubuntu* images. Any distribution that
packages `dnf` may be used to build *CentOS*, *Alma Linux*, *Rocky Linux*,
*Fedora Linux*, *Mageia* or *OpenMandriva* images. Any distro that packages
`pacman` may be used to build *Arch Linux* images. Any distribution that
packages `zypper` may be used to build *openSUSE* images. Any distribution
that packages `emerge` may be used to build *Gentoo* images.

Currently, *Fedora Linux* packages all relevant tools as of Fedora 28.

# Files

To make it easy to build images for development versions of your
projects, mkosi can read configuration data from the local directory,
under the assumption that it is invoked from a *source*
tree. Specifically, the following files are used if they exist in the
local directory:

* The **`mkosi.conf`** file provides the default configuration for
  the image building process. For example, it may specify the
  distribution to use (`fedora`, `ubuntu`, `debian`, `arch`,
  `opensuse`, `mageia`, `openmandriva`, `gentoo`) for the image, or additional
  distribution packages to install. Note that all options encoded in
  this configuration file may also be set on the command line, and
  this file is hence little more than a way to make sure invoking
  `mkosi` without further parameters in your *source* tree is enough
  to get the right image of your choice set up.

  Additionally, if a *`mkosi.conf.d/`* directory exists, each file
  in it is loaded in the same manner adding/overriding the values
  specified in `mkosi.conf`. If `mkosi.conf.d/` contains a
  directory named after the distribution being built, each file in
  that directory is also processed.

  The file format is inspired by Windows `.ini` files and supports
  multi-line assignments: any line with initial whitespace is
  considered a continuation line of the line before. Command-line
  arguments, as shown in the help description, have to be included in
  a configuration block (e.g.  "`[Content]`") corresponding to the
  argument group (e.g. "`Content`"), and the argument gets converted
  as follows: "`--with-network`" becomes "`WithNetwork=yes`". For
  further details see the table above.

* The **`mkosi.skeleton/`** directory or **`mkosi.skeleton.tar`**
  archive may be used to insert files into the image. The files are
  copied *before* the distribution packages are installed into the
  image.  This allows creation of files that need to be provided
  early, for example to configure the package manager or set systemd
  presets.

  When using the directory, file ownership is not preserved: all files
  copied will be owned by root. To preserve ownership, use a tar
  archive.

* The **`mkosi.extra/`** directory or **`mkosi.extra.tar`** archive
  may be used to insert additional files into the image, on top of
  what the distribution includes in its packages. They are similar to
  `mkosi.skeleton/` and `mkosi.skeleton.tar`, but the files are copied
  into the directory tree of the image *after* the OS was installed.

  When using the directory, file ownership is not preserved: all files
  copied will be owned by root. To preserve ownership, use a tar
  archive.

* **`mkosi.build`** may be an executable script. If it exists, the
  image will be built twice: the first iteration will be the
  *development* image, the second iteration will be the *final*
  image. The *development* image is used to build the project in the
  current working directory (the *source* tree). For that the whole
  directory is copied into the image, along with the `mkosi.build`
  script. The script is then invoked inside the image, with `$SRCDIR`
  pointing to the *source* tree. `$DESTDIR` points to a directory where
  the script should place any files generated it would like to end up
  in the *final* image. Note that `make`/`automake`/`meson` based build
  systems generally honor `$DESTDIR`, thus making it very natural to
  build *source* trees from the build script. After the *development*
  image was built and the build script ran inside of it, it is removed
  again. After that the *final* image is built, without any *source*
  tree or build script copied in. However, this time the contents of
  `$DESTDIR` are added into the image.

  When the source tree is copied into the *build* image, all files are
  copied, except for `mkosi.builddir/`, `mkosi.cache/` and
  `mkosi.output/`. That said, `.gitignore` is respected if the source
  tree is a `git` checkout. If multiple different images shall be
  built from the same source tree it is essential to exclude their
  output files from this copy operation, as otherwise a version of an
  image built earlier might be included in a later build, which is
  usually not intended. An alternative to excluding these built images
  via `.gitignore` entries is to use the `mkosi.output/` directory,
  which is an easy way to exclude all build artifacts.

  The `$MKOSI_CONFIG` environment variable will be set inside of this
  script so that you know which `mkosi.conf` (if any) was passed
  in.

* The **`mkosi.prepare`** script is invoked directly after the
  software packages are installed, from within the image context, if
  it exists. It is once called for the *development* image (if this is
  enabled, see above) with the "build" command line parameter, right
  before copying the extra tree. It is called a second time for the
  *final* image with the "final" command line parameter. This script
  has network access and may be used to install packages from other
  sources than the distro's package manager (e.g. `pip`, `npm`, ...),
  after all software packages are installed but before the image is
  cached (if incremental mode is enabled). This script is executed
  within `$SRCDIR`. In contrast to a general purpose installation, it
  is safe to install packages to the system (`pip install`, `npm
  install -g`) instead of in `$SRCDIR` itself because the build image
  is only used for a single project and can easily be thrown away and
  rebuilt so there's no risk of conflicting dependencies and no risk
  of polluting the host system.

* The **`mkosi.postinst`** script is invoked as the penultimate step
  of preparing an image, from within the image context, if it exists.
  It is called first for the *development* image (if this is enabled,
  see above) with the "build" command line parameter, right before
  invoking the build script. It is called a second time for the
  *final* image with the "final" command line parameter, right before
  the image is considered complete. This script may be used to alter
  the images without any restrictions, after all software packages and
  built sources have been installed. Note that this script is executed
  directly in the image context with the final root directory in
  place, without any `$SRCDIR`/`$DESTDIR` setup.

* The **`mkosi.finalize`** script, if it exists, is invoked as last
  step of preparing an image, from the host system.  It is once called
  for the *development* image (if this is enabled, see above) with the
  "build" command line parameter, as the last step before invoking the
  build script, after the `mkosi.postinst` script is invoked. It is
  called the second time with the "final" command line parameter as
  the last step before the image is considered complete. The
  environment variable `$BUILDROOT` points to the root directory of
  the installation image. Additional verbs may be added in the future,
  the script should be prepared for that. This script may be used to
  alter the images without any restrictions, after all software
  packages and built sources have been installed. This script is more
  flexible than `mkosi.postinst` in two regards: it has access to the
  host file system so it's easier to copy in additional files or to
  modify the image based on external configuration, and the script is
  run in the host, so it can be used even without emulation even if
  the image has a foreign architecture.

* The **`mkosi.nspawn`** nspawn settings file will be copied into the
  same place as the output image file, if it exists. This is useful since nspawn
  looks for settings files next to image files it boots, for
  additional container runtime settings.

* The **`mkosi.cache/`** directory, if it exists, is automatically
  used as package download cache, in order to speed repeated runs of
  the tool.

* The **`mkosi.builddir/`** directory, if it exists, is automatically
  used as out-of-tree build directory, if the build commands in the
  `mkosi.build` script support it. Specifically, this directory will
  be mounted into the build container, and the `$BUILDDIR` environment
  variable will be set to it when the build script is invoked. The
  build script may then use this directory as build directory, for
  automake-style or ninja-style out-of-tree builds. This speeds up
  builds considerably, in particular when `mkosi` is used in
  incremental mode (`-i`): not only the disk images, but also the
  build tree is reused between subsequent invocations. Note that if
  this directory does not exist the `$BUILDDIR` environment variable
  is not set, and it is up to build script to decide whether to do in
  in-tree or an out-of-tree build, and which build directory to use.

* The **`mkosi.includedir/`** directory, if it exists, is
  automatically used as an out-of-tree include directory for header
  files.  Specifically, it will be mounted in the build container at
  `/usr/include/` when building the build image and when running the
  build script. After building the (cached) build image, this
  directory will contain all the files installed to
  `/usr/include`. Language servers or other tools can use these files
  to provide a better editing experience for developers working on a
  project.

* The **`mkosi.installdir/`** directory, if it exists, is
  automatically used as the install directory. Specifically, this
  directory will be mounted into the container at `/root/dest` when
  running the build script. After running the build script, the
  contents of this directory are installed into the final image. This
  is useful to cache the install step of the build. If used,
  subsequent builds will only have to reinstall files that have
  changed since the previous build.

* The **`mkosi.rootpw`** file can be used to provide the password or
  hashed password (if `--password-is-hashed` is set) for the root user
  of the image.  The password may optionally be followed by a newline
  character which is implicitly removed. The file must have an access
  mode of 0600 or less. If this file does not exist, the
  distribution's default root password is set (which usually means
  access to the root user is blocked).

* The **`mkosi.passphrase`** file provides the passphrase to use when
  LUKS encryption is selected. It should contain the passphrase
  literally, and not end in a newline character (i.e. in the same
  format as cryptsetup and `/etc/crypttab` expect the passphrase
  files). The file must have an access mode of 0600 or less. If this
  file does not exist and encryption is requested, the user is queried
  instead.

* The **`mkosi.secure-boot.crt`** and **`mkosi.secure-boot.key`**
  files contain an X.509 certificate and PEM private key to use when
  UEFI SecureBoot support is enabled. All EFI binaries included in the
  image's ESP are signed with this key, as a late step in the build
  process.

* The **`mkosi.output/`** directory will be used for all build
  artifacts, if the image output path is not configured (i.e. no
  `--output=` setting specified), or configured to a filename (i.e. a
  path containing no `/` character). This includes the image itself,
  the root hash file in case Verity is used, the checksum and its
  signature if that's enabled, and the nspawn settings file if there
  is any. Note that this directory is not used if the image output
  path contains at least one slash, and has no effect in that case.
  This setting is particularly useful if multiple different images
  shall be built from the same working directory, as otherwise the
  build result of a preceding run might be copied into a build image
  as part of the source tree (see above).

* The **`mkosi.reposdir/`** directory, if it exists, is automatically
  used as the repository directory for extra repository files. See
  the `RepositoryDirectories` option for more information.

* The **`mkosi.credentials/`** directory is used as a
  source of extra credentials similar to the `Credentials=` option. For
  each file in the directory, the filename will be used as the credential
  name and the file contents become the credential value, or, if the file is
  executable, mkosi will execute the file and the command's
  output to stdout will be used as the credential value. Output to stderr will be ignored.
  Credentials configured with `Credentials=` take precedence over files in `mkosi.credentials`.

All these files are optional.

Note that the location of all these files may also be configured
during invocation via command line switches, and as settings in
`mkosi.conf`, in case the default settings are not acceptable for a
project.

# CACHING

`mkosi` supports three different caches for speeding up repetitive
re-building of images. Specifically:

1. The package cache of the distribution package manager may be cached
   between builds. This is configured with the `--cache-dir=` option or
   the `mkosi.cache/` directory. This form of caching relies on the
   distribution's package manager, and caches distribution packages
   (RPM, DEB, …) after they are downloaded, but before they are
   unpacked.

2. If the incremental build mode is enabled with `--incremental`, cached
   copies of the final image and build overlay are made immediately
   before the build sources are copied in (for the build overlay) or the
   artifacts generated by `mkosi.build` are copied in (in case of the
   final image). This form of caching allows bypassing the time-consuming
   package unpacking step of the distribution package managers, but is only
   effective if the list of packages to use remains stable, but the build
   sources and its scripts change regularly. Note that this cache requires
   manual flushing: whenever the package list is modified the cached
   images need to be explicitly removed before the next re-build,
   using the `-f` switch.

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
  without or with installed documentation was requested
  (`WithDocs=yes`). The build script should suppress installation of
  any package documentation to `$DESTDIR` in case `$WITH_DOCS` is set
  to `0`.

* `$WITH_TESTS` is either `0`or `1` depending on whether a build
  without or with running the test suite was requested
  (`WithTests=no`). The build script should avoid running any unit or
  integration tests in case `$WITH_TESTS` is `0`.

* `$WITH_NETWORK` is either `0`or `1` depending on whether a build
  without or with networking is being executed (`WithNetwork=no`).
  The build script should avoid any network communication in case
  `$WITH_NETWORK` is `0`.

* `$MKOSI_LESS` overrides options for `less` when it is invoked by
  `mkosi` to page output.

# EXAMPLES

Create and run a raw *GPT* image with *ext4*, as `image.raw`:

```console
# mkosi -p systemd --incremental boot
```

Create and run a bootable *GPT* image, as `foobar.raw`:

```console
$ mkosi -d fedora -p kernel -p systemd -p udev -o foobar.raw
# mkosi --output foobar.raw boot
$ mkosi --output foobar.raw qemu
```

Create and run a *Fedora Linux* image in a plain directory:

```console
# mkosi --distribution fedora --format directory boot
```

Create a compressed image `image.raw.xz` with *SSH* installed and add a checksum file:

```console
$ mkosi --distribution fedora --format disk --checksum --compress-output --package=openssh-clients
```

Inside the source directory of an `automake`-based project, configure
*mkosi* so that simply invoking `mkosi` without any parameters builds
an OS image containing a built version of the project in its current
state:

```console
$ cat >mkosi.conf <<EOF
[Distribution]
Distribution=fedora

[Output]
Format=disk

[Content]
Packages=kernel,systemd,systemd-udev,openssh-clients,httpd
BuildPackages=make,gcc,libcurl-devel
EOF
$ cat >mkosi.build <<EOF
#!/bin/sh
cd $SRCDIR
./autogen.sh
./configure --prefix=/usr
make -j `nproc`
make install
EOF
$ chmod +x mkosi.build
# mkosi --incremental boot
# systemd-nspawn -bi image.raw
```

## Different ways to boot with `qemu`

The easiest way to boot a virtual machine is to build an image with the
required components and let `mkosi` call `qemu` with all the right options:
```console
$ mkosi -d fedora \
    --autologin \
    -p systemd-udev,systemd-boot,kernel-core \
    build
$ mkosi -d fedora qemu
...
fedora login: root (automatic login)
[root@fedora ~]#
```

The default is to boot with a text console only.
In this mode, messages from the boot loader, the kernel, and systemd,
and later the getty login prompt and shell all use the same terminal.
It is possible to switch between the qemu console and monitor
by pressing `Ctrl-a c`.
The qemu monitor may for example be used to inject special keys
or shut down the machine quickly.

To boot with a graphical window, add `--qemu-qui`:
```console
$ mkosi -d fedora --qemu-gui qemu
```

A kernel may be booted directly with
`mkosi qemu -kernel ... -initrd ... -append '...'`.
This is a bit faster because no boot loader is used, and it is also
easier to experiment with different kernels and kernel commandlines.
Note that despite the name, qemu's `-append` option replaces
the default kernel commandline embedded in the kernel
and any previous `-append` specifications.

`mkosi` builds a Unified Kernel Image (UKI).
It is also copied into the output directory and may be booted directly:
```console
$ mkosi qemu -kernel mkosi.output/fedora~38/image.efi
```

When booting using an external kernel, we don't need the kernel *in* the image,
but we would still want the kernel modules to be installed.

It is also possible to do a "direct kernel boot" into a boot loader,
taking advantage of the fact that `systemd-boot(7)` is a valid UEFI binary:
```console
$ mkosi qemu -kernel /usr/lib/systemd/boot/efi/systemd-bootx64.efi
```
In this scenario, the kernel is loaded from the ESP in the image by `systemd-boot`.

# REQUIREMENTS

mkosi is packaged for various distributions: Debian, Ubuntu, Arch
Linux, Fedora Linux, OpenMandriva, Gentoo. It is usually easiest to use the
distribution package.

The latest code from git requires systemd 253.

When not using distribution packages make sure to install the
necessary dependencies. For example, on *Fedora Linux* you need:

```bash
# dnf install bubblewrap btrfs-progs apt dosfstools mtools edk2-ovmf e2fsprogs squashfs-tools gnupg python3 tar xfsprogs xz zypper sbsigntools
```

On Debian/Ubuntu it might be necessary to install the `ubuntu-keyring`,
`ubuntu-archive-keyring` and/or `debian-archive-keyring` packages explicitly,
in addition to `apt`, depending on what kind of distribution images you want
to build.

Note that the minimum required Python version is 3.9.

# REFERENCES
* [Primary mkosi git repository on GitHub](https://github.com/systemd/mkosi/)
* [mkosi — A Tool for Generating OS Images](http://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html) introductory blog post by Lennart Poettering
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN

# SEE ALSO
`systemd-nspawn(1)`, `dnf(8)`
