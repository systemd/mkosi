% mkosi(1)
%
%

# NAME

mkosi — Build Bespoke OS Images

# SYNOPSIS

`mkosi [options…] summary`

`mkosi [options…] build`

`mkosi [options…] shell [command line…]`

`mkosi [options…] boot [nspawn settings…]`

`mkosi [options…] qemu [qemu parameters…]`

`mkosi [options…] ssh [command line…]`

`mkosi [options…] clean`

`mkosi [options…] serve`

`mkosi [options…] bump`

`mkosi [options…] genkey`

`mkosi [options…] documentation`

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
  read from configuration files. This command is the default if no verb is
  explicitly specified.

`shell`

: This builds the image if it is not built yet, and then invokes
  `systemd-nspawn` to acquire an interactive shell prompt in it. An optional
  command line may be specified after the `shell` verb, to be invoked in place
  of the shell in the container. Use `-f` in order to rebuild the image
  unconditionally before acquiring the shell, see below. This command must be
  executed as `root`.

`boot`

: Similar to `shell`, but boots the image using `systemd-nspawn`. An
  optional command line may be specified after the `boot` verb, which
  can contain extra nspawn options as well as arguments which are passed
  as the "kernel command line" to the init system in the image.

`qemu`

: Similar to `boot`, but uses `qemu` to boot up the image, i.e. instead
  of container virtualization virtual machine virtualization is used.
  This verb is only supported for disk images that contain a boot loader
  and cpio images in which a kernel was installed. For cpio images a
  kernel can also be provided by passing the `-kernel` qemu argument to
  the `qemu` verb. Any arguments specified after the `qemu` verb are
  appended to the `qemu` invocation.

`ssh`

: When the image is built with the `Ssh=yes` option, this command
  connects to a booted virtual machine (`qemu`) via SSH. Make sure to
  run `mkosi ssh` with the same config as `mkosi build` was run with so
  that it has the necessary information available to connect to the
  running virtual machine via SSH. Any arguments passed after the `ssh`
  verb are passed as arguments to the `ssh` invocation. To connect to a
  container, use `machinectl login` or `machinectl shell`.

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

`documentation`

: Show mkosi's documentation. By default this verb will try several ways
  to output the documentation, but a specific option can be chosen with
  the `--doc-format` option. Distro packagers are encouraged to add a
  file `mkosi.1` into the `mkosi/resources` directory of the Python
  package, if it is missing, as well as to install it in the appropriate
  search path for man pages. The man page can be generated from the
  markdown file `mkosi/resources/mkosi.md` e.g via
  `pandoc -t man -s -o mkosi.1 mkosi.md`.

`help`

: This verb is equivalent to the `--help` switch documented below: it
  shows a brief usage explanation.

## Commandline-only Options

Those settings cannot be configured in the configuration files.

`--force`, `-f`

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

`--directory=`, `-C`

: Takes a path to a directory. `mkosi` switches to this directory before
  doing anything. Note that the various configuration files are searched
  for in this directory, hence using this option is an effective way to
  build a project located in a specific directory.

`--debug=`

: Enable additional debugging output.

`--debug-shell=`

: When executing a command in the image fails, mkosi will start an interactive
  shell in the image allowing further debugging.

`--version`

: Show package version.

`--help`, `-h`

: Show brief usage information.

`--genkey-common-name=`

: Common name to be used when generating keys via mkosi's `genkey` command. Defaults to `mkosi of %u`, where
  `%u` expands to the username of the user invoking mkosi.

`--genkey-valid-days=`

: Number of days that the keys should remain valid when generating keys via mkosi's `genkey` command.
  Defaults to two years (730 days).

`--auto-bump=`, `-B`

: If specified, after each successful build the the version is bumped
  in a fashion equivalent to the `bump` verb, in preparation for the
  next build. This is useful for simple, linear version management:
  each build in a series will have a version number one higher then
  the previous one.

`--preset=`

: If specified, only build the given presets. Can be specified multiple
  times to build multiple presets. All the given presets and their
  dependencies are built. If not specified, all presets are built. See
  the `Presets` section for more information.

`--doc-format`

: The format to show the documentation in. Supports the values `markdown`,
  `man`, `pandoc`, `system` and `auto`. In the case of `markdown` the
  documentation is shown in the original Markdown format. `man` shows the
  documentation in man page format, if it is available. `pandoc` will generate
  the man page format on the fly, if `pandoc` is available. `system` will show
  the system-wide man page for mkosi, which may or may not correspond to the
  version you are using, depending on how you installed mkosi. `auto`, which is
  the default, will try all methods in the order `man`, `pandoc`, `markdown`,
  `system`.

## Supported output formats

The following output formats are supported:

* Raw *GPT* disk image, created using systemd-repart (*disk*)

* Plain directory, containing the OS tree (*directory*)

* Tar archive (*tar*)

* CPIO archive (*cpio*)

The output format may also be set to *none* to have mkosi produce no
image at all. This can be useful if you only want to use the image to
produce another output in the build script (e.g. build an rpm).

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
* `mkosi.conf` is parsed if it exists in the directory configured with
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

To conditionally include configuration files, the `[Match]` section can be used. Matches can use a pipe
symbol ("|") after the equals sign ("…=|…"), which causes the match to become a triggering match. The config
file will be included if the logical AND of all non-triggering matches and the logical OR of all triggering
matches is satisfied. To negate the result of a match, prefix the argument with an exclamation mark. If an
argument is prefixed with the pipe symbol and an exclamation mark, the pipe symbol must be passed first, and
the exclamation second.

Command line options that take no argument are shown without "=" in their long version. In the config files,
they should be specified with a boolean argument: either "1", "yes", or "true" to enable, or "0", "no",
"false" to disable.

### [Match] Section.

`Distribution=`

: Matches against the configured distribution.

`Release=`

: Matches against the configured distribution release. If this condition is used and no distribution has been
  explicitly configured yet, the host distribution and release are used.

`PathExists=`

: This condition is satisfied if the given path exists. Relative paths are interpreted relative to the parent
  directory of the config file that the condition is read from.

`ImageId=`

: Matches against the configured image ID, supporting globs. If this condition is used and no image ID has
  been explicitly configured yet, this condition fails.

`ImageVersion=`

: Matches against the configured image version. Image versions can be prepended by the operators `==`, `!=`,
  `>=`, `<=`, `<`, `>` for rich version comparisons according to the UAPI group version format specification.
  If no operator is prepended, the equality operator is assumed by default If this condition is used and no
  image version has been explicitly configured yet, this condition fails.

`Bootable=`

: Matches against the configured value for the `Bootable=` feature. Takes a boolean value or `auto`.

| Matcher         | Globs | Rich Comparisons | Default                 |
|-----------------|-------|------------------|-------------------------|
| `Distribution=` | no    | no               | match host distribution |
| `Release=`      | no    | no               | match host release      |
| `PathExists=`   | no    | no               | match fails             |
| `ImageId=`      | yes   | no               | match fails             |
| `ImageVersion=` | no    | yes              | match fails             |
| `Bootable=`     | no    | no               | match auto feature      |

### [Preset] Section

`Dependencies=`, `--dependency=`

: The presets that this preset depends on specified as a comma-separated
  list. All presets configured in this option will be built before this
  preset and will be pulled in as dependencies of this preset when
  `--preset` is used.

### [Distribution] Section

`Distribution=`, `--distribution=`, `-d`

: The distribution to install in the image. Takes one of the following
  arguments: `fedora`, `debian`, `ubuntu`, `arch`, `opensuse`, `mageia`,
  `centos`, `openmandriva`, `rocky`, `alma`. If not
  specified, defaults to the distribution of the host.

`Release=`, `--release=`, `-r`

: The release of the distribution to install in the image. The precise
  syntax of the argument this takes depends on the distribution used,
  and is either a numeric string (in case of Fedora Linux, CentOS, …,
  e.g. `29`), or a distribution version name (in case of Debian, Ubuntu,
  …, e.g. `artful`). Defaults to a recent version of the chosen
  distribution, or the version of the distribution running on the host
  if it matches the configured distribution.

`Architecture=`, `--architecture=`

: The architecture to build the image for. A number of architectures can
  be specified, but which ones are actually supported depends on the
  distribution used and whether a bootable image is requested or not.
  When building for a foreign architecture, you'll also need to install
  and register a user mode emulator for that architecture.

  The following architectures can be specified:

  - alpha
  - arc
  - arm
  - arm64
  - ia64
  - loongarch64
  - mips64-le
  - mips-le
  - parisc
  - ppc
  - ppc64
  - ppc64-le
  - riscv32
  - riscv64
  - s390
  - s390x
  - tilegx
  - x86
  - x86-64

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

: Enable package repositories that are disabled by default. This can be used to enable the EPEL repos for
  CentOS or different components of the Debian/Ubuntu repositories.

`CacheOnly=`, `--cache-only=`

: If specified, the package manager is instructed not to contact the
  network for updating package data. This provides a minimal level of
  reproducibility, as long as the package cache is already fully
  populated.

### [Output] Section

`Format=`, `--format=`, `-t`

: The image format type to generate. One of `directory` (for generating OS
  images inside a local directory), `tar` (similar, but a tarball of the
  image is generated), `cpio` (similar, but a cpio archive is generated),
  `disk` (a block device image with a GPT partition table) or `none`
  (the image is solely intended as a build image to produce another
  artifact).

`ManifestFormat=`, `--manifest-format=`

: The manifest format type or types to generate. A comma-delimited
  list consisting of `json` (the standard JSON output format that
  describes the packages installed), `changelog` (a human-readable
  text format designed for diffing). Defaults to `json`.

`Output=`, `--output=`, `-o`

: Filename to use for the generated output image file or directory. If
  neither this option nor `OutputDirectory=` is used, the image is
  generated under the name `image`, but its name suffixed with an
  appropriate file suffix (e.g. `image.raw.xz` in case `disk` is used in
  combination with `xz` compression). If the `ImageId=` option is
  configured it is used instead of `image` in the default output name.
  If an image version is specified via `ImageVersion=`, it is included
  in the default name, e.g. a specified image version of `7.8` might
  result in an image file name of `image_7.8.raw.xz`.

`CompressOutput=`, `--compress-output=`

: Configure compression for the resulting image or archive. The
  argument can be either a boolean or a compression algorithm (`xz`,
  `zstd`). `xz` compression is used by default. Note that when applied
  to block device image types this means the image cannot be started
  directly but needs to be decompressed first. This also means that
  the `shell`, `boot`, `qemu` verbs are not available when this option
  is used. Implied for `tar` and `cpio`.

`OutputDirectory=`, `--output-dir=`, `-O`

: Path to a directory where to place all generated artifacts. If this is
  not specified and the directory `mkosi.output/` exists in the local
  directory, it is automatically used for this purpose.

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
  automatically used for this purpose.

`BuildDirectory=`, `--build-dir=`

: Takes a path to a directory to use as the build directory for build
  systems that support out-of-tree builds (such as Meson). The directory
  used this way is shared between repeated builds, and allows the build
  system to reuse artifacts (such as object files, executable, …)
  generated on previous invocations. The build script can find the path
  to this directory in the `$BUILDDIR` environment variable. This
  directory is mounted into the image's root directory when
  `mkosi-chroot` is invoked during execution of the build script. If
  this option is not specified, but a directory `mkosi.builddir/` exists
  in the local directory it is automatically used for this purpose (also
  see the "Files" section below).

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

`RepartDirectories=`, `--repart-dir=`

: Paths to directories containing systemd-repart partition definition files that
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

`UseSubvolumes=`, `--use-subvolumes=`

: Takes a boolean or `auto`. Enables or disables use of btrfs subvolumes for
  directory tree outputs. If enabled, mkosi will create the root directory as
  a btrfs subvolume and use btrfs subvolume snapshots where possible to copy
  base or cached trees which is much faster than doing a recursive copy. If
  explicitly enabled and `btrfs` is not installed or subvolumes cannot be
  created, an error is raised. If `auto`, missing `btrfs` or failures to
  create subvolumes are ignored.

### [Content] Section

`Packages=`, `--package=`, `-p`

: Install the specified distribution packages (i.e. RPM, DEB, …) in the
  image. Takes a comma separated list of package specifications. This
  option may be used multiple times in which case the specified package
  lists are combined. Use `BuildPackages=` to specify packages that
  shall only be installed in an overlay that is mounted when the prepare
  script is executed with the `build` argument and when the build script
  is executed.

: The types and syntax of "package specifications" that are allowed
  depend on the package installer (e.g. `dnf` for `rpm`-based distros or
  `apt` for `deb`-based distros), but may include package names, package
  names with version and/or architecture, package name globs, paths to
  packages in the file system, package groups, and virtual provides,
  including file paths.

: Example: when using a distro that uses `dnf`,

  ```
  Packages=meson
           libfdisk-devel.i686
           git-*
           prebuilt/rpms/systemd-249-rc1.local.rpm
           /usr/bin/ld
           @development-tools
           python3dist(mypy)
  ```

  would install the `meson` package (in the latest version), the 32-bit
  version of the `libfdisk-devel` package, all available packages that
  start with the `git-` prefix, a `systemd` rpm from the local file
  system, one of the packages that provides `/usr/bin/ld`, the packages
  in the "Development Tools" group, and the package that contains the
  `mypy` python module.

`BuildPackages=`, `--build-package=`

: Similar to `Packages=`, but configures packages to install only in an
  overlay that is made available on top of the image to the prepare
  script when executed with the `build` argument and the build script.
  This option should be used to list packages containing header files,
  compilers, build systems, linkers and other build tools the
  `mkosi.build` script requires to operate. Note that packages listed
  here will be absent in the final image.

`WithDocs=`, `--with-docs`

: Include documentation in the image built. By default if the
  underlying distribution package manager supports it documentation is
  not included in the image built. The `$WITH_DOCS` environment
  variable passed to the `mkosi.build` script indicates whether this
  option was used or not.

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

`PackageManagerTrees=`, `--package-manager-tree=`

: This option mirrors the above `SkeletonTrees=` option and defaults to the
  same value if not configured otherwise, but installs the files to a
  subdirectory of the workspace directory instead of the OS tree. This
  subdirectory of the workspace is used to configure the package manager.

: `SkeletonTrees=` and `PackageManagerTrees=` fulfill similar roles. Use
  `SkeletonTrees=` if you want the files to be present in the final image. Use
  `PackageManagerTrees=` if you don't want the files to be present in the final
  image, e.g. when building an initrd or if you want to refer to paths outside
  of the image in your repository configuration.

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

`RemovePackages=`, `--remove-package=`

: Takes a comma-separated list of package specifications for removal, in
  the same format as `Packages=`. The removal will be performed as one
  of the last steps. This step is skipped if `CleanPackageMetadata=no`
  is used.

`RemoveFiles=`, `--remove-files=`

: Takes a comma-separated list of globs. Files in the image matching
  the globs will be purged at the end.

`CleanPackageMetadata=`, `--clean-package-metadata=`

: Enable/disable removal of package manager databases at the end of
  installation. Can be specified as true, false, or "`auto`" (the
  default). With "`auto`", files will be removed if the respective
  package manager executable is *not* present at the end of the
  installation.

`PrepareScript=`, `--prepare-script=`

: Takes a path to an executable that is used as the prepare script for
  this image. See the `SCRIPTS` section for more information.

`BuildScript=`, `--build-script=`

: Takes a path to an executable that is used as build script for this
  image. See the `SCRIPTS` section for more information.

`PostInstallationScript=`, `--postinst-script=`

: Takes a path to an executable that is used as the post-installation
  script for this image. See the `SCRIPTS` section for more information.

`FinalizeScript=`, `--finalize-script=`

: Takes a path to an executable that is used as the finalize script for
  this image. See the `SCRIPTS` section for more information.

`BuildSources=`, `--build-sources=`

: Takes a list of colon-separated pairs of paths to source trees and
  where to mount them when running scripts. Every target path is
  prefixed with the current working directory and all build sources are
  sorted lexicographically by mount target before mounting so that top
  level paths are mounted first. When using the `mkosi-chroot` script (
  see the `SCRIPTS` section), the current working directory with all
  build sources mounted in it is mounted to `/work/src` inside the
  image's root directory.

`Environment=`, `--environment=`

: Adds variables to the environment that package managers and the
  prepare/build/postinstall/finalize scripts are executed with. Takes
  a space-separated list of variable assignments or just variable
  names. In the latter case, the values of those variables will be
  passed through from the environment in which `mkosi` was invoked.
  This option may be specified more than once, in which case all
  listed variables will be set. If the same variable is set twice, the
  later setting overrides the earlier one.

`WithTests=`, `--without-tests`, `-T`

: If set to false (or when the command-line option is used), the
  `$WITH_TESTS` environment variable is set to `0` when the
  `mkosi.build` script is invoked. This is supposed to be used by the
  build script to bypass any unit or integration tests that are
  normally run during the source build process. Note that this option
  has no effect unless the `mkosi.build` build script honors it.

`WithNetwork=`, `--with-network=`

: When true, enables network connectivity while the build script
  `mkosi.build` is invoked. By default, the build script runs with
  networking turned off. The `$WITH_NETWORK` environment variable is
  passed to the `mkosi.build` build script indicating whether the
  build is done with or without network.

`Bootable=`, `--bootable=`

: Takes a boolean or `auto`. Enables or disables generation of a
  bootable image. If enabled, mkosi will install systemd-boot, and add
  an ESP partition when the disk image output is used. If systemd-boot
  is not installed or no kernel images can be found, the build will
  fail. `auto` behaves as if the option was enabled, but the build won't
  fail if either no kernel images or systemd-boot can't be found. If
  disabled, systemd-boot won't be installed even if found inside the
  image, no unified kernel images will be generated and no ESP partition
  will be added to the image if the disk output format is used.

`Initrds=`, `--initrd`

: Use user-provided initrd(s). Takes a comma separated list of paths to
  initrd files. This option may be used multiple times in which case the
  initrd lists are combined.

`KernelCommandLine=`, `--kernel-command-line=`

: Use the specified kernel command line when building images.

`KernelModulesInclude=`, `--kernel-modules-include=`

: Takes a list of regex patterns that specify kernel modules to include in the image. Patterns should be
  relative to the `/usr/lib/modules/<kver>/kernel` directory. mkosi checks for a match anywhere in the module
  path (e.g. "i915" will match against "drivers/gpu/drm/i915.ko"). All modules that match any of the
  specified patterns are included in the image. All module and firmware dependencies of the matched modules
  are included in the image as well. This setting takes priority over `KernelModulesExclude=` and only makes
  sense when used in combination with it because all kernel modules are included in the image by default.

`KernelModulesExclude=`, `--kernel-modules-exclude=`

: Takes a list of regex patterns that specify modules to exclude from the image. Behaves the same as
  `KernelModulesInclude=` except that all modules that match any of the specified patterns are excluded from
  the image.

`KernelModulesInitrd=`, `--kernel-modules-initrd=`

: Enable/Disable generation of the kernel modules initrd when building a bootable image. Enabled by default.
  If enabled, when building a bootable image, for each kernel that we assemble a unified kernel image for we
  generate an extra initrd containing only the kernel modules for that kernel version and append it to the
  prebuilt initrd. This allows generating kernel independent initrds which are augmented with the necessary
  kernel modules when the UKI is assembled.

`KernelModulesInitrdInclude=`, `--kernel-modules-initrd-include=`

: Like `KernelModulesInclude=`, but applies to the kernel modules included in the kernel modules initrd.

`KernelModulesInitrdExclude=`, `--kernel-modules-initrd-exclude=`

: Like `KernelModulesExclude=`, but applies to the kernel modules included in the kernel modules initrd.

`Locale=`, `--locale=`,
`LocaleMessages=`, `--locale-messages=`,
`Keymap=`, `--keymap=`,
`Timezone=`, `--timezone=`,
`Hostname=`, `--hostname=`,
`RootShell=`, `--root-shell=`

: These settings correspond to the identically named systemd-firstboot options. See the systemd firstboot
  [manpage](https://www.freedesktop.org/software/systemd/man/systemd-firstboot.html) for more information.
  Additionally, where applicable, the corresponding systemd credentials for these settings are written to
  `/usr/lib/credstore`, so that they apply even if only `/usr` is shipped in the image.

`RootPassword=`, `--root-password=`,

: Set the system root password. If this option is not used, but a `mkosi.rootpw` file is found in the local
  directory, the password is automatically read from it. If the password starts with `hashed:`, it is treated
  as an already hashed root password. The root password is also stored in `/usr/lib/credstore` under the
  appropriate systemd credential so that it applies even if only `/usr` is shipped in the image.

`Autologin=`, `--autologin`

: Enable autologin for the `root` user on `/dev/pts/0` (nspawn),
  `/dev/tty1` and `/dev/ttyS0`.

`MakeInitrd=`, `--make-initrd`

: Add `/etc/initrd-release` and `/init` to the image so that it can be
  used as an initramfs.

`Ssh=`, `--ssh`

: If specified, an sshd socket unit and matching service are installed
  in the final image that expose SSH over VSock. When building with this
  option and running the image using `mkosi qemu`, the `mkosi ssh`
  command can be used to connect to the container/VM via SSH. Note that
  you still have to make sure openssh is installed in the image to make
  this option behave correctly. mkosi will automatically provision the
  user's public SSH key into the image using the
  `ssh.authorized_keys.root` credential if it can be retrieved from a
  running SSH agent. To access images booted using `mkosi boot`, use
  `machinectl`.

### [Validation] Section

`SecureBoot=`, `--secure-boot`

: Sign systemd-boot (if it is not signed yet) and the resulting
  kernel/initrd image for UEFI SecureBoot. Also set up secure boot key
  auto enrollment as documented in the systemd-boot [man page](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)

`SecureBootKey=`, `--secure-boot-key=`

: Path to the PEM file containing the secret key for signing the
  UEFI kernel image, if `SecureBoot=` is used.

`SecureBootCertificate=`, `--secure-boot-certificate=`

: Path to the X.509 file containing the certificate for the signed
  UEFI kernel image, if `SecureBoot=` is used.

`SecureBootSignTool=`, `--secure-boot-sign-tool`

: Tool to use to sign secure boot PE binaries. Takes one of `sbsign`, `pesign` or `auto`. Defaults to `auto`.
  If set to `auto`, either sbsign or pesign are used if available, with sbsign being preferred if both are
  installed.

`VerityKey=`, `--verity-key=`

: Path to the PEM file containing the secret key for signing the verity signature, if a verity signature
  partition is added with systemd-repart.

`VerityCertificate=`, `--verity-certificate=`

: Path to the X.509 file containing the certificate for signing the verity signature, if a verity signature
  partition is added with systemd-repart.

`SignExpectedPCR=`, `--sign-expected-pcr`

: Measure the components of the unified kernel image (UKI) using
  `systemd-measure` and embed the PCR signature into the unified kernel
  image. This option takes a boolean value or the special value `auto`,
  which is the default, which is equal to a true value if the
  `systemd-measure` binary is in `PATH`.

`Passphrase=`, `--passphrase`

: Specify the path to a file containing the passphrase to use for LUKS
  encryption. It should contain the passphrase literally, and not end in
  a newline character (i.e. in the same format as cryptsetup and
  `/etc/crypttab` expect the passphrase files). The file must have an
  access mode of 0600 or less.

`Checksum=`, `--checksum`

: Generate a `SHA256SUMS` file of all generated artifacts after the
  build is complete.

`Sign=`, `--sign`

: Sign the generated `SHA256SUMS` using `gpg` after completion.

`Key=`, `--key=`

: Select the `gpg` key to use for signing `SHA256SUMS`. This key must
  be already present in the `gpg` keyring.

### [Host] Section

`Incremental=`, `--incremental=`, `-i`

: Enable incremental build mode. In this mode, a copy of the OS image is
  created immediately after all OS packages are installed and the
  prepare script has executed but before the `mkosi.build` script is
  invoked (or anything that happens after it). On subsequent invocations
  of `mkosi` with the `-i` switch this cached image may be used to skip
  the OS package installation, thus drastically speeding up repetitive
  build times. Note that while there is some rudimentary cache
  invalidation, it is definitely not perfect. In order to force
  rebuilding of the cached image, combine `-i` with `-ff` to ensure the
  cached image is first removed and then re-created.

`NSpawnSettings=`, `--settings=`

: Specifies a `.nspawn` settings file for `systemd-nspawn` to use in
  the `boot` and `shell` verbs, and to place next to the generated
  image file. This is useful to configure the `systemd-nspawn`
  environment when the image is run. If this setting is not used but
  an `mkosi.nspawn` file found in the local directory it is
  automatically used for this purpose.

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

: When used with the `qemu` verb, this option specifies whether QEMU should use KVM acceleration. Takes a
  boolean value or `auto`. Defaults to `auto`.

`QemuVsock=`, `--qemu-vsock=`

: When used with the `qemu` verb, this option specifies whether QEMU should be configured with a vsock. Takes
  a boolean value or `auto`. Defaults to `auto`.

`QemuSwtpm=`, `--qemu-swtpm=`

: When used with the `qemu` verb, this option specifies whether to start an instance of swtpm to be used as a
  TPM with qemu. This requires swtpm to be installed on the host. Takes a boolean value or `auto`. Defaults
  to `auto`.

`QemuCdrom=`, `--qemu-cdrom=`

: When used with the `qemu` verb, this option specifies whether to
  attach the image to the virtual machine as a CD-ROM device. Takes a
  boolean. Defaults to `no`.

`QemuArgs=`

: Space-delimited list of additional arguments to pass when invoking
  qemu.

`Ephemeral=`, `--ephemeral`

: When used with the `shell`, `boot`, or `qemu` verbs, this option runs the specified verb on a temporary
  snapshot of the output image that is removed immediately when the container terminates. Taking the
  temporary snapshot is more efficient on file systems that support reflinks natively ("btrfs" or new "xfs")
  than on more traditional file systems that do not ("ext4").

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

`ToolsTree=`, `--tools-tree=`

: If specified, programs executed by mkosi are looked up inside the
  given tree instead of in the host system. Use this option to make
  image builds more reproducible by always using the same versions of
  programs to build the final image instead of whatever version is
  installed on the host system. If this option is not used, but the
  `mkosi.tools/` directory is found in the local directory it is
  automatically used for this purpose with the root directory as target.
  Note that when looking up binaries in `--tools-tree=`, only `/usr/bin`
  and `/usr/sbin` are considered. Specifically, paths specified by
  `--extra-search-path=` are ignored when looking up binaries in the
  given tools tree.

## Supported distributions

Images may be created containing installations of the following
distributions:

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

* *Gentoo* (**Gentoo is experimental and unsupported. We make no
  guarantee that it will work at all and the core maintainers will
  generally not fix gentoo specific issues**)

In theory, any distribution may be used on the host for building images
containing any other distribution, as long as the necessary tools are
available. Specifically, any distribution that packages `apt` may be
used to build *Debian* or *Ubuntu* images. Any distribution that
packages `dnf` may be used to build *CentOS*, *Alma Linux*, *Rocky
Linux*, *Fedora Linux*, *OpenSUSE*, *Mageia* or *OpenMandriva* images.
Any distro that packages `pacman` may be used to build *Arch Linux*
images. Any distribution that packages `zypper` may be used to build
*openSUSE* images.

Currently, *Fedora Linux* packages all relevant tools as of Fedora 28.

# Execution Flow

Execution flow for `mkosi build`. Default values/calls are shown in parentheses.
When building with `--incremental` mkosi creates a cache of the distribution
installation if not already existing and replaces the distribution installation
in consecutive runs with data from the cached one.

* Parse CLI options
* Parse configuration files
* If we're not running as root, unshare the user namespace and map the
  subuid range configured in /etc/subuid and /etc/subgid into it.
* Unshare the mount namespace
* Remount the following directories read-only if they exist:
  - /usr
  - /etc
  - /opt
  - /srv
  - /boot
  - /efi
  - /media
  - /mnt

Then, for each preset, we execute the following steps:

* Copy package manager trees into the workspace
* Copy base trees (`--base-tree=`) into the image
* Copy skeleton trees (`mkosi.skeleton`) into image
* Install distribution and packages into image or use cache tree if
  available
* Run prepare script on image with the `final` argument (`mkosi.prepare`)
* Install build packages in overlay if a build script is configured
* Run prepare script on overlay with the `build` argument if a build
  script is configured (`mkosi.prepare`)
* Cache the image if configured (`--incremental`)
* Run build script on image + overlay if a build script is configured (`mkosi.build`)
* Finalize the build if the output format `none` is configured
* Copy the build script outputs into the image
* Copy the extra trees into the image (`mkosi.extra`)
* Run post-install script (`mkosi.postinst`)
* Write config files required for `Ssh=`, `Autologin=` and `MakeInitrd=`
* Install systemd-boot and configure secure boot if configured (`--secure-boot`)
* Run `systemd-sysusers`
* Run `systemctl preset-all`
* Run `depmod`
* Run `systemd-firstboot`
* Run `systemd-hwdb`
* Remove packages and files (`RemovePackages=`, `RemoveFiles=`)
* Run SELinux relabel is a SELinux policy is installed
* Run finalize script (`mkosi.finalize`)
* Generate unified kernel image if configured to do so
* Generate final output format

# Scripts

To allow for image customization that cannot be implemented using
mkosi's builtin features, mkosi supports running scripts at various
points during the image build process that can customize the image as
needed. Scripts are executed on the host system with a customized
environment to simplify modifying the image. For each script, the
configured build sources (`BuildSources=`) are mounted into the current
working directory before running the script and `$SRCDIR` is set to
point to the current working directory. The following scripts are
supported:

* If **`mkosi.prepare`** (`PrepareScript=`) exists, it is first called
  with the `final` argument, right after the software packages are
  installed. It is called a second time with the `build` command line
  parameter, right after the build packages are installed and the build
  overlay mounted on top of the image's root directory . This script has
  network access and may be used to install packages from other sources
  than the distro's package manager (e.g. `pip`, `npm`, ...), after all
  software packages are installed but before the image is cached (if
  incremental mode is enabled). In contrast to a general purpose
  installation, it is safe to install packages to the system
  (`pip install`, `npm install -g`) instead of in `$SRCDIR` itself
  because the build image is only used for a single project and can
  easily be thrown away and rebuilt so there's no risk of conflicting
  dependencies and no risk of polluting the host system.

* If **`mkosi.build`** (`BuildScript=`) exists, it is executed with the
  build overlay mounted on top of the image's root directory. When
  running the build script, `$DESTDIR` points to a directory where the
  script should place any files generated it would like to end up in the
  image. Note that `make`/`automake`/`meson` based build systems
  generally honor `$DESTDIR`, thus making it very natural to build
  *source* trees from the build script. After running the build script,
  the contents of `$DESTDIR` are copied into the image.

* If **`mkosi.postinst`** (`PostInstallationScript=`) exists, it is
  executed after the (optional) build tree and extra trees have been
  installed. This script may be used to alter the images without any
  restrictions, after all software packages and built sources have been
  installed.

* If **`mkosi.finalize`** (`FinalizeScript=`) exists, it is executed as
  the last step of preparing an image.

Scripts executed by mkosi receive the following environment variables:

* `$SCRIPT` contains the path to the running script relative to the
  image root directory. The primary usecase for this variable is in
  combination with the `mkosi-chroot` script. See the description of
  `mkosi-chroot` below for more information.

* `$SRCDIR` contains the path to the directory mkosi was invoked from,
  with any configured build sources mounted on top. `$CHROOT_SRCDIR`
  contains the value that `$SRCDIR` will have after invoking
  `mkosi-chroot`.

* `$BUILDDIR` is only defined if `mkosi.builddir` exists and points to
  the build directory to use. This is useful for all build systems that
  support out-of-tree builds to reuse already built artifacts from
  previous runs. `$CHROOT_BUILDDIR` contains the value that `$BUILDDIR`
  will have after invoking `mkosi-chroot`.

* `$DESTDIR` is a directory into which any installed software generated
  by the build script may be placed. This variable is only set when
  executing the build script. `$CHROOT_DESTDIR` contains the value that
  `$DESTDIR` will have after invoking `mkosi-chroot`.

* `$OUTPUTDIR` points to the staging directory used to store build
  artifacts generated during the build. `$CHROOT_OUTPUTDIR` contains the
  value that `$OUTPUTDIR` will have after invoking `mkosi-chroot`.

* `$BUILDROOT` is the root directory of the image being built,
  optionally with the build overlay mounted on top depending on the
  script that's being executed.

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

Additionally, when a script is executed, a few scripts are made
available via `$PATH` to simplify common usecases.

* `mkosi-chroot`: This script will chroot into the image and execute the
  given command. On top of chrooting into the image, it will also mount
  various files and directories (`$SRCDIR`, `$DESTDIR`, `$BUILDDIR`,
  `$OUTPUTDIR`, `$SCRIPT`) into the image and modify the corresponding
  environment variables to point to the locations inside the image. It
  will also mount APIVFS filesystems (`/proc`, `/dev`, ...) to make sure
  scripts and tools executed inside the chroot work properly. It also
  propagates `/etc/resolv.conf` from the host into the chroot if
  requested so that DNS resolution works inside the chroot. After the
  mkosi-chroot command exits, various mount points are cleaned up.

  To execute the entire script inside the image, put the following
  snippet at the start of the script:

  ```sh
  if [ "$container" != "mkosi" ]; then
      exec mkosi-chroot "$SCRIPT" "$@"
  fi
  ```

* For all of the supported package managers except portage (`dnf`,
  `apt`, `pacman`, `zypper`), scripts of the same name are put into
  `$PATH` that make sure these commands operate on the image's root
  directory with the configuration supplied by the user instead of on
  the host system. This means that from a script, you can do e.g.
  `dnf install vim` to install vim into the image.

When scripts are executed, any directories that are still writable are
also made read-only (/home, /var, /root, ...) and only the minimal set
of directories that need to be writable remain writable. This is to
ensure that scripts can't mess with the host system when mkosi is
running as root.

# Files

To make it easy to build images for development versions of your
projects, mkosi can read configuration data from the local directory,
under the assumption that it is invoked from a *source*
tree. Specifically, the following files are used if they exist in the
local directory:

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

* The **`mkosi.nspawn`** nspawn settings file will be copied into the same place as the output image file, if
  it exists. This is useful since nspawn looks for settings files next to image files it boots, for
  additional container runtime settings.

* The **`mkosi.cache/`** directory, if it exists, is automatically used as package download cache, in order
  to speed repeated runs of the tool.

* The **`mkosi.builddir/`** directory, if it exists, is automatically used as out-of-tree build directory, if
  the build commands in the `mkosi.build` script support it. Specifically, this directory will be mounted
  into the build container, and the `$BUILDDIR` environment variable will be set to it when the build script
  is invoked. The build script may then use this directory as build directory, for automake-style or
  ninja-style out-of-tree builds. This speeds up builds considerably, in particular when `mkosi` is used in
  incremental mode (`-i`): not only the image and build overlay, but also the build tree is reused between
  subsequent invocations. Note that if this directory does not exist the `$BUILDDIR` environment variable is
  not set, and it is up to build script to decide whether to do in in-tree or an out-of-tree build, and which
  build directory to use.

* The **`mkosi.rootpw`** file can be used to provide the password for the root user of the image. If the
  password is prefixed with `hashed:` it is treated as an already hashed root password. The password may
  optionally be followed by a newline character which is implicitly removed. The file must have an access
  mode of 0600 or less. If this file does not exist, the distribution's default root password is set (which
  usually means access to the root user is blocked).

* The **`mkosi.passphrase`** file provides the passphrase to use when
  LUKS encryption is selected. It should contain the passphrase
  literally, and not end in a newline character (i.e. in the same
  format as cryptsetup and `/etc/crypttab` expect the passphrase
  files). The file must have an access mode of 0600 or less.

* The **`mkosi.crt`** and **`mkosi.key`** files contain an X.509 certificate and PEM private key to use when
  signing is required (UEFI SecureBoot, verity, ...).

* The **`mkosi.output/`** directory is used to store all build
  artifacts.

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

The package cache and incremental mode are unconditionally useful. The
final cache only apply to uses of `mkosi` with a source tree and build
script. When all three are enabled together turn-around times for
complete image builds are minimal, as only changed source files need to
be recompiled.

# PRESETS

Presets allow building more than one image with mkosi. Presets are
loaded from the `mkosi.presets/` directory. Presets can be either
directories containing mkosi configuration files or regular files with
the `.conf` extension.

When presets are found in `mkosi.presets/`, mkosi will build the
configured preset and its dependencies (or all of them if no presets
were explicitly configured using `--preset=`). To add dependencies
between presets, the `Dependencies=` setting can be used.

When presets are defined, mkosi will first read the global configuration
(configuration outside of the `mkosi.presets/` directory), followed by
the preset specific configuration. This means that global configuration
takes precedence over preset specific configuration.

Presets can refer to outputs of presets they depend on. Specifically,
for the following options, mkosi will only check whether the inputs
exist just before building the preset:

- `BaseTrees=`
- `PackageManagerTrees=`
- `SkeletonTrees=`
- `ExtraTrees=`
- `ToolsTree=`
- `Initrds=`

To refer to outputs of a preset's dependencies, simply configure any of
these options with a relative path to the output to use in the output
directory of the dependency.

A good example on how to use presets can be found in the systemd
repository: https://github.com/systemd/systemd/tree/main/mkosi.presets.

# ENVIRONMENT VARIABLES

* `$MKOSI_LESS` overrides options for `less` when it is invoked by
  `mkosi` to page output.

# EXAMPLES

Create and run a raw *GPT* image with *ext4*, as `image.raw`:

```console
# mkosi -p systemd --incremental boot
```

Create and run a bootable *GPT* image, as `foobar.raw`:

```console
$ mkosi -d fedora -p kernel-core -p systemd -p systemd-boot -p udev -o foobar.raw
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

if [ "$container" != "mkosi" ]; then
    exec mkosi-chroot "$SCRIPT" "$@"
fi

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
Further customization, e.g. a splash image, can be applied using a configuration
for `ukify` in `/etc/kernel/uki.conf` inside the skeleton tree.
`ukify` is run from the same working directory as mkosi itself.

The UKI is also copied into the output directory and may be booted directly:
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
Linux, Fedora Linux, OpenMandriva, Gentoo. Note that it has been a while
since the last release and the packages shipped by distributions are
very out of date. We currently recommend running mkosi from git until a
new release happens.

The latest code from git requires systemd 254.

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
