% mkosi(1)
%
%

# NAME

mkosi — Build Bespoke OS Images

# SYNOPSIS

`mkosi [options…] summary`

`mkosi [options…] build [command line…]`

`mkosi [options…] shell [command line…]`

`mkosi [options…] boot [nspawn settings…]`

`mkosi [options…] qemu [qemu parameters…]`

`mkosi [options…] ssh [command line…]`

`mkosi [options…] journalctl [command line…]`

`mkosi [options…] coredumpctl [command line…]`

`mkosi [options…] clean`

`mkosi [options…] serve`

`mkosi [options…] burn <device>`

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
  actually build anything.

`build`

: This builds the image based on the settings passed in on the command
  line or read from configuration files. This command is the default if
  no verb is explicitly specified. If any command line arguments are
  specified, these are passed directly to the build script if one is
  defined.

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
  as the *kernel command line* to the init system in the image.

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
  run `mkosi ssh` with the same config as `mkosi build` so that it has
  the necessary information available to connect to the running virtual
  machine via SSH. Specifically, the SSH private key from the `SshKey=`
  setting is used to connect to the virtual machine. Use `mkosi genkey`
  to automatically generate a key and certificate that will be picked up
  by mkosi. Any arguments passed after the `ssh` verb are passed as
  arguments to the `ssh` invocation. To connect to a container, use
  `machinectl login` or `machinectl shell`.

`journalctl`

: Uses `journalctl` to inspect the journal inside the image.
  Any arguments specified after the `journalctl` verb are appended to the
  `journalctl` invocation.

`coredumpctl`

: Uses `coredumpctl` to look for coredumps inside the image.
  Any arguments specified after the `coredumpctl` verb are appended to the
  `coredumpctl` invocation.

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

`burn <device>`

: This builds the image if it is not built yet, and then writes it to the
  specified block device. The partition contents are written as-is, but the GPT
  partition table is corrected to match sector and disk size of the specified
  medium.

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
  package cache is used (also see the **Files** section below),
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

`--debug-workspace=`

: When an error occurs, the workspace directory will not be deleted.

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

`--json`

: Show the summary output as JSON-SEQ.

## Supported output formats

The following output formats are supported:

* Raw *GPT* disk image, created using systemd-repart (*disk*)
* Plain directory, containing the OS tree (*directory*)
* Tar archive (*tar*)
* CPIO archive (*cpio*)

The output format may also be set to *none* to have mkosi produce no
image at all. This can be useful if you only want to use the image to
produce another output in the build scripts (e.g. build an rpm).

When a *GPT* disk image is created, repart partition definition files
may be placed in `mkosi.repart/` to configure the generated disk image.

It is highly recommended to run `mkosi` on a file system that supports reflinks
such as XFS and btrfs and to keep all related directories on the same file
system. This allows mkosi to create images very quickly by using reflinks to
perform copying via copy-on-write operations.

## Configuration Settings

The following settings can be set through configuration files (the
syntax with `SomeSetting=value`) and on the command line (the syntax
with `--some-setting=value`). For some command line parameters, a
single-letter shortcut is also allowed. In the configuration files,
the setting must be in the appropriate section, so the settings are
grouped by section below.

Configuration is parsed in the following order:

* The command line arguments are parsed
* `mkosi.local.conf` is parsed if it exists. This file should be in the
  gitignore (or equivalent) and is intended for local configuration.
* Any default paths (depending on the option) are configured if the
  corresponding path exists.
* `mkosi.conf` is parsed if it exists in the directory configured with
  `--directory=` or the current working directory if `--directory=` is
  not used.
* `mkosi.conf.d/` is parsed in the same directory if it exists. Each
  directory and each file with the `.conf` extension in `mkosi.conf.d/`
  is parsed. Any directory in `mkosi.conf.d` is parsed as if it were
  a regular top level directory.

Note that if the same setting is configured twice, the later assignment
overrides the earlier assignment unless the setting is a list based
setting. Also note that before v16, we used to do the opposite, where
the earlier assignment would be used instead of later assignments.

Settings that take a list of values are merged by appending the new
values to the previously configured values. Assigning the empty string
to such a setting removes all previously assigned values.

If a setting's name in the configuration file is prefixed with `@`, it
configures the default value used for that setting if no explicit
default value is set. This can be used to set custom default values in
configuration files that can still be overridden by specifying the
setting explicitly via the CLI.

To conditionally include configuration files, the `[Match]` section can
be used. Matches can use a pipe symbol (`|`) after the equals sign
(`…=|…`), which causes the match to become a triggering match. The
config file will be included if the logical AND of all non-triggering
matches and the logical OR of all triggering matches is satisfied. To
negate the result of a match, prefix the argument with an exclamation
mark. If an argument is prefixed with the pipe symbol and an exclamation
mark, the pipe symbol must be passed first, and the exclamation second.

Note that `[Match]` settings match against the current values of
specific settings, and do not take into account changes made to the
setting in configuration files that have not been parsed yet. Also note
that matching against a setting and then changing its value afterwards
in a different config file may lead to unexpected results.

The `[Match]` section of a `mkosi.conf` file in a directory applies to
the entire directory. If the conditions are not satisfied, the entire
directory is skipped. The `[Match]` sections of files in `mkosi.conf.d/`
and `mkosi.local.conf` only apply to the file itself.

If there are multiple `[Match]` sections in the same configuration file,
each of them has to be satisified in order for the configuration file to
be included. Specifically, triggering matches only apply to the current
`[Match]` section and are reset between multiple `[Match]` sections. As
an example, the following will only match if the output format is one
of `disk` or `directory` and the architecture is one of `x86-64` or
`arm64`:

```conf
[Match]
Format=|disk
Format=|directory

[Match]
Architecture=|x86-64
Architecture=|arm64
```

Command line options that take no argument are shown without `=` in
their long version. In the config files, they should be specified with a
boolean argument: either `1`, `yes`, or `true` to enable, or `0`, `no`,
`false` to disable.

### [Match] Section.

`Profile=`

: Matches against the configured profile.

`Distribution=`

: Matches against the configured distribution.

`Release=`

: Matches against the configured distribution release. If this condition is used and no distribution has been
  explicitly configured yet, the host distribution and release are used.

`Architecture=`

: Matches against the configured architecture. If this condition is used
  and no architecture has been explicitly configured yet, the host
  architecture is used.

`PathExists=`

: This condition is satisfied if the given path exists. Relative paths are interpreted relative to the parent
  directory of the config file that the condition is read from.

`ImageId=`

: Matches against the configured image ID, supporting globs. If this condition is used and no image ID has
  been explicitly configured yet, this condition fails.

`ImageVersion=`

: Matches against the configured image version. Image versions can be prepended by the operators `==`, `!=`,
  `>=`, `<=`, `<`, `>` for rich version comparisons according to the UAPI group version format specification.
  If no operator is prepended, the equality operator is assumed by default. If this condition is used and no
  image version has been explicitly configured yet, this condition fails.

`Bootable=`

: Matches against the configured value for the `Bootable=` feature. Takes a boolean value or `auto`.

`Format=`

: Matches against the configured value for the `Format=` option. Takes
  an output format (see the `Format=` option).

`SystemdVersion=`

: Matches against the systemd version on the host (as reported by
  `systemctl --version`). Values can be prepended by the operators `==`,
  `!=`, `>=`, `<=`, `<`, `>` for rich version comparisons according to
  the UAPI group version format specification. If no operator is
  prepended, the equality operator is assumed by default.

`BuildSources=`

: Takes a build source target path (see `BuildSources=`). This match is
  satisfied if any of the configured build sources uses this target
  path. For example, if we have a `mkosi.conf` file containing:

  ```conf
  [Content]
  BuildSources=../abc/qed:kernel
  ```

  and a drop-in containing:

  ```conf
  [Match]
  BuildSources=kernel
  ```

  The drop-in will be included.

: Any absolute paths passed to this setting are interpreted relative to
  the current working directory.

`HostArchitecture=`

: Matches against the host's native architecture. See the
  `Architecture=` setting for a list of possible values.

| Matcher             | Globs | Rich Comparisons | Default                 |
|---------------------|-------|------------------|-------------------------|
| `Profile=`          | no    | no               | match fails             |
| `Distribution=`     | no    | no               | match host distribution |
| `Release=`          | no    | no               | match host release      |
| `Architecture=`     | no    | no               | match host architecture |
| `PathExists=`       | no    | no               | n/a                     |
| `ImageId=`          | yes   | no               | match fails             |
| `ImageVersion=`     | no    | yes              | match fails             |
| `Bootable=`         | no    | no               | match auto feature      |
| `Format=`           | no    | no               | match default format    |
| `SystemdVersion=`   | no    | yes              | n/a                     |
| `BuildSources=`     | no    | no               | match fails             |
| `HostArchitecture=` | no    | no               | n/a                     |

### [Config] Section

`Profile=`, `--profile=`

: Select the given profile. A profile is a configuration file or
  directory in the `mkosi.profiles/` directory. When selected, this
  configuration file or directory is included after parsing the
  `mkosi.conf` file, but before any `mkosi.conf.d/*.conf` drop in
  configuration.

`Include=`, `--include=`

: Include extra configuration from the given file or directory. The
  extra configuration is included immediately after parsing the setting,
  except when a default is set using `@Include=`, in which case the
  configuration is included after parsing all the other configuration
  files.

: Note that each path containing extra configuration is only parsed
  once, even if included more than once with `Include=`.

`InitrdInclude=`, `--initrd-include=`

: Same as `Include=`, but the extra configuration files or directories
  are included when building the default initrd.

`Images=`, `--image=`

: If specified, only build the given image. Can be specified multiple
  times to build multiple images. All the given images and their
  dependencies are built. If not specified, all images are built. See
  the **Building multiple images** section for more information.

: Note that this section only takes effect when specified in the global
  configuration files. It has no effect if specified as an image
  specific setting.

`Dependencies=`, `--dependency=`

: The images that this image depends on specified as a comma-separated
  list. All images configured in this option will be built before this
  image and will be pulled in as dependencies of this image when
  `Images=` is used.

`MinimumVersion=`, `--minimum-version=`

: The minimum mkosi version required to build this configuration. If
  specified multiple times, the highest specified version is used.

### [Distribution] Section

`Distribution=`, `--distribution=`, `-d`

: The distribution to install in the image. Takes one of the following
  arguments: `fedora`, `debian`, `ubuntu`, `arch`, `opensuse`, `mageia`,
  `centos`, `rhel`, `rhel-ubi`, `openmandriva`, `rocky`, `alma`,
  `custom`. If not specified, defaults to the distribution of the host
  or `custom` if the distribution of the host is not a supported
  distribution.

`Release=`, `--release=`, `-r`

: The release of the distribution to install in the image. The precise
  syntax of the argument this takes depends on the distribution used,
  and is either a numeric string (in case of Fedora Linux, CentOS, …,
  e.g. `29`), or a distribution version name (in case of Debian, Ubuntu,
  …, e.g. `artful`). Defaults to a recent version of the chosen
  distribution, or the version of the distribution running on the host
  if it matches the configured distribution.

`Architecture=`, `--architecture=`

: The architecture to build the image for. The architectures that are
  actually supported depends on the distribution used and whether a
  bootable image is requested or not. When building for a foreign
  architecture, you'll also need to install and register a user mode
  emulator for that architecture.

: One of the following architectures can be specified per image built:
  `alpha`, `arc`, `arm`, `arm64`, `ia64`, `loongarch64`, `mips64-le`,
  `mips-le`, `parisc`, `ppc`, `ppc64`, `ppc64-le`, `riscv32`, `riscv64`,
  `s390`, `s390x`, `tilegx`, `x86`, `x86-64`.

`Mirror=`, `--mirror=`, `-m`

: The mirror to use for downloading the distribution packages. Expects
  a mirror URL as argument. If not provided, the default mirror for the
  distribution is used.

: The default mirrors for each distribution are as follows (unless
  specified, the same mirror is used for all architectures):

  |                | x86-64                            | aarch64                        |
  |----------------|-----------------------------------|--------------------------------|
  | `debian`       | http://deb.debian.org/debian      |                                |
  | `arch`         | https://geo.mirror.pkgbuild.com   | http://mirror.archlinuxarm.org |
  | `opensuse`     | http://download.opensuse.org      |                                |
  | `ubuntu`       | http://archive.ubuntu.com         | http://ports.ubuntu.com        |
  | `centos`       | https://mirrors.centos.org        |                                |
  | `rocky`        | https://mirrors.rockylinux.org    |                                |
  | `alma`         | https://mirrors.almalinux.org     |                                |
  | `fedora`       | https://mirrors.fedoraproject.org |                                |
  | `rhel-ubi`     | https://cdn-ubi.redhat.com        |                                |
  | `mageia`       | https://www.mageia.org            |                                |
  | `openmandriva` | http://mirrors.openmandriva.org   |                                |

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

`PackageManagerTrees=`, `--package-manager-tree=`

: This option mirrors the above `SkeletonTrees=` option and defaults to the
  same value if not configured otherwise, but installs the files to a
  subdirectory of the workspace directory instead of the OS tree. This
  subdirectory of the workspace is used to configure the package manager.

: `mkosi` will look for the package manager configuration and related
  files in the configured package manager trees. Unless specified
  otherwise, it will use the configuration file from its canonical
  location in `/etc` in the package manager trees. For example, it will
  look for `etc/dnf/dnf.conf` in the package manager trees if `dnf` is
  used to install packages.

: `SkeletonTrees=` and `PackageManagerTrees=` fulfill similar roles. Use
  `SkeletonTrees=` if you want the files to be present in the final image. Use
  `PackageManagerTrees=` if you don't want the files to be present in the final
  image, e.g. when building an initrd or if you want to refer to paths outside
  of the image in your repository configuration.

### [Output] Section

`Format=`, `--format=`, `-t`

: The image format type to generate. One of `directory` (for generating
  an OS image directly in a local directory), `tar` (similar, but a
  tarball of the OS image is generated), `cpio` (similar, but a cpio
  archive is generated), `disk` (a block device OS image with a GPT
  partition table), `uki` (a unified kernel image with the OS image in
  the `.initrd` PE section), `esp` (`uki` but wrapped in a disk image
  with only an ESP partition), `sysext`, `confext`, `portable` or `none`
  (the OS image is solely intended as a build image to produce another
  artifact).

: If the `disk` output format is used, the disk image is generated using
  `systemd-repart`. The repart partition definition files to use can be
  configured using the `RepartDirectories=` setting or via
  `mkosi.repart/`. When verity partitions are configured using
  systemd-repart's `Verity=` setting, mkosi will automatically parse the
  verity hash partition's roothash from systemd-repart's JSON output and
  include it in the kernel command line of every unified kernel image
  built by mkosi.

`ManifestFormat=`, `--manifest-format=`

: The manifest format type or types to generate. A comma-delimited
  list consisting of `json` (the standard JSON output format that
  describes the packages installed), `changelog` (a human-readable
  text format designed for diffing). By default no manifest is
  generated.

`Output=`, `--output=`, `-o`

: Name to use for the generated output image file or directory. All
  outputs will be prefixed with the given name. Defaults to `image` or,
  if `ImageId=` is specified, it is used as the default output name,
  optionally suffixed with the version set with `ImageVersion=`. Note
  that this option does not allow configuring the output directory, use
  `OutputDirectory=` for that.

: Note that this only specifies the output prefix, depending on the
  specific output format, compression and image version used, the full
  output name might be `image_7.8.raw.xz`.

`CompressOutput=`, `--compress-output=`

: Configure compression for the resulting image or archive. The argument can be
  either a boolean or a compression algorithm (`xz`, `zstd`). `zstd`
  compression is used by default, except CentOS and derivatives up to version
  8, which default to `xz`. Note that when applied to block device image types,
  compression means the image cannot be started directly but needs to be
  decompressed first. This also means that the `shell`, `boot`, `qemu` verbs
  are not available when this option is used. Implied for `tar`, `cpio`, `uki`,
  and `esp`.

`OutputDirectory=`, `--output-dir=`, `-O`

: Path to a directory where to place all generated artifacts. If this is
  not specified and the directory `mkosi.output/` exists in the local
  directory, it is automatically used for this purpose.

`WorkspaceDirectory=`, `--workspace-dir=`

: Path to a directory where to store data required temporarily while
  building the image. This directory should have enough space to store
  the full OS image, though in most modes the actually used disk space
  is smaller. If not specified, a subdirectory of `$XDG_CACHE_HOME` (if
  set), `$HOME/.cache` (if set) or `/var/tmp` is used.

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
  generated on previous invocations. The build scripts can find the path
  to this directory in the `$BUILDDIR` environment variable. This
  directory is mounted into the image's root directory when
  `mkosi-chroot` is invoked during execution of the build scripts. If
  this option is not specified, but a directory `mkosi.builddir/` exists
  in the local directory it is automatically used for this purpose (also
  see the **Files** section below).

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
  file will be named after it (possibly suffixed with the version). The
  identifier is also passed via the `$IMAGE_ID` to any build scripts
  invoked. The image ID is automatically added to `/usr/lib/os-release`.

`SplitArtifacts=`, `--split-artifacts`

: If specified and building a disk image, pass `--split=yes` to systemd-repart
  to have it write out split partition files for each configured partition.
  Read the [man](https://www.freedesktop.org/software/systemd/man/systemd-repart.html#--split=BOOL)
  page for more information. This is useful in A/B update scenarios where
  an existing disk image shall be augmented with a new version of a
  root or `/usr` partition along with its Verity partition and unified
  kernel.

`RepartDirectories=`, `--repart-dir=`

: Paths to directories containing systemd-repart partition definition
  files that are used when mkosi invokes systemd-repart when building a
  disk image. If `mkosi.repart/` exists in the local directory, it will
  be used for this purpose as well. Note that mkosi invokes repart with
  `--root=` set to the root of the image root, so any `CopyFiles=`
  source paths in partition definition files will be relative to the
  image root directory.

`SectorSize=`, `--sector-size=`

: Override the default sector size that systemd-repart uses when building a disk
  image.

`RepartOffline=`, `--repart-offline=`

: Specifies whether to build disk images using loopback devices. Enabled
  by default. When enabled, `systemd-repart` will not use loopback
  devices to build disk images. When disabled, `systemd-repart` will
  always use loopback devices to build disk images.

: Note that when using `RepartOffline=no` mkosi cannot run unprivileged and
  the image build has to be done as the root user outside of any
  containers and with loopback devices available on the host system.

: There are currently two known scenarios where `RepartOffline=no` has to be
  used. The first is when using `Subvolumes=` in a repart partition
  definition file, as subvolumes cannot be created without using
  loopback devices. The second is when creating a system with SELinux
  and an XFS root partition. Because `mkfs.xfs` does not support
  populating an XFS filesystem with extended attributes, loopback
  devices have to be used to ensure the SELinux extended attributes end
  up in the generated XFS filesystem.

`Overlay=`, `--overlay`

: When used together with `BaseTrees=`, the output will consist only out of
  changes to the specified base trees. Each base tree is attached as a lower
  layer in an overlayfs structure, and the output becomes the upper layer,
  initially empty. Thus files that are not modified compared to the base trees
  will not be present in the final output.

: This option may be used to create [systemd *system extensions* or
  *portable services*](https://uapi-group.org/specifications/specs/extension_image).

`UseSubvolumes=`, `--use-subvolumes=`

: Takes a boolean or `auto`. Enables or disables use of btrfs subvolumes for
  directory tree outputs. If enabled, mkosi will create the root directory as
  a btrfs subvolume and use btrfs subvolume snapshots where possible to copy
  base or cached trees which is much faster than doing a recursive copy. If
  explicitly enabled and `btrfs` is not installed or subvolumes cannot be
  created, an error is raised. If `auto`, missing `btrfs` or failures to
  create subvolumes are ignored.

`Seed=`, `--seed=`

: Takes a UUID as argument or the special value `random`.
  Overrides the seed that [`systemd-repart(8)`](https://www.freedesktop.org/software/systemd/man/systemd-repart.service.html)
  uses when building a disk image. This is useful to achieve reproducible
  builds, where deterministic UUIDs and other partition metadata should be
  derived on each build.

`SourceDateEpoch=`, `--source-date-epoch=`

: Takes a timestamp as argument. Resets file modification times of all files to
  this timestamp. The variable is also propagated to systemd-repart and
  scripts executed by mkosi. If not set explicitly, `SOURCE_DATE_EPOCH` from
  `--environment` and from the host environment are tried in that order.
  This is useful to make builds reproducible. See
  [SOURCE_DATE_EPOCH](https://reproducible-builds.org/specs/source-date-epoch/)
  for more information.

### [Content] Section

`Packages=`, `--package=`, `-p`

: Install the specified distribution packages (i.e. RPM, DEB, …) in the
  image. Takes a comma separated list of package specifications. This
  option may be used multiple times in which case the specified package
  lists are combined. Use `BuildPackages=` to specify packages that
  shall only be installed in an overlay that is mounted when the prepare
  scripts are executed with the `build` argument and when the build scripts
  are executed.

: The types and syntax of *package specifications* that are allowed
  depend on the package installer (e.g. `dnf` for `rpm`-based distros or
  `apt` for `deb`-based distros), but may include package names, package
  names with version and/or architecture, package name globs, paths to
  packages in the file system, package groups, and virtual provides,
  including file paths.

: Example: when using a distro that uses `dnf`, the following configuration
  would install the `meson` package (in the latest version), the 32-bit version
  of the `libfdisk-devel` package, all available packages that start with the
  `git-` prefix, a `systemd` rpm from the local file system, one of the
  packages that provides `/usr/bin/ld`, the packages in the *Development Tools*
  group, and the package that contains the `mypy` python module.

  ```
  Packages=meson
           libfdisk-devel.i686
           git-*
           prebuilt/rpms/systemd-249-rc1.local.rpm
           /usr/bin/ld
           @development-tools
           python3dist(mypy)
  ```


`BuildPackages=`, `--build-package=`

: Similar to `Packages=`, but configures packages to install only in an
  overlay that is made available on top of the image to the prepare
  scripts when executed with the `build` argument and the build scripts.
  This option should be used to list packages containing header files,
  compilers, build systems, linkers and other build tools the
  `mkosi.build` scripts require to operate. Note that packages listed
  here will be absent in the final image.

`WithRecommends=`, `--with-recommends=`

: Configures whether to install recommended or weak dependencies,
  depending on how they are named by the used package manager, or not.
  By default, recommended packages are not installed. This is only used
  for package managers that support the concept, which are currently
  apt, dnf and zypper.

`WithDocs=`, `--with-docs`

: Include documentation in the image. Enabled by default. When disabled,
  if the underlying distribution package manager supports it
  documentation is not included in the image. The `$WITH_DOCS`
  environment variable passed to the `mkosi.build` scripts is set to `0`
  or `1` depending on whether this option is enabled or disabled.

`BaseTrees=`, `--base-tree=`

: Takes a comma separated list of paths to use as base trees. When used,
  these base trees are each copied into the OS tree and form the base
  distribution instead of installing the distribution from scratch. Only
  extra packages are installed on top of the ones already installed in
  the base trees. Note that for this to work properly, the base image
  still needs to contain the package manager metadata (see
  `CleanPackageMetadata=`).

: Instead of a directory, a tar file or a disk image may be provided. In
  this case it is unpacked into the OS tree. This mode of operation
  allows setting permissions and file ownership explicitly, in
  particular for projects stored in a version control system such as
  `git` which retain full file ownership and access mode metadata for
  committed files.

`SkeletonTrees=`, `--skeleton-tree=`

: Takes a comma separated list of colon separated path pairs. The first
  path of each pair refers to a directory to copy into the OS tree
  before invoking the package manager. The second path of each pair
  refers to the target directory inside the image. If the second path is
  not provided, the directory is copied on top of the root directory of
  the image. The second path is always interpreted as an absolute path.
  Use this to insert files and directories into the OS tree before the
  package manager installs any packages. If the `mkosi.skeleton/`
  directory is found in the local directory it is also used for this
  purpose with the root directory as target (also see the **Files**
  section below).

: As with the base tree logic above, instead of a directory, a tar
  file may be provided too. `mkosi.skeleton.tar` will be automatically
  used if found in the local directory.

`ExtraTrees=`, `--extra-tree=`

: Takes a comma separated list of colon separated path pairs. The first
  path of each pair refers to a directory to copy from the host into the
  image. The second path of each pair refers to the target directory
  inside the image. If the second path is not provided, the directory is
  copied on top of the root directory of the image. The second path is
  always interpreted as an absolute path. Use this to override any
  default configuration files shipped with the distribution. If the
  `mkosi.extra/` directory is found in the local directory it is also
  used for this purpose with the root directory as target. (also see the
  **Files** section below).

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
  installation. Can be specified as `true`, `false`, or `auto` (the
  default). With `auto`, files will be removed if the respective
  package manager executable is *not* present at the end of the
  installation.

`PrepareScripts=`, `--prepare-script=`

: Takes a comma-separated list of paths to executables that are used as
  the prepare scripts for this image. See the **Scripts** section for
  more information.

`BuildScripts=`, `--build-script=`

: Takes a comma-separated list of paths to executables that are used as
  the build scripts for this image. See the **Scripts** section for more
  information.

`PostInstallationScripts=`, `--postinst-script=`

: Takes a comma-separated list of paths to executables that are used as
  the post-installation scripts for this image. See the **Scripts** section
  for more information.

`FinalizeScripts=`, `--finalize-script=`

: Takes a comma-separated list of paths to executables that are used as
  the finalize scripts for this image. See the **Scripts** section for more
  information.

`BuildSources=`, `--build-sources=`

: Takes a comma separated list of colon separated path pairs. The first
  path of each pair refers to a directory to mount from the host. The
  second path of each pair refers to the directory where the source
  directory should be mounted when running scripts. Every target path
  is prefixed with the current working directory and all build sources
  are sorted lexicographically by their target before mounting so that
  top level paths are mounted first. When using the `mkosi-chroot`
  script ( see the **Scripts** section), the current working directory
  with all build sources mounted in it is mounted to `/work/src` inside
  the image's root directory.

`BuildSourcesEphemeral=`, `--build-sources-ephemeral=`

: Takes a boolean. Disabled by default. Configures whether changes to
  source directories (The working directory and configured using
  `BuildSources=`) are persisted. If enabled, all source directories
  will be reset to their original state after scripts finish executing.

`Environment=`, `--environment=`

: Adds variables to the environment that package managers and the
  prepare/build/postinstall/finalize scripts are executed with. Takes
  a space-separated list of variable assignments or just variable
  names. In the latter case, the values of those variables will be
  passed through from the environment in which `mkosi` was invoked.
  This option may be specified more than once, in which case all
  listed variables will be set. If the same variable is set twice, the
  later setting overrides the earlier one.

`EnvironmentFiles=`, `--env-file=`

: Takes a comma-separated list of paths to files that contain enviroment
  variable definitions to be added to the scripting environment. Uses
  `mkosi.env` if it is found in the local directory. The variables are
  first read from `mkosi.env` if it exists, then from the given list of
  files and then from the `Environment=` settings.

`WithTests=`, `--without-tests`, `-T`

: If set to false (or when the command-line option is used), the
  `$WITH_TESTS` environment variable is set to `0` when the
  `mkosi.build` scripts are invoked. This is supposed to be used by the
  build scripts to bypass any unit or integration tests that are
  normally run during the source build process. Note that this option
  has no effect unless the `mkosi.build` build scripts honor it.

`WithNetwork=`, `--with-network=`

: When true, enables network connectivity while the build scripts
  `mkosi.build` are invoked. By default, the build scripts run with
  networking turned off. The `$WITH_NETWORK` environment variable is
  passed to the `mkosi.build` build scripts indicating whether the
  build is done with or without network.

`Bootable=`, `--bootable=`

: Takes a boolean or `auto`. Enables or disables generation of a
  bootable image. If enabled, mkosi will install an EFI bootloader, and
  add an ESP partition when the disk image output is used. If the
  selected EFI bootloader (See `Bootloader=`) is not installed or no
  kernel images can be found, the build will fail. `auto` behaves as if
  the option was enabled, but the build won't fail if either no kernel
  images or the selected EFI bootloader can't be found. If disabled, no
  bootloader will be installed even if found inside the image, no
  unified kernel images will be generated and no ESP partition will be
  added to the image if the disk output format is used.

`Bootloader=`, `--bootloader=`

: Takes one of `none`, `systemd-boot`, `uki` or `grub`. Defaults to
  `systemd-boot`. If set to `none`, no EFI bootloader will be installed
  into the image. If set to `systemd-boot`, systemd-boot will be
  installed and for each installed kernel, a UKI will be generated and
  stored in `EFI/Linux` in the ESP. If set to `uki`, a single UKI will
  be generated for the latest installed kernel (the one with the highest
  version) which is installed to `EFI/BOOT/BOOTX64.EFI` in the ESP. If
  set to `grub`, for each installed kernel, a UKI will be generated and
  stored in `EFI/Linux` in the ESP. For each generated UKI, a menu entry
  is appended to the grub configuration in `grub/grub.cfg` in the ESP
  which chainloads into the UKI. A shim grub.cfg is also written to
  `EFI/<distribution>/grub.cfg` in the ESP which loads `grub/grub.cfg`
  in the ESP for compatibility with signed versions of grub which load
  the grub configuration from this location.

: Note that we do not yet install grub to the ESP when `Bootloader=` is
  set to `grub`. This has to be done manually in a postinst or finalize
  script. The grub EFI binary should be installed to
  `/efi/EFI/BOOT/BOOTX64.EFI` (or similar depending on the architecture)
  and should be configured to load its configuration from
  `EFI/<distribution>/grub.cfg` in the ESP. Signed versions of grub
  shipped by distributions will load their configuration from this
  location by default.

`BiosBootloader=`, `--bios-bootloader=`

: Takes one of `none` or `grub`. Defaults to `none`. If set to `none`,
  no BIOS bootloader will be installed. If set to `grub`, grub is
  installed as the BIOS boot loader if a bootable image is requested
  with the `Bootable=` option. If no repart partition definition files
  are configured, mkosi will add a grub BIOS boot partition and an EFI
  system partition to the default partition definition files.

: Note that this option is not mutually exclusive with `Bootloader=`. It
  is possible to have an image that is both bootable on UEFI and BIOS by
  configuring both `Bootloader=` and `BiosBootloader=`.

: The grub BIOS boot partition should have UUID
  `21686148-6449-6e6f-744e-656564454649` and should be at least 1MB.

: Even if no EFI bootloader is installed, we still need an ESP for BIOS
  boot as that's where we store the kernel, initrd and grub modules.

`ShimBootloader=`, `--shim-bootloader=`

: Takes one of `none`, `unsigned`, or `signed`. Defaults to `none`. If
  set to `none`, shim and MokManager will not be installed to the ESP.
  If set to `unsigned`, mkosi will search for unsigned shim and
  MokManager EFI binaries and install them. If `SecureBoot=` is enabled,
  mkosi will sign the unsigned EFI binaries before installing thel. If
  set to `signed`, mkosi will search for signed EFI binaries and install
  those. Even if `SecureBoot=` is enabled, mkosi won't sign these
  binaries again.

: Note that this option only takes effect when an image that is bootable
  on UEFI firmware is requested using other options
  (`Bootable=`, `Bootloader=`).

`Initrds=`, `--initrd`

: Use user-provided initrd(s). Takes a comma separated list of paths to
  initrd files. This option may be used multiple times in which case the
  initrd lists are combined. If no initrds are specified and a bootable
  image is requested, mkosi will automatically build a default initrd.

`InitrdPackages=`, `--initrd-package=`

: Extra packages to install into the default initrd. Takes a comma
  separated list of package specifications. This option may be used
  multiple times in which case the specified package lists are combined.

`KernelCommandLine=`, `--kernel-command-line=`

: Use the specified kernel command line when building images.

`KernelModulesInclude=`, `--kernel-modules-include=`

: Takes a list of regex patterns that specify kernel modules to include in the image. Patterns should be
  relative to the `/usr/lib/modules/<kver>/kernel` directory. mkosi checks for a match anywhere in the module
  path (e.g. `i915` will match against `drivers/gpu/drm/i915.ko`). All modules that match any of the
  specified patterns are included in the image. All module and firmware dependencies of the matched modules
  are included in the image as well. This setting takes priority over `KernelModulesExclude=` and only makes
  sense when used in combination with it because all kernel modules are included in the image by default.

`KernelModulesExclude=`, `--kernel-modules-exclude=`

: Takes a list of regex patterns that specify modules to exclude from the image. Behaves the same as
  `KernelModulesInclude=` except that all modules that match any of the specified patterns are excluded from
  the image.

`KernelModulesIncludeHost=`, `--kernel-modules-include-host=`

: Takes a boolean. Specifies whether to include the currently loaded
  modules on the host system in the image. This setting takes priority
  over `KernelModulesExclude=` and only makes sense when used in
  combination with it because all kernel modules are included in the
  image by default.

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

`KernelModulesInitrdIncludeHost=`, `--kernel-modules-initrd-include-host=`

: Like `KernelModulesIncludeHost=`, but applies to the kernel modules included in the kernel modules initrd.

: The settings `Locale=`, `--locale=`, `LocaleMessages=`, `--locale-messages=`,
  `Keymap=`, `--keymap=`, `Timezone=`, `--timezone=`, `Hostname=`,
  `--hostname=`, `RootShell=`, `--root-shell=` correspond to the identically
  named systemd-firstboot options. See the systemd firstboot
  [manpage](https://www.freedesktop.org/software/systemd/man/systemd-firstboot.html)
  for more information.  Additionally, where applicable, the corresponding
  systemd credentials for these settings are written to `/usr/lib/credstore`,
  so that they apply even if only `/usr` is shipped in the image.

`RootPassword=`, `--root-password=`,

: Set the system root password. If this option is not used, but a `mkosi.rootpw` file is found in the local
  directory, the password is automatically read from it. If the password starts with `hashed:`, it is treated
  as an already hashed root password. The root password is also stored in `/usr/lib/credstore` under the
  appropriate systemd credential so that it applies even if only `/usr` is shipped in the image. To create
  an unlocked account without any password use `hashed:` without a hash.

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
  this option behave correctly. Run `mkosi genkey` to automatically
  generate an X509 certificate and private key to be used by mkosi to
  enable SSH access to any virtual machines via `mkosi ssh`. To access
  images booted using `mkosi boot`, use `machinectl`.

`SELinuxRelabel=`, `--selinux-relabel=`

: Specifies whether to relabel files to match the image's SELinux
  policy. Takes a boolean value or `auto`. Defaults to `auto`. If
  disabled, files will not relabeled. If enabled, an SELinux policy has
  to be installed in the image and `setfiles` has to be available to
  relabel files. If any errors occur during `setfiles`, the build will
  fail. If set to `auto`, files will be relabeled if an SELinux policy
  is installed in the image and if `setfiles` is available. Any errors
  occurred during `setfiles` will be ignored.

: Note that when running unprivileged, `setfiles` will fail to set any
  labels that are not in the host's SELinux policy. To ensure `setfiles`
  succeeds without errors, make sure to run mkosi as root or build from
  a host system with the same SELinux policy as the image you're
  building.

### [Validation] Section

`SecureBoot=`, `--secure-boot`

: Sign systemd-boot (if it is not signed yet) and any generated
  unified kernel images for UEFI SecureBoot.

`SecureBootAutoEnroll=`, `--secure-boot-auto-enroll=`

: Set up automatic enrollment of the secure boot keys in virtual machines as
  documented in the systemd-boot
  [man page](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)
  if `SecureBoot=` is used.
  Note that systemd-boot will only do automatic secure boot key
  enrollment in virtual machines starting from systemd v253. To do auto
  enrollment on systemd v252 or on bare metal machines, write a
  systemd-boot configuration file to `/efi/loader/loader.conf` using an
  extra tree with `secure-boot-enroll force` or
  `secure-boot-enroll manual` in it. Auto enrollment is not supported on
  systemd versions older than v252. Defaults to `yes`.

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

`SignExpectedPcr=`, `--sign-expected-pcr`

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
  prepare scripts have executed but before the `mkosi.build` scripts are
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
  argument which controls the amount of guest's RAM. Defaults to `2G`.

`QemuKvm=`, `--qemu-kvm=`

: When used with the `qemu` verb, this option specifies whether QEMU should use KVM acceleration. Takes a
  boolean value or `auto`. Defaults to `auto`.

`QemuVsock=`, `--qemu-vsock=`

: When used with the `qemu` verb, this option specifies whether QEMU should be configured with a vsock. Takes
  a boolean value or `auto`. Defaults to `auto`.

`QemuVsockConnectionId=`, `--qemu-vsock-cid=`

: When used with the `qemu` verb, this option specifies the vsock
  connection ID to use. Takes a number in the interval `[3, 0xFFFFFFFF)`
  or `hash` or `auto`. Defaults to `hash`. When set to `hash`, the
  connection ID will be derived from the full path to the image. When
  set to `auto`, `mkosi` will try to find a free connection ID
  automatically. Otherwise, the provided number will be used as is.

: Note that when set to `auto`, `mkosi ssh` cannot be used as we cannot
  figure out which free connection ID we found when booting the image
  earlier.

`QemuSwtpm=`, `--qemu-swtpm=`

: When used with the `qemu` verb, this option specifies whether to start an instance of swtpm to be used as a
  TPM with qemu. This requires swtpm to be installed on the host. Takes a boolean value or `auto`. Defaults
  to `auto`.

`QemuCdrom=`, `--qemu-cdrom=`

: When used with the `qemu` verb, this option specifies whether to
  attach the image to the virtual machine as a CD-ROM device. Takes a
  boolean. Defaults to `no`.

`QemuFirmware=`, `--qemu-firmware=`

: When used with the `qemu` verb, this option specifies which firmware
  to use. Takes one of `uefi`, `bios`, `linux`, or `auto`. Defaults to
  `auto`. When set to `uefi`, the OVMF firmware is used. When set to
  `bios`, the default SeaBIOS firmware is used. When set to `linux`,
  direct kernel boot is used. See the `QemuKernel=` option for more
  details on which kernel image is used with direct kernel boot. When
  set to `auto`, `linux` is used if a cpio image is being booted, `uefi`
  otherwise.

`QemuFirmwareVariables=`, `--qemu-firmware-variables=`

: When used with the `qemu` verb, this option specifies the path to the
  the firmware variables file to use. Currently, this option is only
  taken into account when the `uefi` firmware is used. If not specified,
  mkosi will search for the default variables file and use that instead.

: `virt-fw-vars` from the
  [virt-firmware](https://gitlab.com/kraxel/virt-firmware) project can
  be used to customize OVMF variable files.

: Some distributions also provide variable files which already have
  Microsoft's certificates for secure boot enrolled. For Fedora
  and Debian these are `OVMF_VARS.secboot.fd` and `OVMF_VARS_4M.ms.fd`
  under `/usr/share/OVMF` respectively. You can use `locate` and look
  under `/usr/share/qemu/firmware` for hints on where to find these
  files if your distribution ships them.

`QemuKernel=`, `--qemu-kernel=`

: Set the kernel image to use for qemu direct kernel boot. If not
  specified, mkosi will use the kernel provided via the command line
  (`-kernel` option) or latest the kernel that was installed into
  the image (or fail if no kernel was installed into the image).

: Note that when the `cpio` output format is used, direct kernel boot is
  used regardless of the configured firmware. Depending on the
  configured firmware, qemu might boot the kernel itself or using the
  configured firmware.

`QemuDrives=`, `--qemu-drive=`

: Add a qemu drive. Takes a colon-delimited string of format
  `<id>:<size>[:<directory>[:<options>]]`. `id` specifies the qemu id we
  assign to the drive. This can be used as the `drive=` property in
  various qemu devices. `size` specifies the size of the drive. This
  takes a size in bytes. Additionally, the suffixes `K`, `M` and `G` can
  be used to specify a size in kilobytes, megabytes and gigabytes
  respectively. `directory` optionally specifies the directory in which
  to create the file backing the drive. `options` optionally specifies
  extra comma-delimited properties which are passed verbatime to qemu's
  `-drive` option.

`QemuArgs=`

: Space-delimited list of additional arguments to pass when invoking
  qemu.

`Ephemeral=`, `--ephemeral`

: When used with the `shell`, `boot`, or `qemu` verbs, this option runs the specified verb on a temporary
  snapshot of the output image that is removed immediately when the container terminates. Taking the
  temporary snapshot is more efficient on file systems that support reflinks natively (btrfs or xfs)
  than on more traditional file systems that do not (ext4).

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

: If set to `default`, mkosi will automatically add an extra tools tree
  image and use it as the tools tree. The following table shows for
  which distributions default tools tree packages are defined and which
  packages are included in those default tools trees:

  |                         | Fedora | CentOS | Debian | Arch | openSUSE |
  |-------------------------|--------|--------|--------|------|----------|
  | `apt`                   | X      | X      | X      | X    |          |
  | `archlinux-keyring`     | X      |        | X      | X    |          |
  | `bash`                  | X      | X      | X      | X    | X        |
  | `btrfs-progs`           | X      |        | X      | X    | X        |
  | `bubblewrap`            | X      | X      | X      | X    | X        |
  | `ca-certificates`       | X      | X      | X      | X    | X        |
  | `coreutils`             | X      | X      | X      | X    | X        |
  | `cpio`                  | X      | X      | X      | X    | X        |
  | `curl`                  | X      | X      | X      | X    | X        |
  | `debian-keyring`        | X      | X      | X      | X    |          |
  | `diffutils`             | X      | X      | X      | X    | X        |
  | `distribution-gpg-keys` | X      | X      |        |      | X        |
  | `dnf`                   | X      | X      | X      | X    | X        |
  | `dnf-plugins-core`      | X      | X      |        |      | X        |
  | `dnf5`                  | X      |        |        |      |          |
  | `dnf5-plugins`          | X      |        |        |      |          |
  | `dosfstools`            | X      | X      | X      | X    | X        |
  | `e2fsprogs`             | X      | X      | X      | X    | X        |
  | `edk2-ovmf`             | X      | X      | X      | X    | X        |
  | `erofs-utils`           | X      |        | X      | X    | X        |
  | `kmod`                  | X      | X      | X      | X    | X        |
  | `less`                  | X      | X      | X      | X    | X        |
  | `mtools`                | X      | X      | X      | X    | X        |
  | `nano`                  | X      | X      | X      | X    | X        |
  | `openssh`               | X      | X      | X      | X    | X        |
  | `openssl`               | X      | X      | X      | X    | X        |
  | `pacman`                | X      |        | X      | X    |          |
  | `pesign`                | X      | X      | X      | X    | X        |
  | `qemu`                  | X      | X      | X      | X    | X        |
  | `sbsigntools`           | X      |        | X      | X    | X        |
  | `socat`                 | X      | X      | X      | X    | X        |
  | `squashfs-tools`        | X      | X      | X      | X    | X        |
  | `strace`                | X      | X      | X      | X    | X        |
  | `swtpm`                 | X      | X      | X      | X    | X        |
  | `systemd`               | X      | X      | X      | X    | X        |
  | `ukify`                 | X      |        | X      | X    | X        |
  | `tar`                   | X      | X      | X      | X    | X        |
  | `ubuntu-keyring`        | X      | X      | X      | X    |          |
  | `util-linux`            | X      | X      | X      | X    | X        |
  | `virtiofsd`             | X      | X      |        | X    | X        |
  | `xfsprogs`              | X      | X      | X      | X    | X        |
  | `xz`                    | X      | X      | X      | X    | X        |
  | `zstd`                  | X      | X      | X      | X    | X        |
  | `zypper`                | X      |        | X      | X    |          |

`ToolsTreeDistribution=`, `--tools-tree-distribution=`

: Set the distribution to use for the default tools tree. By default,
  the same distribution as the image that's being built is used, except
  for CentOS and Ubuntu images, in which case Fedora and Debian are used
  respectively.

`ToolsTreeRelease=`, `--tools-tree-release=`

: Set the distribution release to use for the default tools tree. By
  default, the hardcoded default release in mkosi for the distribution
  is used.

`ToolsTreeMirror=`, `--tools-tree-mirror=`

: Set the mirror to use for the default tools tree. By default, the
  default mirror for the tools tree distribution is used.

`ToolsTreePackages=`, `--tools-tree-packages=`

: Extra packages to install into the default tools tree. Takes a comma
  separated list of package specifications. This option may be used
  multiple times in which case the specified package lists are combined.

`RuntimeTrees=`, `--runtime-tree=`

: Takes a colon separated pair of paths. The first path refers to a
  directory to mount into any machine (container or VM) started by
  mkosi. The second path refers to the target directory inside the
  machine. If the second path is not provided, the directory is mounted
  below `/root/src` in the machine. If the second path is relative, it
  is interpreted relative to `/root/src` in the machine.

: For each mounted directory, the uid and gid of the user running mkosi
  are mapped to the root user in the machine. This means that all the
  files and directories will appear as if they're owned by root in the
  machine, and all new files and directories created by root in the
  machine in these directories will be owned by the user running mkosi
  on the host.

: Note that when using `mkosi qemu` with this feature systemd v254 or
  newer has to be installed in the image.

`RuntimeSize=`, `--runtime-size`

: If specified, disk images are grown to the specified size before
  they're booted with systemd-nspawn or qemu. Takes a size in bytes.
  Additionally, the suffixes `K`, `M` and `G` can be used to specify a
  size in kilobytes, megabytes and gigabytes respectively.

`SshKey=`, `--ssh-key=`

: Path to the X509 private key in PEM format to use to connect to a
  virtual machine started with `mkosi qemu` and built with the `Ssh=`
  option enabled via the `mkosi ssh` command. If not configured and
  `mkosi.key` exists in the working directory, it will automatically be
  used for this purpose. Run `mkosi genkey` to automatically generate
  a key in `mkosi.key`.

`SshCertificate=`, `--ssh-certificate=`

: Path to the X509 certificate in PEM format to provision as the SSH
  public key in virtual machines started with `mkosi qemu`.  If not
  configured and `mkosi.crt` exists in the working directory, it will
  automatically be used for this purpose. Run `mkosi genkey` to
  automatically generate a certificate in `mkosi.crt`.

## Specifiers

The current value of various settings can be accessed when parsing
configuration files by using specifiers. To write a literal `%`
character in a configuration file without treating it as a specifier,
use `%%`. The following specifiers are understood:

| Setting            | Specifier |
|--------------------|-----------|
| `Distribution=`    | `%d`      |
| `Release=`         | `%r`      |
| `Architecture=`    | `%a`      |
| `Format=`          | `%t`      |
| `Output=`          | `%o`      |
| `OutputDirectory=` | `%O`      |
| `ImageId=`         | `%i`      |
| `ImageVersion=`    | `%v`      |

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

* *RHEL*

* *RHEL UBI*

* *OpenMandriva*

* *Rocky Linux*

* *Alma Linux*

* *Gentoo* (**Gentoo is experimental and unsupported. We make no
  guarantee that it will work at all and the core maintainers will
  generally not fix gentoo specific issues**)

* *None* (**Requires the user to provide a pre-built rootfs**)

In theory, any distribution may be used on the host for building images
containing any other distribution, as long as the necessary tools are
available.
Specifically,
any distribution that packages `apt` may be used to build *Debian* or *Ubuntu* images.
Any distribution that packages `dnf` may be used to build images for any of the rpm-based distributions.
Any distro that packages `pacman` may be used to build *Arch Linux* images.
Any distribution that packages `zypper` may be used to build *openSUSE* images.
Other distributions and build automation tools for embedded Linux
systems such as Buildroot, OpenEmbedded and Yocto Project may be used by
selecting the `custom` distribution, and populating the rootfs via a
combination of base trees, skeleton trees, and prepare scripts.

Currently, *Fedora Linux* packages all relevant tools as of Fedora 28.

Note that when not using a custom mirror, `RHEL` images can only be
built from a host system with a `RHEL` subscription (established using
e.g. `subscription-manager`).

# Execution Flow

Execution flow for `mkosi build`. Default values/calls are shown in parentheses.
When building with `--incremental` mkosi creates a cache of the distribution
installation if not already existing and replaces the distribution installation
in consecutive runs with data from the cached one.

1. Parse CLI options
2. Parse configuration files
3. If we're not running as root, unshare the user namespace and map the
   subuid range configured in `/etc/subuid` and `/etc/subgid` into it.
4. Unshare the mount namespace
5. Remount the following directories read-only if they exist:
   - `/usr`
   - `/etc`
   - `/opt`
   - `/srv`
   - `/boot`
   - `/efi`
   - `/media`
   - `/mnt`

Then, for each image, we execute the following steps:

6. Copy package manager trees into the workspace
7. Copy base trees (`--base-tree=`) into the image
8. Copy skeleton trees (`mkosi.skeleton`) into image
9. Install distribution and packages into image or use cache tree if
   available
10. Run prepare scripts on image with the `final` argument (`mkosi.prepare`)
11. Install build packages in overlay if any build scripts are configured
12. Run prepare scripts on overlay with the `build` argument if any build
    scripts are configured (`mkosi.prepare`)
13. Cache the image if configured (`--incremental`)
14. Run build scripts on image + overlay if any build scripts are configured (`mkosi.build`)
15. Finalize the build if the output format `none` is configured
16. Copy the build scripts outputs into the image
17. Copy the extra trees into the image (`mkosi.extra`)
18. Run post-install scripts (`mkosi.postinst`)
19. Write config files required for `Ssh=`, `Autologin=` and `MakeInitrd=`
20. Install systemd-boot and configure secure boot if configured (`--secure-boot`)
21. Run `systemd-sysusers`
22. Run `systemctl preset-all`
23. Run `depmod`
24. Run `systemd-firstboot`
25. Run `systemd-hwdb`
26. Remove packages and files (`RemovePackages=`, `RemoveFiles=`)
27. Run SELinux relabel is a SELinux policy is installed
28. Run finalize scripts (`mkosi.finalize`)
29. Generate unified kernel image if configured to do so
30. Generate final output format

# Scripts

To allow for image customization that cannot be implemented using
mkosi's builtin features, mkosi supports running scripts at various
points during the image build process that can customize the image as
needed. Scripts are executed on the host system as root (either real
root or root within the user namespace that mkosi created when running
unprivileged) with a customized environment to simplify modifying the
image. For each script, the configured build sources (`BuildSources=`)
are mounted into the current working directory before running the script
in the current working directory. `$SRCDIR` is set to point to the
current working directory. The following scripts are supported:

* If **`mkosi.prepare`** (`PrepareScripts=`) exists, it is first called
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

* If **`mkosi.build`** (`BuildScripts=`) exists, it is executed with the
  build overlay mounted on top of the image's root directory. When
  running the build script, `$DESTDIR` points to a directory where the
  script should place any files generated it would like to end up in the
  image. Note that `make`/`automake`/`meson` based build systems
  generally honor `$DESTDIR`, thus making it very natural to build
  *source* trees from the build script. After running the build script,
  the contents of `$DESTDIR` are copied into the image.

* If **`mkosi.postinst`** (`PostInstallationScripts=`) exists, it is
  executed after the (optional) build tree and extra trees have been
  installed. This script may be used to alter the images without any
  restrictions, after all software packages and built sources have been
  installed.

* If **`mkosi.finalize`** (`FinalizeScripts=`) exists, it is executed as
  the last step of preparing an image.

If a script uses the `.chroot` extension, mkosi will chroot into the
image using `mkosi-chroot` (see below) before executing the script. For
example, if `mkosi.postinst.chroot` exists, mkosi will chroot into the
image and execute it as the post-installation script.

Scripts executed by mkosi receive the following environment variables:

* `$ARCHITECTURE` contains the architecture from the `Architecture=`
  setting. If `Architecture=` is not set, it will contain the native
  architecture of the host machine. See the documentation of
  `Architecture=` for possible values for this variable.

* `$CHROOT_SCRIPT` contains the path to the running script relative to
  the image root directory. The primary usecase for this variable is in
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
  by a build script may be placed. This variable is only set when
  executing a build script. `$CHROOT_DESTDIR` contains the value that
  `$DESTDIR` will have after invoking `mkosi-chroot`.

* `$OUTPUTDIR` points to the staging directory used to store build
  artifacts generated during the build. `$CHROOT_OUTPUTDIR` contains the
  value that `$OUTPUTDIR` will have after invoking `mkosi-chroot`.

* `$BUILDROOT` is the root directory of the image being built,
  optionally with the build overlay mounted on top depending on the
  script that's being executed.

* `$WITH_DOCS` is either `0` or `1` depending on whether a build
  without or with installed documentation was requested
  (`WithDocs=yes`). A build script should suppress installation of
  any package documentation to `$DESTDIR` in case `$WITH_DOCS` is set
  to `0`.

* `$WITH_TESTS` is either `0` or `1` depending on whether a build
  without or with running the test suite was requested
  (`WithTests=no`). A build script should avoid running any unit or
  integration tests in case `$WITH_TESTS` is `0`.

* `$WITH_NETWORK` is either `0` or `1` depending on whether a build
  without or with networking is being executed (`WithNetwork=no`).
  A build script should avoid any network communication in case
  `$WITH_NETWORK` is `0`.

* `$SOURCE_DATE_EPOCH` is defined if requested (`SourceDateEpoch=TIMESTAMP`,
  `Environment=SOURCE_DATE_EPOCH=TIMESTAMP` or the host environment variable
  `$SOURCE_DATE_EPOCH`). This is useful to make builds reproducible. See
  [SOURCE_DATE_EPOCH](https://reproducible-builds.org/specs/source-date-epoch/)
  for more information.

* `$MKOSI_UID` and `$MKOSI_GID` are the respectively the uid, gid of the
  user that invoked mkosi, potentially translated to a uid in the user
  namespace that mkosi is running in. These can be used in combination
  with `setpriv` to run commands as the user that invoked mkosi (e.g.
  `setpriv --reuid=$MKOSI_UID --regid=$MKOSI_GID --clear-groups <command>`)

Consult this table for which script receives which environment variables:

| Variable            | `mkosi.prepare` | `mkosi.build` | `mkosi.postinst` | `mkosi.finalize` |
|---------------------|-----------------|---------------|------------------|------------------|
| `$CHROOT_SCRIPT`    | X               | X             | X                | X                |
| `$SRCDIR`           | X               | X             | X                | X                |
| `CHROOT_SRCDIR`     | X               | X             | X                | X                |
| `$BUILDDIR`         |                 | X             |                  |                  |
| `CHROOT_BUILDDIR`   |                 | X             |                  |                  |
| `DESTDIR`           |                 | X             |                  |                  |
| `CHROOT_DESTDIR`    |                 | X             |                  |                  |
| `$OUTPUTDIR`        |                 | X             | X                | X                |
| `CHROOT_OUTPUTDIR`  |                 | X             | X                | X                |
| `$BUILDROOT`        | X               | X             | X                | X                |
| `WITH_DOCS`         | X               | X             |                  |                  |
| `WITH_TESTS`        | X               | X             |                  |                  |
| `WITH_NETWORK`      | X               | X             |                  |                  |
| `SOURCE_DATE_EPOCH` | X               | X             | X                | X                |
| `MKOSI_UID`         | X               | X             | X                | X                |
| `MKOSI_GID`         | X               | X             | X                | X                |


Additionally, when a script is executed, a few scripts are made
available via `$PATH` to simplify common usecases.

* `mkosi-chroot`: This script will chroot into the image and execute the
  given command. On top of chrooting into the image, it will also mount
  various files and directories (`$SRCDIR`, `$DESTDIR`, `$BUILDDIR`,
  `$OUTPUTDIR`, `$CHROOT_SCRIPT`) into the image and modify the
  corresponding environment variables to point to the locations inside
  the image. It will also mount APIVFS filesystems (`/proc`, `/dev`,
  ...) to make sure scripts and tools executed inside the chroot work
  properly. It also propagates `/etc/resolv.conf` from the host into the
  chroot if requested so that DNS resolution works inside the chroot.
  After the mkosi-chroot command exits, various mount points are cleaned
  up.

  For example, to invoke `ls` inside of the image, use the following

  ```sh
  mkosi-chroot ls ...
  ```

  To execute the entire script inside the image, add a ".chroot" suffix
  to the name (`mkosi.build.chroot` instead of `mkosi.build`, etc.).

* For all of the supported package managers except portage (`dnf`,
  `rpm`, `apt`, `pacman`, `zypper`), scripts of the same name are put
  into `$PATH` that make sure these commands operate on the image's root
  directory with the configuration supplied by the user instead of on
  the host system. This means that from a script, you can do e.g. `dnf
  install vim` to install vim into the image.

* `mkosi-as-caller`: This script uses `setpriv` to switch from
  the user `root` in the user namespace used for various build steps
  back to the original user that called mkosi. This is useful when
  we want to invoke build steps which will write to `$BUILDDIR` and
  we want to have the files owned by the calling user.

  For example, a complete `mkosi.build` script might be the following:

  ```sh
  set -ex

  mkosi-as-caller meson setup "$BUILDDIR/build" "$SRCDIR"
  mkosi-as-caller meson compile -C "$BUILDDIR/build"
  meson install -C "$BUILDDIR/build" --no-rebuild
  ```

* `git` is automatically invoked with `safe.directory=*` to avoid
  permissions errors when running as the root user in a user namespace.

* `useradd` is automatically invoked with `--root=$BUILDROOT` when
  executed outside of the image.

When scripts are executed, any directories that are still writable are
also made read-only (`/home`, `/var`, `/root`, ...) and only the minimal
set of directories that need to be writable remain writable. This is to
ensure that scripts can't mess with the host system when mkosi is
running as root.

Note that when executing scripts, all source directories are made
ephemeral which means all changes made to source directories while
running scripts are thrown away after the scripts finish executing. Use
the output, build or cache directories if you need to persist data
between builds.

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
  the build commands in the `mkosi.build` scripts support it. Specifically, this directory will be mounted
  into the build container, and the `$BUILDDIR` environment variable will be set to it when the build scripts
  are invoked. A build script may then use this directory as build directory, for automake-style or
  ninja-style out-of-tree builds. This speeds up builds considerably, in particular when `mkosi` is used in
  incremental mode (`-i`): not only the image and build overlay, but also the build tree is reused between
  subsequent invocations. Note that if this directory does not exist the `$BUILDDIR` environment variable is
  not set, and it is up to the build scripts to decide whether to do in in-tree or an out-of-tree build, and
  which build directory to use.

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

* The **`mkosi.repart/`** directory is used as the source for
  systemd-repart partition definition files which are passed to
  systemd-repart when building a disk image. If it does not exist and
  the `RepartDirectories=` setting is not configured, mkosi will default
  to the following partition definition files:

  `00-esp.conf` (if we're building a bootable image):

  ```
  [Partition]
  Type=esp
  Format=vfat
  CopyFiles=/boot:/
  CopyFiles=/efi:/
  SizeMinBytes=512M
  SizeMaxBytes=512M
  ```

  `05-bios.conf` (if we're building a BIOS bootable image):

  ```
  [Partition]
  # UUID of the grub BIOS boot partition which grubs needs on GPT to
  # embed itself into.
  Type=21686148-6449-6e6f-744e-656564454649
  SizeMinBytes=1M
  SizeMaxBytes=1M
  ```

  `10-root.conf`:

  ```
  [Partition]
  Type=root
  Format=<distribution-default-filesystem>
  CopyFiles=/
  Minimize=guess
  ```

  Note that if either `mkosi.repart/` is found or `RepartDirectories=`
  is used, we will not use any of the default partition definitions.

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
   of a `mkosi.build` build script.

The package cache and incremental mode are unconditionally useful. The
final cache only apply to uses of `mkosi` with a source tree and build
script. When all three are enabled together turn-around times for
complete image builds are minimal, as only changed source files need to
be recompiled.

# Building multiple images

If the `mkosi.images/` directory exists, mkosi will load individual
image configurations from it and build each of them. Image
configurations can be either directories containing mkosi configuration
files or regular files with the `.conf` extension.

When image configurations are found in `mkosi.images/`, mkosi will build
the configured images and all of their dependencies (or all of them if
no images were explicitly configured using `Images=`). To add
dependencies between images, the `Dependencies=` setting can be used.

When images are defined, mkosi will first read the global configuration
(configuration outside of the `mkosi.images/` directory), followed by
the image specific configuration. This means that global configuration
takes precedence over image specific configuration.

Images can refer to outputs of images they depend on. Specifically,
for the following options, mkosi will only check whether the inputs
exist just before building the image:

- `BaseTrees=`
- `PackageManagerTrees=`
- `SkeletonTrees=`
- `ExtraTrees=`
- `ToolsTree=`
- `Initrds=`

To refer to outputs of a image's dependencies, simply configure any of
these options with a relative path to the output to use in the output
directory of the dependency. Or use the `%O` specifier to refer to the
output directory.

A good example on how to build multiple images can be found in the
[systemd](https://github.com/systemd/systemd/tree/main/mkosi.presets)
repository.

# ENVIRONMENT VARIABLES

* `$MKOSI_LESS` overrides options for `less` when it is invoked by
  `mkosi` to page output.

* `$MKOSI_DNF` can be used to override the executable used as `dnf`.
  This is particularly useful to select between `dnf` and `dnf5`.

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
    exec mkosi-chroot "$CHROOT_SCRIPT" "$@"
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

It is also possible to do a *direct kernel boot* into a boot loader,
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

mkosi currently requires systemd 254 to build bootable disk images.

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

# Frequently Asked Questions (FAQ)

- Why does `mkosi qemu` with KVM not work on Debian/Ubuntu?

While other distributions are OK with allowing access to `/dev/kvm`, on
Debian/Ubuntu this is only allowed for users in the `kvm` group. Because
mkosi unshares a user namespace when running unprivileged, even if the
calling user was in the kvm group, when mkosi unshares the user
namespace to run unprivileged, it loses access to the `kvm` group and by
the time we start `qemu` we don't have access to `/dev/kvm` anymore. As
a workaround, you can change the permissions of the device nodes to
`0666` which is sufficient to make KVM work unprivileged. To persist
these settings across reboots, copy
`/usr/lib/tmpfiles.d/static-nodes-permissions.conf` to
`/etc/tmpfiles.d/static-nodes-permissions.conf` and change the mode of
`/dev/kvm` from `0660` to `0666`.

# REFERENCES
* [Primary mkosi git repository on GitHub](https://github.com/systemd/mkosi/)
* [mkosi — A Tool for Generating OS Images](https://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html) introductory blog post by Lennart Poettering
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN

# SEE ALSO
`systemd-nspawn(1)`, `dnf(8)`
