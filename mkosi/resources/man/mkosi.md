% mkosi(1)
%
%

# NAME

mkosi — Build Bespoke OS Images

# SYNOPSIS

`mkosi [options…] summary`

`mkosi [options…] cat-config`

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

`mkosi [options…] dependencies`

`mkosi [options…] help`

# DESCRIPTION

`mkosi` is a tool for easily building customized OS images. It's a
fancy wrapper around `dnf --installroot`, `apt`, `pacman` and `zypper`
that may generate disk images with a number of bells and whistles.

## Command Line Verbs

The following command line verbs are known:

`summary`
:   Show a human-readable summary of all options used for building the images.
    This will parse the command line and configuration files, but only print
    what it is configured for and not actually build or run anything.

`cat-config`
:   Output the names and contents of all loaded configuration files. `mkosi`
    loads a bunch of files from different locations and this command makes
    it easier to figure out what is configured where.

`build`
:   Build the image based on the settings passed on the command line and in the
    configuration files. This command is the default if no verb is specified.
    Any command line arguments specified after the verb will be passed directly
    to the build script, if one is defined.

`shell`
:   This builds the image if it is not built yet, and then invokes
    `systemd-nspawn` to acquire an interactive shell prompt in it. An optional
    command line may be specified after the `shell` verb, to be invoked in place
    of the shell in the container. Use `-f` in order to rebuild the image
    unconditionally before acquiring the shell, see below. This command must be
    executed as `root`.

`boot`
:   Similar to `shell`, but boots the image using `systemd-nspawn`. An
    optional command line may be specified after the `boot` verb, which
    can contain extra nspawn options as well as arguments which are passed
    as the *kernel command line* to the init system in the image.

`qemu`
:   Similar to `boot`, but uses the configured virtual machine monitor (by
    default `qemu`) to boot up the image, i.e. instead of container
    virtualization, virtual machine virtualization is used. How extra
    command line arguments are interpreted depends on the configured
    virtual machine monitor. See `VirtualMachineMonitor=` for more
    information.

`ssh`
:   When the image is built with the `Ssh=yes` option, this command
    connects to a booted virtual machine (`qemu`) via SSH. Make sure to
    run `mkosi ssh` with the same config as `mkosi build` so that it has
    the necessary information available to connect to the running virtual
    machine via SSH. Specifically, the SSH private key from the `SshKey=`
    setting is used to connect to the virtual machine. Use `mkosi genkey`
    to automatically generate a key and certificate that will be picked up
    by mkosi. Any arguments passed after the `ssh` verb are passed as
    arguments to the `ssh` invocation. To connect to a container, use
    `machinectl login` or `machinectl shell`.

    The `Machine=` option can be used to give the machine a custom
    hostname when booting it which can later be used to ssh into the image
    (e.g. `mkosi --machine=mymachine qemu` followed by
    `mkosi --machine=mymachine ssh`).

`journalctl`
:   Uses `journalctl` to inspect the journal inside the image.
    Any arguments specified after the `journalctl` verb are appended to the
    `journalctl` invocation.

    If `ForwardJournal=` is specified, this verb will operate on the
    forwarded journal instead of the journal inside the image.

`coredumpctl`
:   Uses `coredumpctl` to look for coredumps inside the image.
    Any arguments specified after the `coredumpctl` verb are appended to the
    `coredumpctl` invocation.

    If `ForwardJournal=` is specified, this verb will operate on the
    forwarded journal instead of the image. Note that this requires
    configuring systemd-coredump to store coredumps in the journal.

`clean`
:   Remove build artifacts generated on a previous build. If combined
    with `-f`, also removes incremental build cache images. If `-f` is
    specified twice, also removes any package cache.

`serve`
:   This builds the image if it is not built yet, and then serves the
    output directory (i.e. usually `mkosi.output/`, see below) via a
    small embedded HTTP server, listening on port 8081. Combine with
    `-f` in order to rebuild the image unconditionally before serving
    it. This command is useful for testing network based acquisition of
    OS images, for example via `machinectl pull-raw …` and `machinectl
    pull-tar …`.

`burn <device>`
:   This builds the image if it is not built yet, and then writes it to the
    specified block device. The partition contents are written as-is, but the GPT
    partition table is corrected to match sector and disk size of the specified
    medium.

`bump`
:   Bumps the image version from `mkosi.version` and writes the resulting
    version string to `mkosi.version`. This is useful for implementing a
    simple versioning scheme: each time this verb is called the version is
    bumped in preparation for the subsequent build. Note that
    `--auto-bump`/`-B` may be used to automatically bump the version
    after each successful build.

`genkey`
:   Generate a pair of SecureBoot keys for usage with the
    `SecureBootKey=`/`--secure-boot-key=` and
    `SecureBootCertificate=`/`--secure-boot-certificate=` options.

`documentation`
:   Show mkosi's documentation. By default this verb will try several ways
    to output the documentation, but a specific option can be chosen with
    the `--doc-format` option. Distro packagers are encouraged to add a
    file `mkosi.1` into the `mkosi/resources` directory of the Python
    package, if it is missing, as well as to install it in the appropriate
    search path for man pages. The man page can be generated from the
    markdown file `mkosi/resources/man/mkosi.md` e.g via
    `pandoc -t man -s -o mkosi.1 mkosi.md`.

`dependencies`
:   Output the list of packages required by mkosi to build and boot
    images.

    This list can be piped directly to a package manager to install the
    packages. For example, if the host system uses the dnf package
    manager, the packages could be installed as follows:

    ```sh
    mkosi dependencies | xargs -d '\n' dnf install
    ```

`help`
:   This verb is equivalent to the `--help` switch documented below: it
    shows a brief usage explanation.

## Commandline-only Options

Those settings cannot be configured in the configuration files.

`--force`, `-f`
:   Replace the output file if it already exists, when building an
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
:   Takes a path to a directory. `mkosi` switches to this directory before
    doing anything. Note that the various configuration files are searched
    for in this directory, hence using this option is an effective way to
    build a project located in a specific directory.

`--debug=`
:   Enable additional debugging output.

`--debug-shell`
:   When executing a command in the image fails, mkosi will start an interactive
    shell in the image allowing further debugging.

`--debug-workspace=`
:   When an error occurs, the workspace directory will not be deleted.

`--version`
:   Show package version.

`--help`, `-h`
:   Show brief usage information.

`--genkey-common-name=`
:   Common name to be used when generating keys via mkosi's `genkey` command. Defaults to `mkosi of %u`, where
    `%u` expands to the username of the user invoking mkosi.

`--genkey-valid-days=`
:   Number of days that the keys should remain valid when generating keys via mkosi's `genkey` command.
    Defaults to two years (730 days).

`--auto-bump=`, `-B`
:   If specified, after each successful build the version is bumped in a
    fashion equivalent to the `bump` verb, in preparation for the next
    build. This is useful for simple, linear version management: each
    build in a series will have a version number one higher then the
    previous one.

`--doc-format`
:   The format to show the documentation in. Supports the values `markdown`,
    `man`, `pandoc`, `system` and `auto`. In the case of `markdown` the
    documentation is shown in the original Markdown format. `man` shows the
    documentation in man page format, if it is available. `pandoc` will generate
    the man page format on the fly, if `pandoc` is available. `system` will show
    the system-wide man page for mkosi, which may or may not correspond to the
    version you are using, depending on how you installed mkosi. `auto`, which is
    the default, will try all methods in the order `man`, `pandoc`, `markdown`,
    `system`.

`--json`
:   Show the summary output as JSON-SEQ.

`--wipe-build-dir`, `-w`
:   Wipe the build directory if one is configured before building the image.

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

* The command line arguments are parsed.
* `mkosi.local.conf` is parsed if it exists. This file should be in
  `.gitignore` (or equivalent) and is intended for local configuration.
* Any default paths (depending on the option) are configured if the
  corresponding path exists.
* `mkosi.conf` is parsed if it exists in the directory configured with
  `--directory=` or the current working directory if `--directory=` is
  not used.
* If a profile is defined, its configuration is parsed from the
  `mkosi.profiles/` directory.
* `mkosi.conf.d/` is parsed in the same directory if it exists. Each
  directory and each file with the `.conf` extension in `mkosi.conf.d/`
  is parsed. Any directory in `mkosi.conf.d` is parsed as if it were
  a regular top level directory.
* Subimages are parsed from the `mkosi.images` directory if it exists.

Note that settings configured via the command line always override
settings configured via configuration files. If the same setting is
configured more than once via configuration files, later assignments
override earlier assignments except for settings that take a collection
of values. Also, settings read from `mkosi.local.conf` will override
settings from configuration files that are parsed later, but not settings
specified on the CLI.

For settings that take a single value, the empty assignment (`SomeSetting=` or
`--some-setting=`) can be used to override a previous setting and reset to the
default.

Settings that take a collection of values are merged by appending the
new values to the previously configured values. Assigning the empty
string to such a setting removes all previously assigned values, and
overrides any configured default values as well. The values specified
on the CLI are appended after all the values from configuration files.

To conditionally include configuration files, the `[Match]` section can
be used. A `[Match]` section consists of individual conditions.
Conditions can use a pipe symbol (`|`) after the equals sign (`…=|…`),
which causes the condition to become a triggering condition. The config
file will be included if the logical AND of all non-triggering
conditions and the logical OR of all triggering conditions is satisfied.
To negate the result of a condition, prefix the argument with an
exclamation mark. If an argument is prefixed with the pipe symbol and an
exclamation mark, the pipe symbol must be passed first, and the
exclamation second.

Note that `[Match]` conditions compare against the current values of
specific settings, and do not take into account changes made to the
setting in configuration files that have not been parsed yet (settings
specified on the CLI are taken into account). Also note that matching
against a setting and then changing its value afterwards in a different
config file may lead to unexpected results.

The `[Match]` section of a `mkosi.conf` file in a directory applies to
the entire directory. If the conditions are not satisfied, the entire
directory is skipped. The `[Match]` sections of files in `mkosi.conf.d/`
and `mkosi.local.conf` only apply to the file itself.

If there are multiple `[Match]` sections in the same configuration file,
each of them has to be satisfied in order for the configuration file to
be included. Specifically, triggering conditions only apply to the
current `[Match]` section and are reset between multiple `[Match]`
sections. As an example, the following will only match if the output
format is one of `disk` or `directory` and the architecture is one of
`x86-64` or `arm64`:

```ini
[Match]
Format=|disk
Format=|directory

[Match]
Architecture=|x86-64
Architecture=|arm64
```

The `[TriggerMatch]` section can be used to indicate triggering match
sections. These are identical to triggering conditions except they apply
to the entire match section instead of just a single condition. As an
example, the following will match if the distribution is `debian` and
the release is `bookworm` or if the distribution is `ubuntu` and the
release is `focal`.

```ini
[TriggerMatch]
Distribution=debian
Release=bookworm

[TriggerMatch]
Distribution=ubuntu
Release=focal
```

The semantics of conditions in `[TriggerMatch]` sections is the same as
in `[Match]`, i.e. all normal conditions are joined by a logical AND and
all triggering conditions are joined by a logical OR. When mixing
`[Match]` and `[TriggerMatch]` sections, a match is achieved when all
`[Match]` sections match and at least one `[TriggerMatch]` section
matches. No match sections are valued as true. Logically this means:

```
(⋀ᵢ Matchᵢ) ∧ (⋁ᵢ TriggerMatchᵢ)
```

Command line options that take no argument are shown without `=` in
their long version. In the config files, they should be specified with a
boolean argument: either `1`, `yes`, or `true` to enable, or `0`, `no`,
`false` to disable.

### [Distribution] Section

`Distribution=`, `--distribution=`, `-d`
:   The distribution to install in the image. Takes one of the following
    arguments: `fedora`, `debian`, `kali`, `ubuntu`, `arch`, `opensuse`,
    `mageia`, `centos`, `rhel`, `rhel-ubi`, `openmandriva`, `rocky`, `alma`,
    `azure` or `custom`. If not specified, defaults to the distribution of
    the host or `custom` if the distribution of the host is not a supported
    distribution.

`Release=`, `--release=`, `-r`
:   The release of the distribution to install in the image. The precise
    syntax of the argument this takes depends on the distribution used,
    and is either a numeric string (in case of Fedora Linux, CentOS, …,
    e.g. `29`), or a distribution version name (in case of Debian, Kali,
    Ubuntu, …, e.g. `artful`). Defaults to a recent version of the chosen
    distribution, or the version of the distribution running on the host
    if it matches the configured distribution.

`Architecture=`, `--architecture=`
:   The architecture to build the image for. The architectures that are
    actually supported depends on the distribution used and whether a
    bootable image is requested or not. When building for a foreign
    architecture, you'll also need to install and register a user mode
    emulator for that architecture.

    One of the following architectures can be specified per image built:
    `alpha`, `arc`, `arm`, `arm64`, `ia64`, `loongarch64`, `mips64-le`,
    `mips-le`, `parisc`, `ppc`, `ppc64`, `ppc64-le`, `riscv32`, `riscv64`,
    `s390`, `s390x`, `tilegx`, `x86`, `x86-64`.

`Mirror=`, `--mirror=`, `-m`
:   The mirror to use for downloading the distribution packages. Expects
    a mirror URL as argument. If not provided, the default mirror for the
    distribution is used.

    The default mirrors for each distribution are as follows (unless
    specified, the same mirror is used for all architectures):

    |                | x86-64                            | aarch64                        |
    |----------------|-----------------------------------|--------------------------------|
    | `debian`       | http://deb.debian.org/debian      |                                |
    | `arch`         | https://geo.mirror.pkgbuild.com   | http://mirror.archlinuxarm.org |
    | `opensuse`     | http://download.opensuse.org      |                                |
    | `kali`         | http://http.kali.org/kali         |                                |
    | `ubuntu`       | http://archive.ubuntu.com         | http://ports.ubuntu.com        |
    | `centos`       | https://mirrors.centos.org        |                                |
    | `rocky`        | https://mirrors.rockylinux.org    |                                |
    | `alma`         | https://mirrors.almalinux.org     |                                |
    | `fedora`       | https://mirrors.fedoraproject.org |                                |
    | `rhel-ubi`     | https://cdn-ubi.redhat.com        |                                |
    | `mageia`       | https://www.mageia.org            |                                |
    | `openmandriva` | http://mirrors.openmandriva.org   |                                |
    | `azure`        | https://packages.microsoft.com/   |                                |

`LocalMirror=`, `--local-mirror=`
:   The mirror will be used as a local, plain and direct mirror instead
    of using it as a prefix for the full set of repositories normally supported
    by distributions. Useful for fully offline builds with a single repository.
    Supported on deb/rpm/arch based distributions. Overrides `--mirror=` but only
    for the local mkosi build, it will not be configured inside the final image,
    `--mirror=` (or the default repository) will be configured inside the final
    image instead.

`RepositoryKeyCheck=`, `--repository-key-check=`
:   Controls signature/key checks when using repositories, enabled by default.
    Useful to disable checks when combined with `--local-mirror=` and using only
    a repository from a local filesystem.

`RepositoryKeyFetch=`, `--repository-key-fetch=`
:   Controls whether mkosi will fetch distribution GPG keys remotely. Enabled by
    default on Ubuntu when not using a tools tree, disabled by default on all
    other distributions. When disabled, the distribution GPG keys for the target distribution
    have to be installed locally on the host system alongside the package manager for
    that distribution.

    This setting is only implemented for distributions using dnf or zypper as their
    package manager. For other distributions the distribution GPG keys are always looked
    up locally regardless of the value of this setting. To make the distribution GPG keys
    for distributions available without enabling this setting, the corresponding package
    has to be installed on the host. This is usually one of `archlinux-keyring`,
    `debian-keyring`, `kali-archive-keyring`, `ubuntu-keyring` or `distribution-gpg-keys`
    (for rpm-based distributions).

`Repositories=`, `--repositories=`
:   Enable package repositories that are disabled by default. This can be used to enable the EPEL repos for
    CentOS or different components of the Debian/Kali/Ubuntu repositories.

`CacheOnly=`, `--cache-only=`
:   Takes one of `auto`, `metadata`, `always` or `never`. Defaults to
    `auto`. If `always`, the package manager is instructed not to contact
    the network. This provides a minimal level of reproducibility, as long
    as the package cache is already fully populated. If set to `metadata`,
    the package manager can still download packages, but we won't sync the
    repository metadata. If set to `auto`, the repository metadata is
    synced unless we have a cached image (see `Incremental=`) and packages
    can be downloaded during the build. If set to `never`, repository
    metadata is always synced and and packages can be downloaded during
    the build.

`SandboxTrees=`, `--sandbox-tree=`
:   Takes a comma separated list of colon separated path pairs. The first
    path of each pair refers to a directory to copy into the mkosi
    sandbox before executing a tool. If the `mkosi.sandbox/` directory
    is found in the local directory it is used for this purpose with the
    root directory as target (also see the **Files** section below).

    `mkosi` will look for the package manager configuration and related
    files in the configured sandbox trees. Unless specified otherwise,
    it will use the configuration files from their canonical locations
    in `/usr` or `/etc` in the sandbox trees. For example, it  will look
    for `/etc/dnf/dnf.conf` in the sandbox trees  if `dnf` is used to
    install packages.

### [Output] Section

`Format=`, `--format=`, `-t`
:   The image format type to generate. One of `directory` (for generating
    an OS image directly in a local directory), `tar` (similar, but a
    tarball of the OS image is generated), `cpio` (similar, but a cpio
    archive is generated), `disk` (a block device OS image with a GPT
    partition table), `uki` (a unified kernel image with the OS image in
    the `.initrd` PE section), `esp` (`uki` but wrapped in a disk image
    with only an ESP partition), `oci` (a directory compatible with the
    OCI image specification), `sysext`, `confext`, `portable` or `none`
    (the OS image is solely intended as a build image to produce another
    artifact).

    If the `disk` output format is used, the disk image is generated using
    `systemd-repart`. The repart partition definition files to use can be
    configured using the `RepartDirectories=` setting or via
    `mkosi.repart/`. When verity partitions are configured using
    systemd-repart's `Verity=` setting, mkosi will automatically parse the
    verity hash partition's roothash from systemd-repart's JSON output and
    include it in the kernel command line of every unified kernel image
    built by mkosi.

    If the `none` output format is used, the outputs from a previous
    build are not removed, but clean scripts (see `CleanScripts=`) are
    still executed. This allows rerunning a build script
    (see `BuildScripts=`) without removing the results of a previous
    build.

`ManifestFormat=`, `--manifest-format=`
:   The manifest format type or types to generate. A comma-delimited
    list consisting of `json` (the standard JSON output format that
    describes the packages installed), `changelog` (a human-readable
    text format designed for diffing). By default no manifest is
    generated.

`Output=`, `--output=`, `-o`
:   Name to use for the generated output image file or directory. Defaults
    to `image` or, if `ImageId=` is specified, it is used as the default
    output name, optionally suffixed with the version set with
    `ImageVersion=` or if a specific image is built from `mkosi.images`, the
    name of the image is preferred over `ImageId`. Note that this option does
    not allow configuring the output directory, use `OutputDirectory=` for that.

    Note that this only specifies the output prefix, depending on the
    specific output format, compression and image version used, the full
    output name might be `image_7.8.raw.xz`.

`CompressOutput=`, `--compress-output=`
:   Configure compression for the resulting image or archive. The argument can be
    either a boolean or a compression algorithm (`xz`, `zstd`). `zstd`
    compression is used by default, except CentOS and derivatives up to version
    8, which default to `xz`, and OCI images, which default to `gzip`.
    Note that when applied to block device image types,
    compression means the image cannot be started directly but needs to be
    decompressed first. This also means that the `shell`, `boot`, `qemu` verbs
    are not available when this option is used. Implied for `tar`, `cpio`, `uki`,
    `esp`, and `oci`.

`CompressLevel=`, `--compress-level=`
:   Configure the compression level to use. Takes an integer. The possible
    values depend on the compression being used.

`OutputDirectory=`, `--output-dir=`, `-O`
:   Path to a directory where to place all generated artifacts. If this is
    not specified and the directory `mkosi.output/` exists in the local
    directory, it is automatically used for this purpose.

`WorkspaceDirectory=`, `--workspace-dir=`
:   Path to a directory where to store data required temporarily while
    building the image. This directory should have enough space to store
    the full OS image, though in most modes the actually used disk space
    is smaller. If not specified, a subdirectory of `$XDG_CACHE_HOME` (if
    set), `$HOME/.cache` (if set) or `/var/tmp` is used.

    The data in this directory is removed automatically after each
    build. It's safe to manually remove the contents of this directory
    should an `mkosi` invocation be aborted abnormally (for example, due
    to reboot/power failure).

`CacheDirectory=`, `--cache-dir=`
:   Takes a path to a directory to use as the incremental cache directory
    for the incremental images produced when the `Incremental=` option is
    enabled. If this option is not used, but a `mkosi.cache/` directory is
    found in the local directory it is automatically used for this
    purpose.

`PackageCacheDirectory=`, `--package-cache-dir`
:   Takes a path to a directory to use as the package cache directory for
    the distribution package manager used. If unset, a suitable directory
    in the user's home directory or system is used.

`BuildDirectory=`, `--build-dir=`
:   Takes a path to a directory to use as the build directory for build
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
:   Configure the image version. This accepts any string, but it is
    recommended to specify a series of dot separated components. The
    version may also be configured by reading a `mkosi.version` file (in
    which case it may be conveniently managed via the `bump` verb or the
    `--auto-bump` option) or by reading stdout if it is executable (see
    the **Scripts** section below). When specified the image version is
    included in the default output file name, i.e. instead of `image.raw`
    the default will be `image_0.1.raw` for version `0.1` of the image,
    and similar. The version is also passed via the `$IMAGE_VERSION` to
    any build scripts invoked (which may be useful to patch it into
    `/usr/lib/os-release` or similar, in particular the `IMAGE_VERSION=`
    field of it).

`ImageId=`, `--image-id=`
:   Configure the image identifier. This accepts a freeform string that
    shall be used to identify the image with. If set the default output
    file will be named after it (possibly suffixed with the version). The
    identifier is also passed via the `$IMAGE_ID` to any build scripts
    invoked. The image ID is automatically added to `/usr/lib/os-release`.

`SplitArtifacts=`, `--split-artifacts`
:   If specified and building a disk image, pass `--split=yes` to systemd-repart
    to have it write out split partition files for each configured partition.
    Read the [man](https://www.freedesktop.org/software/systemd/man/systemd-repart.html#--split=BOOL)
    page for more information. This is useful in A/B update scenarios where
    an existing disk image shall be augmented with a new version of a
    root or `/usr` partition along with its Verity partition and unified
    kernel.

`RepartDirectories=`, `--repart-dir=`
:   Paths to directories containing systemd-repart partition definition
    files that are used when mkosi invokes systemd-repart when building a
    disk image. If `mkosi.repart/` exists in the local directory, it will
    be used for this purpose as well. Note that mkosi invokes repart with
    `--root=` set to the root of the image root, so any `CopyFiles=`
    source paths in partition definition files will be relative to the
    image root directory.

`SectorSize=`, `--sector-size=`
:   Override the default sector size that systemd-repart uses when building a disk
    image.

`RepartOffline=`, `--repart-offline=`
:   Specifies whether to build disk images using loopback devices. Enabled
    by default. When enabled, `systemd-repart` will not use loopback
    devices to build disk images. When disabled, `systemd-repart` will
    always use loopback devices to build disk images.

    Note that when using `RepartOffline=no` mkosi cannot run unprivileged and
    the image build has to be done as the root user outside of any
    containers and with loopback devices available on the host system.

    There are currently two known scenarios where `RepartOffline=no` has to be
    used. The first is when using `Subvolumes=` in a repart partition
    definition file, as subvolumes cannot be created without using
    loopback devices. The second is when creating a system with SELinux
    and an XFS root partition. Because `mkfs.xfs` does not support
    populating an XFS filesystem with extended attributes, loopback
    devices have to be used to ensure the SELinux extended attributes end
    up in the generated XFS filesystem.

`Overlay=`, `--overlay`
:   When used together with `BaseTrees=`, the output will consist only out of
    changes to the specified base trees. Each base tree is attached as a lower
    layer in an overlayfs structure, and the output becomes the upper layer,
    initially empty. Thus files that are not modified compared to the base trees
    will not be present in the final output.

    This option may be used to create [systemd *system extensions* or
    *portable services*](https://uapi-group.org/specifications/specs/extension_image).

`UseSubvolumes=`, `--use-subvolumes=`
:   Takes a boolean or `auto`. Enables or disables use of btrfs subvolumes for
    directory tree outputs. If enabled, mkosi will create the root directory as
    a btrfs subvolume and use btrfs subvolume snapshots where possible to copy
    base or cached trees which is much faster than doing a recursive copy. If
    explicitly enabled and `btrfs` is not installed or subvolumes cannot be
    created, an error is raised. If `auto`, missing `btrfs` or failures to
    create subvolumes are ignored.

`Seed=`, `--seed=`
:   Takes a UUID as argument or the special value `random`.
    Overrides the seed that [`systemd-repart(8)`](https://www.freedesktop.org/software/systemd/man/systemd-repart.service.html)
    uses when building a disk image. This is useful to achieve reproducible
    builds, where deterministic UUIDs and other partition metadata should be
    derived on each build.

`CleanScripts=`, `--clean-script=`
:   Takes a comma-separated list of paths to executables that are used as
    the clean scripts for this image. See the **Scripts** section for
    more information.

### [Content] Section

`Packages=`, `--package=`, `-p`
:   Install the specified distribution packages (i.e. RPM, DEB, …) in the
    image. Takes a comma separated list of package specifications. This
    option may be used multiple times in which case the specified package
    lists are combined. Use `BuildPackages=` to specify packages that
    shall only be installed in an overlay that is mounted when the prepare
    scripts are executed with the `build` argument and when the build scripts
    are executed.

    The types and syntax of *package specifications* that are allowed
    depend on the package installer (e.g. `dnf` for `rpm`-based distros or
    `apt` for `deb`-based distros), but may include package names, package
    names with version and/or architecture, package name globs, package
    groups, and virtual provides, including file paths.

    See `PackageDirectories=` for information on how to make local
    packages available for installation with `Packages=`.

    **Example**: when using a distro that uses `dnf`, the following configuration
    would install the `meson` package (in the latest version), the 32-bit version
    of the `libfdisk-devel` package, all available packages that start with the
    `git-` prefix, a `systemd` rpm from the local file system, one of the
    packages that provides `/usr/bin/ld`, the packages in the *Development Tools*
    group, and the package that contains the `mypy` python module.

    ```ini
    Packages=meson
             libfdisk-devel.i686
             git-*
             /usr/bin/ld
             @development-tools
             python3dist(mypy)
    ```

`BuildPackages=`, `--build-package=`
:   Similar to `Packages=`, but configures packages to install only in an
    overlay that is made available on top of the image to the prepare
    scripts when executed with the `build` argument and the build scripts.
    This option should be used to list packages containing header files,
    compilers, build systems, linkers and other build tools the
    `mkosi.build` scripts require to operate. Note that packages listed
    here will be absent in the final image.

`VolatilePackages=`, `--volatile-package=`
:   Similar to `Packages=`, but packages configured with this setting are
    not cached when `Incremental=` is enabled and are installed after
    executing any build scripts.

    Specifically, this setting can be used to install packages that change
    often or which are built by a build script.

`PackageDirectories=`, `--package-directory=`
:   Specify directories containing extra packages to be made available during
    the build. `mkosi` will create a local repository containing all
    packages in these directories and make it available when installing packages or
    running scripts. If the `mkosi.packages/` directory is found in the local
    directory it is also used for this purpose.

`VolatilePackageDirectories=`, `--volatile-package-directory=`

:   Like `PackageDirectories=`, but any changes to the packages in these
    directories will not invalidate the cached images if `Incremental=`
    is enabled.

    Additionally, build scripts can add more packages to the local
    repository by placing the built packages in `$PACKAGEDIR`. The
    packages placed in `$PACKAGEDIR` are shared between all image builds
    and thus available for installation in all images using
    `VolatilePackages=`.

`WithRecommends=`, `--with-recommends=`
:   Configures whether to install recommended or weak dependencies,
    depending on how they are named by the used package manager, or not.
    By default, recommended packages are not installed. This is only used
    for package managers that support the concept, which are currently
    apt, dnf and zypper.

`WithDocs=`, `--with-docs`
:   Include documentation in the image. Enabled by default. When disabled,
    if the underlying distribution package manager supports it
    documentation is not included in the image. The `$WITH_DOCS`
    environment variable passed to the `mkosi.build` scripts is set to `0`
    or `1` depending on whether this option is enabled or disabled.

`BaseTrees=`, `--base-tree=`
:   Takes a comma separated list of paths to use as base trees. When used,
    these base trees are each copied into the OS tree and form the base
    distribution instead of installing the distribution from scratch. Only
    extra packages are installed on top of the ones already installed in
    the base trees. Note that for this to work properly, the base image
    still needs to contain the package manager metadata by setting
    `CleanPackageMetadata=no` (see `CleanPackageMetadata=`).

    Instead of a directory, a tar file or a disk image may be provided. In
    this case it is unpacked into the OS tree. This mode of operation
    allows setting permissions and file ownership explicitly, in
    particular for projects stored in a version control system such as
    `git` which retain full file ownership and access mode metadata for
    committed files.

`SkeletonTrees=`, `--skeleton-tree=`
:   Takes a comma separated list of colon separated path pairs. The first
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

    Note that skeleton trees are cached and any changes to skeleton trees
    after a cached image has been built (when using `Incremental=`) are
    only applied when the cached image is rebuilt (by using `-ff` or
    running `mkosi -f clean`).

    As with the base tree logic above, instead of a directory, a tar
    file may be provided too. `mkosi.skeleton.tar` will be automatically
    used if found in the local directory.

`ExtraTrees=`, `--extra-tree=`
:   Takes a comma separated list of colon separated path pairs. The first
    path of each pair refers to a directory to copy from the host into the
    image. The second path of each pair refers to the target directory
    inside the image. If the second path is not provided, the directory is
    copied on top of the root directory of the image. The second path is
    always interpreted as an absolute path. Use this to override any
    default configuration files shipped with the distribution. If the
    `mkosi.extra/` directory is found in the local directory it is also
    used for this purpose with the root directory as target. (also see the
    **Files** section below).

    As with the base tree logic above, instead of a directory, a tar
    file may be provided too. `mkosi.extra.tar` will be automatically
    used if found in the local directory.

`RemovePackages=`, `--remove-package=`
:   Takes a comma-separated list of package specifications for removal, in
    the same format as `Packages=`. The removal will be performed as one
    of the last steps. This step is skipped if `CleanPackageMetadata=no`
    is used.

`RemoveFiles=`, `--remove-files=`
:   Takes a comma-separated list of globs. Files in the image matching
    the globs will be purged at the end.

`CleanPackageMetadata=`, `--clean-package-metadata=`
:   Enable/disable removal of package manager databases and repository
    metadata at the end of installation. Can be specified as `true`,
    `false`, or `auto` (the default). With `auto`, package manager
    databases and repository metadata will be removed if the respective
    package manager executable is *not* present at the end of the
    installation.

`SourceDateEpoch=`, `--source-date-epoch=`
:   Takes a timestamp in seconds since the UNIX epoch as argument.
    File modification times of all files will be clamped to this value.
    The variable is also propagated to systemd-repart and
    scripts executed by mkosi. If not set explicitly, `SOURCE_DATE_EPOCH` from
    `--environment` and from the host environment are tried in that order.
    This is useful to make builds reproducible. See
    [SOURCE_DATE_EPOCH](https://reproducible-builds.org/specs/source-date-epoch/)
    for more information.

`SyncScripts=`, `--sync-script=`
:   Takes a comma-separated list of paths to executables that are used as
    the sync scripts for this image. See the **Scripts** section for
    more information.

`PrepareScripts=`, `--prepare-script=`
:   Takes a comma-separated list of paths to executables that are used as
    the prepare scripts for this image. See the **Scripts** section for
    more information.

`BuildScripts=`, `--build-script=`
:   Takes a comma-separated list of paths to executables that are used as
    the build scripts for this image. See the **Scripts** section for more
    information.

`PostInstallationScripts=`, `--postinst-script=`
:   Takes a comma-separated list of paths to executables that are used as
    the post-installation scripts for this image. See the **Scripts** section
    for more information.

`FinalizeScripts=`, `--finalize-script=`
:   Takes a comma-separated list of paths to executables that are used as
    the finalize scripts for this image. See the **Scripts** section for more
    information.

`PostOutputScripts=`, `--postoutput-script`
:   Takes a comma-separated list of paths to executables that are used as
    the post output scripts for this image. See the **Scripts** section for more
    information.

`BuildSources=`, `--build-sources=`
:   Takes a comma separated list of colon separated path pairs. The first
    path of each pair refers to a directory to mount from the host. The
    second path of each pair refers to the directory where the source
    directory should be mounted when running scripts. Every target path is
    prefixed with `/work/src` and all build sources are sorted
    lexicographically by their target before mounting, so that top level
    paths are mounted first. If not configured explicitly, the current
    working directory is mounted to `/work/src`.

`BuildSourcesEphemeral=`, `--build-sources-ephemeral=`
:   Takes a boolean. Disabled by default. Configures whether changes to
    source directories (The working directory and configured using
    `BuildSources=`) are persisted. If enabled, all source directories
    will be reset to their original state every time after running all
    scripts of a specific type (except sync scripts).

`Environment=`, `--environment=`
:   Adds variables to the environment that package managers and the
    prepare/build/postinstall/finalize scripts are executed with. Takes
    a space-separated list of variable assignments or just variable
    names. In the latter case, the values of those variables will be
    passed through from the environment in which `mkosi` was invoked.
    This option may be specified more than once, in which case all
    listed variables will be set. If the same variable is set twice, the
    later setting overrides the earlier one.

`EnvironmentFiles=`, `--env-file=`
:   Takes a comma-separated list of paths to files that contain environment
    variable definitions to be added to the scripting environment. Uses
    `mkosi.env` if it is found in the local directory. The variables are
    first read from `mkosi.env` if it exists, then from the given list of
    files and then from the `Environment=` settings.

`WithTests=`, `--without-tests`, `-T`
:   If set to false (or when the command-line option is used), the
    `$WITH_TESTS` environment variable is set to `0` when the
    `mkosi.build` scripts are invoked. This is supposed to be used by the
    build scripts to bypass any unit or integration tests that are
    normally run during the source build process. Note that this option
    has no effect unless the `mkosi.build` build scripts honor it.

`WithNetwork=`, `--with-network=`
:   When true, enables network connectivity while the build scripts
    `mkosi.build` are invoked. By default, the build scripts run with
    networking turned off. The `$WITH_NETWORK` environment variable is
    passed to the `mkosi.build` build scripts indicating whether the
    build is done with or without network.

`Bootable=`, `--bootable=`
:   Takes a boolean or `auto`. Enables or disables generation of a
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
:   Takes one of `none`, `systemd-boot`, `uki` or `grub`. Defaults to
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

    Note that we do not yet install grub to the ESP when `Bootloader=` is
    set to `grub`. This has to be done manually in a postinst or finalize
    script. The grub EFI binary should be installed to
    `/efi/EFI/BOOT/BOOTX64.EFI` (or similar depending on the architecture)
    and should be configured to load its configuration from
    `EFI/<distribution>/grub.cfg` in the ESP. Signed versions of grub
    shipped by distributions will load their configuration from this
    location by default.

`BiosBootloader=`, `--bios-bootloader=`
:   Takes one of `none` or `grub`. Defaults to `none`. If set to `none`,
    no BIOS bootloader will be installed. If set to `grub`, grub is
    installed as the BIOS boot loader if a bootable image is requested
    with the `Bootable=` option. If no repart partition definition files
    are configured, mkosi will add a grub BIOS boot partition and an EFI
    system partition to the default partition definition files.

    Note that this option is not mutually exclusive with `Bootloader=`. It
    is possible to have an image that is both bootable on UEFI and BIOS by
    configuring both `Bootloader=` and `BiosBootloader=`.

    The grub BIOS boot partition should have UUID
    `21686148-6449-6e6f-744e-656564454649` and should be at least 1MB.

    Even if no EFI bootloader is installed, we still need an ESP for BIOS
    boot as that's where we store the kernel, initrd and grub modules.

`ShimBootloader=`, `--shim-bootloader=`
:   Takes one of `none`, `unsigned`, or `signed`. Defaults to `none`. If
    set to `none`, shim and MokManager will not be installed to the ESP.
    If set to `unsigned`, mkosi will search for unsigned shim and
    MokManager EFI binaries and install them. If `SecureBoot=` is enabled,
    mkosi will sign the unsigned EFI binaries before installing them. If
    set to `signed`, mkosi will search for signed EFI binaries and install
    those. Even if `SecureBoot=` is enabled, mkosi won't sign these
    binaries again.

    Note that this option only takes effect when an image that is bootable
    on UEFI firmware is requested using other options
    (`Bootable=`, `Bootloader=`).

    Note that when this option is enabled, mkosi will only install already
    signed bootloader binaries, kernel image files and unified kernel
    images as self-signed binaries would not be accepted by the signed
    version of shim.

`UnifiedKernelImages=`, `--unified-kernel-images=`
:   Specifies whether to use unified kernel images or not when
    `Bootloader=` is set to `systemd-boot` or `grub`. Takes a boolean
    value or `auto`. Defaults to `auto`. If enabled, unified kernel images
    are always used and the build will fail if any components required to
    build unified kernel images are missing. If set to `auto`, unified
    kernel images will be used if all necessary components are available.
    Otherwise Type 1 entries as defined by the Boot Loader Specification
    will be used instead. If disabled, Type 1 entries will always be used.

`UnifiedKernelImageFormat=`, `--unified-kernel-image-format=`
:   Takes a filename without any path components to specify the format that
    unified kernel images should be installed as. This may include both the
    regular specifiers (see **Specifiers**) and special delayed specifiers, that
    are expanded during the installation of the files, which are described below.
    The default format for this parameter is `&e-&k` with `-&h` being appended
    if `roothash=` or `usrhash=` is found on the kernel command line and `+&c`
    if `/etc/kernel/tries` is found in the image.

    The following specifiers may be used:

    | Specifier | Value                                              |
    |-----------|----------------------------------------------------|
    | `&&`      | `&` character                                      |
    | `&e`      | Entry Token                                        |
    | `&k`      | Kernel version                                     |
    | `&h`      | `roothash=` or `usrhash=` value of kernel argument |
    | `&c`      | Number of tries used for boot attempt counting     |

`Initrds=`, `--initrd`
:   Use user-provided initrd(s). Takes a comma separated list of paths to initrd
    files. This option may be used multiple times in which case the initrd lists
    are combined. If no initrds are specified and a bootable image is requested,
    mkosi will look for initrds in a subdirectory `io.mkosi.initrd` of the
    artifact directory (see `$ARTIFACTDIR` in the section **ENVIRONMENT
    VARIABLES**), if none are found there mkosi will automatically build a
    default initrd.

`InitrdPackages=`, `--initrd-package=`
:   Extra packages to install into the default initrd. Takes a comma
    separated list of package specifications. This option may be used
    multiple times in which case the specified package lists are combined.

`InitrdVolatilePackages=`, `--initrd-volatile-package=`
:   Similar to `VolatilePackages=`, except it applies to the default
    initrd.

`MicrocodeHost=`, `--microcode-host=`
:   When set to true only include microcode for the host's CPU in the image.

`KernelCommandLine=`, `--kernel-command-line=`
:   Use the specified kernel command line when building images.

    If the value of this setting contains the literals `root=PARTUUID`
    or `mount.usr=PARTUUID`, these are replaced with the partition UUID
    of the root or usr partition respectively. For example,
    `root=PARTUUID` would be replaced with
    `root=PARTUUID=58c7d0b2-d224-4834-a16f-e036322e88f7` where
    `58c7d0b2-d224-4834-a16f-e036322e88f7` is the partition UUID of the
    root partition.

`KernelModulesInclude=`, `--kernel-modules-include=`
:   Takes a list of regex patterns that specify kernel modules to include in the image. Patterns should be
    relative to the `/usr/lib/modules/<kver>/kernel` directory. mkosi checks for a match anywhere in the module
    path (e.g. `i915` will match against `drivers/gpu/drm/i915.ko`). All modules that match any of the
    specified patterns are included in the image. All module and firmware dependencies of the matched modules
    are included in the image as well.

    If the special value `default` is used, the default kernel modules
    defined in the `mkosi-initrd` configuration are included as well.

    If the special value `host` is used, the currently loaded modules on
    the host system are included as well.

    This setting takes priority over `KernelModulesExclude=` and only makes
    sense when used in combination with it because all kernel modules are included in the image by default.

`KernelModulesExclude=`, `--kernel-modules-exclude=`
:   Takes a list of regex patterns that specify modules to exclude from the image. Behaves the same as
    `KernelModulesInclude=` except that all modules that match any of the specified patterns are excluded from
    the image.

`KernelModulesInitrd=`, `--kernel-modules-initrd=`
:   Enable/Disable generation of the kernel modules initrd when building a bootable image. Enabled by default.
    If enabled, when building a bootable image, for each kernel that we assemble a unified kernel image for we
    generate an extra initrd containing only the kernel modules for that kernel version and append it to the
    prebuilt initrd. This allows generating kernel independent initrds which are augmented with the necessary
    kernel modules when the UKI is assembled.

`KernelModulesInitrdInclude=`, `--kernel-modules-initrd-include=`
:   Like `KernelModulesInclude=`, but applies to the kernel modules included in the kernel modules initrd.

`KernelModulesInitrdExclude=`, `--kernel-modules-initrd-exclude=`
:   Like `KernelModulesExclude=`, but applies to the kernel modules included in the kernel modules initrd.

`Locale=`, `--locale=`, `LocaleMessages=`, `--locale-messages=`, `Keymap=`, `--keymap=`, `Timezone=`, `--timezone=`, `Hostname=`, `--hostname=`, `RootShell=`, `--root-shell=`
:   The settings `Locale=`, `--locale=`, `LocaleMessages=`, `--locale-messages=`,
    `Keymap=`, `--keymap=`, `Timezone=`, `--timezone=`, `Hostname=`,
    `--hostname=`, `RootShell=`, `--root-shell=` correspond to the identically
    named systemd-firstboot options. See the systemd firstboot
    [manpage](https://www.freedesktop.org/software/systemd/man/systemd-firstboot.html)
    for more information.  Additionally, where applicable, the corresponding
    systemd credentials for these settings are written to `/usr/lib/credstore`,
    so that they apply even if only `/usr` is shipped in the image.

`RootPassword=`, `--root-password=`,
:   Set the system root password. If this option is not used, but a `mkosi.rootpw` file is found in the local
    directory, the password is automatically read from it or if the file is executable it is run as a script
    and stdout is read instead (see the **Scripts** section below). If the password starts with `hashed:`, it is
    treated as an already hashed root password. The root password is also stored in `/usr/lib/credstore` under
    the appropriate systemd credential so that it applies even if only `/usr` is shipped in the image. To create
    an unlocked account without any password use `hashed:` without a hash.

`Autologin=`, `--autologin`
:   Enable autologin for the `root` user on `/dev/pts/0` (nspawn),
    `/dev/tty1` and `/dev/hvc0`.

`MakeInitrd=`, `--make-initrd`
:   Add `/etc/initrd-release` and `/init` to the image so that it can be
    used as an initramfs.

`Ssh=`, `--ssh`
:   If specified, an sshd socket unit and matching service are installed
    in the final image that expose SSH over VSock. When building with this
    option and running the image using `mkosi qemu`, the `mkosi ssh`
    command can be used to connect to the container/VM via SSH. Note that
    you still have to make sure openssh is installed in the image to make
    this option behave correctly. Run `mkosi genkey` to automatically
    generate an X509 certificate and private key to be used by mkosi to
    enable SSH access to any virtual machines via `mkosi ssh`. To access
    images booted using `mkosi boot`, use `machinectl`.

`SELinuxRelabel=`, `--selinux-relabel=`
:   Specifies whether to relabel files to match the image's SELinux
    policy. Takes a boolean value or `auto`. Defaults to `auto`. If
    disabled, files will not relabeled. If enabled, an SELinux policy has
    to be installed in the image and `setfiles` has to be available to
    relabel files. If any errors occur during `setfiles`, the build will
    fail. If set to `auto`, files will be relabeled if an SELinux policy
    is installed in the image and if `setfiles` is available. Any errors
    occurred during `setfiles` will be ignored.

    Note that when running unprivileged, `setfiles` will fail to set any
    labels that are not in the host's SELinux policy. To ensure `setfiles`
    succeeds without errors, make sure to run mkosi as root or build from
    a host system with the same SELinux policy as the image you're
    building.

### [Validation] Section

`SecureBoot=`, `--secure-boot`
:   Sign systemd-boot (if it is not signed yet) and any generated
    unified kernel images for UEFI SecureBoot.

`SecureBootAutoEnroll=`, `--secure-boot-auto-enroll=`
:   Set up automatic enrollment of the secure boot keys in virtual machines as
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
:   Path to the PEM file containing the secret key for signing the
    UEFI kernel image if `SecureBoot=` is used and PCR signatures when
    `SignExpectedPcr=` is also used. When `SecureBootKeySource=` is specified,
    the input type depends on the source.

`SecureBootKeySource=`, `--secure-boot-key-source=`
:   Source of `SecureBootKey=`, to support OpenSSL engines. E.g.:
    `--secure-boot-key-source=engine:pkcs11`

`SecureBootCertificate=`, `--secure-boot-certificate=`
:   Path to the X.509 file containing the certificate for the signed
    UEFI kernel image, if `SecureBoot=` is used.

`SecureBootSignTool=`, `--secure-boot-sign-tool`
:   Tool to use to sign secure boot PE binaries. Takes one of `sbsign`, `pesign` or `auto`. Defaults to `auto`.
    If set to `auto`, either sbsign or pesign are used if available, with sbsign being preferred if both are
    installed.

`VerityKey=`, `--verity-key=`
:   Path to the PEM file containing the secret key for signing the verity signature, if a verity signature
    partition is added with systemd-repart. When `VerityKeySource=` is specified, the input type depends on
    the source.

`VerityKeySource=`, `--verity-key-source=`
:   Source of `VerityKey=`, to support OpenSSL engines. E.g.:
    `--verity-key-source=engine:pkcs11`

`VerityCertificate=`, `--verity-certificate=`
:   Path to the X.509 file containing the certificate for signing the verity signature, if a verity signature
    partition is added with systemd-repart.

`SignExpectedPcr=`, `--sign-expected-pcr`
:   Measure the components of the unified kernel image (UKI) using
    `systemd-measure` and embed the PCR signature into the unified kernel
    image. This option takes a boolean value or the special value `auto`,
    which is the default, which is equal to a true value if the
    `systemd-measure` binary is in `PATH`.  Depends on `SecureBoot=`
    being enabled and key from `SecureBootKey=`.

`Passphrase=`, `--passphrase`
:   Specify the path to a file containing the passphrase to use for LUKS
    encryption. It should contain the passphrase literally, and not end in
    a newline character (i.e. in the same format as cryptsetup and
    `/etc/crypttab` expect the passphrase files). The file must have an
    access mode of 0600 or less.

`Checksum=`, `--checksum`
:   Generate a `SHA256SUMS` file of all generated artifacts after the
    build is complete.

`Sign=`, `--sign`
:   Sign the generated `SHA256SUMS` using `gpg` after completion.

`Key=`, `--key=`
:   Select the `gpg` key to use for signing `SHA256SUMS`. This key must
    be already present in the `gpg` keyring.

### [Host] Section

`ProxyUrl=`, `--proxy-url=`
:   Configure a proxy to be used for all outgoing network connections.
    Various tools that mkosi invokes and for which the proxy can be
    configured are configured to use this proxy. mkosi also sets various
    well-known environment variables to specify the proxy to use for any
    programs it invokes that may need internet access.

`ProxyExclude=`, `--proxy-exclude=`
:   Configure hostnames for which requests should not go through the
    proxy. Takes a comma separated list of hostnames.

`ProxyPeerCertificate=`, `--proxy-peer-certificate=`
:   Configure a file containing certificates used to verify the proxy.
    Defaults to the system-wide certificate store.

    Currently, setting a proxy peer certificate is only supported when
    `dnf` or `dnf5` is used to build the image.

`ProxyClientCertificate=`, `--proxy-client-certificate=`
:   Configure a file containing the certificate used to authenticate the
    client with the proxy.

    Currently, setting a proxy client certificate is only supported when
    `dnf` or `dnf5` is used to build the image.

`ProxyClientKey=`, `--proxy-client-key=`
:   Configure a file containing the private key used to authenticate the
    client with the proxy. Defaults to the proxy client certificate if one
    is provided.

    Currently, setting a proxy client key is only supported when `dnf` or
    `dnf5` is used to build the image.

`Incremental=`, `--incremental=`, `-i`
:   Enable incremental build mode. In this mode, a copy of the OS image is
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
:   Specifies a `.nspawn` settings file for `systemd-nspawn` to use in
    the `boot` and `shell` verbs, and to place next to the generated
    image file. This is useful to configure the `systemd-nspawn`
    environment when the image is run. If this setting is not used but
    an `mkosi.nspawn` file found in the local directory it is
    automatically used for this purpose.

`ExtraSearchPaths=`, `--extra-search-path=`
:   List of colon-separated paths to look for tools in, before using the
    regular `$PATH` search path.

`VirtualMachineMonitor=`, `--vmm=`
:   Configures the virtual machine monitor to use. Takes one of `qemu` or
    `vmspawn`. Defaults to `qemu`.

    When set to `qemu`, the image is booted with `qemu`. Most output
    formats can be booted in `qemu`. Any arguments specified after the
    verb are appended to the `qemu` invocation and are interpreted as
    extra qemu command line arguments.

    When set to `vmspawn`, `systemd-vmspawn` is used to boot up the image,
    `vmspawn` only supports disk and directory type images. Any arguments
    specified after the verb are appended to the `systemd-vmspawn`
    invocation and are interpreted as extra vmspawn options and extra
    kernel command line arguments.

`QemuGui=`, `--qemu-gui=`
:   If enabled, qemu is executed with its graphical interface instead of
    with a serial console.

`QemuSmp=`, `--qemu-smp=`
:   When used with the `qemu` verb, this options sets `qemu`'s `-smp`
    argument which controls the number of guest's CPUs. Defaults to `2`.

    When set to `0`, the number of CPUs available to the mkosi process
    will be used.

`QemuMem=`, `--qemu-mem=`
:   When used with the `qemu` verb, this options sets `qemu`'s `-m`
    argument which controls the amount of guest's RAM. Defaults to `2G`.

`QemuKvm=`, `--qemu-kvm=`
:   When used with the `qemu` verb, this option specifies whether QEMU should use KVM acceleration. Takes a
    boolean value or `auto`. Defaults to `auto`.

`QemuVsock=`, `--qemu-vsock=`
:   When used with the `qemu` verb, this option specifies whether QEMU should be configured with a vsock. Takes
    a boolean value or `auto`. Defaults to `auto`.

`QemuVsockConnectionId=`, `--qemu-vsock-cid=`
:   When used with the `qemu` verb, this option specifies the vsock
    connection ID to use. Takes a number in the interval `[3, 0xFFFFFFFF)`
    or `hash` or `auto`. Defaults to `auto`. When set to `hash`, the
    connection ID will be derived from the full path to the image. When
    set to `auto`, `mkosi` will try to find a free connection ID
    automatically. Otherwise, the provided number will be used as is.

`QemuSwtpm=`, `--qemu-swtpm=`
:   When used with the `qemu` verb, this option specifies whether to start an instance of swtpm to be used as a
    TPM with qemu. This requires swtpm to be installed on the host. Takes a boolean value or `auto`. Defaults
    to `auto`.

`QemuCdrom=`, `--qemu-cdrom=`
:   When used with the `qemu` verb, this option specifies whether to
    attach the image to the virtual machine as a CD-ROM device. Takes a
    boolean. Defaults to `no`.

`QemuFirmware=`, `--qemu-firmware=`
:   When used with the `qemu` verb, this option specifies which firmware
    to use. Takes one of `uefi`, `uefi-secure-boot`, `bios`, `linux`, or
    `auto`. Defaults to `auto`. When set to `uefi`, the OVMF firmware
    without secure boot support is used. When set to `uefi-secure-boot`,
    the OVMF firmware with secure boot support is used. When set to
    `bios`, the default SeaBIOS firmware is used. When set to `linux`,
    direct kernel boot is used. See the `QemuKernel=` option for more
    details on which kernel image is used with direct kernel boot. When
    set to `auto`, `uefi-secure-boot` is used if possible and `linux`
    otherwise.

`QemuFirmwareVariables=`, `--qemu-firmware-variables=`
:   When used with the `qemu` verb, this option specifies the path to the
    the firmware variables file to use. Currently, this option is only
    taken into account when the `uefi` or `uefi-secure-boot` firmware is
    used. If not specified, mkosi will search for the default variables
    file and use that instead.

    When set to `microsoft`, a firmware variables file with the Microsoft
    secure boot certificates already enrolled will be used.

    When set to `custom`, the secure boot certificate from
    `SecureBootCertificate=` will be enrolled into the default firmware
    variables file.

    `virt-fw-vars` from the
    [virt-firmware](https://gitlab.com/kraxel/virt-firmware) project can
    be used to customize OVMF variable files.

`QemuKernel=`, `--qemu-kernel=`
:   Set the kernel image to use for qemu direct kernel boot. If not
    specified, mkosi will use the kernel provided via the command line
    (`-kernel` option) or latest the kernel that was installed into
    the image (or fail if no kernel was installed into the image).

    Note that when the `cpio` output format is used, direct kernel boot is
    used regardless of the configured firmware. Depending on the
    configured firmware, qemu might boot the kernel itself or using the
    configured firmware.

`QemuDrives=`, `--qemu-drive=`
:   Add a qemu drive. Takes a colon-delimited string of format
    `<id>:<size>[:<directory>[:<options>[:<file-id>]]]`. `id` specifies
    the qemu ID assigned to the drive. This can be used as the `drive=`
    property in various qemu devices. `size` specifies the size of the
    drive. This takes a size in bytes. Additionally, the suffixes `K`, `M`
    and `G` can be used to specify a size in kilobytes, megabytes and
    gigabytes respectively. `directory` optionally specifies the directory
    in which to create the file backing the drive. `options` optionally
    specifies extra comma-delimited properties which are passed verbatim
    to qemu's `-drive` option. `file-id` specifies the ID of the file
    backing the drive. Drives with the same file ID will share the
    backing file. The directory and size of the file will be determined
    from the first drive with a given file ID.

    **Example usage:**

    ```ini
    [Host]
    QemuDrives=btrfs:10G
               ext4:20G
    QemuArgs=-device nvme,serial=btrfs,drive=btrfs
             -device nvme,serial=ext4,drive=ext4
    ```

`QemuArgs=`
:   Space-delimited list of additional arguments to pass when invoking
    qemu.

`Ephemeral=`, `--ephemeral`
:   When used with the `shell`, `boot`, or `qemu` verbs, this option runs the specified verb on a temporary
    snapshot of the output image that is removed immediately when the container terminates. Taking the
    temporary snapshot is more efficient on file systems that support reflinks natively (btrfs or xfs)
    than on more traditional file systems that do not (ext4).

`Credentials=`, `--credential=`
:   Set credentials to be passed to systemd-nspawn or qemu respectively
    when `mkosi shell/boot` or `mkosi qemu` are used. This option takes a
    space separated list of values which can be either key=value pairs or
    paths. If a path is provided, if it is a file, the credential name
    will be the name of the file. If the file is executable, the
    credential value will be the output of executing the file. Otherwise,
    the credential value will be the contents of the file. If the path is
    a directory, the same logic applies to each file in the directory.

    Note that values will only be treated as paths if they do not contain
    the delimiter (`=`).

`KernelCommandLineExtra=`, `--kernel-command-line-extra=`
:   Set extra kernel command line entries that are appended to the kernel command
    line at runtime when booting the image. When booting in a container, these are
    passed as extra arguments to systemd. When booting in a VM, these are appended
    to the kernel command line via the SMBIOS io.systemd.stub.kernel-cmdline-extra
    OEM string. This will only be picked up by systemd-boot/systemd-stub versions
    newer than or equal to v254.

`ToolsTree=`, `--tools-tree=`
:   If specified, programs executed by mkosi to build and boot an image
    are looked up inside the given tree instead of in the host system. Use
    this option to make image builds more reproducible by always using the
    same versions of programs to build the final image instead of whatever
    version is installed on the host system. If this option is not used,
    but the `mkosi.tools/` directory is found in the local directory it is
    automatically used for this purpose with the root directory as target.

    Note if a binary is found in any of the paths configured with
    `ExtraSearchPaths=`, the binary will be executed on the host.

    If set to `default`, mkosi will automatically add an extra tools tree
    image and use it as the tools tree.

    Note that mkosi will only build a single default tools tree per build,
    even if multiple images are defined in `mkosi.images` with
    `ToolsTree=default`. The settings of the "last" image will apply to
    the default tools tree (usually the image defined last in
    mkosi.images and without any dependencies on other images).

    The following table shows for which distributions default tools tree
    packages are defined and which packages are included in those default
    tools trees:

    |                         | Fedora | CentOS | Debian | Kali | Ubuntu | Arch | openSUSE |
    |-------------------------|:------:|:------:|:------:|:----:|:------:|:----:|:--------:|
    | `acl`                   | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `apt`                   | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    |          |
    | `archlinux-keyring`     | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    |          |
    | `attr`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `bash`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `btrfs-progs`           | ✓      |        | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `bubblewrap`            | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `ca-certificates`       | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `coreutils`             | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `cpio`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `curl`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `debian-keyring`        | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    |          |
    | `diffutils`             | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `distribution-gpg-keys` | ✓      | ✓      |        |      |        | ✓    | ✓        |
    | `dnf`                   | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `dnf-plugins-core`      | ✓      | ✓      |        |      |        |      | ✓        |
    | `dnf5`                  | ✓      |        |        |      |        |      |          |
    | `dnf5-plugins`          | ✓      |        |        |      |        |      |          |
    | `dosfstools`            | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `e2fsprogs`             | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `edk2-ovmf`             | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `erofs-utils`           | ✓      |        | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `findutils`             | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `git`                   | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `grep`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `grub-tools`            | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    |          |
    | `jq`                    | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `kali-archive-keyring`  |        |        |        | ✓    |        |      |          |
    | `kmod`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `less`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `mtools`                | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `nano`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `openssh`               | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `openssl`               | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `sed`                   | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `pacman`                | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    |          |
    | `pesign`                | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `policycoreutils`       | ✓      | ✓      | ✓      | ✓    | ✓      |      | ✓        |
    | `qemu`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `sbsigntools`           | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `socat`                 | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `squashfs-tools`        | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `strace`                | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `swtpm`                 | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `systemd`               | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `ukify`                 | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `tar`                   | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `ubuntu-keyring`        | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    |          |
    | `util-linux`            | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `virtiofsd`             | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `virt-firmware`         | ✓      | ✓      |        |      |        | ✓    |          |
    | `xfsprogs`              | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `xz`                    | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `zstd`                  | ✓      | ✓      | ✓      | ✓    | ✓      | ✓    | ✓        |
    | `zypper`                | ✓      |        | ✓      | ✓    | ✓      | ✓    |          |

`ToolsTreeDistribution=`, `--tools-tree-distribution=`
:   Set the distribution to use for the default tools tree. By default,
    the same distribution as the image that's being built is used, except
    for CentOS and Ubuntu images, in which case Fedora and Debian are used
    respectively.

`ToolsTreeRelease=`, `--tools-tree-release=`
:   Set the distribution release to use for the default tools tree. By
    default, the hardcoded default release in mkosi for the distribution
    is used.

`ToolsTreeMirror=`, `--tools-tree-mirror=`
:   Set the mirror to use for the default tools tree. By default, the
    default mirror for the tools tree distribution is used.

`ToolsTreeRepositories=`, `--tools-tree-repository`
:   Same as `Repositories=` but for the default tools tree.

`ToolsTreeSandboxTrees=`, `--tools-tree-sandbox-tree`
:   Same as `SandboxTrees=` but for the default tools tree.

`ToolsTreePackages=`, `--tools-tree-packages=`
:   Extra packages to install into the default tools tree. Takes a comma
    separated list of package specifications. This option may be used
    multiple times in which case the specified package lists are combined.

`ToolsTreeCertificates=`, `--tools-tree-certificates=`
:   Specify whether to use certificates and keys from the tools tree. If
    enabled, `/usr/share/keyrings`, `/usr/share/distribution-gpg-keys`,
    `/etc/pki`, `/etc/ssl`, `/etc/ca-certificates`, `/etc/pacman.d/gnupg`
    and `/var/lib/ca-certificates` from the tools tree are used.
    Otherwise, these directories are picked up from the host.

`RuntimeTrees=`, `--runtime-tree=`
:   Takes a colon separated pair of paths. The first path refers to a
    directory to mount into any machine (container or VM) started by
    mkosi. The second path refers to the target directory inside the
    machine. If the second path is not provided, the directory is mounted
    at `/root/src` in the machine. If the second path is relative, it
    is interpreted relative to `/root/src` in the machine.

    For each mounted directory, the uid and gid of the user running mkosi
    are mapped to the root user in the machine. This means that all the
    files and directories will appear as if they're owned by root in the
    machine, and all new files and directories created by root in the
    machine in these directories will be owned by the user running mkosi
    on the host.

    Note that when using `mkosi qemu` with this feature systemd v254 or
    newer has to be installed in the image.

`RuntimeSize=`, `--runtime-size=`
:   If specified, disk images are grown to the specified size when
    they're booted with `mkosi boot` or `mkosi qemu`. Takes a size in
    bytes. Additionally, the suffixes `K`, `M` and `G` can be used to
    specify a size in kilobytes, megabytes and gigabytes respectively.

`RuntimeScratch=`, `--runtime-scratch=`
:   Takes a boolean value or `auto`. Specifies whether to mount extra
    scratch space to `/var/tmp`. If enabled, practically unlimited scratch
    space is made available under `/var/tmp` when booting the image with
    `mkosi qemu`, `mkosi boot` or `mkosi shell`.

    Note that using this feature with `mkosi qemu` requires systemd v254
    or newer in the guest.

`RuntimeNetwork=`, `--runtime-network=`
:   Takes one of `user`, `interface` or `none`. Defaults to `user`.
    Specifies the networking to set up when booting the image. `user` sets
    up usermode networking. `interface` sets up a virtual network
    connection between the host and the image. This translates to a veth
    interface for `mkosi shell` and `mkosi boot` and a tap interface for
    `mkosi qemu` and `mkosi vmspawn`.

    Note that when using `interface`, mkosi does not automatically
    configure the host interface. It is expected that a recent version of
    `systemd-networkd` is running on the host which will automatically
    configure the host interface of the link.

`RuntimeBuildSources=`, `--runtime-build-sources=`
:   Mount the build sources configured with `BuildSources=` and the build
    directory (if one is configured) to the same locations in `/work` that
    they were mounted to when running the build script when using `mkosi
    boot` or `mkosi qemu`.

`RuntimeHome=`, `--runtime-home=`
:   Mount the current home directory from which mkosi is running to
    `/root` when using `mkosi boot` or `mkosi qemu`.

`UnitProperties=`, `--unit-property=`
:   Configure systemd unit properties to add to the systemd scopes
    allocated when using `mkosi boot` or `mkosi qemu`. These are passed
    directly to the `--property` options of `systemd-nspawn` and
    `systemd-run` respectively.

`SshKey=`, `--ssh-key=`
:   Path to the X509 private key in PEM format to use to connect to a
    virtual machine started with `mkosi qemu` and built with the `Ssh=`
    option enabled via the `mkosi ssh` command. If not configured and
    `mkosi.key` exists in the working directory, it will automatically be
    used for this purpose. Run `mkosi genkey` to automatically generate
    a key in `mkosi.key`.

`SshCertificate=`, `--ssh-certificate=`
:   Path to the X509 certificate in PEM format to provision as the SSH
    public key in virtual machines started with `mkosi qemu`.  If not
    configured and `mkosi.crt` exists in the working directory, it will
    automatically be used for this purpose. Run `mkosi genkey` to
    automatically generate a certificate in `mkosi.crt`.

`Machine=`, `--machine=`
:   Specify the machine name to use when booting the image. Can also be
    used to refer to a specific image when SSH-ing into an image (e.g.
    `mkosi --image=myimage ssh`).

    Note that `Ephemeral=` has to be enabled to start multiple instances
    of the same image.

`ForwardJournal=`, `--forward-journal=`
:   Specify the path to which journal logs from containers and virtual
    machines should be forwarded. If the path has the `.journal`
    extension, it is interpreted as a file to which the journal should be
    written. Otherwise, the path is interpreted as a directory to which
    the journal should be written.

    Note that systemd v256 or newer is required in the virtual machine for
    log forwarding to work.

    Note that if a path with the `.journal` extension is given, the
    journal size is limited to `4G`. Configure an output directory instead
    of file if your workload produces more than `4G` worth of journal
    data.

### [Match] Section.

`Profile=`
:   Matches against the configured profile.

`Distribution=`
:   Matches against the configured distribution.

`Release=`
:   Matches against the configured distribution release. If this condition is used and no distribution has been
    explicitly configured yet, the host distribution and release are used.

`Architecture=`
:   Matches against the configured architecture. If this condition is used
    and no architecture has been explicitly configured yet, the host
    architecture is used.

`Repositories=`
:   Matches against repositories enabled with the `Repositories=` setting.
    Takes a single repository name.

`PathExists=`
:   This condition is satisfied if the given path exists. Relative paths are interpreted relative to the parent
    directory of the config file that the condition is read from.

`ImageId=`
:   Matches against the configured image ID, supporting globs. If this condition is used and no image ID has
    been explicitly configured yet, this condition fails.

`ImageVersion=`
:   Matches against the configured image version. Image versions can be prepended by the operators `==`, `!=`,
    `>=`, `<=`, `<`, `>` for rich version comparisons according to the UAPI group version format specification.
    If no operator is prepended, the equality operator is assumed by default. If this condition is used and no
    image version has been explicitly configured yet, this condition fails.

`Bootable=`
:   Matches against the configured value for the `Bootable=` feature. Takes a boolean value or `auto`.

`Format=`
:   Matches against the configured value for the `Format=` option. Takes
    an output format (see the `Format=` option).

`SystemdVersion=`
:   Matches against the systemd version on the host (as reported by
    `systemctl --version`). Values can be prepended by the operators `==`,
    `!=`, `>=`, `<=`, `<`, `>` for rich version comparisons according to
    the UAPI group version format specification. If no operator is
    prepended, the equality operator is assumed by default.

`BuildSources=`
:   Takes a build source target path (see `BuildSources=`). This match is
    satisfied if any of the configured build sources uses this target
    path. For example, if we have a `mkosi.conf` file containing:

    ```ini
    [Content]
    BuildSources=../abc/qed:kernel
    ```

    and a drop-in containing:

    ```ini
    [Match]
    BuildSources=kernel
    ```

    The drop-in will be included.

    Any absolute paths passed to this setting are interpreted relative to
    the current working directory.

`HostArchitecture=`
:   Matches against the host's native architecture. See the
    `Architecture=` setting for a list of possible values.

`ToolsTreeDistribution=`
:   Matches against the configured tools tree distribution.

`Environment=`
:   Matches against a specific key/value pair configured with
    `Environment=`. If no value is provided, check if the given key is in
    the environment regardless of which value it has.

This table shows which matchers support globs, rich comparisons and the default
value that is matched against if no value has been configured at the time the
config file is read:

| Matcher                  | Globs | Rich Comparisons | Default                               |
|--------------------------|-------|------------------|---------------------------------------|
| `Profile=`               | no    | no               | match fails                           |
| `Distribution=`          | no    | no               | match host distribution               |
| `Release=`               | no    | no               | match host release                    |
| `Architecture=`          | no    | no               | match host architecture               |
| `PathExists=`            | no    | no               | n/a                                   |
| `ImageId=`               | yes   | no               | match fails                           |
| `ImageVersion=`          | no    | yes              | match fails                           |
| `Bootable=`              | no    | no               | match auto feature                    |
| `Format=`                | no    | no               | match default format                  |
| `SystemdVersion=`        | no    | yes              | n/a                                   |
| `BuildSources=`          | no    | no               | match fails                           |
| `HostArchitecture=`      | no    | no               | n/a                                   |
| `ToolsTreeDistribution=` | no    | no               | match default tools tree distribution |
| `Environment=`           | no    | no               | n/a                                   |

### [Config] Section

`Profile=`, `--profile=`
:   Select the given profile. A profile is a configuration file or
    directory in the `mkosi.profiles/` directory. When selected, this
    configuration file or directory is included after parsing the
    `mkosi.conf` file, but before any `mkosi.conf.d/*.conf` drop in
    configuration.

`Include=`, `--include=`, `-I`
:   Include extra configuration from the given file or directory. The
    extra configuration is included immediately after parsing the setting,
    except when used on the command line, in which case the extra
    configuration is included after parsing all command line arguments.

    Note that each path containing extra configuration is only parsed
    once, even if included more than once with `Include=`.

    The builtin configs for the mkosi default initrd and default tools
    tree can be included by including the literal value `mkosi-initrd` and
    `mkosi-tools` respectively.

    Note: Include names starting with either of the literals `mkosi-` or
    `contrib-` are reserved for use by mkosi itself.

`InitrdInclude=`, `--initrd-include=`
:   Same as `Include=`, but the extra configuration files or directories
    are included when building the default initrd.

`Dependencies=`, `--dependency=`
:   The images that this image depends on specified as a comma-separated
    list. All images configured in this option will be built before this
    image.

    When this setting is specified for the "main" image, it specifies
    which subimages should be built. See the
    **Building multiple images** section for more information.

`MinimumVersion=`, `--minimum-version=`
:   The minimum mkosi version required to build this configuration. If
    specified multiple times, the highest specified version is used.

`ConfigureScripts=`, `--configure-script=`
:   Takes a comma-separated list of paths to executables that are used as
    the configure scripts for this image. See the **Scripts** section for
    more information.

`PassEnvironment=`, `--pass-environment=`
:   Takes a list of environment variable names separated by spaces. When
    building multiple images, pass the listed environment variables to
    each individual subimage as if they were "universal" settings. See
    the **Building multiple images** section for more information.

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
| `Profile=`         | `%p`      |

There are also specifiers that are independent of settings:

| Specifier | Value                                   |
|-----------|-----------------------------------------|
| `%C`      | Parent directory of current config file |
| `%P`      | Current working directory               |
| `%D`      | Directory that mkosi was invoked in     |

Finally, there are specifiers that are derived from a setting:

| Specifier | Value                                                 |
|-----------|-------------------------------------------------------|
| `%F`      | The default filesystem of the configured distribution |

Note that the current working directory changes as mkosi parses its
configuration. Specifically, each time mkosi parses a directory
containing a `mkosi.conf` file, mkosi changes its working directory to
that directory.

Note that the directory that mkosi was invoked in is influenced by the
`--directory=` command line argument.

The following table shows example values for the directory specifiers
listed above:

|      | `$D/mkosi.conf` | `$D/mkosi.conf.d/abc/abc.conf` | `$D/mkosi.conf.d/abc/mkosi.conf` |
|------|-----------------|--------------------------------|----------------------------------|
| `%C` | `$D`            | `$D/mkosi.conf.d`              | `$D/mkosi.conf.d/abc`            |
| `%P` | `$D`            | `$D`                           | `$D/mkosi.conf.d/abc`            |
| `%D` | `$D`            | `$D`                           | `$D`                             |

## Supported distributions

Images may be created containing installations of the following
distributions:

* *Fedora Linux*

* *Debian*

* *Kali Linux*

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

* *Azure Linux*

* *None* (**Requires the user to provide a pre-built rootfs**)

In theory, any distribution may be used on the host for building images
containing any other distribution, as long as the necessary tools are
available.
Specifically,
any distribution that packages `apt` may be used to build *Debian*, *Kali* or *Ubuntu* images.
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
1. Parse configuration files
1. Run configure scripts (`mkosi.configure`)
1. If we're not running as root, unshare the user namespace and map the
   subuid range configured in `/etc/subuid` and `/etc/subgid` into it.
1. Unshare the mount namespace
1. Remount the following directories read-only if they exist:
   - `/usr`
   - `/etc`
   - `/opt`
   - `/srv`
   - `/boot`
   - `/efi`
   - `/media`
   - `/mnt`

Then, for each image, we execute the following steps:

1. Copy sandbox trees into the workspace
1. Sync the package manager repository metadata
1. Run sync scripts (`mkosi.sync`)
1. Copy base trees (`--base-tree=`) into the image
1. Reuse a cached image if one is available
1. Copy a snapshot of the package manager repository metadata into the
   image
1. Copy skeleton trees (`mkosi.skeleton`) into image
1. Install distribution and packages into image
1. Run prepare scripts on image with the `final` argument (`mkosi.prepare`)
1. Install build packages in overlay if any build scripts are configured
1. Run prepare scripts on overlay with the `build` argument if any build
    scripts are configured (`mkosi.prepare`)
1. Cache the image if configured (`--incremental`)
1. Run build scripts on image + overlay if any build scripts are configured (`mkosi.build`)
1. Finalize the build if the output format `none` is configured
1. Copy the build scripts outputs into the image
1. Copy the extra trees into the image (`mkosi.extra`)
1. Run post-install scripts (`mkosi.postinst`)
1. Write config files required for `Ssh=`, `Autologin=` and `MakeInitrd=`
1. Install systemd-boot and configure secure boot if configured (`--secure-boot`)
1. Run `systemd-sysusers`
1. Run `systemd-tmpfiles`
1. Run `systemctl preset-all`
1. Run `depmod`
1. Run `systemd-firstboot`
1. Run `systemd-hwdb`
1. Remove packages and files (`RemovePackages=`, `RemoveFiles=`)
1. Run SELinux relabel is a SELinux policy is installed
1. Run finalize scripts (`mkosi.finalize`)
1. Generate unified kernel image if configured to do so
1. Generate final output format
1. Run post-output scripts (`mkosi.postoutput`)

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

* If **`mkosi.configure`** (`ConfigureScripts=`) exists, it is executed
  before building the image. This script may be used to dynamically
  modify the configuration. It receives the configuration serialized as
  JSON on stdin and should output the modified configuration serialized
  as JSON on stdout. Note that this script only runs when building or
  booting the image (`build`, `qemu`, `boot` and `shell` verbs). If a
  default tools tree is configured, it will be built before running the
  configure scripts and the configure scripts will run with the tools
  tree available. This also means that the modifications made by
  configure scripts will not be visible in the `summary` output.

* If **`mkosi.sync`** (`SyncScripts=`) exists, it is executed before the
  image is built. This script may be used to update various sources that
  are used to build the image. One use case is to run `git pull` on
  various source repositories before building the image. Specifically,
  the `BuildSourcesEphemeral=` setting does not apply to sync scripts,
  which means sync scripts can be used to update build sources even if
  `BuildSourcesEphemeral=` is enabled.

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

* If **`mkosi.postoutput`** (`PostOutputScripts=`) exists, it is executed right
  after all the output files have been generated, before they are finally
  moved into the output directory. This can be used to generate additional or
  alternative outputs, e.g. `SHA256FILES` or SBOM manifests.

* If **`mkosi.clean`** (`CleanScripts=`) exists, it is executed right
  after the outputs of a previous build have been cleaned up. A clean
  script can clean up any outputs that mkosi does not know about (e.g.
  artifacts from `SplitArtifacts=yes` or RPMs built in a build script).
  Note that this script does not use the tools tree even if one is configured.

* If **`mkosi.version`** exists and is executable, it is run during
  configuration parsing and populates `ImageVersion=` with the output on stdout.
  This can be used for external version tracking, e.g. with `git describe` or
  `date '+%Y-%m-%d'`. Note that this script is executed on the host system
  without any sandboxing.

* If **`mkosi.rootpw`** exists and is executable, it is run during
  configuration parsing and populates `RootPassword=` with the output
  on stdout. This can be used to randomly generate a password and can
  be remembered by outputting it to stderr or by reading `$MKOSI_CONFIG`
  in another script (e.g. `mkosi.postoutput`). Note that this script is
  executed on the host system without any sandboxing.

If a script uses the `.chroot` extension, mkosi will chroot into the
image using `mkosi-chroot` (see below) before executing the script. For
example, if `mkosi.postinst.chroot` exists, mkosi will chroot into the
image and execute it as the post-installation script.

Scripts executed by mkosi receive the following environment variables:

* `$ARCHITECTURE` contains the architecture from the `Architecture=`
  setting. If `Architecture=` is not set, it will contain the native
  architecture of the host machine. See the documentation of
  `Architecture=` for possible values for this variable.

* `$QEMU_ARCHITECTURE` contains the architecture from `$ARCHITECTURE` in
   the format used by `qemu`. Useful for finding the qemu binary (
    `qemu-system-$QEMU_ARCHITECTURE`).

* `$DISTRIBUTION` contains the distribution from the `Distribution=` setting.

* `$RELEASE` contains the release from the `Release=` setting.

* `$DISTRIBUTION_ARCHITECTURE` contains the architecture from
  `$ARCHITECTURE` in the format used by the configured distribution.

* `$PROFILE` contains the profile from the `Profile=` setting.

* `$CACHED=` is set to `1` if a cached image is available, `0` otherwise.

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

* `$PACKAGEDIR` points to the directory containing the local package
  repository. Build scripts can add more packages to the local
  repository by writing the packages to `$PACKAGEDIR`.

* `$ARTIFACTDIR` points to the directory that is used to pass around build
  artifacts generated during the build and make them available for use by
  mkosi. This is similar to `PACKAGEDIR`, but is meant for artifacts that may
  not be packages understood by the package manager, e.g. initrds created by
  other initrd generators than mkosi. Build scripts can add more artifacts to
  the directory by placing them in `$ARTIFACTDIR`. Files in this directory are
  only available for the current build and are not copied out like the contents
  of `$OUTPUTDIR`.

  `mkosi` will also use certain subdirectories of an artifacts directory to
  automatically use their contents at certain steps. Currently the following
  two subdirectories in the artifact directory are used by mkosi:
  - `io.mkosi.microcode`: All files in this directory are used as microcode
    files, i.e. they are prepended to the initrds in lexicographical order.
  - `io.mkosi.initrd`: All files in this directory are used as initrds and
    joined in lexicographical order.

  It is recommend users of `$ARTIFACTDIR` put things for their own use in a
  similar namespaced directory, e.h. `local.my.namespace`.

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
  user that invoked mkosi.

* `$MKOSI_CONFIG` is a file containing a json summary of the settings of the
  current image. This file can be parsed inside scripts to gain access to all
  settings for the current image.

* `$IMAGE_ID` contains the identifier from the `ImageId=` or `--image-id=` setting.

* `$IMAGE_VERSION` contains the version from the `ImageVersion=` or `--image-version=` setting

Consult this table for which script receives which environment variables:

| Variable                    | `configure` | `sync` | `prepare` | `build` | `postinst` | `finalize` | `postoutput` | `clean` |
|-----------------------------|:-----------:|:------:|:---------:|:-------:|:----------:|:----------:|:------------:|:-------:|
| `ARCHITECTURE`              | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `QEMU_ARCHITECTURE`         | ✓           |        |           |         |            |            |              |         |
| `DISTRIBUTION`              | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `DISTRIBUTION_ARCHITECTURE` | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `RELEASE`                   | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `PROFILE`                   | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          |              | ✓       |
| `CACHED`                    |             | ✓      |           |         |            |            |              |         |
| `CHROOT_SCRIPT`             |             |        | ✓         | ✓       | ✓          | ✓          |              |         |
| `SRCDIR`                    | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `CHROOT_SRCDIR`             |             |        | ✓         | ✓       | ✓          | ✓          |              |         |
| `BUILDDIR`                  |             |        | ✓         | ✓       | ✓          | ✓          |              |         |
| `CHROOT_BUILDDIR`           |             |        |           | ✓       |            |            |              |         |
| `DESTDIR`                   |             |        |           | ✓       |            |            |              |         |
| `CHROOT_DESTDIR`            |             |        |           | ✓       |            |            |              |         |
| `OUTPUTDIR`                 |             |        |           | ✓       | ✓          | ✓          | ✓            | ✓       |
| `CHROOT_OUTPUTDIR`          |             |        |           | ✓       | ✓          | ✓          |              |         |
| `BUILDROOT`                 |             |        | ✓         | ✓       | ✓          | ✓          |              |         |
| `PACKAGEDIR`                |             |        | ✓         | ✓       | ✓          | ✓          |              |         |
| `ARTIFACTDIR`               |             |        | ✓         | ✓       | ✓          | ✓          |              |         |
| `WITH_DOCS`                 |             |        | ✓         | ✓       |            |            |              |         |
| `WITH_TESTS`                |             |        | ✓         | ✓       |            |            |              |         |
| `WITH_NETWORK`              |             |        | ✓         | ✓       | ✓          | ✓          |              |         |
| `SOURCE_DATE_EPOCH`         |             |        | ✓         | ✓       | ✓          | ✓          |              | ✓       |
| `MKOSI_UID`                 | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `MKOSI_GID`                 | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `MKOSI_CONFIG`              |             | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `IMAGE_ID`                  | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |
| `IMAGE_VERSION`             | ✓           | ✓      | ✓         | ✓       | ✓          | ✓          | ✓            | ✓       |

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

* For all of the supported package managers (`dnf`, `rpm`, `apt`, `dpkg`,
  `pacman`, `zypper`), scripts of the same name are put into `$PATH`
  that make sure these commands operate on the image's root directory
  with the configuration supplied by the user instead of on the host
  system. This means that from a script, you can do e.g.
  `dnf install vim` to install vim into the image.

  Additionally, `mkosi-install`, `mkosi-reinstall`, `mkosi-upgrade` and
  `mkosi-remove` will invoke the corresponding operation of the package
  manager being used to built the image.

* `git` is automatically invoked with `safe.directory=*` to avoid
  permissions errors when running as the root user in a user namespace.

* `useradd` and `groupadd` are automatically invoked with
  `--root=$BUILDROOT` when executed outside of the image.

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

* The **`mkosi.pkgmngr/`** directory or **`mkosi.pkgmngr.tar`** archive
  may be used to configure the package manager without the files being
  inserted into the image. If the files should be included in the image
  `mkosi.skeleton/` and `mkosi.skeleton.tar` should be used instead.

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

  ```ini
  [Partition]
  Type=esp
  Format=vfat
  CopyFiles=/boot:/
  CopyFiles=/efi:/
  SizeMinBytes=512M
  SizeMaxBytes=512M
  ```

  `05-bios.conf` (if we're building a BIOS bootable image):

  ```ini
  [Partition]
  # UUID of the grub BIOS boot partition which grubs needs on GPT to
  # embed itself into.
  Type=21686148-6449-6e6f-744e-656564454649
  SizeMinBytes=1M
  SizeMaxBytes=1M
  ```

  `10-root.conf`

  ```ini
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
subimage configurations from it and build each of them. Image
configurations can be either directories containing mkosi configuration
files or regular files with the `.conf` extension.

When image configurations are found in `mkosi.images/`, mkosi will build
the images specified in the `Dependencies=` setting of the main image
and all of their dependencies (or all of them if no images were
explicitly configured using `Dependencies=` in the main image
configuration). To add dependencies between subimages, the
`Dependencies=` setting can be used as well. Subimages are always built
before the main image.

When images are defined, mkosi will first read the main image
configuration (configuration outside of the `mkosi.images/` directory),
followed by the image specific configuration. Several "universal"
settings apply to the main image and all its subimages and cannot be
configured separately in subimages. The following settings are universal
and cannot be configured in subimages:

- `Architecture=`
- `BuildDirectory=`
- `BuildSources=`
- `BuildSourcesEphemeral=`
- `CacheDirectory=`
- `CacheOnly=`
- `Distribution=`
- `ExtraSearchPaths=`
- `Incremental=`
- `LocalMirror=`
- `Mirror=`
- `OutputDirectory=`
- `PackageCacheDirectory=`
- `PackageDirectories=`
- `Profile=`
- `ProxyClientCertificate=`
- `ProxyClientKey=`
- `ProxyExclude=`
- `ProxyPeerCertificate=`
- `ProxyUrl=`
- `Release=`
- `RepartOffline=`
- `Repositories=`
- `RepositoryKeyCheck=`
- `SandboxTrees=`
- `SourceDateEpoch=`
- `ToolsTree=`
- `ToolsTreeCertificates=`
- `UseSubvolumes=`
- `VerityCertificate=`
- `VerityKey=`
- `VerityKeySource=`
- `VolatilePackageDirectories=`
- `WithNetwork=`
- `WithTests`
- `WorkspaceDirectory=`

There are also settings which are passed down to subimages but can
be overridden. For these settings, values configured explicitly in
the subimage will take priority over values configured on the CLI or
in the main image config. Currently the following settings are passed
down to subimages but can be overridden:

- `ImageId=`
- `ImageVersion=`
- `SectorSize=`

Images can refer to outputs of images they depend on. Specifically,
for the following options, mkosi will only check whether the inputs
exist just before building the image:

- `BaseTrees=`
- `ExtraTrees=`
- `Initrds=`

To refer to outputs of a image's dependencies, simply configure any of
these options with a relative path to the output to use in the output
directory of the dependency. Or use the `%O` specifier to refer to the
output directory.

A good example on how to build multiple images can be found in the
[systemd](https://github.com/systemd/systemd/tree/main/mkosi.images)
repository.

# ENVIRONMENT VARIABLES

* `$MKOSI_LESS` overrides options for `less` when it is invoked by
  `mkosi` to page output.

* `$MKOSI_DNF` can be used to override the executable used as `dnf`.
  This is particularly useful to select between `dnf` and `dnf5`.

* `$EPEL_MIRROR` can be used to override the default mirror location
  used for the epel repositories when `Mirror=` is used. By default
  mkosi looks for the epel repositories in the `fedora` subdirectory of
  the parent directory of the mirror specified in `Mirror=`. For example
  if the mirror is set to `https://mirror.net/centos-stream` mkosi will
  look for the epel repositories in `https://mirror.net/fedora/epel`.

* `SYSEXT_SCOPE` and `CONFEXT_SCOPE` can be used to override the default
  value of the respecive `extension-release` file when building a sysext
  or confext. By default the value is set to `initrd system portable`.

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
or shut down the machine quickly. Alternatively the machine can be shut down
using `Ctrl-a x`.

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

mkosi is packaged for various distributions: Debian, Kali, Ubuntu, Arch
Linux, Fedora Linux, OpenMandriva, Gentoo. Note that it has been a while
since the last release and the packages shipped by distributions are
very out of date. We currently recommend running mkosi from git until a
new release happens.

mkosi currently requires systemd 254 to build bootable disk images.

When not using distribution packages make sure to install the
necessary dependencies. For example, on *Fedora Linux* you need:

```bash
# dnf install btrfs-progs apt dosfstools mtools edk2-ovmf e2fsprogs squashfs-tools gnupg python3 tar xfsprogs xz zypper sbsigntools
```

On Debian/Kali/Ubuntu it might be necessary to install the `ubuntu-keyring`,
`ubuntu-archive-keyring`, `kali-archive-keyring` and/or `debian-archive-keyring`
packages explicitly, in addition to `apt`, depending on what kind of distribution
images you want to build.

Note that the minimum required Python version is 3.9.

# Frequently Asked Questions (FAQ)

- Why does `mkosi qemu` with KVM not work on Debian/Kali/Ubuntu?

  While other distributions are OK with allowing access to `/dev/kvm`, on
  Debian/Kali/Ubuntu this is only allowed for users in the `kvm` group. Because
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

- How do I add a regular user to an image?

  You can use the following snippet in a post-installation script:

  ```sh
  useradd --create-home --user-group $USER --password "$(openssl passwd -stdin -6 <$USER_PASSWORD_FILE)"
  ```

  Note that from systemd v256 onwards, if enabled,
  `systemd-homed-firstboot.service` will prompt to create a regular user
  on first boot if there are no regular users.

- Why do I see failures to chown files when building images?

  When not running as root, your user is not able to change ownership of
  files to arbitrary owners. Various distributions still ship files in their
  packages that are not owned by the root user. When not running as root, mkosi
  maps the current user to root when invoking package managers, which means that
  changing ownership to root will work but changing ownership to any other user
  or group will fail.

  Note that chown calls are only suppressed when running package managers, but
  not when running scripts. If this is required, e.g. for a build script, you
  can set the `MKOSI_CHROOT_SUPPRESS_CHOWN` variable to a true value (`1`,
  `yes`, `true`) to suppress chown calls in `mkosi-chroot` and `.chroot` scripts.

  If this behavior causes applications running in your image to misbehave, you
  can consider running `mkosi` as root which avoids this problem. Alternatively,
  if running `mkosi` as root is not desired, you can use
  `unshare --map-auto --map-current-user --setuid 0 --setgid 0` to become root in
  a user namespace with more than one user assuming the UID/GID mappings in
  `/etc/subuid` and `/etc/subgid` are configured correctly. Note that running mkosi
  as root or with `unshare` means that all output files produced by mkosi will not
  be owned by your current user anymore.

  Note that for systemd services that need directories in `/var` owned by the service
  user and group, an alternative to shipping these directories in packages or
  creating them via systemd-tmpfiles is to use `StateDirectory=`, `CacheDirectory=` or
  `LogsDirectory=` in the service file which instructs systemd to create the directory
  when it first starts the service.

  Alternatively, the `z` or `Z` directives for `systemd-tmpfiles` can be used to chown
  various directories and files to their owning user when the system first boots up.

# REFERENCES
* [Primary mkosi git repository on GitHub](https://github.com/systemd/mkosi/)
* [mkosi — A Tool for Generating OS Images](https://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html) introductory blog post by Lennart Poettering
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN

# SEE ALSO
`systemd-nspawn(1)`, `dnf(8)`
