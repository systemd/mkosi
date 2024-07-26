# mkosi Changelog

## v24

- The default kernel command line of `console=ttyS0` (or equivalent for
  other architectures) has been removed. The required `console=`
  argument to have the kernel output to the serial console has to be
  added manually from `v24` onwards.
- Support for installing local packages located in directories in
  `BuildSources=` was dropped. Instead, the packages can be made
  available for installation via `PackageManagerTrees=`.
- Configuration parsing was reworked to remove the need for the `@`
  specifier and to streamline building multiple images with
  `mkosi.images/`. If you were building multiple images with
  `mkosi.images/`, you'll need to adapt your configuration to the
  rework. Read the **Building multiple images** section in the
  documentation for more information.
- mkosi has gained the option to generate completion scripts for bash,
  fish and zsh. Packagers should generate the scripts during packaging
  and ship them in the appropriate places.
- Added support for CentOS Stream 10.
- mkosi now installs a separate `mkosi-initrd` script that can be used
  to build initramfs images intended for use on the local system.
- We do not automatically append `centos-stream` or `fedora` anymore to
  CentOS (and derivatives) and Fedora mirrors specified with `Mirror=`
  as not all mirrors store the repository metadata under these
  subdirectories. Users are now required to add these subdirectories
  themselves in `Mirror=`. If the EPEL repositories are enabled for
  CentOS Stream (and derivatives) and `Mirror=` is used, we look for the
  EPEL repositories in `../fedora` relative to the mirror specified in
  `Mirror=`.
- We now support compressed tar archives wherever we already accept tar
  archives as input.
- We now always rerun the build if `Format=none` and don't remove
  previous outputs in that case (unless `--force` is specified). This
  allows using `mkosi -t none` to rerun the build scripts without
  removing the previous image. This can then be combined with
  `RuntimeBuildSources=yes` to make the build script outputs available
  in a booted container or virtual machine so they can be installed
  without having to rebuild the image.
- We now use `virtconsole` to provide the serial console when booting
  with `qemu`.
- `root=PARTUUID` and `mount.usr=PARTUUID` on the kernel command line
  are now automatically extended with the actual PARTUUID of the
  corresponding partition.
- All available OpenSUSE repositories are now supported and can be
  enabled with `Repositories=`.
- Building OpenSUSE `aarch64` images is now supported
- `mkosi dependencies` was beefed up to handle more scenarios properly
- The default list of kernel modules that are always added to the
  initramfs was extended with various virtualization modules.
- Added a `Repositories=` match.
- Cached images are now invalidated if packages specified via
  `PackageDirectories=` change.
- Added `VolatilePackageDirectories=` which can be used to provide local
  packages that do not invalidate cached images.
- `mkosi.pkgmngr` is now used as the default path for
  `PackageManagerTrees=`.
- The package directory that build scripts can use to make built
  packages available for installation (`$PACKAGEDIR`) is now shared
  between all image builds. This means that packages built in earlier
  images and stored in `$PACKAGEDIR` become available for installation
  in all subsequent image builds.
- The default tools tree distribution is now chosen based on the host
  distribution instead of the target distribution.
- mkosi can now be invoked from the initramfs.


## v23.1

- Respin due to git tag mismatch

## v23

- Added `CleanScripts=` to allow running custom cleanup code whenever
  mkosi cleans up the output directory. This allows cleaning up extra
  outputs produced by e.g. a build script that mkosi doesn't know about.
- Added `ConfigureScripts=` to allow dynamically modifying the mkosi
  configuration. Each configure script receives the current config as
  JSON on stdin and should output the new config as JSON on stdout.
- When building a UKI, we don't measure for the TPM SHA1 PCR bank
  anymore.
- All keys in the mkosi config JSON output are now in pascal case,
  except for credentials and environments, where the keys encode names
  of credentials and environment variables and are therefore case
  sensitive.
- Added various settings to allow running mkosi behind a proxy.
- Various fixes to kernel module filtering that should result in fewer
  modules being pulled into the default initrd when
  `KernelModulesExclude=` or `KernelModulesInitrdExclude=` are used.
- Added `ToolsTreeDistribution=` match.
- Removed `vmspawn` verb and replaced it with `VirtualMachineMonitor=`.
- New specifiers for various directories were added. `%D` resolves to
  the directory that mkosi was invoked in, `%P` to the current working
  directory, and `%C` to the parent directory of the config file.
- Added `ForwardJournal=` to have systemd inside a container/VM forward
  its journal to the specified file or directory.
- Systemd scopes are now allocated for qemu, swtpm, virtiofsd and
  systemd-journal-remote if available.
- The `mkosi qemu` virtual machine is now registered with
  systemd-machined if available.
- Added new `oci` output format
- Runtime trees without a target are now mounted to `/root/src` instead
  of a subdirectory of it (To have the same behaviour as
  `BuildSources=`).
- Added `RuntimeBuildSources=` to mount build and source directories
  when booting the image with `mkosi nspawn` or `mkosi qemu`.
- Introduced `--append` to allow command line settings to be parsed
  after parsing configuration files.
- `distribution-release` is not installed by default anymore on
  OpenSUSE.
- Setting `QemuSmp=` to `0` will now make qemu use all available CPUs
- Free page reporting and discard request processing are now enabled by
  default in VMs spawned by `mkosi qemu`.
- Added `ToolsTreeCertificates=` to allow configuring whether to use
  certificates and keys from the tools tree (if one is used) or the
  host.
- Added `never` for `CacheOnly=` to specify that repository metadata
  should always be refreshed.
- Renamed the `none` option for `CacheOnly=` to `auto`.
- Added `ProxyExclude=` to configure hostnames for which requests should
  not go through the configured proxy.
- The default tools tree is now reused on incremental builds.
- Added `VolatilePackages=` and `InitrdVolatilePackages=` to configure
  packages that should be installed after executing build scripts and
  which should not be cached when using `Incremental=`.
- `PackageDirectories=` now has an associated default path
  `mkosi.packages`.
- `reprepro` is now used to generate local apt repositories.
- Support for BSD tar/cpio was dropped.
- When both `ExtraSearchPaths=` and `ToolsTree=` are used, mkosi will
  now prefer running a binary found in `ExtraSearchPaths=` without the
  tools tree over running the binary from the tools tree. If a binary is
  not found in `ExtraSearchPaths=`, the tools tree is used instead.
- An artifact directory is now made available when running scripts which
  can be used to pass around data between different scripts. mkosi will
  also look for microcode and initrds in the artifact directory under
  the `io.mkosi.microcode` and `io.mkosi.initrd` subdirectories.
- Added `Environment=` match setting to check for environment variables
  defined with the `Environment=` setting.
- The `basesystem` package is now always installed in Fedora and
  CentOS images instead of the `filesystem` package.
- The `qemu`, `shell` and `boot` verbs do not automatically build the
  image anymore unless `--force` is specified.
- `SplitArtifacts=` is now supported for the portable, sysext and
  confext outputs.
- The `WithDocs=` option was implemented for pacman-based distributions.
- The default Fedora release was bumped to 40.
- `QemuSwtpm=` can now be used with `QemuFirmware=` set to `linux` or
  `bios`.
- Added `UnitProperties=` to allow configure properties on the scopes
  generated by `systemd-nspawn` and `systemd-run`.
- mkosi now only builds a single default tools tree per build using the
  settings from the last regular image that we'll build.
- Configure scripts are now only executed for verbs which imply an image
  build and are executed with the tools tree instead of without it.
- `$QEMU_ARCHITECTURE` is now set for configure scripts to easily allow
  scripts to figure out which qemu binary will be used to run qemu.
- A file ID can now be specified for `QemuDrives=`. This allows adding
  multiple qemu drives that are backed by the same file.
- mkosi doesn't fail anymore if images already exist when running
  `mkosi build`.
- Image names from `mkosi.images/` are now preferred over the specified
  image ID when determining the output filename to use for an image.
- `--include` now has a shorthand option `-I`.
- The `WITH_NETWORK` environment variable is now passed to build and
  finalize scripts.
- We now clamp mtimes to the specified source date epoch timestamp
  instead of resetting all mtimes. This means that we won't touch any
  mtimes that are already older than the given source date epoch
  timestamp.
- Removed support for CentOS 8 Stream as it is now EOL.
- The `coredumpctl` and `journalctl` verbs now operrate on the path
  specified in `ForwardJournal=` if one is set.
- Added `UnifiedKernelImageFormat=` format setting to allow configuring
  the naming of unified kernel images generated by mkosi.
- The `versionlock` plugin is now enabled by default for dnf with a noop
  configuration.
- `Repositories=` is now implemented for zypper.
- `KernelModulesInclude=` and `KernelModulesInitrdInclude=` now take the
  special values `host` and `default` to include the host's loaded
  modules and the default kernel modules defined in `mkosi-initrd`
  respectively.
- `KernelModulesIncludeHost=` and `KernelModulesInitrdIncludeHost=` are
  now deprecated.
- Added `mkosi dependencies` to output the list of packages required by
  mkosi to build and boot images.

## v22

- We'll now try to delete btrfs subvolumes with `btrfs subvolume delete`
  first before falling back to recursively deleting the directory.
- The invoking user is now always mapped to `root` when running sync
  scripts. This fixes an issue where we would fail when a package
  manager tree or skeleton tree contained a `/usr` directory as we would
  not have permissions to run mount in the sandbox.
- We now use qemu's official firmware descriptions to find EDK2/OVMF
  UEFI firmware. Addititionally, `QemuFirmware=uefi` now boots without
  SecureBoot support, and `QemuFirmware=uefi-secure-boot` was introduced
  to boot with SecureBoot support. By default we will still boot with
  SecureBoot support if `QemuFirmware=auto`.
- Added support for `QemuFirmwareVariables=custom` and
  `QemuFirmwareVariables=microsoft` to use OVMF/EDK2 variables with
  either the user's custom keys enrolled or with the Microsoft keys
  enrolled.
- Added `UnifiedKernelImages=` to control whether we generate unified
  kernel images or not.
- `Bootloader=grub` will now generate a grub EFI image and install it.
  If `SecureBoot=` is enabled and `ShimBootloader=` is not set to
  `signed`, the grub EFI image will be signed for SecureBoot.
- `ShimBootloader=signed` will now also instruct mkosi to look for and
  install already signed grub, systemd-boot, kernel and UKI binaries.
- We now build grub images with a fixed set of modules and don't copy
  any grub modules to the ESP anymore.
- The configuration is now made available as a JSON file to all mkosi
  scripts via the `$MKOSI_CONFIG` environment variable.
- `$PROFILE` is now set for all mkosi scripts containing the value of
  `Profile=` if it is set.

## v21

- We now handle unmerged-usr systems correctly
- Builtin configs (`mkosi-initrd`, `mkosi-tools`) can now be included
  using `Include=` (e.g. `Include=mkosi-initrd`)
- The kernel-install plugin now uses the builtin `mkosi-initrd` config
  so there's no need anymore to copy the full `mkosi-initrd` config into
  `/usr/lib/mkosi-initrd`.
- We don't require a build anymore for the `journalctl` and
  `coredumpctl` verbs.
- `mkosi ssh` works again when used with `ToolsTree=default`
- We now use `.zst` instead of `.zstd` for compressed split artifacts
  produced by `systemd-repart`.
- `systemd-repart` uses a persistent temporary directory again for
  assembling images instead of a tmpfs.
- Added `MicrocodeHost=` setting to only include the CPU specific
  microcode for the current host system.
- The kernel-install plugin now only includes the CPU specific microcode
- Introduced `PackageCacheDirectory=` to set the directory for package
  manager caches. This setting defaults to a suitable location in the
  system or user directory depending on how mkosi is invoked.
  `CacheDirectory=` is only used for incremental cached images now.
- Repository metadata is now synced once at the start of each image
  build and never during an image build. Each image includes a snapshot
  of the repository metadata in the canonical locations in `/var` so
  that incremental images and extension images can reuse the same
  snapshot. When building an image intended to be used with
  `BaseTrees=`, disable `CleanPackageMetadata=` to make sure the
  repository metadata in `/var` is not cleaned up, otherwise any
  extension images using this image as their base tree will not be able
  to install additional packages.
- Implemented `CacheOnly=metadata`. Note that in the JSON output, the
  value of `CacheOnly=` will now be a string instead of a boolean.
- Added `CompressLevel=` to set the compression level to use.
- Dropped experimental Gentoo support.
- Added `TriggerMatch=` to specify multiple match sections of which only
  one should be satisfied.
- Added `jq`, `attr`, `acl`, `git`, `sed`, `grep` and `findutils` to
  the default tools tree.
- Added `mkosi-install`, `mkosi-upgrade`, `mkosi-remove` and
  `mkosi-reinstall` scripts which allow writing scripts that are
  independent of the package manager being used to build the image.
- We now expand specifiers in `Match` section values
- Made GPG key handling for Fedora rawhide more robust
- If systemd-repart 256 or newer is available, mkosi will instruct it
  to generate `/etc/fstab` and `/etc/crypttab` for the image if any
  partition definitions contain the corresponding settings
  (`MountPoint=` and `EncryptedVolume=`).
- `bash` is now started in the debug shell instead of `sh`.
- The default release for Ubuntu is now `noble`.
- Ubuntu is now used as the default tools tree distribution for Ubuntu
  instead of Debian.
- Added `mkosi vmspawn` which boots the image with `systemd-vmspawn`.
  Note that `systemd-vmspawn` is experimental and its interface may
  still change. As such `mkosi vmspawn` is also considered experimental.
  Note that `systemd-vmspawn` version `256` or newer is required.
- Added `SyncScripts=` which can be used to update various build sources
  before starting the image build.
- The `DISTRIBUTION=` and `RELEASE=` environment variables are now set
  when running scripts.
- Added `ToolsTreeRepositories=` and `ToolsTreePackageManagerTrees=`.
- Added `RuntimeNetwork=` to configure the networking used when booting
  the image.
- Added `SecureBootKeySource=` and `VerityKeySource=` to support signing
  images with OpenSSL engines. Note that these settings require various
  systemd tools to be version `256` or newer.
- We don't clean up package manager metadata anymore unless explicitly
  requested with `CleanPackageManagerMetadata=yes` when building
  `directory` and `tar` images.

## v20.2

- Fixed a bug in signing unsigned shim EFI binaries.
- We now build an early microcode initrd in the mkosi kernel-install
  plugin.
- Added `PackageDirectories=` to allow providing extra packages to be
  made available during the build.
- Fixed issue where `KernelModulesIncludeHost` was including unnecessary
  modules
- Fixed `--mirror` specification for CentOS (and variants) and Fedora.
  Previously a subdirectory within the mirror had to be specified which
  prevented using CentOS and EPEL repositories from the same mirror. Now
  only the URL has be specified.
- We now mount package manager cache directories when running scripts on
  the host so that any packages installed in scripts are properly
  cached.
- We don't download filelists on Fedora anymore
- Nested build sources don't cause errors anymore when trying to install
  packages.
- We don't try to build the same tools tree more than once anymore when
  building multiple images.
- We now create the `/etc/mtab` compatibility symlink in mkosi's
  sandbox.
- We now always hash the root password ourselves instead of leaving it
  to `systemd-firstboot`.
- `/srv` and `/mnt` are not mounted read-only anymore during builds.
- Fixed a crash when running mkosi in a directory with fewer than two
  parent directories.
- Implemented `RepositoryKeyCheck=` for apt-based distributions.

## v20.1

- `BuildSources=` are now mounted when we install packages so local
  packages can be made available in the sandbox.
- Fixed check to see if we're running as root which makes sure we don't
  do shared mounts when running as root.
- The extension release file is now actually written when building
  system or configuration extensions.
- The nspawn settings are copied to the output directory again.
- Incremental caching is now skipped when `Overlay=` is enabled as this
  combination isn't supported.
- The SELinux relabel check is more granular and now checks for all
  required files instead of just whether there's a policy configured.
- `qemu-system-xxx` binaries are now preferred over the generic `qemu`
  and `qemu-kvm` binaries.
- Grub tools from the tools tree are now used to install grub instead of
  grub tools from the image itself. The grub tools were added to the
  default tools trees as well.
- The pacman keyring in tools trees is now only populated from the
  Arch Linux keyring (and not the Debian/Ubuntu ones anymore).
- `gpg` is allowed to access `/run/pscsd/pscsd.comm` on the host if it
  exists to allow interaction with smartcards.

## v20

- The current working directory is not mounted unconditionally to
  `/work/src` anymore. Instead, the default value for `BuildSources=`
  now mounts the current working directory to `/work/src`. This means
  that the current working directory is no longer implicitly included
  when `BuildSources=` is explicitly configured.
- Assigning the empty string to a setting that takes a list of values
  now overrides any configured default value as well.
- The github action does not build and install systemd from source
  anymore. Instead, `ToolsTree=default` can be used to make sure a
  recent version of systemd is used to do the image build.
- Added `EnvironmentFiles=` to read environment variables from
  environment files.
- We drastically reduced how much of the host system we expose to
  scripts. Aside from `/usr`, a few directories in `/etc`, `/tmp`,
  `/var/tmp` and various directories configured in mkosi settings, all
  host directories are hidden from scripts, package managers and other
  tools executed by mkosi.
- Added `RuntimeScratch=` to automatically mount a directory with extra
  scratch space into mkosi-spawned containers and virtual machines.
- Package manager trees can now be used to configure every tool invoked
  by mkosi while building an image that reads config files from `/etc`
  or `/usr`.
- Added `SELinuxRelabel=` to specify whether to relabel selinux files
  or not.
- Many fixes to tools trees were made and tools trees are now covered by
  CI. Some combinations aren't possible yet but we're actively working
  to make these possible.
- `mkosi qemu` now supports direct kernel boots of `s390x` and `powerpc` images.
- Added `HostArchitecture=` match to match against the host
  architecture.
- We don't use the user's SSH public/private keypair anymore for
  `mkosi ssh` but instead use a separate key pair which can be
  generated by `mkosi genkey`. Users using `mkosi ssh` will have to run
  `mkosi genkey` once to generate the necessary files to keep
  `mkosi ssh` working.
- We don't automatically set `--offline=no` anymore when we detect the
  `Subvolumes=` setting is used in a `systemd-repart` partition
  definition file. Instead, use the new `RepartOffline=` option to
  explicitly disable running `systemd-repart` in offline mode.
- During the image build we now install UKIs/kernels/initrds to `/boot`
  instead of `/efi`. While this will generally not be noticeable, users
  with custom systemd-repart ESP partition definitions will need to add
  `CopyFiles=/boot:/` along with the usual `CopyFiles=/efi:/` to their
  ESP partition definitions. By installing UKIs/kernels/initrds to
  `/boot`, it becomes possible to use `/boot` to populate an XBOOTLDR
  partition which wasn't possible before. Note that this is also safe to
  do before `v20` so `CopyFiles=/boot:/` can unconditionally be added to
  any ESP partition definition files.
- Added `QemuFirmwareVariables=` to allow specifying a custom OVMF
  variables file to use.
- Added `MinimumVersion=` to allow specifying the minimum required mkosi
  version to build an image.
- Added support for Arch Linux's debug repositories.
- Merged the mkosi-initrd project into mkosi itself. mkosi-initrd is now
  used to build the default initrd.
- Implemented mkosi-initrd for all supported distributions.
- Added `ShimBootloader=` to support installing shim to the ESP.
- Added sysext, confext and portable output formats. These will produce
  signed disk images that can be used as sysexts, confexts and portable
  services respectively.
- Added `QemuVsockConnectionId=` to configure how to allocate the vsock
  connection ID when `QemUVsock=` is enabled.
- Added documentation on how to build sysexts with mkosi.
- Global systemd user presets are now also configured.
- Implemented `WithDocs=` for `apt`.
- On supported package managers, locale data for other locales is now
  stripped if the local is explicitly configured using `Locale=`.
- All `rpm` plugins are now disabled when building images.
- Added `KernelModulesIncludeHost=` and
  `KernelModulesInitrdIncludeHost=` to only include modules loaded on
  the host system in the image/initrd respectively.
- Implemented `RemovePackages=` for Arch Linux.
- Added `useradd` and `groupadd` scripts to configure these binaries to
  operate on the image during builds instead on the host.
- Added microcode support. If installed into the image, an early
  microcode initrd will automatically be built and prepended to the
  initrd.
- A passwordless root account may now be created by specifying `hashed:`.
- The `Autologin=` feature was extended with support for `arm64`,
  `s390x` and `powerpc` architectures.
- Added `SecureBootAutoEnroll=` to control automatic enrollment of secureboot
  keys separately from signing `systemd-boot` and generated UKIs.
- `ImageVersion=` is no longer automatically appended to the output files,
  instead this is automatically appended to `Output=` if not specified and
  results in the `%o` specifier being equivalent to `%i` or `%i_%v` depending
  on whether `ImageVersion=` is specified.

## v19

- Support for RHEL was added!
- Added `journalctl` and `coredumpctl` verbs for running the respective
  tools on built directory or disk images.
- Added a `burn` verb to write the output image to a block device.
- Added a new `esp` output format, which is largely similar to the existing
  `uki` output format but wraps it in a disk image with only an ESP.
- `Presets` were renamed to `Images`. `mkosi.images/` is now used
  instead of `mkosi.presets/`,  the `Presets=` setting was renamed
  to `Images=` and the `Presets` section was merged into the `Config`
  section. The old names can still be used for backwards compatibility.
- Added profiles to support building variants of the same image in one
  repository. Profiles can be defined in `mkosi.profiles/` and one can
  be selected using the new `Profile=` setting.
- mkosi will now parse `mkosi.local.conf` before any other config files
  if that exists.
- Added a kernel-install plugin. This is only shipped in source tree and not
  included in the Python module.
- Added a `--json` option to get the output of `mkosi summary` as JSON.
- Added shorthand `-a` for `--autologin`.
- Added a `--debug-workspace` option to not remove the workspace directory
  after a build. This is useful to inspect the workspace after failing
  builds. As a consequence the prefix for the default workspace directory
  prefix has been changed from `.mkosi-tmp` to `mkosi-workspace`.
- Scripts with the `.chroot` extension are now executed in the image
  automatically.
- Added `rpm` helper script to have `rpm` automatically operate on the
  image when running scripts.
- Added `mkosi-as-caller` helper script that can be used in scripts to
  run commands as the user invoking mkosi.
- `mkosi-chroot` will now start a shell if no arguments are specified.
- Added `WithRecommends=` to configure whether to install recommended packages
  by default or not where this is supported. It is disabled by default.
- Added `ToolsTreeMirror=` setting for configuring the mirror to use for the
  default tools tree.
- `WithDocs=` is now enabled by default.
- Added `BuildSourcesEphemeral=` to make source directories ephemeral
  when running scripts. This means any changes made to source
  directories while running scripts will be undone after the scripts
  have finished executing.
- Added `QemuDrives=` to have mkosi create extra qemu drives and pass
  them to qemu when using the `qemu` verb.
- Added `BuildSources=` match to match against configured build source
  targets.
- `PackageManagerTrees=` was moved to the `Distribution` section.
- We now automatically configure the qemu firmware, kernel cmdline and
  initrd based on what type of kernel is passed by the user via
  `-kernel` or `QemuKernel=`.
- The mkosi repository itself now ships configuration to build basic
  bootable images that can be used to test mkosi.
- Added support for enabling `updates-testing` repositories for Fedora.
- GPG keys for CentOS, Fedora, Alma and Rocky are now looked up locally
  first before fetching them remotely.
- Signatures are not required for local packages on Arch anymore.
- Packages on opensuse are now always downloaded in advance before
  installation when using zypper.
- The tar output is now reproducible.
- We now make sure `git` can be executed from mkosi scripts without
  running into permission errors.
- We don't create subdirectories beneath the configured cache directory
  anymore.
- Workspace directories are now created outside of any source
  directories. mkosi will either use `XDG_CACHE_HOME`, `$HOME/.cache` or
  `/var/tmp` depending on the situation.
- Added environment variable `MKOSI_DNF` to override which dnf to use
  for building images (`dnf` or `dnf5`).
- The rootfs can now be modified when running build scripts (with all
  changes thrown away after the last build script has been executed).
- mkosi now fails if configuration specified via the CLI does not apply
  to any image (because it is overridden).
- Added a new doc on building rpms from source with mkosi
  (`docs/building-rpms-from-source.md`).
- `/etc/resolv.conf` will now only be mounted for scripts when they are run
  with network access.

## v18

- `$SCRIPT` was renamed to `$CHROOT_SCRIPT`. `$SCRIPT` can still be used
  but is considered deprecated.
- Added `RuntimeTrees=` setting to mount directories when booting images
  via `mkosi boot`, `mkosi shell` or `mkosi qemu`. The directories are
  mounted with a uid map that maps the user invoking mkosi to the root
  user so that all files in the directory appear as if owned by the root
  user in the container or virtual machine and any new files created in
  the directories are owned by the user invoking mkosi. To make this
  work in VMs, we use `VirtioFS` via `virtiofsd`. Note that this
  requires systemd v254 or newer to be installed in the image.
- Added support for booting directory images with `mkosi qemu` via
  `VirtioFS`. When `CONFIG_VIRTIOFS` and `CONFIG_VIRTIO_PCI` are builtin
  modules, no initramfs is required to make this work.
- Added `Include=` or `--include` to include extra configuration files
  or directories.
- Added support for specifiers to access the current value of certain
  settings during configuration file parsing.
- `mkosi` will now exit with an error when no configuration was
  provided.
- Multiple scripts of the same type are now supported.
- Custom distributions are now supported via the new `custom`
  distribution. When using `custom` as the distribution, the rootfs must
  be provided via base trees, skeleton trees or prepare scripts.
- We now use local GPG keys for rpm based distributions if the
  `distribution-gpg-keys` package is installed on the host.
- Added `RuntimeSize=` to grow the image to a specific size before
  booting it when using `mkosi boot` or `mkosi qemu`.
- We now set `MKOSI_UID` and `MKOSI_GID` when running scripts which are
  set to the uid and gid of the user invoking mkosi respectively. These
  can be used to run commands as the user that invoked mkosi.
- Added an `Architecture=` match
- Initrds specified with `Initrds=` are now used for grub menuentries as
  well.
- `ImageId=` and `ImageVersion=` are now written to os-release as
  `IMAGE_ID` and `IMAGE_VERSION` if provided.
- We pass command line arguments passed to the `build` verb to the build
  script again.
- We added support for the "RHEL Universal Base Image" distribution.

## v17.1

- Fixed bug where `--autologin` was broken when used in combination with
  a tools tree when using a packaged version of mkosi.

## v17

- Added `ToolsTreePackages=` to add extra packages to the default tools
  tree.
- Added `SystemdVersion=` match to match on the host's systemd version
- Added `Format=` match to match on the configured output format
- `Presets=` can now be configured in global configuration files to select
  which presets to build
- UKIs can now be booted using direct linux boot.
- We don't try to make images UEFI bootable anymore on architectures
  that do not support UEFI
- Fixed `--help` to show all options again
- We now warn when settings are configured in the wrong section

## v16

- `mkosi.version` is now picked up from preset and dropin directories as
  well following the usual config precedence logic
- Removed the "first assignment wins" logic from configuration parsing.
  Settings parsed later will now override earlier values
- Removed the `!` operator for lists. Instead, assign the empty string
  to the list to remove all previous values.
- Added support for configuring custom default values for settings by
  prefixing their name in the configuration file with `@`.
- Added `QemuCdrom=` to attach the image to the virtual machine as a
  CD-ROM instead of a block device.
- Added `SectorSize=` to set the sector size of the disk images built by
  systemd-repart.
- Added back grub support (BIOS/UEFI). Note that we don't install grub
  on UEFI yet but we do add the necessary configuration and partitions.
- Added `Bootloader=` option to configure which EFI bootloader to
  install. Added `uki` option to install just the UKI without
  systemd-boot and `grub` to generate grub configuration to chainload
  into the built UKIs.
- Added `BiosBootloader=` to configure whether grub for BIOS gets
  installed or not.
- Added `QemuFirmware=` to select which qemu firmware to use (OVMF,
  Seabios or direct kernel boot).
- Added `QemuKernel=` to specify the kernel that should be used with
  direct kernel boot.
- `/var/lib/dbus/machine-id` is now removed if it was added by a package
  manager postinstall script.
- The manifest is not generated by default anymore. Use
  `ManifestFormat=json` to make sure the manifest is generated.
- Added `SourceDateEpoch=` to enable more reproducible image builds.
- Added `Seed=` to set the seed passed to systemd-repart.
- Updated the default Fedora release to Fedora 39.
- If `ToolsTree=` is set to `default`, mkosi will now build a default
  tools tree containing all the necessary tools to build images. The
  distribution and release to use can be configured with
  `ToolsTreeDistribution=` and `ToolsTreeRelease=` or are determined
  automatically based on the image being built.
- Added `uki` output format. This is similar to `cpio`, except the cpio
  is packaged up as a UKI with a kernel image and stub picked up from
  the rootfs.

## v15.1

- The man page can be generated from the markdown file via
  `tools/make-man-page.sh`.
- Fixed issue where not all packages and data files where included in
  the generated python package.
- mkosi doesn't try to unshare the network namespace anymore when it
  doesn't have `CAP_NET_ADMIN`.
- Fixed issue when the workspace was located in `/tmp`.
- Don't try to run `timedatectl` or `ssh-add` when they're not installed.

## v15

- Migrated to systemd-repart. Many options are dropped in favor of specifying them directly
  in repart partition definition files:
    - Format=gpt_xxx options are replaced with a single "disk" options. Filesystem to use can now be specified with repart's Format= option
    - Format=plain_squashfs (Can be reproduced by a single repart squashfs
    root partition combined with SplitArtifacts=yes)
    - Verity= (Replaced by repart's Verity= options)
    - Encrypt= (Replaced by repart's Encrypt= option)
    - RootSize=, HomeSize=, VarSize=, TmpSize=, ESPSize=, SwapSize=, SrvSize=
    (Replaced by repart's size options)
    - UsrOnly= (replaced with `CopyFiles=/:/usr` in a usr partition definition)
    - OutputSplitRoot=, OutputSplitVerity=, (Replaced by repart's SplitName= option)
    - OutputSplitKernel= (UKI is now always written to its own output file)
    - GPTFirstLBA (Removed, no equivalent in repart)
    - ReadOnly= (Replaced by repart's ReadOnly= option per partition)
    - Minimize= (Replaced by repart's Minimize= option per partition)
    - CompressFs= (No equivalent in repart, can be replicated by replacing mkfs.<fs>
    in $PATH with a script that adds the necessary command line option)
    - MkSquashfs= (Can be replaced with a script in $PATH that invokes
    the correct binary)

    We also remove the WithoutUnifiedKernelImages= switch as building unified
    kernel images is trivial and fast these days.
- Support for --qemu-boot was dropped
- Support for --use-host-repositories was dropped, use --repository-directory instead
- `RepositoryDirectory` was removed, use `PackageManagerTrees=` or `SkeletonTrees=` instead.
- `--repositories` is now only usable on Debian/RPM based distros and can only be used to enable additional
  repositories. Specifically, it cannot be used on Arch Linux anymore to add new repositories.
- The `_epel` distributions were removed. Use `--repositories=epel` instead to enable
  the EPEL repository.
- Removed `-stream` from CentOS release specifiers. Instead of specifying `8-stream`,
  you know just specify `8`.
- Removed default kernel command line arguments `rhgb`, `selinux=0` and `audit=0`.
- Dropped --all and --all-directory as this functionality is better implemented by
  using a build system.
- mkosi now builds images without needing root privileges.
- Removed `--no-chown`, `--idmap` and `--nspawn-keep-unit` options as they were made obsolete by moving to
  rootless builds.
- Removed `--source-file-transfer`, `--source-file-transfer-final`, `--source-resolve-symlinks` and
  `--source-resolve-symlinks-final` in favor of always mounting the source directory into the build image.
  `--source-file-transfer-final` might be reimplemented in the future using virtiofsd.
- Dropped `--include-dir` option. Usage can be replaced by using `--incremental` and reading includes from
  the cached build image tree.
- Removed `--machine-id` in favor of shipping images without a machine ID at all.
- Removed `--skip-final-phase` as we only have a single phase now.
- The post install script is only called for the final image now and not for the build image anymore. Use the
  prepare script instead.
- `--ssh-key`, `--ssh-agent`, `--ssh-port` and `--ssh-timeout` options were dropped as the SSH support was
  reimplemented using VSock. `mkosi ssh` can only be used with images booted with `mkosi qemu`. Use
  `machinectl` to access images booted with `mkosi boot`. Use --extra-tree or --credential with the
  `.ssh.authorized_keys.root` credentials as alternatives for provisioning the public key inside the image.
- Only configuration files matching `*.conf` are parsed in dropin directories now.
- Removed `--qemu-headless`, we now start qemu in the terminal by default and configure the serial console at
  runtime. Use the new `--qemu-gui` option to start qemu in its graphical interface.
- Removed `--netdev`. Can be replaced by manually installing systemd-networkd, putting a network file in the
  image and enabling systemd-networkd.
- If `mkosi.extra/` or `mkosi.skeleton/` exist, they are now always used instead of only when no explicit
  extra/skeleton trees are defined.
- mkosi doesn't install any default packages anymore aside from packages required by the distro or the base
  filesystem layout package if there are no required packages. In practice, this means systemd and other
  basic tools have to be installed explicitly from now on.
- Removed `--base-packages` as it's not needed anymore since we don't install any packages by default anymore
  aside from the base filesystem layout package.
- Removed `--qcow2` option in favor of supporting only raw disk images as the disk image output format.
- Removed `--bmap` option as it can be trivially added manually by utilizing a finalize script.
- The `never` value for `--with-network` was spun of into its own custom option `--cache-only`.
- `--bootable` now defaults to `auto`. When set to `auto`, mkosi will generate a bootable image only if all
  the necessary packages are installed. Documentation was added in docs/bootable.md on how a bootable image
  can be generated on mainstream distros.
- The RPM db is no longer rebuilt in bdb format on CentOS Stream 8. To be able to install packages on a
  CentOS Stream 8 image with a RPM db in sqlite format, rewrite the db in bdb format using
  `rpm --rebuilddb --define _db_backend bdb`.
- Repositories are now only written to /etc/apt/sources.list if apt is installed in the image.
- Removed the dependency on `debootstrap` to build Ubuntu or Debian images.
- Apt now uses the keyring from the host instead of the keyring from the image. This means
  `debian-archive-keyring` or `ubuntu-archive-keyring` are now required to be installed to build Debian or
  Ubuntu images respectively.
- `--base-image` is split into `--base-tree` and `--overlay`.
- Removed `--cache-initrd`, instead, use a prebuilt initrd with `Initrds=` to avoid rebuilding the initrd all
  the time.
- Disk images are now resized to 8G when booted to give some disk space to play around with in the booted
  image.
- Removed `--install-directory=` option. This was originally added for caching the installation results, but
  this doesn't work properly as it might result in leftover files in the install directory from a previous
  installation, so we have to empty the directory before reusing it, invalidating the caching, so the option
  was removed.
- Build scripts are now executed on the host. See the `SCRIPTS` section
  in the manual for more information. Existing build scripts will need
  to be updated to make sure they keep working. Specifically, most paths
  in scripts will need to be prefixed with $BUILDROOT to have them
  operate on the image instead of on the host system. To ensure the host
  system cannot be modified when running a script, most host directories
  are mounted read-only when running a script to ensure a script cannot
  modify the host in any way. Alternatively to making the script run on
  the host, the script can also still be executed in the image itself by
  putting the following snippet at the top of the script:

  ```sh
  if [ "$container" != "mkosi" ]; then
      exec mkosi-chroot "$SCRIPT" "$@"
  fi
  ```
- Removed `--tar-strip-selinux-context=` option. We now label all files
  properly if selinux is enabled and if users don't want the labels,
  they can simply exclude them when extracting the archive.
- Gentoo is now marked as experimental and unsupported and there's no
  guarantee at all that it will work. Issues related to gentoo will
  generally not receive attention from core maintainers. All gentoo
  specific hacks outside of the gentoo implementation module have been
  removed.
- A verb `documentation` has been added. Calling mkosi with this verb will show
  the documentation. This is useful when running mkosi during development to
  always have the documentation in the correct version available. By default it
  will try several ways to output the documentation, but a specific option can
  be chosen with the `--doc-format` option. Distro packagers are encouraged to
  add a file `mkosi.1` into the `mkosi/resources` directory of the Python
  package, if it is missing, as well es install it in the appropriate search
  path for man pages. The man page can be generated from the markdown file
  `mkosi/resources/mkosi.md` e.g via `pandoc -t man -s -o mkosi.1 mkosi.md`.
- BuildSources= now takes source:target pairs which specify the source
  directory and where to mount it relative to the top level source
  directory when running scripts. (e.g. BuildSources=../my-project:my-project)

## v14

- Support for Clear Linux was dropped. See https://github.com/systemd/mkosi/pull/1037
  for more information.
- Support for Photon was dropped. See https://github.com/systemd/mkosi/pull/1048
  for more information.
- The Arch kernel/bootloader pacman hooks were removed. For anyone that still
  wants to use them, they can be found
  [here](https://github.com/systemd/mkosi/tree/v13/mkosi/resources/arch).
- mkosi now creates `distro~release` subdirectories inside the build, cache and
  output directories for each `distro~release` combination that is built. This
  allows building for multiple distros without throwing away the results of a
  previous distro build every time.
- The preferred names for mkosi configuration files and directories are now
  `mkosi.conf` and `mkosi.conf.d/` respectively. The old names (`mkosi.default` and
  `mkosi.default.d`) have been removed from the docs but are still supported for
  backwards compatibility.
- `plain_squashfs` type images will now also be named with a `.raw` suffix.
- `tar` type images will now respect the `--compress` option.
- Pacman's `SigLevel` option was changed to use the same default value as used
  on Arch which is `SigLevel = Required DatabaseOptional`. If this results in
  keyring errors, you need to update the keyring by running `pacman-key
  --populate archlinux`.
- Support for CentOS 7 was dropped. If you still need to support CentOS 7, we
  recommend using any mkosi version up to 13.
- Support for BIOS/grub was dropped. because EFI hardware is widely available
  and legacy BIOS systems do not support the feature set to fully verify a boot
  chain from firmware to userland and it has become bothersome to maintain for
  little use.

  To generate BIOS images you can use any version of mkosi up to mkosi 13 or the
  new `--bios-size` option. This can be used to add a BIOS boot partition of the
  specified size on which `grub` (or any other bootloader) can be installed with
  the help of mkosi's script support (depending on your needs most likely
  `mkosi.postinst` or `mkosi.finalize`). This method can also be used for other
  EFI bootloaders that mkosi intentionally does not support.
- mkosi now unconditionally copies the kernel, initrd and kernel cmdline from
  the image that were previously only copied out for Qemu boot.
- mkosi now runs apt and dpkg on the host. As such, we now require apt and dpkg
  to be installed on the host along with debootstrap in order to be able to
  build debian/ubuntu images.
- Split dm-verity artifacts default names have been changed to match what
  `systemd` and other tools expect: `image.root.raw`, `image.root.verity`,
  `image.root.roothash`, `image.root.roothash.p7s` (same for `usr` variants).
- `mkosi` will again default to the same OS release as the host system when the
  host system uses the same distribution as the image that's being built.
- By default, `mkosi` will now change the owner of newly created directories to
  `SUDO_UID` or `PKEXEC_UID` if defined, unless `--no-chown` is used.
- If `systemd-nspawn` v252 or newer is used, bind-mounted directories with
  `systemd-nspawn` will use the new `rootidmap` option so files and directories
  created from within the container will be owned by the actual directory owner
  on the host.

## v13

- The `--network-veth` option has been renamed to `--netdev`. The old name made
  sense with virtual ethernet devices, but when booting images with qemu a
  TUN/TAP device is used instead.
- The network config file installed by mkosi when the `--netdev` (previously
  `--network-veth`) option is used (formerly
  `/etc/systemd/network/80-mkosi-network-veth.network` in the image) now only
  matches network interfaces using the `virtio_net` driver. Please make sure
  you weren't relying on this file to configure any network interfaces other
  than the tun/tap virtio-net interface created by mkosi when booting the image
  in QEMU with the `--netdev` option. If you were relying on this config file
  when the host system uses the same distribution as the image that's being
  built. Instead, when no release is specified, mkosi will now always default
  to the default version embedded in mkosi itself.
- `mkosi` will now use the `pacman` keyring from the host when building Arch
  images. This means that users will, on top of installing `archlinux-keyring`,
  also have to run `pacman-key --init` and `pacman-key --populate archlinux` on
  the host system to be able to build Arch images. Also, unless the package
  manager is configured to do it automatically, the host keyring will have to
  be updated after `archlinux-keyring` updates by running `pacman-key
  --populate archlinux` and `pacman-key --updatedb`.
- Direct qemu linux boot is now supported with `BootProtocols=linux`. When
  enabled, the kernel image, initrd, and cmdline will be extracted from the
  image and passed to `qemu` by `mkosi qemu` to directly boot into the kernel
  image without a bootloader. This can be used to boot for example s390x images
  in `qemu`.
- The initrd will now always be rebuilt after the extra trees and build
  artifacts have been installed into the image.
- The github action has been migrated to Ubuntu Jammy. To migrate any jobs
  using the action, add `runs-on: ubuntu-22.04` to the job config.
- All images are now configured by default with the `C.UTF-8` locale.
- New `--repository-directory` option can be used to configure a directory with
  extra repository files to be used by the package manager when building an
  image. Note that this option is currently only supported for `pacman` and
  `dnf`-based distros.
- Option `--skeleton-tree` is now supported on Debian-based distros.
- Removed `--hostname` as its trivial to configure using systemd-firstboot.
- Removed default locale configuration as its trivial to configure using
  systemd-firstboot and systemd writes a default locale well.


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
