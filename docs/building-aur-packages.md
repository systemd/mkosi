---
title: Installing AUR Packages in Arch Linux Images
category: Tutorials
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Installing AUR Packages in Arch Linux Images:

`mkosi` does not natively support installing packages from the [Arch User Repository
(AUR)](https://aur.archlinux.org/), since AUR packages must be built from source using `makepkg` rather than
installed through `pacman`. This section describes how to install AUR packages at image build time using
[`aurutils`](https://aur.archlinux.org/packages/aurutils).

## Overview:

The approach involves using two `mkosi` hook scripts and a stub `build` script:

1. `mkosi.prepare.chroot`: Bootstraps `aurutils` from AUR, resolves its dependency graph, builds all
   requested packages as the unprivileged [`nobody`](https://wiki.ubuntu.com/nobody) user, and places the resulting packages in `$PACKAGEDIR`.

2. `mkosi.build.chroot`: A stub script that exists solely to trigger mkosi's build phase, which causes mkosi.prepare.chroot to be called with the build argument.

3. `mkosi.postinst.chroot`:  Installs the built packages from `$PACKAGEDIR` into the final image using `pacman -U`.

`BuildSourcesEphemeral=yes` ensures that build tools (`base-devel`, `git`, etc.) installed via
`BuildPackages=` are present during the build phase but [are not included in the final image](/mkosi/resources/man/mkosi.1.md#build-section). `$PACKAGEDIR` is a mkosi-managed directory that persists between the build phase and the postinst phase.

### Why `nobody`?

Since `makepkg` checks `EUID` (Effective User ID) rather than strictly requiring non-root, the `nobody` user (`uid` 65534) works as a convenient unprivileged identity, as it is always available in the build sandbox without requiring a persistent user database.

### Why `aur depends` and `tsort`?

AUR packages can depend on other AUR packages. Using `aur depends -r` emits the full
transitive dependency graph. `tsort` linearises the dependencies into a build order that guarantees each package is built after the packages it depends on. For neovim-git, the AUR package used in this example, this means any AUR dependencies are built and registered before neovim-git itself attempts to build against them.

### Why `aurutils` is bootstrapped manually?
`aurutils` cannot be listed in `BuildPackages=` because it is itself an AUR package. Its dependencies are
installed explicitly as root before `makepkg` runs, since `makepkg --syncdeps` calls `pacman` via `sudo`
internally, which `nobody` does not have access to in the build sandbox.

# Example installing `neovim-git`:

## `mkosi.conf`:

```sh
[Distribution]
Distribution=arch

[Build]
BuildSourcesEphemeral=yes

# Enables network connectivity while mkosi.build build scripts are invoked.
# Required to fetch AUR sources and dependencies.
WithNetwork=yes

[Content]
# Build-time only tools.
BuildPackages=
    base-devel
    git
    jq

# AUR packages are installed via mkosi.postinst.chroot.
Packages=
    base
    linux
    linux-firmware
```

## `mkosi.prepare.chroot`:

```sh
#!/usr/bin/env bash

set -eux

if [[ "$1" != "build" ]]; then
    exit 0
fi

# The prepare script runs in a fresh build overlay where the keyring has
# not been initialised and no package databases exist. Both steps are
# required, omitting them causes "keyring is not writable" and
# "database file does not exist" errors respectively.
pacman-key --init
pacman-key --populate archlinux

cat > /etc/pacman.d/mirrorlist << 'EOF'
Server = https://fastly.mirror.pkgbuild.com/$repo/os/$arch
EOF

pacman -Sy

install -d /tmp/aurutils-build -o nobody
cd /tmp/aurutils-build
sudo -u nobody git clone https://aur.archlinux.org/aurutils.git
cd aurutils

pacman -S --needed --noconfirm \
    git pacutils curl perl perl-json-xs bash

sudo -u nobody \
    PKGDEST="/tmp" \
    PKGEXT=".pkg.tar" \
    makepkg --clean --cleanbuild --noconfirm

pacman -U --noconfirm /tmp/aurutils-*.pkg.tar

cd /

# Add any AUR packages you want to build here,
PACKAGES=(
    neovim-git
)

install -d /tmp/aurbuild -o nobody
install -d /var/tmp/aurutils-65534 -o nobody
install -d "$PACKAGEDIR" -o nobody
cd /tmp/aurbuild

# Resolve full AUR dependency graph and linearise into build order.
aur_deps=$(aur depends "${PACKAGES[@]}" -r | tsort)
echo "AUR build order: ${aur_deps}"

# Install official-repo dependencies upfront so makepkg does not need sudo.
pacman_deps=$(aur depends "${PACKAGES[@]}" --json --all \
    | jq -r '.[] | select(.ID == null) | .Name')

if [[ -n "${pacman_deps}" ]]; then
    # shellcheck disable=SC2086
    pacman -S --needed --noconfirm ${pacman_deps}
fi

# shellcheck disable=SC2086
aur fetch ${aur_deps[@]}
chown -R nobody:nobody /tmp/aurbuild

for pkg in ${aur_deps[@]}; do
    pushd "${pkg}"

    sudo -u nobody \
        BUILDDIR="/tmp/aurbuild" \
        SRCDEST="/tmp/aurbuild" \
        PKGDEST="$PACKAGEDIR" \
        makepkg --noconfirm --noprogressbar

    popd
done
```

## `mkosi.build.chroot`:

```sh
#!/usr/bin/env bash
# This script exists solely to trigger mkosi's build phase, which causes
# mkosi.prepare.chroot to be called with the "build" argument. All actual
# AUR package building happens in mkosi.prepare.chroot.
```

## `mkosi.postinst.chroot`:

```sh
#!/usr/bin/env bash

set -eux

# The final image context also starts with no keyring, mirrorlist, or
# synced databases. pacman -U needs all three to verify package signatures
# and resolve official-repo dependencies of the AUR packages.
pacman-key --init
pacman-key --populate archlinux

cat > /etc/pacman.d/mirrorlist << 'EOF'
Server = https://fastly.mirror.pkgbuild.com/$repo/os/$arch
EOF

pacman -Sy

pacman -U --noconfirm $PACKAGEDIR/*.pkg.tar.zst
```

# Building and Executing the Scripts:

Once you have confiuged the scripts to contain the desired AUR packages, the image can be built:

```sh
chmod +x mkosi.prepare.chroot mkosi.build.chroot mkosi.postinst.chroot
mkosi
```

Then boot the resulting image and verify that the package was correctly installed:

```sh
mkosi vm

pacman -Q neovim-git
nvim --version
```

# Miscellaneous Notes:

This example assumes the host is running Arch Linux or an Arch-based distribution. Building Arch images from
non-Arch hosts is possible using [`ToolsTree=arch`](/mkosi/resources/man/mkosi.1.md#build-section)
