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
[`aurutils`](https://aur.archlinux.org/packages/aurutils) and a local pacman repository.

## Overview:

The approach involves using three `mkosi` hook scripts that run in sequence:

1. `mkosi.prepare.chroot`: Initialises the pacman keyring, bootstraps `aurutils` from the AUR (since it is an AUR package itself and therefore cannot be listed in
   the `BuildPackages=` section of an `mkosi.conf` file), and then sets up a local pacman repository backed by
   `$PACKAGEDIR`.

2. `mkosi.build.chroot`: Resolves the full AUR dependency graph, installs official-repo makedepends, fetches `PKGBUILD`s, builds packages as the unprivileged [nobody](https://wiki.ubuntu.com/nobody) user, and registers the results in the local repository inside `$PACKAGEDIR`.

3. `mkosi.postinst.chroot`: Configures pacman in the final image to read from `$PACKAGEDIR` and installs all built AUR packages.

`BuildSourcesEphemeral=yes` ensures that build tools (`base-devel`, `git`, etc.) installed via
`BuildPackages=` are present during the build phase but [are not included in the final image](/mkosi/resources/man/mkosi.1.md#build-section). `$PACKAGEDIR` is a mkosi-managed directory that persists between the build phase and the postinst phase.

### Why `nobody`?

Since `makepkg` checks `EUID` (Effective User ID) rather than strictly requiring non-root, the `nobody` user (`uid` 65534) works as a convenient unprivileged identity, as it is always available in the build sandbox without requiring a persistent user database.

### Why `aur depends` and `tsort`?

AUR packages can depend on other AUR packages. Using `aur depends -r` emits the full
transitive dependency graph. `tsort` linearises the dependencies into a build order that guarantees each package is built after the packages it depends on. For neovim-git, the AUR package used in this example, this means any AUR dependencies are built and registered before neovim-git itself attempts to build against them.

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

if [[ "${1}" != "build" ]]; then
    exit 0
fi

# Pacman initialization operations:
pacman-key --init
pacman-key --populate archlinux

cat > /etc/pacman.d/mirrorlist << 'EOF'
Server = https://fastly.mirror.pkgbuild.com/$repo/os/$arch
EOF

pacman -Sy

# Bootstrap aurutils from AUR, with user nobody into /tmp, then install with pacman.
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

# Initialize the local pacman repo inside $PACKAGEDIR.
install -d "$PACKAGEDIR" -o nobody
sudo -u nobody tar -ca -f "$PACKAGEDIR/aur.db.tar.xz" -T /dev/null
sudo -u nobody ln -sf "$PACKAGEDIR/aur.db.tar.xz" "$PACKAGEDIR/aur.db"

mkdir -p /etc/pacman.d

cat > /etc/pacman.d/aur.conf << EOF
[aur]
SigLevel = Optional TrustAll
Server = file://$PACKAGEDIR
EOF

if ! grep -q 'Include = /etc/pacman.d/\*.conf' /etc/pacman.conf; then
    echo -e '\nInclude = /etc/pacman.d/*.conf' >> /etc/pacman.conf
fi

pacman -Sy
```

## `mkosi.build.chroot`:

```sh
#!/usr/bin/env bash

# This runs after mkosi.prepare.chroot "build" phase.
# Still inside the BUILD overlay, so base-devel, aurutils, git, are all available here.

set -eux

PACKAGES=(
    neovim-git
    # foo
    # bar
    # and any other AUR packages you want to build here
)

# /var/tmp/aurutils-65534 is aurutils' own working directory (65534 = nobody uid).
install -d /tmp/aurbuild -o nobody
install -d /var/tmp/aurutils-65534 -o nobody
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
        aur build --no-sync

    sudo -u nobody repo-add "$PACKAGEDIR/aur.db.tar.xz" \
        "$PACKAGEDIR/${pkg}"-*.pkg.tar*

    popd
done

pacman -Sy
```

## `mkosi.postinst.chroot`:

```sh
#!/usr/bin/env bash

# Installs built AUR packages into the final image.

set -eux

mkdir -p /etc/pacman.d

cat > /etc/pacman.d/aur.conf << EOF
[aur]
SigLevel = Optional TrustAll
Server = file://$PACKAGEDIR
EOF

cat > /etc/pacman.d/mirrorlist << 'EOF'
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
EOF

if ! grep -q 'Include = /etc/pacman.d/\*.conf' /etc/pacman.conf; then
    echo -e '\nInclude = /etc/pacman.d/*.conf' >> /etc/pacman.conf
fi

pacman-key --init
pacman-key --populate archlinux

cat > /etc/pacman.d/mirrorlist << 'EOF'
Server = https://fastly.mirror.pkgbuild.com/$repo/os/$arch
EOF

pacman -Sy

# Install every package registered in the [aur] repo.
pacman -S --noconfirm $(pacman -Sql aur)
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
