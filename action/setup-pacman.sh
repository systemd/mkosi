#!/usr/bin/env bash
set -e

PACMAN_VERSION="6.0.1"
ARCHLINUX_KEYRING_VERSION="20220424"

apt-get --assume-yes --no-install-recommends install \
        gcc \
        git \
        libarchive-dev \
        libgpgme-dev \
        libssl-dev \
        libcurl4-openssl-dev \
        make \
        meson \
        pkgconf \
        sq

cd "$BUILDDIR"

if [ ! -f pacman-$PACMAN_VERSION.tar.xz ]; then
    wget https://sources.archlinux.org/other/pacman/pacman-$PACMAN_VERSION.tar.xz
    tar xf pacman-$PACMAN_VERSION.tar.xz
fi

if [ ! -f pacman-$PACMAN_VERSION-build/build.ninja ]; then
    meson \
        --buildtype=release \
        --prefix /usr \
        --libdir lib/x86_64-linux-gnu \
        -Ddoc=disabled \
        -Dscriptlet-shell=/usr/bin/bash \
        -Dldconfig=/usr/bin/ldconfig \
        pacman-$PACMAN_VERSION-build \
        pacman-$PACMAN_VERSION
fi

meson install -C pacman-$PACMAN_VERSION-build

# Ubuntu 22.04 doesn't ship the python-is-python3 package anymore so we manually create the symlink instead.
if [ ! -f /usr/bin/python ]; then
    ln -s /usr/bin/python3 /usr/bin/python
fi

if [ ! -d archlinux-keyring-$ARCHLINUX_KEYRING_VERSION ]; then
    git clone \
        --branch $ARCHLINUX_KEYRING_VERSION \
        --depth 1 \
        https://gitlab.archlinux.org/archlinux/archlinux-keyring.git \
        archlinux-keyring-$ARCHLINUX_KEYRING_VERSION
fi

make -C archlinux-keyring-$ARCHLINUX_KEYRING_VERSION PREFIX=/usr install
