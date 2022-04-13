#!/usr/bin/env bash
set -e

PACMAN_VERSION="6.0.1"
ARCHLINUX_KEYRING_COMMIT="29dc5d228d033929f90af14d219487b1edc4c2c0"
RPM_VERSION="4.17.0"
LIBCOMPS_VERSION="0.1.18"
LIBREPO_VERSION="1.14.2"
LIBMODULEMD_VERSION="2.14.0"
LIBSOLV_VERSION="0.7.22"
LIBDNF_VERSION="0.66.0"
DNF_VERSION="4.11.1"
SEQUOIA_SQ_VERSION="0.26.0"

export CMAKE_GENERATOR=Ninja
export CARGO_HOME=cargo

# All built libraries are installed to both $DESTDIR and /usr so they appear in
# the final image and can be found by the build scripts of the libraries and
# binaries that depend on them. If every library/binary used CMake as the build
# systemd we'd just use CMAKE_PREFIX_PATH to allow CMake to find libraries in
# $DESTDIR but unfortunately meson and autotools don't have an equivalent
# feature.

apt-get update

apt-get --assume-yes --no-install-recommends install \
        asciidoc \
        autoconf \
        automake \
        autopoint \
        check \
        cargo \
        cmake \
        debootstrap \
        docbook-xsl \
        e2fsprogs \
        g++ \
        gcc \
        gettext \
        gobject-introspection \
        libarchive-dev \
        libbz2-dev \
        libcap-dev \
        libcppunit-dev \
        libcurl4-openssl-dev \
        libdb-dev \
        libgcrypt-dev \
        libgirepository1.0-dev \
        libglib2.0-dev \
        libgpgme-dev \
        libjson-c-dev \
        liblua5.3-dev \
        liblzma-dev \
        libmagic-dev \
        libpopt-dev \
        libsmartcols-dev \
        libsqlite3-dev \
        libssl-dev \
        libtool \
        libxml2-dev \
        libyaml-dev \
        libzstd-dev \
        m4 \
        make \
        meson \
        ninja-build \
        ovmf \
        pandoc \
        pkgconf \
        python3 \
        python3-dev \
        python3-gpg \
        python3-sphinx \
        python3-setuptools \
        qemu-system-x86-64 \
        squashfs-tools \
        swig \
        systemd-container \
        xfsprogs \
        xsltproc \
        zlib1g-dev \
        zypper \
        libclang-dev \
        nettle-dev \
        capnproto

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

cargo install sequoia-sq --version $SEQUOIA_SQ_VERSION --features 'crypto-nettle compression-bzip2 autocrypt' --target-dir .
install -Dm 755 "$CARGO_HOME"/bin/sq -t /usr/bin

if [ ! -d archlinux-keyring-$ARCHLINUX_KEYRING_COMMIT ]; then
    git clone https://gitlab.archlinux.org/archlinux/archlinux-keyring.git archlinux-keyring-$ARCHLINUX_KEYRING_COMMIT
    git -C archlinux-keyring-$ARCHLINUX_KEYRING_COMMIT checkout $ARCHLINUX_KEYRING_COMMIT
fi

make -C archlinux-keyring-$ARCHLINUX_KEYRING_COMMIT PREFIX=/usr install

if [ ! -f rpm-$RPM_VERSION-release.tar.gz ]; then
    wget https://github.com/rpm-software-management/rpm/archive/refs/tags/rpm-$RPM_VERSION-release.tar.gz
    tar xf rpm-$RPM_VERSION-release.tar.gz
fi

pushd rpm-rpm-$RPM_VERSION-release

if [ ! -f Makefile ]; then
    ./autogen.sh \
        --prefix=/usr \
        --libdir=/usr/lib/x86_64-linux-gnu \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --enable-python \
        --with-external-db \
        --with-lua \
        --with-cap \
        LUA_CFLAGS="$(pkg-config --cflags lua5.3)" \
        LUA_LIBS="$(pkg-config --libs lua5.3)"
fi

make -j 2
make install
make DESTDIR="" install

pushd python
python3 setup.py install --root="$DESTDIR" --optimize=1
python3 setup.py install --optimize=1
popd

popd

if [ ! -f $LIBCOMPS_VERSION.tar.gz ]; then
    wget https://github.com/rpm-software-management/libcomps/archive/$LIBCOMPS_VERSION.tar.gz
    tar xf $LIBCOMPS_VERSION.tar.gz
fi

if [ ! -f libcomps-$LIBCOMPS_VERSION-build/build.ninja ]; then
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib/x86_64-linux-gnu \
        -DENABLE_TESTS=OFF \
        -DENABLE_DOCS=OFF \
        -DBUILD_SHARED_LIBS=ON \
        -Wno-dev \
        -B libcomps-$LIBCOMPS_VERSION-build \
        -S libcomps-$LIBCOMPS_VERSION/libcomps
fi

cmake --build libcomps-$LIBCOMPS_VERSION-build
cmake --install libcomps-$LIBCOMPS_VERSION-build
DESTDIR="" cmake --install libcomps-$LIBCOMPS_VERSION-build

if [ ! -f $LIBREPO_VERSION.tar.gz ]; then
    wget https://github.com/rpm-software-management/librepo/archive/$LIBREPO_VERSION.tar.gz
    tar xf $LIBREPO_VERSION.tar.gz
fi

if [ ! -f librepo-$LIBREPO_VERSION-build/build.ninja ]; then
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib/x86_64-linux-gnu \
        -DENABLE_TESTS=OFF \
        -DENABLE_DOCS=OFF \
        -DWITH_ZCHUNK=OFF \
        -DBUILD_SHARED_LIBS=ON \
        -Wno-dev \
        -B librepo-$LIBREPO_VERSION-build \
        -S librepo-$LIBREPO_VERSION
fi

cmake --build librepo-$LIBREPO_VERSION-build
cmake --install librepo-$LIBREPO_VERSION-build
DESTDIR="" cmake --install librepo-$LIBREPO_VERSION-build

if [ ! -f libmodulemd-$LIBMODULEMD_VERSION.tar.gz ]; then
    wget https://github.com/fedora-modularity/libmodulemd/archive/libmodulemd-$LIBMODULEMD_VERSION.tar.gz
    tar xf libmodulemd-$LIBMODULEMD_VERSION.tar.gz
fi

if [ ! -f libmodulemd-$LIBMODULEMD_VERSION-build/build.ninja ]; then
    meson \
        --buildtype=release \
        --prefix /usr \
        --libdir lib/x86_64-linux-gnu \
        --pkg-config-path /usr/lib/x86_64-linux-gnu/pkgconfig \
        -Ddeveloper_build=false \
        -Dwith_docs=false \
        -Dwith_manpages=disabled \
        -Dskip_introspection=false \
        -Dgobject_overrides_dir_py3=override \
        libmodulemd-$LIBMODULEMD_VERSION-build \
        libmodulemd-libmodulemd-$LIBMODULEMD_VERSION
fi

meson install -C libmodulemd-$LIBMODULEMD_VERSION-build
DESTDIR="" meson install -C libmodulemd-$LIBMODULEMD_VERSION-build

if [ ! -f $LIBSOLV_VERSION.tar.gz ]; then
    wget https://github.com/openSUSE/libsolv/archive/$LIBSOLV_VERSION.tar.gz
    tar xf $LIBSOLV_VERSION.tar.gz
    patch -d libsolv-$LIBSOLV_VERSION -p1 <<'EOF'
diff --git a/ext/repo_rpmdb_librpm.h b/ext/repo_rpmdb_librpm.h
index 3f9798c2..e1b30a0f 100644
--- a/ext/repo_rpmdb_librpm.h
+++ b/ext/repo_rpmdb_librpm.h
@@ -136,7 +136,7 @@ opendbenv(struct rpmdbstate *state)
       return 0;
     }
 #ifndef HAVE_RPMDBNEXTITERATORHEADERBLOB
-  if (!strcmp(RPMVERSION, "4.16.0"))
+  if (!strcmp(RPMVERSION, "4.16.0") || !strcmp(RPMVERSION, "4.17.0"))
     set_db_backend();
 #endif
   if (rpmtsOpenDB(ts, O_RDONLY))
EOF
fi

if [ ! -f libsolv-$LIBSOLV_VERSION-build/build.ninja ]; then
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib/x86_64-linux-gnu \
        -DENABLE_RPMDB=ON \
        -DENABLE_RPMPKG=ON \
        -DENABLE_PUBKEY=ON \
        -DENABLE_RPMDB_BYRPMHEADER=ON \
        -DENABLE_RPMDB_LIBRPM=ON \
        -DENABLE_RPMPKG_LIBRPM=ON \
        -DENABLE_RPMMD=ON \
        -DENABLE_COMPS=ON \
        -DENABLE_MDKREPO=ON \
        -DENABLE_COMPLEX_DEPS=ON \
        -DENABLE_APPDATA=ON \
        -DENABLE_LZMA_COMPRESSION=ON \
        -DENABLE_BZIP2_COMPRESSION=ON \
        -DENABLE_ZSTD_COMPRESSION=ON \
        -Wno-dev \
        -B libsolv-$LIBSOLV_VERSION-build \
        -S libsolv-$LIBSOLV_VERSION
fi

cmake --build libsolv-$LIBSOLV_VERSION-build
cmake --install libsolv-$LIBSOLV_VERSION-build
DESTDIR="" cmake --install libsolv-$LIBSOLV_VERSION-build

if [ ! -f $LIBDNF_VERSION.tar.gz ]; then
    wget https://github.com/rpm-software-management/libdnf/archive/$LIBDNF_VERSION.tar.gz
    tar xf $LIBDNF_VERSION.tar.gz
fi

if [ ! -f libdnf-$LIBDNF_VERSION-build/build.ninja ]; then
    cp /usr/share/cmake/Modules/FindLibSolv.cmake libdnf-$LIBDNF_VERSION/cmake/modules
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_INSTALL_LIBDIR=lib/x86_64-linux-gnu \
        -DWITH_GTKDOC=OFF \
        -DWITH_HTML=OFF \
        -DWITH_MAN=OFF \
        -DWITH_ZCHUNK=OFF \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_CXX_FLAGS="-pthread" \
        -DPYTHON_DESIRED=3 \
        -Wno-dev \
        -B libdnf-$LIBDNF_VERSION-build \
        -S libdnf-$LIBDNF_VERSION
fi

cmake --build libdnf-$LIBDNF_VERSION-build
cmake --install libdnf-$LIBDNF_VERSION-build
DESTDIR="" cmake --install libdnf-$LIBDNF_VERSION-build

if [ ! -f $DNF_VERSION.tar.gz ]; then
    wget https://github.com/rpm-software-management/dnf/archive/$DNF_VERSION.tar.gz
    tar xf $DNF_VERSION.tar.gz
fi

if [ ! -f dnf-$DNF_VERSION-build/build.ninja ]; then
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DPYTHON_DESIRED=3 \
        -DWITH_MAN=0 \
        -Wno-dev \
        -B dnf-$DNF_VERSION-build \
        -S dnf-$DNF_VERSION
fi

cmake --build dnf-$DNF_VERSION-build
cmake --install dnf-$DNF_VERSION-build

# All python libraries are installed to a location that's not in the default
# search path so let's fix that by moving those python files to a location that
# is in the default search path.
mkdir -p "$DESTDIR"/usr/lib/python3/dist-packages
mv "$DESTDIR"/usr/lib/python3.8/site-packages/* "$DESTDIR"/usr/lib/python3/dist-packages

ln -sf /usr/bin/dnf-3 "$DESTDIR"/usr/bin/dnf
