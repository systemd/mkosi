---
title: Building RPMs from source with mkosi
category: Tutorials
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Building RPMs from source with mkosi

If you want to build an RPM from source and install it within a mkosi
image, you can do that with mkosi itself without using `mock`. The steps
required are as follows:

1. Install `BuildRequires` dependencies in the build overlay
1. Install dynamic `BuildRequires` dependencies in the build overlay
1. Build the RPM with `rpmbuild`
1. Install the built rpms in the image

In the following examples, we'll use mkosi itself and its Fedora RPM
spec as an example.

To keep things snappy, we execute the first 3 steps in a prepare
script so that they're cached on subsequent runs of mkosi if the
`Incremental=` setting is enabled.

First, we need access to the upstream sources and the RPM spec and
related files. These can be mounted into the current working directory
when running mkosi scripts by using the `BuildSources=` setting. For
example, in `mkosi.local.conf`, we could have the following settings:

```conf
[Content]
BuildSources=../mkosi:mkosi
             ../fedora/mkosi:mkosi/rpm
BuildSourcesEphemeral=yes
```

Which instructs mkosi to mount the local version of the mkosi upstream
repository at `../mkosi` to `mkosi` in the current working directory
when running mkosi. The Fedora RPM spec is mounted at `mkosi/rpm`.

We enable the `BuildSourcesEphemeral=` option as `rpmbuild` will write
quite a few files to the source directory as part of building the rpm
which we don't want to remain there after the build finishes.

We use `rpmspec` and `rpmbuild`, but these do not really support running
from outside of the image that the RPM is being built in, so we have to
make sure they're available inside the image by adding the following to
`mkosi.conf`:

```conf
[Content]
Packages=rpm-build
# If you don't want rpm-build in the final image.
RemovePackages=rpm-build
```

The prepare script `mkosi.prepare` then looks as follows:

```shell
#!/bin/sh
set -e

if [ "$1" = "final" ]; then
    exit 0
fi

mkosi-chroot \
    env --chdir=mkosi \
    rpmspec \
    --query \
    --buildrequires \
    --define "_topdir /var/tmp" \
    --define "_sourcedir rpm" \
    rpm/mkosi.spec |
        sort --unique |
        tee /tmp/buildrequires |
        xargs --delimiter '\n' mkosi-install

until mkosi-chroot \
    env --chdir=mkosi \
    rpmbuild \
    -bd \
    --build-in-place \
    --define "_topdir /var/tmp" \
    --define "_sourcedir rpm" \
    --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
    rpm/mkosi.spec
do
    EXIT_STATUS=$?
    if [ $EXIT_STATUS -ne 11 ]; then
        exit $EXIT_STATUS
    fi

    mkosi-chroot \
        rpm \
        --query \
        --package \
        --requires \
        /var/tmp/SRPMS/mkosi-*.buildreqs.nosrc.rpm |
            grep --invert-match '^rpmlib(' |
            sort --unique >/tmp/dynamic-buildrequires

    sort /tmp/buildrequires /tmp/dynamic-buildrequires |
        uniq --unique |
        tee --append /tmp/buildrequires |
        xargs --delimiter '\n' mkosi-install
done
```

To install non-dynamic dependencies, we use `rpmspec`. What's important
is to set `_sourcedir` to the directory containing the RPM sources for
the RPM spec that we want to build. We run `rpmspec` inside the image to
make sure all the RPM macros have their expected values and then run
`mkosi-install` outside the image to install the required dependencies.
`mkosi-install` will invoke the package manager that's being used to
build the image to install the given packages.

We always set `_topdir` to `/var/tmp` to avoid polluting the image with
`rpmbuild` artifacts.

After installing non-dynamic `BuildRequires` dependencies, we have to
install the dynamic `BuildRequires` dependencies by running `rpmbuild
-bd` until it succeeds or fails with an exit code that's not `11`. After
each run of `rpmbuild -bd` that exits with exit code `11`, there will be
an SRPM in the `SRPMS` subdirectory of the rpm working directory
(`_topdir`) of which the `BuildRequires` dependencies have to be
installed. We retrieve the list of `BuildRequires` dependencies with
`rpm` this time (because we're operating on a package instead of a
spec), remove all `rpmlib` style dependencies which can't be installed
and store them in a temporary file after filtering duplicates. Because
the `BuildRequires` dependencies from the SRPM will also contain the
non-dynamic `BuildRequires` dependencies, we have to filter those out as
well.

Now we have an image and build overlay with all the necessary
dependencies installed to be able to build the RPM.

Next is the build script. We suffix the build script with `.chroot` so
that mkosi runs it entirely inside the image. In the build script, we
invoke `rpmbuild -bb --build-in-place` to have `rpmbuild` build the RPM
in place from the upstream sources. Because `--build-in-place`
configures `_builddir` to the current working directory, we change
directory to the upstream sources before invoking `rpmbuild`. Again,
`_sourcedir` has to point to the RPM spec sources. We also have to
override `_rpmdir` to point to the mkosi output directory (stored in
`$OUTPUTDIR`). The build script `mkosi.build.chroot` then looks as
follows:

```shell
#!/bin/sh
set -e

env --chdir=mkosi \
    rpmbuild \
    -bb \
    --build-in-place \
    $([ "$WITH_TESTS" = "0" ] && echo --nocheck) \
    --define "_topdir /var/tmp" \
    --define "_sourcedir rpm" \
    --define "_rpmdir $OUTPUTDIR" \
    ${BUILDDIR:+--define} \
    ${BUILDDIR:+"_vpath_builddir $BUILDDIR"} \
    --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
    --define "_binary_payload w.ufdio" \
    --define "debug_package %{nil}" \
    --define "__brp_strip %{nil}" \
    --define "__brp_compress %{nil}" \
    --define "__brp_mangle_shebangs %{nil}" \
    --define "__brp_strip_comment_note %{nil}" \
    --define "__brp_strip_static_archive %{nil}" \
    rpm/mkosi.spec
```

The `_vpath_builddir` directory will be used to store out-of-tree build
artifacts for build systems that support out-of-tree builds (CMake,
Meson) so we set it to mkosi's out-of-tree build directory in
`$BUILDDIR` if one is provided. This will make subsequent RPM builds
much faster as CMake or Meson will be able to do an incremental build.

Setting `_binary_payload` to `w.ufdio` disables compression to speed up
the build. We also disable debug package generation using
`debug_package` and various rpm build root policy scripts to speed up
the build. Note that the build root policy macros we use here are
CentOS/Fedora specific.

After the build script finishes, the produced rpms will be located in
`$OUTPUTDIR`. We can now install them from the `mkosi.postinst`
post-installation script:

```shell
#!/bin/sh
set -e

rpm --install "$OUTPUTDIR"/*mkosi*.rpm
```
