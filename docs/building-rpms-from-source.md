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

1. Install `Requires` dependencies in the image
2. Install `BuildRequires` dependencies in the build overlay
3. Install dynamic `BuildRequires` dependencies in the build overlay
4. Build the RPM with `rpmbuild`
5. Install the built rpms in the image

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

if [ "$1" = "build" ]; then
    DEPS="--buildrequires"
else
    DEPS="--requires"
fi

mkosi-chroot \
    rpmspec \
    --query \
    "$DEPS" \
    --define "_topdir /var/tmp" \
    --define "_sourcedir mkosi/rpm" \
    mkosi/rpm/mkosi.spec |
        grep -E -v mkosi |
        xargs -d '\n' dnf install

if [ "$1" = "build" ]; then
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

        dnf builddep /var/tmp/SRPMS/mkosi-*.buildreqs.nosrc.rpm
    done
fi
```

To install non-dynamic dependencies, we use `rpmspec`. What's important
is to set `_sourcedir` to the directory containing the RPM sources for
the RPM spec that we want to build. We run `rpmspec` inside the image to
make sure all the RPM macros have their expected values and then run
`dnf` outside the image to install the required dependencies.

We always set `_topdir` to `/var/tmp` to avoid polluting the image with
`rpmbuild` artifacts.

Subpackages from the same RPM might depend on each other. We need to
filter out those dependencies using `grep -E -v <package-name>`.

After installing non-dynamic `Requires` and `BuildRequires`
dependencies, we have to install the dynamic `BuildRequires` by running
`rpmbuild -bd` until it succeeds or fails with an exit code that's not
`11`. After each run of `rpmbuild -bd` that exits with exit code `11`,
there will be an SRPM in the `SRPMS` subdirectory of the upstream
sources directory of which the `BuildRequires` have to be installed for
which we use `dnf builddep`.

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
    rpm/mkosi.spec
```

The `_vpath_builddir` directory will be used to store out-of-tree build
artifacts for build systems that support out-of-tree builds (CMake,
Meson) so we set it to mkosi's out-of-tree build directory in
`$BUILDDIR` if one is provided. This will make subsequent RPM builds
much faster as CMake or Meson will be able to do an incremental build.

After the build script finishes, the produced rpms will be located in
`$OUTPUTDIR`. We can now install them from the `mkosi.postinst`
post-installation script:

```shell
#!/bin/sh
set -e

rpm --install "$OUTPUTDIR"/*mkosi*.rpm
```
