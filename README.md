# mkosi — Build Bespoke OS Images

A fancy wrapper around `dnf --installroot`, `apt`, `pacman`
and `zypper` that generates customized disk images with a number of
bells and whistles.

For a longer description and available features and options, see the
[man page](mkosi/resources/man/mkosi.1.md).

<a href="https://repology.org/project/mkosi/versions">
    <img align="right" src="https://repology.org/badge/vertical-allrepos/mkosi.svg?exclude_sources=site&exclude_unsupported=1" alt="Packaging status">
</a>

# Installation

You can install mkosi from your distribution using its package manager
or install the development version from git. If you install mkosi using
your distribution's package manager, make sure it installs at least
mkosi v16 or newer (Use `mkosi --version` to check). If your
distribution only packages an older version of mkosi, it is recommended
to install mkosi using one of the alternative installation methods
listed below instead.

## Running mkosi from the repository

To run mkosi straight from its git repository, you can invoke the shim
`bin/mkosi`. The `MKOSI_INTERPRETER` environment variable can be set
when using the `bin/mkosi` shim to configure the python interpreter used
to execute mkosi. The shim can be symlinked to e.g. `~/.local/bin` to
make it accessible from the `PATH`. Note that to make this work you
might have to add `~/.local/bin` to your user's `PATH`.

```shell
git clone https://github.com/systemd/mkosi
ln -s $PWD/mkosi/bin/mkosi ~/.local/bin/mkosi
mkosi --version
```

## Python installation methods

mkosi can also be installed straight from the git repository url using
`pipx`:

```shell
pipx install git+https://github.com/systemd/mkosi.git
mkosi --version
```

which will transparently install mkosi into a Python virtual environment
and a mkosi binary to `~/.local/bin`. This is, up to the path of the
virtual environment and the mkosi binary, equivalent to

```shell
python3 -m venv mkosivenv
mkosivenv/bin/pip install git+https://github.com/systemd/mkosi.git
mkosivenv/bin/mkosi --version
```

You can also package mkosi as a
[zipapp](https://docs.python.org/3/library/zipapp.html) that you can
deploy anywhere in your `PATH`. Running this will leave a `mkosi` binary
in `builddir/`

```shell
git clone https://github.com/systemd/mkosi
cd mkosi
tools/generate-zipapp.sh
builddir/mkosi --version
```

Besides the mkosi binary, you can also call mkosi via

```shell
python3 -m mkosi
```

when not installed as a zipapp.

Please note, that the python module exists solely for the usage of the
mkosi binary and is not to be considered a public API.

## kernel-install plugins

mkosi can also be used as a kernel-install plugin to build initrds and addons.
It is recommended to use only one of these two plugins at a given time.

## UKI plugin
To enable this feature, install `kernel-install/50-mkosi.install`
into `/usr/lib/kernel/install.d`. Extra distro configuration for the
initrd can be configured in `/usr/lib/mkosi-initrd`. Users can add their
own customizations in `/etc/mkosi-initrd`. A full self-contained UKI will
be built and installed.

Once installed, the mkosi plugin can be enabled by writing
`initrd_generator=mkosi-initrd` and `layout=uki` to `/usr/lib/kernel/install.conf`
or to `/etc/kernel/install.conf`.

## Addon plugin
To enable this feature, install `kernel-install/51-mkosi-addon.install` into
`/usr/lib/kernel/install.d`. Extra distro configuration for the addon can be
configured in `/usr/lib/mkosi-addon`. Users can add their own customizations in
`/etc/mkosi-addon` and `/run/mkosi-addon`. Note that unless at least one of the
last two directories are present, the plugin will not operate.

This plugin is useful to enhance a vendor-provided UKI with local-only
modifications.

# Hacking on mkosi

To hack on mkosi itself you will also need
[mypy](https://github.com/python/mypy), for type checking, and
[pytest](https://github.com/pytest-dev/pytest), to run tests. We check
tests and typing in CI (see `.github/workflows`), but you can run the
tests locally as well.

# References

* [Primary mkosi git repository on GitHub](https://github.com/systemd/mkosi/)
* [A re-introduction to mkosi — A Tool for Generating OS Images](https://0pointer.net/blog/a-re-introduction-to-mkosi-a-tool-for-generating-os-images.html)
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN (2017)
* [systemd-repart: Building Discoverable Disk Images](https://media.ccc.de/v/all-systems-go-2023-191-systemd-repart-building-discoverable-disk-images) and [mkosi: Building Bespoke Operating System Images](https://media.ccc.de/v/all-systems-go-2023-190-mkosi-building-bespoke-operating-system-images) talks at All Systems Go! 2023
* [Building RHEL and RHEL UBI images with mkosi](https://fedoramagazine.org/create-images-directly-from-rhel-and-rhel-ubi-package-using-mkosi/) an article in Fedora Magazine (2023)
* [Building USIs with mkosi](https://overhead.neocities.org/blog/build-usi-mkosi/)
* [Constellation 💖 mkosi — Minimal TCB, tailor-made for measured boot](https://www.edgeless.systems/blog/constellation-mkosi-minimal-tcb-tailor-made-for-measured-boot/)
* [Streamlining kernel hacking with mkosi-kernel](https://video.fosdem.org/2024/ub5132/fosdem-2024-2209-streamlining-kernel-hacking-with-mkosi-kernel.av1.webm)
* [mkosi-initrd: Building initrds out of distribution packages](https://video.fosdem.org/2024/ua2118/fosdem-2024-2888-mkosi-initrd-building-initrds-out-of-distribution-packages.av1.webm)
* [Running systemd integration tests with mkosi](https://video.fosdem.org/2024/ud2208/fosdem-2024-3431-running-systemd-integration-tests-with-mkosi.av1.webm)
* [Arch Linux rescue image with mkosi](https://swsnr.de/archlinux-rescue-image-with-mkosi)
* [Building vagrant images with mkosi](https://vdwaa.nl/mkosi-vagrant-images.html#mkosi-vagrant-images)

## Community

Find us on Matrix at [#mkosi:matrix.org](https://matrix.to/#/#mkosi:matrix.org).
