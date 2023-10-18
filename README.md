# mkosi — Build Bespoke OS Images

A fancy wrapper around `dnf --installroot`, `apt`, `pacman`
and `zypper` that generates customized disk images with a number of
bells and whistles.

For a longer description and available features and options, see the
[man page](mkosi/resources/mkosi.md).

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
to execute mkosi. The shim can be symlinked to e.g. `/usr/local/bin` to
make it accessible from the `PATH`.

## Python installation methods

mkosi can also be installed straight from the git repository url using
`pipx`:

```shell
pipx install git+https://github.com/systemd/mkosi.git
```

which will transparently install mkosi into a Python virtual environment
and a mkosi binary to `~/.local/bin`. This is, up to the path of the
virtual environment and the mkosi binary, equivalent to
```shell
python -m venv mkosivenv
mkosivenv/bin/pip install git+https://github.com/systemd/mkosi.git
# the mkosi binary is installed to mkosivenv/bin/mkosi
```

You can also package mkosi as a
[zipapp](https://docs.python.org/3/library/zipapp.html) that you can
deploy anywhere in your `PATH`. Running this will leave a `mkosi` binary
in `builddir/`

```shell
tools/generate-zipapp.sh
```

Besides the mkosi binary, you can also call mkosi via

```shell
python -m mkosi
```

when not installed as a zipapp.

Please note, that the python module exists solely for the usage of the
mkosi binary and is not to be considered a public API.

# Hacking on mkosi

To hack on mkosi itself you will also need
[mypy](https://github.com/python/mypy), for type checking, and
[pytest](https://github.com/pytest-dev/pytest), to run tests. We check
tests and typing in CI (see `.github/workflows`), but you can run the
tests locally as well.

# References

* [Primary mkosi git repository on GitHub](https://github.com/systemd/mkosi/)
* [mkosi — A Tool for Generating OS Images](http://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html) introductory blog post by Lennart Poettering (2017)
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN (2017)
* [systemd-repart: Building Discoverable Disk Images](https://media.ccc.de/v/all-systems-go-2023-191-systemd-repart-building-discoverable-disk-images) and [mkosi: Building Bespoke Operating System Images](https://media.ccc.de/v/all-systems-go-2023-190-mkosi-building-bespoke-operating-system-images) talks at All Systems Go! 2023

## Community

Find us on Matrix at [#mkosi:matrix.org](https://matrix.to/#/#mkosi:matrix.org).
