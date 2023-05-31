# mkosi — Build Bespoke OS Images

A fancy wrapper around `dnf --installroot`, `apt`, `pacman`
and `zypper` that generates customized disk images with a number of
bells and whistles.

For a longer description and available features and options, see the
[man page](mkosi.md).

<a href="https://repology.org/project/mkosi/versions">
    <img align="right" src="https://repology.org/badge/vertical-allrepos/mkosi.svg?exclude_sources=site&exclude_unsupported=1" alt="Packaging status">
</a>

# Installation

You can install mkosi from your distribution with its package manager or the
development version from git. The distribution packages are the preferred way to
install mkosi.

The development version of mkosi might require tools from the systemd main
branch, see the [`action.yaml`](action.yaml) for what we currently use in CI.

## Alternative Installation methods

If you just want to give the development version of mkosi a quick spin you can run
```shell
pipx install git+https://github.com/systemd/mkosi.git
```
which will transparently install mkosi into a Python virtual environment and a mkosi
binary to `~/.local/bin`. This is, up to the path of the virtual environment and
the mkosi binary, equivalent to
```shell
python -m venv mkosivenv
mkosivenv/bin/pip install git+https://github.com/systemd/mkosi.git
# the mkosi binary is installed to mkosivenv/bin/mkosi
```

If you want to help develop mkosi you can run it from your clone of this
repository by calling the module
```shell
python3 -m mkosi
```
when you are in the repository top level.

To use your local mkosi checkout without being in the top level of the
repository you can either call the shim `bin/mkosi` or make an editable install
into a virtual environment.

The shim can be symlinked somewhere into your `PATH`. To make an editable
install add `--editable` to either of the above examples using pip or pipx and
exchange the URL of the repository for the path to your local checkout, e.g
```shell
pipx install --editable path/to/yout/local/checkout
```

For development you will also need [mypy](https://github.com/python/mypy), for
type checking, and [pytest](https://github.com/pytest-dev/pytest), to run tests.
We check tests and typing in CI (see `.github/workflows`), but you can run the
tests locally as well.

You can also package mkosi as a
[zipapp](https://docs.python.org/3/library/zipapp.html) that you can deploy
anywhere in your `PATH`. Running this will leave a `mkosi` binary in `builddir/`
```shell
tools/generate-zipapp.sh
```

## Python module

Besides the mkosi binary, you can also call mkosi via
```shell
python -m mkosi
```
when not installed as a zipapp.

Please note, that the python module exists solely for the usage of the mkosi
binary and is not to be considered a public API.

## git blame

When using git blame, be sure to add `--ignore-revs-file .git-blame-ignore-revs` to the arguments to ignore
irrelevant code formatting commits. This can be set permanently via the `blame.ignoreRevsFile` git option.

# References

* [Primary mkosi git repository on GitHub](https://github.com/systemd/mkosi/)
* [mkosi — A Tool for Generating OS Images](http://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html) introductory blog post by Lennart Poettering
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN
