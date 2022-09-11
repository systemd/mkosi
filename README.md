# mkosi — Build Bespoke OS Images

A fancy wrapper around `dnf --installroot`, `debootstrap`, `pacman`
and `zypper` that generates customized disk images with a number of
bells and whistles.

For a longer description and available features and options, see the
[man page](mkosi.md).

<a href="https://repology.org/project/mkosi/versions">
    <img align="right" src="https://repology.org/badge/vertical-allrepos/mkosi.svg?exclude_sources=site&exclude_unsupported=1" alt="Packaging status">
</a>

# Installation

Installing mkosi is easy, as it has no runtime Python dependencies (you will
need all the tools to format filesystems and bootstrap the distribution
appropriate for your image, though).

If you just want the main branch you can run
```shell
python3 -m pip install --user git+https://github.com/systemd/mkosi.git
```

If you want to hack on mkosi do
```shell
# clone either this repository or your fork of it
git clone https://github.com/systemd/mkosi/
cd mkosi
python3 -m pip install --user --no-use-pep517 --editable .
```
This will install mkosi in editable mode to `~/.local/bin/mkosi`, allowing you
to use your own changes right away.

For development you also need [mypy](https://github.com/python/mypy), for type
checking, and [pytest](https://github.com/pytest-dev/pytest), to run tests.
We check tests and typing in CI (see `.github/workflows`), but you can run the
tests locally as well.

## zipapp

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
* [mkosi — A Tool for Generating OS Images](http://0pointer.net/blog/mkosi-a-tool-for-generating-os-images.html) indroductory blog post by Lennart Poettering
* [The mkosi OS generation tool](https://lwn.net/Articles/726655/) story on LWN
