#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1+

from setuptools import setup, Command

class BuildManpage(Command):
    description = ('builds the manpage')
    user_options = []

    def initialize_options(self):
        pass
    def finalize_options(self):
        pass

    def run(self):
        self.spawn(['pandoc', '-t', 'man', '-s', '-o', 'man/mkosi.1', 'mkosi.md'])


setup(
    name="mkosi",
    version="9",
    description="Create legacy-free OS images",
    url="https://github.com/systemd/mkosi",
    maintainer="mkosi contributors",
    maintainer_email="systemd-devel@lists.freedesktop.org",
    license="LGPLv2+",
    python_requires=">=3.7",
    packages = ["mkosi"],
    scripts = ["bin/mkosi"],
    cmdclass = { "man": BuildManpage },
    data_files = [('share/man/man1', ["man/mkosi.1"])],
)
