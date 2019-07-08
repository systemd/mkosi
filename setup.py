#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1+

import sys

from setuptools import setup, Command

class BuildManpage(Command):
    description = ('builds the manpage')
    user_options = []

    def initialize_options(self):
        pass
    def finalize_options(self):
        pass

    def run(self):
        self.spawn(['pandoc', '-t', 'man', '-o', 'mkosi.1', 'mkosi.md'])

if sys.version_info < (3, 6):
    sys.exit("Sorry, we need at least Python 3.6.")


setup(
    name="mkosi",
    version="5",
    description="Create legacy-free OS images",
    url="https://github.com/systemd/mkosi",
    maintainer="mkosi contributors",
    maintainer_email="systemd-devel@lists.freedesktop.org",
    license="LGPLv2+",
    scripts=["mkosi"],
    cmdclass = { "man": BuildManpage }
)
