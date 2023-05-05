#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1+

from setuptools import setup, find_packages
from setuptools.command.install import install


class InstallCommand(install):
    def run(self):
        self.spawn(['pandoc', '-t', 'man', '-s', '-o', 'mkosi.1', 'mkosi.md'])
        install.run(self)


setup(
    name="mkosi",
    version="14",
    description="Build Bespoke OS Images",
    url="https://github.com/systemd/mkosi",
    maintainer="mkosi contributors",
    maintainer_email="systemd-devel@lists.freedesktop.org",
    license="LGPLv2+",
    python_requires=">=3.9",
    packages = find_packages(".", exclude=["tests"]),
    package_data = {"": ["*.sh", "*.hook", "*.conf", "*.install"]},
    include_package_data = True,
    entry_points = { "console_scripts": ["mkosi = mkosi.__main__:main"] },
    cmdclass = { "install": InstallCommand },
    data_files = [('share/man/man1', ["mkosi.1"])],
)
