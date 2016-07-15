#!/usr/bin/python3

from setuptools import setup

setup(
    name="mkosi",
    version="1",
    description="Create legacy-free OS images",
    url="https://github.com/systemd/mkosi",
    author="Lennart Poettering",
    author_email="lennart@poettering.net",
    license="LICENSE",
    scripts=["mkosi"],
)
