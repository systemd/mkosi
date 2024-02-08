# SPDX-License-Identifier: LGPL-2.1+
from typing import Any, cast

import pytest

from mkosi.config import parse_config
from mkosi.distributions import Distribution, detect_distribution

from . import Image


def pytest_addoption(parser: Any) -> None:
    parser.addoption(
        "-D",
        "--distribution",
        metavar="DISTRIBUTION",
        help="Run the integration tests for the given distribution.",
        default=detect_distribution()[0],
        type=Distribution,
        choices=[Distribution(d) for d in Distribution.values()],
    )
    parser.addoption(
        "-R",
        "--release",
        metavar="RELEASE",
        help="Run the integration tests for the given release.",
    )
    parser.addoption(
        "-T",
        "--tools-tree-distribution",
        metavar="DISTRIBUTION",
        help="Use the given tools tree distribution to build the integration test images",
        type=Distribution,
        choices=[Distribution(d) for d in Distribution.values()],
    )
    parser.addoption(
        "--debug-shell",
        help="Pass --debug-shell when running mkosi",
        action="store_true",
    )


@pytest.fixture(scope="session")
def config(request: Any) -> Image.Config:
    distribution = cast(Distribution, request.config.getoption("--distribution"))
    release = cast(str, request.config.getoption("--release") or parse_config(["-d", str(distribution)])[1][0].release)
    return Image.Config(
        distribution=distribution,
        release=release,
        tools_tree_distribution=cast(Distribution, request.config.getoption("--tools-tree-distribution")),
        debug_shell=request.config.getoption("--debug-shell"),
    )
