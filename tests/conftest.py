# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterator
from typing import Any, cast

import pytest

import mkosi.resources
from mkosi.config import parse_config
from mkosi.distribution import Distribution, detect_distribution
from mkosi.log import log_setup
from mkosi.util import resource_path

from . import ImageConfig, ci_group


def pytest_addoption(parser: Any) -> None:
    distribution = detect_distribution()[0]
    parser.addoption(
        "-D",
        "--distribution",
        metavar="DISTRIBUTION",
        help="Run the integration tests for the given distribution.",
        default=distribution if isinstance(distribution, Distribution) else None,
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
        "--debug-shell",
        help="Pass --debug-shell when running mkosi",
        action="store_true",
    )


@pytest.fixture(scope="session")
def config(request: Any) -> ImageConfig:
    distribution = cast(Distribution, request.config.getoption("--distribution"))
    with resource_path(mkosi.resources) as resources:
        release = cast(
            str,
            request.config.getoption("--release")
            or parse_config(["-d", str(distribution)], resources=resources)[2][0].release,
        )
    return ImageConfig(
        distribution=distribution,
        release=release,
        debug_shell=request.config.getoption("--debug-shell"),
    )


@pytest.fixture(autouse=True)
def ci_sections(request: Any) -> Iterator[None]:
    with ci_group(request.node.name):
        yield


@pytest.fixture(scope="session", autouse=True)
def logging() -> None:
    log_setup()
