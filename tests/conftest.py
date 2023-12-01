# SPDX-License-Identifier: LGPL-2.1+
from typing import Any, Optional, cast

import pytest

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


@pytest.fixture(scope="session")
def config(request: Any) -> Image.Config:
    distribution = cast(Distribution, request.config.getoption("--distribution"))
    release = cast(Optional[str], request.config.getoption("--release"))
    if release is None:
        release = distribution.default_release()

    return Image.Config(distribution=distribution, release=release)
