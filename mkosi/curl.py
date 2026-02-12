# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import subprocess
from pathlib import Path
from typing import overload

from mkosi.config import Config
from mkosi.mounts import finalize_certificate_mounts
from mkosi.run import run, workdir


@overload
def curl(
    config: Config,
    url: str,
    *,
    output_dir: Path | None,
    log: bool = True,
) -> None: ...


@overload
def curl(
    config: Config,
    url: str,
    *,
    output_dir: None = None,
    log: bool = True,
) -> str: ...


def curl(config: Config, url: str, *, output_dir: Path | None = None, log: bool = True) -> str | None:
    result = run(
        [
            "curl",
            "--location",
            *(["--output-dir", workdir(output_dir)] if output_dir else []),
            *(["--remote-name"] if output_dir else []),
            "--no-progress-meter",
            "--fail",
            *(["--silent"] if not log else []),
            *(["--proxy", config.proxy_url] if config.proxy_url else []),
            *(["--noproxy", ",".join(config.proxy_exclude)] if config.proxy_exclude else []),
            *(["--proxy-capath", "/proxy.cacert"] if config.proxy_peer_certificate else []),
            *(["--proxy-cert", "/proxy.clientcert"] if config.proxy_client_certificate else []),
            *(["--proxy-key", "/proxy.clientkey"] if config.proxy_client_key else []),
            url,
        ],
        stdout=None if output_dir else subprocess.PIPE,
        sandbox=config.sandbox(
            network=True,
            options=[
                *(["--bind", os.fspath(output_dir), workdir(output_dir)] if output_dir else []),
                *finalize_certificate_mounts(config)
            ],
        ),
        log=log,
    )  # fmt: skip

    return None if output_dir else result.stdout
