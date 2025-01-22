# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

from mkosi.config import Config
from mkosi.mounts import finalize_certificate_mounts
from mkosi.run import run, workdir


def curl(config: Config, url: str, output_dir: Path) -> None:
    run(
        [
            "curl",
            "--location",
            "--output-dir", workdir(output_dir),
            "--remote-name",
            "--no-progress-meter",
            "--fail",
            *(["--proxy", config.proxy_url] if config.proxy_url else []),
            *(["--noproxy", ",".join(config.proxy_exclude)] if config.proxy_exclude else []),
            *(["--proxy-capath", "/proxy.cacert"] if config.proxy_peer_certificate else []),
            *(["--proxy-cert", "/proxy.clientcert"] if config.proxy_client_certificate else []),
            *(["--proxy-key", "/proxy.clientkey"] if config.proxy_client_key else []),
            url,
        ],
        sandbox=config.sandbox(
            network=True,
            options=["--bind", output_dir, workdir(output_dir), *finalize_certificate_mounts(config)],
        ),
    )  # fmt: skip
