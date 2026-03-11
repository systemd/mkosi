# SPDX-License-Identifier: LGPL-2.1-or-later

import ssl
import urllib.parse
import urllib.request

from mkosi.config import Config


def url_should_proxy(url: str, proxy_exclude: list[str]) -> bool:
    if not proxy_exclude:
        return True

    host = urllib.parse.urlparse(url).hostname or ""

    for pattern in proxy_exclude:
        pattern = pattern.strip().lstrip(".").lower()

        if not pattern:
            continue

        if pattern == "*":
            return False

        if host == pattern or host.endswith(f".{pattern}"):
            return False

    return True


def curl(config: Config, url: str) -> str:
    handlers: list[urllib.request.BaseHandler] = []

    if config.proxy_url and url_should_proxy(url, config.proxy_exclude):
        handlers.append(urllib.request.ProxyHandler({"http": config.proxy_url, "https": config.proxy_url}))

    context = ssl.create_default_context()

    if config.proxy_peer_certificate:
        context.load_verify_locations(cafile=config.proxy_peer_certificate)

    if config.proxy_client_certificate:
        context.load_cert_chain(
            certfile=config.proxy_client_certificate,
            keyfile=config.proxy_client_key,
        )

    handlers.append(urllib.request.HTTPSHandler(context=context))

    opener = urllib.request.build_opener(*handlers)

    with opener.open(url) as response:
        result: bytes = response.read()
        return result.decode()
