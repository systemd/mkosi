# SPDX-License-Identifier: LGPL-2.1-or-later

from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from mkosi.config import Architecture
from mkosi.distribution.alinux import Installer


def _context(
    release: str = "3",
    *,
    mirror: Optional[str] = None,
    local_mirror: Optional[str] = None,
    epel_mirror: Optional[str] = None,
) -> MagicMock:
    context = MagicMock()
    context.config.release = release
    context.config.snapshot = None
    context.config.mirror = mirror
    context.config.local_mirror = local_mirror
    env = {}
    if epel_mirror is not None:
        env["EPEL_MIRROR"] = epel_mirror
    context.config.finalize_environment.return_value = env
    return context


def test_alinux_repository_urls() -> None:
    context = _context()

    repos = Installer.repository_variants(context, ("gpg",), "os")
    assert repos[0].url == "baseurl=https://mirrors.aliyun.com/alinux/$releasever/os/$basearch"

    repos = Installer.repository_variants(context, ("gpg",), "updates")
    assert repos[0].url == "baseurl=https://mirrors.aliyun.com/alinux/$releasever/updates/$basearch"

    context = _context(mirror="https://example.com/alinux")
    repos = Installer.repository_variants(context, ("gpg",), "os")
    assert repos[0].url == "baseurl=https://example.com/alinux/$releasever/os/$basearch"


def test_alinux_repositories() -> None:
    context = _context()

    with patch("mkosi.distribution.alinux.find_rpm_gpgkey", side_effect=lambda *args, **kwargs: "gpg"):
        repos = {repo.id: repo for repo in Installer.repositories(context)}

    assert set(repos) == {"os", "updates", "plus", "module", "powertools", "epel"}
    assert repos["os"].url == "baseurl=https://mirrors.aliyun.com/alinux/$releasever/os/$basearch"
    assert not repos["os"].repo_gpgcheck
    assert repos["epel"].url == "baseurl=https://mirrors.aliyun.com/epel/8/Everything/$basearch"
    assert not repos["epel"].enabled
    assert not repos["epel"].repo_gpgcheck


def test_alinux_epel_follows_mirror() -> None:
    context = _context(mirror="https://example.com/alinux")

    with patch("mkosi.distribution.alinux.find_rpm_gpgkey", side_effect=lambda *args, **kwargs: "gpg"):
        repos = {repo.id: repo for repo in Installer.repositories(context)}

    assert repos["epel"].url == "baseurl=https://example.com/epel/8/Everything/$basearch"

    context = _context(epel_mirror="https://epel.example.com")
    with patch("mkosi.distribution.alinux.find_rpm_gpgkey", side_effect=lambda *args, **kwargs: "gpg"):
        repos = {repo.id: repo for repo in Installer.repositories(context)}

    assert repos["epel"].url == "baseurl=https://epel.example.com/epel/8/Everything/$basearch"


def test_alinux_local_mirror() -> None:
    context = _context(local_mirror="https://example.com/local")

    with patch("mkosi.distribution.alinux.find_rpm_gpgkey", side_effect=lambda *args, **kwargs: "gpg"):
        repos = list(Installer.repositories(context))

    assert len(repos) == 1
    assert repos[0].id == "local"
    assert repos[0].url == "baseurl=https://example.com/local"


def test_alinux_unsupported_release() -> None:
    context = _context("4")

    with pytest.raises(SystemExit):
        Installer.setup(context)


def test_alinux_snapshot_unsupported() -> None:
    context = _context()
    context.config.snapshot = "20240101"

    with pytest.raises(SystemExit):
        Installer.repository_variants(context, ("gpg",), "os")


def test_alinux_architecture() -> None:
    assert Installer.architecture(Architecture.x86_64) == "x86_64"
    assert Installer.architecture(Architecture.arm64) == "aarch64"

    with pytest.raises(SystemExit):
        Installer.architecture(Architecture.s390x)


def test_alinux_gpgurls_remote_fallback() -> None:
    context = _context()

    with patch("mkosi.distribution.alinux.find_rpm_gpgkey", return_value=None):
        assert Installer.gpgurls(context) == ("https://mirrors.aliyun.com/alinux/3/RPM-GPG-KEY-ALINUX-3",)

    context = _context(mirror="https://example.com/alinux")
    with patch("mkosi.distribution.alinux.find_rpm_gpgkey", return_value=None):
        assert Installer.gpgurls(context) == ("https://example.com/alinux/3/RPM-GPG-KEY-ALINUX-3",)

    with patch("mkosi.distribution.alinux.find_rpm_gpgkey", return_value="file:///local.key"):
        assert Installer.gpgurls(context) == ("file:///local.key",)
