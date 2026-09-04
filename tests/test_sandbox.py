# SPDX-License-Identifier: LGPL-2.1-or-later

from unittest import mock

from mkosi.sandbox import acquire_privileges


def test_acquire_privileges_root_with_delegate_skips_userns() -> None:
    """Running as root with delegate>0 should not enter a user namespace.

    Regression test for https://github.com/systemd/mkosi/issues/4233:
    when mkosi runs as root, acquire_privileges(foreign=True, delegate=3)
    must return False (skip namespace entry) so that subsequent calls to
    ensure_directories_exist() retain host-root filesystem access.
    """
    with (
        mock.patch("mkosi.sandbox.have_effective_cap", return_value=True),
        mock.patch("os.getuid", return_value=0),
        mock.patch("os.getgid", return_value=0),
    ):
        result = acquire_privileges(foreign=True, delegate=3)
    assert result is False
