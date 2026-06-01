# SPDX-License-Identifier: LGPL-2.1-or-later

import importlib.util
import os
import shutil
import socket
import tempfile
from pathlib import Path

import pytest

from mkosi.run import run

REPO_ROOT = Path(__file__).parent.parent

# tolerate missing tools/prerequisites in some random dev or packaging environment, but enforce them
# in CI/mkosi box
SKIP_MISSING_TOOLS = "MKOSI_IN_BOX" not in os.environ


def _network_unavailable() -> bool:
    """Return True if we have no outbound network access (e.g. in an offline package build)."""
    try:
        with socket.create_connection(("pypi.org", 443), timeout=5):
            return False
    except OSError:
        return True


def _venv_unavailable() -> bool:
    """Return True if we should skip venv tests because ensurepip or network is missing."""
    return SKIP_MISSING_TOOLS and (importlib.util.find_spec("ensurepip") is None or _network_unavailable())


def _script_missing(script: str) -> bool:
    """Return True if we should skip the test because the helper script is missing."""
    return SKIP_MISSING_TOOLS and not (REPO_ROOT / script).exists()


def _tool_missing(tool: str) -> bool:
    """Return True if we should skip the test because tool is missing."""
    return SKIP_MISSING_TOOLS and shutil.which(tool) is None


def test_mkosi_help_direct() -> None:
    """Test mkosi can be run from current directory."""
    run(["python3", "-m", "mkosi", "-h"], cwd=REPO_ROOT)


@pytest.mark.skipif(_venv_unavailable(), reason="ensurepip or network not available")
def test_venv_installation() -> None:
    """Test mkosi can be installed in a venv."""
    with tempfile.TemporaryDirectory() as tmpdir:
        venv = Path(tmpdir) / "testvenv"

        # Create venv
        run(["python3", "-m", "venv", os.fspath(venv)], cwd=REPO_ROOT)
        pip = venv / "bin/python3"

        # Upgrade pip, setuptools, wheel
        run(
            [os.fspath(pip), "-m", "pip", "install", "--upgrade", "setuptools", "wheel", "pip"],
            cwd=REPO_ROOT,
        )

        # Install mkosi
        run([os.fspath(pip), "-m", "pip", "install", "."], cwd=REPO_ROOT)

        # Test that mkosi works
        run([os.fspath(venv / "bin/mkosi"), "-h"], cwd=REPO_ROOT)


@pytest.mark.skipif(_venv_unavailable(), reason="ensurepip or network not available")
def test_editable_venv_installation() -> None:
    """Test mkosi can be installed in editable mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        venv = Path(tmpdir) / "testvenv"

        run(["python3", "-m", "venv", os.fspath(venv)], cwd=REPO_ROOT)
        pip = venv / "bin/python3"

        # Upgrade pip, setuptools, wheel
        run(
            [os.fspath(pip), "-m", "pip", "install", "--upgrade", "setuptools", "wheel", "pip"],
            cwd=REPO_ROOT,
        )

        # Install mkosi in editable mode
        run([os.fspath(pip), "-m", "pip", "install", "--editable", "."], cwd=REPO_ROOT)

        # Test that mkosi works
        run([os.fspath(venv / "bin/mkosi"), "-h"], cwd=REPO_ROOT)


@pytest.mark.skipif(_script_missing("tools/generate-zipapp.sh"), reason="tools/generate-zipapp.sh not found")
@pytest.mark.skipif(_tool_missing("man"), reason="man not found")
def test_zipapp_creation() -> None:
    """Test zipapp generation."""
    run(["./tools/generate-zipapp.sh"], cwd=REPO_ROOT)

    run(["./builddir/mkosi", "-h"], cwd=REPO_ROOT)
    run(["./builddir/mkosi", "documentation"], cwd=REPO_ROOT)
