# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import tempfile
from pathlib import Path

from mkosi.run import run

REPO_ROOT = Path(__file__).parent.parent


def test_mkosi_help_direct() -> None:
    """Test mkosi can be run from current directory."""
    run(["python3", "-m", "mkosi", "-h"], cwd=REPO_ROOT)


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


def test_zipapp_creation() -> None:
    """Test zipapp generation."""
    run(["./tools/generate-zipapp.sh"], cwd=REPO_ROOT)

    run(["./builddir/mkosi", "-h"], cwd=REPO_ROOT)
    run(["./builddir/mkosi", "documentation"], cwd=REPO_ROOT)
