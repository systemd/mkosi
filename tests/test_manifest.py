# SPDX-License-Identifier: LGPL-2.1-or-later

import logging
from pathlib import Path

import pytest

from mkosi import save_manifest
from mkosi.config import parse_config
from mkosi.context import Context
from mkosi.manifest import Manifest, PackageManifest
from mkosi.util import chdir


def make_context(tmp_path: Path, argv: list[str]) -> Context:
    with chdir(tmp_path):
        args, _, [config] = parse_config(argv)

    workspace = tmp_path / "workspace"
    workspace.mkdir()

    return Context(
        args,
        config,
        workspace=workspace,
        resources=tmp_path,
        keyring_dir=tmp_path,
        metadata_dir=tmp_path,
    )


@pytest.mark.parametrize("formats", ["json", "changelog", "json,changelog"])
@pytest.mark.parametrize("distribution", ["fedora", "debian", "arch", "nura", "custom"])
@pytest.mark.parametrize("base_trees", [True, False])
@pytest.mark.parametrize("packages", [True, False])
def test_save_manifest(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    formats: str,
    distribution: str,
    base_trees: bool,
    packages: bool,
) -> None:
    argv = [f"--manifest-format={formats}", f"--distribution={distribution}"]
    if base_trees:
        (tmp_path / "base").mkdir()
        argv += ["--base-tree=base"]

    context = make_context(tmp_path, argv)
    manifest = Manifest(context)
    if packages:
        manifest.packages.append(PackageManifest("rpm", "strace", "6.0-1", "aarch64", 1024))

    with caplog.at_level(logging.WARNING):
        save_manifest(context, manifest)

    manifest_path = context.staging / context.config.output_manifest
    changelog_path = context.staging / context.config.output_changelog
    assert manifest_path.exists() == (packages and "json" in formats)
    assert changelog_path.exists() == (packages and "changelog" in formats)

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    # Only the rpm and deb recorders leave out packages from base trees, so only they can explain
    # an empty manifest that way.
    if base_trees and not packages and distribution in ("fedora", "debian"):
        assert len(warnings) == 1
        assert "base trees" in warnings[0]
        assert (context.config.output_manifest in warnings[0]) == ("json" in formats)
        assert (context.config.output_changelog in warnings[0]) == ("changelog" in formats)
    else:
        assert warnings == []
