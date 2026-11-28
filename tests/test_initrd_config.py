# SPDX-License-Identifier: LGPL-2.1-or-later

from pathlib import Path

import pytest

import mkosi.resources
from mkosi.config import parse_config
from mkosi.context import Context
from mkosi.initrd import populate_sandbox_tree
from mkosi.installer.dnf import Dnf
from mkosi.util import chdir, resource_path


def test_populate_sandbox_tree(tmp_path: Path) -> None:
    root = tmp_path / "root"
    sandbox = tmp_path / "sandbox"

    for rel, content in (
        ("usr/share/dnf5/repos.d/fedora.repo", "[fedora]\nname=vendor\n"),
        ("usr/share/dnf5/repos.d/override.repo", "[override]\nname=vendor\n"),
        ("etc/distro.repos.d/override.repo", "[override]\nname=distro\n"),
        ("etc/yum.repos.d/local.repo", "[local]\nname=local\n"),
        ("usr/share/dnf5/vars.d/v1", "vendor1\n"),
        ("usr/share/dnf5/vars.d/v2", "vendor2\n"),
        ("etc/dnf/vars/v1", "etc1\n"),
        ("etc/dnf/dnf.conf", "[main]\n"),
    ):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    populate_sandbox_tree(sandbox, root=root)

    # Default mkosi repo stubs are created empty so mkosi doesn't generate its own repos.
    assert (sandbox / "etc/yum.repos.d/mkosi.repo").read_text() == ""
    assert (sandbox / "etc/apt/sources.list.d/mkosi.sources").read_text() == ""
    assert (sandbox / "etc/zypp/repos.d/mkosi.repo").read_text() == ""
    assert (sandbox / "etc/pacman.conf").read_text() == ""

    # Vendor dnf5 repos are copied into etc/distro.repos.d and overridden by /etc/distro.repos.d,
    # leaving /etc/yum.repos.d unmerged.
    assert (sandbox / "etc/distro.repos.d/fedora.repo").read_text() == "[fedora]\nname=vendor\n"
    assert (sandbox / "etc/distro.repos.d/override.repo").read_text() == "[override]\nname=distro\n"
    assert (sandbox / "etc/yum.repos.d/local.repo").read_text() == "[local]\nname=local\n"
    assert not (sandbox / "etc/yum.repos.d/fedora.repo").exists()

    # Vendor dnf5 vars are copied into etc/dnf/vars and overridden by /etc/dnf/vars.
    assert (sandbox / "etc/dnf/vars/v1").read_text() == "etc1\n"
    assert (sandbox / "etc/dnf/vars/v2").read_text() == "vendor2\n"
    assert (sandbox / "etc/dnf/dnf.conf").read_text() == "[main]\n"


@pytest.mark.parametrize("dnf", ["dnf5", "dnf"])
def test_dnf_cmd_reposdir_varsdir(tmp_path: Path, dnf: str) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with chdir(tmp_path), resource_path(mkosi.resources) as resources:
        args, _, [config] = parse_config(
            ["--distribution=centos", "--release=10", f"--environment=MKOSI_DNF={dnf}"],
            resources=resources,
        )
        context = Context(
            args,
            config,
            workspace=workspace,
            resources=resources,
            keyring_dir=tmp_path / "keyring",
            metadata_dir=tmp_path / "metadata",
        )
        cmd = Dnf.cmd(context)

    assert cmd[0] == dnf
    assert ("--use-host-config" if dnf == "dnf5" else "--config=/etc/dnf/dnf.conf") in cmd
    assert "--setopt=reposdir=/etc/yum.repos.d,/etc/distro.repos.d" in cmd
    assert "--setopt=varsdir=/etc/dnf/vars" in cmd
