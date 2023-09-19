# SPDX-License-Identifier: LGPL-2.1+

import os
import textwrap
import uuid
from pathlib import Path
from typing import Optional

import pytest

from mkosi.architecture import Architecture
from mkosi.config import (
    BiosBootloader,
    Bootloader,
    Compression,
    ConfigFeature,
    DocFormat,
    ManifestFormat,
    MkosiArgs,
    MkosiConfig,
    OutputFormat,
    QemuFirmware,
    SecureBootSignTool,
    Verb,
)
from mkosi.distributions import Distribution


@pytest.mark.parametrize("path", [None, "/baz/qux"])
def test_args(path: Optional[Path]) -> None:
    dump = textwrap.dedent(
        f"""\
        {{
            "auto_bump": false,
            "cmdline": [
                "foo",
                "bar"
            ],
            "debug": false,
            "debug_shell": false,
            "directory": {f'"{os.fspath(path)}"' if path is not None else 'null'},
            "doc_format": "auto",
            "force": 9001,
            "genkey_common_name": "test",
            "genkey_valid_days": "100",
            "pager": true,
            "verb": "build"
        }}
        """
    )

    args = MkosiArgs(
        verb = Verb.build,
        cmdline = ["foo", "bar"],
        force = 9001,
        directory = Path(path) if path is not None else None,
        debug = False,
        debug_shell = False,
        pager = True,
        genkey_valid_days = "100",
        genkey_common_name = "test",
        auto_bump = False,
        doc_format = DocFormat.auto,
    )

    assert args.to_json(indent=4, sort_keys=True) == dump.rstrip()
    assert MkosiArgs.from_json(dump) == args


def test_config() -> None:
    dump = textwrap.dedent(
        """\
        {
            "acl": true,
            "architecture": "ia64",
            "autologin": false,
            "base_trees": [
                "/hello/world"
            ],
            "bios_bootloader": "none",
            "bootable": "disabled",
            "bootloader": "grub",
            "build_dir": null,
            "build_packages": [
                "pkg1",
                "pkg2"
            ],
            "build_scripts": [
                "/path/to/buildscript"
            ],
            "build_sources": [
                [
                    "/qux",
                    "/frob"
                ]
            ],
            "cache_dir": "/is/this/the/cachedir",
            "cache_only": true,
            "checksum": false,
            "clean_package_metadata": "auto",
            "compress_output": "bz2",
            "credentials": {
                "credkey": "credval"
            },
            "dependencies": [
                "dep1"
            ],
            "distribution": "fedora",
            "environment": {},
            "ephemeral": true,
            "extra_search_paths": [],
            "extra_trees": [],
            "finalize_scripts": [],
            "hostname": null,
            "image_id": "myimage",
            "image_version": "5",
            "include": [],
            "incremental": false,
            "initrd_packages": [
                "clevis"
            ],
            "initrds": [
                "/efi/initrd1",
                "/efi/initrd2"
            ],
            "kernel_command_line": [],
            "kernel_command_line_extra": [
                "look",
                "im",
                "on",
                "the",
                "kernel",
                "command",
                "line"
            ],
            "kernel_modules_exclude": [
                "nvidia"
            ],
            "kernel_modules_include": [
                "loop"
            ],
            "kernel_modules_initrd": true,
            "kernel_modules_initrd_exclude": [],
            "kernel_modules_initrd_include": [],
            "key": null,
            "keymap": "wow, so much keymap",
            "local_mirror": null,
            "locale": "en_C.UTF-8",
            "locale_messages": "",
            "make_initrd": false,
            "manifest_format": [
                "json",
                "changelog"
            ],
            "mirror": null,
            "nspawn_settings": null,
            "output": "outfile",
            "output_dir": "/your/output/here",
            "output_format": "uki",
            "overlay": true,
            "package_manager_trees": [
                [
                    "/foo/bar",
                    null
                ]
            ],
            "packages": [],
            "passphrase": null,
            "postinst_scripts": [
                "/bar/qux"
            ],
            "prepare_scripts": [
                "/run/foo"
            ],
            "preset": "default",
            "presets": [
                "default",
                "initrd"
            ],
            "qemu_args": [],
            "qemu_cdrom": false,
            "qemu_firmware": "linux",
            "qemu_gui": true,
            "qemu_kernel": null,
            "qemu_kvm": "auto",
            "qemu_mem": "",
            "qemu_smp": "yes",
            "qemu_swtpm": "auto",
            "qemu_vsock": "enabled",
            "release": "53",
            "remove_files": [],
            "remove_packages": [
                "all"
            ],
            "repart_dirs": [],
            "repositories": [],
            "repository_key_check": false,
            "root_password": [
                "test1234",
                false
            ],
            "root_shell": "/bin/tcsh",
            "runtime_size": 8589934592,
            "runtime_trees": [
                [
                    "/foo/bar",
                    "/baz"
                ],
                [
                    "/bar/baz",
                    "/qux"
                ]
            ],
            "sector_size": null,
            "secure_boot": true,
            "secure_boot_certificate": null,
            "secure_boot_key": "/path/to/keyfile",
            "secure_boot_sign_tool": "pesign",
            "seed": "7496d7d8-7f08-4a2b-96c6-ec8c43791b60",
            "sign": false,
            "sign_expected_pcr": "disabled",
            "skeleton_trees": [
                [
                    "/foo/bar",
                    null
                ],
                [
                    "/bar/baz",
                    "/qux"
                ]
            ],
            "source_date_epoch": 12345,
            "split_artifacts": true,
            "ssh": false,
            "timezone": null,
            "tools_tree": null,
            "tools_tree_distribution": null,
            "tools_tree_packages": [],
            "tools_tree_release": null,
            "use_subvolumes": "auto",
            "verity_certificate": "/path/to/cert",
            "verity_key": null,
            "with_docs": true,
            "with_network": false,
            "with_tests": true,
            "workspace_dir": "/cwd"
        }
        """
    )

    args = MkosiConfig(
        acl =  True,
        architecture = Architecture.ia64,
        autologin = False,
        base_trees = [Path("/hello/world")],
        bios_bootloader = BiosBootloader.none,
        bootable = ConfigFeature.disabled,
        bootloader = Bootloader.grub,
        build_dir = None,
        build_packages =  ["pkg1", "pkg2"],
        build_scripts =  [Path("/path/to/buildscript")],
        build_sources = [(Path("/qux"), Path("/frob"))],
        cache_dir = Path("/is/this/the/cachedir"),
        cache_only =  True,
        checksum =  False,
        clean_package_metadata = ConfigFeature.auto,
        compress_output = Compression.bz2,
        credentials =  {"credkey": "credval"},
        dependencies = ("dep1",),
        distribution = Distribution.fedora,
        environment = {},
        ephemeral = True,
        extra_search_paths = [],
        extra_trees = [],
        finalize_scripts = [],
        hostname = None,
        image_id = "myimage",
        image_version = "5",
        include = tuple(),
        incremental = False,
        initrd_packages = ["clevis"],
        initrds = [Path("/efi/initrd1"), Path("/efi/initrd2")],
        kernel_command_line = [],
        kernel_command_line_extra = ["look", "im", "on", "the", "kernel", "command", "line"],
        kernel_modules_exclude = ["nvidia"],
        kernel_modules_include = ["loop"],
        kernel_modules_initrd = True,
        kernel_modules_initrd_exclude = [],
        kernel_modules_initrd_include = [],
        key = None,
        keymap = "wow, so much keymap",
        local_mirror = None,
        locale = "en_C.UTF-8",
        locale_messages = "",
        make_initrd = False,
        manifest_format = [ManifestFormat.json, ManifestFormat.changelog],
        mirror = None,
        nspawn_settings = None,
        output = "outfile",
        output_dir = Path("/your/output/here"),
        output_format = OutputFormat.uki,
        overlay = True,
        package_manager_trees = [(Path("/foo/bar"), None)],
        packages = [],
        passphrase = None,
        postinst_scripts = [Path("/bar/qux")],
        prepare_scripts = [Path("/run/foo")],
        preset = "default",
        presets = ("default", "initrd"),
        qemu_args = [],
        qemu_cdrom = False,
        qemu_firmware = QemuFirmware.linux,
        qemu_gui = True,
        qemu_kernel = None,
        qemu_kvm = ConfigFeature.auto,
        qemu_mem = "",
        qemu_smp = "yes",
        qemu_swtpm = ConfigFeature.auto,
        qemu_vsock = ConfigFeature.enabled,
        release = "53",
        remove_files = [],
        remove_packages = ["all"],
        repart_dirs = [],
        repositories = [],
        repository_key_check = False,
        root_password = ("test1234", False),
        root_shell = "/bin/tcsh",
        runtime_size = 8589934592,
        runtime_trees = [(Path("/foo/bar"), Path("/baz")), (Path("/bar/baz"), Path("/qux"))],
        sector_size = None,
        secure_boot = True,
        secure_boot_certificate = None,
        secure_boot_key = Path("/path/to/keyfile"),
        secure_boot_sign_tool = SecureBootSignTool.pesign,
        seed = uuid.UUID("7496d7d8-7f08-4a2b-96c6-ec8c43791b60"),
        sign = False,
        sign_expected_pcr = ConfigFeature.disabled,
        skeleton_trees = [(Path("/foo/bar"), None), (Path("/bar/baz"), Path("/qux"))],
        source_date_epoch = 12345,
        split_artifacts = True,
        ssh = False,
        timezone = None,
        tools_tree = None,
        tools_tree_distribution = None,
        tools_tree_packages = [],
        tools_tree_release = None,
        use_subvolumes = ConfigFeature.auto,
        verity_certificate = Path("/path/to/cert"),
        verity_key = None,
        with_docs = True,
        with_network = False,
        with_tests =  True,
        workspace_dir = Path("/cwd"),
    )

    assert args.to_json() == dump.rstrip()
    assert MkosiConfig.from_json(dump) == args
