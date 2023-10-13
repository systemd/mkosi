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
            "AutoBump": false,
            "Cmdline": [
                "foo",
                "bar"
            ],
            "Debug": false,
            "DebugShell": false,
            "Directory": {f'"{os.fspath(path)}"' if path is not None else 'null'},
            "DocFormat": "auto",
            "Force": 9001,
            "GenkeyCommonName": "test",
            "GenkeyValidDays": "100",
            "Pager": true,
            "Verb": "build"
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
            "Acl": true,
            "Architecture": "ia64",
            "Autologin": false,
            "BaseTrees": [
                "/hello/world"
            ],
            "BiosBootloader": "none",
            "Bootable": "disabled",
            "Bootloader": "grub",
            "BuildDirectory": null,
            "BuildPackages": [
                "pkg1",
                "pkg2"
            ],
            "BuildScripts": [
                "/path/to/buildscript"
            ],
            "BuildSources": [
                [
                    "/qux",
                    "/frob"
                ]
            ],
            "CacheDirectory": "/is/this/the/cachedir",
            "CacheOnly": true,
            "Checksum": false,
            "CleanPackageMetadata": "auto",
            "CompressOutput": "bz2",
            "Credentials": {
                "credkey": "credval"
            },
            "Dependencies": [
                "dep1"
            ],
            "Distribution": "fedora",
            "Environment": {},
            "Ephemeral": true,
            "ExtraSearchPaths": [],
            "ExtraTrees": [],
            "FinalizeScripts": [],
            "Format": "uki",
            "Hostname": null,
            "ImageId": "myimage",
            "ImageVersion": "5",
            "Include": [],
            "Incremental": false,
            "InitrdPackages": [
                "clevis"
            ],
            "Initrds": [
                "/efi/initrd1",
                "/efi/initrd2"
            ],
            "KernelCommandLine": [],
            "KernelCommandLineExtra": [
                "look",
                "im",
                "on",
                "the",
                "kernel",
                "command",
                "line"
            ],
            "KernelModulesExclude": [
                "nvidia"
            ],
            "KernelModulesInclude": [
                "loop"
            ],
            "KernelModulesInitrd": true,
            "KernelModulesInitrdExclude": [],
            "KernelModulesInitrdInclude": [],
            "Key": null,
            "Keymap": "wow, so much keymap",
            "LocalMirror": null,
            "Locale": "en_C.UTF-8",
            "LocaleMessages": "",
            "MakeInitrd": false,
            "ManifestFormat": [
                "json",
                "changelog"
            ],
            "Mirror": null,
            "NSpawnSettings": null,
            "Output": "outfile",
            "OutputDirectory": "/your/output/here",
            "Overlay": true,
            "PackageManagerTrees": [
                [
                    "/foo/bar",
                    null
                ]
            ],
            "Packages": [],
            "Passphrase": null,
            "PostInstallationScripts": [
                "/bar/qux"
            ],
            "PrepareScripts": [
                "/run/foo"
            ],
            "Preset": "default",
            "Presets": [
                "default",
                "initrd"
            ],
            "QemuArgs": [],
            "QemuCdrom": false,
            "QemuFirmware": "linux",
            "QemuGui": true,
            "QemuKernel": null,
            "QemuKvm": "auto",
            "QemuMem": "",
            "QemuSmp": "yes",
            "QemuSwtpm": "auto",
            "QemuVsock": "enabled",
            "Release": "53",
            "RemoveFiles": [],
            "RemovePackages": [
                "all"
            ],
            "RepartDirectories": [],
            "Repositories": [],
            "RepositoryKeyCheck": false,
            "RootPassword": [
                "test1234",
                false
            ],
            "RootShell": "/bin/tcsh",
            "RuntimeSize": 8589934592,
            "RuntimeTrees": [
                [
                    "/foo/bar",
                    "/baz"
                ],
                [
                    "/bar/baz",
                    "/qux"
                ]
            ],
            "SectorSize": null,
            "SecureBoot": true,
            "SecureBootCertificate": null,
            "SecureBootKey": "/path/to/keyfile",
            "SecureBootSignTool": "pesign",
            "Seed": "7496d7d8-7f08-4a2b-96c6-ec8c43791b60",
            "Sign": false,
            "SignExpectedPcr": "disabled",
            "SkeletonTrees": [
                [
                    "/foo/bar",
                    null
                ],
                [
                    "/bar/baz",
                    "/qux"
                ]
            ],
            "SourceDateEpoch": 12345,
            "SplitArtifacts": true,
            "Ssh": false,
            "Timezone": null,
            "ToolsTree": null,
            "ToolsTreeDistribution": null,
            "ToolsTreePackages": [],
            "ToolsTreeRelease": null,
            "UseSubvolumes": "auto",
            "VerityCertificate": "/path/to/cert",
            "VerityKey": null,
            "WithDocs": true,
            "WithNetwork": false,
            "WithRecommends": true,
            "WithTests": true,
            "WorkspaceDirectory": "/cwd"
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
        with_recommends = True,
        with_tests =  True,
        workspace_dir = Path("/cwd"),
    )

    assert args.to_json() == dump.rstrip()
    assert MkosiConfig.from_json(dump) == args
