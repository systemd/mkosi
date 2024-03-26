# SPDX-License-Identifier: LGPL-2.1+

import os
import textwrap
import uuid
from pathlib import Path
from typing import Optional

import pytest

from mkosi.config import (
    Architecture,
    Args,
    BiosBootloader,
    Bootloader,
    Cacheonly,
    Compression,
    Config,
    ConfigFeature,
    ConfigTree,
    DocFormat,
    KeySource,
    ManifestFormat,
    Network,
    OutputFormat,
    QemuDrive,
    QemuFirmware,
    QemuVsockCID,
    SecureBootSignTool,
    ShimBootloader,
    Verb,
    Vmm,
)
from mkosi.distributions import Distribution
from mkosi.versioncomp import GenericVersion


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
            "DebugWorkspace": false,
            "Directory": {f'"{os.fspath(path)}"' if path is not None else 'null'},
            "DocFormat": "auto",
            "Force": 9001,
            "GenkeyCommonName": "test",
            "GenkeyValidDays": "100",
            "Json": false,
            "Pager": true,
            "Verb": "build"
        }}
        """
    )

    args = Args(
        auto_bump = False,
        cmdline = ["foo", "bar"],
        debug = False,
        debug_shell = False,
        debug_workspace = False,
        directory = Path(path) if path is not None else None,
        doc_format = DocFormat.auto,
        force = 9001,
        genkey_common_name = "test",
        genkey_valid_days = "100",
        json = False,
        pager = True,
        verb = Verb.build,
    )

    assert args.to_json(indent=4, sort_keys=True) == dump.rstrip()
    assert Args.from_json(dump) == args


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
                {
                    "source": "/qux",
                    "target": "/frob"
                }
            ],
            "BuildSourcesEphemeral": true,
            "CacheDirectory": "/is/this/the/cachedir",
            "CacheOnly": "always",
            "Checksum": false,
            "CleanPackageMetadata": "auto",
            "CompressLevel": 3,
            "CompressOutput": "bz2",
            "ConfigureScripts": [
                "/configure"
            ],
            "Credentials": {
                "credkey": "credval"
            },
            "Dependencies": [
                "dep1"
            ],
            "Distribution": "fedora",
            "Environment": {},
            "EnvironmentFiles": [],
            "Ephemeral": true,
            "ExtraSearchPaths": [],
            "ExtraTrees": [],
            "FinalizeScripts": [],
            "Format": "uki",
            "Hostname": null,
            "Image": "default",
            "ImageId": "myimage",
            "ImageVersion": "5",
            "Images": [
                "default",
                "initrd"
            ],
            "Include": [],
            "Incremental": false,
            "InitrdInclude": [
                "/foo/bar"
            ],
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
            "KernelModulesIncludeHost": true,
            "KernelModulesInitrd": true,
            "KernelModulesInitrdExclude": [],
            "KernelModulesInitrdInclude": [],
            "KernelModulesInitrdIncludeHost": true,
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
            "MicrocodeHost": true,
            "MinimumVersion": "123",
            "Mirror": null,
            "NSpawnSettings": null,
            "Output": "outfile",
            "OutputDirectory": "/your/output/here",
            "Overlay": true,
            "PackageCacheDirectory": "/a/b/c",
            "PackageDirectories": [],
            "PackageManagerTrees": [
                {
                    "source": "/foo/bar",
                    "target": null
                }
            ],
            "Packages": [],
            "Passphrase": null,
            "PostInstallationScripts": [
                "/bar/qux"
            ],
            "PrepareScripts": [
                "/run/foo"
            ],
            "Profile": "profile",
            "ProxyClientCertificate": "/my/client/cert",
            "ProxyClientKey": "/my/client/key",
            "ProxyPeerCertificate": "/my/peer/cert",
            "ProxyUrl": "https://my/proxy",
            "QemuArgs": [],
            "QemuCdrom": false,
            "QemuDrives": [
                {
                    "directory": "/foo/bar",
                    "id": "abc",
                    "options": "abc,qed",
                    "size": 200
                },
                {
                    "directory": null,
                    "id": "abc",
                    "options": "",
                    "size": 200
                }
            ],
            "QemuFirmware": "linux",
            "QemuFirmwareVariables": "/foo/bar",
            "QemuGui": true,
            "QemuKernel": null,
            "QemuKvm": "auto",
            "QemuMem": 123,
            "QemuSmp": 2,
            "QemuSwtpm": "auto",
            "QemuVsock": "enabled",
            "QemuVsockConnectionId": -2,
            "Release": "53",
            "RemoveFiles": [],
            "RemovePackages": [
                "all"
            ],
            "RepartDirectories": [],
            "RepartOffline": true,
            "Repositories": [],
            "RepositoryKeyCheck": false,
            "RootPassword": [
                "test1234",
                false
            ],
            "RootShell": "/bin/tcsh",
            "RuntimeNetwork": "interface",
            "RuntimeScratch": "enabled",
            "RuntimeSize": 8589934592,
            "RuntimeTrees": [
                {
                    "source": "/foo/bar",
                    "target": "/baz"
                },
                {
                    "source": "/bar/baz",
                    "target": "/qux"
                }
            ],
            "SELinuxRelabel": "disabled",
            "SectorSize": null,
            "SecureBoot": true,
            "SecureBootAutoEnroll": true,
            "SecureBootCertificate": null,
            "SecureBootKey": "/path/to/keyfile",
            "SecureBootKeySource": {
                "source": "",
                "type": "file"
            },
            "SecureBootSignTool": "pesign",
            "Seed": "7496d7d8-7f08-4a2b-96c6-ec8c43791b60",
            "ShimBootloader": "none",
            "Sign": false,
            "SignExpectedPcr": "disabled",
            "SkeletonTrees": [
                {
                    "source": "/foo/bar",
                    "target": "/"
                },
                {
                    "source": "/bar/baz",
                    "target": "/qux"
                }
            ],
            "SourceDateEpoch": 12345,
            "SplitArtifacts": true,
            "Ssh": false,
            "SshCertificate": "/path/to/cert",
            "SshKey": null,
            "SyncScripts": [
                "/sync"
            ],
            "Timezone": null,
            "ToolsTree": null,
            "ToolsTreeDistribution": null,
            "ToolsTreeMirror": null,
            "ToolsTreePackageManagerTrees": [
                {
                    "source": "/a/b/c",
                    "target": "/"
                }
            ],
            "ToolsTreePackages": [],
            "ToolsTreeRelease": null,
            "ToolsTreeRepositories": [
                "abc"
            ],
            "UnifiedKernelImages": "auto",
            "UseSubvolumes": "auto",
            "VerityCertificate": "/path/to/cert",
            "VerityKey": null,
            "VerityKeySource": {
                "source": "",
                "type": "file"
            },
            "VirtualMachineMonitor": "qemu",
            "WithDocs": true,
            "WithNetwork": false,
            "WithRecommends": true,
            "WithTests": true,
            "WorkspaceDirectory": "/cwd"
        }
        """
    )

    args = Config(
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
        build_sources = [ConfigTree(Path("/qux"), Path("/frob"))],
        build_sources_ephemeral = True,
        cache_dir = Path("/is/this/the/cachedir"),
        cacheonly = Cacheonly.always,
        checksum =  False,
        clean_package_metadata = ConfigFeature.auto,
        compress_level = 3,
        compress_output = Compression.bz2,
        configure_scripts = [Path("/configure")],
        credentials =  {"credkey": "credval"},
        dependencies = ("dep1",),
        distribution = Distribution.fedora,
        environment = {},
        environment_files = [],
        ephemeral = True,
        extra_search_paths = [],
        extra_trees = [],
        finalize_scripts = [],
        hostname = None,
        vmm = Vmm.qemu,
        image = "default",
        image_id = "myimage",
        image_version = "5",
        images = ("default", "initrd"),
        include = [],
        incremental = False,
        initrd_include = [Path("/foo/bar"),],
        initrd_packages = ["clevis"],
        initrds = [Path("/efi/initrd1"), Path("/efi/initrd2")],
        microcode_host=True,
        kernel_command_line = [],
        kernel_command_line_extra = ["look", "im", "on", "the", "kernel", "command", "line"],
        kernel_modules_exclude = ["nvidia"],
        kernel_modules_include = ["loop"],
        kernel_modules_include_host = True,
        kernel_modules_initrd = True,
        kernel_modules_initrd_exclude = [],
        kernel_modules_initrd_include = [],
        kernel_modules_initrd_include_host = True,
        key = None,
        keymap = "wow, so much keymap",
        local_mirror = None,
        locale = "en_C.UTF-8",
        locale_messages = "",
        make_initrd = False,
        manifest_format = [ManifestFormat.json, ManifestFormat.changelog],
        minimum_version = GenericVersion("123"),
        mirror = None,
        nspawn_settings = None,
        output = "outfile",
        output_dir = Path("/your/output/here"),
        output_format = OutputFormat.uki,
        overlay = True,
        package_cache_dir = Path("/a/b/c"),
        package_directories = [],
        package_manager_trees = [ConfigTree(Path("/foo/bar"), None)],
        packages = [],
        passphrase = None,
        postinst_scripts = [Path("/bar/qux")],
        prepare_scripts = [Path("/run/foo")],
        profile = "profile",
        proxy_client_certificate = Path("/my/client/cert"),
        proxy_client_key = Path("/my/client/key"),
        proxy_peer_certificate = Path("/my/peer/cert"),
        proxy_url = "https://my/proxy",
        qemu_args = [],
        qemu_cdrom = False,
        qemu_drives = [QemuDrive("abc", 200, Path("/foo/bar"), "abc,qed"), QemuDrive("abc", 200, None, "")],
        qemu_firmware = QemuFirmware.linux,
        qemu_firmware_variables = Path("/foo/bar"),
        qemu_gui = True,
        qemu_kernel = None,
        qemu_kvm = ConfigFeature.auto,
        qemu_mem = 123,
        qemu_smp = 2,
        qemu_swtpm = ConfigFeature.auto,
        qemu_vsock = ConfigFeature.enabled,
        qemu_vsock_cid = QemuVsockCID.hash,
        release = "53",
        remove_files = [],
        remove_packages = ["all"],
        repart_dirs = [],
        repart_offline = True,
        repositories = [],
        repository_key_check = False,
        root_password = ("test1234", False),
        root_shell = "/bin/tcsh",
        runtime_network = Network.interface,
        runtime_scratch = ConfigFeature.enabled,
        runtime_size = 8589934592,
        runtime_trees = [ConfigTree(Path("/foo/bar"), Path("/baz")), ConfigTree(Path("/bar/baz"), Path("/qux"))],
        sector_size = None,
        secure_boot = True,
        secure_boot_auto_enroll = True,
        secure_boot_certificate = None,
        secure_boot_key = Path("/path/to/keyfile"),
        secure_boot_key_source = KeySource(type=KeySource.Type.file),
        secure_boot_sign_tool = SecureBootSignTool.pesign,
        seed = uuid.UUID("7496d7d8-7f08-4a2b-96c6-ec8c43791b60"),
        selinux_relabel = ConfigFeature.disabled,
        shim_bootloader = ShimBootloader.none,
        sign = False,
        sign_expected_pcr = ConfigFeature.disabled,
        skeleton_trees = [ConfigTree(Path("/foo/bar"), Path("/")), ConfigTree(Path("/bar/baz"), Path("/qux"))],
        source_date_epoch = 12345,
        split_artifacts = True,
        ssh = False,
        ssh_certificate = Path("/path/to/cert"),
        ssh_key = None,
        sync_scripts = [Path("/sync")],
        timezone = None,
        tools_tree = None,
        tools_tree_distribution = None,
        tools_tree_mirror = None,
        tools_tree_package_manager_trees = [ConfigTree(Path("/a/b/c"), Path("/"))],
        tools_tree_packages = [],
        tools_tree_release = None,
        tools_tree_repositories = ["abc"],
        unified_kernel_images = ConfigFeature.auto,
        use_subvolumes = ConfigFeature.auto,
        verity_certificate = Path("/path/to/cert"),
        verity_key = None,
        verity_key_source = KeySource(type=KeySource.Type.file),
        with_docs = True,
        with_network = False,
        with_recommends = True,
        with_tests =  True,
        workspace_dir = Path("/cwd"),
    )

    assert args.to_json() == dump.rstrip()
    assert Config.from_json(dump) == args
