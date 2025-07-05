# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import textwrap
import uuid
from pathlib import Path
from typing import Optional

import pytest

from mkosi.config import (
    Architecture,
    Args,
    ArtifactOutput,
    BiosBootloader,
    Bootloader,
    BuildSourcesEphemeral,
    Cacheonly,
    CertificateSource,
    CertificateSourceType,
    Compression,
    Config,
    ConfigFeature,
    ConfigTree,
    ConsoleMode,
    DocFormat,
    Drive,
    DriveFlag,
    Firmware,
    Incremental,
    InitrdProfile,
    KeySource,
    KeySourceType,
    ManifestFormat,
    Network,
    OutputFormat,
    SecureBootSignTool,
    ShimBootloader,
    Ssh,
    UKIProfile,
    Verb,
    Verity,
    Vmm,
    VsockCID,
    dump_json,
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
            "DebugSandbox": false,
            "DebugShell": false,
            "DebugWorkspace": false,
            "Directory": {f'"{os.fspath(path)}"' if path is not None else "null"},
            "DocFormat": "auto",
            "Force": 9001,
            "GenkeyCommonName": "test",
            "GenkeyValidDays": "100",
            "Json": false,
            "Pager": true,
            "RerunBuildScripts": true,
            "Verb": "build",
            "WipeBuildDir": true
        }}
        """
    )

    args = Args(
        auto_bump=False,
        cmdline=["foo", "bar"],
        debug=False,
        debug_sandbox=False,
        debug_shell=False,
        debug_workspace=False,
        directory=Path(path) if path is not None else None,
        doc_format=DocFormat.auto,
        force=9001,
        genkey_common_name="test",
        genkey_valid_days="100",
        json=False,
        pager=True,
        rerun_build_scripts=True,
        verb=Verb.build,
        wipe_build_dir=True,
    )

    assert dump_json(args.to_dict()) == dump.rstrip()
    assert Args.from_json(dump) == args


def test_config() -> None:
    dump = textwrap.dedent(
        """\
        {
            "Architecture": "ia64",
            "Autologin": false,
            "BaseTrees": [
                "/hello/world"
            ],
            "BiosBootloader": "none",
            "Bootable": "disabled",
            "Bootloader": "grub",
            "BuildDirectory": "abc",
            "BuildKey": "abc",
            "BuildPackages": [
                "pkg1",
                "pkg2"
            ],
            "BuildScripts": [
                "/path/to/buildscript"
            ],
            "BuildSources": [
                {
                    "Source": "/qux",
                    "Target": "/frob"
                }
            ],
            "BuildSourcesEphemeral": "yes",
            "BuildSubdirectory": "abc/abc",
            "CDROM": false,
            "CPUs": 2,
            "CacheDirectory": "/is/this/the/cachedir",
            "CacheKey": "qed",
            "CacheOnly": "always",
            "Checksum": false,
            "CleanPackageMetadata": "auto",
            "CleanScripts": [
                "/clean"
            ],
            "CompressLevel": 3,
            "CompressOutput": "bz2",
            "ConfigureScripts": [
                "/configure"
            ],
            "Console": "gui",
            "Credentials": {
                "credkey": "credval"
            },
            "Dependencies": [
                "dep1"
            ],
            "Devicetree": "freescale/imx8mm-verdin-nonwifi-dev.dtb",
            "Distribution": "fedora",
            "Drives": [
                {
                    "Directory": "/foo/bar",
                    "FileId": "red",
                    "Flags": [],
                    "Id": "abc",
                    "Options": "abc,qed",
                    "Size": 200
                },
                {
                    "Directory": null,
                    "FileId": "wcd",
                    "Flags": [],
                    "Id": "abc",
                    "Options": "",
                    "Size": 200
                },
                {
                    "Directory": null,
                    "FileId": "bla",
                    "Flags": [
                        "persist"
                    ],
                    "Id": "abc",
                    "Options": "",
                    "Size": 200
                }
            ],
            "Environment": {
                "BAR": "BAR",
                "Qux": "Qux",
                "foo": "foo"
            },
            "EnvironmentFiles": [],
            "Ephemeral": true,
            "ExtraSearchPaths": [],
            "ExtraTrees": [],
            "Files": [],
            "FinalizeScripts": [],
            "Firmware": "linux",
            "FirmwareExclude": [
                "brcm/"
            ],
            "FirmwareFiles": [
                "ath3k-1"
            ],
            "FirmwareVariables": "/foo/bar",
            "Format": "uki",
            "ForwardJournal": "/mkosi.journal",
            "History": true,
            "Hostname": null,
            "Image": "main",
            "ImageId": "myimage",
            "ImageVersion": "5",
            "Incremental": "no",
            "InitrdPackages": [
                "clevis"
            ],
            "InitrdProfiles": [
                "lvm"
            ],
            "InitrdVolatilePackages": [
                "abc"
            ],
            "Initrds": [
                "/efi/initrd1",
                "/efi/initrd2"
            ],
            "KVM": "auto",
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
            "KernelInitrdModules": [],
            "KernelModules": [
                "loop"
            ],
            "KernelModulesExclude": [
                "nvidia"
            ],
            "KernelModulesIncludeHost": true,
            "KernelModulesInitrd": true,
            "KernelModulesInitrdExclude": [],
            "KernelModulesInitrdIncludeHost": true,
            "Key": null,
            "Keymap": "wow, so much keymap",
            "Linux": null,
            "LocalMirror": null,
            "Locale": "en_C.UTF-8",
            "LocaleMessages": "",
            "Machine": "machine",
            "MachineId": "b58253b0-cc92-4a34-8782-bcd99b20d07f",
            "MakeInitrd": false,
            "ManifestFormat": [
                "json",
                "changelog"
            ],
            "MicrocodeHost": true,
            "MinimumVersion": "123",
            "Mirror": null,
            "NSpawnSettings": null,
            "OpenPGPTool": "gpg",
            "Output": "outfile",
            "OutputDirectory": "/your/output/here",
            "OutputExtension": "raw",
            "OutputMode": 83,
            "Overlay": true,
            "PackageCacheDirectory": "/a/b/c",
            "PackageDirectories": [],
            "Packages": [],
            "PassEnvironment": [
                "abc"
            ],
            "Passphrase": null,
            "PostInstallationScripts": [
                "/bar/qux"
            ],
            "PostOutputScripts": [
                "/foo/src"
            ],
            "PrepareScripts": [
                "/run/foo"
            ],
            "Profiles": [
                "profile"
            ],
            "ProxyClientCertificate": "/my/client/cert",
            "ProxyClientKey": "/my/client/key",
            "ProxyExclude": [
                "www.example.com"
            ],
            "ProxyPeerCertificate": "/my/peer/cert",
            "ProxyUrl": "https://my/proxy",
            "QemuArgs": [],
            "RAM": 123,
            "Register": "enabled",
            "Release": "53",
            "Removable": false,
            "RemoveFiles": [],
            "SkipPackages": [],
            "RemovePackages": [
                "all"
            ],
            "RepartDirectories": [],
            "RepartOffline": true,
            "Repositories": [],
            "RepositoryKeyCheck": false,
            "RepositoryKeyFetch": true,
            "RootPassword": [
                "test1234",
                false
            ],
            "RootShell": "/bin/tcsh",
            "RuntimeBuildSources": true,
            "RuntimeHome": true,
            "RuntimeNetwork": "interface",
            "RuntimeScratch": "enabled",
            "RuntimeSize": 8589934592,
            "RuntimeTrees": [
                {
                    "Source": "/foo/bar",
                    "Target": "/baz"
                },
                {
                    "Source": "/bar/baz",
                    "Target": "/qux"
                }
            ],
            "SELinuxRelabel": "disabled",
            "SandboxTrees": [
                {
                    "Source": "/foo/bar",
                    "Target": null
                }
            ],
            "SectorSize": null,
            "SecureBoot": true,
            "SecureBootAutoEnroll": true,
            "SecureBootCertificate": null,
            "SecureBootCertificateSource": {
                "Source": "",
                "Type": "file"
            },
            "SecureBootKey": "/path/to/keyfile",
            "SecureBootKeySource": {
                "Source": "",
                "Type": "file"
            },
            "SecureBootSignTool": "systemd-sbsign",
            "Seed": "7496d7d8-7f08-4a2b-96c6-ec8c43791b60",
            "ShimBootloader": "none",
            "Sign": false,
            "SignExpectedPcr": "disabled",
            "SignExpectedPcrCertificate": "/my/cert",
            "SignExpectedPcrCertificateSource": {
                "Source": "",
                "Type": "file"
            },
            "SignExpectedPcrKey": "/my/key",
            "SignExpectedPcrKeySource": {
                "Source": "",
                "Type": "file"
            },
            "SkeletonTrees": [
                {
                    "Source": "/foo/bar",
                    "Target": "/"
                },
                {
                    "Source": "/bar/baz",
                    "Target": "/qux"
                }
            ],
            "SourceDateEpoch": 12345,
            "Splash": "/splash",
            "SplitArtifacts": [
                "uki",
                "kernel"
            ],
            "Ssh": "auto",
            "SshCertificate": "/path/to/cert",
            "SshKey": null,
            "StorageTargetMode": "enabled",
            "SyncScripts": [
                "/sync"
            ],
            "SysupdateDirectory": "/sysupdate",
            "TPM": "auto",
            "Timezone": null,
            "ToolsTree": null,
            "ToolsTreeCertificates": true,
            "UnifiedKernelImageFormat": "myuki",
            "UnifiedKernelImageProfiles": [
                {
                    "Cmdline": [
                        "key=value"
                    ],
                    "Profile": {
                        "key": "value"
                    },
                    "SignExpectedPcr": true
                }
            ],
            "UnifiedKernelImages": "auto",
            "UnitProperties": [
                "PROPERTY=VALUE"
            ],
            "UseSubvolumes": "auto",
            "VSock": "enabled",
            "VSockCID": -2,
            "Verity": "signed",
            "VerityCertificate": "/path/to/cert",
            "VerityCertificateSource": {
                "Source": "",
                "Type": "file"
            },
            "VerityKey": null,
            "VerityKeySource": {
                "Source": "",
                "Type": "file"
            },
            "VirtualMachineMonitor": "qemu",
            "VolatilePackageDirectories": [
                "def"
            ],
            "VolatilePackages": [
                "abc"
            ],
            "WithDocs": true,
            "WithNetwork": false,
            "WithRecommends": true,
            "WithTests": true,
            "WorkspaceDirectory": "/cwd"
        }
        """
    )

    args = Config(
        architecture=Architecture.ia64,
        autologin=False,
        base_trees=[Path("/hello/world")],
        bios_bootloader=BiosBootloader.none,
        bootable=ConfigFeature.disabled,
        bootloader=Bootloader.grub,
        build_dir=Path("abc"),
        build_key="abc",
        build_packages=["pkg1", "pkg2"],
        build_scripts=[Path("/path/to/buildscript")],
        build_sources_ephemeral=BuildSourcesEphemeral.yes,
        build_sources=[ConfigTree(Path("/qux"), Path("/frob"))],
        cache_dir=Path("/is/this/the/cachedir"),
        cache_key="qed",
        cacheonly=Cacheonly.always,
        cdrom=False,
        checksum=False,
        clean_package_metadata=ConfigFeature.auto,
        clean_scripts=[Path("/clean")],
        compress_level=3,
        compress_output=Compression.bz2,
        configure_scripts=[Path("/configure")],
        console=ConsoleMode.gui,
        cpus=2,
        credentials={"credkey": "credval"},
        dependencies=["dep1"],
        distribution=Distribution.fedora,
        drives=[
            Drive("abc", 200, Path("/foo/bar"), "abc,qed", "red", []),
            Drive("abc", 200, None, "", "wcd", []),
            Drive("abc", 200, None, "", "bla", [DriveFlag.persist]),
        ],
        environment_files=[],
        environment={"foo": "foo", "BAR": "BAR", "Qux": "Qux"},
        ephemeral=True,
        extra_search_paths=[],
        extra_trees=[],
        files=[],
        finalize_scripts=[],
        firmware_exclude=["brcm/"],
        firmware_include=["ath3k-1"],
        firmware_variables=Path("/foo/bar"),
        firmware=Firmware.linux,
        forward_journal=Path("/mkosi.journal"),
        history=True,
        hostname=None,
        image_id="myimage",
        image_version="5",
        image="main",
        incremental=Incremental.no,
        initrd_packages=["clevis"],
        initrd_profiles=[str(InitrdProfile.lvm)],
        initrd_volatile_packages=["abc"],
        initrds=[Path("/efi/initrd1"), Path("/efi/initrd2")],
        kernel_command_line_extra=["look", "im", "on", "the", "kernel", "command", "line"],
        kernel_command_line=[],
        kernel_modules_exclude=["nvidia"],
        kernel_modules_include_host=True,
        kernel_modules_include=["loop"],
        kernel_modules_initrd_exclude=[],
        kernel_modules_initrd_include_host=True,
        kernel_modules_initrd_include=[],
        kernel_modules_initrd=True,
        key=None,
        keymap="wow, so much keymap",
        kvm=ConfigFeature.auto,
        linux=None,
        local_mirror=None,
        locale_messages="",
        locale="en_C.UTF-8",
        machine_id=uuid.UUID("b58253b0cc924a348782bcd99b20d07f"),
        machine="machine",
        make_initrd=False,
        manifest_format=[ManifestFormat.json, ManifestFormat.changelog],
        microcode_host=True,
        devicetree=Path("freescale/imx8mm-verdin-nonwifi-dev.dtb"),
        minimum_version="123",
        mirror=None,
        nspawn_settings=None,
        openpgp_tool="gpg",
        output_dir=Path("/your/output/here"),
        output_extension="raw",
        output_format=OutputFormat.uki,
        output_mode=0o123,
        output="outfile",
        overlay=True,
        package_cache_dir=Path("/a/b/c"),
        package_directories=[],
        packages=[],
        pass_environment=["abc"],
        passphrase=None,
        postinst_scripts=[Path("/bar/qux")],
        postoutput_scripts=[Path("/foo/src")],
        prepare_scripts=[Path("/run/foo")],
        profiles=["profile"],
        proxy_client_certificate=Path("/my/client/cert"),
        proxy_client_key=Path("/my/client/key"),
        proxy_exclude=["www.example.com"],
        proxy_peer_certificate=Path("/my/peer/cert"),
        proxy_url="https://my/proxy",
        qemu_args=[],
        ram=123,
        register=ConfigFeature.enabled,
        release="53",
        removable=False,
        remove_files=[],
        skip_packages=[],
        remove_packages=["all"],
        repart_dirs=[],
        repart_offline=True,
        repositories=[],
        repository_key_check=False,
        repository_key_fetch=True,
        root_password=("test1234", False),
        root_shell="/bin/tcsh",
        runtime_build_sources=True,
        runtime_home=True,
        runtime_network=Network.interface,
        runtime_scratch=ConfigFeature.enabled,
        runtime_size=8589934592,
        runtime_trees=[
            ConfigTree(Path("/foo/bar"), Path("/baz")),
            ConfigTree(Path("/bar/baz"), Path("/qux")),
        ],
        sandbox_trees=[ConfigTree(Path("/foo/bar"), None)],
        sector_size=None,
        secure_boot_auto_enroll=True,
        secure_boot_certificate_source=CertificateSource(type=CertificateSourceType.file),
        secure_boot_certificate=None,
        secure_boot_key_source=KeySource(type=KeySourceType.file),
        secure_boot_key=Path("/path/to/keyfile"),
        secure_boot_sign_tool=SecureBootSignTool.systemd_sbsign,
        secure_boot=True,
        seed=uuid.UUID("7496d7d8-7f08-4a2b-96c6-ec8c43791b60"),
        selinux_relabel=ConfigFeature.disabled,
        shim_bootloader=ShimBootloader.none,
        sign_expected_pcr_certificate_source=CertificateSource(type=CertificateSourceType.file),
        sign_expected_pcr_certificate=Path("/my/cert"),
        sign_expected_pcr_key_source=KeySource(type=KeySourceType.file),
        sign_expected_pcr_key=Path("/my/key"),
        sign_expected_pcr=ConfigFeature.disabled,
        sign=False,
        skeleton_trees=[ConfigTree(Path("/foo/bar"), Path("/")), ConfigTree(Path("/bar/baz"), Path("/qux"))],
        source_date_epoch=12345,
        splash=Path("/splash"),
        split_artifacts=[ArtifactOutput.uki, ArtifactOutput.kernel],
        ssh_certificate=Path("/path/to/cert"),
        ssh_key=None,
        ssh=Ssh.auto,
        storage_target_mode=ConfigFeature.enabled,
        sync_scripts=[Path("/sync")],
        sysupdate_dir=Path("/sysupdate"),
        timezone=None,
        tools_tree_certificates=True,
        tools_tree=None,
        tpm=ConfigFeature.auto,
        unified_kernel_image_format="myuki",
        unified_kernel_image_profiles=[
            UKIProfile(
                profile={"key": "value"},
                cmdline=["key=value"],
                sign_expected_pcr=True,
            )
        ],
        unified_kernel_images=ConfigFeature.auto,
        unit_properties=["PROPERTY=VALUE"],
        use_subvolumes=ConfigFeature.auto,
        verity_certificate_source=CertificateSource(type=CertificateSourceType.file),
        verity_certificate=Path("/path/to/cert"),
        verity_key_source=KeySource(type=KeySourceType.file),
        verity_key=None,
        verity=Verity.signed,
        vmm=Vmm.qemu,
        volatile_package_directories=[Path("def")],
        volatile_packages=["abc"],
        vsock_cid=VsockCID.hash,
        vsock=ConfigFeature.enabled,
        with_docs=True,
        with_network=False,
        with_recommends=True,
        with_tests=True,
        workspace_dir=Path("/cwd"),
    )

    assert dump_json(args.to_dict()) == dump.rstrip()
    assert Config.from_json(dump) == args
