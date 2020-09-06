# SPDX-License-Identifier: LGPL-2.1+

import configparser
import copy
import os

import pytest

import mkosi


class ChangeCwd(object):
    """Change working directory temporarily"""

    def __init__(self, path):
        self.old_dir = os.getcwd()
        self.new_dir = path

    def __enter__(self):
        os.chdir(self.new_dir)

    def __exit__(self, *args):
        os.chdir(self.old_dir)


DEFAULT_JOB_NAME = "default"


class MkosiConfig(object):
    """Base class for mkosi test and reference configuration generators"""

    def __init__(self):
        self.cli_arguments = []
        self.reference_config = {}

    def add_reference_config(self, job_name=DEFAULT_JOB_NAME):
        """create one initial reference configuration

        This default reference configuration is equal to the configuration returned by parse_args
        function without default files and without any command line arguments.
        """
        self.reference_config[job_name] = {
            "all": False,
            "all_directory": None,
            "architecture": None,
            "bmap": False,
            "boot_protocols": [],
            "bootable": False,
            "build_dir": None,
            "build_packages": [],
            "build_script": None,
            "build_env": [],
            "build_sources": None,
            "cache_path": None,
            "checksum": False,
            "cmdline": [],
            "compress": None,
            "debug": [],
            "default_path": None,
            "directory": None,
            "distribution": None,
            "encrypt": None,
            "esp_size": None,
            "extra_search_paths": [],
            "extra_trees": [],
            "finalize_script": None,
            "force_count": 0,
            "gpt_first_lba": None,
            "home_size": None,
            "hostname": None,
            "include_dir": None,
            "incremental": False,
            "install_dir": None,
            "kernel_command_line": ["rhgb", "selinux=0", "audit=0"],
            "key": None,
            "mirror": None,
            "mksquashfs_tool": [],
            "no_chown": False,
            "nspawn_settings": None,
            "output": None,
            "output_dir": None,
            "output_format": None,
            "packages": [],
            "password": None,
            "password_is_hashed": False,
            "autologin": False,
            "skip_final_phase": False,
            "tar_strip_selinux_context": False,
            "prepare_script": None,
            "postinst_script": None,
            "qcow2": False,
            "read_only": False,
            "release": None,
            "repositories": [],
            "root_size": None,
            "secure_boot": False,
            "secure_boot_certificate": None,
            "secure_boot_key": None,
            "secure_boot_common_name": "mkosi of %u",
            "secure_boot_valid_days": "730",
            "sign": False,
            "skeleton_trees": [],
            "source_file_transfer": None,
            "source_file_transfer_final": None,
            "srv_size": None,
            "swap_size": None,
            "tmp_size": None,
            "var_size": None,
            "verb": "build",
            "verity": False,
            "with_docs": False,
            "with_network": False,
            "with_tests": True,
            "xbootldr_size": None,
            "xz": False,
            "qemu_headless": False,
            "network_veth": False,
            "ephemeral": False,
            "with_unified_kernel_images": True,
            "hostonly_initrd": False,
            "ssh": False,
            "minimize": False,
        }

    def __eq__(self, other: [mkosi.CommandLineArguments]) -> bool:
        """Compare the configuration returned by parse_args against self.reference_config"""
        if len(self.reference_config) != len(other):
            return False

        is_eq = True
        for other_job, other_args in other.items():
            try:
                this_args = self.reference_config[other_job]
            except KeyError:
                return False
            other_args_v = vars(other_args)
            if this_args != other_args_v:
                is_eq = False
        return is_eq

    def _append_list(self, ref_entry, new_args, job_name=DEFAULT_JOB_NAME, separator=","):
        """Helper function handling comma separated list as supported by mkosi"""
        args_list = []
        if isinstance(new_args, str):
            args_list = new_args.split(separator)
        else:
            for arg in new_args:
                args_list.extend(arg.split(separator))
        for arg in args_list:
            if isinstance(arg, str) and arg.startswith("!"):
                if arg[1:] in self.reference_config[job_name][ref_entry]:
                    self.reference_config[job_name][ref_entry].remove(arg[1:])
            else:
                self.reference_config[job_name][ref_entry].append(arg)

    @staticmethod
    def write_ini(dname: str, fname: str, config: dict, prio=1000) -> None:
        """Write mkosi.default(.d/*) files"""
        if not os.path.exists(dname):
            os.makedirs(dname)
        if prio < 1000:
            fname = "{:03d}_{}".format(prio, fname)
        config_parser = configparser.RawConfigParser()
        config_parser.optionxform = str

        # Replace lists in dict before calling config_parser write file
        config_all_normalized = copy.deepcopy(config)
        for section, key_val in config_all_normalized.items():
            for key, val in key_val.items():
                if isinstance(val, list):
                    config_all_normalized[section][key] = os.linesep.join(val)

        config_parser.read_dict(config_all_normalized)
        with open(os.path.join(dname, fname), "w") as f_ini:
            config_parser.write(f_ini)

    def _update_ref_from_file(self, mk_config: dict, job_name=DEFAULT_JOB_NAME) -> None:
        """Update reference_config from a dict as needed to write an ini file using configparser

        This is basically a conversion from snake case to - separated format.
        """
        if "Distribution" in mk_config:
            mk_config_distro = mk_config["Distribution"]
            if "Distribution" in mk_config_distro:
                self.reference_config[job_name]["distribution"] = mk_config_distro["Distribution"]
            if "Release" in mk_config_distro:
                self.reference_config[job_name]["release"] = mk_config_distro["Release"]
            if "Repositories" in mk_config_distro:
                self._append_list("repositories", mk_config_distro["Repositories"], job_name)
            if "Mirror" in mk_config_distro:
                self.reference_config[job_name]["mirror"] = mk_config_distro["Mirror"]
            if "Architecture" in mk_config_distro:
                self.reference_config[job_name]["architecture"] = mk_config_distro["Architecture"]
        if "Output" in mk_config:
            mk_config_output = mk_config["Output"]
            if "Format" in mk_config_output:
                self.reference_config[job_name]["output_format"] = mkosi.OutputFormat.from_string(
                    mk_config_output["Format"]
                )
            if "Output" in mk_config_output:
                self.reference_config[job_name]["output"] = mk_config_output["Output"]
            if "Force" in mk_config_output:
                self.reference_config[job_name]["force_count"] += 1
            if "Bootable" in mk_config_output:
                self.reference_config[job_name]["bootable"] = mk_config_output["Bootable"]
            if "BootProtocols" in mk_config_output:
                self._append_list("boot_protocols", mk_config_output["BootProtocols"], job_name)
            if "KernelCommandLine" in mk_config_output:
                self._append_list("kernel_command_line", mk_config_output["KernelCommandLine"], job_name, " ")
            if "SecureBoot" in mk_config_output:
                self.reference_config[job_name]["secure_boot"] = mk_config_output["SecureBoot"]
            if "SecureBootKey" in mk_config_output:
                self.reference_config[job_name]["secure_boot_key"] = mk_config_output["SecureBootKey"]
            if "SecureBootCertificate" in mk_config_output:
                self.reference_config[job_name]["secure_boot_certificate"] = mk_config_output["SecureBootCertificate"]
            if "SecureBootCommonName" in mk_config_output:
                self.reference_config[job_name]["secure_boot_common_name"] = mk_config_output["SecureBootCommonName"]
            if "SecureBootValidDays" in mk_config_output:
                self.reference_config[job_name]["secure_boot_valid_days"] = mk_config_output["SecureBootValidDays"]
            if "ReadOnly" in mk_config_output:
                self.reference_config[job_name]["read_only"] = mk_config_output["ReadOnly"]
            if "Encrypt" in mk_config_output:
                self.reference_config[job_name]["encrypt"] = mk_config_output["Encrypt"]
            if "Verity" in mk_config_output:
                self.reference_config[job_name]["verity"] = mk_config_output["Verity"]
            if "Compress" in mk_config_output:
                self.reference_config[job_name]["compress"] = mk_config_output["Compress"]
            if "Mksquashfs" in mk_config_output:
                self.reference_config[job_name]["mksquashfs_tool"] = mk_config_output["Mksquashfs"].split()
            if "XZ" in mk_config_output:
                self.reference_config[job_name]["xz"] = mk_config_output["XZ"]
            if "QCow2" in mk_config_output:
                self.reference_config[job_name]["qcow2"] = mk_config_output["QCow2"]
            if "TarStripSELinuxContext" in mk_config_output:
                self.reference_config[job_name]["tar_strip_selinux_context"] = mk_config_output[
                    "TarStripSELinuxContext"
                ]
            if "Hostname" in mk_config_output:
                self.reference_config[job_name]["hostname"] = mk_config_output["Hostname"]
            if "WithUnifiedKernelImages" in mk_config_output:
                self.reference_config[job_name]["with_unified_kernel_images"] = mk_config_output[
                    "WithUnifiedKernelImages"
                ]
            if "HostonlyInitrd" in mk_config_output:
                self.reference_config[job_name]["hostonly_initrd"] = mk_config_output["HostonlyInitrd"]
        if "Packages" in mk_config:
            mk_config_packages = mk_config["Packages"]
            if "Packages" in mk_config_packages:
                self._append_list("packages", mk_config_packages["Packages"], job_name)
            if "WithDocs" in mk_config_packages:
                self.reference_config[job_name]["with_docs"] = mk_config_packages["WithDocs"]
            if "WithTests" in mk_config_packages:
                self.reference_config[job_name]["with_tests"] = mk_config_packages["WithTests"]
            if "Cache" in mk_config_packages:
                self.reference_config[job_name]["cache_path"] = mk_config_packages["Cache"]
            if "ExtraTrees" in mk_config_packages:
                self._append_list("extra_trees", mk_config_packages["ExtraTrees"], job_name)
            if "SkeletonTrees" in mk_config_packages:
                self._append_list("skeleton_trees", mk_config_packages["SkeletonTrees"], job_name)
            if "BuildScript" in mk_config_packages:
                self.reference_config[job_name]["build_script"] = mk_config_packages["BuildScript"]
            if "BuildEnvironment" in mk_config_packages:
                self.reference_config["build_env"] = mk_config_packages["BuildEnvironment"]
            if "BuildSources" in mk_config_packages:
                self.reference_config[job_name]["build_sources"] = mk_config_packages["BuildSources"]
            if "SourceFileTransfer" in mk_config_packages:
                self.reference_config[job_name]["source_file_transfer"] = mk_config_packages["SourceFileTransfer"]
            if "SourceFileTransferFinal" in mk_config_packages:
                self.reference_config[job_name]["source_file_transfer_final"] = mk_config_packages[
                    "SourceFileTransferFinal"
                ]
            if "BuildDirectory" in mk_config_packages:
                self.reference_config[job_name]["build_dir"] = mk_config_packages["BuildDirectory"]
            if "IncludeDirectory" in mk_config_packages:
                self.reference_config[job_name]["include_dir"] = mk_config_packages["IncludeDirectory"]
            if "InstallDirectory" in mk_config_packages:
                self.reference_config[job_name]["install_dir"] = mk_config_packages["InstallDirectory"]
            if "BuildPackages" in mk_config_packages:
                self._append_list("build_packages", mk_config_packages["BuildPackages"], job_name)
            if "PostInstallationScript" in mk_config_packages:
                self.reference_config[job_name]["postinst_script"] = mk_config_packages["PostInstallationScript"]
            if "FinalizeScript" in mk_config_packages:
                self.reference_config[job_name]["finalize_script"] = mk_config_packages["FinalizeScript"]
            if "WithNetwork" in mk_config_packages:
                self.reference_config[job_name]["with_network"] = mk_config_packages["WithNetwork"]
            if "NSpawnSettings" in mk_config_packages:
                self.reference_config[job_name]["nspawn_settings"] = mk_config_packages["NSpawnSettings"]
        if "Partitions" in mk_config:
            mk_config_partitions = mk_config["Partitions"]
            if "RootSize" in mk_config_partitions:
                self.reference_config[job_name]["root_size"] = mk_config_partitions["RootSize"]
            if "ESPSize" in mk_config_partitions:
                self.reference_config[job_name]["esp_size"] = mk_config_partitions["ESPSize"]
            if "SwapSize" in mk_config_partitions:
                self.reference_config[job_name]["swap_size"] = mk_config_partitions["SwapSize"]
            if "HomeSize" in mk_config_partitions:
                self.reference_config[job_name]["home_size"] = mk_config_partitions["HomeSize"]
            if "SrvSize" in mk_config_partitions:
                self.reference_config[job_name]["srv_size"] = mk_config_partitions["SrvSize"]
        if "Validation" in mk_config:
            mk_config_validation = mk_config["Validation"]
            if "CheckSum" in mk_config_validation:
                self.reference_config[job_name]["checksum"] = mk_config_validation["CheckSum"]
            if "Sign" in mk_config_validation:
                self.reference_config[job_name]["sign"] = mk_config_validation["Sign"]
            if "Key" in mk_config_validation:
                self.reference_config[job_name]["key"] = mk_config_validation["Key"]
            if "BMap" in mk_config_validation:
                self.reference_config[job_name]["bmap"] = mk_config_validation["BMap"]
            if "Password" in mk_config_validation:
                self.reference_config[job_name]["password"] = mk_config_validation["Password"]
            if "PasswordIsHashed" in mk_config_validation:
                self.reference_config[job_name]["password_is_hashed"] = mk_config_validation["PasswordIsHashed"]
            if "Autologin" in mk_config_validation:
                self.reference_config[job_name]["autologin"] = mk_config_validation["Autologin"]

        if "Host" in mk_config:
            mk_config_host = mk_config["Host"]
            if "ExtraSearchPaths" in mk_config_host:
                self._append_list("extra_search_paths", mk_config_host["ExtraSearchPaths"], job_name, ":")
            if "QemuHeadless" in mk_config_host:
                self.reference_config[job_name]["qemu_headless"] = mk_config_host["QemuHeadless"]
            if "NetworkVeth" in mk_config_host:
                self.reference_config[job_name]["network_veth"] = mk_config_host["NetworkVeth"]
            if "Ephemeral" in mk_config_host:
                self.reference_config[job_name]["ephemeral"] = mk_config_host["Ephemeral"]
            if "Ssh" in mk_config_host:
                self.reference_config[job_name]["ssh"] = mk_config_host["Ssh"]


class MkosiConfigOne(MkosiConfig):
    """Classes derived from this class are magically instantiated by pytest

    Each test_ function with a parameter named "tested_config" gets
    called by pytest for each class derived from this class. These test cases
    verify the parse_args function in single image (not --all) mode.
    This class implements four functions:
    - prepare_mkosi_default
    - prepare_mkosi_default_d_1
    - prepare_mkosi_default_d_2
    - prepare_args or prepare_args_short

    The purpose of these function is to generate configuration files and sets of command line
    arguments processed by the parse_args function of mkosi. Additionally each of these four functions
    alters the reference_config to be consistent with the expected values returned by the parse_args
    function under test.

    This allows to write test cases with four steps. The first step generates a reference configuration
    consisting of mkosi.default file only. Therefore prepare_mkosi_default function is is called to
    generate the test configuration. Finally parse_args is called and the configuration returned by
    parse_args is compared against the reference_config. The second test step generates a test
    configuration by calling prepare_mkosi_default and prepare_mkosi_default_d_1. This verifies the
    behavior of parse_args is fine for mkosi.default plus one override file. The third test case verifies
    that mkosi.default with two files in mkosi.default.d folder works as expected. The fourth test case
    additionally overrides some default values with command line arguments.

    Classes derived from this base class should override the mentioned functions to implement specific
    test cases.
    """

    def __init__(self):
        """Add the default mkosi.default config"""
        super().__init__()
        self.add_reference_config()

    def _prepare_mkosi_default(self, directory: str, config: dict) -> None:
        __class__.write_ini(directory, "mkosi.default", config)

    def _prepare_mkosi_default_d(self, directory: str, config: dict, prio=1000, fname="mkosi.conf") -> None:
        __class__.write_ini(os.path.join(directory, "mkosi.default.d"), fname, config, prio)

    def prepare_mkosi_default(self, directory: str) -> None:
        """Generate a mkosi.default defaults file in the working directory"""
        pass

    def prepare_mkosi_default_d_1(self, directory: str) -> None:
        """Generate a prio 1 config file in mkosi.default.d

        The file name should be prefixed with 001_.
        """
        pass

    def prepare_mkosi_default_d_2(self, directory: str) -> None:
        """Generate a prio 2 config file in mkosi.default.d

        The file name should be prefixed with 002_.
        """
        pass

    def prepare_args(self) -> None:
        """Add some command line arguments to this test run"""
        pass

    def prepare_args_short(self) -> None:
        """Add some command line arguments to this test run, in short form"""
        pass


class MkosiConfigSummary(MkosiConfigOne):
    """Test configuration for mkosi summary

    This test checks if the default parameter set of these tests is in sync
    with the default parameters implemented in mkosi. No config files or command
    line arguments are in place.
    """

    def __init__(self):
        super().__init__()
        for ref_c in self.reference_config.values():
            ref_c["verb"] = "summary"
        self.cli_arguments = ["summary"]


class MkosiConfigDistro(MkosiConfigOne):
    """Minimal test configuration for the distribution parameter

    This tests defines the distribution parameter on several configuration priorities:
    - mkosi.default
    - mkosi.default.d/001_mkosi.conf
    - mkosi.default.d/002_mkosi.conf
    - --distribution
    """

    def __init__(self, subdir_name=None, alldir_name=None):
        super().__init__()
        self.subdir_name = subdir_name
        if subdir_name:
            for ref_c in self.reference_config.values():
                ref_c["directory"] = self.subdir_name
            self.cli_arguments = ["--directory", self.subdir_name, "summary"]

    def prepare_mkosi_default(self, directory: str) -> None:
        mk_config = {"Distribution": {"Distribution": "fedora"}}
        self._prepare_mkosi_default(directory, mk_config)
        for ref_c in self.reference_config.values():
            ref_c["distribution"] = "fedora"
            if self.subdir_name:
                ref_c["directory"] = self.subdir_name
        if self.subdir_name:
            self.cli_arguments = ["--directory", self.subdir_name, "summary"]

    def prepare_mkosi_default_d_1(self, directory: str) -> None:
        mk_config = {"Distribution": {"Distribution": "ubuntu"}}
        self._prepare_mkosi_default_d(directory, mk_config, 1)
        for ref_c in self.reference_config.values():
            ref_c["distribution"] = "ubuntu"

    def prepare_mkosi_default_d_2(self, directory: str) -> None:
        mk_config = {"Distribution": {"Distribution": "debian"}}
        self._prepare_mkosi_default_d(directory, mk_config, 2)
        for ref_c in self.reference_config.values():
            ref_c["distribution"] = "debian"

    def prepare_args(self) -> None:
        if not self.cli_arguments:
            self.cli_arguments = ["build"]
        self.cli_arguments[0:0] = ["--distribution", "arch"]
        for ref_c in self.reference_config.values():
            ref_c["distribution"] = "arch"

    def prepare_args_short(self) -> None:
        if not self.cli_arguments:
            self.cli_arguments = ["build"]
        self.cli_arguments[0:0] = ["-d", "arch"]
        for ref_c in self.reference_config.values():
            ref_c["distribution"] = "arch"


class MkosiConfigDistroDir(MkosiConfigDistro):
    """Same as Distro, but gets --directory passed and sets verb to summary"""

    def __init__(self):
        super().__init__("a_sub_dir")
        for ref_c in self.reference_config.values():
            ref_c["verb"] = "summary"


class MkosiConfigManyParams(MkosiConfigOne):
    """Test configuration for most parameters"""

    def prepare_mkosi_default(self, directory: str) -> None:
        mk_config = {
            "Distribution": {
                "Distribution": "fedora",
                "Release": "28",
                "Repositories": "http://fedora/repos",
                "Mirror": "http://fedora/mirror",
                "Architecture": "i386",
            },
            "Output": {
                "Format": "gpt_ext4",
                "Output": "test_image.raw",
                #                 # 'OutputDirectory': '',
                "Bootable": False,
                "BootProtocols": "uefi",
                "KernelCommandLine": ["console=ttyS0"],
                "SecureBoot": False,
                "SecureBootKey": "/foo.pem",
                "SecureBootCertificate": "bar.crt",
                "SecureBootCommonName": "mkosi for %u",
                "SecureBootValidDays": "730",
                "ReadOnly": False,
                "Encrypt": "all",
                "Verity": False,
                "Compress": "lz4",
                "Mksquashfs": "my/fo/sq-tool",
                "XZ": False,
                "QCow2": False,
                "Hostname": "myhost1",
            },
            "Packages": {
                "Packages": ["pkg-foo", "pkg-bar", "pkg-foo1,pkg-bar1"],
                "WithDocs": False,
                "WithTests": True,
                "Cache": "the/cache/dir",
                "ExtraTrees": "another/tree",
                "SkeletonTrees": "a/skeleton",
                "BuildScript": "fancy_build.sh",
                "BuildSources": "src",
                "SourceFileTransfer": mkosi.SourceFileTransfer.copy_all,
                "BuildDirectory": "here/we/build",
                "BuildPackages": ["build-me", "build-me2"],
                "PostInstallationScript": "post-script.sh",
                "FinalizeScript": "final.sh",
                "WithNetwork": False,
                "NSpawnSettings": "foo.nspawn",
            },
            "Partitions": {"RootSize": "2G", "ESPSize": "128M", "SwapSize": "1024M", "HomeSize": "3G"},
            "Validation": {
                "CheckSum": True,
                "Sign": False,
                "Key": "mykey.gpg",
                "BMap": False,
                "Password": "secret1234",
                "Autologin": True,
            },
            "Host": {
                "ExtraSearchPaths": "search/here:search/there",
                "QemuHeadless": True,
                "NetworkVeth": True,
            },
        }
        self._prepare_mkosi_default(directory, mk_config)
        for j in self.reference_config:
            self._update_ref_from_file(mk_config, j)

    def prepare_mkosi_default_d_1(self, directory: str) -> None:
        mk_config = {
            "Distribution": {
                "Distribution": "ubuntu",
                "Release": "18.04",
                "Repositories": "http://ubuntu/repos",
                "Mirror": "http://ubuntu/mirror",
                "Architecture": "x86_64",
            },
            "Output": {
                "Format": "gpt_btrfs",
                "Output": "test_image.raw.xz",
                #                 # 'OutputDirectory': '',
                "Bootable": True,
                "BootProtocols": "bios",
                "KernelCommandLine": ["console=ttyS1"],
                "SecureBoot": True,
                "SecureBootKey": "/foo-ubu.pem",
                "SecureBootCertificate": "bar-bub.crt",
                "ReadOnly": True,
                "Encrypt": "data",
                "Verity": True,
                "Compress": "zstd",
                "Mksquashfs": "my/fo/sq-tool-ubu",
                "XZ": True,
                "QCow2": True,
                "Hostname": "myubuhost1",
            },
            "Packages": {
                "Packages": ["add-ubu-1", "add-ubu-2"],
                "WithDocs": True,
                "WithTests": False,
                "Cache": "the/cache/dir/ubu",
                "ExtraTrees": "another/tree/ubu",
                "SkeletonTrees": "a/skeleton/ubu",
                "BuildScript": "ubu_build.sh",
                "BuildSources": "src/ubu",
                "SourceFileTransfer": mkosi.SourceFileTransfer.copy_git_cached,
                "BuildDirectory": "here/we/build/ubu",
                "BuildPackages": ["build-me", "build-me2-ubu"],
                "PostInstallationScript": "post-ubu-script.sh",
                "FinalizeScript": "final-ubu.sh",
                "WithNetwork": True,
                "NSpawnSettings": "foo-ubu.nspawn",
            },
            "Partitions": {"RootSize": "4G", "ESPSize": "148M", "SwapSize": "1536M", "HomeSize": "5G"},
            "Validation": {
                "CheckSum": False,
                "Sign": True,
                "Key": "mykey-ubu.gpg",
                "BMap": True,
                "Password": "secret12345",
                "Autologin": True,
            },
            "Host": {
                "ExtraSearchPaths": "search/ubu",
                "QemuHeadless": True,
                "NetworkVeth": True,
            },
        }
        self._prepare_mkosi_default_d(directory, mk_config, 1)
        for j in self.reference_config:
            self._update_ref_from_file(mk_config, j)

    def prepare_mkosi_default_d_2(self, directory: str) -> None:
        mk_config = {
            "Distribution": {
                "Distribution": "debian",
                "Release": "unstable",
                "Repositories": "http://debian/repos",
                "Mirror": "http://ubuntu/mirror",
                "Architecture": "x86_64",
            },
            "Output": {
                "Format": "gpt_btrfs",
                "Output": "test_image.raw.xz",
                #                 # 'OutputDirectory': '',
                "Bootable": True,
                "BootProtocols": "bios",
                "KernelCommandLine": ["console=ttyS1"],
                "SecureBoot": True,
                "SecureBootKey": "/foo-debi.pem",
                "SecureBootCertificate": "bar-bub.crt",
                "ReadOnly": True,
                "Encrypt": "data",
                "Verity": True,
                "Compress": "zstd",
                "Mksquashfs": "my/fo/sq-tool-debi",
                "XZ": True,
                "QCow2": True,
                "Hostname": "mydebihost1",
            },
            "Packages": {
                "Packages": ["!add-ubu-1", "!add-ubu-2", "add-debi-1", "add-debi-2"],
                "WithDocs": True,
                "WithTests": False,
                "Cache": "the/cache/dir/debi",
                "ExtraTrees": "another/tree/debi",
                "SkeletonTrees": "a/skeleton/debi",
                "BuildScript": "debi_build.sh",
                "BuildSources": "src/debi",
                "SourceFileTransfer": mkosi.SourceFileTransfer.copy_git_cached,
                "BuildDirectory": "here/we/build/debi",
                "BuildPackages": ["build-me", "build-me2-debi"],
                "PostInstallationScript": "post-debi-script.sh",
                "FinalizeScript": "final-debi.sh",
                "WithNetwork": True,
                "NSpawnSettings": "foo-debi.nspawn",
            },
            "Partitions": {"RootSize": "4G", "ESPSize": "148M", "SwapSize": "1536M", "HomeSize": "5G"},
            "Validation": {
                "CheckSum": False,
                "Sign": True,
                "Key": "mykey-debi.gpg",
                "BMap": True,
                "Password": "secret12345",
                "Autologin": True,
            },
            "Host": {
                "ExtraSearchPaths": "search/debi",
                "QemuHeadless": True,
                "NetworkVeth": True,
            },
        }
        self._prepare_mkosi_default_d(directory, mk_config, 2)
        for j in self.reference_config:
            self._update_ref_from_file(mk_config, j)

    def prepare_args(self) -> None:
        if not self.cli_arguments:
            self.cli_arguments = ["build"]
        self.cli_arguments[0:0] = ["--distribution", "arch"]
        self.cli_arguments[0:0] = ["--release", "7"]
        self.cli_arguments[0:0] = ["--repositories", "centos/repos"]
        self.cli_arguments[0:0] = ["--force"]
        self.cli_arguments[0:0] = ["--read-only", "no"]
        self.cli_arguments[0:0] = ["--incremental"]

        for j, ref_c in self.reference_config.items():
            ref_c["distribution"] = "arch"
            ref_c["release"] = "7"
            self._append_list("repositories", "centos/repos", j)
            ref_c["force_count"] += 1
            ref_c["read_only"] = False
            ref_c["incremental"] = True

    def prepare_args_short(self) -> None:
        if not self.cli_arguments:
            self.cli_arguments = ["build"]
        self.cli_arguments[0:0] = ["-d", "centos"]
        for ref_c in self.reference_config.values():
            ref_c["distribution"] = "centos"


class MkosiConfigIniLists1(MkosiConfigOne):
    """Manually written ini files with advanced list syntax."""

    def prepare_mkosi_default(self, directory: str) -> None:
        ini_lines = [
            "[Distribution]",
            "Distribution=fedora",
            "",
            "[Packages]",
            "Packages=openssh-clients",
            "  httpd",
            "  tar",
        ]
        with open(os.path.join(directory, "mkosi.default"), "w") as f_ini:
            f_ini.write(os.linesep.join(ini_lines))
        self.reference_config[DEFAULT_JOB_NAME]["distribution"] = "fedora"
        self.reference_config[DEFAULT_JOB_NAME]["packages"] = ["openssh-clients", "httpd", "tar"]

    def prepare_mkosi_default_d_1(self, directory: str) -> None:
        ini_lines = [
            "[Distribution]",
            "Distribution=ubuntu",
            "",
            "[Packages]",
            "Packages=   ",
            "          !httpd",
            "           apache2",
            "",
            "[Output]",
            "KernelCommandLine=console=ttyS0",
        ]
        dname = os.path.join(directory, "mkosi.default.d")
        if not os.path.exists(dname):
            os.makedirs(dname)
        with open(os.path.join(dname, "1_ubuntu.conf"), "w") as f_ini:
            f_ini.write(os.linesep.join(ini_lines))
        self.reference_config[DEFAULT_JOB_NAME]["distribution"] = "ubuntu"
        if "httpd" in self.reference_config[DEFAULT_JOB_NAME]["packages"]:
            self.reference_config[DEFAULT_JOB_NAME]["packages"].remove("httpd")
        self.reference_config[DEFAULT_JOB_NAME]["packages"].append("apache2")
        self.reference_config[DEFAULT_JOB_NAME]["kernel_command_line"].extend(["console=ttyS0"])

    def prepare_mkosi_default_d_2(self, directory: str) -> None:
        ini_lines = [
            "[Packages]",
            "Packages=[ vim,!vi",
            "  ca-certificates, bzip ]" "",
            "[Output]",
            "KernelCommandLine=console=ttyS1",
            "  driver.feature=1",
        ]
        dname = os.path.join(directory, "mkosi.default.d")
        if not os.path.exists(dname):
            os.makedirs(dname)
        with open(os.path.join(dname, "2_additional_stuff.conf"), "w") as f_ini:
            f_ini.write(os.linesep.join(ini_lines))
        if "vi" in self.reference_config[DEFAULT_JOB_NAME]["packages"]:
            self.reference_config[DEFAULT_JOB_NAME]["packages"].remove("vi")
        self.reference_config[DEFAULT_JOB_NAME]["packages"].extend(["vim", "ca-certificates", "bzip"])
        self.reference_config[DEFAULT_JOB_NAME]["kernel_command_line"].extend(["console=ttyS1", "driver.feature=1"])


class MkosiConfigIniLists2(MkosiConfigIniLists1):
    """Same as MkosiConfigIniLists2 but with clean KernelCommandLine"""

    def prepare_mkosi_default(self, directory: str) -> None:
        ini_lines = ["[Output]", "KernelCommandLine=!*"]
        with open(os.path.join(directory, "mkosi.default"), "w") as f_ini:
            f_ini.write(os.linesep.join(ini_lines))
        self.reference_config[DEFAULT_JOB_NAME]["kernel_command_line"] = []


# pytest magic: run each test function with each class derived from MkosiConfigOne
@pytest.fixture(params=MkosiConfigOne.__subclasses__())
def tested_config(request):
    return request.param()


def test_verb_none(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        args = mkosi.parse_args([])
        assert args["default"].verb == "build"


def test_verb_build(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        args = mkosi.parse_args(["build"])
        assert args["default"].verb == "build"


def test_verb_boot_no_cli_args1(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        cmdline_ref = ["boot", "--par-for-sub", "--pom", "--for_sub", "1234"]
        args = mkosi.parse_args(cmdline_ref)
        assert args["default"].verb == "boot"
        assert args["default"].cmdline == cmdline_ref[1:]


def test_verb_boot_no_cli_args2(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        cmdline_ref = ["-pa-package", "boot", "--par-for-sub", "--popenssl", "--for_sub", "1234"]
        args = mkosi.parse_args(cmdline_ref)
        assert args["default"].verb == "boot"
        assert "a-package" in args["default"].packages
        assert args["default"].cmdline == cmdline_ref[2:]


def test_verb_boot_no_cli_args3(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        cmdline_ref = ["-pa-package", "-p", "another-package", "build"]
        args = mkosi.parse_args(cmdline_ref)
        assert args["default"].verb == "build"
        assert args["default"].packages == ["a-package", "another-package"]


def test_verb_summary_no_cli_args4(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        cmdline_ref = ["-pa-package", "-p", "another-package", "summary"]
        args = mkosi.parse_args(cmdline_ref)
        assert args["default"].verb == "summary"
        assert args["default"].packages == ["a-package", "another-package"]


def test_verb_shell_cli_args5(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        cmdline_ref = ["-pa-package", "-p", "another-package", "shell", "python3 -foo -bar;", "ls --inode"]
        args = mkosi.parse_args(cmdline_ref)
        assert args["default"].verb == "shell"
        assert args["default"].packages == ["a-package", "another-package"]
        assert args["default"].cmdline == cmdline_ref[4:]


def test_verb_shell_cli_args6(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        cmdline_ref = ["-i", "yes", "summary"]
        args = mkosi.parse_args(cmdline_ref)
        assert args["default"].verb == "summary"
        assert args["default"].incremental == True


def test_verb_shell_cli_args7(tmpdir):
    with ChangeCwd(tmpdir.strpath):
        cmdline_ref = ["-i", "summary"]
        args = mkosi.parse_args(cmdline_ref)
        assert args["default"].verb == "summary"
        assert args["default"].incremental == True


def test_builtin(tested_config, tmpdir):
    """Test if builtin config and reference config match"""
    with ChangeCwd(tmpdir.strpath):
        if "--all" in tested_config.cli_arguments:
            with pytest.raises(mkosi.MkosiParseException):
                args = mkosi.parse_args(tested_config.cli_arguments)
        else:
            args = mkosi.parse_args(tested_config.cli_arguments)
            assert tested_config == args


def test_def(tested_config, tmpdir):
    """Generate the mkosi.default file only"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_mkosi_default(tmpdir.strpath)
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


def test_def_1(tested_config, tmpdir):
    """Generate the mkosi.default file plus one config file"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_mkosi_default(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_1(tmpdir.strpath)
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


def test_def_2(tested_config, tmpdir):
    """Generate the mkosi.default file plus another config file"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_mkosi_default(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_2(tmpdir.strpath)
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


def test_def_1_2(tested_config, tmpdir):
    """Generate the mkosi.default file plus two config files"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_mkosi_default(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_1(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_2(tmpdir.strpath)
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


def test_def_args(tested_config, tmpdir):
    """Generate the mkosi.default plus command line arguments"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_args()
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


def test_def_1_args(tested_config, tmpdir):
    """Generate the mkosi.default plus a config file plus command line arguments"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_mkosi_default(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_1(tmpdir.strpath)
        tested_config.prepare_args()
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


def test_def_1_2_args(tested_config, tmpdir):
    """Generate the mkosi.default plus two config files plus command line arguments"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_mkosi_default(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_1(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_2(tmpdir.strpath)
        tested_config.prepare_args()
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


def test_def_1_2_argssh(tested_config, tmpdir):
    """Generate the mkosi.default plus two config files plus short command line arguments"""
    with ChangeCwd(tmpdir.strpath):
        tested_config.prepare_mkosi_default(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_1(tmpdir.strpath)
        tested_config.prepare_mkosi_default_d_2(tmpdir.strpath)
        tested_config.prepare_args_short()
        args = mkosi.parse_args(tested_config.cli_arguments)
        assert tested_config == args


class MkosiConfigAll(MkosiConfig):
    """Classes derived from this class are magically instantiated by pytest

    Each test_ function with a parameter named "tested_config_all" gets
    called by pytest for each class derived from this class.
    """


class MkosiConfigAllHost(MkosiConfigAll):
    """Test --all option with two simple configs"""

    def __init__(self):
        """Add two default mkosi.default configs"""
        super().__init__()
        for hostname in ["test1.example.org", "test2.example.org"]:
            job_name = "mkosi." + hostname
            self.add_reference_config(job_name)
            self.reference_config[job_name]["all"] = True
            self.reference_config[job_name]["hostname"] = hostname
        self.cli_arguments = ["--all", "build"]

    def prepare_mkosi_files(self, directory: str, all_directory=None) -> None:
        if all_directory is None:
            all_dir = os.path.abspath("mkosi.files")
        else:
            all_dir = os.path.join(directory, all_directory)

        for job_name, config in self.reference_config.items():
            mk_config = {"Output": {"Hostname": config["hostname"]}}
            __class__.write_ini(all_dir, job_name, mk_config)

        if all_directory:
            self.cli_arguments[0:0] = ["--all-directory", "all_dir"]


# pytest magic: run each test function with each class derived from MkosiConfigAll
@pytest.fixture(params=MkosiConfigAll.__subclasses__())
def tested_config_all(request):
    return request.param()


def test_all_1(tested_config_all, tmpdir):
    """Generate the mkosi.default plus two config files plus short command line arguments"""
    with ChangeCwd(tmpdir.strpath):
        tested_config_all.prepare_mkosi_files(tmpdir.strpath)
        args = mkosi.parse_args(tested_config_all.cli_arguments)
        assert tested_config_all == args
