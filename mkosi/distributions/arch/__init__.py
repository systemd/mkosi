# SPDX-License-Identifier: LGPL-2.1+

import os
import platform
import urllib
from textwrap import dedent
from typing import List, Set

from mkosi import (
    configure_dracut,
    disable_pam_securetty,
    make_executable,
    mount_api_vfs,
)
from mkosi.backend import (
    DistributionInstaller,
    MkosiPrinter,
    OutputFormat,
    install_grub,
    patch_file,
    run,
    run_workspace_command,
    workspace,
)


class Arch(DistributionInstaller):
    pam_device_prefix = "/dev"

    def __str__(self) -> str:
        return "Arch Linux"

    @property
    def mirror(self) -> str:
        if platform.machine() == "aarch64":
            return "http://mirror.archlinuxarm.org"
        return ""

    @property
    def package_cache(self) -> List[str]:
        return ["var/cache/pacman/pkg"]

    def install_distribution(self, root: str, do_run_build_script: bool) -> None:
        if self.release is not None:
            MkosiPrinter.info("Distribution release specification is not supported for Arch Linux, ignoring.")

        if self.mirror:
            if platform.machine() == "aarch64":
                server = f"Server = {self.mirror}/$arch/$repo"
            else:
                server = f"Server = {self.mirror}/$repo/os/$arch"
        else:
            # Instead of harcoding a single mirror, we retrieve a list of mirrors from Arch's mirrorlist
            # generator ordered by mirror score. This usually results in a solid mirror and also ensures that we
            # have fallback mirrors available if necessary. Finally, the mirrors will be more likely to be up to
            # date and we won't end up with a stable release that hardcodes a broken mirror.
            mirrorlist = os.path.join(workspace(root), "mirrorlist")
            with urllib.request.urlopen(
                "https://www.archlinux.org/mirrorlist/?country=all&protocol=https&ip_version=4&use_mirror_status=on"
            ) as r:
                with open(mirrorlist, "w") as f:
                    mirrors = r.readlines()
                    uncommented = [line.decode("utf-8")[1:] for line in mirrors]
                    f.writelines(uncommented)
                    server = f"Include = {mirrorlist}"

        # Create base layout for pacman and pacman-key
        os.makedirs(os.path.join(root, "var/lib/pacman"), 0o755, exist_ok=True)
        os.makedirs(os.path.join(root, "etc/pacman.d/gnupg"), 0o755, exist_ok=True)

        # Permissions on these directories are all 0o777 because of `mount --bind`
        # limitations but pacman expects them to be 0o755 so we fix them before
        # calling pacstrap (except /var/tmp which is 0o1777).
        fix_permissions_dirs = {
            "boot": 0o755,
            "etc": 0o755,
            "etc/pacman.d": 0o755,
            "var": 0o755,
            "var/lib": 0o755,
            "var/cache": 0o755,
            "var/cache/pacman": 0o755,
            "var/tmp": 0o1777,
            "run": 0o755,
        }

        for dir, permissions in fix_permissions_dirs.items():
            path = os.path.join(root, dir)
            if os.path.exists(path):
                os.chmod(path, permissions)

        pacman_conf = os.path.join(workspace(root), "pacman.conf")
        with open(pacman_conf, "w") as f:
            f.write(
                dedent(
                    f"""\
                    [options]
                    RootDir     = {root}
                    LogFile     = /dev/null
                    CacheDir    = {root}/var/cache/pacman/pkg/
                    GPGDir      = {root}/etc/pacman.d/gnupg/
                    HookDir     = {root}/etc/pacman.d/hooks/
                    HoldPkg     = pacman glibc
                    Architecture = auto
                    Color
                    CheckSpace
                    SigLevel    = Required DatabaseOptional TrustAll

                    [core]
                    {server}

                    [extra]
                    {server}

                    [community]
                    {server}
                    """
                )
            )

        if self.repositories:
            for repository in self.repositories:
                # repositories must be passed in the form <repo name>::<repo url>
                repository_name, repository_server = repository.split("::", 1)

                # note: for additional repositories, signature checking options are set to pacman's default values
                f.write(
                    dedent(
                        f"""\

                        [{repository_name}]
                        SigLevel = Optional TrustedOnly
                        Server = {repository_server}
                        """
                    )
                )

        if not do_run_build_script and self._args.bootable:
            hooks_dir = os.path.join(root, "etc/pacman.d/hooks")
            scripts_dir = os.path.join(root, "etc/pacman.d/scripts")

            os.makedirs(hooks_dir, 0o755, exist_ok=True)
            os.makedirs(scripts_dir, 0o755, exist_ok=True)

            # Disable depmod pacman hook as depmod is handled by kernel-install as well.
            os.symlink("/dev/null", os.path.join(hooks_dir, "60-depmod.hook"))

            kernel_add_hook = os.path.join(hooks_dir, "90-mkosi-kernel-add.hook")
            with open(kernel_add_hook, "w") as f:
                f.write(
                    dedent(
                        """\
                        [Trigger]
                        Operation = Install
                        Operation = Upgrade
                        Type = Path
                        Target = usr/lib/modules/*/vmlinuz
                        Target = usr/lib/kernel/install.d/*
                        Target = boot/*-ucode.img

                        [Trigger]
                        Operation = Install
                        Operation = Upgrade
                        Type = Package
                        Target = systemd

                        [Action]
                        Description = Adding kernel and initramfs images to /boot...
                        When = PostTransaction
                        Exec = /etc/pacman.d/scripts/mkosi-kernel-add
                        NeedsTargets
                        """
                    )
                )

            kernel_add_script = os.path.join(scripts_dir, "mkosi-kernel-add")
            with open(kernel_add_script, "w") as f:
                f.write(
                    dedent(
                        """\
                        #!/bin/bash -e
                        shopt -s nullglob

                        declare -a kernel_version

                        # Check the targets passed by the pacman hook.
                        while read -r line
                        do
                            if [[ "$line" =~ usr/lib/modules/([^/]+)/vmlinuz ]]
                            then
                                kernel_version+=( "${BASH_REMATCH[1]}" )
                            else
                                # If a non-matching line is passed, just rebuild all kernels.
                                kernel_version=()
                                for f in /usr/lib/modules/*/vmlinuz
                                do
                                    kernel_version+=( "$(basename "$(dirname "$f")")" )
                                done
                                break
                            fi
                        done

                        # (re)build the kernel images.
                        for kv in "${kernel_version[@]}"
                        do
                            kernel-install add "$kv" "/usr/lib/modules/${kv}/vmlinuz"
                        done
                        """
                    )
                )

            make_executable(kernel_add_script)

            kernel_remove_hook = os.path.join(hooks_dir, "60-mkosi-kernel-remove.hook")
            with open(kernel_remove_hook, "w") as f:
                f.write(
                    dedent(
                        """\
                        [Trigger]
                        Operation = Upgrade
                        Operation = Remove
                        Type = Path
                        Target = usr/lib/modules/*/vmlinuz

                        [Action]
                        Description = Removing kernel and initramfs images from /boot...
                        When = PreTransaction
                        Exec = /etc/pacman.d/mkosi-kernel-remove
                        NeedsTargets
                        """
                    )
                )

            kernel_remove_script = os.path.join(scripts_dir, "mkosi-kernel-remove")
            with open(kernel_remove_script, "w") as f:
                f.write(
                    dedent(
                        """\
                        #!/bin/bash -e

                        while read -r f; do
                            kernel-install remove "$(basename "$(dirname "$f")")"
                        done
                        """
                    )
                )

            make_executable(kernel_remove_script)

            if self._args.esp_partno is not None:
                bootctl_update_hook = os.path.join(hooks_dir, "91-mkosi-bootctl-update-hook")
                with open(bootctl_update_hook, "w") as f:
                    f.write(
                        dedent(
                            """\
                            [Trigger]
                            Operation = Upgrade
                            Type = Package
                            Target = systemd

                            [Action]
                            Description = Updating systemd-boot...
                            When = PostTransaction
                            Exec = /usr/bin/bootctl update
                            """
                        )
                    )

            if self._args.bios_partno is not None:
                vmlinuz_add_hook = os.path.join(hooks_dir, "90-mkosi-vmlinuz-add.hook")
                with open(vmlinuz_add_hook, "w") as f:
                    f.write(
                        """\
                        [Trigger]
                        Operation = Install
                        Operation = Upgrade
                        Type = Path
                        Target = usr/lib/modules/*/vmlinuz

                        [Action]
                        Description = Adding vmlinuz to /boot...
                        When = PostTransaction
                        Exec = /bin/bash -c 'while read -r f; do install -Dm644 "$f" "/boot/vmlinuz-$(basename "$(dirname "$f")")"; done'
                        NeedsTargets
                        """
                    )

                make_executable(vmlinuz_add_hook)

                vmlinuz_remove_hook = os.path.join(hooks_dir, "60-mkosi-vmlinuz-remove.hook")
                with open(vmlinuz_remove_hook, "w") as f:
                    f.write(
                        """\
                        [Trigger]
                        Operation = Upgrade
                        Operation = Remove
                        Type = Path
                        Target = usr/lib/modules/*/vmlinuz

                        [Action]
                        Description = Removing vmlinuz from /boot...
                        When = PreTransaction
                        Exec = /bin/bash -c 'while read -r f; do rm -f "/boot/vmlinuz-$(basename "$(dirname "$f")")"; done'
                        NeedsTargets
                        """
                    )

                make_executable(vmlinuz_remove_hook)

        keyring = "archlinux"
        if platform.machine() == "aarch64":
            keyring += "arm"

        packages = {"base"}

        if not do_run_build_script and self._args.bootable:
            if self._args.output_format == OutputFormat.gpt_btrfs:
                packages.add("btrfs-progs")
            elif self._args.output_format == OutputFormat.gpt_xfs:
                packages.add("xfsprogs")
            if self._args.encrypt:
                packages.add("cryptsetup")
                packages.add("device-mapper")
            if self._args.bios_partno:
                packages.add("grub")

            packages.add("dracut")
            packages.add("binutils")

            configure_dracut(self._args, root)

        packages.update(self.packages)

        official_kernel_packages = {
            "linux",
            "linux-lts",
            "linux-hardened",
            "linux-zen",
        }

        has_kernel_package = official_kernel_packages.intersection(self.packages)
        if not do_run_build_script and self._args.bootable and not has_kernel_package:
            # No user-specified kernel
            packages.add("linux")

        if do_run_build_script:
            packages.update(self._args.build_packages)

        if not do_run_build_script and self._args.ssh:
            packages.add("openssh")

        def run_pacman(packages: Set[str]) -> None:
            conf = ["--config", pacman_conf]

            try:
                run(["pacman-key", *conf, "--init"])
                run(["pacman-key", *conf, "--populate"])
                run(["pacman", *conf, "--noconfirm", "-Sy", *packages])
            finally:
                # Kill the gpg-agent started by pacman and pacman-key.
                run(["gpgconf", "--homedir", os.path.join(root, "etc/pacman.d/gnupg"), "--kill", "all"])

        with mount_api_vfs(self._args, root):
            run_pacman(packages)

        # If /etc/locale.gen exists, uncomment the desired locale and leave the rest of the file untouched.
        # If it doesn’t exist, just write the desired locale in it.
        try:

            def _enable_locale(line: str) -> str:
                if line.startswith("#en_US.UTF-8"):
                    return line.replace("#", "")
                return line

            patch_file(os.path.join(root, "etc/locale.gen"), _enable_locale)

        except FileNotFoundError:
            with open(os.path.join(root, "etc/locale.gen"), "x") as f:
                f.write("en_US.UTF-8 UTF-8\n")

        run_workspace_command(self._args, root, ["/usr/bin/locale-gen"])

        with open(os.path.join(root, "etc/locale.conf"), "w") as f:
            f.write("LANG=en_US.UTF-8\n")

        # Arch still uses pam_securetty which prevents root login into
        # systemd-nspawn containers. See https://bugs.archlinux.org/task/45903.
        disable_pam_securetty(root)

    def install_bootloader_bios(self, root: str, loopdev: str) -> None:
        install_grub(self._args, root, loopdev, "grub")
