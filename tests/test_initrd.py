# SPDX-License-Identifier: LGPL-2.1+

import contextlib
import os
import subprocess
import tempfile
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from mkosi.distributions import Distribution
from mkosi.mounts import mount
from mkosi.run import run
from mkosi.tree import copy_tree
from mkosi.util import INVOKING_USER

from . import Image

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def passphrase() -> Iterator[Path]:
    # We can't use tmp_path fixture because pytest creates it in a nested directory we can't access using our
    # unprivileged user.
    # TODO: Use delete_on_close=False and close() instead of flush() when we require Python 3.12 or newer.
    with tempfile.NamedTemporaryFile(prefix="mkosi.passphrase", mode="w") as passphrase:
        passphrase.write("mkosi")
        passphrase.flush()
        os.fchown(passphrase.fileno(), INVOKING_USER.uid, INVOKING_USER.gid)
        os.fchmod(passphrase.fileno(), 0o600)
        yield Path(passphrase.name)


@pytest.fixture(scope="module")
def initrd(config: Image.Config) -> Iterator[Image]:
    with Image(
        config,
        options=[
            "--directory", "",
            "--include=mkosi-initrd/",
        ],
    ) as initrd:
        if initrd.config.distribution == Distribution.rhel_ubi:
            pytest.skip("Cannot build RHEL-UBI initrds")

        initrd.build()
        yield initrd


def test_initrd(initrd: Image) -> None:
    with Image(
        initrd.config,
        options=[
            "--initrd", Path(initrd.output_dir.name) / "initrd",
            "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
            "--incremental",
            "--ephemeral",
            "--format=disk",
        ]
    ) as image:
        image.build()
        image.qemu()


@pytest.mark.skipif(os.getuid() != 0, reason="mkosi-initrd LVM test can only be executed as root")
def test_initrd_lvm(initrd: Image) -> None:
    with Image(
        initrd.config,
        options=[
            "--initrd", Path(initrd.output_dir.name) / "initrd",
            "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
            "--kernel-command-line=root=LABEL=root",
            "--kernel-command-line=rw",
            "--incremental",
            "--ephemeral",
            "--qemu-firmware=linux",
        ]
    ) as image, contextlib.ExitStack() as stack:
        image.build(["--format", "directory"])

        drive = Path(image.output_dir.name) / "image.raw"
        drive.touch()
        os.truncate(drive, 5000 * 1024**2)

        lodev = run(["losetup", "--show", "--find", "--partscan", drive], stdout=subprocess.PIPE).stdout.strip()
        stack.callback(lambda: run(["losetup", "--detach", lodev]))
        run(["sfdisk", "--label", "gpt", lodev], input="type=E6D6D379-F507-44C2-A23C-238F2A3DF928 bootable")
        run(["lvm", "pvcreate", f"{lodev}p1"])
        run(["lvm", "pvs"])
        run(["lvm", "vgcreate", "vg_mkosi", f"{lodev}p1"])
        run(["lvm", "vgchange", "-ay", "vg_mkosi"])
        run(["lvm", "vgs"])
        stack.callback(lambda: run(["vgchange", "-an", "vg_mkosi"]))
        run(["lvm", "lvcreate", "-l", "100%FREE", "-n", "lv0", "vg_mkosi"])
        run(["lvm", "lvs"])
        run(["udevadm", "wait", "/dev/vg_mkosi/lv0"])
        run([f"mkfs.{image.config.distribution.filesystem()}", "-L", "root", "/dev/vg_mkosi/lv0"])

        with tempfile.TemporaryDirectory() as mnt, mount(Path("/dev/vg_mkosi/lv0"), Path(mnt)):
            # The image might have been built unprivileged so we need to fix the file ownership. Making all the
            # files owned by root isn't completely correct but good enough for the purposes of the test.
            copy_tree(Path(image.output_dir.name) / "image", Path(mnt), preserve=False)

        stack.close()

        image.qemu(["--format=disk"])


def test_initrd_luks(initrd: Image, passphrase: Path) -> None:
    with tempfile.TemporaryDirectory() as repartd:
        os.chown(repartd, INVOKING_USER.uid, INVOKING_USER.gid)

        (Path(repartd) / "00-esp.conf").write_text(
            textwrap.dedent(
                """\
                [Partition]
                Type=esp
                Format=vfat
                CopyFiles=/boot:/
                CopyFiles=/efi:/
                SizeMinBytes=512M
                SizeMaxBytes=512M
                """
            )
        )

        (Path(repartd) / "05-bios.conf").write_text(
            textwrap.dedent(
                """\
                [Partition]
                # UUID of the grub BIOS boot partition which grubs needs on GPT to
                # embed itself into.
                Type=21686148-6449-6e6f-744e-656564454649
                SizeMinBytes=1M
                SizeMaxBytes=1M
                """
            )
        )

        (Path(repartd) / "10-root.conf").write_text(
            textwrap.dedent(
                f"""\
                [Partition]
                Type=root
                Format={initrd.config.distribution.filesystem()}
                Minimize=guess
                Encrypt=key-file
                CopyFiles=/
                """
            )
        )

        with Image(
            initrd.config,
            options=[
                "--initrd", Path(initrd.output_dir.name) / "initrd",
                "--repart-dir", repartd,
                "--passphrase", passphrase,
                "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
                "--credential=cryptsetup.passphrase=mkosi",
                "--incremental",
                "--ephemeral",
                "--format=disk",
            ]
        ) as image:
            image.build()
            image.qemu()


@pytest.mark.skipif(os.getuid() != 0, reason="mkosi-initrd LUKS+LVM test can only be executed as root")
def test_initrd_luks_lvm(config: Image.Config, initrd: Image, passphrase: Path) -> None:
    with Image(
        config,
        options=[
            "--initrd", Path(initrd.output_dir.name) / "initrd",
            "--kernel-command-line=systemd.unit=mkosi-check-and-shutdown.service",
            "--kernel-command-line=root=LABEL=root",
            "--kernel-command-line=rw",
            "--credential=cryptsetup.passphrase=mkosi",
            "--incremental",
            "--ephemeral",
            "--qemu-firmware=linux",
        ]
    ) as image, contextlib.ExitStack() as stack:
        image.build(["--format", "directory"])

        drive = Path(image.output_dir.name) / "image.raw"
        drive.touch()
        os.truncate(drive, 5000 * 1024**2)

        lodev = run(["losetup", "--show", "--find", "--partscan", drive], stdout=subprocess.PIPE).stdout.strip()
        stack.callback(lambda: run(["losetup", "--detach", lodev]))
        run(["sfdisk", "--label", "gpt", lodev], input="type=E6D6D379-F507-44C2-A23C-238F2A3DF928 bootable")
        run(
            [
                "cryptsetup",
                "--key-file", passphrase,
                "--use-random",
                "--pbkdf", "pbkdf2",
                "--pbkdf-force-iterations", "1000",
                "luksFormat",
                f"{lodev}p1",
            ]
        )
        run(["cryptsetup", "--key-file", passphrase, "luksOpen", f"{lodev}p1", "lvm_root"])
        stack.callback(lambda: run(["cryptsetup", "close", "lvm_root"]))
        luks_uuid = run(["cryptsetup", "luksUUID", f"{lodev}p1"], stdout=subprocess.PIPE).stdout.strip()
        run(["lvm", "pvcreate", "/dev/mapper/lvm_root"])
        run(["lvm", "pvs"])
        run(["lvm", "vgcreate", "vg_mkosi", "/dev/mapper/lvm_root"])
        run(["lvm", "vgchange", "-ay", "vg_mkosi"])
        run(["lvm", "vgs"])
        stack.callback(lambda: run(["vgchange", "-an", "vg_mkosi"]))
        run(["lvm", "lvcreate", "-l", "100%FREE", "-n", "lv0", "vg_mkosi"])
        run(["lvm", "lvs"])
        run(["udevadm", "wait", "/dev/vg_mkosi/lv0"])
        run([f"mkfs.{image.config.distribution.filesystem()}", "-L", "root", "/dev/vg_mkosi/lv0"])

        with tempfile.TemporaryDirectory() as mnt, mount(Path("/dev/vg_mkosi/lv0"), Path(mnt)):
            # The image might have been built unprivileged so we need to fix the file ownership. Making all the
            # files owned by root isn't completely correct but good enough for the purposes of the test.
            copy_tree(Path(image.output_dir.name) / "image", Path(mnt), preserve=False)

        stack.close()

        image.qemu([
            "--format=disk",
            f"--kernel-command-line=rd.luks.uuid={luks_uuid}",
        ])


def test_initrd_size(initrd: Image) -> None:
    # The fallback value is for CentOS and related distributions.
    maxsize = 1024**2 * {
        Distribution.fedora: 46,
        Distribution.debian: 40,
        Distribution.ubuntu: 36,
        Distribution.arch: 47,
        Distribution.opensuse: 39,
    }.get(initrd.config.distribution, 48)

    assert (Path(initrd.output_dir.name) / "initrd").stat().st_size <= maxsize
