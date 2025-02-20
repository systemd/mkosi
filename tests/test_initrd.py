# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import os
import subprocess
import tempfile
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from mkosi.run import run
from mkosi.sandbox import umask
from mkosi.tree import copy_tree
from mkosi.util import PathString

from . import Image, ImageConfig

pytestmark = pytest.mark.integration


@contextlib.contextmanager
def mount(what: PathString, where: PathString) -> Iterator[Path]:
    where = Path(where)

    if not where.exists():
        with umask(~0o755):
            where.mkdir(parents=True)

    run(["mount", "--no-mtab", what, where])
    try:
        yield where
    finally:
        run(["umount", "--no-mtab", where])


@pytest.fixture(scope="module")
def passphrase() -> Iterator[Path]:
    # We can't use tmp_path fixture because pytest creates it in a nested directory we can't access using our
    # unprivileged user.
    # TODO: Use delete_on_close=False and close() instead of flush() when we require Python 3.12 or newer.
    with tempfile.NamedTemporaryFile(prefix="mkosi.passphrase", mode="w") as passphrase:
        passphrase.write("mkosi")
        passphrase.flush()
        st = Path.cwd().stat()
        os.fchown(passphrase.fileno(), st.st_uid, st.st_gid)
        os.fchmod(passphrase.fileno(), 0o600)
        yield Path(passphrase.name)


def test_initrd(config: ImageConfig) -> None:
    with Image(config) as image:
        image.build(options=["--format=disk"])
        image.vm()


@pytest.mark.skipif(os.getuid() != 0, reason="mkosi-initrd LVM test can only be executed as root")
def test_initrd_lvm(config: ImageConfig) -> None:
    with Image(config) as image, contextlib.ExitStack() as stack:
        image.build(["--format=disk"])

        lvm = Path(image.output_dir) / "lvm.raw"
        lvm.touch()
        os.truncate(lvm, 5000 * 1024**2)

        lodev = run(
            ["losetup", "--show", "--find", "--partscan", lvm], stdout=subprocess.PIPE
        ).stdout.strip()
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
        run(["udevadm", "wait", "--timeout=30", "/dev/vg_mkosi/lv0"])
        run([f"mkfs.{image.config.distribution.filesystem()}", "-L", "root", "/dev/vg_mkosi/lv0"])

        src = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        run(["systemd-dissect", "--mount", "--mkdir", Path(image.output_dir) / "image.raw", src])
        stack.callback(lambda: run(["systemd-dissect", "--umount", "--rmdir", src]))

        dst = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        stack.enter_context(mount(Path("/dev/vg_mkosi/lv0"), dst))

        copy_tree(src, dst)

        stack.close()

        lvm.rename(Path(image.output_dir) / "image.raw")

        image.vm(
            [
                "--firmware=linux",
                # LVM confuses systemd-repart so we mask it for this test.
                "--kernel-command-line-extra=systemd.mask=systemd-repart.service",
                "--kernel-command-line-extra=root=LABEL=root",
            ]
        )


def test_initrd_luks(config: ImageConfig, passphrase: Path) -> None:
    with tempfile.TemporaryDirectory() as repartd:
        st = Path.cwd().stat()
        os.chown(repartd, st.st_uid, st.st_gid)

        (Path(repartd) / "00-esp.conf").write_text(
            textwrap.dedent(
                """\
                [Partition]
                Type=esp
                Format=vfat
                CopyFiles=/boot:/
                CopyFiles=/efi:/
                SizeMinBytes=1G
                SizeMaxBytes=1G
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
                Format={config.distribution.filesystem()}
                Minimize=guess
                Encrypt=key-file
                CopyFiles=/
                """
            )
        )

        with Image(config) as image:
            image.build(["--repart-directory", repartd, "--passphrase", passphrase, "--format=disk"])
            image.vm(["--credential=cryptsetup.passphrase=mkosi"])


@pytest.mark.skipif(os.getuid() != 0, reason="mkosi-initrd LUKS+LVM test can only be executed as root")
def test_initrd_luks_lvm(config: ImageConfig, passphrase: Path) -> None:
    with Image(config) as image, contextlib.ExitStack() as stack:
        image.build(["--format=disk"])

        lvm = Path(image.output_dir) / "lvm.raw"
        lvm.touch()
        os.truncate(lvm, 5000 * 1024**2)

        lodev = run(
            ["losetup", "--show", "--find", "--partscan", lvm], stdout=subprocess.PIPE
        ).stdout.strip()
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
        )  # fmt: skip
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
        run(["udevadm", "wait", "--timeout=30", "/dev/vg_mkosi/lv0"])
        run([f"mkfs.{image.config.distribution.filesystem()}", "-L", "root", "/dev/vg_mkosi/lv0"])

        src = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        run(["systemd-dissect", "--mount", "--mkdir", Path(image.output_dir) / "image.raw", src])
        stack.callback(lambda: run(["systemd-dissect", "--umount", "--rmdir", src]))

        dst = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        stack.enter_context(mount(Path("/dev/vg_mkosi/lv0"), dst))

        copy_tree(src, dst)

        stack.close()

        lvm.rename(Path(image.output_dir) / "image.raw")

        image.vm(
            [
                "--format=disk",
                "--credential=cryptsetup.passphrase=mkosi",
                "--firmware=linux",
                "--kernel-command-line-extra=root=LABEL=root",
                f"--kernel-command-line-extra=rd.luks.uuid={luks_uuid}",
            ]
        )


def test_initrd_size(config: ImageConfig) -> None:
    with Image(config) as image:
        image.build()

        # Set a reasonably high limit to avoid having to bump it every single time by
        # small amounts. 100M should do.
        maxsize = 1024**2 * 100

        assert (Path(image.output_dir) / "image.initrd").stat().st_size <= maxsize
