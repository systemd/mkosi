# SPDX-License-Identifier: LGPL-2.1-or-later

import barrage.assertions as Assert

from mkosi import kmod


async def test_globs_match_module() -> None:
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["ahci"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.xz.2", ["ahci"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["ata"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["drivers"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["/drivers"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["/drivers"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci-2.ko.xz", ["ahci"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci2.ko.zst", ["ahci"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["ata/*"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["/ata/*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["drivers/*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["/drivers/*"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko", ["ahci/*"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko", ["bahci*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.zst", ["ahci*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["ahc*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["ah*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["ata/"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["drivers/"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["drivers/ata/"]))

    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["-ahci", "*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko", ["-ahci", "*", "ahciahci"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["-ahci", "*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.zst", ["-ahci", "*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "*"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "drivers/"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "ata/"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "ata/ata/"]))
    Assert.true(kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "drivers/ata/"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko", ["*", "-ahci"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko", ["ahci", "-*"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.zst", ["-*"]))
    Assert.false(kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["-*"]))

    # absolute glob behavior unchanged when paths are relative to /lib/module/<kver>
    Assert.true(kmod.globs_match_module("kernel/drivers/ata/ahci.ko", ["drivers/*"]))
    Assert.true(kmod.globs_match_module("kernel/drivers/ata/ahci.ko", ["/drivers/*"]))
    Assert.false(kmod.globs_match_module("kernel/drivers/ata/ahci.ko.xz", ["/ata/*"]))

    # absolute globs match both relative to kernel/ and module_dir root
    Assert.true(kmod.globs_match_module("kernel/drivers/ata/ahci.ko.xz", ["/drivers/ata/ahci"]))
    Assert.true(kmod.globs_match_module("kernel/drivers/ata/ahci.ko.xz", ["/kernel/drivers/ata/ahci"]))


async def test_normalize_module_glob() -> None:
    Assert.eq(kmod.normalize_module_glob("raid[0-9]"), "raid[0-9]")
    Assert.eq(kmod.normalize_module_glob("raid[0_9]"), "raid[0_9]")
    Assert.eq(kmod.normalize_module_glob("raid[0_9]a_z"), "raid[0_9]a-z")
    Assert.eq(kmod.normalize_module_glob("0_9"), "0-9")
    Assert.eq(kmod.normalize_module_glob("[0_9"), "[0_9")
    Assert.eq(kmod.normalize_module_glob("0_9]"), "0-9]")
    Assert.eq(kmod.normalize_module_glob("raid[0_9]a_z[a_c]"), "raid[0_9]a-z[a_c]")
