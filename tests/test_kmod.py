# SPDX-License-Identifier: LGPL-2.1-or-later

from mkosi import kmod


def test_globs_match_module() -> None:
    assert kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["ahci"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.xz.2", ["ahci"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["ata"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["drivers"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["/drivers"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["/drivers"])
    assert not kmod.globs_match_module("drivers/ata/ahci-2.ko.xz", ["ahci"])
    assert not kmod.globs_match_module("drivers/ata/ahci2.ko.zst", ["ahci"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["ata/*"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["/ata/*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["drivers/*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["/drivers/*"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko", ["ahci/*"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko", ["bahci*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.zst", ["ahci*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["ahc*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["ah*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["ata/"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["drivers/"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["drivers/ata/"])

    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["-ahci", "*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko", ["-ahci", "*", "ahciahci"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["-ahci", "*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.zst", ["-ahci", "*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "*"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "drivers/"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "ata/"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "ata/ata/"])
    assert kmod.globs_match_module("drivers/ata/ahci.ko.gz", ["-ahci", "drivers/ata/"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko", ["*", "-ahci"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko", ["ahci", "-*"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.zst", ["-*"])
    assert not kmod.globs_match_module("drivers/ata/ahci.ko.xz", ["-*"])


def test_normalize_module_glob() -> None:
    assert kmod.normalize_module_glob("raid[0-9]") == "raid[0-9]"
    assert kmod.normalize_module_glob("raid[0_9]") == "raid[0_9]"
    assert kmod.normalize_module_glob("raid[0_9]a_z") == "raid[0_9]a-z"
    assert kmod.normalize_module_glob("0_9") == "0-9"
    assert kmod.normalize_module_glob("[0_9") == "[0_9"
    assert kmod.normalize_module_glob("0_9]") == "0-9]"
    assert kmod.normalize_module_glob("raid[0_9]a_z[a_c]") == "raid[0_9]a-z[a_c]"
