# SPDX-License-Identifier: LGPL-2.1+

import logging
import os
import re
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path

from mkosi.log import complete_step, log_step
from mkosi.run import bwrap, chroot_cmd


def filter_kernel_modules(root: Path, kver: str, include: Sequence[str], exclude: Sequence[str]) -> list[Path]:
    modulesd = root / "usr/lib/modules" / kver
    modules = set(m for m in (root / modulesd).rglob("*.ko*"))

    keep = set()
    for pattern in include:
        regex = re.compile(pattern)
        for m in modules:
            rel = os.fspath(m.relative_to(modulesd / "kernel"))
            if regex.search(rel):
                logging.debug(f"Including module {rel}")
                keep.add(m)

    for pattern in exclude:
        regex = re.compile(pattern)
        remove = set()
        for m in modules:
            rel = os.fspath(m.relative_to(modulesd / "kernel"))
            if rel not in keep and regex.search(rel):
                logging.debug(f"Excluding module {rel}")
                remove.add(m)

        modules -= remove

    return sorted(modules)


def module_path_to_name(path: Path) -> str:
    return path.name.partition(".")[0]


def resolve_module_dependencies(root: Path, kver: str, modules: Sequence[str]) -> tuple[set[Path], set[Path]]:
    """
    Returns a tuple of lists containing the paths to the module and firmware dependencies of the given list
    of module names (including the given module paths themselves). The paths are returned relative to the
    root directory.
    """
    modulesd = Path("usr/lib/modules") / kver
    builtin = set(module_path_to_name(Path(m)) for m in (root / modulesd / "modules.builtin").read_text().splitlines())
    allmodules = set((root / modulesd / "kernel").glob("**/*.ko*"))
    nametofile = {module_path_to_name(m): m for m in allmodules}

    log_step("Running modinfo to fetch kernel module dependencies")

    # We could run modinfo once for each module but that's slow. Luckily we can pass multiple modules to
    # modinfo and it'll process them all in a single go. We get the modinfo for all modules to build two maps
    # that map the path of the module to its module dependencies and its firmware dependencies respectively.
    info = bwrap(chroot_cmd(root) + ["modinfo", "--set-version", kver, "--null", *nametofile.keys()],
                 stdout=subprocess.PIPE).stdout

    log_step("Calculating required kernel modules and firmware")

    moddep = {}
    firmwaredep = {}

    depends = []
    firmware = []
    for line in info.split("\0"):
        key, sep, value = line.partition(":")
        if not sep:
            key, sep, value = line.partition("=")

        if key in ("depends", "softdep"):
            depends += [d for d in value.strip().split(",") if d]

        elif key == "firmware":
            firmware += [f for f in (root / "usr/lib/firmware").glob(f"{value.strip()}*")]

        elif key == "name":
            name = value.strip()

            moddep[name] = depends
            firmwaredep[name] = firmware

            depends = []
            firmware = []

    todo = [*builtin, *modules]
    mods = set()
    firmware = set()

    while todo:
        m = todo.pop()
        if m in mods:
            continue

        depends = moddep.get(m, [])
        for d in depends:
            if d not in nametofile and d not in builtin:
                logging.warning(f"{d} is a dependency of {m} but is not installed, ignoring ")

        mods.add(m)
        todo += depends
        firmware.update(firmwaredep.get(m, []))

    return set(nametofile[m] for m in mods if m in nametofile), set(firmware)


def gen_required_kernel_modules(
    root: Path,
    kver: str,
    include: Sequence[str],
    exclude: Sequence[str],
) -> Iterator[Path]:
    modulesd = root / "usr/lib/modules" / kver
    modules = filter_kernel_modules(root, kver, include, exclude)

    names = [module_path_to_name(m) for m in modules]
    mods, firmware = resolve_module_dependencies(root, kver, names)

    def files() -> Iterator[Path]:
        yield modulesd.parent
        yield modulesd
        yield modulesd / "kernel"

        for d in (modulesd, root / "usr/lib/firmware"):
            for p in (root / d).rglob("*"):
                if p.is_dir():
                    yield p

        for p in sorted(mods) + sorted(firmware):
            yield p

        for p in (root / modulesd).iterdir():
            if not p.name.startswith("modules"):
                continue

            yield p

        if (root / modulesd / "vdso").exists():
            yield modulesd / "vdso"

            for p in (root / modulesd / "vdso").iterdir():
                yield p

    return files()


def process_kernel_modules(root: Path, kver: str, include: Sequence[str], exclude: Sequence[str]) -> None:
    if not include and not exclude:
        return

    with complete_step("Applying kernel module filters"):
        required = set(gen_required_kernel_modules(root, kver, include, exclude))

        for m in (root / "usr/lib/modules" / kver).rglob("*.ko*"):
            if m in required:
                continue

            logging.debug(f"Removing module {m}")
            (root / m).unlink()

        for fw in (m for m in (root / "usr/lib/firmware").rglob("*") if not m.is_dir()):
            if fw in required:
                continue

            logging.debug(f"Removing firmware {fw}")
            (root / fw).unlink()
