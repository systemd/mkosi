# SPDX-License-Identifier: LGPL-2.1-or-later

import itertools
import logging
import os
import re
import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path

from mkosi.log import complete_step, log_step
from mkosi.run import run
from mkosi.sandbox import Mount, SandboxProtocol, chroot_cmd, nosandbox
from mkosi.util import parents_below


def loaded_modules() -> list[str]:
    return [fr"{line.split()[0]}\.ko" for line in Path("/proc/modules").read_text().splitlines()]


def filter_kernel_modules(root: Path, kver: str, *, include: Iterable[str], exclude: Iterable[str]) -> list[Path]:
    modulesd = root / "usr/lib/modules" / kver
    modules = set(modulesd.rglob("*.ko*"))

    keep = set()
    if include:
        regex = re.compile("|".join(include))
        for m in modules:
            rel = os.fspath(Path(*m.relative_to(modulesd).parts[1:]))
            if regex.search(rel):
                logging.debug(f"Including module {rel}")
                keep.add(rel)

    if exclude:
        remove = set()
        regex = re.compile("|".join(exclude))
        for m in modules:
            rel = os.fspath(Path(*m.relative_to(modulesd).parts[1:]))
            if rel not in keep and regex.search(rel):
                logging.debug(f"Excluding module {rel}")
                remove.add(m)

        modules -= remove

    return sorted(modules)


def normalize_module_name(name: str) -> str:
    return name.replace("_", "-")


def module_path_to_name(path: Path) -> str:
    return normalize_module_name(path.name.partition(".")[0])


def resolve_module_dependencies(
    root: Path,
    kver: str,
    modules: Iterable[str],
    *,
    sandbox: SandboxProtocol = nosandbox,
) -> tuple[set[Path], set[Path]]:
    """
    Returns a tuple of lists containing the paths to the module and firmware dependencies of the given list
    of module names (including the given module paths themselves). The paths are returned relative to the
    root directory.
    """
    modulesd = root / "usr/lib/modules" / kver
    if (modulesd / "modules.builtin").exists():
        builtin = set(module_path_to_name(Path(m)) for m in (modulesd / "modules.builtin").read_text().splitlines())
    else:
        builtin = set()
    allmodules = set(modulesd.rglob("*.ko*"))
    nametofile = {module_path_to_name(m): m for m in allmodules}

    log_step("Running modinfo to fetch kernel module dependencies")

    # We could run modinfo once for each module but that's slow. Luckily we can pass multiple modules to
    # modinfo and it'll process them all in a single go. We get the modinfo for all modules to build two maps
    # that map the path of the module to its module dependencies and its firmware dependencies respectively.
    # Because there's more kernel modules than the max number of accepted CLI arguments for bwrap, we split the modules
    # list up into chunks.
    info = ""
    for i in range(0, len(nametofile.keys()), 8500):
        chunk = list(nametofile.keys())[i:i+8500]
        info += run(
            ["modinfo", "--set-version", kver, "--null", *chunk],
            stdout=subprocess.PIPE,
            sandbox=sandbox(binary="modinfo", mounts=[Mount(root, "/buildroot", ro=True)], extra=chroot_cmd()),
        ).stdout.strip()

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
            depends += [normalize_module_name(d) for d in value.strip().split(",") if d]

        elif key == "firmware":
            fw = [f for f in (root / "usr/lib/firmware").glob(f"{value.strip()}*")]
            if not fw:
                logging.debug(f"Not including missing firmware /usr/lib/firmware/{value} in the initrd")

            firmware += fw

        elif key == "name":
            # The file names use dashes, but the module names use underscores. We track the names
            # in terms of the file names, since the depends use dashes and therefore filenames as
            # well.
            name = normalize_module_name(value.strip())

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
    *,
    include: Iterable[str],
    exclude: Iterable[str],
    sandbox: SandboxProtocol = nosandbox,
) -> Iterator[Path]:
    modulesd = root / "usr/lib/modules" / kver

    # There is firmware in /usr/lib/firmware that is not depended on by any modules so if any firmware was installed
    # we have to take the slow path to make sure we don't copy firmware into the initrd that is not depended on by any
    # kernel modules.
    if exclude or (root / "usr/lib/firmware").glob("*"):
        modules = filter_kernel_modules(root, kver, include=include, exclude=exclude)
        names = [module_path_to_name(m) for m in modules]
        mods, firmware = resolve_module_dependencies(root, kver, names, sandbox=sandbox)
    else:
        logging.debug("No modules excluded and no firmware installed, using kernel modules generation fast path")
        mods = set(modulesd.rglob("*.ko*"))
        firmware = set()

    yield from sorted(
        itertools.chain(
            {p for f in mods | firmware for p in parents_below(f, root / "usr/lib")},
            mods,
            firmware,
            modulesd.glob("modules*"),
        )
    )

    if (modulesd / "vdso").exists():
        if not mods:
            yield from parents_below(modulesd / "vdso", root / "usr/lib")

        yield modulesd / "vdso"
        yield from sorted((modulesd / "vdso").iterdir())


def process_kernel_modules(
    root: Path,
    kver: str,
    *,
    include: Iterable[str],
    exclude: Iterable[str],
    sandbox: SandboxProtocol = nosandbox,
) -> None:
    if not exclude:
        return

    with complete_step("Applying kernel module filters"):
        required = set(gen_required_kernel_modules(root, kver, include=include, exclude=exclude, sandbox=sandbox))

        for m in sorted((root / "usr/lib/modules" / kver).rglob("*.ko*"), reverse=True):
            if m in required:
                continue

            if m.is_file() or m.is_symlink():
                logging.debug(f"Removing module {m}")
                m.unlink()
            else:
                m.rmdir()

        for fw in sorted((root / "usr/lib/firmware").rglob("*"), reverse=True):
            if fw in required:
                continue

            if any(fw.is_relative_to(root / "usr/lib/firmware" / d) for d in ("amd-ucode", "intel-ucode")):
                continue

            if fw.is_file() or fw.is_symlink():
                logging.debug(f"Removing firmware {fw}")
                fw.unlink()
            else:
                fw.rmdir()
