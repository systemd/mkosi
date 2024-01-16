# SPDX-License-Identifier: LGPL-2.1+

import logging
import os
import re
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path

from mkosi.log import complete_step, log_step
from mkosi.run import run
from mkosi.types import PathString


def loaded_modules() -> list[str]:
    return [f"{line.split()[0]}\\.ko" for line in Path("/proc/modules").read_text().splitlines()]


def filter_kernel_modules(
    root: Path,
    kver: str,
    *,
    include: Sequence[str],
    exclude: Sequence[str],
    host: bool,
) -> list[Path]:
    modulesd = root / "usr/lib/modules" / kver
    modules = {m for m in modulesd.rglob("*.ko*")}

    if host:
        include = [*include, *loaded_modules()]

    keep = set()
    if include:
        regex = re.compile("|".join(include))
        for m in modules:
            rel = os.fspath(m.relative_to(modulesd / "kernel"))
            if regex.search(rel):
                logging.debug(f"Including module {rel}")
                keep.add(rel)

    if exclude:
        remove = set()
        regex = re.compile("|".join(exclude))
        for m in modules:
            rel = os.fspath(m.relative_to(modulesd / "kernel"))
            if rel not in keep and regex.search(rel):
                logging.debug(f"Excluding module {rel}")
                remove.add(m)

        modules -= remove

    return sorted(modules)


def module_path_to_name(path: Path) -> str:
    return path.name.partition(".")[0]


def resolve_module_dependencies(
    root: Path,
    kver: str,
    modules: Sequence[str],
    *,
    sandbox: Sequence[PathString] = (),
) -> tuple[set[Path], set[Path]]:
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
    # Because there's more kernel modules than the max number of accepted CLI arguments for bwrap, we split the modules
    # list up into chunks.
    info = ""
    for i in range(0, len(nametofile.keys()), 8500):
        chunk = list(nametofile.keys())[i:i+8500]
        info += run(["modinfo", "--basedir", root, "--set-version", kver, "--null", *chunk],
                    stdout=subprocess.PIPE, sandbox=sandbox).stdout.strip()

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
            fw = [f for f in (root / "usr/lib/firmware").glob(f"{value.strip()}*")]
            if not fw:
                logging.debug(f"Not including missing firmware /usr/lib/firmware/{value} in the initrd")

            firmware += fw

        elif key == "name":
            # The file names use dashes, but the module names use underscores. We track the names
            # in terms of the file names, since the depends use dashes and therefore filenames as
            # well.
            name = value.strip().replace("_", "-")

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
    include: Sequence[str],
    exclude: Sequence[str],
    host: bool,
    sandbox: Sequence[PathString] = (),
) -> Iterator[Path]:
    modulesd = root / "usr/lib/modules" / kver
    modules = filter_kernel_modules(root, kver, include=include, exclude=exclude, host=host)

    names = [module_path_to_name(m) for m in modules]
    mods, firmware = resolve_module_dependencies(root, kver, names, sandbox=sandbox)

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


def process_kernel_modules(
    root: Path,
    kver: str,
    *,
    include: Sequence[str],
    exclude: Sequence[str],
    host: bool,
    sandbox: Sequence[PathString] = (),
) -> None:
    if not include and not exclude:
        return

    with complete_step("Applying kernel module filters"):
        required = set(
            gen_required_kernel_modules(root, kver, include=include, exclude=exclude, host=host, sandbox=sandbox)
        )

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
