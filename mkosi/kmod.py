# SPDX-License-Identifier: LGPL-2.1-or-later

import itertools
import logging
import os
import re
import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path

from mkosi.context import Context
from mkosi.log import complete_step, log_step
from mkosi.run import chroot_cmd, run
from mkosi.sandbox import chase
from mkosi.util import chdir, parents_below


def loaded_modules() -> list[str]:
    # Loaded modules are listed with underscores but the filenames might use dashes instead.
    return [
        rf"/{line.split()[0].replace('_', '[_-]')}\.ko"
        for line in Path("/proc/modules").read_text().splitlines()
    ]


def filter_kernel_modules(
    root: Path,
    kver: str,
    *,
    include: Iterable[str],
    exclude: Iterable[str],
) -> list[Path]:
    modulesd = Path("usr/lib/modules") / kver
    with chdir(root):
        modules = set(modulesd.rglob("*.ko*"))

    keep = set()
    if include:
        regex = re.compile("|".join(include))
        for m in modules:
            rel = os.fspath(Path(*m.parts[5:]))
            if regex.search(rel):
                keep.add(rel)

    if exclude:
        remove = set()
        regex = re.compile("|".join(exclude))
        for m in modules:
            rel = os.fspath(Path(*m.parts[5:]))
            if rel not in keep and regex.search(rel):
                remove.add(m)

        modules -= remove

    return sorted(modules)


def normalize_module_name(name: str) -> str:
    return name.replace("_", "-")


def module_path_to_name(path: Path) -> str:
    return normalize_module_name(path.name.partition(".")[0])


def resolve_module_dependencies(
    context: Context,
    kver: str,
    modules: Iterable[str],
) -> tuple[set[Path], set[Path]]:
    """
    Returns a tuple of lists containing the paths to the module and firmware dependencies of the given list
    of module names (including the given module paths themselves). The paths are returned relative to the
    root directory.
    """
    modulesd = Path("usr/lib/modules") / kver
    if (p := context.root / modulesd / "modules.builtin").exists():
        builtin = set(module_path_to_name(Path(m)) for m in p.read_text().splitlines())
    else:
        builtin = set()
    with chdir(context.root):
        allmodules = set(modulesd.rglob("*.ko*"))
    nametofile = {module_path_to_name(m): m for m in allmodules}

    log_step("Running modinfo to fetch kernel module dependencies")

    # We could run modinfo once for each module but that's slow. Luckily we can pass multiple modules to
    # modinfo and it'll process them all in a single go. We get the modinfo for all modules to build two maps
    # that map the path of the module to its module dependencies and its firmware dependencies
    # respectively. Because there's more kernel modules than the max number of accepted CLI arguments, we
    # split the modules list up into chunks.
    info = ""
    for i in range(0, len(nametofile.keys()), 8500):
        chunk = list(nametofile.keys())[i : i + 8500]
        info += run(
            ["modinfo", "--set-version", kver, "--null", *chunk],
            stdout=subprocess.PIPE,
            sandbox=chroot_cmd(root=context.root),
        ).stdout.strip()

    log_step("Calculating required kernel modules and firmware")

    moddep = {}
    firmwaredep = {}

    depends: set[str] = set()
    firmware: set[Path] = set()

    with chdir(context.root):
        for line in info.split("\0"):
            key, sep, value = line.partition(":")
            if not sep:
                key, sep, value = line.partition("=")

            value = value.strip()

            if key == "depends":
                depends.update(normalize_module_name(d) for d in value.split(",") if d)

            elif key == "softdep":
                # softdep is delimited by spaces and can contain strings like pre: and post: so discard
                # anything that ends with a colon.
                depends.update(normalize_module_name(d) for d in value.split() if not d.endswith(":"))

            elif key == "firmware":
                glob = "" if value.endswith("*") else "*"
                fw = [f for f in Path("usr/lib/firmware").glob(f"{value}{glob}")]
                if not fw:
                    logging.debug(f"Not including missing firmware /usr/lib/firmware/{value} in the initrd")

                firmware.update(fw)

            elif key == "name":
                # The file names use dashes, but the module names use underscores. We track the names in
                # terms of the file names, since the depends use dashes and therefore filenames as well.
                name = normalize_module_name(value)

                moddep[name] = depends
                firmwaredep[name] = firmware

                depends = set()
                firmware = set()

    todo = [*builtin, *modules]
    mods = set()
    firmware = set()

    while todo:
        m = todo.pop()
        if m in mods:
            continue

        depends = moddep.get(m, set())
        for d in depends:
            if d not in nametofile and d not in builtin:
                logging.warning(f"{d} is a dependency of {m} but is not installed, ignoring ")

        mods.add(m)
        todo += depends
        firmware.update(firmwaredep.get(m, set()))

    return set(nametofile[m] for m in mods if m in nametofile), set(firmware)


def gen_required_kernel_modules(
    context: Context,
    kver: str,
    *,
    include: Iterable[str],
    exclude: Iterable[str],
) -> Iterator[Path]:
    modulesd = Path("usr/lib/modules") / kver

    # There is firmware in /usr/lib/firmware that is not depended on by any modules so if any firmware was
    # installed we have to take the slow path to make sure we don't copy firmware into the initrd that is not
    # depended on by any kernel modules.
    if exclude or (context.root / "usr/lib/firmware").glob("*"):
        modules = filter_kernel_modules(context.root, kver, include=include, exclude=exclude)
        names = [module_path_to_name(m) for m in modules]
        mods, firmware = resolve_module_dependencies(context, kver, names)
    else:
        logging.debug(
            "No modules excluded and no firmware installed, using kernel modules generation fast path"
        )
        with chdir(context.root):
            mods = set(modulesd.rglob("*.ko*"))
        firmware = set()

    # Some firmware dependencies are symbolic links, so the targets for those must be included in the list
    # of required firmware files too. Intermediate symlinks are not included, and so links pointing to links
    # results in dangling symlinks in the final image.
    for fw in firmware.copy():
        if (context.root / fw).is_symlink():
            target = Path(chase(os.fspath(context.root), os.fspath(fw)))
            if target.exists():
                firmware.add(target.relative_to(context.root))

    yield from sorted(
        itertools.chain(
            {
                p.relative_to(context.root)
                for f in mods | firmware
                for p in parents_below(context.root / f, context.root / "usr/lib")
            },
            mods,
            firmware,
            (p.relative_to(context.root) for p in (context.root / modulesd).glob("modules*")),
        )
    )

    if (modulesd / "vdso").exists():
        if not mods:
            yield from (
                p.relative_to(context.root)
                for p in parents_below(context.root / modulesd / "vdso", context.root / "usr/lib")
            )

        yield modulesd / "vdso"
        yield from sorted(p.relative_to(context.root) for p in (context.root / modulesd / "vdso").iterdir())


def process_kernel_modules(
    context: Context,
    kver: str,
    *,
    include: Iterable[str],
    exclude: Iterable[str],
) -> None:
    if not exclude:
        return

    modulesd = Path("usr/lib/modules") / kver
    firmwared = Path("usr/lib/firmware")

    with complete_step("Applying kernel module filters"):
        required = set(gen_required_kernel_modules(context, kver, include=include, exclude=exclude))

        with chdir(context.root):
            modules = sorted(modulesd.rglob("*.ko*"), reverse=True)
            firmware = sorted(firmwared.rglob("*"), reverse=True)

        for m in modules:
            if m in required:
                continue

            p = context.root / m
            if p.is_file() or p.is_symlink():
                p.unlink()
            elif p.exists():
                p.rmdir()

        for fw in firmware:
            if fw in required:
                continue

            if any(fw.is_relative_to(firmwared / d) for d in ("amd-ucode", "intel-ucode")):
                continue

            p = context.root / fw
            if p.is_file() or p.is_symlink():
                p.unlink()
                if p.parent != context.root / firmwared and not any(p.parent.iterdir()):
                    p.parent.rmdir()
            elif p.exists():
                p.rmdir()
