# SPDX-License-Identifier: LGPL-2.1-or-later

import fnmatch
import itertools
import logging
import os
import re
import subprocess
from collections.abc import Iterable, Iterator, Reversible
from pathlib import Path

from mkosi.context import Context
from mkosi.log import complete_step, log_step
from mkosi.run import chroot_cmd, run
from mkosi.sandbox import chase
from mkosi.util import chdir, parents_below


def loaded_modules() -> list[str]:
    # Loaded modules are listed with underscores but the filenames might use dashes instead.
    return [
        normalize_module_name(line.split()[0]) for line in Path("/proc/modules").read_text().splitlines()
    ]


def globs_match_filename(
    name: str,
    globs: Reversible[str],
    *,
    match_default: bool = False,
) -> bool:
    # Check whether the path matches any of the globs

    for glob in reversed(globs):
        # Patterns are evaluated in order and last matching one wins.
        # Patterns may be prefixed with '-' to exclude modules.
        if negative := glob.startswith("-"):
            glob = glob[1:]
        # As a special case, if a directory is specified, all items
        # below that directory are matched.
        if glob.endswith("/"):
            glob += "*"

        if (
            # match the full path
            (glob.startswith("/") and fnmatch.fnmatch(f"/{name}", glob))
            # match a subset of the path, at path element boundary
            or ("/" in glob and fnmatch.fnmatch(f"/{name}", f"*/{glob}"))
            # match the basename
            or fnmatch.fnmatch(name.split("/")[-1], glob)
        ):
            return not negative

    return match_default


def globs_match_module(
    name: str,
    globs: Reversible[str],
) -> bool:
    # Strip '.ko' suffix and an optional compression suffix
    name = re.sub(r"\.ko(\.(gz|xz|zst))?$", "", name)
    # Check whether the suffixless-path matches any of the globs
    return globs_match_filename(name, globs)


def globs_match_firmware(
    name: str,
    globs: Reversible[str],
    *,
    match_default: bool = False,
) -> bool:
    # Strip any known compression suffixes
    name = re.sub(r"\.(gz|xz|zst)$", "", name)
    # Check whether the suffixless-path matches any of the globs
    return globs_match_filename(name, globs, match_default=match_default)


def filter_kernel_modules(
    root: Path,
    kver: str,
    *,
    include: Iterable[str],
    exclude: Iterable[str],
) -> list[str]:
    if include:
        logging.debug(f"Kernel modules include: {' '.join(include)}")
    if exclude:
        logging.debug(f"Kernel modules exclude: {' '.join(exclude)}")

    modulesd = Path("usr/lib/modules") / kver
    with chdir(root):
        # The glob may match additional paths.
        # Narrow this down to *.ko, *.ko.gz, *.ko.xz, *.ko.zst.
        modules = {
            m for m in modulesd.rglob("*.ko*") if m.name.endswith((".ko", ".ko.gz", ".ko.xz", ".ko.zst"))
        }

    n_modules = len(modules)

    keep = set()

    if include:
        patterns = [p[3:] for p in include if p.startswith("re:")]
        regex = re.compile("|".join(patterns))

        globs = [normalize_module_glob(p) for p in include if not p.startswith("re:")]

        for m in modules:
            rel = os.fspath(Path(*m.parts[5:]))

            if (patterns and regex.search(rel)) or globs_match_module(normalize_module_name(rel), globs):
                keep.add(rel)

    if exclude:
        assert all(p.startswith("re:") for p in exclude)
        patterns = [p[3:] for p in exclude]
        regex = re.compile("|".join(patterns))

        remove = set()
        for m in modules:
            rel = os.fspath(Path(*m.parts[5:]))
            if rel not in keep and regex.search(rel):
                remove.add(m)

        modules -= remove
    elif include:
        # If no exclude patterns are specified, only keep the specified kernel modules.
        modules = {modulesd / m for m in keep}

    logging.debug(f"Including {len(modules)}/{n_modules} kernel modules.")

    return sorted(module_path_to_name(m) for m in modules)


def filter_firmware(
    root: Path,
    firmware: set[Path],
    *,
    include: Iterable[str],
    exclude: Iterable[str],
) -> set[Path]:
    if include:
        logging.debug(f"Firmware include: {' '.join(include)}")
    if exclude:
        logging.debug(f"Firmware exclude: {' '.join(exclude)}")

    # globs can be also used to exclude firmware, so we we need to apply them
    # to the inherited list of firmware files too.
    globs = [p for p in include if not p.startswith("re:")]

    if exclude or globs:
        assert all(p.startswith("re:") for p in exclude)
        remove = set()
        patterns = [p[3:] for p in exclude]
        regex = re.compile("|".join(patterns))

        for f in firmware:
            rel = os.fspath(Path(*f.parts[3:]))
            if (patterns and regex.search(rel)) or not globs_match_firmware(rel, globs, match_default=True):
                remove.add(f)

        firmware -= remove

    if include:
        firmwared = Path("usr/lib/firmware")
        with chdir(root):
            all_firmware = set(firmwared.rglob("*"))

        patterns = [p[3:] for p in include if p.startswith("re:")]
        regex = re.compile("|".join(patterns))

        for f in all_firmware:
            rel = os.fspath(Path(*f.parts[3:]))
            if (patterns and regex.search(rel)) or globs_match_firmware(rel, globs):
                firmware.add(f)

    logging.debug(f"Including {len(firmware)} firmware files")

    return firmware


def normalize_module_name(name: str) -> str:
    # Replace '_' by '-'
    return name.replace("_", "-")


def normalize_module_glob(name: str) -> str:
    # We want to replace '_' by '-', except when used in […]
    ans = ""
    while name:
        i = (name + "[").index("[")
        ans += name[:i].replace("_", "-")
        name = name[i:]
        i = (name + "]").index("]")
        ans += name[: i + 1]
        name = name[i + 1 :]
    return ans


def module_path_to_name(path: Path) -> str:
    return normalize_module_name(path.name.partition(".")[0])


def modinfo(context: Context, kver: str, modules: Iterable[str]) -> str:
    cmdline = ["modinfo", "--set-version", kver, "--null"]

    if context.config.output_format.is_extension_image() and not context.config.overlay:
        cmdline += ["--basedir", "/buildroot"]
        sandbox = context.sandbox(options=context.rootoptions(readonly=True))
    else:
        sandbox = chroot_cmd(root=context.rootoptions)

    cmdline += [*modules]

    return run(
        cmdline,
        stdout=subprocess.PIPE,
        sandbox=sandbox,
    ).stdout.strip()


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
        info += modinfo(context, kver, chunk)

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
    modules_include: Iterable[str],
    modules_exclude: Iterable[str],
    firmware_include: Iterable[str],
    firmware_exclude: Iterable[str],
) -> Iterator[Path]:
    modulesd = Path("usr/lib/modules") / kver
    firmwared = Path("usr/lib/firmware")

    # There is firmware in /usr/lib/firmware that is not depended on by any modules so if any firmware was
    # installed we have to take the slow path to make sure we don't copy firmware into the initrd that is not
    # depended on by any kernel modules.
    if modules_include or modules_exclude or (context.root / firmwared).glob("*"):
        modules, firmware = resolve_module_dependencies(
            context,
            kver,
            modules=filter_kernel_modules(
                context.root,
                kver,
                include=modules_include,
                exclude=modules_exclude,
            ),
        )
    else:
        logging.debug(
            "No modules excluded and no firmware installed, using kernel modules generation fast path"
        )
        with chdir(context.root):
            modules = set(modulesd.rglob("*.ko*"))
        firmware = set()

    # Include or exclude firmware explicitly configured
    firmware = filter_firmware(context.root, firmware, include=firmware_include, exclude=firmware_exclude)

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
                for f in modules | firmware
                for p in parents_below(context.root / f, context.root / "usr/lib")
            },
            modules,
            firmware,
            (p.relative_to(context.root) for p in (context.root / modulesd).glob("modules*")),
        )
    )

    if (modulesd / "vdso").exists():
        if not modules:
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
    modules_include: Iterable[str],
    modules_exclude: Iterable[str],
    firmware_include: Iterable[str],
    firmware_exclude: Iterable[str],
) -> None:
    if not (modules_include or modules_exclude or firmware_include or firmware_exclude):
        return

    modulesd = Path("usr/lib/modules") / kver
    firmwared = Path("usr/lib/firmware")

    with complete_step("Applying kernel module filters"):
        required = set(
            gen_required_kernel_modules(
                context,
                kver,
                modules_include=modules_include,
                modules_exclude=modules_exclude,
                firmware_include=firmware_include,
                firmware_exclude=firmware_exclude,
            )
        )

        with chdir(context.root):
            modules = sorted(modulesd.rglob("*.ko*"), reverse=True)
            firmware = sorted(firmwared.rglob("*"), reverse=True)

        for m in modules:
            if m in required:
                continue

            p = context.root / m
            if p.is_file() or p.is_symlink():
                if p.is_symlink():
                    p_target = Path(chase(os.fspath(context.root), os.fspath(m)))
                    if p_target.exists():
                        p_target.unlink()
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


def is_valid_kdir(kdir: Path) -> bool:
    dircontent = list(kdir.glob("*"))

    # kdir does not exist or is empty
    if not dircontent:
        return False

    # check that kdir contains more than just updates
    return dircontent != [kdir / "updates"]
