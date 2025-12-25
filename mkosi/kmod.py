# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import fnmatch
import itertools
import logging
import os
import re
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path

from mkosi.context import Context
from mkosi.log import complete_step
from mkosi.run import chroot_cmd, run
from mkosi.sandbox import chase
from mkosi.util import chdir, parents_below


def loaded_modules() -> list[str]:
    # Loaded modules are listed with underscores but the filenames might use dashes instead.
    return [
        normalize_module_name(line.split()[0]) for line in Path("/proc/modules").read_text().splitlines()
    ]


def globs_match_filename(name: str, globs: Sequence[str], *, match_default: bool = False) -> bool:
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
            # Match globs starting with / relative to kernel/ first, since in-tree module are the common case
            (glob.startswith("/") and fnmatch.fnmatch(f"/{name}", f"/kernel{glob}"))
            # Now match absolute globs relative to lib/modules/KVER/
            or (glob.startswith("/") and fnmatch.fnmatch(f"/{name}", glob))
            # match a subset of the path, at path element boundary
            or ("/" in glob and fnmatch.fnmatch(f"/{name}", f"*/{glob}"))
            # match the basename
            or fnmatch.fnmatch(name.split("/")[-1], glob)
        ):
            return not negative

    return match_default


def globs_match_module(name: str, globs: Sequence[str]) -> bool:
    # Strip '.ko' suffix and an optional compression suffix
    name = re.sub(r"\.ko(\.(gz|xz|zst))?$", "", name)
    # Check whether the suffixless-path matches any of the globs
    return globs_match_filename(name, globs)


def globs_match_firmware(name: str, globs: Sequence[str], *, match_default: bool = False) -> bool:
    # Strip any known compression suffixes
    name = re.sub(r"\.(gz|xz|zst)$", "", name)
    # Check whether the suffixless-path matches any of the globs
    return globs_match_filename(name, globs, match_default=match_default)


@complete_step("Applying kernel modules include/exclude configuration")
def filter_kernel_modules(
    root: Path,
    kver: str,
    *,
    include: Sequence[str],
    exclude: Sequence[str],
) -> list[str]:
    if include:
        logging.debug(f"Kernel modules include directives: {' '.join(include)}")
    if exclude:
        logging.debug(f"Kernel modules exclude directives: {' '.join(exclude)}")

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
            rel = os.fspath(m.relative_to(modulesd))
            # old regexes match relative to modulesd/subdir/ not modulesd/
            legacy_rel = os.fspath(Path(*m.parts[5:]))

            if (patterns and regex.search(legacy_rel)) or globs_match_module(
                normalize_module_name(rel), globs
            ):
                keep.add(rel)

    if exclude:
        assert all(p.startswith("re:") for p in exclude)
        patterns = [p[3:] for p in exclude]
        regex = re.compile("|".join(patterns))

        remove = set()
        for m in modules:
            rel = os.fspath(m.relative_to(modulesd))
            # old regexes match relative to modulesd/subdir/ not modulesd/
            legacy_rel = os.fspath(Path(*m.parts[5:]))

            if rel not in keep and regex.search(legacy_rel):
                remove.add(m)

        modules -= remove
    elif include:
        # If no exclude patterns are specified, only keep the specified kernel modules.
        modules = {modulesd / m for m in keep}

    logging.debug(f"Passing {len(modules)}/{n_modules} kernel modules on to dependency resolution.")

    return sorted(module_path_to_name(m) for m in modules)


@complete_step("Applying firmware include/exclude configuration")
def filter_firmware(
    root: Path,
    firmware: set[Path],
    *,
    include: Sequence[str],
    exclude: Sequence[str],
) -> set[Path]:
    if include:
        logging.debug(f"Firmware include directives: {' '.join(include)}")
    if exclude:
        logging.debug(f"Firmware exclude directives: {' '.join(exclude)}")

    firmwared = Path("usr/lib/firmware")

    # globs can be also used to exclude firmware, so we we need to apply them
    # to the inherited list of firmware files too.
    globs = [p for p in include if not p.startswith("re:")]

    if exclude or globs:
        assert all(p.startswith("re:") for p in exclude)
        remove = set()
        patterns = [p[3:] for p in exclude]
        regex = re.compile("|".join(patterns))

        for f in firmware:
            rel = os.fspath(f.relative_to(firmwared))
            if (patterns and regex.search(rel)) or not globs_match_firmware(rel, globs, match_default=True):
                remove.add(f)

        firmware -= remove

    if include:
        with chdir(root):
            all_firmware = {p for p in firmwared.rglob("*") if p.is_file() or p.is_symlink()}

        patterns = [p[3:] for p in include if p.startswith("re:")]
        regex = re.compile("|".join(patterns))

        for f in all_firmware:
            rel = os.fspath(f.relative_to(firmwared))
            if (patterns and regex.search(rel)) or globs_match_firmware(rel, globs):
                firmware.add(f)

    logging.debug(f"A total of {len(firmware)} firmware files will be included in the image")

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


@dataclasses.dataclass(frozen=True)
class ModuleDependencyInfo:
    modules: set[str]
    firmware: set[Path]


def modinfo(context: Context, kver: str, modules: Sequence[str]) -> dict[str, ModuleDependencyInfo]:
    cmdline = ["modinfo", "--modname", "--set-version", kver, "--null"]

    if context.config.output_format.is_extension_image() and not context.config.overlay:
        cmdline += ["--basedir", "/buildroot"]
        sandbox = context.sandbox(options=context.rootoptions(readonly=True))
    else:
        sandbox = chroot_cmd(root=context.rootoptions)

    cmdline += [*modules]

    output = run(cmdline, stdout=subprocess.PIPE, sandbox=sandbox).stdout.strip()

    moddep: dict[str, ModuleDependencyInfo] = {}
    depends: set[str] = set()
    firmware: set[Path] = set()

    with chdir(context.root):
        for line in output.split("\0"):
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
                if (Path("usr/lib/firmware") / value).exists():
                    firmware.add(Path("usr/lib/firmware") / value)

                glob = "" if value.endswith("*") else ".*"

                firmware.update(Path("usr/lib/firmware").glob(f"{value}{glob}"))

            elif key == "name":
                # The file names use dashes, but the module names use underscores. We track the names in
                # terms of the file names, since the depends use dashes and therefore filenames as well.
                name = normalize_module_name(value)
                moddep[name] = ModuleDependencyInfo(modules=depends, firmware=firmware)
                depends = set()
                firmware = set()

    return moddep


@complete_step("Calculating required kernel modules and firmware")
def resolve_module_dependencies(
    context: Context,
    kver: str,
    modules: Sequence[str],
) -> tuple[set[Path], set[Path]]:
    """
    Returns a tuple of lists containing the paths to the module and firmware dependencies of the given list
    of module names (including the given module paths themselves). The paths are returned relative to the
    root directory.
    """
    modulesd = Path("usr/lib/modules") / kver

    if (p := context.root / modulesd / "modules.builtin").exists():
        builtin = {module_path_to_name(Path(m)) for m in p.read_text().splitlines()}
    else:
        builtin = set()

    with chdir(context.root):
        allmodules = set(modulesd.rglob("*.ko*"))
    nametofile = {module_path_to_name(m): m for m in allmodules}

    todo = [*builtin, *modules]
    mods = set()
    firmware = set()

    while todo:
        moddep: dict[str, ModuleDependencyInfo] = {}

        # We could run modinfo once for each module but that's slow. Luckily we can pass multiple modules
        # to modinfo and it'll process them all in a single go. We get the modinfo for all modules to
        # build a map that maps the module name to both its module dependencies and its firmware
        # dependencies. Because there's more kernel modules than the max number of accepted CLI
        # arguments, we split the modules list up into chunks if needed.
        for i in range(0, len(todo), 8500):
            chunk = todo[i : i + 8500]
            moddep |= modinfo(context, kver, chunk)

        todo = []

        for name, depinfo in moddep.items():
            for d in depinfo.modules:
                if d not in nametofile and d not in builtin:
                    logging.warning(f"{d} is a dependency of {name} but is not installed, ignoring ")

            mods.add(name)
            firmware.update(depinfo.firmware)
            todo += [m for m in depinfo.modules if m not in mods]

    return set(nametofile[m] for m in mods if m in nametofile), set(firmware)


def gen_required_kernel_modules(
    context: Context,
    kver: str,
    *,
    modules_include: Sequence[str],
    modules_exclude: Sequence[str],
    firmware_include: Sequence[str],
    firmware_exclude: Sequence[str],
) -> Iterator[Path]:
    modulesd = Path("usr/lib/modules") / kver
    firmwared = Path("usr/lib/firmware")

    # There is firmware in /usr/lib/firmware that is not depended on by any modules so if any firmware was
    # installed we have to take the slow path to make sure we don't copy firmware into the initrd that is not
    # depended on by any kernel modules.
    if modules_include or modules_exclude or any((context.root / firmwared).glob("*")):
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

    # /usr/lib/firmware makes use of symbolic links so we have to make sure the symlinks and their targets
    # are all included.
    fwcopy = firmware.copy()
    firmware.clear()
    for fw in fwcopy:
        # Every path component from /usr/lib/firmware up to and including the firmware file itself might be a
        # symlink. We need to make sure we include all of them so we iterate over them and keep resolving
        # each symlink separately (and recursively) and add all of them to the list of firmware to add.
        #
        # As of the time of writing this logic, the only firmware that actually requires intermediate path
        # symlink resolution are the following:
        #
        # $ find /usr/lib/firmware -type l | grep -v "\."
        # /usr/lib/firmware/intel/sof-ace-tplg
        # /usr/lib/firmware/nvidia/ad103
        # /usr/lib/firmware/nvidia/ad104
        # /usr/lib/firmware/nvidia/ad106
        # /usr/lib/firmware/nvidia/ad107
        # /usr/lib/firmware/nvidia/ga103/gsp
        # /usr/lib/firmware/nvidia/ga104/gsp
        # /usr/lib/firmware/nvidia/ga106/gsp
        # /usr/lib/firmware/nvidia/ga107/gsp
        # /usr/lib/firmware/nvidia/gb102
        # /usr/lib/firmware/nvidia/gb203
        # /usr/lib/firmware/nvidia/gb205
        # /usr/lib/firmware/nvidia/gb206
        # /usr/lib/firmware/nvidia/gb207
        # /usr/lib/firmware/nvidia/tu104/gsp
        # /usr/lib/firmware/nvidia/tu106/gsp
        # /usr/lib/firmware/nvidia/tu117/gsp

        todo = list(reversed(fw.parts))
        current = context.root
        while todo:
            part = todo.pop()
            if part == "/":
                current = context.root
                continue
            elif part == "..":
                current = current.parent
                continue
            elif part == ".":
                continue

            current /= part
            if not current.is_symlink():
                continue

            if current.readlink().is_relative_to("/etc/alternatives"):
                target = chase(os.fspath(context.root), os.fspath(current.relative_to(context.root)))
                current.unlink()
                current.symlink_to(os.path.relpath(target, start=current.parent))

            firmware.add(current.relative_to(context.root))
            todo += list(reversed(current.readlink().parts))
            # Relative symlinks are resolved relative to the directory
            # the symlink is located in. If the symlink is absolute we'll
            # override the current path anyway so modifying it here doesn't
            # matter.
            current = current.parent

        # Finally, add the actual fully resolved path to the firmware file.
        if current.exists():
            firmware.add(current.relative_to(context.root))

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
    modules_include: Sequence[str],
    modules_exclude: Sequence[str],
    firmware_include: Sequence[str],
    firmware_exclude: Sequence[str],
) -> None:
    if not (modules_include or modules_exclude or firmware_include or firmware_exclude):
        return

    modulesd = Path("usr/lib/modules") / kver
    firmwared = Path("usr/lib/firmware")

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

    with complete_step("Applying kernel module filters"):
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


def filter_devicetrees(
    root: Path,
    kver: str,
    *,
    include: Sequence[str],
) -> list[Path]:
    if not include:
        return []

    logging.debug(f"Devicetrees include: {' '.join(include)}")

    # Search standard DTB locations
    dtb_dirs = [
        Path("usr/lib/firmware") / kver / "device-tree",
        Path(f"usr/lib/linux-image-{kver}"),
        Path("usr/lib/modules") / kver / "dtb",
    ]

    matched_dtbs = []
    globs = list(include)

    with chdir(root):
        for dtb_dir in dtb_dirs:
            all_dtbs = [p for p in dtb_dir.rglob("*.dtb") if p.is_file() or p.is_symlink()]
            logging.debug(f"Found {len(all_dtbs)} DTB files in {dtb_dir}")

            for dtb in all_dtbs:
                rel_path = os.fspath(dtb.relative_to(dtb_dir))
                if globs_match_filename(rel_path, globs):
                    logging.debug(f"Matched DTB: {rel_path} in {dtb_dir}")
                    matched_dtbs.append(dtb)

    if not matched_dtbs:
        logging.warning(f"Devicetrees patterns '{globs}' matched 0 files")
    else:
        logging.debug(f"Including {len(matched_dtbs)} devicetree files")

    return sorted(matched_dtbs)
