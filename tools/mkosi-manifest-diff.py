#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Diff two mkosi JSON manifests and produce a readable summary of package changes."""

import json
import sys


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <old-manifest> <new-manifest>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        old = json.load(f)

    with open(sys.argv[2]) as f:
        new = json.load(f)

    old_packages = {(p["name"], p["architecture"]): p["version"] for p in old.get("packages", [])}
    new_packages = {(p["name"], p["architecture"]): p["version"] for p in new.get("packages", [])}

    old_keys = set(old_packages.keys())
    new_keys = set(new_packages.keys())

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = sorted(
        key for key in old_keys & new_keys if old_packages[key] != new_packages[key]
    )

    if not added and not removed and not changed:
        print("No package changes.")
        return

    if changed:
        print("## Version Changes\n")
        print("| Package | Architecture | Old Version | New Version |")
        print("|---------|--------------|-------------|-------------|")
        for name, arch in changed:
            print(f"| {name} | {arch} | {old_packages[(name, arch)]} | {new_packages[(name, arch)]} |")
        print()

    if added:
        print("## Added Packages\n")
        print("| Package | Architecture | Version |")
        print("|---------|--------------|---------|")
        for name, arch in added:
            print(f"| {name} | {arch} | {new_packages[(name, arch)]} |")
        print()

    if removed:
        print("## Removed Packages\n")
        print("| Package | Architecture | Version |")
        print("|---------|--------------|---------|")
        for name, arch in removed:
            print(f"| {name} | {arch} | {old_packages[(name, arch)]} |")
        print()

    counts = []
    if changed:
        counts.append(f"{len(changed)} upgraded")
    if added:
        counts.append(f"{len(added)} added")
    if removed:
        counts.append(f"{len(removed)} removed")
    print(f"**Summary:** {', '.join(counts)}")


if __name__ == "__main__":
    main()