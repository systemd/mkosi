#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Fetch the latest snapshot for a distribution and update the mkosi config."""

import argparse
import configparser
import shlex
import subprocess
import sys

from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--distribution", "-d", required=True)
    p.add_argument("--commit", "-c", action="store_true", default=False)

    return p.parse_args()


def find_config(distribution: str) -> Path:
    for p in (
        Path(f"mkosi.conf.d/{distribution}.conf"),
        Path(f"mkosi.conf.d/{distribution}/mkosi.conf"),
    ):
        if p.exists():
            return p

    print(f"No config file found for {distribution}", file=sys.stderr)
    sys.exit(1)


def read_release(path: Path) -> str | None:
    config = configparser.ConfigParser()
    # Preserve case of keys.
    config.optionxform = str  # type: ignore[assignment]
    config.read(path)

    return config.get("Distribution", "Release", fallback=None)


def update_snapshot(path: Path, snapshot: str) -> bool:
    lines = path.read_text().splitlines()

    # Check if there's already a Snapshot= line we can replace.
    found = False
    new = []
    for line in lines:
        if line.startswith("Snapshot="):
            if line == f"Snapshot={snapshot}":
                # Already up to date.
                return False
            new.append(f"Snapshot={snapshot}")
            found = True
        else:
            new.append(line)

    if not found:
        # Add Snapshot= after the last key in the [Distribution] section.
        result = []
        added = False
        in_distribution = False
        for i, line in enumerate(new):
            result.append(line)
            if line.strip() == "[Distribution]":
                in_distribution = True
                continue
            if in_distribution:
                # Check if the next line starts a new section or if we're at the last line of the section.
                next_is_end = (i + 1 >= len(new)) or new[i + 1].startswith("[")
                is_blank = line.strip() == ""
                if next_is_end and not is_blank:
                    result.append(f"Snapshot={snapshot}")
                    added = True
                    in_distribution = False
                elif next_is_end and is_blank:
                    # Insert before the blank line.
                    result.pop()
                    result.append(f"Snapshot={snapshot}")
                    result.append(line)
                    added = True
                    in_distribution = False

        if not added:
            # No [Distribution] section exists; add one.
            result = new + ["", "[Distribution]", f"Snapshot={snapshot}"]

        new = result

    path.write_text("\n".join(new) + "\n")
    return True


def commit(distribution: str, release: str | None, path: Path, snapshot: str) -> None:
    if release:
        msg = f"mkosi: Update {distribution} {release} snapshot to {snapshot}"
    else:
        msg = f"mkosi: Update {distribution} snapshot to {snapshot}"

    add_cmd = ["git", "add", str(path)]
    print(f"+ {shlex.join(add_cmd)}")
    subprocess.run(add_cmd, check=True)

    commit_cmd = ["git", "commit", "-m", msg]
    print(f"+ {shlex.join(commit_cmd)}")
    subprocess.run(commit_cmd, check=True)


def main() -> None:
    args = parse_args()

    path = find_config(args.distribution)
    release = read_release(path)

    cmd = [
        "mkosi",
        "-d", args.distribution,
        "latest-snapshot",
    ]
    print(f"+ {shlex.join(cmd)}")
    snapshot = subprocess.check_output(cmd, text=True).strip()

    print(f"Latest snapshot for {args.distribution}: {snapshot}")

    if not update_snapshot(path, snapshot):
        print("Snapshot already up to date, nothing to do.")
        return

    print(f"Updated {path} with Snapshot={snapshot}")

    if args.commit:
        commit(args.distribution, release, path, snapshot)


if __name__ == "__main__":
    main()
