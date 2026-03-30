# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
from pathlib import Path

from mkosi.config import Args, Config
from mkosi.run import run


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
        result: list[str] = []
        added = False
        in_distribution = False
        for i, line in enumerate(new):
            result.append(line)
            if line.strip() == "[Distribution]":
                in_distribution = True
                continue
            if in_distribution:
                if line.startswith("["):
                    result.pop()
                    result.append(f"Snapshot={snapshot}")
                    result.append(line)
                    added = True
                    in_distribution = False
                    continue

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


def run_latest_snapshot(args: Args, config: Config) -> None:
    p = argparse.ArgumentParser(
        prog="mkosi latest-snapshot",
        description="Fetch the latest snapshot for a distribution and optionally update a config file.",
    )
    p.add_argument("--update", metavar="PATH", type=Path, help="path to the config file to update")
    p.add_argument("--commit", "-c", action="store_true", default=False, help="commit the change with git")
    latestargs = p.parse_args(args.cmdline)

    snapshot = config.distribution.installer.latest_snapshot(config)

    if not latestargs.update:
        print(snapshot)
        return

    print(f"Latest snapshot for {config.distribution}: {snapshot}")

    if not update_snapshot(latestargs.update, snapshot):
        print("Snapshot already up to date, nothing to do.")
        return

    print(f"Updated {latestargs.update} with Snapshot={snapshot}")

    if latestargs.commit:
        msg = f"mkosi: Update {config.distribution} {config.release} snapshot to {snapshot}"

        run(["git", "add", str(latestargs.update)])
        run(["git", "commit", "-m", msg])
