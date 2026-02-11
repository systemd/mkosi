# SPDX-License-Identifier: LGPL-2.1-or-later

import dataclasses
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from mkosi.log import die
from mkosi.run import SandboxProtocol, nosandbox, run, workdir


@dataclasses.dataclass(frozen=True)
class Partition:
    type: str
    uuid: str
    partno: int | None
    split_path: Path | None
    roothash: str | None

    @classmethod
    def from_dict(cls, dict: Mapping[str, Any]) -> "Partition":
        return cls(
            type=dict["type"],
            uuid=dict["uuid"],
            partno=int(partno) if (partno := dict.get("partno")) else None,
            # We have to translate the sandbox path to the path on the host by removing the /work prefix.
            split_path=(
                Path(p.removeprefix("/work")) if ((p := dict.get("split_path")) and p != "-") else None
            ),
            roothash=dict.get("roothash"),
        )

    GRUB_BOOT_PARTITION_UUID: Final[str] = "21686148-6449-6e6f-744e-656564454649"


def find_partitions(image: Path, *, sandbox: SandboxProtocol = nosandbox) -> list[Partition]:
    output = json.loads(
        run(
            ["systemd-repart", "--json=short", workdir(image, sandbox)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            sandbox=sandbox(options=["--ro-bind", image, workdir(image, sandbox)]),
        ).stdout
    )
    return [Partition.from_dict(d) for d in output]


def finalize_roothash(partitions: Sequence[Partition]) -> str | None:
    roothash: str | None = None
    usrhash: str | None = None

    for p in partitions:
        if (h := p.roothash) is None:
            continue

        if not (p.type.startswith("usr") or p.type.startswith("root")):
            die(f"Found roothash property on unexpected partition type {p.type}")

        # When the partition is deferred/skipped the roothash is listed as the literal 'TBD' string
        if h == "TBD":
            continue

        # When there's multiple verity enabled root or usr partitions, the first one wins.
        if p.type.startswith("usr"):
            usrhash = usrhash or h
        else:
            roothash = roothash or h

    return f"roothash={roothash}" if roothash else f"usrhash={usrhash}" if usrhash else None


def finalize_root(partitions: Sequence[Partition]) -> str | None:
    root = finalize_roothash(partitions)
    if not root:
        root = next((f"root=PARTUUID={p.uuid}" for p in partitions if p.type.startswith("root")), None)
    if not root:
        root = next((f"mount.usr=PARTUUID={p.uuid}" for p in partitions if p.type.startswith("usr")), None)

    return root
