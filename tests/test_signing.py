# SPDX-License-Identifier: LGPL-2.1-or-later


import os
import tempfile
from pathlib import Path

import pytest

from mkosi.run import find_binary, run

from . import Image, ImageConfig

pytestmark = pytest.mark.integration


def test_signing_checksums_with_sop(config: ImageConfig) -> None:
    if find_binary("sqop", root=config.tools) is None:
        pytest.skip("Needs 'sqop' binary in tools tree PATH to perform sop tests.")

    if find_binary("sqop") is None:
        pytest.skip("Needs 'sqop' binary in host system PATH to perform sop tests.")

    with tempfile.TemporaryDirectory() as path, Image(config) as image:
        tmp_path = Path(path)
        os.chown(tmp_path, image.uid, image.gid)

        signing_key = tmp_path / "signing-key.pgp"
        signing_cert = tmp_path / "signing-cert.pgp"

        # create a brand new signing key
        with open(signing_key, "wb") as o:
            run(cmdline=["sqop", "generate-key", "--signing-only", "Test"], stdout=o)

        # extract public key (certificate)
        with open(signing_key, "rb") as i, open(signing_cert, "wb") as o:
            run(cmdline=["sqop", "extract-cert"], stdin=i, stdout=o)

        image.build(
            options=["--checksum=true", "--openpgp-tool=sqop", "--sign=true", f"--key={signing_key}"]
        )

        signed_file = image.output_dir / "image.SHA256SUMS"
        signature = image.output_dir / "image.SHA256SUMS.gpg"

        with open(signed_file, "rb") as i:
            run(cmdline=["sqop", "verify", signature, signing_cert], stdin=i)


def test_signing_checksums_with_gpg(config: ImageConfig) -> None:
    with tempfile.TemporaryDirectory() as path, Image(config) as image:
        tmp_path = Path(path)
        os.chown(tmp_path, image.uid, image.gid)

        signing_key = "mkosi-test@example.org"
        signing_cert = tmp_path / "signing-cert.pgp"
        gnupghome = tmp_path / ".gnupg"

        env = dict(GNUPGHOME=str(gnupghome))

        # Creating GNUPGHOME directory and appending an *empty* common.conf
        # file stops GnuPG from spawning keyboxd which causes issues when switching
        # users. See https://stackoverflow.com/a/72278246 for details
        gnupghome.mkdir()
        os.chown(gnupghome, image.uid, image.gid)
        (gnupghome / "common.conf").touch()

        # create a brand new signing key
        run(
            cmdline=["gpg", "--quick-gen-key", "--batch", "--passphrase", "", signing_key],
            env=env,
            user=image.uid,
            group=image.gid,
        )

        # export public key (certificate)
        with open(signing_cert, "wb") as o:
            run(
                cmdline=["gpg", "--export", signing_key],
                env=env,
                stdout=o,
                user=image.uid,
                group=image.gid,
            )

        image.build(options=["--checksum=true", "--sign=true", f"--key={signing_key}"], env=env)

        signed_file = image.output_dir / "image.SHA256SUMS"
        signature = image.output_dir / "image.SHA256SUMS.gpg"

        run(cmdline=["gpg", "--verify", signature, signed_file], env=env)
