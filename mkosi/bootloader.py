import itertools
import logging
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Optional

from mkosi.config import (
    BiosBootloader,
    Bootloader,
    Config,
    ConfigFeature,
    KeySourceType,
    OutputFormat,
    SecureBootSignTool,
    ShimBootloader,
)
from mkosi.context import Context
from mkosi.distributions import Distribution
from mkosi.log import complete_step, die, log_step
from mkosi.partition import Partition
from mkosi.qemu import KernelType
from mkosi.run import run, workdir
from mkosi.sandbox import umask
from mkosi.types import PathString
from mkosi.util import flatten
from mkosi.versioncomp import GenericVersion


def want_efi(config: Config) -> bool:
    # Do we want to make the image bootable on EFI firmware?
    # Note that this returns True also in the case where autodetection might later cause the system to not be
    # made bootable on EFI firmware after the filesystem has been populated.

    if config.output_format in (OutputFormat.uki, OutputFormat.esp):
        return True

    if config.bootable == ConfigFeature.disabled:
        return False

    if config.bootloader == Bootloader.none:
        return False

    if (
        config.output_format == OutputFormat.cpio
        or config.output_format.is_extension_image()
        or config.overlay
    ) and config.bootable == ConfigFeature.auto:
        return False

    if config.architecture.to_efi() is None:
        if config.bootable == ConfigFeature.enabled:
            die(f"Cannot make image bootable on UEFI on {config.architecture} architecture")

        return False

    return True


def want_grub_efi(context: Context) -> bool:
    if not want_efi(context.config):
        return False

    if context.config.bootloader != Bootloader.grub:
        return False

    if context.config.shim_bootloader != ShimBootloader.signed:
        have = find_grub_directory(context, target="x86_64-efi") is not None
        if not have and context.config.bootable == ConfigFeature.enabled:
            die("An EFI bootable image with grub was requested but grub for EFI is not installed")

    return True


def want_grub_bios(context: Context, partitions: Sequence[Partition] = ()) -> bool:
    if context.config.bootable == ConfigFeature.disabled:
        return False

    if context.config.output_format != OutputFormat.disk:
        return False

    if context.config.bios_bootloader != BiosBootloader.grub:
        return False

    if context.config.overlay:
        return False

    have = find_grub_directory(context, target="i386-pc") is not None
    if not have and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but grub for BIOS is not installed")

    bios = any(p.type == Partition.GRUB_BOOT_PARTITION_UUID for p in partitions)
    if partitions and not bios and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no BIOS Boot Partition was configured")

    esp = any(p.type == "esp" for p in partitions)
    if partitions and not esp and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no ESP partition was configured")

    root = any(p.type.startswith("root") or p.type.startswith("usr") for p in partitions)
    if partitions and not root and context.config.bootable == ConfigFeature.enabled:
        die("A BIOS bootable image with grub was requested but no root or usr partition was configured")

    installed = True

    for binary in ("mkimage", "bios-setup"):
        if find_grub_binary(context.config, binary):
            continue

        if context.config.bootable == ConfigFeature.enabled:
            die(f"A BIOS bootable image with grub was requested but {binary} was not found")

        installed = False

    return (have and bios and esp and root and installed) if partitions else have


def find_grub_directory(context: Context, *, target: str) -> Optional[Path]:
    for d in ("usr/lib/grub", "usr/share/grub2"):
        if (p := context.root / d / target).exists() and any(p.iterdir()):
            return p

    return None


def find_grub_binary(config: Config, binary: str) -> Optional[Path]:
    assert "grub" not in binary

    # Debian has a bespoke setup where if only grub-pc-bin is installed, grub-bios-setup is installed in
    # /usr/lib/i386-pc instead of in /usr/bin. Let's take that into account and look for binaries in
    # /usr/lib/grub/i386-pc as well.
    return config.find_binary(f"grub-{binary}", f"grub2-{binary}", f"/usr/lib/grub/i386-pc/grub-{binary}")


def prepare_grub_config(context: Context) -> Optional[Path]:
    config = context.root / "efi" / context.config.distribution.grub_prefix() / "grub.cfg"
    with umask(~0o700):
        config.parent.mkdir(exist_ok=True)

    # For some unknown reason, if we don't set the timeout to zero, grub never leaves its menu, so we default
    # to a zero timeout, but only if the config file hasn't been provided by the user.
    if not config.exists():
        with umask(~0o600), config.open("w") as f:
            f.write("set timeout=0\n")

    if want_grub_efi(context):
        # Signed EFI grub shipped by distributions reads its configuration from /EFI/<distribution>/grub.cfg
        # (except in openSUSE) in the ESP so let's put a shim there to redirect to the actual configuration
        # file.
        if context.config.distribution == Distribution.opensuse:
            earlyconfig = context.root / "efi/EFI/BOOT/grub.cfg"
        else:
            earlyconfig = context.root / "efi/EFI" / context.config.distribution.name / "grub.cfg"

        with umask(~0o700):
            earlyconfig.parent.mkdir(parents=True, exist_ok=True)

        # Read the actual config file from the root of the ESP.
        earlyconfig.write_text(f"configfile /{context.config.distribution.grub_prefix()}/grub.cfg\n")

    return config


def grub_mkimage(
    context: Context,
    *,
    target: str,
    modules: Sequence[str] = (),
    output: Optional[Path] = None,
    sbat: Optional[Path] = None,
) -> None:
    mkimage = find_grub_binary(context.config, "mkimage")
    assert mkimage

    directory = find_grub_directory(context, target=target)
    assert directory

    with (
        complete_step(f"Generating grub image for {target}"),
        tempfile.NamedTemporaryFile("w", prefix="grub-early-config") as earlyconfig,
    ):
        earlyconfig.write(
            textwrap.dedent(
                f"""\
                search --no-floppy --set=root --file /{context.config.distribution.grub_prefix()}/grub.cfg
                set prefix=($root)/{context.config.distribution.grub_prefix()}
                """
            )
        )

        earlyconfig.flush()

        run(
            [
                mkimage,
                "--directory", "/grub",
                "--config", earlyconfig.name,
                "--prefix", f"/{context.config.distribution.grub_prefix()}",
                "--output", output or ("/grub/core.img"),
                "--format", target,
                *(["--sbat", str(sbat)] if sbat else []),
                *(["--disable-shim-lock"] if context.config.shim_bootloader == ShimBootloader.none else []),
                "cat",
                "cmp",
                "div",
                "echo",
                "fat",
                "hello",
                "help",
                "keylayouts",
                "linux",
                "loadenv",
                "ls",
                "normal",
                "part_gpt",
                "read",
                "reboot",
                "search_fs_file",
                "search",
                "sleep",
                "test",
                "tr",
                "true",
                *modules,
            ],
            sandbox=context.sandbox(
                binary=mkimage,
                options=[
                    "--bind", directory, "/grub",
                    "--ro-bind", earlyconfig.name, earlyconfig.name,
                    *(["--bind", str(output.parent), str(output.parent)] if output else []),
                    *(["--ro-bind", str(sbat), str(sbat)] if sbat else []),
                ],
            ),
        )  # fmt: skip


def find_signed_grub_image(context: Context) -> Optional[Path]:
    arch = context.config.architecture.to_efi()

    patterns = [
        f"usr/lib/grub/*-signed/grub{arch}.efi.signed",  # Debian/Ubuntu
        f"boot/efi/EFI/*/grub{arch}.efi",  # Fedora/CentOS
        "usr/share/efi/*/grub.efi",  # openSUSE
    ]

    for p in flatten(context.root.glob(pattern) for pattern in patterns):
        if p.is_symlink() and p.readlink().is_absolute():
            logging.warning(f"Ignoring signed grub EFI binary which is an absolute path to {p.readlink()}")
            continue

        return p

    return None


def python_binary(config: Config, *, binary: Optional[PathString]) -> PathString:
    tools = (
        not binary
        or not (path := config.find_binary(binary))
        or not any(path.is_relative_to(d) for d in config.extra_search_paths)
    )

    # If there's no tools tree, prefer the interpreter from MKOSI_INTERPRETER. If there is a tools
    # tree, just use the default python3 interpreter.
    exe = Path(sys.executable)
    return "python3" if (tools and config.tools_tree) or not exe.is_relative_to("/usr") else exe


def extract_pe_section(context: Context, binary: Path, section: str, output: Path) -> Path:
    # When using a tools tree, we want to use the pefile module from the tools tree instead of requiring that
    # python-pefile is installed on the host. So we execute python as a subprocess to make sure we load
    # pefile from the tools tree if one is used.

    # TODO: Use ignore_padding=True instead of length once we can depend on a newer pefile.
    # TODO: Drop KeyError logic once we drop support for Ubuntu Jammy and sdmagic will always be available.
    pefile = textwrap.dedent(
        f"""\
        import pefile
        import sys
        from pathlib import Path
        pe = pefile.PE("{binary}", fast_load=True)
        section = {{s.Name.decode().strip("\\0"): s for s in pe.sections}}.get("{section}")
        if not section:
            sys.exit(67)
        sys.stdout.buffer.write(section.get_data(length=section.Misc_VirtualSize))
        """
    )

    with open(output, "wb") as f:
        result = run(
            [python_binary(context.config, binary=None)],
            input=pefile,
            stdout=f,
            sandbox=context.sandbox(
                binary=python_binary(context.config, binary=None),
                options=["--ro-bind", binary, binary],
            ),
            success_exit_status=(0, 67),
        )
        if result.returncode == 67:
            raise KeyError(f"{section} section not found in {binary}")

    return output


def install_grub(context: Context) -> None:
    if not want_grub_bios(context) and not want_grub_efi(context):
        return

    if want_grub_bios(context):
        grub_mkimage(context, target="i386-pc", modules=("biosdisk",))

    if want_grub_efi(context):
        if context.config.shim_bootloader != ShimBootloader.none:
            output = context.root / shim_second_stage_binary(context)
        else:
            output = context.root / efi_boot_binary(context)

        with umask(~0o700):
            output.parent.mkdir(parents=True, exist_ok=True)

        if context.config.shim_bootloader == ShimBootloader.signed:
            if not (signed := find_signed_grub_image(context)):
                if context.config.bootable == ConfigFeature.enabled:
                    die("Couldn't find a signed grub EFI binary installed in the image")

                return

            rel = output.relative_to(context.root)
            log_step(f"Installing signed grub EFI binary from /{signed.relative_to(context.root)} to /{rel}")
            shutil.copy2(signed, output)
        else:
            if context.config.secure_boot and context.config.shim_bootloader != ShimBootloader.none:
                if not (signed := find_signed_grub_image(context)):
                    die("Couldn't find a signed grub EFI binary installed in the image to extract SBAT from")

                sbat = extract_pe_section(context, signed, ".sbat", context.workspace / "sbat")
            else:
                sbat = None

            grub_mkimage(context, target="x86_64-efi", output=output, modules=("chain",), sbat=sbat)
            if context.config.secure_boot:
                sign_efi_binary(context, output, output)

    dst = context.root / "efi" / context.config.distribution.grub_prefix() / "fonts"
    with umask(~0o700):
        dst.mkdir(parents=True, exist_ok=True)

    for d in ("grub", "grub2"):
        unicode = context.root / "usr/share" / d / "unicode.pf2"
        if unicode.exists():
            shutil.copy2(unicode, dst)


def grub_bios_setup(context: Context, partitions: Sequence[Partition]) -> None:
    if not want_grub_bios(context, partitions):
        return

    setup = find_grub_binary(context.config, "bios-setup")
    assert setup

    directory = find_grub_directory(context, target="i386-pc")
    assert directory

    with (
        complete_step("Installing grub boot loader for BIOS…"),
        tempfile.NamedTemporaryFile(mode="w") as mountinfo,
    ):
        # grub-bios-setup insists on being able to open the root device that --directory is located on, which
        # needs root privileges. However, it only uses the root device when it is unable to embed itself in
        # the bios boot partition. To make installation work unprivileged, we trick grub to think that the
        # root device is our image by mounting over its /proc/self/mountinfo file (where it gets its
        # information from) with our own file correlating the root directory to our image file.
        mountinfo.write(f"1 0 1:1 / / - fat {context.staging / context.config.output_with_format}\n")
        mountinfo.flush()

        run(
            [
                setup,
                "--directory", "/grub",
                context.staging / context.config.output_with_format,
            ],
            sandbox=context.sandbox(
                binary=setup,
                options=[
                    "--bind", directory, "/grub",
                    "--bind", context.staging, context.staging,
                    "--bind", mountinfo.name, "/proc/self/mountinfo",
                ],
            ),
        )  # fmt: skip


def efi_boot_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    assert arch
    return Path(f"efi/EFI/BOOT/BOOT{arch.upper()}.EFI")


def shim_second_stage_binary(context: Context) -> Path:
    arch = context.config.architecture.to_efi()
    assert arch
    if context.config.distribution == Distribution.opensuse:
        return Path("efi/EFI/BOOT/grub.EFI")
    else:
        return Path(f"efi/EFI/BOOT/grub{arch}.EFI")


def certificate_common_name(context: Context, certificate: Path) -> str:
    output = run(
        [
            "openssl",
            "x509",
            "-noout",
            "-subject",
            "-nameopt", "multiline",
            "-in", certificate,
        ],
        stdout=subprocess.PIPE,
        sandbox=context.sandbox(binary="openssl", options=["--ro-bind", certificate, certificate]),
    ).stdout  # fmt: skip

    for line in output.splitlines():
        if not line.strip().startswith("commonName"):
            continue

        _, sep, value = line.partition("=")
        if not sep:
            die("Missing '=' delimiter in openssl output")

        return value.strip()

    die(f"Certificate {certificate} is missing Common Name")


def pesign_prepare(context: Context) -> None:
    assert context.config.secure_boot_key
    assert context.config.secure_boot_certificate

    if (context.workspace / "pesign").exists():
        return

    (context.workspace / "pesign").mkdir()

    # pesign takes a certificate directory and a certificate common name as input arguments, so we have
    # to transform our input key and cert into that format. Adapted from
    # https://www.mankier.com/1/pesign#Examples-Signing_with_the_certificate_and_private_key_in_individual_files
    with open(context.workspace / "secure-boot.p12", "wb") as f:
        run(
            [
                "openssl",
                "pkcs12",
                "-export",
                # Arcane incantation to create a pkcs12 certificate without a password.
                "-keypbe", "NONE",
                "-certpbe", "NONE",
                "-nomaciter",
                "-passout", "pass:",
                "-inkey", context.config.secure_boot_key,
                "-in", context.config.secure_boot_certificate,
            ],
            stdout=f,
            sandbox=context.sandbox(
                binary="openssl",
                options=[
                    "--ro-bind", context.config.secure_boot_key, context.config.secure_boot_key,
                    "--ro-bind", context.config.secure_boot_certificate, context.config.secure_boot_certificate,  # noqa
                ],
            ),
        )  # fmt: skip

    (context.workspace / "pesign").mkdir(exist_ok=True)

    run(
        [
            "pk12util",
            "-K", "",
            "-W", "",
            "-i", context.workspace / "secure-boot.p12",
            "-d", context.workspace / "pesign",
        ],
        sandbox=context.sandbox(
            binary="pk12util",
            options=[
                "--ro-bind", context.workspace / "secure-boot.p12", context.workspace / "secure-boot.p12",
                "--ro-bind", context.workspace / "pesign", context.workspace / "pesign",
            ],
        ),
    )  # fmt: skip


def sign_efi_binary(context: Context, input: Path, output: Path) -> Path:
    assert context.config.secure_boot_key
    assert context.config.secure_boot_certificate

    if (
        context.config.secure_boot_sign_tool == SecureBootSignTool.sbsign
        or context.config.secure_boot_sign_tool == SecureBootSignTool.auto
        and context.config.find_binary("sbsign") is not None
    ):
        cmd: list[PathString] = [
            "sbsign",
            "--cert", workdir(context.config.secure_boot_certificate),
            "--output", workdir(output),
        ]  # fmt: skip
        options: list[PathString] = [
            "--ro-bind", context.config.secure_boot_certificate, workdir(context.config.secure_boot_certificate),  # noqa
            "--ro-bind", input, workdir(input),
            "--bind", output.parent, workdir(output.parent),
        ]  # fmt: skip
        if context.config.secure_boot_key_source.type == KeySourceType.engine:
            cmd += ["--engine", context.config.secure_boot_key_source.source]
            options += ["--bind-try", "/run/pcscd", "/run/pcscd"]
        if context.config.secure_boot_key.exists():
            cmd += ["--key", workdir(context.config.secure_boot_key)]
            options += ["--ro-bind", context.config.secure_boot_key, workdir(context.config.secure_boot_key)]
        else:
            cmd += ["--key", context.config.secure_boot_key]
        cmd += [workdir(input)]
        run(
            cmd,
            sandbox=context.sandbox(
                binary="sbsign",
                options=options,
                devices=context.config.secure_boot_key_source.type != KeySourceType.file,
            ),
        )
    elif (
        context.config.secure_boot_sign_tool == SecureBootSignTool.pesign
        or context.config.secure_boot_sign_tool == SecureBootSignTool.auto
        and context.config.find_binary("pesign") is not None
    ):
        pesign_prepare(context)
        run(
            [
                "pesign",
                "--certdir", workdir(context.workspace / "pesign"),
                "--certificate", certificate_common_name(context, context.config.secure_boot_certificate),
                "--sign",
                "--force",
                "--in", workdir(input),
                "--out", workdir(output),
            ],
            sandbox=context.sandbox(
                binary="pesign",
                options=[
                    "--ro-bind", context.workspace / "pesign", workdir(context.workspace / "pesign"),
                    "--ro-bind", input, workdir(input),
                    "--bind", output.parent, workdir(output),
                ]
            ),
        )  # fmt: skip
    else:
        die("One of sbsign or pesign is required to use SecureBoot=")

    return output


def find_and_install_shim_binary(
    context: Context,
    name: str,
    signed: Sequence[str],
    unsigned: Sequence[str],
    output: Path,
) -> None:
    if context.config.shim_bootloader == ShimBootloader.signed:
        for pattern in signed:
            for p in context.root.glob(pattern):
                if p.is_symlink() and p.readlink().is_absolute():
                    logging.warning(
                        f"Ignoring signed {name} EFI binary which is an absolute path to {p.readlink()}"
                    )
                    continue

                rel = p.relative_to(context.root)
                if (context.root / output).is_dir():
                    output /= rel.name

                log_step(f"Installing signed {name} EFI binary from /{rel} to /{output}")
                shutil.copy2(p, context.root / output)
                return

        if context.config.bootable == ConfigFeature.enabled:
            die(f"Couldn't find signed {name} EFI binary installed in the image")
    else:
        for pattern in unsigned:
            for p in context.root.glob(pattern):
                if p.is_symlink() and p.readlink().is_absolute():
                    logging.warning(
                        f"Ignoring unsigned {name} EFI binary which is an absolute path to {p.readlink()}"
                    )
                    continue

                rel = p.relative_to(context.root)
                if (context.root / output).is_dir():
                    output /= rel.name

                if context.config.secure_boot:
                    log_step(f"Signing and installing unsigned {name} EFI binary from /{rel} to /{output}")
                    sign_efi_binary(context, p, context.root / output)
                else:
                    log_step(f"Installing unsigned {name} EFI binary /{rel} to /{output}")
                    shutil.copy2(p, context.root / output)

                return

        if context.config.bootable == ConfigFeature.enabled:
            die(f"Couldn't find unsigned {name} EFI binary installed in the image")


def gen_kernel_images(context: Context) -> Iterator[tuple[str, Path]]:
    if not (context.root / "usr/lib/modules").exists():
        return

    for kver in sorted(
        (k for k in (context.root / "usr/lib/modules").iterdir() if k.is_dir()),
        key=lambda k: GenericVersion(k.name),
        reverse=True,
    ):
        # Make sure we look for anything that remotely resembles vmlinuz, as the arch specific install
        # scripts in the kernel source tree sometimes do weird stuff. But let's make sure we're not returning
        # UKIs as the UKI on Fedora is named vmlinuz-virt.efi. Also look for uncompressed images (vmlinux) as
        # some architectures ship those. Prefer vmlinuz if both are present.
        for kimg in kver.glob("vmlinuz*"):
            if KernelType.identify(context.config, kimg) != KernelType.uki:
                yield kver.name, kimg
                break
        else:
            for kimg in kver.glob("vmlinux*"):
                if KernelType.identify(context.config, kimg) != KernelType.uki:
                    yield kver.name, kimg
                    break


def install_systemd_boot(context: Context) -> None:
    if not want_efi(context.config):
        return

    if context.config.bootloader != Bootloader.systemd_boot:
        return

    if not any(gen_kernel_images(context)) and context.config.bootable == ConfigFeature.auto:
        return

    if not context.config.find_binary("bootctl"):
        if context.config.bootable == ConfigFeature.enabled:
            die("An EFI bootable image with systemd-boot was requested but bootctl was not found")
        return

    directory = context.root / "usr/lib/systemd/boot/efi"
    signed = context.config.shim_bootloader == ShimBootloader.signed
    if not directory.glob("*.efi.signed" if signed else "*.efi"):
        if context.config.bootable == ConfigFeature.enabled:
            die(
                f"An EFI bootable image with systemd-boot was requested but a {'signed ' if signed else ''}"
                f"systemd-boot binary was not found at {directory.relative_to(context.root)}"
            )
        return

    if context.config.secure_boot and not signed:
        with complete_step("Signing systemd-boot binaries…"):
            for input in itertools.chain(directory.glob("*.efi"), directory.glob("*.EFI")):
                output = directory / f"{input}.signed"
                sign_efi_binary(context, input, output)

    with complete_step("Installing systemd-boot…"):
        run(
            ["bootctl", "install", "--root=/buildroot", "--all-architectures", "--no-variables"],
            env={"SYSTEMD_ESP_PATH": "/efi", "SYSTEMD_XBOOTLDR_PATH": "/boot"},
            sandbox=context.sandbox(binary="bootctl", options=["--bind", context.root, "/buildroot"]),
        )
        # TODO: Use --random-seed=no when we can depend on systemd 256.
        Path(context.root / "efi/loader/random-seed").unlink(missing_ok=True)

        if context.config.shim_bootloader != ShimBootloader.none:
            shutil.copy2(
                context.root / f"efi/EFI/systemd/systemd-boot{context.config.architecture.to_efi()}.efi",
                context.root / shim_second_stage_binary(context),
            )

    if context.config.secure_boot and context.config.secure_boot_auto_enroll:
        assert context.config.secure_boot_key
        assert context.config.secure_boot_certificate

        with complete_step("Setting up secure boot auto-enrollment…"):
            keys = context.root / "efi/loader/keys/auto"
            with umask(~0o700):
                keys.mkdir(parents=True, exist_ok=True)

            # sbsiglist expects a DER certificate.
            with umask(~0o600):
                run(
                    [
                        "openssl",
                        "x509",
                        "-outform", "DER",
                        "-in", workdir(context.config.secure_boot_certificate),
                        "-out", workdir(context.workspace / "mkosi.der"),
                    ],
                    sandbox=context.sandbox(
                        binary="openssl",
                        options=[
                            "--ro-bind",
                            context.config.secure_boot_certificate,
                            workdir(context.config.secure_boot_certificate),
                            "--bind", context.workspace, workdir(context.workspace),
                        ],
                    ),
                )  # fmt: skip

            with umask(~0o600):
                run(
                    [
                        "sbsiglist",
                        "--owner", str(uuid.uuid4()),
                        "--type", "x509",
                        "--output", workdir(context.workspace / "mkosi.esl"),
                        workdir(context.workspace / "mkosi.der"),
                    ],
                    sandbox=context.sandbox(
                        binary="sbsiglist",
                        options=[
                            "--bind", context.workspace, workdir(context.workspace),
                            "--ro-bind", context.workspace / "mkosi.der", workdir(context.workspace / "mkosi.der"),  # noqa
                        ]
                    ),
                )  # fmt: skip

            # We reuse the key for all secure boot databases to keep things simple.
            for db in ["PK", "KEK", "db"]:
                with umask(~0o600):
                    cmd: list[PathString] = [
                        "sbvarsign",
                        "--attr",
                            "NON_VOLATILE,BOOTSERVICE_ACCESS,RUNTIME_ACCESS,TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
                        "--cert", workdir(context.config.secure_boot_certificate),
                        "--output", workdir(keys / f"{db}.auth"),
                    ]  # fmt: skip
                    options: list[PathString] = [
                        "--ro-bind",
                        context.config.secure_boot_certificate,
                        workdir(context.config.secure_boot_certificate),
                        "--ro-bind", context.workspace / "mkosi.esl", workdir(context.workspace / "mkosi.esl"),  # noqa
                        "--bind", keys, workdir(keys),
                    ]  # fmt: skip
                    if context.config.secure_boot_key_source.type == KeySourceType.engine:
                        cmd += ["--engine", context.config.secure_boot_key_source.source]
                        options += ["--bind-try", "/run/pcscd", "/run/pcscd"]
                    if context.config.secure_boot_key.exists():
                        cmd += ["--key", workdir(context.config.secure_boot_key)]
                        options += [
                            "--ro-bind", context.config.secure_boot_key, workdir(context.config.secure_boot_key),  # noqa
                        ]  # fmt: skip
                    else:
                        cmd += ["--key", context.config.secure_boot_key]
                    cmd += [db, workdir(context.workspace / "mkosi.esl")]
                    run(
                        cmd,
                        sandbox=context.sandbox(
                            binary="sbvarsign",
                            options=options,
                            devices=context.config.secure_boot_key_source.type != KeySourceType.file,
                        ),
                    )


def install_shim(context: Context) -> None:
    if not want_efi(context.config):
        return

    if context.config.shim_bootloader == ShimBootloader.none:
        return

    if not any(gen_kernel_images(context)) and context.config.bootable == ConfigFeature.auto:
        return

    dst = efi_boot_binary(context)
    with umask(~0o700):
        (context.root / dst).parent.mkdir(parents=True, exist_ok=True)

    arch = context.config.architecture.to_efi()

    signed = [
        f"usr/lib/shim/shim{arch}.efi.signed.latest",  # Ubuntu
        f"usr/lib/shim/shim{arch}.efi.signed",  # Debian
        f"boot/efi/EFI/*/shim{arch}.efi",  # Fedora/CentOS
        "usr/share/efi/*/shim.efi",  # openSUSE
    ]

    unsigned = [
        f"usr/lib/shim/shim{arch}.efi",  # Debian/Ubuntu
        f"usr/share/shim/*/*/shim{arch}.efi",  # Fedora/CentOS
        f"usr/share/shim/shim{arch}.efi",  # Arch
    ]

    find_and_install_shim_binary(context, "shim", signed, unsigned, dst)

    signed = [
        f"usr/lib/shim/mm{arch}.efi.signed",  # Debian
        f"usr/lib/shim/mm{arch}.efi",  # Ubuntu
        f"boot/efi/EFI/*/mm{arch}.efi",  # Fedora/CentOS
        "usr/share/efi/*/MokManager.efi",  # openSUSE
    ]

    unsigned = [
        f"usr/lib/shim/mm{arch}.efi",  # Debian/Ubuntu
        f"usr/share/shim/*/*/mm{arch}.efi",  # Fedora/CentOS
        f"usr/share/shim/mm{arch}.efi",  # Arch
    ]

    find_and_install_shim_binary(context, "mok", signed, unsigned, dst.parent)
