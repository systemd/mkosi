# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable, Sequence
from pathlib import Path

from mkosi.config import Architecture
from mkosi.context import Context
from mkosi.distribution import Distribution, centos, join_mirror
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.log import die
from mkosi.versioncomp import GenericVersion


def _is_kernel_rpm(package: str) -> bool:
    return package == "kernel" or package.startswith("kernel-")


class Installer(centos.Installer, distribution=Distribution.alinux):
    @classmethod
    def pretty_name(cls) -> str:
        return "Alibaba Cloud Linux"

    @classmethod
    def default_release(cls) -> str:
        return "3"

    @classmethod
    def setup(cls, context: Context) -> None:
        if GenericVersion(cls.major_release(context.config)) != 3:
            die(f"Only {cls.pretty_name()} 3 is currently supported")

        setup_rpm(context, dbpath=cls.dbpath(context))
        Dnf.setup(context, list(cls.repositories(context)))

    @classmethod
    def install(cls, context: Context) -> None:
        cls.install_packages(context, ["filesystem", "alinux-release"], apivfs=False)

        # alinux-release only ships /etc/os-release; mkosi expects /usr/lib/os-release.
        etc_os_release = context.root / "etc/os-release"
        usr_lib_os_release = context.root / "usr/lib/os-release"
        if etc_os_release.exists() and not usr_lib_os_release.exists():
            usr_lib_os_release.parent.mkdir(parents=True, exist_ok=True)
            usr_lib_os_release.write_bytes(etc_os_release.read_bytes())

    @classmethod
    def install_packages(
        cls,
        context: Context,
        packages: Sequence[str],
        *,
        apivfs: bool = True,
        allow_downgrade: bool = False,
    ) -> None:
        kernels = [p for p in packages if _is_kernel_rpm(p)]
        others = [p for p in packages if not _is_kernel_rpm(p)]

        # Alinux kernel %posttrans runs `grubby --update-kernel` after kernel-install. Under an
        # installroot there are no BLS entries for /boot/vmlinuz-*, so grubby exits 1 and newer
        # dnf5/rpm abort the transaction. mkosi configures the bootloader itself later, so install
        # grubby first, temporarily stub it out, install the kernel packages, then restore it.
        if kernels:
            if "grubby" not in others:
                others = [*others, "grubby"]

        if others:
            super().install_packages(
                context,
                others,
                apivfs=apivfs,
                allow_downgrade=allow_downgrade,
            )

        if not kernels:
            return

        stubs = [
            context.root / "usr/sbin/grubby",
            context.root / "usr/libexec/grubby/grubby-bls",
        ]
        saved: dict[Path, bytes] = {}
        for path in stubs:
            if path.exists():
                saved[path] = path.read_bytes()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\nexit 0\n")
            path.chmod(0o755)

        try:
            super().install_packages(
                context,
                kernels,
                apivfs=apivfs,
                allow_downgrade=allow_downgrade,
            )
        finally:
            for path, content in saved.items():
                path.write_bytes(content)
                path.chmod(0o755)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64: "x86_64",
            Architecture.arm64:  "aarch64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {arch} is not supported by {cls.pretty_name()}")

        return a

    @classmethod
    def _default_mirror(cls) -> str:
        return "https://mirrors.aliyun.com/alinux"

    @classmethod
    def _epel_mirror(cls, context: Context) -> str:
        if epel := context.config.finalize_environment().get("EPEL_MIRROR"):
            return epel

        # Alinux mirrors keep EPEL as a sibling of the alinux tree (…/alinux → …/epel).
        mirror = context.config.mirror or cls._default_mirror()
        return join_mirror(mirror, "..").rstrip("/")

    @classmethod
    def gpgurls(cls, context: Context) -> tuple[str, ...]:
        major = cls.major_release(context.config)
        mirror = context.config.mirror or cls._default_mirror()
        keyurl = join_mirror(mirror, f"{major}/RPM-GPG-KEY-ALINUX-{major}")

        # Prefer a locally installed key. Do not fall back to RPM-GPG-KEY-ANOLIS from
        # distribution-gpg-keys: that file contains multiple keys and dnf may import the
        # Anolis OS key instead of the Alibaba Cloud Linux package-signing key.
        key = find_rpm_gpgkey(context, f"RPM-GPG-KEY-ALINUX-{major}", required=False)
        return (key or keyurl,)

    @classmethod
    def repository_variants(
        cls,
        context: Context,
        gpgurls: tuple[str, ...],
        repo: str,
    ) -> list[RpmRepository]:
        if context.config.snapshot:
            die(f"Snapshot= is not supported for {cls.pretty_name()}")

        relpath = f"$releasever/{repo.lower()}/$basearch"
        mirror = context.config.mirror or cls._default_mirror()
        url = f"baseurl={join_mirror(mirror, relpath)}"

        return [RpmRepository(repo, url, gpgurls, repo_gpgcheck=False)]

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            gpgurls = cls.gpgurls(context)
            yield RpmRepository(
                "local",
                f"baseurl={context.config.local_mirror}",
                gpgurls,
                repo_gpgcheck=False,
            )
            return

        gpgurls = cls.gpgurls(context)

        yield from cls.repository_variants(context, gpgurls, "os")
        yield from cls.repository_variants(context, gpgurls, "updates")
        yield from cls.repository_variants(context, gpgurls, "plus")
        yield from cls.repository_variants(context, gpgurls, "module")
        yield from cls.repository_variants(context, gpgurls, "powertools")

        epel_mirror = cls._epel_mirror(context)
        epel_gpgurls = (
            find_rpm_gpgkey(
                context,
                "RPM-GPG-KEY-EPEL-8",
                join_mirror(epel_mirror, "epel/RPM-GPG-KEY-EPEL-8"),
            ),
        )
        yield RpmRepository(
            "epel",
            f"baseurl={join_mirror(epel_mirror, 'epel/8/Everything/$basearch')}",
            epel_gpgurls,
            enabled=False,
            repo_gpgcheck=False,
        )

        yield from cls.sig_repositories(context)

    @classmethod
    def sig_repositories(cls, context: Context) -> list[RpmRepository]:
        return []
