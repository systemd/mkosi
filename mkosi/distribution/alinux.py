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


def _kernel_versions_in_root(root: Path) -> list[str]:
    versions: set[str] = set()

    boot = root / "boot"
    if boot.exists():
        for p in boot.glob("vmlinuz-*"):
            if p.name.endswith(".hmac"):
                continue
            versions.add(p.name[len("vmlinuz-") :])

    modules = root / "lib/modules"
    if modules.exists():
        for p in modules.iterdir():
            if p.is_dir() and (p / "vmlinuz").exists():
                versions.add(p.name)

    return sorted(versions)


def _ensure_grubby_bls_entries(root: Path) -> list[Path]:
    # Alinux kernel %posttrans runs `grubby --update-kernel /boot/vmlinuz-$KVER`. mkosi sets
    # KERNEL_INSTALL_BYPASS=1, so kernel-install does not create BLS entries under the
    # installroot and grubby fails with "The param ... is incorrect". Create matching
    # disposable entries first; mkosi configures the real bootloader later.
    versions = _kernel_versions_in_root(root)
    if not versions:
        return []

    entries = root / "boot/loader/entries"
    entries.mkdir(parents=True, exist_ok=True)

    created: list[Path] = []
    for kver in versions:
        path = entries / f"mkosi-grubby-{kver}.conf"
        if path.exists():
            continue

        # installroot /boot is not a mountpoint; linux /boot/vmlinuz-$KVER matches the path
        # passed to grubby in the kernel %posttrans scriptlet.
        path.write_text(
            f"title mkosi ({kver})\n"
            f"version {kver}\n"
            f"linux /boot/vmlinuz-{kver}\n"
            f"options root=mkosi\n"
        )
        created.append(path)

    return created


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

        # Make sure the real grubby is present before kernel %posttrans runs.
        if kernels and "grubby" not in others:
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

        def arguments(*pkgs: str, noscripts: bool = False) -> list[str]:
            args: list[str] = []
            if allow_downgrade and Dnf.executable(context.config) == "dnf5":
                args += ["--allow-downgrade"]
            if noscripts:
                args += ["--setopt=tsflags=noscripts"]
            args += list(pkgs)
            return args

        # Install kernel payloads without scriptlets so /boot/vmlinuz-* is present and we can
        # create matching BLS entries before the real grubby runs in %posttrans.
        Dnf.invoke(context, "install", arguments(*kernels, noscripts=True), apivfs=apivfs)

        if not _kernel_versions_in_root(context.root):
            die("No kernel image found after installing kernel packages")

        created = _ensure_grubby_bls_entries(context.root)
        try:
            # Re-run scriptlets now that BLS scaffolding exists. Always include kernel-core:
            # installing the kernel metapackage pulls it in, and that is where %posttrans lives.
            reinstall = list(dict.fromkeys([*kernels, "kernel-core"]))
            Dnf.invoke(context, "reinstall", arguments(*reinstall), apivfs=apivfs)
        finally:
            for path in created:
                path.unlink(missing_ok=True)

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
