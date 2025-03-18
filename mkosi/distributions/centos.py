# SPDX-License-Identifier: LGPL-2.1-or-later

from collections.abc import Iterable

from mkosi.config import Architecture, Config
from mkosi.context import Context
from mkosi.distributions import (
    Distribution,
    DistributionInstaller,
    PackageType,
    join_mirror,
)
from mkosi.installer.dnf import Dnf
from mkosi.installer.rpm import RpmRepository, find_rpm_gpgkey, setup_rpm
from mkosi.log import die
from mkosi.versioncomp import GenericVersion

CENTOS_SIG_REPO_PRIORITY = 50


class Installer(DistributionInstaller):
    @classmethod
    def pretty_name(cls) -> str:
        return "CentOS"

    @classmethod
    def filesystem(cls) -> str:
        return "xfs"

    @classmethod
    def package_type(cls) -> PackageType:
        return PackageType.rpm

    @classmethod
    def default_release(cls) -> str:
        return "10"

    @classmethod
    def default_tools_tree_distribution(cls) -> Distribution:
        return Distribution.fedora

    @classmethod
    def major_release(cls, config: "Config") -> str:
        return config.release.partition(".")[0]

    @classmethod
    def package_manager(cls, config: "Config") -> type[Dnf]:
        return Dnf

    @classmethod
    def grub_prefix(cls) -> str:
        return "grub2"

    @classmethod
    def dbpath(cls, context: Context) -> str:
        # The Hyperscale SIG uses /usr/lib/sysimage/rpm in its rebuild of rpm for C9S that's shipped in the
        # hyperscale-packages-experimental repository.
        if (
            GenericVersion(context.config.release) > 9
            or "hyperscale-packages-experimental" in context.config.repositories
        ):
            return "/usr/lib/sysimage/rpm"

        return "/var/lib/rpm"

    @classmethod
    def setup(cls, context: Context) -> None:
        if GenericVersion(context.config.release) <= 8:
            die(f"{cls.pretty_name()} Stream 8 or earlier variants are not supported")

        setup_rpm(context, dbpath=cls.dbpath(context))

        Dnf.setup(context, list(cls.repositories(context)))
        (context.sandbox_tree / "etc/dnf/vars/stream").write_text(
            f"{cls.major_release(context.config)}-stream\n"
        )

    @classmethod
    def install(cls, context: Context) -> None:
        Dnf.install(context, ["basesystem"], apivfs=False)

    @classmethod
    def architecture(cls, arch: Architecture) -> str:
        a = {
            Architecture.x86_64:   "x86_64",
            Architecture.ppc64_le: "ppc64le",
            Architecture.s390x:    "s390x",
            Architecture.arm64:    "aarch64",
        }.get(arch)  # fmt: skip

        if not a:
            die(f"Architecture {a} is not supported by {cls.pretty_name()}")

        return a

    @classmethod
    def gpgurls(cls, context: Context) -> tuple[str, ...]:
        # First, start with the names of the appropriate keys in /etc/pki/rpm-gpg.

        if GenericVersion(context.config.release) == 9:
            rel = "RPM-GPG-KEY-centosofficial"
        else:
            rel = "RPM-GPG-KEY-centosofficial-SHA256"

        one = find_rpm_gpgkey(context, rel, required=False)

        # Next, follow up with the names of the appropriate keys in /usr/share/distribution-gpg-keys.

        if GenericVersion(context.config.release) == 9:
            rel = "RPM-GPG-KEY-CentOS-Official"
        else:
            rel = "RPM-GPG-KEY-CentOS-Official-SHA256"

        # The key in /usr/share/distribution-gpg-keys is only required if we didn't find one in
        # /etc/pki/rpm-gpg.
        two = find_rpm_gpgkey(context, rel, f"https://www.centos.org/keys/{rel}", required=bool(one))

        # Finally, look up the key for the SIG-Extras repository.

        sig = find_rpm_gpgkey(
            context,
            "RPM-GPG-KEY-CentOS-SIG-Extras",
            "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-SIG-Extras",
        )

        return tuple(key for key in (one, two, sig) if key is not None)

    @classmethod
    def repository_variants(cls, context: Context, repo: str) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield RpmRepository(repo, f"baseurl={context.config.local_mirror}", cls.gpgurls(context))

        elif mirror := context.config.mirror:
            if repo == "extras":
                yield RpmRepository(
                    repo.lower(),
                    f"baseurl={join_mirror(mirror, f'SIGs/$stream/{repo}/$basearch/extras-common')}",
                    cls.gpgurls(context),
                )
                yield RpmRepository(
                    f"{repo.lower()}-source",
                    f"baseurl={join_mirror(mirror, f'SIGs/$stream/{repo}/source/extras-common')}",
                    cls.gpgurls(context),
                    enabled=False,
                )

            else:
                yield RpmRepository(
                    repo.lower(),
                    f"baseurl={join_mirror(mirror, f'$stream/{repo}/$basearch/os')}",
                    cls.gpgurls(context),
                )
                yield RpmRepository(
                    f"{repo.lower()}-debuginfo",
                    f"baseurl={join_mirror(mirror, f'$stream/{repo}/$basearch/debug/tree')}",
                    cls.gpgurls(context),
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo.lower()}-source",
                    f"baseurl={join_mirror(mirror, f'$stream/{repo}/source/tree')}",
                    cls.gpgurls(context),
                    enabled=False,
                )
        else:
            url = "metalink=https://mirrors.centos.org/metalink"

            if repo == "extras":
                yield RpmRepository(
                    repo.lower(),
                    f"{url}?arch=$basearch&repo=centos-extras-sig-extras-common-$stream",
                    cls.gpgurls(context),
                )
                yield RpmRepository(
                    f"{repo.lower()}-source",
                    f"{url}?arch=source&repo=centos-extras-sig-extras-common-source-$stream",
                    cls.gpgurls(context),
                    enabled=False,
                )
            else:
                yield RpmRepository(
                    repo.lower(),
                    f"{url}?arch=$basearch&repo=centos-{repo.lower()}-$stream",
                    cls.gpgurls(context),
                )
                yield RpmRepository(
                    f"{repo.lower()}-debuginfo",
                    f"{url}?arch=$basearch&repo=centos-{repo.lower()}-debug-$stream",
                    cls.gpgurls(context),
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo.lower()}-source",
                    f"{url}?arch=source&repo=centos-{repo.lower()}-source-$stream",
                    cls.gpgurls(context),
                    enabled=False,
                )

    @classmethod
    def repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            yield from cls.repository_variants(context, "AppStream")
            return

        yield from cls.repository_variants(context, "BaseOS")
        yield from cls.repository_variants(context, "AppStream")
        yield from cls.repository_variants(context, "extras")
        yield from cls.repository_variants(context, "CRB")

        yield from cls.epel_repositories(context)
        yield from cls.sig_repositories(context)

    @classmethod
    def epel_repositories(cls, context: Context) -> Iterable[RpmRepository]:
        # Since EPEL 10, there's an associated minor release for every RHEL minor release.
        if GenericVersion(context.config.release) >= 10:
            release = context.config.release
        else:
            release = cls.major_release(context.config)

        gpgurls = (
            find_rpm_gpgkey(
                context,
                f"RPM-GPG-KEY-EPEL-{cls.major_release(context.config)}",
                f"https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-{cls.major_release(context.config)}",
            ),
        )

        if context.config.local_mirror:
            return

        if mirror := context.config.mirror:
            # epel-next does not exist anymore since EPEL 10.
            repodirs = [
                ("epel", "epel"),
                ("epel-testing", "epel/testing"),
            ]
            if GenericVersion(context.config.release) < 10:
                repodirs += [
                    ("epel-next", "epel/next"),
                    ("epel-next-testing", "epel/testing/next"),
                ]

            for repo, dir in repodirs:
                # For EPEL we make the assumption that epel is mirrored in the parent directory of the mirror
                # URL and path we were given. Since this doesn't work for all scenarios, we also allow
                # overriding the mirror via an environment variable.
                url = context.config.finalize_environment().get(
                    "EPEL_MIRROR", join_mirror(mirror, "../fedora")
                )
                yield RpmRepository(
                    repo,
                    f"baseurl={url}/{dir}/{release}/Everything/$basearch",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo}-debuginfo",
                    f"baseurl={url}/{dir}/{release}/Everything/$basearch/debug",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo}-source",
                    f"baseurl={url}/{dir}/{release}/Everything/source/tree",
                    gpgurls,
                    enabled=False,
                )
        else:
            url = "metalink=https://mirrors.fedoraproject.org/metalink?arch=$basearch"

            # epel-next does not exist anymore since EPEL 10.
            repos = ["epel"]
            if GenericVersion(context.config.release) < 10:
                repos += ["epel-next"]

            for repo in repos:
                yield RpmRepository(
                    repo,
                    f"{url}&repo={repo}-{release}",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo}-debuginfo",
                    f"{url}&repo={repo}-debug-{release}",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    f"{repo}-source",
                    f"{url}&repo={repo}-source-{release}",
                    gpgurls,
                    enabled=False,
                )

            yield RpmRepository(
                "epel-testing",
                f"{url}&repo=testing-epel{release}",
                gpgurls,
                enabled=False,
            )
            yield RpmRepository(
                "epel-testing-debuginfo",
                f"{url}&repo=testing-debug-epel{release}",
                gpgurls,
                enabled=False,
            )
            yield RpmRepository(
                "epel-testing-source",
                f"{url}&repo=testing-source-epel{release}",
                gpgurls,
                enabled=False,
            )

            # epel-next does not exist anymore since EPEL 10.
            if GenericVersion(context.config.release) < 10:
                yield RpmRepository(
                    "epel-next-testing",
                    f"{url}&repo=epel-testing-next-{release}",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    "epel-next-testing-debuginfo",
                    f"{url}&repo=epel-testing-next-debug-{release}",
                    gpgurls,
                    enabled=False,
                )
                yield RpmRepository(
                    "epel-next-testing-source",
                    f"{url}&repo=epel-testing-next-source-{release}",
                    gpgurls,
                    enabled=False,
                )

    @classmethod
    def sig_repositories(cls, context: Context) -> Iterable[RpmRepository]:
        if context.config.local_mirror:
            return

        sigs = (
            (
                "hyperscale",
                (f"packages-{c}" for c in ("main", "experimental", "facebook", "hotfixes", "spin", "intel")),
                ("RPM-GPG-KEY-CentOS-SIG-HyperScale",),
            ),
        )

        for sig, components, keys in sigs:
            gpgurls = tuple(
                find_rpm_gpgkey(context, key, f"https://www.centos.org/keys/{key}") for key in keys
            )

            for c in components:
                if mirror := context.config.mirror:
                    yield RpmRepository(
                        f"{sig}-{c}",
                        f"baseurl={join_mirror(mirror, f'SIGs/$stream/{sig}/$basearch/{c}')}",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
                    yield RpmRepository(
                        f"{sig}-{c}-debuginfo",
                        f"baseurl={join_mirror(mirror, f'SIGs/$stream/{sig}/$basearch/{c}/debug')}",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
                    yield RpmRepository(
                        f"{sig}-{c}-source",
                        f"baseurl={join_mirror(mirror, f'SIGs/$stream/{sig}/source/{c}')}",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
                else:
                    url = "metalink=https://mirrors.centos.org/metalink"
                    yield RpmRepository(
                        f"{sig}-{c}",
                        f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-$stream",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
                    yield RpmRepository(
                        f"{sig}-{c}-debuginfo",
                        f"{url}?arch=$basearch&repo=centos-{sig}-sig-{c}-debug-$stream",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
                    yield RpmRepository(
                        f"{sig}-{c}-source",
                        f"{url}?arch=source&repo=centos-{sig}-sig-{c}-source-$stream",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
                    yield RpmRepository(
                        f"{sig}-{c}-testing",
                        f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
                    yield RpmRepository(
                        f"{sig}-{c}-testing-debuginfo",
                        f"baseurl=https://buildlogs.centos.org/centos/$stream/{sig}/$basearch/{c}",
                        gpgurls,
                        enabled=False,
                        priority=CENTOS_SIG_REPO_PRIORITY,
                    )
