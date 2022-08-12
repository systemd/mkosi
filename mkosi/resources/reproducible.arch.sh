#!/bin/bash -x

rm -f ${BUILDROOT}/var/cache/ldconfig/aux-cache
sed -i -e '/INSTALLDATE/{n;s/.*/0/}' "${BUILDROOT}"/var/lib/pacman/local/*/desc
