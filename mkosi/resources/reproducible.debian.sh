#!/bin/bash -x

rm -f ${BUILDROOT}/var/log/dpkg.log
rm -f ${BUILDROOT}/var/log/bootstrap.log
rm -f ${BUILDROOT}/var/cache/apt/pkgcache.bin
rm -f ${BUILDROOT}/var/log/apt/history.log
rm -f ${BUILDROOT}/var/log/apt/term.log
rm -f ${BUILDROOT}/var/log/alternatives.log
rm -f ${BUILDROOT}/var/cache/ldconfig/aux-cache
rm -f ${BUILDROOT}/var/log/apt/eipp.log.xz
rm -f ${BUILDROOT}/var/lib/dbus/machine-id
