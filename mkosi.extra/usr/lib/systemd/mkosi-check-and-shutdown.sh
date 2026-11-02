#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

rc=0

# Ignore masked units (in particular lvm2-monitor.service,, see mkosi.postinst); these
# are not a real image failure
: >/failed-services
systemctl --failed --no-legend --plain |
    while read -r service state rest
    do
        [ "$state" = masked ] && continue
        rc=1
        printf '%s %s %s\n' "$service" "$state" "$rest"
    done

exit $rc
