#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

# Ignore masked units (in particular lvm2-monitor.service,, see mkosi.postinst); these
# are not a real image failure
systemctl --failed --no-legend --plain |
    awk '$2 != "masked"' |
    tee /failed-services

# Exit with non-zero EC if the /failed-services file is not empty (we have -e set)
[[ ! -s /failed-services ]]
