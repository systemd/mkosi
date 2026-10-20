#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux

# Ignore masked units (in particular lvm2-monitor.service,, see mkosi.postinst); these
# are not a real image failure
systemctl --failed --no-legend --plain |
    awk '$2 != "masked"' |
    tee /failed-services

# systemd v256+ reports SuccessAction=exit to mkosi over the vmm.notify_socket credential.
# Alibaba Cloud Linux 3's systemd 239 has the exit action, but in a VM it turns that into
# poweroff and never reads the credential, so qemu exits 0 and the integration tests fail.
# Forward the status ourselves before that poweroff.
if ! grep -q -a -F 'vmm.notify_socket' /usr/lib/systemd/systemd 2>/dev/null; then
    status=123
    if [[ -s /failed-services ]]; then
        status=1
    fi

    if systemd-detect-virt --container --quiet; then
        systemctl exit "${status}" || true
    else
        cred=""
        if [[ -e /sys/firmware/dmi/tables/DMI ]] &&
            command -v strings >/dev/null &&
            command -v base64 >/dev/null &&
            [[ -x /usr/libexec/platform-python ]]; then
            cred=$(
                strings /sys/firmware/dmi/tables/DMI |
                    sed -n 's/^io\.systemd\.credential\.binary:vmm\.notify_socket=//p' |
                    head -n 1
            ) || true
        fi

        socket=$(printf '%s' "${cred}" | base64 -d 2>/dev/null) || socket=""
        socket="${socket#vsock-stream:}"
        cid="${socket%%:*}"
        port="${socket##*:}"
        # systemd 239's sd_notify() only speaks AF_UNIX. Open the vsock ourselves.
        if [[ -n "${cid}" && -n "${port}" && "${cid}" != "${port}" ]]; then
            timeout 5 /usr/libexec/platform-python - "${cid}" "${port}" "${status}" <<'PY' || true
import ctypes
import sys

cid, port, status = sys.argv[1:]
AF_VSOCK = 40
SOCK_STREAM = 1


class sockaddr_vm(ctypes.Structure):
    _fields_ = [
        ("svm_family", ctypes.c_ushort),
        ("svm_reserved1", ctypes.c_ushort),
        ("svm_port", ctypes.c_uint),
        ("svm_cid", ctypes.c_uint),
        ("svm_zero", ctypes.c_ubyte * 4),
    ]


libc = ctypes.CDLL("libc.so.6", use_errno=True)
fd = libc.socket(AF_VSOCK, SOCK_STREAM, 0)
if fd < 0:
    raise OSError(ctypes.get_errno(), "socket")
addr = sockaddr_vm(AF_VSOCK, 0, int(port), int(cid))
if libc.connect(fd, ctypes.byref(addr), ctypes.sizeof(addr)) < 0:
    raise OSError(ctypes.get_errno(), "connect")
msg = f"EXIT_STATUS={status}\n".encode()
if libc.send(fd, msg, len(msg), 0) < 0:
    raise OSError(ctypes.get_errno(), "send")
libc.close(fd)
PY
        fi
        systemctl poweroff || true
    fi
    exit 0
fi

# Exit with non-zero EC if the /failed-services file is not empty (we have -e set)
[[ ! -s /failed-services ]]
