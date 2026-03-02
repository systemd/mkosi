#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# mkosi-cmd-daemon.sh - VM-side command execution daemon
#
# Listens on /dev/ttyS1 for JSON command requests, executes them,
# and writes JSON responses back. Designed to be driven by the
# host-side mkosi-cmd script via a QEMU unix socket chardev.
#
# Protocol:
#   Request:  {"id": "...", "cmd": "..."}\n
#   Response: {"id": "...", "stdout": "...", "stderr": "...", "rc": N}\n

SERIAL="/dev/ttyS1"
TIMEOUT=30

# Wait for the serial device to appear (give up after TIMEOUT seconds)
elapsed=0
while [ ! -e "$SERIAL" ]; do
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
        echo "mkosi-cmd-daemon: $SERIAL not found after ${TIMEOUT}s, exiting" >&2
        exit 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

# Configure serial port: raw mode, no echo
stty -F "$SERIAL" raw -echo -echoe -echok -echoctl

# Open serial port for read/write
exec 3<>"$SERIAL"

while IFS= read -r line <&3; do
    # Skip empty lines
    [ -z "$line" ] && continue

    # Strip any trailing carriage return
    line="${line%$'\r'}"

    # Parse JSON request
    id=$(printf '%s' "$line" | jq -r '.id // empty' 2>/dev/null)
    cmd=$(printf '%s' "$line" | jq -r '.cmd // empty' 2>/dev/null)

    # Skip malformed requests
    if [ -z "$id" ] || [ -z "$cmd" ]; then
        continue
    fi

    # Execute the command, capturing stdout and stderr separately
    stderr_file=$(mktemp)
    stdout=$(bash -c "$cmd" 2>"$stderr_file")
    rc=$?
    stderr=$(cat "$stderr_file")
    rm -f "$stderr_file"

    # Build and send JSON response (monochrome, no ANSI colors)
    jq -Mnc \
        --arg id "$id" \
        --arg stdout "$stdout" \
        --arg stderr "$stderr" \
        --argjson rc "$rc" \
        '{id: $id, stdout: $stdout, stderr: $stderr, rc: $rc}' >&3

done
