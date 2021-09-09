#!/bin/bash -e
shopt -s nullglob

declare -a kernel_version

# Check the targets passed by the pacman hook.
while read -r line
do
    if [[ "$line" =~ usr/lib/modules/([^/]+)/vmlinuz ]]
    then
        kernel_version+=( "${BASH_REMATCH[1]}" )
    else
        # If a non-matching line is passed, just rebuild all kernels.
        kernel_version=()
        for f in /usr/lib/modules/*/vmlinuz
        do
            kernel_version+=( "$(basename "$(dirname "$f")")" )
        done
        break
    fi
done

# (re)build the kernel images.
for kv in "${kernel_version[@]}"
do
    kernel-install add "$kv" "/usr/lib/modules/${kv}/vmlinuz"
done
