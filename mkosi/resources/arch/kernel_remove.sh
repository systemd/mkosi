#!/bin/bash -e

while read -r f; do
    kernel-install remove "$(basename "$(dirname "$f")")"
done
