#!/bin/bash -e

COMMAND="$1"
KERNEL_VERSION="$2"
BOOT_DIR_ABS="$3"
KERNEL_IMAGE="$4"

# If KERNEL_INSTALL_MACHINE_ID is defined but empty, BOOT_DIR_ABS is a fake directory so let's skip creating
# the unified kernel image.
if [[ -z "${KERNEL_INSTALL_MACHINE_ID-unset}" ]]; then
    exit 0
fi

# Strip machine ID and kernel version to get the boot directory.
PREFIX=$(dirname "$(dirname "$BOOT_DIR_ABS")")

# Pick a default prefix name for the unified kernel binary
if [[ -n "$IMAGE_ID" ]] ; then
    if [[ -n "$IMAGE_VERSION" ]]; then
        PARTLABEL="${IMAGE_ID}_${IMAGE_VERSION}"
    else
        PARTLABEL="${IMAGE_ID}"
    fi
else
    IMAGE_ID=linux
fi

if [[ -n "$IMAGE_VERSION" ]] ; then
    BOOT_BINARY="${PREFIX}/EFI/Linux/${IMAGE_ID}_${IMAGE_VERSION}.efi"
elif [[ -n "$ROOTHASH" ]] ; then
    BOOT_BINARY="${PREFIX}/EFI/Linux/${IMAGE_ID}-${KERNEL_VERSION}-${ROOTHASH}.efi"
elif [[ -n "$USRHASH" ]] ; then
    BOOT_BINARY="${PREFIX}/EFI/Linux/${IMAGE_ID}-${KERNEL_VERSION}-${USRHASH}.efi"
else
    BOOT_BINARY="${PREFIX}/EFI/Linux/${IMAGE_ID}-${KERNEL_VERSION}.efi"
fi

case "$COMMAND" in
    add)
        if [[ -f /etc/kernel/cmdline ]]; then
            read -r -d '' BOOT_OPTIONS < /etc/kernel/cmdline || true
        elif [[ -f /usr/lib/kernel/cmdline ]]; then
            read -r -d '' BOOT_OPTIONS < /usr/lib/kernel/cmdline || true
        else
            read -r -d '' BOOT_OPTIONS < /proc/cmdline || true
        fi

        if [[ -n "$ROOTHASH" ]]; then
            BOOT_OPTIONS="${BOOT_OPTIONS} roothash=${ROOTHASH}"
        elif [[ -n "$USRHASH" ]]; then
            BOOT_OPTIONS="${BOOT_OPTIONS} usrhash=${USRHASH}"
        elif [[ -n "$PARTLABEL" ]]; then
            BOOT_OPTIONS="${BOOT_OPTIONS} root=PARTLABEL=${PARTLABEL}"
        fi

        if [[ -n "$KERNEL_IMAGE" ]]; then
            DRACUT_KERNEL_IMAGE_OPTION="--kernel-image ${KERNEL_IMAGE}"
        else
            DRACUT_KERNEL_IMAGE_OPTION=""
        fi

        # shellcheck disable=SC2086
        dracut \
            --uefi \
            --kver "$KERNEL_VERSION" \
            $DRACUT_KERNEL_IMAGE_OPTION \
            --kernel-cmdline "$BOOT_OPTIONS" \
            --force \
            "$BOOT_BINARY"
        ;;
    remove)
        rm -f -- "$BOOT_BINARY"
        ;;
esac
