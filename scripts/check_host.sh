#!/usr/bin/env bash
# Exit 0 healthy, 1 threshold or inactive service, 2 usage or probe failure.
set -euo pipefail

if [[ "$#" != 3 || ! "$2" =~ ^[[:alnum:]_][[:alnum:]_.@:-]*$ || ! "$3" =~ ^[0-9]{1,3}$ ]]; then
    printf 'Usage: %s MOUNT_PATH SYSTEMD_UNIT MAX_USED_PERCENT\n' "$0" >&2
    exit 2
fi

disk_path=$1
unit=$2
limit=$((10#$3))
if ((limit < 1 || limit > 100)); then
    printf 'MAX_USED_PERCENT must be between 1 and 100\n' >&2
    exit 2
fi

if ! used=$(LC_ALL=C df -P -- "$disk_path" | awk 'NR == 2 { sub(/%$/, "", $5); print $5 }'); then
    printf 'status=error probe=df\n' >&2
    exit 2
fi
if [[ ! "$used" =~ ^[0-9]{1,3}$ ]]; then
    printf 'status=error probe=df detail=unrecognized_output\n' >&2
    exit 2
fi
used=$((10#$used))

if service_state=$(systemctl is-active -- "$unit"); then
    case "$service_state" in
        active) ;;
        *) printf 'status=error probe=systemctl detail=unrecognized_output\n' >&2; exit 2 ;;
    esac
else
    case "$service_state" in
        inactive|failed|activating|deactivating|reloading|unknown) ;;
        *) printf 'status=error probe=systemctl detail=unrecognized_output\n' >&2; exit 2 ;;
    esac
fi

if ((used >= limit)) || [[ "$service_state" != active ]]; then
    printf 'status=alert disk_used_percent=%s service_state=%s unit=%s\n' "$used" "$service_state" "$unit"
    exit 1
fi
printf 'status=ok disk_used_percent=%s service_state=%s unit=%s\n' "$used" "$service_state" "$unit"
