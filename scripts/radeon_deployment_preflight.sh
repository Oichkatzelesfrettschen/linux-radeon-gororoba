#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Read-only deployment identity and ring-health preflight for an RS480-class
# radeon host.
#
# The record binds the source tree, the built and installed module, the
# running module, the kernel, the boot, and the device into one artifact, so a
# later hardware run names the exact software that accepted it.  Every probe
# reads; none writes, loads, unloads, resets, or opens a 3D context, so the
# preflight is safe to run on the boot that will carry the attended cell.
#
# gpu_parked has no operator-readable sysfs or debugfs node.  It is a field
# radeon_gpu_reset latches when reset recovery fails on RS400/RS480, and its
# only observable signal is the kernel message it prints, so the preflight
# reads the journal for that signature rather than a node that does not exist.
# It also latches only along the reset path, and lockup_timeout=0 removes the
# automatic reset that would reach it, so a qualification profile running that
# parameter has no route to the latch short of an explicit reset.
#
# Usage: radeon_deployment_preflight.sh [source-tree] [evidence-dir]
#
# Output is one key=value line per fact, then a verdict line.  Exit 0 when
# every blocking condition is clear, 1 when one is not, 2 on usage failure.

set -u

source_tree="${1:-}"
evidence_dir="${2:-}"
blocking=0

emit() {
    printf '%s=%s\n' "$1" "$2"
}

# A fact the preflight could not read is reported as unavailable with the
# reason, so an absent probe never reads as a clear result.
unavailable() {
    printf '%s=unavailable(%s)\n' "$1" "$2"
}

block() {
    printf 'BLOCKING %s\n' "$1"
    blocking=$((blocking + 1))
}

echo "# host and boot identity"
emit kernel_release "$(uname -r)"
emit uname_version "$(uname -v | tr ' ' '_')"
if [ -r /proc/sys/kernel/random/boot_id ]; then
    emit boot_id "$(cat /proc/sys/kernel/random/boot_id)"
else
    unavailable boot_id "/proc/sys/kernel/random/boot_id unreadable"
fi
emit hostname_class "$(uname -m)"

echo "# source tree"
if [ -n "${source_tree}" ] && [ -d "${source_tree}/.git" ]; then
    emit source_commit "$(git -C "${source_tree}" rev-parse HEAD)"
    emit source_branch "$(git -C "${source_tree}" rev-parse --abbrev-ref HEAD)"
    if [ -n "$(git -C "${source_tree}" status --porcelain)" ]; then
        emit source_worktree dirty
    else
        emit source_worktree clean
    fi
    emit source_has_gpu_parked \
        "$(grep -rl 'gpu_parked' "${source_tree}/drivers/gpu/drm/radeon/" \
            2>/dev/null | wc -l)"
    # The CS admission path is the one that lets an executable command stream
    # reach the ring, so whether it consults the latch is recorded on its own.
    if grep -q 'gpu_parked' \
        "${source_tree}/drivers/gpu/drm/radeon/radeon_cs.c" 2>/dev/null; then
        emit source_cs_ioctl_checks_parked yes
    else
        emit source_cs_ioctl_checks_parked no
    fi
else
    unavailable source_commit "no source tree given or not a git checkout"
fi

echo "# radeon module"
if [ -d /sys/module/radeon ]; then
    emit module_loaded yes
    if [ -r /sys/module/radeon/srcversion ]; then
        emit module_srcversion "$(cat /sys/module/radeon/srcversion)"
    else
        unavailable module_srcversion "/sys/module/radeon/srcversion absent"
    fi
    for param in lockup_timeout dpm audio runpm; do
        if [ -r "/sys/module/radeon/parameters/${param}" ]; then
            emit "module_param_${param}" \
                "$(cat "/sys/module/radeon/parameters/${param}")"
        else
            unavailable "module_param_${param}" "parameter not exposed"
        fi
    done
    # No sysfs node reports the parked latch, so its absence is recorded as a
    # property of the module rather than probed for.
    emit module_parked_sysfs_node absent
else
    emit module_loaded no
    unavailable module_srcversion "radeon module not loaded"
fi

installed_ko=$(modinfo -n radeon 2>/dev/null)
if [ -n "${installed_ko}" ] && [ -r "${installed_ko}" ]; then
    emit installed_module_path "${installed_ko}"
    emit installed_module_srcversion \
        "$(modinfo -F srcversion radeon 2>/dev/null || echo unknown)"
    emit installed_module_vermagic \
        "$(modinfo -F vermagic radeon 2>/dev/null | tr ' ' '_')"
    # The parked path prints a message no other path prints, so its presence
    # in the built object reports whether the deployed module carries the
    # mechanism at all.  A packed module must be expanded first: scanning the
    # container reports every string absent, which reads as a module without
    # the mechanism.
    module_text=""
    case "${installed_ko}" in
        *.zst) command -v zstdcat >/dev/null 2>&1 &&
               module_text=$(zstdcat "${installed_ko}" 2>/dev/null |
                             strings 2>/dev/null) ;;
        *.xz)  command -v xzcat >/dev/null 2>&1 &&
               module_text=$(xzcat "${installed_ko}" 2>/dev/null |
                             strings 2>/dev/null) ;;
        *.gz)  command -v zcat >/dev/null 2>&1 &&
               module_text=$(zcat "${installed_ko}" 2>/dev/null |
                             strings 2>/dev/null) ;;
        *)     module_text=$(strings "${installed_ko}" 2>/dev/null) ;;
    esac
    if [ -z "${module_text}" ]; then
        unavailable installed_module_has_parked \
            "module text unreadable; no decompressor for ${installed_ko}"
        block "the deployed module could not be scanned for the parked path"
    elif printf '%s' "${module_text}" | \
        grep -q 'parking GPU, skipping resume-side access'; then
        emit installed_module_has_parked yes
    else
        emit installed_module_has_parked no
    fi
    # Calibration for the scan: a string every radeon module carries proves
    # the reader reached module text, so a "no" above is an absent mechanism
    # rather than an unread file.
    if printf '%s' "${module_text}" | grep -q 'radeon_gem_object_create'; then
        emit module_text_scan calibrated
    else
        emit module_text_scan uncalibrated
        block "the module text scan found no known radeon symbol"
    fi
else
    unavailable installed_module_path "modinfo found no radeon module"
fi

echo "# device"
if command -v lspci >/dev/null 2>&1; then
    ids=$(lspci -n 2>/dev/null | awk '$2 ~ /^0300:/ {print $3}' | tr '\n' ',')
    emit pci_display_ids "${ids:-none}"
    case "${ids}" in
        *1002:5974*) emit target_device rs482_present ;;
        *) emit target_device rs482_absent ;;
    esac
else
    unavailable pci_display_ids "lspci not installed"
fi

echo "# ring health"
# A task blocked in the radeon fence wait is the wedge signature: it is
# uninterruptible, so no signal reaches it and no userspace unwinder may
# attach to it.
waiters=0
if [ -r /proc/self/wchan ]; then
    for p in /proc/[0-9]*; do
        [ -r "${p}/wchan" ] || continue
        case "$(cat "${p}/wchan" 2>/dev/null)" in
            *radeon_fence*) waiters=$((waiters + 1)) ;;
        esac
    done
    emit radeon_fence_waiters "${waiters}"
    [ "${waiters}" -eq 0 ] || block "a task is blocked in a radeon fence wait"
else
    unavailable radeon_fence_waiters "/proc wchan unreadable"
fi

dstate=$(ps -eo stat= 2>/dev/null | grep -c '^D' || true)
emit uninterruptible_tasks "${dstate:-0}"

echo "# journal signatures for this boot"
if command -v journalctl >/dev/null 2>&1; then
    park=$(journalctl -k -b 2>/dev/null | \
        grep -c 'parking GPU, skipping resume-side access' || true)
    lockup=$(journalctl -k -b 2>/dev/null | \
        grep -cE 'ring [0-9]+ stalled for more than|GPU lockup' || true)
    reset=$(journalctl -k -b 2>/dev/null | \
        grep -cE 'GPU reset (succeeded|failed)' || true)
    csfail=$(journalctl -k -b 2>/dev/null | \
        grep -cE 'Forbidden register|Buffer too small|No reloc for' || true)
    emit journal_parked_signature "${park:-0}"
    emit journal_lockup_signature "${lockup:-0}"
    emit journal_reset_signature "${reset:-0}"
    emit journal_cs_reject_signature "${csfail:-0}"
    [ "${park:-0}" -eq 0 ] || block "this boot already parked the GPU"
    [ "${lockup:-0}" -eq 0 ] || block "this boot already recorded a lockup"
    [ "${reset:-0}" -eq 0 ] || block "this boot already reset the GPU"
else
    unavailable journal_parked_signature "journalctl not available"
fi

echo "# evidence and logging"
if [ -n "${evidence_dir}" ]; then
    if [ ! -e "${evidence_dir}" ]; then
        emit evidence_dir absent
        block "the evidence directory does not exist"
    elif [ -e "${evidence_dir}/attempt.token" ]; then
        emit evidence_dir already_attempted
        block "the evidence directory carries an attempt token"
    elif [ -n "$(ls -A "${evidence_dir}" 2>/dev/null)" ]; then
        emit evidence_dir not_fresh
        block "the evidence directory is not empty"
    else
        emit evidence_dir fresh
    fi
else
    emit evidence_dir not_checked
fi

if [ -r /proc/net/netconsole ] || \
    grep -q netconsole /proc/modules 2>/dev/null; then
    emit offbox_logging netconsole
elif [ -e /dev/ttyS0 ]; then
    emit offbox_logging serial_present
else
    emit offbox_logging none
    block "no off-box log path; a hard lock would lose its record"
fi

echo "# containment rules in force"
emit rule_no_3d_positive_control_on_this_boot required
emit rule_direct_write_control_on_sacrificial_boot required
emit rule_cold_boot_before_successor required
emit rule_no_userspace_unwinder_on_fence_waiter required
emit rule_recovery_is_physical_power_cycle required

if [ "${blocking}" -ne 0 ]; then
    echo "verdict=BLOCKED conditions=${blocking}"
    exit 1
fi
echo "verdict=CLEAR conditions=0"
exit 0
