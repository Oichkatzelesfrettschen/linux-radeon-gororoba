#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Arm the one-shot RS400 GART TLB invalidation timeout and report the five
# facts the software disposition makes observable.
#
# The trigger is a GTT-domain GEM allocation. radeon_gart_bind_locked calls the
# ASIC tlb_flush callback after writing the page table entries, and on RS400 and
# RS480 that callback is rs400_gart_tlb_flush, so one bind consumes one armed
# invalidation. policy/rs4xx-gart-memory-path.tsv row
# GART_BIND_PTE_MB_TLB_PUBLICATION records that binding. The RS4xx cache-drain
# node radeon_rs480_mc_flush is not the trigger: it emits an RB3D and Z cache
# packet sequence on the CP ring and reaches no GART TLB invalidation.
#
# The module must be built with the mutate profile and the runtime profile must
# select mutate-dev, because the arming node compiles and registers there alone.
#
# usage: run_rs400_gart_tlb_fault_injection.sh [DRI_DEBUGFS_DIR]

set -u

verdict_status=0

report() {
	printf '%s: %s\n' "$1" "$2"
	if [ "$1" = FAIL ]; then
		verdict_status=1
	fi
}

fatal() {
	printf 'BLOCKED: %s\n' "$1" >&2
	exit 2
}

[ "$(id -u)" -eq 0 ] || fatal "the debugfs nodes are root-only"

debugfs_dir=${1:-}
if [ -z "$debugfs_dir" ]; then
	for candidate in /sys/kernel/debug/dri/*; do
		if [ -e "$candidate/radeon_rs400_gart_tlb_disposition" ]; then
			debugfs_dir=$candidate
			break
		fi
	done
fi
[ -n "$debugfs_dir" ] || fatal "no DRM minor exposes radeon_rs400_gart_tlb_disposition"

disposition=$debugfs_dir/radeon_rs400_gart_tlb_disposition
arm=$debugfs_dir/radeon_rs400_gart_tlb_fault_inject

[ -r "$disposition" ] || fatal "$disposition is absent; the module lacks the observe profile"
[ -w "$arm" ] || fatal "$arm is absent; the module lacks the mutate profile or the runtime profile is lower"

# The disposition emits its schema line first and then one "key = value" line
# per field. A field that reads back empty or non-numeric means the node or its
# schema moved, and a verdict computed from an unread value would be a
# fabricated one, so the run refuses instead.
read_field() {
	value=$(awk -v key="$1" '$1 == key { print $3 }' "$disposition")
	case $value in
	"" | *[!0-9]*)
		fatal "$disposition supplies no numeric $1"
		;;
	esac
	printf '%s' "$value"
}

# Calibrate the arming node before trusting an armed run. The node compares the
# written bytes against the token "1" whole, so each spelling a numeric parser
# would have accepted must be refused; a later success is then the exact
# command and not an unconditional accept. The open must succeed for the
# refusal to be the write handler's, so a failed redirection blocks the run
# rather than counting as one.
refuse_token() {
	exec 3>"$arm" || fatal "$arm cannot be opened for writing"
	token_status=0
	printf '%s' "$1" >&3 2>/dev/null || token_status=$?
	exec 3>&-
	if [ "$token_status" -eq 0 ]; then
		report FAIL "the arming node accepted the token $2"
		return
	fi
	report PASS "the arming node refuses the token $2"
}

refuse_token '2' '2'
refuse_token '+1' '+1'
refuse_token '01' '01'
refuse_token '0x1' '0x1'
refuse_token '11' '11'
refuse_token '1 ' '1 with a trailing space'
armed_now=$(read_field fault_inject_armed) || fatal "the disposition is unreadable"
if [ "$armed_now" != 0 ]; then
	fatal "a refused write left the one-shot armed"
fi

timeouts_before=$(read_field tlb_flush_timeouts)
ready_before=$(read_field gart_ready)
printf 'baseline: tlb_flush_timeouts=%s gart_ready=%s\n' \
	"$timeouts_before" "$ready_before"

printf '1\n' >"$arm" || fatal "the exact arming write failed"
[ "$(read_field fault_inject_armed)" = 1 ] || fatal "the exact write left the one-shot disarmed"

# Trigger: a GTT-domain buffer object binds its pages into the GART and the
# bind path publishes them through the ASIC tlb_flush callback.
trigger_output=$(python3 - "$debugfs_dir" <<'PYEOF'
import ctypes, fcntl, os, struct, sys

# DRM_IOCTL_RADEON_GEM_CREATE: DRM_COMMAND_BASE 0x40 + DRM_RADEON_GEM_CREATE 0x1d.
DRM_IOCTL_RADEON_GEM_CREATE = 0xC020645D
RADEON_GEM_DOMAIN_GTT = 0x2
DRM_IOCTL_GEM_CLOSE = 0x40086409

minor = os.path.basename(sys.argv[1])
node = "/dev/dri/card" + minor if minor.isdigit() else "/dev/dri/card0"
try:
    fd = os.open(node, os.O_RDWR)
except OSError as error:
    print("unreachable:" + str(error))
    raise SystemExit(0)
try:
    # struct drm_radeon_gem_create: size, alignment, handle, initial_domain,
    # flags, and tail padding to the 32-byte ioctl argument.
    request = struct.pack("=QQIIII", 1 << 20, 4096, 0, RADEON_GEM_DOMAIN_GTT, 0, 0)
    buffer = ctypes.create_string_buffer(request)
    try:
        fcntl.ioctl(fd, DRM_IOCTL_RADEON_GEM_CREATE, buffer)
    except OSError as error:
        print("refused:" + str(error.errno))
        raise SystemExit(0)
    handle = struct.unpack("=QQIIII", buffer.raw)[2]
    fcntl.ioctl(fd, DRM_IOCTL_GEM_CLOSE, struct.pack("=II", handle, 0))
    print("bound")
finally:
    os.close(fd)
PYEOF
)
printf 'trigger: %s\n' "$trigger_output"

timeouts_after=$(read_field tlb_flush_timeouts)
armed_after=$(read_field fault_inject_armed)
ready_after=$(read_field gart_ready)

# Fact 1: the invalidation reported failure and the callback counted it.
if [ "$timeouts_after" -gt "$timeouts_before" ] && [ "$armed_after" = 0 ]; then
	report PASS "fact 1: the invalidation reported -ETIMEDOUT; tlb_flush_timeouts moved $timeouts_before to $timeouts_after and the one-shot cleared"
elif [ "$armed_after" = 1 ]; then
	report NOT_RUN "fact 1: the one-shot stayed armed, so the trigger reached no rs400_gart_tlb_invalidate call and the arm waits for the next one; the allocation reported $trigger_output"
else
	report FAIL "fact 1: the one-shot was consumed yet tlb_flush_timeouts stayed $timeouts_after"
fi

# Fact 2: rs400_gart_enable runs at initialization and resume alone, so a
# userspace run reaches no enable. The observable statement is the published
# ready state across the injected flush.
if [ "$ready_after" = "$ready_before" ]; then
	report PASS "fact 2 (scoped to the reachable path): rs400_gart_enable is unreachable from userspace, and the bind-path flush left gart_ready=$ready_after unchanged; only an enable-time invalidation clears it"
else
	report FAIL "fact 2: gart_ready moved $ready_before to $ready_after without an enable"
fi

# Fact 3: the resume re-enable needs a suspend cycle.
report NOT_RUN "fact 3: the resume path needs a system suspend and resume, which this script does not initiate on an attended target"

# Fact 4: the bind-path flush leaves gart.ready true, so radeon_gart_bind_locked
# admits the next submission. A refusal arrives only after an enable-time
# injection, where radeon_gart_bind_locked and radeon_gart_unbind_locked return
# -EINVAL on !rdev->gart.ready.
report NOT_RUN "fact 4: the bind-path injection leaves gart_ready=$ready_after, so the next submission is admitted; the refusal is -EINVAL from radeon_gart_bind_locked and needs an enable-time injection"

# Fact 5: nothing cleared readiness, so nothing needs restoring.
report NOT_RUN "fact 5: gart_ready stayed $ready_after, so no recovery re-initialization is required; a cleared aperture is republished by rs400_gart_enable through resume or module reload"

printf 'final: tlb_flush_timeouts=%s fault_inject_armed=%s gart_ready=%s\n' \
	"$timeouts_after" "$armed_after" "$ready_after"
exit "$verdict_status"
