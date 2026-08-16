#!/bin/sh
# Host-wide two-permit build semaphore: acquire one of two shared slots,
# then exec "$@".
#
# A single flock serialized every module build across all jobs and both
# runner instances on this host, so two independent builds never overlapped
# even with a second runner online. Two slot files admit two concurrent
# builds and make a third wait, and the slots are shared across every
# repository that calls this helper, so the host runs at most two module
# builds at once. The build commands pass make -l equal to the thread count,
# so two concurrent builds share the cores rather than oversubscribing.
#
# A build waiting for a slot still counts against the caller's timeout, so
# the caller keeps wrapping this in `timeout`.
set -eu

slot_dir="${GOROROBA_CI_BUILD_SLOT_DIR:-$HOME/.cache/gororoba-ci}"
mkdir -p "$slot_dir"

# Try the first slot without blocking; fall back to blocking on the second.
# Two runners cap concurrency at two, so a third caller blocks here until a
# slot frees.
exec 9>"$slot_dir/radeon-build.slot1"
if ! flock -n 9; then
	exec 9>"$slot_dir/radeon-build.slot2"
	flock 9
fi

exec "$@"
