#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Calibrate the run-form correspondence controls against defective replays.
#
# Each mutant below breaks one clause of the r100_cs_parse_packet0 run form
# in a copy of replay_r300_cs_track.c: the count + 1 loop bound, register
# advancement, the per-register bitmap consultation, and ONE_REG_WR
# decoding.  The correspondence gate earns trust here by failing on every
# mutant while holding on the pristine replay, so a run-form regression in
# the replay cannot pass the gate unnoticed.
#
# Usage: run_r300_cs_runform_calibration.sh [workdir]
#
# Exit 0 when the pristine replay passes and every mutant fails, 1 when a
# mutant survives the gate or the pristine replay fails it, 2 on build
# failure.

set -eu

repo_root=$(git rev-parse --show-toplevel)
workdir="${1:-${repo_root}/build/runform-calibration}"
radeon="${repo_root}/drivers/gpu/drm/radeon"
src="${repo_root}/scripts/replay_r300_cs_track.c"

mkdir -p "${workdir}"
cc_flags="-O2 -Wall -Wextra"

cc -O2 -o "${workdir}/mkregtable" "${radeon}/mkregtable.c"
"${workdir}/mkregtable" "${radeon}/reg_srcs/r300" \
    > "${workdir}/r300_reg_safe.h"

# shellcheck disable=SC2086
cc ${cc_flags} -Werror \
    -o "${workdir}/r300_cs_grammar_correspondence" \
    "${repo_root}/scripts/r300_cs_grammar_correspondence.c"

# The gate records a skipped sweep as its own failed control, so a
# --sweep 0 run always exits 1; the calibration verdict therefore counts
# the failed controls other than that sentinel.
run_gate() {
    binary=$1
    "${workdir}/r300_cs_grammar_correspondence" \
        --tree "${repo_root}" \
        --replay "${binary}" \
        --workdir "${workdir}" \
        --reg-safe-header "${workdir}/r300_reg_safe.h" \
        --sweep 0 > "${workdir}/gate-last.txt" 2>&1 || true
    [ "$(grep -c '^  FAIL' "${workdir}/gate-last.txt" || true)" = 1 ] &&
        grep -q '^  FAIL.*sweep skipped' "${workdir}/gate-last.txt"
}

# mutate NAME PATTERN REPLACEMENT: write a mutant source whose single
# difference from the pristine replay is the named substitution, and refuse
# a pattern that changes nothing.
mutate() {
    name=$1
    pattern=$2
    replacement=$3
    out="${workdir}/replay_${name}.c"
    sed "s|${pattern}|${replacement}|" "${src}" > "${out}"
    if cmp -s "${src}" "${out}"; then
        echo "mutant ${name}: pattern '${pattern}' matched nothing" >&2
        exit 2
    fi
    # A mutant is a deliberately defective program, so it builds without
    # -Werror; the defect must be the semantic one the substitution names.
    # shellcheck disable=SC2086
    cc ${cc_flags} -I "${workdir}" -I "${radeon}" \
        -o "${workdir}/replay_${name}" "${out}"
}

status=0

echo "pristine replay against the gate"
# shellcheck disable=SC2086
cc ${cc_flags} -Werror -I "${workdir}" -I "${radeon}" \
    -o "${workdir}/replay_pristine" "${src}"
if run_gate "${workdir}/replay_pristine"; then
    echo "  PASS pristine replay holds every control"
else
    echo "  FAIL pristine replay fails the gate"
    status=1
fi

check_mutant() {
    name=$1
    what=$2
    if run_gate "${workdir}/replay_${name}"; then
        echo "  FAIL mutant ${name} (${what}) survives the gate"
        status=1
    else
        echo "  PASS mutant ${name} (${what}) is caught"
    fi
}

echo "mutants against the gate"

mutate count_off_by_one \
    'i <= pkt->count; i++, idx++' \
    'i < pkt->count; i++, idx++'
check_mutant count_off_by_one "count field decodes count rather than count+1"

mutate advance_zero \
    'reg += 4;' \
    'reg += 0;'
check_mutant advance_zero "register never advances through a run"

mutate advance_four_regs \
    'reg += 4;' \
    'reg += 16;'
check_mutant advance_four_regs "register advances four registers per dword"

mutate bitmap_first_only \
    'j = reg >> 7;' \
    'j = pkt->reg >> 7; m = 1u << ((pkt->reg >> 2) \& 31); if (0)'
check_mutant bitmap_first_only \
    "safe bitmap consulted for the first register alone"

mutate one_reg_wr_ignored \
    'pkt->one_reg_wr = PACKET0_GET_ONE_REG_WR(header);' \
    'pkt->one_reg_wr = 0;'
check_mutant one_reg_wr_ignored "ONE_REG_WR bit ignored by the decoder"

if [ "${status}" -ne 0 ]; then
    echo "run_r300_cs_runform_calibration: calibration did not hold" >&2
    exit 1
fi
echo "run_r300_cs_runform_calibration: gate catches every mutant"
