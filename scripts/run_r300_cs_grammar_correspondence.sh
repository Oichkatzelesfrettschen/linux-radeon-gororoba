#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Build and run the r300 CS-grammar correspondence over replay_r300_cs_track.
#
# The correspondence tool derives the grammar from the kernel sources and holds
# the replay to it.  This driver supplies the three inputs that derivation
# needs -- the generated safe-register header mkregtable produces, the replay
# binary under test, and the tree the sources come from -- and then extracts
# r300_packet0_check's case labels a second time, in shell, and diffs that list
# against the one the C tool resolved.  Two independent extractions agreeing is
# what makes the case list evidence rather than a restatement of one parser.
#
# Usage: run_r300_cs_grammar_correspondence.sh [workdir] [replay-binary]
#
# With no replay binary the driver builds the in-tree replay.  Pointing it at
# another binary is how a deliberately defective copy is calibrated against the
# same controls.
#
# Exit 0 when every control holds and the two case lists agree, 1 when one does
# not, 2 on build or usage failure.

set -eu

repo_root=$(git rev-parse --show-toplevel)
workdir="${1:-${repo_root}/build}"
replay="${2:-}"
radeon="${repo_root}/drivers/gpu/drm/radeon"

mkdir -p "${workdir}"

cc_flags="-O2 -Wall -Wextra -Werror"

echo "building the safe-register header from reg_srcs/r300"
# mkregtable is upstream kernel host tooling and builds under the kernel's own
# warning set, so it is compiled with the default flags rather than the
# project flags this driver applies to the code it owns.
cc -O2 -o "${workdir}/mkregtable" "${radeon}/mkregtable.c"
"${workdir}/mkregtable" "${radeon}/reg_srcs/r300" > "${workdir}/r300_reg_safe.h"

if [ -z "${replay}" ]; then
    echo "building replay_r300_cs_track"
    # shellcheck disable=SC2086
    cc ${cc_flags} -I "${workdir}" -I "${radeon}" \
        -o "${workdir}/replay_r300_cs_track" \
        "${repo_root}/scripts/replay_r300_cs_track.c"
    replay="${workdir}/replay_r300_cs_track"
fi

echo "building r300_cs_grammar_correspondence"
# shellcheck disable=SC2086
cc ${cc_flags} -o "${workdir}/r300_cs_grammar_correspondence" \
    "${repo_root}/scripts/r300_cs_grammar_correspondence.c"

report="${workdir}/r300_cs_grammar_correspondence.txt"
status=0
"${workdir}/r300_cs_grammar_correspondence" \
    --tree "${repo_root}" \
    --replay "${replay}" \
    --workdir "${workdir}" \
    --reg-safe-header "${workdir}/r300_reg_safe.h" \
    > "${report}" 2>&1 || status=$?
sed '/^KCASE /d' "${report}"

# The second extraction.  Case labels of r300_packet0_check sit at one tab of
# indentation; the nested format and pitch switches indent deeper, so the
# indentation separates the switch this grammar belongs to from the value
# enumerations inside it.  Symbolic labels resolve out of the register headers
# and SYMBOL+N arithmetic is evaluated, which is the same resolution the C tool
# performs and a different implementation of it.
echo
echo "independent case-label extraction:"
defines="${workdir}/r300_case_defines.txt"
grep -h -E '^#[[:space:]]*define[[:space:]]+[A-Za-z_][A-Za-z_0-9]*[[:space:]]+0x' \
    "${radeon}/r300_reg.h" "${radeon}/radeon_reg.h" "${radeon}/r500_reg.h" \
    "${radeon}/r100_track.h" \
    | sed -E 's/^#[[:space:]]*define[[:space:]]+([A-Za-z_][A-Za-z_0-9]*)[[:space:]]+(0x[0-9a-fA-F]+).*/\1 \2/' \
    > "${defines}"

shell_list="${workdir}/r300_case_labels_shell.txt"
awk '
    /^static int r300_packet0_check\(/ { inside = 1 }
    inside && /^}/ { inside = 0 }
    inside && /^\tcase [^\t]/ {
        label = $0
        sub(/^\tcase[[:space:]]*/, "", label)
        sub(/:.*$/, "", label)
        gsub(/[[:space:]]/, "", label)
        print label
    }
' "${radeon}/r300.c" | while read -r label; do
    case "${label}" in
    0x*|0X*)
        printf '%d\n' "$((label))"
        ;;
    *+*)
        sym=${label%%+*}
        add=${label#*+}
        base=$(awk -v s="${sym}" '$1 == s { print $2; exit }' "${defines}")
        if [ -z "${base}" ]; then
            echo "unresolved ${label}" >&2
            exit 1
        fi
        printf '%d\n' "$((base + add))"
        ;;
    *)
        base=$(awk -v s="${label}" '$1 == s { print $2; exit }' "${defines}")
        if [ -z "${base}" ]; then
            echo "unresolved ${label}" >&2
            exit 1
        fi
        printf '%d\n' "$((base))"
        ;;
    esac
done | sort -n -u > "${shell_list}"

tool_list="${workdir}/r300_case_labels_tool.txt"
sed -n 's/^KCASE \(0x[0-9a-f]*\) .*/\1/p' "${report}" \
    | while read -r hex; do printf '%d\n' "$((hex))"; done \
    | sort -n -u > "${tool_list}"

shell_n=$(wc -l < "${shell_list}")
tool_n=$(wc -l < "${tool_list}")
if cmp -s "${shell_list}" "${tool_list}"; then
    printf '  %-4s %-21s %s\n' PASS KERNEL_SOURCE_DERIVED \
        "two extractions of r300_packet0_check agree on ${shell_n} registers"
else
    printf '  %-4s %-21s %s\n' FAIL KERNEL_SOURCE_DERIVED \
        "case lists differ: shell ${shell_n}, tool ${tool_n}"
    diff "${shell_list}" "${tool_list}" || true
    status=1
fi

if [ "${status}" -ne 0 ]; then
    echo "run_r300_cs_grammar_correspondence: correspondence did not hold" >&2
    exit 1
fi
echo "run_r300_cs_grammar_correspondence: correspondence holds"
