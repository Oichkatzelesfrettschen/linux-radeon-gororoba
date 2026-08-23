#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Calibration for replay_r300_cs_track over a retained cell bundle.
#
# The controls split into two classes the replay must keep apart.  A
# parser-invalid stream breaks the command-stream grammar, the safe-register
# rule, the relocation protocol, or a buffer bound, and the kernel-derived
# parser rejects it.  A semantically blank stream is well formed and passes the
# parser while writing no color: the three gates measured on RS482 --
# US_OUT_FMT_0 unused, COLOR_CHANNEL_MASK zero, SC_SCREENDOOR zero -- each
# suppress every color write while leaving the stream legal.  Reporting a blank
# stream as a parser defect would attribute a first-draw state failure to
# command-stream validation, so the two classes are asserted separately.
#
# Usage: run_r300_cs_track_controls.sh <replay-tool> <bundle.txt> <ib.bin>

set -eu

tool="$1"
bundle="$2"
ib="$3"
failures=0

# The dword index of each register payload the controls rewrite, found by
# walking the stream rather than hardcoded, so a cell whose layout moves keeps
# its controls.
find_payload() {
    reg="$1"
    python3 - "$ib" "$reg" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
reg = int(sys.argv[2], 0)
words = struct.unpack('<%dI' % (len(data) // 4), data)
i = 0
while i < len(words):
    header = words[i]
    ptype = (header >> 30) & 3
    count = (header >> 16) & 0x3FFF
    if ptype == 0:
        base = (header & 0x1FFF) << 2
        one_reg = (header >> 15) & 1
        for k in range(count + 1):
            here = base if one_reg else base + 4 * k
            if here == reg:
                print(i + 1 + k)
                sys.exit(0)
    i += count + 2
sys.exit(1)
PY
}

expect() {
    want="$1"
    label="$2"
    shift 2
    if "$@" >/dev/null 2>&1; then
        got=accept
    else
        rc=$?
        if [ "${rc}" -eq 1 ]; then
            got=reject
        else
            got="error(${rc})"
        fi
    fi
    if [ "${got}" = "${want}" ]; then
        printf '  %-46s %s\n' "${label}" "${got}"
    else
        printf '  %-46s %s, %s expected\n' "${label}" "${got}" "${want}"
        failures=$((failures + 1))
    fi
}

echo "known-good:"
expect accept "the retained cell" "${tool}" "${bundle}" "${ib}"

echo "parser-invalid controls:"
# A truncated stream leaves a packet running past the chunk end.
expect reject "truncated stream" \
    "${tool}" --truncate 5 "${bundle}" "${ib}"
# A packet count reaching past the chunk end.
expect reject "packet count past the chunk end" \
    "${tool}" --set-dword "0=0x3fff0000" "${bundle}" "${ib}"
# Packet type 1 has no grammar.
expect reject "unknown packet type" \
    "${tool}" --set-dword "0=0x40000000" "${bundle}" "${ib}"
# A type-3 opcode the parser does not handle.
expect reject "unknown packet3 opcode" \
    "${tool}" --set-dword "0=0xc0007f00" "${bundle}" "${ib}"
# A register the safe bitmap flags and r300_packet0_check does not name
# reaches the switch's default arm, which is a rejection.  0x2100 is flagged
# and unnamed; the header keeps the original packet's one-payload framing, so
# only the register changes.
expect reject "forbidden register" \
    "${tool}" --set-dword "0=0x00000840" "${bundle}" "${ib}"
# A register the bitmap does not flag is written through unvalidated, which is
# the arm that separates "forbidden" from "unchecked".
expect accept "unflagged register passes unchecked" \
    "${tool}" --set-dword "0=0x00001392" "${bundle}" "${ib}"
# The relocation payload past the relocation chunk.
reloc_payload=$(python3 - "$ib" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
words = struct.unpack('<%dI' % (len(data) // 4), data)
for i, w in enumerate(words):
    if w == 0xC0001000:
        print(i + 1)
        break
PY
)
expect reject "reloc index past the relocation chunk" \
    "${tool}" --set-dword "${reloc_payload}=64" "${bundle}" "${ib}"
# The NOP that must follow a consuming packet replaced by a plain type-2 NOP.
expect reject "missing relocation NOP" \
    "${tool}" --set-dword "$((reloc_payload - 1))=0x80000000" \
    "${bundle}" "${ib}"
# A color buffer one byte too small for pitch * cpp * maxy.
expect reject "color buffer one byte too small" \
    "${tool}" --set-bo-size "1=16383" "${bundle}" "${ib}"
expect accept "color buffer exactly large enough" \
    "${tool}" --set-bo-size "1=16384" "${bundle}" "${ib}"
# A vertex buffer one byte too small for esize * max_indx * 4, the bound
# r100_cs_track_check applies to each array: esize is the 3D_LOAD_VBPNTR
# stride in dwords and max_indx the VAP_VF_MAX_VTX_INDX payload, both read
# from the stream so a cell with a wider record keeps its controls.
vertex_bound=$(python3 - "$ib" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
words = struct.unpack('<%dI' % (len(data) // 4), data)
esize = None
max_indx = None
i = 0
while i < len(words):
    header = words[i]
    ptype = (header >> 30) & 3
    count = (header >> 16) & 0x3FFF
    if ptype == 0:
        base = (header & 0x1FFF) << 2
        one_reg = (header >> 15) & 1
        for k in range(count + 1):
            here = base if one_reg else base + 4 * k
            if here == 0x2134:
                max_indx = words[i + 1 + k]
    elif ptype == 3 and (header & 0xFF00) == 0x2F00:
        esize = (words[i + 2] >> 8) & 0xFF
    i += count + 2
if esize is None or max_indx is None:
    sys.exit(1)
print(esize * max_indx * 4)
PY
)
expect reject "vertex buffer one byte too small" \
    "${tool}" --set-bo-size "0=$((vertex_bound - 1))" "${bundle}" "${ib}"
expect accept "vertex buffer exactly large enough" \
    "${tool}" --set-bo-size "0=${vertex_bound}" "${bundle}" "${ib}"
# A vertex width below what the output format requires.
expect reject "VAP_VTX_SIZE below the output width" \
    "${tool}" --set-vtx-size 3 "${bundle}" "${ib}"

echo "parser-valid, semantically blank controls:"
# Each of these suppresses every color write on RS482 while leaving the
# command stream legal, so the parser accepts them and the first-draw state
# contract is what rejects them.
mask=$(find_payload 0x4E0C)
expect accept "RB3D_COLOR_CHANNEL_MASK = 0" \
    "${tool}" --set-dword "${mask}=0" "${bundle}" "${ib}"
screendoor=$(find_payload 0x43E8)
if [ -n "${screendoor}" ]; then
    expect accept "SC_SCREENDOOR = 0" \
        "${tool}" --set-dword "${screendoor}=0" "${bundle}" "${ib}"
fi
us_out_fmt=$(find_payload 0x46A4)
if [ -n "${us_out_fmt}" ]; then
    expect accept "US_OUT_FMT_0 unused" \
        "${tool}" --set-dword "${us_out_fmt}=0x0000000f" "${bundle}" "${ib}"
fi

if [ "${failures}" -ne 0 ]; then
    echo "run_r300_cs_track_controls: ${failures} controls did not hold" >&2
    exit 1
fi
echo "run_r300_cs_track_controls: every control held"
