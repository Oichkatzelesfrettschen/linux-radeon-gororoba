#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Calibration for the vertex-array footprint bound in replay_r300_cs_track,
# over streams assembled here from raw packet words and explicit buffer-object
# sizes.
#
# 3D_LOAD_VBPNTR carries a byte offset in each array's address dword, and the
# parser adds it to the relocated object's base.  r100_cs_track_check bounds
# (u64)offset + esize * max_indx * 4 against the array object's size.
#
# Usage: run_r300_cs_vbpntr_controls.sh <replay-tool> <workdir>
#
# Exit 0 when every control holds, 1 when one does not.

set -eu

tool="$1"
work="$2"
failures=0
mkdir -p "${work}"

# One array of esize 4 dwords with VAP_VF_MAX_VTX_INDX 15 needs
# 4 * 15 * 4 = 240 bytes.
bundle="${work}/vbpntr-bundle.txt"
cat > "${bundle}" <<'BUNDLE'
family rs480
bo 0 role=color size=16384 read_domains=0x0 write_domain=0x2
bo 1 role=vertex size=256 read_domains=0x0 write_domain=0x2
BUNDLE

# assemble <out> <array_offset> [pairs]: a color target, one (or, with
# pairs=2, two) vertex arrays at the given byte offset, and one indexed draw.
assemble() {
    python3 - "$@" <<'PY'
import struct, sys
out = sys.argv[1]
offset = int(sys.argv[2], 0)
two = len(sys.argv) > 3 and sys.argv[3] == "2"
words = []
def pkt0(reg, value):
    words.extend([reg >> 2, value & 0xffffffff])
def reloc(idx):
    words.extend([(3 << 30) | (0x10 << 8), idx * 4])
pkt0(0x4F00, 0)                  # ZB_CNTL: no depth enable
pkt0(0x4E00, 0)                  # RB3D_CCTL: one color buffer
pkt0(0x20B4, 4)                  # VAP_VTX_SIZE
pkt0(0x4E38, 0x00C00000 | 4)     # COLORPITCH0
pkt0(0x4E28, 0)                  # COLOROFFSET0
reloc(0)
pkt0(0x2134, 15)                 # VAP_VF_MAX_VTX_INDX
esize = 4
if two:
    # count 2; pair word carries esize0 at bits 8..14 and esize1 at 24..30
    words.extend([(3 << 30) | (3 << 16) | (0x2F << 8), 2,
                  (esize << 8) | (esize << 24), offset, 0])
    reloc(1)
    reloc(1)
else:
    words.extend([(3 << 30) | (2 << 16) | (0x2F << 8), 1,
                  esize << 8, offset])
    reloc(1)
words.extend([(3 << 30) | (0x36 << 8), 0x10])   # DRAW_INDX_2, PRIM_WALK 1
open(out, "wb").write(struct.pack("<%dI" % len(words), *words))
PY
}

expect() {
    want="$1"
    label="$2"
    reason="$3"
    ib="$4"
    shift 4
    out=$("${tool}" "$@" "${bundle}" "${ib}" 2>&1) && rc=0 || rc=$?
    case "${rc}" in
        0) got=accept ;;
        1) got=reject ;;
        *) got="error(${rc})" ;;
    esac
    if [ "${got}" = "${want}" ] && { [ -z "${reason}" ] ||
            printf '%s\n' "${out}" | grep -qF -- "${reason}"; }; then
        printf '  %-52s %s\n' "${label}" "${got}"
    else
        printf '  %-52s %s, %s expected%s\n' "${label}" "${got}" "${want}" \
            "${reason:+ with '${reason}'}"
        printf '%s\n' "${out}" | sed 's/^/      /'
        failures=$((failures + 1))
    fi
}

echo "vertex array footprint (need 240 bytes, BO size 256):"
assemble "${work}/off0.bin" 0
expect accept "offset 0" "" "${work}/off0.bin"
assemble "${work}/off16.bin" 16
expect accept "offset 16, footprint ends at BO end" "" "${work}/off16.bin"
assemble "${work}/off17.bin" 17
expect reject "offset 17, footprint one byte past BO" \
    "vertex array 0 need 60 dwords" "${work}/off17.bin"
assemble "${work}/off-far.bin" 0xfffffff0
expect reject "offset near 0xffffffff does not wrap" \
    "vertex array 0 need" "${work}/off-far.bin"
expect reject "offset 0, object shrunk to 239 bytes" "need 60 dwords" \
    "${work}/off0.bin" --set-bo-size 1=239
assemble "${work}/two-ok.bin" 0 2
expect accept "two arrays, second offset 0" "" "${work}/two-ok.bin"
expect reject "two arrays, second offset 17" "vertex array 1" \
    "${work}/two-ok.bin" --set-dword 18=17

if [ "${failures}" -ne 0 ]; then
    echo "run_r300_cs_vbpntr_controls: ${failures} controls did not hold" >&2
    exit 1
fi
echo "run_r300_cs_vbpntr_controls: every control held"
