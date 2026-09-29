#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Calibration for the ZB_ZPASS_ADDR store bound and the depth footprint gate
# in replay_r300_cs_track, over streams assembled here from raw packet words
# and explicit buffer-object sizes.
#
# r300_packet0_check bounds ZB_ZPASS_ADDR by (u64)offset + 4 <= the relocated
# object's size, because the occlusion counter stores one dword there.
# r100_cs_track_check bounds pitch * cpp * maxy + offset against the depth
# object whenever ZB_CNTL enables stencil, test, or write.
#
# Usage: run_r300_cs_zb_controls.sh <replay-tool> <workdir>
#
# Exit 0 when every control holds, 1 when one does not.

set -eu

tool="$1"
work="$2"
failures=0
mkdir -p "${work}"

# Depth footprint at ZB_DEPTHOFFSET 0 is pitch 16 * cpp 4 * maxy 4096 =
# 262144 bytes (ZB_DEPTHPITCH 32 decodes to pitch 16); the replay's initial
# maxy is 4096.
bundle="${work}/bundle.txt"
cat > "${bundle}" <<'BUNDLE'
family rs480
bo 0 role=color size=16384 read_domains=0x0 write_domain=0x2
bo 1 role=depth size=262144 read_domains=0x0 write_domain=0x2
bo 2 role=zpass size=64 read_domains=0x0 write_domain=0x2
BUNDLE

# assemble <out> <zb_cntl> [zpass_offset]: one immediate draw into color
# object 0 with depth object 1 bound; a zpass offset appends ZB_ZPASS_ADDR
# against object 2.
assemble() {
    python3 - "$@" <<'PY'
import struct, sys
out = sys.argv[1]
zb_cntl = int(sys.argv[2], 0)
zpass = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
words = []
def pkt0(reg, value):
    words.extend([reg >> 2, value & 0xffffffff])
def reloc(idx):
    words.extend([(3 << 30) | (0x10 << 8), idx * 4])
pkt0(0x4F00, zb_cntl)            # ZB_CNTL
pkt0(0x4F10, 0)                  # ZB_FORMAT: 32-bit depth
pkt0(0x4F24, 32)                 # ZB_DEPTHPITCH
pkt0(0x4F20, 0)                  # ZB_DEPTHOFFSET
reloc(1)
pkt0(0x4E00, 0)                  # RB3D_CCTL: one color buffer
pkt0(0x20B4, 1)                  # VAP_VTX_SIZE
pkt0(0x4E38, 0x00C00000 | 4)     # COLORPITCH0
pkt0(0x4E28, 0)                  # COLOROFFSET0
reloc(0)
if zpass is not None:
    pkt0(0x4F5C, zpass)          # ZB_ZPASS_ADDR
    reloc(2)
words.extend([(3 << 30) | (1 << 16) | (0x35 << 8), 0x00010030, 0])
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

echo "depth footprint gate (ZB_CNTL: stencil=1 test=2 write=4):"
assemble "${work}/test.bin" 2
expect accept "test enable, depth object exact (regression)" "" "${work}/test.bin"
expect reject "test enable, depth object one byte short" \
    "buffer too small for z buffer" "${work}/test.bin" --set-bo-size 1=262143
assemble "${work}/stencil.bin" 1
expect accept "stencil-only enable, depth object exact" "" "${work}/stencil.bin"
expect reject "stencil-only enable, undersized depth object" \
    "buffer too small for z buffer" "${work}/stencil.bin" --set-bo-size 1=16
assemble "${work}/write.bin" 4
expect accept "write-only enable, depth object exact" "" "${work}/write.bin"
expect reject "write-only enable, undersized depth object" \
    "buffer too small for z buffer" "${work}/write.bin" --set-bo-size 1=16
assemble "${work}/off.bin" 0
expect accept "all depth enables clear, undersized object" "" \
    "${work}/off.bin" --set-bo-size 1=16

echo "ZB_ZPASS_ADDR store bound (BO size 64):"
assemble "${work}/zp-last.bin" 2 60
expect accept "offset = size - 4" "" "${work}/zp-last.bin"
assemble "${work}/zp-m3.bin" 2 61
expect reject "offset = size - 3" "ZB_ZPASS_ADDR offset 0x0000003D out of range" \
    "${work}/zp-m3.bin"
assemble "${work}/zp-size.bin" 2 64
expect reject "offset = size" "ZB_ZPASS_ADDR offset 0x00000040 out of range" \
    "${work}/zp-size.bin"
assemble "${work}/zp-wrap.bin" 2 0xfffffffe
expect reject "offset near 0xffffffff does not wrap" \
    "ZB_ZPASS_ADDR offset 0xFFFFFFFE out of range" "${work}/zp-wrap.bin"
expect reject "size - 4 offset, object shrunk by one byte" "out of range" \
    "${work}/zp-last.bin" --set-bo-size 2=63

if [ "${failures}" -ne 0 ]; then
    echo "run_r300_cs_zb_controls: ${failures} controls did not hold" >&2
    exit 1
fi
echo "run_r300_cs_zb_controls: every control held"
