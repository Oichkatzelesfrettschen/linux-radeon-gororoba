#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Calibration for the legacy 2D destination containment in
# replay_r300_cs_track, over streams built here from raw packet words and
# explicit buffer-object sizes.
#
# r100_cs_track_2d_dst_check bounds the rectangle a DST_WIDTH_HEIGHT write
# launches against the relocation-backed object DST_PITCH_OFFSET named, so
# every control below is a stream of PACKET0 words this script assembles
# itself: the register numbers, the field packing, the relocation NOP, and
# the object sizes are stated here rather than taken from the client that
# emits such streams.  The known-good stream is the 38-dword solid fill
# (pitch 256, ARGB8888, three rectangles) and an optional third argument
# names a retained ib.bin the assembled stream must match byte for byte.
#
# Usage: run_r300_cs_2d_dst_controls.sh <replay-tool> <workdir> [reference-ib.bin]
#
# Exit 0 when every control holds, 1 when one does not.

set -eu

tool="$1"
work="$2"
reference="${3:-}"
failures=0
mkdir -p "${work}"

bundle="${work}/bundle.txt"
cat > "${bundle}" <<'BUNDLE'
family rs480
bo 0 role=destination size=65536 read_domains=0x0 write_domain=0x2
bo 1 role=completion size=4 read_domains=0x0 write_domain=0x2
bo 2 role=source size=65536 read_domains=0x1 write_domain=0x0
BUNDLE

# assemble <out> <spec>: the spec is a whitespace-separated list of
# operations, each producing the words named:
#   pitch_offset=PITCH,OFFSET[,RELOC]  DST_PITCH_OFFSET (pitch and offset in
#                                       bytes) then the relocation NOP naming
#                                       chunk dword RELOC*4 (RELOC omitted:
#                                       no NOP at all)
#   src_pitch_offset=PITCH,OFFSET[,RELOC]
#                                       SRC_PITCH_OFFSET and its relocation
#   scissor                             SC_TOP_LEFT 0, SC_BOTTOM_RIGHT and
#                                       DEFAULT_SC_BOTTOM_RIGHT 0x1fff1fff
#   scissor=WORD                        the two bottom-right words = WORD
#   master=DATATYPE[,nocntl][,src][,usesource]
#                                       DP_GUI_MASTER_CNTL for a solid brush;
#                                       src selects memory source and usesource
#                                       selects ROP3 S for source-read tests
#   walk                                DP_CNTL left-to-right, top-to-bottom
#   mask                                DP_WRITE_MSK all lanes
#   brush=COLOR                         DP_BRUSH_FRGD_CLR
#   srcyx=X,Y                           SRC_Y_X source origin
#   rect=X,Y,W,H                        DST_Y_X then DST_WIDTH_HEIGHT
#   exarect=X,Y,W,H                     DST_Y_X then DST_HEIGHT_WIDTH, the
#                                       height-high launch the X EXA
#                                       driver writes
#   yx=X,Y                              DST_Y_X alone
#   wh=W,H                              DST_WIDTH_HEIGHT alone
#   line=X0,Y0,X1,Y1                    DST_LINE_START then DST_LINE_END
#   flush                               DSTCACHE_CTLSTAT flush-all
#   wait                                WAIT_UNTIL 2D, host, and DMA idle
assemble() {
    python3 - "$@" <<'PY'
import struct, sys
out = sys.argv[1]
ops = sys.argv[2].split()
REG = {"SRC_PITCH_OFFSET": 0x1428, "SRC_Y_X": 0x1434,
       "DST_PITCH_OFFSET": 0x142C, "SC_TOP_LEFT": 0x16EC,
       "SC_BOTTOM_RIGHT": 0x16F0, "DEFAULT_SC_BOTTOM_RIGHT": 0x16E8,
       "DP_GUI_MASTER_CNTL": 0x146C, "DP_CNTL": 0x16C0,
       "DP_WRITE_MSK": 0x16CC, "DP_BRUSH_FRGD_CLR": 0x147C,
       "DST_Y_X": 0x1438, "DST_WIDTH_HEIGHT": 0x1598,
       "DST_HEIGHT_WIDTH": 0x143C, "DST_LINE_START": 0x1600,
       "DST_LINE_END": 0x1604,
       "DSTCACHE_CTLSTAT": 0x1714, "WAIT_UNTIL": 0x1720}
words = []
def pkt0(reg, value):
    words.append((0 << 30) | (0 << 16) | (REG[reg] >> 2))
    words.append(value & 0xffffffff)
for op in ops:
    name, _, arg = op.partition("=")
    a = arg.split(",") if arg else []
    if name in ("pitch_offset", "src_pitch_offset"):
        pitch, offset = int(a[0], 0), int(a[1], 0)
        register = "DST_PITCH_OFFSET" if name == "pitch_offset" else "SRC_PITCH_OFFSET"
        pkt0(register, ((pitch >> 6) << 22) | (offset >> 10))
        if len(a) > 2:
            words.append((3 << 30) | (0 << 16) | (0x10 << 8))
            words.append(int(a[2], 0) * 4)
    elif name == "scissor":
        word = int(a[0], 0) if a else 0x1fff1fff
        pkt0("SC_TOP_LEFT", 0)
        pkt0("SC_BOTTOM_RIGHT", word)
        pkt0("DEFAULT_SC_BOTTOM_RIGHT", word)
    elif name == "master":
        datatype = int(a[0], 0)
        cntl = 0 if len(a) > 1 and a[1] == "nocntl" else (1 << 1)
        if "src" in a[1:]:
            cntl |= 2 << 24
            if "nocntl" not in a[1:]:
                cntl |= 1
        rop = 0x00cc0000 if "usesource" in a[1:] else 0x00f00000
        pkt0("DP_GUI_MASTER_CNTL", cntl | (13 << 4) | (datatype << 8) |
             rop | (1 << 28) | (1 << 30))
    elif name == "walk":
        pkt0("DP_CNTL", 3)
    elif name == "walkrev":
        pkt0("DP_CNTL", 0)
    elif name == "mask":
        pkt0("DP_WRITE_MSK", 0xffffffff)
    elif name == "srcyx":
        x, y = (int(v, 0) for v in a)
        pkt0("SRC_Y_X", (y << 16) | x)
    elif name == "brush":
        pkt0("DP_BRUSH_FRGD_CLR", int(a[0], 0))
    elif name == "rect":
        x, y, w, h = (int(v, 0) for v in a)
        pkt0("DST_Y_X", (y << 16) | x)
        pkt0("DST_WIDTH_HEIGHT", (w << 16) | h)
    elif name == "exarect":
        x, y, w, h = (int(v, 0) for v in a)
        pkt0("DST_Y_X", (y << 16) | x)
        pkt0("DST_HEIGHT_WIDTH", (h << 16) | w)
    elif name == "line":
        x0, y0, x1, y1 = (int(v, 0) for v in a)
        pkt0("DST_LINE_START", (y0 << 16) | x0)
        pkt0("DST_LINE_END", (y1 << 16) | x1)
    elif name == "yx":
        x, y = (int(v, 0) for v in a)
        pkt0("DST_Y_X", (y << 16) | x)
    elif name == "wh":
        w, h = (int(v, 0) for v in a)
        pkt0("DST_WIDTH_HEIGHT", (w << 16) | h)
    elif name == "flush":
        pkt0("DSTCACHE_CTLSTAT", 0xf)
    elif name == "wait":
        pkt0("WAIT_UNTIL", (1 << 9) | (1 << 16) | (1 << 18))
    else:
        sys.exit("unknown op " + op)
open(out, "wb").write(struct.pack("<%dI" % len(words), *words))
PY
}

# expect <accept|reject> <label> <reason-substring-or-empty> <ib> [tool args]
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
        printf '  %-58s %s\n' "${label}" "${got}"
    else
        printf '  %-58s %s, %s expected%s\n' "${label}" "${got}" "${want}" \
            "${reason:+ with '${reason}'}"
        printf '%s\n' "${out}" | sed 's/^/      /'
        failures=$((failures + 1))
    fi
}

prologue="pitch_offset=256,0,0 scissor master=6 walk mask"
epilogue="flush wait"

copy_prologue="pitch_offset=256,0,0 src_pitch_offset=256,0,2 srcyx=0,0 scissor master=6,src,usesource walk mask"

echo "known-good:"
assemble "${work}/exact.bin" \
    "${prologue} brush=0x11223344 rect=3,0,61,1 brush=0x11223344 rect=0,1,64,18 brush=0x11223344 rect=0,19,35,1 ${epilogue}"
ndw=$(($(wc -c < "${work}/exact.bin") / 4))
if [ "${ndw}" -eq 38 ]; then
    echo "  assembled stream is 38 dwords"
else
    echo "  assembled stream is ${ndw} dwords, 38 expected"
    failures=$((failures + 1))
fi
if [ -n "${reference}" ]; then
    if cmp -s "${work}/exact.bin" "${reference}"; then
        echo "  assembled stream matches ${reference} byte for byte"
    else
        echo "  assembled stream differs from ${reference}"
        failures=$((failures + 1))
    fi
fi
expect accept "exact 38-dword stream" "" "${work}/exact.bin"
expect accept "exact stream, verbose footprint" "end 5004 within 65536" \
    "${work}/exact.bin" --verbose

echo "memory-source containment:"
assemble "${work}/copy.bin" \
    "${copy_prologue} rect=0,0,64,1 ${epilogue}"
expect accept "memory source copy inside both objects" "2D source 64x1" \
    "${work}/copy.bin" --verbose
assemble "${work}/copy-source-past.bin" \
    "${copy_prologue} srcyx=0,256 rect=0,0,64,1 ${epilogue}"
expect reject "source row past the source object" \
    "2D source rectangle past the buffer object" "${work}/copy-source-past.bin"
assemble "${work}/copy-source-small.bin" \
    "${copy_prologue} rect=0,0,64,1 ${epilogue}"
expect reject "source object undersized" \
    "2D source rectangle past the buffer object" "${work}/copy-source-small.bin" \
    --set-bo-size 2=252
assemble "${work}/copy-source-no-reloc.bin" \
    "pitch_offset=256,0,0 src_pitch_offset=256,0 srcyx=0,0 scissor master=6,src walk mask rect=0,0,1,1 ${epilogue}"
expect reject "missing source relocation" "no packet3 NOP" \
    "${work}/copy-source-no-reloc.bin"
assemble "${work}/copy-source-no-control.bin" \
    "pitch_offset=256,0,0 scissor master=6,nocntl,src,usesource walk mask rect=0,0,1,1 ${epilogue}"
expect reject "memory source without pitch control" \
    "2D memory source lacks SRC_PITCH_OFFSET control" \
    "${work}/copy-source-no-control.bin"
assemble "${work}/copy-source-selection-after-binding.bin" \
    "pitch_offset=256,0,0 src_pitch_offset=256,0,2 srcyx=0,0 scissor master=6 master=6,nocntl,src,usesource walk mask rect=0,0,1,1 ${epilogue}"
expect reject "memory source selected after source binding" \
    "2D memory source lacks SRC_PITCH_OFFSET control" \
    "${work}/copy-source-selection-after-binding.bin"
assemble "${work}/copy-source-before-origin.bin" \
    "pitch_offset=256,0,0 src_pitch_offset=256,0,2 scissor master=6,src walk mask rect=0,0,1,1 ${epilogue}"
expect reject "source launch before SRC_Y_X" \
    "2D source geometry before SRC_PITCH_OFFSET" \
    "${work}/copy-source-before-origin.bin"
assemble "${work}/copy-source-overflow.bin" \
    "pitch_offset=256,0,0 src_pitch_offset=256,0xfffffc00,2 srcyx=0,5 scissor master=6,src walk mask rect=0,0,1,1 ${epilogue}"
expect reject "source base plus row overflows the surface" \
    "2D source footprint overflows" "${work}/copy-source-overflow.bin"
assemble "${work}/copy-reverse.bin" \
    "pitch_offset=256,0,0 src_pitch_offset=256,0,2 srcyx=63,0 scissor master=6,src walkrev mask rect=63,0,64,1 ${epilogue}"
expect accept "reverse memory source copy preserves the footprint" "" \
    "${work}/copy-reverse.bin"
assemble "${work}/copy-reverse-underflow.bin" \
    "${copy_prologue} srcyx=0,0 walkrev rect=0,0,2,1 ${epilogue}"
expect reject "reverse source x underflow" \
    "2D source reverse direction starts before the surface" \
    "${work}/copy-reverse-underflow.bin"
expect accept "exact stream binds the destination object by relocation" \
    "DST_PITCH_OFFSET: reloc cursor 2 -> entry 0 (destination) size 65536 base 0 pitch 256" \
    "${work}/exact.bin" --verbose
assemble "${work}/exact-exa.bin" \
    "${prologue} brush=0x11223344 exarect=3,0,61,1 brush=0x11223344 exarect=0,1,64,18 brush=0x11223344 exarect=0,19,35,1 ${epilogue}"
expect accept "the same fill launched through DST_HEIGHT_WIDTH" \
    "end 5004 within 65536" "${work}/exact-exa.bin" --verbose

echo "destination containment (REJECT):"
# The last row of the object: y 255 at pitch 256 fills bytes 65280..65535.
assemble "${work}/last-row.bin" "${prologue} rect=0,255,64,1 ${epilogue}"
expect accept "last row ends exactly at the object end" "" \
    "${work}/last-row.bin"
assemble "${work}/x-past.bin" "${prologue} rect=1,255,63,1 ${epilogue}"
expect accept "x 1, width 63 on the last row ends at the object end" "" \
    "${work}/x-past.bin"
expect reject "x moves the last byte one dword beyond the object" \
    "rectangle past the buffer object" "${work}/x-past.bin" \
    --set-bo-size 0=65532
assemble "${work}/y-past.bin" "${prologue} rect=0,256,64,1 ${epilogue}"
expect reject "y moves the last row beyond the object" \
    "rectangle past the buffer object" "${work}/y-past.bin"
assemble "${work}/width-pitch.bin" "${prologue} rect=0,0,65,1 ${epilogue}"
expect reject "width overruns the pitch" \
    "width overruns the pitch" "${work}/width-pitch.bin"
assemble "${work}/x-pitch.bin" "${prologue} rect=64,0,1,1 ${epilogue}"
expect reject "x starts past the pitch" \
    "x starts past the pitch" "${work}/x-pitch.bin"
assemble "${work}/height-full.bin" "${prologue} rect=0,0,64,256 ${epilogue}"
expect accept "height 256 fills the object exactly" "" \
    "${work}/height-full.bin"
assemble "${work}/height-past.bin" "${prologue} rect=0,0,64,257 ${epilogue}"
expect reject "height overruns the object" \
    "rectangle past the buffer object" "${work}/height-past.bin"
# The offset field is 22 bits of 1 KiB units, so its maximum base sits
# 1 KiB below the 32-bit surface top and one row past it wraps.
assemble "${work}/base-overflow.bin" \
    "pitch_offset=256,0xfffffc00,0 scissor master=6 walk mask rect=0,4,1,1 ${epilogue}"
expect reject "base + row arithmetic overflows the 32-bit surface" \
    "overflows the 32-bit surface address" "${work}/base-overflow.bin"
assemble "${work}/xw-saturated.bin" \
    "${prologue} rect=0xffff,0,0xffff,1 ${epilogue}"
expect reject "x + width saturating both 16-bit fields" \
    "x starts past the pitch" "${work}/xw-saturated.bin"
assemble "${work}/no-reloc.bin" \
    "pitch_offset=256,0 scissor master=6 walk mask rect=0,0,1,1 ${epilogue}"
expect reject "missing destination relocation" "no packet3 NOP" \
    "${work}/no-reloc.bin"
assemble "${work}/cpp-unknown.bin" \
    "pitch_offset=256,0,0 scissor master=0 walk mask rect=0,0,1,1 ${epilogue}"
expect reject "unsupported destination datatype (code 0)" \
    "unsupported 2D destination datatype" "${work}/cpp-unknown.bin"
assemble "${work}/cpp-rgb8.bin" \
    "pitch_offset=256,0,0 scissor master=9 walk mask rect=5,0,3,1 ${epilogue}"
expect reject "RGB8 datatype 9 destination launch" \
    "unsupported 2D destination datatype" "${work}/cpp-rgb8.bin"
assemble "${work}/cpp-ci8.bin" \
    "pitch_offset=256,0,0 scissor master=2 walk mask rect=5,0,3,1 ${epilogue}"
expect accept "CI8 pseudocolor datatype 2 destination launch" "" \
    "${work}/cpp-ci8.bin"
assemble "${work}/before-pitch.bin" \
    "scissor master=6 walk mask rect=0,0,1,1 pitch_offset=256,0,0 ${epilogue}"
expect reject "geometry before DST_PITCH_OFFSET" \
    "geometry before DST_PITCH_OFFSET" "${work}/before-pitch.bin"
assemble "${work}/before-master.bin" \
    "pitch_offset=256,0,0 scissor walk mask rect=0,0,1,1 master=6 ${epilogue}"
expect reject "geometry before DP_GUI_MASTER_CNTL" \
    "geometry before DST_PITCH_OFFSET" "${work}/before-master.bin"
assemble "${work}/before-yx.bin" \
    "${prologue} wh=1,1 yx=0,0 ${epilogue}"
expect reject "launch before DST_Y_X" \
    "geometry before DST_PITCH_OFFSET" "${work}/before-yx.bin"
assemble "${work}/default-pitch.bin" \
    "pitch_offset=256,0,0 scissor master=6,nocntl walk mask rect=0,0,1,1 ${epilogue}"
expect reject "destination taken from DEFAULT_PITCH_OFFSET" \
    "DEFAULT_PITCH_OFFSET" "${work}/default-pitch.bin"
assemble "${work}/pitch-zero.bin" \
    "pitch_offset=0,0,0 scissor master=6 walk mask rect=0,0,1,1 ${epilogue}"
expect reject "pitch 0" "2D destination pitch 0" "${work}/pitch-zero.bin"
assemble "${work}/empty.bin" "${prologue} rect=0,0,0,1 ${epilogue}"
expect reject "width 0" "empty 2D destination rectangle" "${work}/empty.bin"
# One ARGB8888 pixel fits the 4-byte completion object exactly; the second
# pixel is the one that leaves it.
assemble "${work}/wrong-object-fit.bin" \
    "pitch_offset=256,0,1 scissor master=6 walk mask rect=0,0,1,1 ${epilogue}"
expect accept "one pixel into the 4-byte completion object" "" \
    "${work}/wrong-object-fit.bin"
assemble "${work}/wrong-object.bin" \
    "pitch_offset=256,0,1 scissor master=6 walk mask rect=0,0,2,1 ${epilogue}"
expect reject "two pixels into the 4-byte completion object" \
    "rectangle past the buffer object" "${work}/wrong-object.bin"
# The bound came from the object the relocation consumed: the trace names
# entry 1, the completion role, and its 4-byte size at the binding.
expect reject "completion-object arm binds entry 1 at size 4" \
    "DST_PITCH_OFFSET: reloc cursor 2 -> entry 1 (completion) size 4 base 0 pitch 256" \
    "${work}/wrong-object.bin" --verbose
assemble "${work}/retained-into-completion.bin" \
    "pitch_offset=256,0,1 scissor master=6 walk mask brush=0x11223344 rect=3,0,61,1 brush=0x11223344 rect=0,1,64,18 brush=0x11223344 rect=0,19,35,1 ${epilogue}"
expect reject "retained rectangles into the completion object" \
    "rectangle past the buffer object" \
    "${work}/retained-into-completion.bin"
expect reject "destination object undersized (1024 bytes)" \
    "rectangle past the buffer object" "${work}/exact.bin" \
    --set-bo-size 0=1024
assemble "${work}/exa-past.bin" "${prologue} exarect=0,256,64,1 ${epilogue}"
expect reject "DST_HEIGHT_WIDTH launch past the object" \
    "rectangle past the buffer object" "${work}/exa-past.bin"
assemble "${work}/exa-before-state.bin" \
    "scissor master=6 walk mask exarect=0,0,1,1 pitch_offset=256,0,0 ${epilogue}"
expect reject "DST_HEIGHT_WIDTH launch before DST_PITCH_OFFSET" \
    "geometry before DST_PITCH_OFFSET" "${work}/exa-before-state.bin"
assemble "${work}/line.bin" "${prologue} line=0,0,63,0 ${epilogue}"
expect reject "line launch through DST_LINE_START/END is forbidden" \
    "forbidden register 0x1600" "${work}/line.bin"

echo "outside the kernel's bound (ACCEPT; the client owns these):"
assemble "${work}/past-scissor.bin" \
    "pitch_offset=256,0,0 scissor=0x00100010 master=6 walk mask rect=0,32,64,1 ${epilogue}"
expect accept "rectangle past the 2D scissor but inside the object" "" \
    "${work}/past-scissor.bin"
assemble "${work}/wide-scissor.bin" \
    "pitch_offset=256,0,0 scissor=0x3fff3fff master=6 walk mask rect=0,0,1,1 ${epilogue}"
expect accept "scissor widened past 0x1fff" "" "${work}/wide-scissor.bin"
assemble "${work}/no-wait.bin" "${prologue} rect=0,0,1,1 flush"
expect accept "stream ending before the final wait" "" "${work}/no-wait.bin"
assemble "${work}/cpp2.bin" \
    "pitch_offset=256,0,0 scissor master=4 walk mask rect=0,255,128,1 ${epilogue}"
expect accept "RGB565 fills 128 pixels of a 256-byte row" "" "${work}/cpp2.bin"
assemble "${work}/cpp2-past.bin" \
    "pitch_offset=256,0,0 scissor master=4 walk mask rect=0,255,129,1 ${epilogue}"
expect reject "RGB565 pixel 129 overruns the pitch" \
    "width overruns the pitch" "${work}/cpp2-past.bin"

if [ "${failures}" -ne 0 ]; then
    echo "run_r300_cs_2d_dst_controls: ${failures} controls did not hold" >&2
    exit 1
fi
echo "run_r300_cs_2d_dst_controls: every control held"
