#!/bin/sh
# Reason-coded census of the TCL-bypass vertex-underfeed decision over a corpus
# of retained PM4 indirect buffers. Builds replay_r300_tcl_bypass_ib with the
# same r300_tcl_bypass_vtx_check.h the kernel compiles, runs it in --reasons
# mode over every *.bin under the corpus root, and tabulates the verdict split,
# the first-decline-reason histogram, and the full-identity-EXT subset. The
# census measures how much of a real corpus reaches the REJECT/PASS decision
# rather than declining on an unwitnessed premise.
#
# usage: rad06_corpus_reason_census.sh CORPUS_ROOT
set -eu

corpus=${1:-}
if [ -z "$corpus" ] || [ ! -d "$corpus" ]; then
	echo "usage: $0 CORPUS_ROOT" >&2
	exit 2
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
header_dir="$repo_root/drivers/gpu/drm/radeon"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
replay="$work/replay_r300_tcl_bypass_ib"
raw="$work/reasons.txt"

cc -O2 -Wall -Wextra -I "$header_dir" \
	"$repo_root/scripts/replay_r300_tcl_bypass_ib.c" -o "$replay"

files=0
: >"$raw"
find "$corpus" -type f -name '*.bin' | sort | while IFS= read -r f; do
	"$replay" --reasons "$f" 2>/dev/null | grep '^reason ' || true
done >"$raw"
files=$(find "$corpus" -type f -name '*.bin' | wc -l)

printf 'corpus_root=%s\n' "$corpus"
printf 'ib_files=%s draw_lines=%s\n' "$files" "$(wc -l <"$raw")"

printf '\nverdict distribution (all draws):\n'
awk '{for(i=1;i<=NF;i++) if($i~/^verdict=/){split($i,a,"=");v[a[2]]++}}
     END{for(k in v) printf "  %-8s %d\n", k, v[k]}' "$raw"

printf '\nfirst-decline-reason histogram:\n'
awk '/verdict=DECLINE/{for(i=1;i<=NF;i++) if($i~/^first=/){split($i,a,"=");r[a[2]]++}}
     END{for(k in r) printf "  %-22s %d\n", k, r[k]}' "$raw" | sort -k2 -rn

printf '\nfull-identity-EXT draws (ext_mask=0xff, ext_nonident=0) verdict split:\n'
awk '/ext_mask=0xff/ && /ext_nonident=0/{for(i=1;i<=NF;i++) if($i~/^verdict=/){split($i,a,"=");v[a[2]]++}}
     END{for(k in v) printf "  %-8s %d\n", k, v[k]}' "$raw"

printf '\ndraws one VAP_VTX_SIZE write from the firing shape:\n'
awk '{delete f; for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
      if(f["pin_tcl"]==1&&f["pin_fmt0"]==1&&f["pin_fmt1"]==1&&
         f["ext_mask"]=="0xff"&&f["ext_nonident"]==0&&f["pw_imm"]==0&&
         f["pos_present"]==1&&f["fmt0_extra"]=="0x00000000"&&
         f["fmt1_undecoded"]=="0x00000000"&&f["comp_gt4"]==0&&f["pin_vtx"]==0)n++}
     END{printf "  %d\n", n+0}' "$raw"

# Calibration: recompute the first-decline reason from the independent premise
# flags on each line, in the header's evaluation order, and assert it equals the
# reason emit_reasons printed. A mismatch means the emitter and the flags
# disagree, so the census is untrusted. The exercised set names which reason
# branches the corpus actually drove.
printf '\nreason-emitter calibration (recompute first= from flags):\n'
awk '{
    delete f; for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
    if(f["pin_tcl"]==0) e="no_tcl_bypass"
    else if(f["pin_fmt0"]==0) e="no_fmt0"
    else if(f["pin_fmt1"]==0) e="no_fmt1"
    else if(f["pin_vtx"]==0) e="no_vtx_size"
    else if(!(f["ext_mask"]=="0xff" && f["ext_nonident"]==0))
        e=(f["ext_mask"]!="0xff")?"ext_incomplete":"ext_nonidentity"
    else if(f["pw_imm"]==1) e="prim_walk_immediate"
    else if(f["pos_present"]==0) e="position_absent"
    else if(f["fmt0_extra"]!="0x00000000") e="fmt0_beyond_position"
    else if(f["fmt1_undecoded"]!="0x00000000") e="fmt1_undecoded"
    else if(f["comp_gt4"]==1) e="component_gt4"
    else e="-"
    lines++; ex[e]++
    if(e != f["first"]){mism++; if(mism<=3) printf "  MISMATCH line %d: emitted=%s recomputed=%s\n", NR, f["first"], e}
}
END{
    n=0; for(k in ex) n++
    printf "  lines=%d mismatches=%d branches_exercised=%d\n", lines, mism+0, n
    for(k in ex) printf "    %-22s %d\n", k, ex[k]
    if(mism+0 > 0) exit 1
}' "$raw"
