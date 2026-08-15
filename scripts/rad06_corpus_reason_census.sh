#!/bin/sh
# Reason-coded census of the TCL-bypass vertex-underfeed decision over a corpus
# of retained PM4 indirect buffers. Builds replay_r300_tcl_bypass_ib with the
# same r300_tcl_bypass_vtx_check.h the kernel compiles, runs it in --reasons
# mode over every *.bin under the corpus root, and tabulates the verdict split,
# the first-decline-reason histogram, and the PSC-declared subset. The
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

printf '\nPSC-declared draws (cntl_mask and ext_mask nonzero) verdict split:\n'
awk '!/cntl_mask=0x00/ && !/ext_mask=0x00/{for(i=1;i<=NF;i++) if($i~/^verdict=/){split($i,a,"=");v[a[2]]++}}
     END{for(k in v) printf "  %-8s %d\n", k, v[k]}' "$raw"

printf '\ndraws one VAP_VTX_SIZE write from the firing shape:\n'
awk '{delete f; for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
      if(f["pin_tcl"]==1&&f["pin_fmt0"]==1&&f["pin_fmt1"]==1&&
         f["cntl_mask"]!="0x00"&&f["ext_mask"]!="0x00"&&f["pw_imm"]==0&&
         f["pos_present"]==1&&f["fmt0_extra"]=="0x00000000"&&
         f["fmt1_undecoded"]=="0x00000000"&&f["comp_gt4"]==0&&f["pin_vtx"]==0)n++}
     END{printf "  %d\n", n+0}' "$raw"

# Calibration: the first= reason on every line is the decision function's
# own decline branch (an enum out-param, not a re-derivation), so the
# census is trusted when every DECLINE carries a named reason and every
# PASS or REJECT carries none. The exercised set names which decline
# branches the corpus actually drove.
printf '\nreason coverage (first= from the decision function):\n'
awk '{
    delete f; for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
    lines++; ex[f["first"]]++
    if(f["verdict"]=="DECLINE" && f["first"]=="-"){bad++;
        if(bad<=3) printf "  UNNAMED DECLINE line %d\n", NR}
    if(f["verdict"]!="DECLINE" && f["first"]!="-"){bad++;
        if(bad<=3) printf "  NAMED NON-DECLINE line %d: %s\n", NR, f["first"]}
}
END{
    n=0; for(k in ex) n++
    printf "  lines=%d violations=%d branches_exercised=%d\n", lines, bad+0, n
    for(k in ex) printf "    %-22s %d\n", k, ex[k]
    if(bad+0 > 0) exit 1
}' "$raw"
