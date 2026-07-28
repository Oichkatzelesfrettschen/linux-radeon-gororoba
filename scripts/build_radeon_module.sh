#!/bin/sh
# Build radeon.ko from the tracked driver subtree against a named kernel
# build root.
#
# The export step is load-bearing: `git archive` copies only tracked content
# into a temporary tree, so the build reads exactly what a commit carries, the
# generated *_reg_safe.h headers and the mkregtable host binary are produced
# fresh from source in the copy, and the checkout stays clean. Kbuild writes
# objects under M= and reads the kernel root, so the retained read-only root
# is never written.
#
# The kernel root resolves from --kernel-build-root, then
# RADEON_MODULE_KERNEL_BUILD_ROOT, then the running kernel. The root is
# validated for the Kbuild surface before make runs, the kernel's own
# compiler family is matched (LLVM=1 on a clang-built root), and the log is
# scanned for warnings: the Kbuild compiler-differs notice on the retained
# root is the one explained diagnostic, and any other warning fails the run.
# A green run means radeon.ko linked and modpost completed.
#
# Exit: 0 module built and linked, 1 self-test calibration failure,
#       2 missing or invalid inputs, 4 build failure or unapproved warning.
set -eu

subtree=drivers/gpu/drm/radeon
kernel_build_root=${RADEON_MODULE_KERNEL_BUILD_ROOT:-}
self_test=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --kernel-build-root)
      [ "$#" -ge 2 ] || { echo "--kernel-build-root requires a directory" >&2; exit 2; }
      kernel_build_root=$2; shift 2 ;;
    --self-test) self_test=1; shift ;;
    -h|--help)
      echo "usage: $0 [--kernel-build-root DIR] [--self-test]"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

scan_build_warnings() {
  unexpected=$(grep -n 'warning' "$1" |
    grep -v 'the compiler differs from the one used to build the kernel' || true)
  if [ -n "$unexpected" ]; then
    echo "BUILD WARNINGS: the log carries warnings outside the allowlist" >&2
    printf '%s\n' "$unexpected" | sed 's/^/  /' >&2
    return 1
  fi
  return 0
}

if [ "$self_test" -eq 1 ]; then
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT INT TERM
  fails=0
  echo "module build gate calibration:"
  printf 'CC [M] radeon_gem.o\nLD [M] radeon.ko\n' > "$TMP/clean.log"
  printf 'warning: the compiler differs from the one used to build the kernel\n' > "$TMP/allowed.log"
  printf 'rs400.c:12:5: warning: unused variable [-Wunused-variable]\n' > "$TMP/bad.log"
  if scan_build_warnings "$TMP/clean.log" && \
     scan_build_warnings "$TMP/allowed.log" 2>/dev/null && \
     ! scan_build_warnings "$TMP/bad.log" 2>/dev/null; then
    echo "  ok: warning scan passes clean and allowlisted logs, fails on any other"
  else
    echo "  CALIBRATION FAIL: warning scan verdicts" >&2; fails=$((fails + 1))
  fi
  got=0
  mkdir -p "$TMP/stub_root"
  sh "$0" --kernel-build-root "$TMP/stub_root" >"$TMP/out.log" 2>&1 || got=$?
  if [ "$got" -eq 2 ]; then
    echo "  ok: directory missing the Kbuild surface exits 2"
  else
    echo "  CALIBRATION FAIL: stub root expected exit 2, got $got" >&2
    fails=$((fails + 1))
  fi
  got=0
  sh "$0" --kernel-build-root "$TMP/absent" >"$TMP/out2.log" 2>&1 || got=$?
  if [ "$got" -eq 2 ]; then
    echo "  ok: absent root exits 2"
  else
    echo "  CALIBRATION FAIL: absent root expected exit 2, got $got" >&2
    fails=$((fails + 1))
  fi
  [ "$fails" -eq 0 ] || { echo "module build gate calibration: FAIL ($fails)" >&2; exit 1; }
  echo "module build gate calibration: 3 warning verdicts, 2 root verdicts"
  exit 0
fi

repo_root=$(git rev-parse --show-toplevel) || { echo "not inside a git repo" >&2; exit 2; }
[ -d "$repo_root/$subtree" ] || { echo "missing driver subtree: $subtree" >&2; exit 2; }

if [ -n "$kernel_build_root" ]; then
  KB=$kernel_build_root
else
  KB="/lib/modules/$(uname -r)/build"
fi
[ -d "$KB" ] || { echo "no kernel build dir at $KB" >&2; exit 2; }
KB=$(CDPATH= cd -- "$KB" && pwd -P)
for required in \
  Makefile \
  Module.symvers \
  include/config/kernel.release \
  include/generated/autoconf.h \
  include/generated/uapi/linux/version.h
do
  [ -r "$KB/$required" ] || {
    echo "invalid kernel build root: missing $KB/$required" >&2; exit 2; }
done
kernel_release=$(cat "$KB/include/config/kernel.release")

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir -p "$WORK/$subtree"
( cd "$repo_root" && git archive HEAD "$subtree" ) |
  tar -x -C "$WORK/$subtree" --strip-components=4
echo "exported tracked $subtree into a clean temporary tree"

# radeon_trace.h sets TRACE_INCLUDE_PATH to ../../drivers/gpu/drm/radeon, and
# define_trace.h resolves that relative to include/trace, so an in-kernel
# build finds the header beside the source while an external build looks
# inside the kernel root, where a headers-only root does not carry it. The
# DKMS lane stages the header into the kernel tree; this harness keeps the
# root read-only, so a shim include directory in the work tree satisfies the
# same relative path: -I$WORK/include/trace joins the recorded ../.. suffix
# to reach the exported subtree.
mkdir -p "$WORK/include/trace"

if grep -q '^CONFIG_CC_IS_CLANG=y' "$KB/include/config/auto.conf" 2>/dev/null ||
   grep -qi clang "$KB/include/generated/compile.h" 2>/dev/null; then
  set -- LLVM=1
else
  set --
fi
build_log="$WORK/build.log"
build_status=0
# shellcheck disable=SC2086
( cd "$WORK/$subtree" && \
  make "$@" KCFLAGS="-I$WORK/include/trace" -C "$KB" M="$PWD" modules ) \
  >"$build_log" 2>&1 || build_status=$?
cat "$build_log"
if [ "$build_status" -ne 0 ]; then
  echo "BUILD FAIL: radeon.ko did not build against $kernel_release" >&2
  exit 4
fi
[ -f "$WORK/$subtree/radeon.ko" ] || {
  echo "BUILD FAIL: make succeeded and radeon.ko is absent" >&2; exit 4; }
grep -q 'MODPOST' "$build_log" || {
  echo "BUILD FAIL: modpost did not run" >&2; exit 4; }
scan_build_warnings "$build_log" || exit 4
if [ -n "$(git -C "$repo_root" status --porcelain "$subtree")" ]; then
  echo "BUILD FAIL: the tracked checkout is not clean after the build" >&2
  exit 4
fi
echo "radeon module build: PASS against $kernel_release"
