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
# compiler family is matched (LLVM=1 on a clang-built root), and every build
# warning fails the run. CI materializes the exact compiler and linker packages
# declared for each retained kernel root before invoking this harness.
# The no-flag default resolves to prod. Each development profile selects its
# monotone source ceiling, and all-dev is an alias for mutate-dev. A green run
# means radeon.ko linked, modpost completed, and the embedded source, profile,
# policy, upstream, and compiled-interface identities match.
#
# Exit: 0 module built and linked, 1 self-test calibration failure,
#       2 missing or invalid inputs, 4 build failure or unapproved warning.
set -eu

subtree=drivers/gpu/drm/radeon
kernel_build_root=${RADEON_MODULE_KERNEL_BUILD_ROOT:-}
if [ -z "${PYTHON:-}" ]; then
  PYTHON=$(command -v python3 || command -v python) || {
    echo "Python 3 interpreter is unavailable" >&2
    exit 2
  }
fi
script_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
self_test=0
requested_profile=default
profile_flags=0

resolve_profile() {
  case "$1" in
    default|prod) printf '%s\n' prod ;;
    observe-dev|probe-dev|mutate-dev) printf '%s\n' "$1" ;;
    all-dev) printf '%s\n' mutate-dev ;;
    *) return 2 ;;
  esac
}

is_lower_hex_identity() {
  identity=$1
  width=$2
  case "$identity" in
    *'
'*|*[!0-9a-f]*) return 1 ;;
  esac
  [ "${#identity}" -eq "$width" ]
}

read_upstream_base() {
  "$PYTHON" - "$1" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as upstream_base_file:
    upstream_base = tomllib.load(upstream_base_file)

print(upstream_base["commit"])
PY
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --kernel-build-root)
      [ "$#" -ge 2 ] || { echo "--kernel-build-root requires a directory" >&2; exit 2; }
      kernel_build_root=$2; shift 2 ;;
    --self-test) self_test=1; shift ;;
    --prod|--observe-dev|--probe-dev|--mutate-dev|--all-dev)
      profile_flags=$((profile_flags + 1))
      [ "$profile_flags" -eq 1 ] || {
        echo "exactly one build profile flag is accepted" >&2
        exit 2
      }
      requested_profile=${1#--}
      shift ;;
    -h|--help)
      echo "usage: $0 [--kernel-build-root DIR] [--prod|--observe-dev|--probe-dev|--mutate-dev|--all-dev] [--self-test]"
      exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! resolved_profile=$(resolve_profile "$requested_profile"); then
  echo "unknown build profile: $requested_profile" >&2
  exit 2
fi

scan_build_warnings() {
  warnings=$(grep -ni 'warning' "$1" || true)
  if [ -n "$warnings" ]; then
    echo "BUILD WARNINGS: the log carries warnings" >&2
    printf '%s\n' "$warnings" | sed 's/^/  /' >&2
    return 1
  fi
  return 0
}

make_work_dir() {
  temp_base=${RUNNER_TEMP:-${TMPDIR:-/var/tmp}}
  [ -d "$temp_base" ] && [ -w "$temp_base" ] || {
    echo "temporary build root is absent or not writable: $temp_base" >&2
    return 1
  }
  mktemp -d "$temp_base/radeon-module.XXXXXX"
}

if [ "$self_test" -eq 1 ]; then
  TMP=$(make_work_dir) || exit 2
  trap 'rm -rf "$TMP"' EXIT INT TERM
  fails=0
  echo "module build gate calibration:"
  printf 'CC [M] radeon_gem.o\nLD [M] radeon.ko\n' > "$TMP/clean.log"
  printf 'warning: the compiler differs from the one used to build the kernel\n' > "$TMP/mismatch.log"
  printf 'rs400.c:12:5: warning: unused variable [-Wunused-variable]\n' > "$TMP/bad.log"
  printf 'WARNING: modpost reported an unresolved contract\n' > "$TMP/uppercase.log"
  if scan_build_warnings "$TMP/clean.log" && \
     ! scan_build_warnings "$TMP/mismatch.log" 2>/dev/null && \
     ! scan_build_warnings "$TMP/bad.log" 2>/dev/null && \
     ! scan_build_warnings "$TMP/uppercase.log" 2>/dev/null; then
    echo "  ok: warning scan passes a clean log and rejects every warning"
  else
    echo "  CALIBRATION FAIL: warning scan verdicts" >&2; fails=$((fails + 1))
  fi
  if [ "$(resolve_profile default)" = prod ] &&
     [ "$(resolve_profile prod)" = prod ] &&
     [ "$(resolve_profile observe-dev)" = observe-dev ] &&
     [ "$(resolve_profile probe-dev)" = probe-dev ] &&
     [ "$(resolve_profile all-dev)" = mutate-dev ] &&
     [ "$(resolve_profile mutate-dev)" = mutate-dev ]; then
    echo "  ok: default is prod and development profiles resolve monotonically"
  else
    echo "  CALIBRATION FAIL: profile resolution" >&2
    fails=$((fails + 1))
  fi
  cat >"$TMP/upstream-base.toml" <<'EOF'
commit = "7d0a66e4bb9081d75c82ec4957c50034cb0ea449"

[target.mainline]
commit = "8cd9520d35a6c38db6567e97dd93b1f11f185dc6"
EOF
  multiline_identity='7d0a66e4bb9081d75c82ec4957c50034cb0ea449
8cd9520d35a6c38db6567e97dd93b1f11f185dc6'
  if [ "$(read_upstream_base "$TMP/upstream-base.toml")" = \
       7d0a66e4bb9081d75c82ec4957c50034cb0ea449 ] &&
     is_lower_hex_identity \
       7d0a66e4bb9081d75c82ec4957c50034cb0ea449 40 &&
     is_lower_hex_identity \
       77a3c9fc7c4006c2732b82a18f3747ab4e0d4a6d2a55027fcab83c00c9f4a65e 64 &&
     ! is_lower_hex_identity "$multiline_identity" 40 &&
     ! is_lower_hex_identity 7D0A66E4BB9081D75C82EC4957C50034CB0EA449 40; then
    echo "  ok: TOML identity parsing selects the top-level commit and rejects malformed values"
  else
    echo "  CALIBRATION FAIL: build identity parsing" >&2
    fails=$((fails + 1))
  fi
  got=0
  sh "$0" --all-dev --mutate-dev >"$TMP/profile.log" 2>&1 || got=$?
  if [ "$got" -eq 2 ]; then
    echo "  ok: multiple profile flags exit 2"
  else
    echo "  CALIBRATION FAIL: multiple profiles expected exit 2, got $got" >&2
    fails=$((fails + 1))
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
  if "$PYTHON" "$script_root/scripts/check_radeon_fbdev_allocation_compat.py" \
      --root "$script_root" --selftest; then
    echo "  ok: fbdev allocation compatibility rejects its source mutants"
  else
    echo "  CALIBRATION FAIL: fbdev allocation compatibility" >&2
    fails=$((fails + 1))
  fi
  [ "$fails" -eq 0 ] || { echo "module build gate calibration: FAIL ($fails)" >&2; exit 1; }
  echo "module build gate calibration: 4 warning verdicts, 2 profile verdicts, 4 identity verdicts, 2 root verdicts, and fbdev allocation compatibility"
  exit 0
fi

repo_root=$(git rev-parse --show-toplevel) || { echo "not inside a git repo" >&2; exit 2; }
[ -d "$repo_root/$subtree" ] || { echo "missing driver subtree: $subtree" >&2; exit 2; }
"$PYTHON" "$repo_root/scripts/check_radeon_fbdev_allocation_compat.py" \
  --root "$repo_root" || exit 2
feature_policy="$repo_root/policy/build-features.toml"
[ -r "$feature_policy" ] || { echo "missing build-feature policy" >&2; exit 2; }
source_commit=$(git -C "$repo_root" rev-parse HEAD)
driver_tree=$(git -C "$repo_root" rev-parse "HEAD:$subtree")
feature_policy_sha256=$(sha256sum "$feature_policy" | awk '{print $1}')
upstream_base=$(read_upstream_base "$repo_root/UPSTREAM_BASE.toml") || {
  echo "upstream-base declaration is invalid TOML" >&2
  exit 2
}
is_lower_hex_identity "$source_commit" 40 || {
  echo "source commit is not a full object ID" >&2
  exit 2
}
is_lower_hex_identity "$feature_policy_sha256" 64 || {
  echo "feature-policy digest is invalid" >&2
  exit 2
}
is_lower_hex_identity "$upstream_base" 40 || {
  echo "upstream base is not a full object ID" >&2
  exit 2
}
is_lower_hex_identity "$driver_tree" 40 || {
  echo "driver tree is not a full object ID" >&2
  exit 2
}

if [ -n "$kernel_build_root" ]; then
  KB=$kernel_build_root
else
  KB="/lib/modules/$(uname -r)/build"
fi
[ -d "$KB" ] || { echo "no kernel build dir at $KB" >&2; exit 2; }
KB=$(CDPATH='' cd -- "$KB" && pwd -P)
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

WORK=$(make_work_dir) || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM
mkdir -p "$WORK/$subtree"
( cd "$repo_root" && git archive HEAD "$subtree" ) |
  tar -x -C "$WORK/$subtree" --strip-components=4
echo "exported tracked $subtree into a clean temporary tree"

profile_header="$WORK/radeon_build_profile.h"
profile_manifest="$WORK/radeon-build-profile.toml"
{
  printf '%s\n' '#ifndef RADEON_BUILD_PROFILE_H'
  printf '%s\n' '#define RADEON_BUILD_PROFILE_H'
  printf '#define RADEON_BUILD_PROFILE "%s"\n' "$resolved_profile"
  printf '#define RADEON_BUILD_SOURCE_COMMIT "%s"\n' "$source_commit"
  printf '#define RADEON_BUILD_DRIVER_TREE "%s"\n' "$driver_tree"
  printf '#define RADEON_BUILD_FEATURE_POLICY_SHA256 "%s"\n' \
    "$feature_policy_sha256"
  printf '#define RADEON_BUILD_UPSTREAM_BASE "%s"\n' "$upstream_base"
  printf '%s\n' '#endif'
} >"$profile_header"
{
  printf '%s\n' 'schema = 1'
  printf 'requested_profile = "%s"\n' "$requested_profile"
  printf 'resolved_profile = "%s"\n' "$resolved_profile"
  printf 'source_commit = "%s"\n' "$source_commit"
  printf 'driver_tree = "%s"\n' "$driver_tree"
  printf 'feature_policy_sha256 = "%s"\n' "$feature_policy_sha256"
  printf 'upstream_base = "%s"\n' "$upstream_base"
  printf 'kernel_release = "%s"\n' "$kernel_release"
} >"$profile_manifest"
echo "radeon build profile: requested=$requested_profile resolved=$resolved_profile"

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
# Extra make variables for callers that build against a kernel they did not
# build themselves. A container installs a packaged kernel's headers and its
# own pahole, and the two versions need not agree; BTF encoding then warns on
# the mismatch, which reports the environment rather than the source under
# test. Turning BTF off is the caller's call, so it arrives as a variable
# rather than being decided here.
if [ -n "${RADEON_BUILD_MAKE_VARS:-}" ]; then
  # shellcheck disable=SC2086
  set -- "$@" $RADEON_BUILD_MAKE_VARS
fi
build_log="$WORK/build.log"
build_status=0
# shellcheck disable=SC2086
build_jobs=$(nproc 2>/dev/null || echo 1)
# -l bounds spawning to the thread count, so a solo build runs at full width
# while two builds sharing this host self-throttle to the cores instead of
# oversubscribing when concurrent runner instances overlap.
( cd "$WORK/$subtree" && \
  make "$@" -j"$build_jobs" -l"$build_jobs" RADEON_BUILD_PROFILE="$resolved_profile" \
    KCFLAGS="-I$WORK/include/trace -include $profile_header" \
    -C "$KB" M="$PWD" modules ) \
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
for metadata in \
  "gororoba_build_profile:$resolved_profile" \
  "gororoba_source_commit:$source_commit" \
  "gororoba_driver_tree:$driver_tree" \
  "gororoba_feature_policy_sha256:$feature_policy_sha256" \
  "gororoba_upstream_base:$upstream_base"
do
  field=${metadata%%:*}
  expected=${metadata#*:}
  actual=$(modinfo -F "$field" "$WORK/$subtree/radeon.ko")
  [ "$actual" = "$expected" ] || {
    echo "BUILD FAIL: module metadata $field is $actual, expected $expected" >&2
    exit 4
  }
done
"$PYTHON" "$repo_root/scripts/check_all_dev_interfaces.py" \
  --module "$WORK/$subtree/radeon.ko" \
  --profile "$resolved_profile" \
  --driver-root "$WORK/$subtree" || exit 4
"$PYTHON" "$repo_root/scripts/check_radeon_debugfs_registration.py" \
  --root "$WORK" || exit 4
"$PYTHON" "$repo_root/scripts/check_parked_admission_guards.py" \
  --root "$WORK" || exit 4
if [ -n "$(git -C "$repo_root" status --porcelain "$subtree")" ]; then
  echo "BUILD FAIL: the tracked checkout is not clean after the build" >&2
  exit 4
fi
echo "radeon module build: PASS against $kernel_release as $resolved_profile"
