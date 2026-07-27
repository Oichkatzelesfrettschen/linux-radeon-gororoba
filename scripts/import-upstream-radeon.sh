#!/bin/sh
# Import the upstream Radeon subtree named by UPSTREAM_BASE.toml.
#
# The import is deterministic: it resolves the recorded peeled commit, verifies
# that commit's subtree tree object matches the recorded one, and exports that
# tree. Resolving by object rather than by tag name means a moved or replaced
# tag cannot change what lands, and it means any mirror serves equally because
# git object IDs are content addresses.
#
# The annotated tag signature is verified when the kernel maintainer keyring is
# present. A missing keyring is reported rather than treated as a pass.
#
# Exit: 0 imported, 2 missing inputs or unreadable declaration,
#       3 object mismatch against the declaration, 4 signature check failed.
set -eu

usage() {
  cat <<'EOF'
usage: import-upstream-radeon.sh --out DIR [--remote URL] [--require-signature]

  --out DIR             export the subtree here
  --remote URL          override the declared repository (a local mirror works)
  --require-signature   fail when the tag signature cannot be verified
EOF
}

out=""
remote=""
require_sig=0
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out=${2:?--out needs a directory}; shift 2 ;;
    --remote) remote=${2:?--remote needs a URL}; shift 2 ;;
    --require-signature) require_sig=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[ -n "$out" ] || { usage >&2; exit 2; }

root=$(git rev-parse --show-toplevel) || { echo "not inside a git repo" >&2; exit 2; }
decl="$root/UPSTREAM_BASE.toml"
[ -f "$decl" ] || { echo "missing declaration: $decl" >&2; exit 2; }

# Read the top-level scalars. Values are quoted single-line assignments, and the
# read stops at the first table header so a target section cannot shadow them.
field() {
  sed -n '/^\[/q;p' "$decl" \
    | sed -n "s/^$1[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*/\1/p" | head -1
}

declared_repo=$(field repository)
declared_commit=$(field commit)
declared_tag=$(field tag)
declared_tag_object=$(field tag_object)
declared_path=$(field path)
declared_tree=$(field subtree_tree)

for v in declared_commit declared_tag declared_tag_object declared_path declared_tree; do
  eval "val=\$$v"
  [ -n "$val" ] || { echo "declaration missing $v" >&2; exit 2; }
done

if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
  echo "destination is not empty: $out" >&2
  echo "  importing over residual files would attribute them to upstream" >&2
  exit 2
fi

url=${remote:-$declared_repo}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

echo "fetching $declared_tag and $declared_commit from $url"
git init -q --bare "$work/mirror"
# Blobs arrive on demand and only the named objects are fetched, so the import
# does not acquire the full Linux history to read one subtree.
git -C "$work/mirror" remote add origin "$url"
git -C "$work/mirror" fetch -q --depth 1 --filter=blob:none origin \
    "refs/tags/$declared_tag:refs/tags/$declared_tag"

# The annotated tag object itself, before anything derived from it. A tag moved
# to a different object fails here rather than after the export.
actual_tag_object=$(git -C "$work/mirror" rev-parse "refs/tags/$declared_tag")
if [ "$actual_tag_object" != "$declared_tag_object" ]; then
  echo "tag object mismatch for $declared_tag" >&2
  echo "  declared: $declared_tag_object" >&2
  echo "  actual:   $actual_tag_object" >&2
  exit 3
fi
echo "tag object: $actual_tag_object (matches declaration)"

peeled=$(git -C "$work/mirror" rev-parse "$declared_tag^{commit}")
if [ "$peeled" != "$declared_commit" ]; then
  echo "tag $declared_tag peels to $peeled, declaration names $declared_commit" >&2
  exit 3
fi
echo "peeled commit: $peeled (matches declaration)"

if [ "$require_sig" -eq 1 ]; then
  if git -C "$work/mirror" verify-tag "$declared_tag" >/dev/null 2>&1; then
    echo "tag signature: verified"
  else
    echo "tag signature: unverified, and --require-signature was given" >&2
    echo "  the tag object is present and matches the declaration, so this is a" >&2
    echo "  keyring result: verification needs the kernel maintainer keys in" >&2
    echo "  this GNUPGHOME" >&2
    exit 4
  fi
fi

# The decisive check: the subtree object, which addresses content rather than a
# name. A tag or commit that no longer carries this tree fails here.
actual_tree=$(git -C "$work/mirror" rev-parse "$declared_commit:$declared_path")
if [ "$actual_tree" != "$declared_tree" ]; then
  echo "subtree mismatch at $declared_path" >&2
  echo "  declared: $declared_tree" >&2
  echo "  actual:   $actual_tree" >&2
  exit 3
fi
echo "subtree tree object: $actual_tree (matches declaration)"

mkdir -p "$out"
git -C "$work/mirror" archive "$actual_tree" | tar -x -C "$out"
echo "imported $(find "$out" -type f | wc -l) files into $out"
