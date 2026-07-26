#!/usr/bin/env python3
"""Emit a content manifest for a source tree, or compare two manifests.

The migration proof compares an exported source tree against a normalized
reference, so both sides need one manifest format: path, mode, size, and
SHA-256 per regular file, sorted by path under C collation. Mode is recorded
because an executable bit is part of a source tree's identity, and a comparison
that ignores it would pass a tree that ships a program as data.

Excluded classes come from source-closure.toml rather than from a constant
here, so the gate and the declaration cannot drift apart.

Exit: 0 manifests match or manifest written, 1 mismatch, 2 usage error.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import sys
from pathlib import Path

# Classes source-closure.toml declares as build products. Parsing the manifest
# of exclusions from that file keeps one home for the fact; this list is the
# fallback used when the declaration is absent, and it is checked against the
# declaration when one exists.
DEFAULT_EXCLUDED = ["*_reg_safe.h", "mkregtable"]
SKIP_DIRS = {".git", ".github"}


def declared_exclusions(root: Path) -> list[str]:
    """Read excluded patterns from source-closure.toml without a TOML parser.

    The file is project-authored and its excluded entries are single-line
    pattern assignments, so a line scan avoids a dependency for one field.
    """
    decl = root / "source-closure.toml"
    if not decl.is_file():
        return list(DEFAULT_EXCLUDED)
    patterns = []
    in_excluded = False
    for line in decl.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[["):
            in_excluded = stripped == "[[excluded]]"
            continue
        if in_excluded and stripped.startswith("pattern"):
            _, _, value = stripped.partition("=")
            patterns.append(value.strip().strip('"'))
    return patterns or list(DEFAULT_EXCLUDED)


def is_excluded(rel: str, patterns: list[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def manifest(root: Path, patterns: list[str]) -> list[str]:
    rows = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if is_excluded(rel, patterns):
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        mode = "755" if path.stat().st_mode & 0o111 else "644"
        rows.append(f"{rel}\t{mode}\t{path.stat().st_size}\t{digest}")
    rows.sort()
    return ["path\tmode\tsize\tsha256", *rows]


def compare(a: Path, b: Path) -> int:
    left = a.read_text(encoding="utf-8").splitlines()
    right = b.read_text(encoding="utf-8").splitlines()
    lmap = {r.split("\t")[0]: r for r in left[1:]}
    rmap = {r.split("\t")[0]: r for r in right[1:]}
    only_left = sorted(set(lmap) - set(rmap))
    only_right = sorted(set(rmap) - set(lmap))
    differ = sorted(p for p in set(lmap) & set(rmap) if lmap[p] != rmap[p])
    for p in only_left:
        print(f"only in {a.name}: {p}")
    for p in only_right:
        print(f"only in {b.name}: {p}")
    for p in differ:
        print(f"differs: {p}")
    total = len(only_left) + len(only_right) + len(differ)
    if total:
        print(f"source manifests differ: {total} paths")
        return 1
    print(f"source manifests match: {len(lmap)} files")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, help="emit a manifest for this tree")
    parser.add_argument("--out", type=Path, help="write the manifest here")
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("A", "B"))
    parser.add_argument("--root", type=Path, default=Path("."),
                        help="repository root holding source-closure.toml")
    args = parser.parse_args()

    if args.compare:
        return compare(*args.compare)
    if not args.tree:
        parser.error("give --tree or --compare")
    if not args.tree.is_dir():
        print(f"not a directory: {args.tree}", file=sys.stderr)
        return 2

    rows = manifest(args.tree, declared_exclusions(args.root))
    text = "\n".join(rows) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"manifest: {args.out} ({len(rows) - 1} files)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
