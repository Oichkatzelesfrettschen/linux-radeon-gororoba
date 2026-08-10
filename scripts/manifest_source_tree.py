#!/usr/bin/env python3
"""Emit a content manifest for a source tree, or compare two manifests.

The migration proof compares an exported source tree against a normalized
reference that radeon-custom emits, so both sides carry one format: a schema
declaration, then path, git mode, size, and SHA-256 per file, sorted by path
under C collation.

    # manifest-schema: gororoba-source-tree-v1
    path<TAB>mode<TAB>size<TAB>sha256

The declaration is load-bearing rather than decorative. A comparison reads the
token from each side and refuses a mismatch, because manifests written in two
schemas differ at every path for a reason that has nothing to do with the
trees, and reporting that as drift buries the real answer.

Git modes are recorded rather than a two-way executable flag, because a source
tree's identity includes 100644 against 100755 against 120000, and a
comparison that collapses those would accept a tree shipping a program as data
or a symlink as a regular file.

The excluded and repository-only classes come from source-closure.toml, which
is the single home for that policy. A missing or malformed declaration is
fatal: falling back to built-in defaults would let a damaged declaration
silently widen what a manifest accepts.

Exit: 0 manifests match or manifest written, 1 mismatch, 2 usage or policy
error.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {".git", ".github"}
SCHEMA = "gororoba-source-tree-v1"
SCHEMA_LINE = f"# manifest-schema: {SCHEMA}"
COLUMNS = "path\tmode\tsize\tsha256"


class SchemaError(Exception):
    """A manifest carries no schema token, or carries a foreign one."""


class PolicyError(Exception):
    """The closure declaration is absent or does not carry what it must."""


@dataclass(frozen=True)
class ClosurePolicy:
    excluded_patterns: tuple[str, ...]
    repository_only_paths: tuple[str, ...]
    restored_paths: tuple[str, ...]
    retained_paths: tuple[str, ...]

    def is_excluded(self, rel: str) -> bool:
        """Excluded by generated-pattern match or by exact repository-only path."""
        if rel in self.repository_only_paths:
            return True
        name = rel.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(name, p) for p in self.excluded_patterns)


def load_policy(root: Path) -> ClosurePolicy:
    decl = root / "source-closure.toml"
    if not decl.is_file():
        raise PolicyError(f"missing closure declaration: {decl}")
    try:
        with decl.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"malformed closure declaration: {exc}") from exc

    def paths(table: str) -> tuple[str, ...]:
        entries = data.get(table, [])
        if not isinstance(entries, list):
            raise PolicyError(f"{table} is not a list of tables")
        out = []
        for entry in entries:
            value = entry.get("path")
            if not value:
                raise PolicyError(f"an entry in {table} carries no path")
            out.append(value)
        return tuple(out)

    excluded = []
    for entry in data.get("excluded", []):
        pattern = entry.get("pattern")
        if not pattern:
            raise PolicyError("an entry in excluded carries no pattern")
        excluded.append(pattern)
    if not excluded:
        raise PolicyError("the declaration names no excluded pattern")

    return ClosurePolicy(
        excluded_patterns=tuple(excluded),
        repository_only_paths=paths("repository_only"),
        restored_paths=paths("restored"),
        retained_paths=paths("retained"),
    )


def git_mode(path: Path) -> str:
    if path.is_symlink():
        return "120000"
    return "100755" if os.stat(path).st_mode & 0o111 else "100644"


def entry_digest(path: Path) -> tuple[str, int]:
    """Hash content, or the link target for a symlink.

    A symlink's identity is where it points, so hashing the target keeps a
    retargeted link from comparing equal to the original.
    """
    if path.is_symlink():
        target = os.readlink(path).encode()
        return hashlib.sha256(target).hexdigest(), len(target)
    blob = path.read_bytes()
    return hashlib.sha256(blob).hexdigest(), len(blob)


def manifest(root: Path, policy: ClosurePolicy) -> list[str]:
    rows = []
    for path in root.rglob("*"):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.is_dir() and not path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        if policy.is_excluded(rel):
            continue
        digest, size = entry_digest(path)
        rows.append(f"{rel}\t{git_mode(path)}\t{size}\t{digest}")
    rows.sort()
    return [SCHEMA_LINE, COLUMNS, *rows]


def read_manifest(path: Path) -> dict[str, str]:
    """Read a manifest after proving it speaks this schema.

    The token is checked before any row is parsed. A foreign schema differs at
    every path for a reason unrelated to the trees, so it is rejected rather
    than reported as drift.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    declared = next((ln for ln in lines if ln.startswith("# manifest-schema:")), None)
    if declared is None:
        raise SchemaError(f"{path} declares no manifest schema")
    token = declared.split(":", 1)[1].strip()
    if token != SCHEMA:
        raise SchemaError(
            f"{path} declares schema {token!r}, and this tool speaks {SCHEMA!r}"
        )
    rows = [ln for ln in lines if ln and not ln.startswith("#")]
    if not rows or rows[0] != COLUMNS:
        raise SchemaError(f"{path} carries no {COLUMNS!r} header")
    return {r.split("\t")[0]: r for r in rows[1:]}


def compare(a: Path, b: Path) -> int:
    lmap = read_manifest(a)
    rmap = read_manifest(b)
    only_left = sorted(set(lmap) - set(rmap))
    only_right = sorted(set(rmap) - set(lmap))
    differ = sorted(p for p in set(lmap) & set(rmap) if lmap[p] != rmap[p])
    for p in only_left:
        print(f"only in {a.name}: {p}")
    for p in only_right:
        print(f"only in {b.name}: {p}")
    for p in differ:
        lm, rm = lmap[p].split("\t"), rmap[p].split("\t")
        if lm[1] != rm[1]:
            print(f"mode differs: {p} ({lm[1]} against {rm[1]})")
        else:
            print(f"content differs: {p}")
    total = len(only_left) + len(only_right) + len(differ)
    if total:
        print(f"source manifests differ: {total} paths")
        return 1
    print(f"source manifests match: {len(lmap)} files")
    return 0


def self_test() -> int:
    """Calibrate against a mutation of each class the manifest claims to catch."""
    import shutil
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "source-closure.toml").write_text(
            "schema = 1\n"
            '[[excluded]]\npattern = "*_reg_safe.h"\nreason = "generated"\n'
            '[[repository_only]]\npath = ".gitignore"\nreason = "metadata"\n',
            encoding="utf-8",
        )
        policy = load_policy(root)

        tree = root / "tree"
        tree.mkdir()
        (tree / "r300.c").write_text(
            "int probe(void) { return 0; }\n", encoding="utf-8"
        )
        (tree / "reg_srcs").mkdir()
        (tree / "reg_srcs" / "r300").write_text("r300 0x4000\n", encoding="utf-8")
        (tree / "gen_reg_safe.h").write_text("generated\n", encoding="utf-8")
        (tree / ".gitignore").write_text("*.o\n", encoding="utf-8")
        (tree / "tool.sh").write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
        (tree / "tool.sh").chmod(0o755)

        base = manifest(tree, policy)
        paths = {r.split("\t")[0] for r in base[1:]}

        def check(label: str, condition: bool) -> None:
            nonlocal failures
            if condition:
                print(f"  ok: {label}")
            else:
                print(f"  CALIBRATION FAIL: {label}")
                failures += 1

        check("generated pattern excluded", "gen_reg_safe.h" not in paths)
        check("repository-only path excluded", ".gitignore" not in paths)
        check(
            "regular file recorded 100644",
            any(r.startswith("r300.c\t100644\t") for r in base),
        )
        check(
            "executable recorded 100755",
            any(r.startswith("tool.sh\t100755\t") for r in base),
        )

        # Symlink: identity is its target, and its mode is distinct.
        (tree / "link.c").symlink_to("r300.c")
        with_link = manifest(tree, policy)
        check(
            "symlink recorded 120000",
            any(r.startswith("link.c\t120000\t") for r in with_link),
        )
        (tree / "link.c").unlink()

        def mutate(label: str, fn) -> None:
            snapshot = root / "snap"
            shutil.copytree(tree, snapshot)
            try:
                fn(snapshot)
                check(label, manifest(snapshot, policy) != base)
            finally:
                shutil.rmtree(snapshot)

        mutate(
            "changed content detected",
            lambda t: (t / "r300.c").write_text("int probe(void) { return 1; }\n"),
        )
        mutate("changed executable bit detected", lambda t: (t / "r300.c").chmod(0o755))
        mutate(
            "unexpected file detected",
            lambda t: (t / "extra.c").write_text("void x(void) {}\n"),
        )
        mutate("missing file detected", lambda t: (t / "r300.c").unlink())

        # A damaged declaration is fatal rather than a fallback to defaults.
        for label, body in (
            ("missing declaration is fatal", None),
            ("malformed declaration is fatal", "schema = [[[\n"),
        ):
            broken = root / "broken"
            broken.mkdir(exist_ok=True)
            decl = broken / "source-closure.toml"
            if body is None:
                decl.unlink(missing_ok=True)
            else:
                decl.write_text(body, encoding="utf-8")
            try:
                load_policy(broken)
                check(label, False)
            except PolicyError:
                check(label, True)

        # The schema token gates the comparison. A foreign or absent token is a
        # tool mismatch rather than tree drift, so it stops the run instead of
        # reporting every path as changed.
        text = "\n".join(base) + "\n"
        good = root / "good.tsv"
        good.write_text(text, encoding="utf-8")
        check("matching schema compares", compare(good, good) == 0)

        for label, mutated in (
            ("absent schema token rejected", text.replace(SCHEMA_LINE + "\n", "")),
            (
                "foreign schema token rejected",
                text.replace(SCHEMA, "some-other-tree-v9"),
            ),
            ("absent column header rejected", text.replace(COLUMNS + "\n", "")),
        ):
            other = root / "other.tsv"
            other.write_text(mutated, encoding="utf-8")
            try:
                compare(good, other)
                check(label, False)
            except SchemaError:
                check(label, True)

    if failures:
        print(f"source-manifest calibration: FAIL ({failures})")
        return 1
    print(
        "source-manifest calibration: every class detected, "
        "fail-closed on policy and schema"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, help="emit a manifest for this tree")
    parser.add_argument("--out", type=Path, help="write the manifest here")
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("A", "B"))
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="repository root holding source-closure.toml",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.compare:
        try:
            return compare(*args.compare)
        except SchemaError as exc:
            print(f"manifest schema: {exc}", file=sys.stderr)
            return 2
    if not args.tree:
        parser.error("give --tree, --compare, or --self-test")
    if not args.tree.is_dir():
        print(f"not a directory: {args.tree}", file=sys.stderr)
        return 2

    try:
        policy = load_policy(args.root)
    except PolicyError as exc:
        print(f"closure policy: {exc}", file=sys.stderr)
        return 2

    rows = manifest(args.tree, policy)
    text = "\n".join(rows) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        # The schema declaration and the column header both precede the rows.
        print(f"manifest: {args.out} ({len(rows) - 2} files)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
