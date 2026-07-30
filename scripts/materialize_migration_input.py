#!/usr/bin/env python3
"""Copy and verify the pinned migration input from its source checkout."""

from __future__ import annotations

import argparse
import csv
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path


class InputError(Exception):
    """The source checkout differs from the frozen migration inventory."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(control_root: Path) -> list[dict[str, str]]:
    path = control_root / "docs/reconstruction-input-inventory.tsv"
    with path.open(encoding="ascii", newline="") as source:
        rows = list(csv.DictReader(source, delimiter="\t"))
    if len(rows) != 6:
        raise InputError("reconstruction input inventory must contain six rows")
    return rows


def safe_source_path(packaging_root: Path, relative: str) -> Path:
    candidate = (packaging_root / relative).resolve()
    try:
        candidate.relative_to(packaging_root.resolve())
    except ValueError as exc:
        raise InputError(f"source path escapes packaging checkout: {relative}") from exc
    return candidate


def materialize(control_root: Path, packaging_root: Path, output_root: Path) -> None:
    if output_root.exists() and any(output_root.iterdir()):
        raise InputError(f"output directory is not empty: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    rows = inventory(control_root)
    repositories = {row["source_repository"] for row in rows}
    commits = {row["source_commit"] for row in rows}
    if len(repositories) != 1 or len(commits) != 1:
        raise InputError("migration inventory has multiple source identities")
    for row in rows:
        source = safe_source_path(packaging_root, row["source_path"])
        name = Path(row["copied_path"]).name
        if name in seen:
            raise InputError(f"duplicate output filename: {name}")
        seen.add(name)
        if not source.is_file():
            raise InputError(f"migration source file is missing: {source}")
        actual = sha256_file(source)
        if actual != row["sha256"]:
            raise InputError(
                f"{row['source_path']}: SHA-256 {actual} != {row['sha256']}"
            )
        destination = output_root / name
        shutil.copyfile(source, destination)
        if sha256_file(destination) != actual:
            raise InputError(f"copied migration input changed: {name}")
    provenance = (
        f"source_repository={next(iter(repositories))}\n"
        f"source_commit={next(iter(commits))}\n"
    )
    (output_root / "ORACLE_PROVENANCE").write_text(
        provenance,
        encoding="ascii",
    )
    print(f"materialized {len(seen)} pinned migration files")


def self_test(control_root: Path) -> int:
    try:
        with tempfile.TemporaryDirectory(prefix="migration-input.") as temporary:
            work = Path(temporary)
            packaging = work / "packaging"
            for row in inventory(control_root):
                destination = packaging / row["source_path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = control_root / row["copied_path"]
                shutil.copyfile(source, destination)
            materialize(control_root, packaging, work / "good")

            first = inventory(control_root)[0]
            with (packaging / first["source_path"]).open("ab") as destination:
                destination.write(b"x")
            try:
                materialize(control_root, packaging, work / "bad")
            except InputError:
                pass
            else:
                raise InputError("self-test accepted a changed migration input")
    except (InputError, OSError, UnicodeDecodeError) as exc:
        print(f"migration-input calibration: FAIL: {exc}", file=sys.stderr)
        return 1
    print("migration-input calibration: exact source passes and drift fails closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--control-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--packaging-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    control_root = args.control_root.resolve()
    if args.self_test:
        return self_test(control_root)
    if args.packaging_root is None or args.output is None:
        parser.error("--packaging-root and --output are required")
    try:
        materialize(
            control_root,
            args.packaging_root.resolve(),
            args.output.resolve(),
        )
    except (InputError, OSError, UnicodeDecodeError) as exc:
        print(f"migration input: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
