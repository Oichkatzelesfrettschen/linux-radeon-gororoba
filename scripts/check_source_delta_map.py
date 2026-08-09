#!/usr/bin/env python3
"""Verify post-tag Radeon source-delta classification and path coverage."""

from __future__ import annotations

import argparse
import copy
import csv
import re
import subprocess
import sys
from pathlib import Path


BASELINE_TAG = "radeon-unified-0.7-profiled-source"
DRIVER_ROOT = Path("drivers/gpu/drm/radeon")
MAP_PATH = Path("docs/base-delta-map.tsv")
REQUIRED_HEADERS = (
    "# schema: gororoba-post-tag-source-delta-map-v1",
    f"# baseline: {BASELINE_TAG}",
    "# imported-base-map: migration/input/base-delta-map.tsv",
)
MAP_FIELDS = {
    "delta_id",
    "source_path",
    "symbol_or_range",
    "classification",
    "mechanism",
    "evidence_class",
    "validation",
}
CLASSIFICATIONS = {
    "upstream-backport",
    "version-compat-adaptation",
    "rs48x-mechanism",
    "palm-mechanism",
}
EVIDENCE_CLASSES = {"source-verified", "compile-verified"}
DURABLE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
CHRONOLOGY_PREFIX = re.compile(
    r"(?:phase|wave|mission|sprint|step|batch|set|group)(?:-|$)"
)


class DeltaMapError(Exception):
    """The post-tag source-delta map differs from the current source range."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DeltaMapError(message)


def parse_map(text: str) -> list[dict[str, str]]:
    lines = text.splitlines()
    require(
        lines[: len(REQUIRED_HEADERS)] == list(REQUIRED_HEADERS),
        "source-delta map provenance headers differ",
    )
    data_lines = [line for line in lines if line and not line.startswith("#")]
    require(bool(data_lines), "source-delta map is empty")
    rows = list(csv.DictReader(data_lines, delimiter="\t"))
    require(bool(rows), "source-delta map has no rows")
    require(set(rows[0]) == MAP_FIELDS, "source-delta map schema differs")
    return rows


def read_map(root: Path) -> list[dict[str, str]]:
    return parse_map((root / MAP_PATH).read_text(encoding="ascii"))


def git_output(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    require(
        result.returncode == 0,
        "git rejected source-delta range: " + result.stderr.strip(),
    )
    return result.stdout


def changed_source_paths(root: Path) -> set[str]:
    git_output(root, "rev-parse", "--verify", f"{BASELINE_TAG}^{{commit}}")
    output = git_output(
        root,
        "diff",
        "--name-only",
        f"{BASELINE_TAG}..HEAD",
        "--",
        DRIVER_ROOT.as_posix(),
    )
    return {line for line in output.splitlines() if line}


def validate(
    root: Path,
    rows: list[dict[str, str]],
    changed_paths: set[str],
) -> None:
    require(bool(changed_paths), "post-tag source range has no Radeon paths")
    keys: set[tuple[str, str, str]] = set()
    declared_paths: set[str] = set()
    for row in rows:
        require(
            all(row.get(field) for field in MAP_FIELDS),
            "source-delta map carries an empty field",
        )
        require(
            DURABLE_ID.fullmatch(row["delta_id"]) is not None,
            f"source-delta ID is not mechanism-named: {row['delta_id']}",
        )
        require(
            CHRONOLOGY_PREFIX.match(row["delta_id"]) is None,
            f"source-delta ID carries chronology: {row['delta_id']}",
        )
        require(
            DURABLE_ID.fullmatch(row["mechanism"]) is not None,
            f"source-delta mechanism is not durable: {row['mechanism']}",
        )
        require(
            CHRONOLOGY_PREFIX.match(row["mechanism"]) is None,
            f"source-delta mechanism carries chronology: {row['mechanism']}",
        )
        require(
            row["classification"] in CLASSIFICATIONS,
            f"source-delta classification is unknown: {row['classification']}",
        )
        require(
            row["evidence_class"] in EVIDENCE_CLASSES,
            f"source-delta evidence class is unknown: {row['evidence_class']}",
        )
        source_path = Path(row["source_path"])
        require(
            not source_path.is_absolute() and ".." not in source_path.parts,
            f"source-delta path escapes the repository: {source_path}",
        )
        require(
            source_path.is_relative_to(DRIVER_ROOT),
            f"source-delta path leaves the imported subtree: {source_path}",
        )
        require(
            (root / source_path).is_file(),
            f"source-delta path is absent: {source_path}",
        )
        key = (row["delta_id"], row["source_path"], row["symbol_or_range"])
        require(key not in keys, f"source-delta row is duplicated: {key}")
        keys.add(key)
        declared_paths.add(row["source_path"])

    require(
        declared_paths == changed_paths,
        "source-delta path coverage differs: "
        + ",".join(sorted(declared_paths ^ changed_paths)),
    )


def self_test(root: Path) -> int:
    map_text = (root / MAP_PATH).read_text(encoding="ascii")
    rows = parse_map(map_text)
    changed_paths = changed_source_paths(root)
    validate(root, rows, changed_paths)
    rejection_count = 0

    invalid_headers = map_text.replace(REQUIRED_HEADERS[0], "# schema: wrong", 1)
    try:
        parse_map(invalid_headers)
    except DeltaMapError:
        rejection_count += 1
    else:
        raise DeltaMapError("self-test accepted a changed map schema")

    candidates: list[list[dict[str, str]]] = []
    empty_field = copy.deepcopy(rows)
    empty_field[0]["validation"] = ""
    candidates.append(empty_field)
    unknown_classification = copy.deepcopy(rows)
    unknown_classification[0]["classification"] = "local-change"
    candidates.append(unknown_classification)
    unknown_evidence = copy.deepcopy(rows)
    unknown_evidence[0]["evidence_class"] = "hardware-pass"
    candidates.append(unknown_evidence)
    chronological_id = copy.deepcopy(rows)
    chronological_id[0]["delta_id"] = "phase-2"
    candidates.append(chronological_id)
    chronological_mechanism = copy.deepcopy(rows)
    chronological_mechanism[0]["mechanism"] = "wave-3"
    candidates.append(chronological_mechanism)
    invalid_mechanism = copy.deepcopy(rows)
    invalid_mechanism[0]["mechanism"] = "forced_reset"
    candidates.append(invalid_mechanism)
    escaping_path = copy.deepcopy(rows)
    escaping_path[0]["source_path"] = "../radeon.h"
    candidates.append(escaping_path)
    absent_path = copy.deepcopy(rows)
    absent_path[0]["source_path"] = (DRIVER_ROOT / "absent.c").as_posix()
    candidates.append(absent_path)
    duplicate = copy.deepcopy(rows)
    duplicate.append(copy.deepcopy(duplicate[0]))
    candidates.append(duplicate)
    first_path = sorted(changed_paths)[0]
    missing_coverage = [
        copy.deepcopy(row) for row in rows if row["source_path"] != first_path
    ]
    candidates.append(missing_coverage)

    for candidate in candidates:
        try:
            validate(root, candidate, changed_paths)
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted an invalid source-delta map")

    print(f"source delta map calibration: {rejection_count} invalid classes rejected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if args.self_test:
            return self_test(root)
        rows = read_map(root)
        paths = changed_source_paths(root)
        validate(root, rows, paths)
    except (DeltaMapError, OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"source delta map: {exc}", file=sys.stderr)
        return 1
    print(
        f"source delta map: {len(paths)} paths, "
        f"{len({row['mechanism'] for row in rows})} mechanisms, "
        f"{len(rows)} rows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
