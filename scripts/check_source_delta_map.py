#!/usr/bin/env python3
"""Verify post-tag Radeon source-delta classification by commit and path."""

from __future__ import annotations

import argparse
import copy
import csv
import re
import subprocess
import sys
from pathlib import Path


BASELINE_TAG = "radeon-unified-0.7-profiled-source"
BASELINE_TAG_OBJECT = "7f500d682aad600ca443c7f26e913b6b4034c834"
BASELINE_COMMIT = "293a4ae3fe82cd03585ef3157e82b0b59b641b47"
DRIVER_ROOT = Path("drivers/gpu/drm/radeon")
MAP_PATH = Path("docs/base-delta-map.tsv")
REQUIRED_HEADERS = (
    "# schema: gororoba-post-tag-source-delta-map-v1",
    f"# baseline-tag: {BASELINE_TAG}",
    f"# baseline-tag-object: {BASELINE_TAG_OBJECT}",
    f"# baseline-commit: {BASELINE_COMMIT}",
    "# imported-base-map: migration/input/base-delta-map.tsv",
)
MAP_FIELDS = {
    "delta_id",
    "source_commit",
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
SHA40 = re.compile(r"[0-9a-f]{40}")
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


def validate_baseline(
    root: Path,
    expected_tag_object: str = BASELINE_TAG_OBJECT,
    expected_commit: str = BASELINE_COMMIT,
) -> None:
    tag_object = git_output(
        root, "rev-parse", "--verify", f"refs/tags/{BASELINE_TAG}^{{tag}}"
    ).strip()
    require(
        tag_object == expected_tag_object,
        f"source-delta baseline tag object differs: {tag_object}",
    )
    commit = git_output(
        root, "rev-parse", "--verify", f"refs/tags/{BASELINE_TAG}^{{commit}}"
    ).strip()
    require(
        commit == expected_commit,
        f"source-delta baseline peeled commit differs: {commit}",
    )
    git_output(root, "merge-base", "--is-ancestor", expected_commit, "HEAD")


def changed_source_commit_paths(root: Path) -> set[tuple[str, str]]:
    output = git_output(
        root,
        "rev-list",
        "--reverse",
        f"{BASELINE_COMMIT}..HEAD",
        "--",
        DRIVER_ROOT.as_posix(),
    )
    changed: set[tuple[str, str]] = set()
    for commit in output.splitlines():
        parents = git_output(root, "rev-list", "--parents", "-n", "1", commit).split()
        require(
            len(parents) == 2,
            f"post-tag Radeon source commit is a merge: {commit}",
        )
        paths = git_output(
            root,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            commit,
            "--",
            DRIVER_ROOT.as_posix(),
        )
        for source_path in paths.splitlines():
            if source_path:
                changed.add((commit, source_path))
    return changed


def validate(
    rows: list[dict[str, str]],
    changed_commit_paths: set[tuple[str, str]],
) -> None:
    require(
        bool(changed_commit_paths),
        "post-tag source range has no Radeon commit-path pairs",
    )
    keys: set[tuple[str, str, str, str]] = set()
    declared_commit_paths: set[tuple[str, str]] = set()
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
            SHA40.fullmatch(row["source_commit"]) is not None,
            f"source-delta commit is not a full object ID: {row['source_commit']}",
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
        commit_path = (row["source_commit"], row["source_path"])
        require(
            commit_path in changed_commit_paths,
            "source-delta row names no post-tag commit-path change: "
            + ":".join(commit_path),
        )
        key = (
            row["delta_id"],
            row["source_commit"],
            row["source_path"],
            row["symbol_or_range"],
        )
        require(key not in keys, f"source-delta row is duplicated: {key}")
        keys.add(key)
        declared_commit_paths.add(commit_path)

    require(
        declared_commit_paths == changed_commit_paths,
        "source-delta commit-path coverage differs: "
        + ",".join(
            f"{commit}:{path}"
            for commit, path in sorted(
                declared_commit_paths ^ changed_commit_paths
            )
        ),
    )


def self_test(root: Path) -> int:
    map_text = (root / MAP_PATH).read_text(encoding="ascii")
    rows = parse_map(map_text)
    validate_baseline(root)
    changed_commit_paths = changed_source_commit_paths(root)
    validate(rows, changed_commit_paths)
    rejection_count = 0

    invalid_headers = map_text.replace(REQUIRED_HEADERS[0], "# schema: wrong", 1)
    try:
        parse_map(invalid_headers)
    except DeltaMapError:
        rejection_count += 1
    else:
        raise DeltaMapError("self-test accepted a changed map schema")

    for expected_tag_object, expected_commit in (
        ("0" * 40, BASELINE_COMMIT),
        (BASELINE_TAG_OBJECT, "0" * 40),
    ):
        try:
            validate_baseline(root, expected_tag_object, expected_commit)
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted a changed baseline identity")

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
    invalid_commit = copy.deepcopy(rows)
    invalid_commit[0]["source_commit"] = "not-a-commit"
    candidates.append(invalid_commit)
    unrelated_commit = copy.deepcopy(rows)
    unrelated_commit[0]["source_commit"] = "0" * 40
    candidates.append(unrelated_commit)
    escaping_path = copy.deepcopy(rows)
    escaping_path[0]["source_path"] = "../radeon.h"
    candidates.append(escaping_path)
    absent_path = copy.deepcopy(rows)
    absent_path[0]["source_path"] = (DRIVER_ROOT / "absent.c").as_posix()
    candidates.append(absent_path)
    duplicate = copy.deepcopy(rows)
    duplicate.append(copy.deepcopy(duplicate[0]))
    candidates.append(duplicate)
    first_commit_path = sorted(changed_commit_paths)[0]
    missing_coverage = [
        copy.deepcopy(row)
        for row in rows
        if (row["source_commit"], row["source_path"]) != first_commit_path
    ]
    candidates.append(missing_coverage)

    for candidate in candidates:
        try:
            validate(candidate, changed_commit_paths)
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
        validate_baseline(root)
        commit_paths = changed_source_commit_paths(root)
        validate(rows, commit_paths)
    except (DeltaMapError, OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"source delta map: {exc}", file=sys.stderr)
        return 1
    print(
        f"source delta map: "
        f"{len({commit for commit, _path in commit_paths})} commits, "
        f"{len(commit_paths)} commit-paths, "
        f"{len({row['mechanism'] for row in rows})} mechanisms, "
        f"{len(rows)} rows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
