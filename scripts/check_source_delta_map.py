#!/usr/bin/env python3
"""Verify post-tag Radeon source-delta classification by commit and path."""

from __future__ import annotations

import argparse
import copy
import csv
import re
import subprocess
import sys
from collections.abc import Callable
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


def tree_entry(root: Path, treeish: str, repository_path: str) -> str | None:
    output = git_output(root, "ls-tree", treeish, "--", repository_path).strip()
    if not output:
        return None
    lines = output.splitlines()
    require(
        len(lines) == 1 and "\t" in lines[0],
        f"source-delta tree entry is ambiguous: {treeish}:{repository_path}",
    )
    return lines[0].split("\t", 1)[0]


def validate_union_path(
    base_entry: str | None,
    first_parent_entry: str | None,
    second_parent_entry: str | None,
    result_entry: str | None,
    repository_path: str,
) -> None:
    if first_parent_entry == second_parent_entry:
        require(
            result_entry == first_parent_entry,
            f"union merge changes equal parent content: {repository_path}",
        )
        return
    if first_parent_entry == base_entry:
        require(
            result_entry == second_parent_entry,
            f"union merge drops its second-parent change: {repository_path}",
        )
        return
    if second_parent_entry == base_entry:
        require(
            result_entry == first_parent_entry,
            f"union merge drops its first-parent change: {repository_path}",
        )
        return
    raise DeltaMapError(
        f"union merge parents diverge on one path: {repository_path}"
    )


def validate_union_only_merge(
    root: Path,
    commit: str,
    parents: list[str],
    git_reader: Callable[..., str] = git_output,
    tree_reader: Callable[[Path, str, str], str | None] = tree_entry,
    pathspec: str | None = DRIVER_ROOT.as_posix(),
) -> None:
    require(
        len(parents) == 2,
        f"post-tag source merge has {len(parents)} parents: {commit}",
    )
    merge_bases = git_reader(root, "merge-base", "--all", *parents).splitlines()
    require(
        len(merge_bases) == 1,
        f"post-tag source merge has {len(merge_bases)} merge bases: {commit}",
    )
    merge_base = merge_bases[0]
    union_paths: set[str] = set()
    for treeish in (*parents, commit):
        arguments = [
            "diff",
            "--name-only",
            "--no-renames",
            merge_base,
            treeish,
        ]
        if pathspec is not None:
            arguments.extend(("--", pathspec))
        changed_paths = git_reader(root, *arguments)
        union_paths.update(path for path in changed_paths.splitlines() if path)
    require(bool(union_paths), f"post-tag union merge is path-empty: {commit}")
    for repository_path in sorted(union_paths):
        validate_union_path(
            tree_reader(root, merge_base, repository_path),
            tree_reader(root, parents[0], repository_path),
            tree_reader(root, parents[1], repository_path),
            tree_reader(root, commit, repository_path),
            repository_path,
        )


def source_history_commits(
    root: Path,
    git_reader: Callable[..., str] = git_output,
) -> list[str]:
    output = git_reader(
        root,
        "rev-list",
        "--full-history",
        "--reverse",
        f"{BASELINE_COMMIT}..HEAD",
        "--",
        DRIVER_ROOT.as_posix(),
    )
    return output.splitlines()


def changed_source_commit_paths(root: Path) -> set[tuple[str, str]]:
    changed: set[tuple[str, str]] = set()
    for commit in source_history_commits(root):
        commit_and_parents = git_output(
            root, "rev-list", "--parents", "-n", "1", commit
        ).split()
        parents = commit_and_parents[1:]
        if len(parents) > 1:
            validate_union_only_merge(root, commit, parents)
            continue
        require(len(parents) == 1, f"post-tag source commit has no parent: {commit}")
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

    def full_history_reader(_root: Path, *arguments: str) -> str:
        require(
            arguments
            == (
                "rev-list",
                "--full-history",
                "--reverse",
                f"{BASELINE_COMMIT}..HEAD",
                "--",
                DRIVER_ROOT.as_posix(),
            ),
            "self-test source history traversal differs",
        )
        return "source-merge\nside-parent\n"

    require(
        source_history_commits(root, full_history_reader)
        == ["source-merge", "side-parent"],
        "self-test source history traversal loses commits",
    )

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

    validate_union_path("base", "first", "base", "first", "first-only.c")
    validate_union_path("base", "base", "second", "second", "second-only.c")
    validate_union_path("base", "shared", "shared", "shared", "shared.c")
    validate_union_path("base", None, "base", None, "deleted.c")
    validate_union_path(
        "100644 blob old",
        None,
        "100644 blob old",
        None,
        "renamed-old.c",
    )
    validate_union_path(
        None,
        "100644 blob old",
        None,
        "100644 blob old",
        "renamed-new.c",
    )
    invalid_union_paths = (
        ("base", "shared", "shared", "novel", "equal-parents.c"),
        ("base", "first", "base", "base", "dropped-first.c"),
        ("base", "base", "second", "base", "dropped-second.c"),
        ("base", "first", "second", "first", "divergent-parents.c"),
        (
            "100644 blob content",
            "100644 blob content",
            "100644 blob content",
            "100755 blob content",
            "mode-mutation.c",
        ),
        (
            "100644 blob content",
            "100644 blob content",
            "100644 blob content",
            "160000 commit content",
            "type-mutation.c",
        ),
        (None, None, None, "100644 blob novel", "novel-result.c"),
    )
    for base_entry, first_entry, second_entry, result_entry, source_path in (
        invalid_union_paths
    ):
        try:
            validate_union_path(
                base_entry,
                first_entry,
                second_entry,
                result_entry,
                source_path,
            )
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted an invalid source merge path")

    first_path = (DRIVER_ROOT / "first-parent.c").as_posix()
    second_path = (DRIVER_ROOT / "second-parent.c").as_posix()

    def merge_git_reader(
        result_paths: tuple[str, ...],
    ) -> Callable[..., str]:
        def read_git(_root: Path, *arguments: str) -> str:
            if arguments == ("merge-base", "--all", "first", "second"):
                return "base\n"
            if arguments[:4] == (
                "diff",
                "--name-only",
                "--no-renames",
                "base",
            ):
                require(
                    arguments[5:] in ((), ("--", DRIVER_ROOT.as_posix())),
                    "self-test merge pathspec differs",
                )
                paths_by_tree = {
                    "first": (first_path,),
                    "second": (second_path,),
                    "result": result_paths,
                }
                treeish = arguments[4]
                require(treeish in paths_by_tree, "self-test merge treeish differs")
                return "".join(f"{path}\n" for path in paths_by_tree[treeish])
            raise DeltaMapError("self-test merge git command differs")

        return read_git

    def merge_tree_reader(
        result_second_entry: str,
    ) -> Callable[[Path, str, str], str | None]:
        entries = {
            ("base", first_path): "base-first",
            ("base", second_path): "base-second",
            ("first", first_path): "first-change",
            ("first", second_path): "base-second",
            ("second", first_path): "base-first",
            ("second", second_path): "second-change",
            ("result", first_path): "first-change",
            ("result", second_path): result_second_entry,
        }

        def read_tree(_root: Path, treeish: str, source_path: str) -> str | None:
            return entries[(treeish, source_path)]

        return read_tree

    validate_union_only_merge(
        root,
        "result",
        ["first", "second"],
        git_reader=merge_git_reader((first_path, second_path)),
        tree_reader=merge_tree_reader("second-change"),
    )
    validate_union_only_merge(
        root,
        "result",
        ["first", "second"],
        git_reader=merge_git_reader((first_path, second_path)),
        tree_reader=merge_tree_reader("second-change"),
        pathspec=None,
    )
    try:
        validate_union_only_merge(
            root,
            "result",
            ["first", "second"],
            git_reader=merge_git_reader((first_path,)),
            tree_reader=merge_tree_reader("base-second"),
        )
    except DeltaMapError:
        rejection_count += 1
    else:
        raise DeltaMapError("self-test accepted a dropped parent-only source path")

    for merge_bases in ("", "base\nother\n"):
        def invalid_merge_base_reader(
            _root: Path,
            *arguments: str,
            merge_base_output: str = merge_bases,
        ) -> str:
            if arguments == ("merge-base", "--all", "first", "second"):
                return merge_base_output
            raise DeltaMapError("self-test merge-base command differs")

        try:
            validate_union_only_merge(
                root,
                "result",
                ["first", "second"],
                git_reader=invalid_merge_base_reader,
            )
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted an ambiguous merge base")

    try:
        validate_union_only_merge(
            root,
            "result",
            ["first", "second", "third"],
        )
    except DeltaMapError:
        rejection_count += 1
    else:
        raise DeltaMapError("self-test accepted an octopus source merge")

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
