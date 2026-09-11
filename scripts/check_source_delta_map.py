#!/usr/bin/env python3
"""Verify post-tag Radeon source-delta classification by commit and path."""

from __future__ import annotations

import argparse
import copy
import csv
import re
import subprocess
import sys
import tempfile
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
    return parse_map((root / MAP_PATH).read_text(encoding="utf-8"))


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


def read_blob(root: Path, object_id: str) -> bytes:
    result = subprocess.run(
        ["git", "cat-file", "blob", object_id], cwd=root,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    require(result.returncode == 0, f"cannot read source blob: {object_id}")
    return result.stdout


def validate_appended_map_union(contents: list[bytes]) -> None:
    base, first, second, result = contents
    require(base.endswith(b"\n"), "source map base ends inside a row")
    suffixes = []
    for parent in (first, second):
        require(parent.startswith(base), "source map merge modifies its base rows")
        suffix = parent[len(base):]
        require(bool(suffix) and suffix.endswith(b"\n"), "source map suffix is incomplete")
        require(
            all(line and not line.startswith(b"#") for line in suffix.splitlines()),
            "source map suffix contains a blank or metadata line",
        )
        suffixes.append(suffix)
    require(
        result in (base + suffixes[0] + suffixes[1],
                   base + suffixes[1] + suffixes[0]),
        "source map merge must retain each complete parent suffix once",
    )
    rows = parse_map(result.decode("utf-8"))
    keys = set()
    for row in rows:
        require(
            set(row) == MAP_FIELDS and all(value is not None for value in row.values()),
            "source map union contains an incomplete or overfull row",
        )
        key = tuple(row[field] for field in (
            "delta_id", "source_commit", "source_path", "symbol_or_range"
        ))
        require(key not in keys, "source map union duplicates a row identity")
        keys.add(key)


def map_row_identity(row: dict[str, str]) -> tuple[str, str, str, str]:
    return tuple(row[field] for field in (
        "delta_id", "source_commit", "source_path", "symbol_or_range"
    ))


def validate_crisscross_map_union(
    contents: list[bytes], authoritative_index: int
) -> None:
    first, second, result = (
        parse_map(content.decode("utf-8")) for content in contents
    )
    keyed_parents = []
    for rows in (first, second):
        keyed = {map_row_identity(row): row for row in rows}
        require(len(keyed) == len(rows), "source map parent duplicates a row identity")
        keyed_parents.append(keyed)
    keyed_result = {map_row_identity(row): row for row in result}
    require(len(keyed_result) == len(result), "source map union duplicates a row identity")
    expected_keys = set(keyed_parents[0]) | set(keyed_parents[1])
    require(set(keyed_result) == expected_keys, "source map row union differs")
    for key in expected_keys:
        parent_rows = [parent[key] for parent in keyed_parents if key in parent]
        require(
            all(row == parent_rows[0] for row in parent_rows[1:]),
            "source map parents disagree on a shared row identity",
        )
        require(
            keyed_result[key] == parent_rows[0],
            "source map union alters a parent row",
        )
    require(authoritative_index in {0, 1}, "source map authority index is invalid")
    parent_rows = (first, second)
    authoritative_rows = parent_rows[authoritative_index]
    other_rows = parent_rows[1 - authoritative_index]
    authoritative_keys = {map_row_identity(row) for row in authoritative_rows}
    expected_rows = authoritative_rows + [
        row for row in other_rows if map_row_identity(row) not in authoritative_keys
    ]
    require(result == expected_rows, "source map union order differs from authority")


def is_line_insertion_superset(base: bytes, candidate: bytes) -> bool:
    base_lines = iter(base.splitlines(keepends=True))
    expected = next(base_lines, None)
    for line in candidate.splitlines(keepends=True):
        if line == expected:
            expected = next(base_lines, None)
    return expected is None


def validate_insertion_superset_merge(contents: list[bytes]) -> bool:
    base, first, second, result = contents
    if not (is_line_insertion_superset(base, first)
            and is_line_insertion_superset(base, second)):
        return False
    if result == first and first != second:
        return is_line_insertion_superset(second, first)
    if result == second and first != second:
        return is_line_insertion_superset(first, second)
    return False


def recursive_merge_tree(root: Path, parents: list[str]) -> tuple[str, set[str]]:
    result = subprocess.run(
        ["git", "merge-tree", "--write-tree", "--messages", *parents],
        cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        check=False,
    )
    require(result.returncode in {0, 1}, "recursive merge-tree execution failed")
    require(not result.stderr, "recursive merge-tree wrote diagnostics to stderr")
    lines = result.stdout.splitlines()
    require(bool(lines) and SHA40.fullmatch(lines[0]) is not None,
            "recursive merge-tree omitted its tree identity")
    conflict_paths = {
        match.group(1)
        for line in lines[1:]
        if (match := re.fullmatch(r"[0-9]{6} [0-9a-f]{40} [123]\t(.+)", line))
    }
    require(
        result.returncode == (1 if conflict_paths else 0),
        "recursive merge-tree status differs from its conflict entries",
    )
    return lines[0], conflict_paths


def validate_merged_blobs(
    root: Path,
    entries: tuple[str | None, ...],
    repository_path: str,
    blob_reader: Callable[[Path, str], bytes] = read_blob,
) -> None:
    parsed = []
    for entry in entries:
        require(entry is not None, f"merge requires existing blobs: {repository_path}")
        fields = entry.split() if entry is not None else []
        require(
            len(fields) == 3 and fields[0] in {"100644", "100755"}
            and fields[1] == "blob" and SHA40.fullmatch(fields[2]) is not None,
            f"merge requires regular source blobs: {repository_path}",
        )
        parsed.append(fields)
    require(len(parsed) == 4, "source merge requires four tree entries")
    require(
        len({fields[0] for fields in parsed}) == 1,
        f"source merge changes file mode: {repository_path}",
    )
    contents = [blob_reader(root, fields[2]) for fields in parsed]
    require(
        all(b"\0" not in content for content in contents),
        f"source merge contains binary content: {repository_path}",
    )
    if repository_path == MAP_PATH.as_posix():
        validate_appended_map_union(contents)
        return
    if validate_insertion_superset_merge(contents):
        return
    # Byte IO preserves line endings and the final newline. Plain merge-file
    # supports the Git versions used by both source and package CI.
    with tempfile.TemporaryDirectory(prefix=".source-delta-merge-", dir=root) as scratch:
        paths = [Path(scratch) / name for name in ("base", "first", "second")]
        for path, content in zip(paths, contents[:3]):
            path.write_bytes(content)
        result = subprocess.run(
            ["git", "merge-file", "-p", "--", str(paths[1]), str(paths[0]), str(paths[2])],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
    require(
        result.returncode == 0 and not result.stderr,
        f"source merge has conflicts or diagnostics: {repository_path}",
    )
    require(
        result.stdout == contents[3],
        f"source merge differs from exact combined parent content: {repository_path}",
    )


def validate_union_path(
    base_entry: str | None,
    first_parent_entry: str | None,
    second_parent_entry: str | None,
    result_entry: str | None,
    repository_path: str,
    merge_checker: Callable[[tuple[str | None, ...], str], None] | None = None,
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
    if merge_checker is not None:
        merge_checker(
            (base_entry, first_parent_entry, second_parent_entry, result_entry),
            repository_path,
        )
        return
    raise DeltaMapError(f"union merge parents diverge on one path: {repository_path}")


def validate_union_only_merge(
    root: Path,
    commit: str,
    parents: list[str],
    git_reader: Callable[..., str] = git_output,
    tree_reader: Callable[[Path, str, str], str | None] = tree_entry,
    pathspec: str | None = DRIVER_ROOT.as_posix(),
    authoritative_parent: str | None = None,
    authoritative_path: Callable[[str], bool] | None = None,
) -> None:
    require(
        len(parents) == 2,
        f"post-tag source merge has {len(parents)} parents: {commit}",
    )
    require(
        (authoritative_parent is None) == (authoritative_path is None),
        "authoritative merge parent and path policy must be paired",
    )
    if authoritative_parent is not None:
        require(
            parents.count(authoritative_parent) == 1,
            "authoritative merge parent is not unique",
        )
    merge_bases = git_reader(root, "merge-base", "--all", *parents).splitlines()
    require(bool(merge_bases), f"post-tag source merge has no merge base: {commit}")
    recursive_tree = None
    if len(merge_bases) > 1:
        recursive_tree, conflict_paths = recursive_merge_tree(root, parents)
        require(
            conflict_paths <= {MAP_PATH.as_posix()},
            "recursive source merge conflicts outside the source map: "
            + ", ".join(sorted(conflict_paths)),
        )
    union_paths: set[str] = set()
    for merge_base in merge_bases:
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
        if authoritative_path is not None and authoritative_path(repository_path):
            authoritative_entry = tree_reader(
                root, authoritative_parent, repository_path
            )
            require(
                tree_reader(root, commit, repository_path) == authoritative_entry,
                f"union merge changes authoritative parent content: {repository_path}",
            )
            continue
        if recursive_tree is not None:
            if repository_path == MAP_PATH.as_posix():
                entries = [
                    tree_reader(root, treeish, repository_path)
                    for treeish in (*parents, commit)
                ]
                parsed_entries = []
                for entry in entries:
                    require(entry is not None, "crisscross source map is absent")
                    fields = entry.split()
                    require(
                        len(fields) == 3 and fields[0] == "100644"
                        and fields[1] == "blob"
                        and SHA40.fullmatch(fields[2]) is not None,
                        "crisscross source map is not a regular blob",
                    )
                    parsed_entries.append(fields)
                validate_crisscross_map_union(
                    [read_blob(root, fields[2]) for fields in parsed_entries],
                    parents.index(authoritative_parent),
                )
                continue
            require(
                tree_reader(root, commit, repository_path)
                == tree_reader(root, recursive_tree, repository_path),
                f"source merge differs from recursive result: {repository_path}",
            )
            continue
        validate_union_path(
            tree_reader(root, merge_base, repository_path),
            tree_reader(root, parents[0], repository_path),
            tree_reader(root, parents[1], repository_path),
            tree_reader(root, commit, repository_path),
            repository_path,
            merge_checker=lambda entries, path: validate_merged_blobs(root, entries, path),
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
            for commit, path in sorted(declared_commit_paths ^ changed_commit_paths)
        ),
    )


def self_test(root: Path) -> int:
    map_text = (root / MAP_PATH).read_text(encoding="utf-8")
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
    for (
        base_entry,
        first_entry,
        second_entry,
        result_entry,
        source_path,
    ) in invalid_union_paths:
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

    ordinary_tree_reader = merge_tree_reader("second-change")

    def authoritative_tree_reader(
        _root: Path, treeish: str, source_path: str
    ) -> str | None:
        if treeish == "result" and source_path == first_path:
            return "base-first"
        return ordinary_tree_reader(_root, treeish, source_path)

    validate_union_only_merge(
        root,
        "result",
        ["first", "second"],
        git_reader=merge_git_reader((first_path, second_path)),
        tree_reader=authoritative_tree_reader,
        pathspec=None,
        authoritative_parent="second",
        authoritative_path=lambda path: path == first_path,
    )
    for authoritative_parent, authoritative_path in (
        ("second", None),
        (None, lambda path: path == first_path),
        ("absent", lambda path: path == first_path),
    ):
        try:
            validate_union_only_merge(
                root,
                "result",
                ["first", "second"],
                git_reader=merge_git_reader((first_path, second_path)),
                tree_reader=merge_tree_reader("second-change"),
                pathspec=None,
                authoritative_parent=authoritative_parent,
                authoritative_path=authoritative_path,
            )
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted invalid merge authority")
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

    base_content = b"head\nanchor-one\nanchor-two\nanchor-three\ntail\n"
    first_content = base_content.replace(b"head", b"first-head")
    second_content = base_content.replace(b"tail", b"second-tail")
    combined_content = first_content.replace(b"tail", b"second-tail")
    object_ids = [f"{number:040x}" for number in range(1, 5)]
    regular_entries = tuple(f"100644 blob {object_id}" for object_id in object_ids)

    def check_fixture(
        contents: tuple[bytes, bytes, bytes, bytes],
        entries: tuple[str | None, ...] = regular_entries,
    ) -> None:
        blobs = dict(zip(object_ids, contents))

        def fixture_blob_reader(_root: Path, object_id: str) -> bytes:
            return blobs[object_id]

        validate_union_path(
            *entries, "combined.c",
            merge_checker=lambda values, path: validate_merged_blobs(
                root, values, path, fixture_blob_reader
            ),
        )

    positive_contents = (
        base_content, first_content, second_content, combined_content,
    )
    check_fixture(positive_contents)
    check_fixture(
        positive_contents,
        tuple(entry.replace("100644", "100755") for entry in regular_entries),
    )
    # Final-newline and CRLF preservation are byte-level merge obligations.
    check_fixture(tuple(content.replace(b"\n", b"\r\n") for content in positive_contents))
    invalid_content_fixtures = (
        (base_content, first_content, second_content, first_content),
        (base_content, first_content, second_content, second_content),
        (base_content, first_content, second_content, combined_content + b"novel\n"),
        (base_content, first_content, second_content, combined_content.rstrip(b"\n")),
        (base_content, first_content, base_content.replace(b"head", b"other-head"), first_content),
        tuple(content + b"\0" for content in positive_contents),
    )
    for contents in invalid_content_fixtures:
        try:
            check_fixture(contents)
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted an invalid combined blob")
    for index in range(4):
        for replacement in (None, "100755 blob " + object_ids[index],
                            "120000 blob " + object_ids[index],
                            "160000 commit " + object_ids[index]):
            entries = list(regular_entries)
            entries[index] = replacement
            try:
                check_fixture(positive_contents, tuple(entries))
            except DeltaMapError:
                rejection_count += 1
            else:
                raise DeltaMapError("self-test accepted an invalid combined entry")

    inserted_once = base_content.replace(
        b"anchor-two\n", b"anchor-two\nshared-control\n"
    )
    inserted_twice = inserted_once.replace(
        b"anchor-three\n", b"anchor-three\nnew-control\n"
    )
    for superset_contents in (
        (base_content, inserted_once, inserted_twice, inserted_twice),
        (base_content, inserted_twice, inserted_once, inserted_twice),
    ):
        check_fixture(superset_contents)
    invalid_superset_fixtures = (
        (base_content, inserted_once, inserted_twice, inserted_once),
        (base_content, inserted_once, inserted_twice, inserted_twice + b"novel\n"),
        (base_content, inserted_once, inserted_twice,
         inserted_twice.replace(b"anchor-one", b"changed-anchor")),
        (base_content, inserted_once,
         inserted_twice.replace(b"anchor-one\n", b""), inserted_twice),
        (base_content, inserted_once,
         inserted_twice.replace(b"anchor-two\nshared-control\n",
                                b"shared-control\nanchor-two\n"), inserted_twice),
    )
    for contents in invalid_superset_fixtures:
        try:
            check_fixture(contents)
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted an invalid insertion superset")

    map_header = ("\n".join(REQUIRED_HEADERS) + "\n" +
                  "\t".join(sorted(MAP_FIELDS)) + "\n").encode()

    def map_row(identity: str) -> bytes:
        fields = {field: "value" for field in MAP_FIELDS}
        fields["delta_id"] = identity
        return ("\t".join(fields[field] for field in sorted(MAP_FIELDS)) + "\n").encode()

    map_base = map_header + map_row("base")
    first_suffix = map_row("first-one") + map_row("first-two")
    second_suffix = map_row("second-one") + map_row("second-two")
    map_first = map_base + first_suffix
    map_second = map_base + second_suffix
    for suffix_order in (first_suffix + second_suffix, second_suffix + first_suffix):
        validate_appended_map_union([map_base, map_first, map_second, map_base + suffix_order])
    invalid_map_results = (
        map_first,
        map_second,
        map_base + first_suffix + second_suffix + map_row("novel"),
        map_base + first_suffix + first_suffix + second_suffix,
        map_base + map_row("first-two") + map_row("first-one") + second_suffix,
        map_base + map_row("first-one") + second_suffix + map_row("first-two"),
        map_base + first_suffix + second_suffix.rstrip(b"\n"),
        (map_base + first_suffix + second_suffix).replace(b"first-one", b"mutated"),
    )
    invalid_map_inputs = [
        [map_base, map_first, map_second, result] for result in invalid_map_results
    ]
    invalid_map_inputs.extend((
        [map_base, map_first.replace(b"base\t", b"changed\t"), map_second,
         map_base + first_suffix + second_suffix],
        [map_base, map_first, map_base + first_suffix, map_base + first_suffix * 2],
        [map_base, map_base + map_row("base"), map_second,
         map_base + map_row("base") + second_suffix],
        [map_base, map_base + b"# metadata\n", map_second,
         map_base + b"# metadata\n" + second_suffix],
        [map_base, map_first + b"\n", map_second,
         map_first + b"\n" + second_suffix],
    ))
    for contents in invalid_map_inputs:
        try:
            validate_appended_map_union(contents)
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted an invalid appended map union")

    validate_crisscross_map_union([
        map_first, map_second, map_base + first_suffix + second_suffix,
    ], 0)
    validate_crisscross_map_union([
        map_first, map_second, map_base + second_suffix + first_suffix,
    ], 1)
    crisscross_invalid = (
        map_base + first_suffix,
        map_base + first_suffix + second_suffix + map_row("novel"),
        map_base + first_suffix + first_suffix + second_suffix,
        map_base + map_row("first-two") + map_row("first-one") + second_suffix,
        (map_base + first_suffix + second_suffix).replace(b"first-one", b"changed"),
    )
    for result in crisscross_invalid:
        try:
            validate_crisscross_map_union([map_first, map_second, result], 0)
        except DeltaMapError:
            rejection_count += 1
        else:
            raise DeltaMapError("self-test accepted an invalid crisscross map union")

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
