#!/usr/bin/env python3
"""Prove that every closed source-closure entry is present and attributed."""

from __future__ import annotations

import argparse
import copy
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

RADEON_SUBTREE = PurePosixPath("drivers/gpu/drm/radeon")
RECONSTRUCTION_ID = re.compile(r"[BM][0-9]{2}")
OBJECT_ID = re.compile(r"[0-9a-f]{40}")


class ClosureError(Exception):
    """The closure declaration is incomplete or contradicts Git history."""


def load_declaration(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            data = tomllib.load(source)
    except FileNotFoundError as exc:
        raise ClosureError(f"missing declaration: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ClosureError(f"malformed declaration: {exc}") from exc
    if data.get("schema") != 1:
        raise ClosureError("source-closure.toml must declare schema = 1")
    return data


def git(repository: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ClosureError(f"git {' '.join(arguments)} failed: {detail}")
    return result


def closure_path(value: object, table: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ClosureError(f"{table} entry carries no path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ClosureError(f"{table} path is not a normalized relative path: {value}")
    return path


def validate_entry(
    repository: Path,
    table: str,
    entry: object,
) -> tuple[str, str, str]:
    if not isinstance(entry, dict):
        raise ClosureError(f"{table} is not a list of tables")
    path = closure_path(entry.get("path"), table)
    if entry.get("status") != "present":
        raise ClosureError(f"{table} {path} must carry status = \"present\"")

    reconstruction_id = entry.get("reconstruction_id")
    if not isinstance(reconstruction_id, str) or not RECONSTRUCTION_ID.fullmatch(
        reconstruction_id
    ):
        raise ClosureError(f"{table} {path} carries no valid reconstruction_id")

    source_commit = entry.get("source_commit")
    if not isinstance(source_commit, str) or not OBJECT_ID.fullmatch(source_commit):
        raise ClosureError(f"{table} {path} carries no full source_commit")

    current_path = repository / RADEON_SUBTREE / path
    if not current_path.exists():
        raise ClosureError(f"{table} path is absent from the current tree: {path}")

    git(repository, "cat-file", "-e", f"{source_commit}^{{commit}}")
    ancestry = git(
        repository,
        "merge-base",
        "--is-ancestor",
        source_commit,
        "HEAD",
        check=False,
    )
    if ancestry.returncode:
        raise ClosureError(
            f"{table} {path} source commit is not an ancestor of HEAD: {source_commit}"
        )

    trailers = git(
        repository,
        "show",
        "-s",
        "--format=%(trailers:key=Reconstruction-id,valueonly)",
        source_commit,
    ).stdout.split()
    if trailers != [reconstruction_id]:
        found = ",".join(trailers) if trailers else "none"
        raise ClosureError(
            f"{table} {path} expects {reconstruction_id}, source commit carries {found}"
        )

    source_path = (RADEON_SUBTREE / path).as_posix()
    if git(
        repository,
        "cat-file",
        "-e",
        f"{source_commit}:{source_path}",
        check=False,
    ).returncode:
        raise ClosureError(
            f"{table} {path} is absent from source commit {source_commit}"
        )
    return path.as_posix(), reconstruction_id, source_commit


def validate_declaration(
    repository: Path,
    declaration: dict[str, Any],
) -> list[tuple[str, str, str, str]]:
    closure = declaration.get("closure")
    if not isinstance(closure, dict):
        raise ClosureError("source-closure.toml carries no [closure] table")
    if closure.get("upstream_path") != RADEON_SUBTREE.as_posix():
        raise ClosureError(
            f"closure upstream_path must be {RADEON_SUBTREE.as_posix()}"
        )

    proven = []
    for table in ("restored", "retained"):
        entries = declaration.get(table)
        if not isinstance(entries, list) or not entries:
            raise ClosureError(f"source-closure.toml carries no [[{table}]] entry")
        for entry in entries:
            path, reconstruction_id, source_commit = validate_entry(
                repository, table, entry
            )
            proven.append((table, path, reconstruction_id, source_commit))
    return proven


def expect_failure(
    repository: Path,
    declaration: dict[str, Any],
    label: str,
) -> None:
    try:
        validate_declaration(repository, declaration)
    except ClosureError:
        print(f"  ok: {label}")
        return
    raise ClosureError(f"self-test accepted {label}")


def self_test(repository: Path, declaration_path: Path) -> int:
    try:
        original = load_declaration(declaration_path)
        validate_declaration(repository, original)
        print("  ok: current closed entries are proven")

        pending = copy.deepcopy(original)
        pending["restored"][0]["status"] = "pending"
        expect_failure(repository, pending, "pending status")

        no_id = copy.deepcopy(original)
        del no_id["restored"][0]["reconstruction_id"]
        expect_failure(repository, no_id, "missing reconstruction ID")

        no_commit = copy.deepcopy(original)
        del no_commit["retained"][0]["source_commit"]
        expect_failure(repository, no_commit, "missing source commit")

        wrong_id = copy.deepcopy(original)
        wrong_id["retained"][0]["reconstruction_id"] = "M11"
        expect_failure(repository, wrong_id, "mismatched reconstruction trailer")

        unknown_commit = copy.deepcopy(original)
        unknown_commit["retained"][0]["source_commit"] = "0" * 40
        expect_failure(repository, unknown_commit, "unknown source commit")

        absent_path = copy.deepcopy(original)
        absent_path["restored"][0]["path"] = "reg_srcs/not-present"
        expect_failure(repository, absent_path, "absent current path")

        traversal = copy.deepcopy(original)
        traversal["retained"][0]["path"] = "../rs480"
        expect_failure(repository, traversal, "path traversal")
    except (ClosureError, OSError, UnicodeDecodeError) as exc:
        print(f"source-closure calibration: FAIL: {exc}", file=sys.stderr)
        return 1
    print("source-closure calibration: every attribution class fails closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--declaration", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    repository = args.repository.resolve()
    declaration_path = (
        args.declaration.resolve()
        if args.declaration
        else repository / "source-closure.toml"
    )
    if args.self_test:
        return self_test(repository, declaration_path)

    try:
        proven = validate_declaration(
            repository,
            load_declaration(declaration_path),
        )
    except (ClosureError, OSError, UnicodeDecodeError) as exc:
        print(f"source closure: {exc}", file=sys.stderr)
        return 1
    for table, path, reconstruction_id, source_commit in proven:
        print(
            f"{table}: {path} present at {reconstruction_id} "
            f"({source_commit})"
        )
    print(f"source closure: {len(proven)} attributed paths proven")
    return 0


if __name__ == "__main__":
    sys.exit(main())
