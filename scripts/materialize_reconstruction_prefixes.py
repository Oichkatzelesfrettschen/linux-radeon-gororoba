#!/usr/bin/env python3
"""Materialize and verify every approved Radeon reconstruction prefix."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from manifest_source_tree import load_policy, manifest


class PrefixError(Exception):
    """A reconstruction prefix differs from its approved identity."""


def run(
    command: list[str],
    *,
    cwd: Path,
    input_bytes: bytes | None = None,
) -> bytes:
    result = subprocess.run(
        command,
        cwd=cwd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = (
            result.stdout.decode("utf-8", errors="replace")
            + result.stderr.decode("utf-8", errors="replace")
        ).strip()
        raise PrefixError(f"{' '.join(command)} failed: {detail}")
    return result.stdout


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def read_plan(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source, delimiter="\t"))
    if not rows:
        raise PrefixError(f"plan is empty: {path}")
    try:
        sequences = [int(row["sequence"]) for row in rows]
    except (KeyError, ValueError) as exc:
        raise PrefixError(f"plan has an invalid sequence: {path}") from exc
    if sequences != list(range(1, len(rows) + 1)):
        raise PrefixError(f"plan sequence is not contiguous: {path}")
    return rows


def git_tree(repository: Path) -> str:
    return run(["git", "write-tree"], cwd=repository).decode("utf-8").strip()


def reject_generated_inputs(repository: Path) -> None:
    tracked = run(["git", "ls-files"], cwd=repository).decode("utf-8").splitlines()
    forbidden = [
        path for path in tracked if path == "mkregtable" or path.endswith("_reg_safe.h")
    ]
    if forbidden:
        raise PrefixError(
            "prefix tracks generated build products: " + ", ".join(forbidden)
        )


def expected_manifest_text(root: Path, repository: Path) -> bytes:
    policy = load_policy(root)
    return ("\n".join(manifest(repository, policy)) + "\n").encode("utf-8")


def verify_row(
    root: Path,
    repository: Path,
    row: dict[str, str],
    *,
    corrupt_expected_tree: bool = False,
) -> tuple[str, int]:
    commit_id = row["commit_id"]
    patch_path = root / row["effect_bundle"]
    run(
        ["git", "apply", "--index", "--whitespace=error-all", str(patch_path)],
        cwd=repository,
    )
    run(["git", "diff", "--check", "--cached"], cwd=repository)
    reject_generated_inputs(repository)

    actual_tree = git_tree(repository)
    expected_tree = row["expected_driver_tree"]
    if corrupt_expected_tree:
        expected_tree = "0" * 40
    if actual_tree != expected_tree:
        raise PrefixError(f"{commit_id}: driver tree {actual_tree} != {expected_tree}")

    actual_manifest = expected_manifest_text(root, repository)
    manifest_path = root / row["expected_manifest"]
    recorded_manifest = manifest_path.read_bytes()
    if actual_manifest != recorded_manifest:
        raise PrefixError(
            f"{commit_id}: materialized manifest differs from recorded bytes"
        )
    actual_manifest_sha = sha256_bytes(actual_manifest)
    if actual_manifest_sha != row["expected_manifest_sha256"]:
        raise PrefixError(
            f"{commit_id}: manifest SHA-256 {actual_manifest_sha} != "
            f"{row['expected_manifest_sha256']}"
        )
    return actual_tree, len(actual_manifest.splitlines()) - 2


def materialize(
    root: Path,
    *,
    corrupt_first_expected_tree: bool = False,
    quiet: bool = False,
) -> None:
    upstream = __import__("tomllib").loads(
        (root / "UPSTREAM_BASE.toml").read_text(encoding="utf-8")
    )
    archive = run(
        ["git", "archive", upstream["subtree_tree"]],
        cwd=root,
    )

    with tempfile.TemporaryDirectory(prefix="radeon-prefixes.") as temporary:
        repository = Path(temporary) / "radeon"
        repository.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            source.extractall(repository, filter="data")
        run(["git", "init", "-q"], cwd=repository)
        run(["git", "config", "user.name", "Radeon Prefix Verifier"], cwd=repository)
        run(
            ["git", "config", "user.email", "prefix-verifier.invalid"],
            cwd=repository,
        )
        run(["git", "add", "-A"], cwd=repository)

        initial_tree = git_tree(repository)
        if initial_tree != upstream["subtree_tree"]:
            raise PrefixError(
                f"pristine driver tree {initial_tree} != {upstream['subtree_tree']}"
            )
        run(["git", "commit", "-qm", "pristine"], cwd=repository)

        plans = (
            root / "docs/base-reconstruction-commit-plan.tsv",
            root / "docs/reconstruction-commit-plan.tsv",
        )
        first = True
        for plan_path in plans:
            for row in read_plan(plan_path):
                tree, count = verify_row(
                    root,
                    repository,
                    row,
                    corrupt_expected_tree=corrupt_first_expected_tree and first,
                )
                first = False
                if not quiet:
                    print(f"{row['commit_id']}\t{tree}\t{count} source entries")
                run(["git", "commit", "-qm", row["commit_id"]], cwd=repository)

        base_final = root / "migration/expected-prefixes/base/B14.manifest.tsv"
        base_oracle = root / "migration/input/legacy-base-source-manifest.tsv"
        if base_final.read_bytes() != base_oracle.read_bytes():
            raise PrefixError("B14 manifest differs from the frozen base oracle")
        mechanism_final = (
            root / "migration/expected-prefixes/mechanism/M24.manifest.tsv"
        )
        migration_oracle = (
            root / "migration/input/migration-oracle-0.3-91-exact-context-manifest.tsv"
        )
        if mechanism_final.read_bytes() != migration_oracle.read_bytes():
            raise PrefixError("M24 manifest differs from the frozen migration oracle")


def self_test(root: Path) -> int:
    try:
        materialize(root, quiet=True)
        try:
            materialize(root, corrupt_first_expected_tree=True, quiet=True)
        except PrefixError:
            pass
        else:
            print("prefix calibration accepted a wrong tree", file=sys.stderr)
            return 1
    except PrefixError as exc:
        print(f"prefix calibration failed: {exc}", file=sys.stderr)
        return 1
    print("prefix calibration: exact trees pass and a wrong tree fails closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="source repository carrying plans and the pristine driver subtree",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = args.repository.resolve()

    if args.self_test:
        return self_test(root)
    try:
        materialize(root)
    except (OSError, PrefixError, UnicodeDecodeError) as exc:
        print(f"reconstruction prefixes: {exc}", file=sys.stderr)
        return 1
    print("38 approved prefixes match their driver trees and source manifests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
