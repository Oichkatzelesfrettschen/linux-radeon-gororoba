#!/usr/bin/env python3
"""Validate and build one exact reconstruction commit range."""

from __future__ import annotations

import argparse
import csv
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from check_generated_register_outputs import OutputError
from check_generated_register_outputs import verify_outputs
from check_kernel_build_root import VerificationError as KernelRootError
from check_kernel_build_root import verify as verify_kernel_root
from check_source_delta_map import DeltaMapError
from check_source_delta_map import changed_source_commit_paths
from check_source_delta_map import read_map
from check_source_delta_map import validate as validate_source_delta
from check_source_delta_map import validate_baseline as validate_source_delta_baseline
from check_source_delta_map import validate_union_only_merge
from check_source_delta_map import validate_union_path
from manifest_source_tree import load_policy, manifest


CONTROL_PATTERNS = (
    ".github/workflows/**",
    "scripts/check_reconstruction_history.py",
    "scripts/check_reconstruction_plan.py",
    "scripts/check_generated_register_outputs.py",
    "scripts/check_kernel_build_root.py",
    "scripts/check_source_delta_map.py",
    "scripts/manifest_source_tree.py",
    "scripts/materialize_migration_input.py",
    "MIGRATION_INPUT.toml",
    "migration/**",
    "docs/*reconstruction*plan.tsv",
    "docs/*effect-assignments.tsv",
    "docs/reconstruction-input-inventory.tsv",
    "policy/kernel-compat-files.txt",
    "UPSTREAM_BASE.toml",
    "source-closure.toml",
)
REQUIRED_TRAILERS = (
    "Reconstruction-id",
    "Legacy-patches",
    "Legacy-effects",
    "Future-profile",
    "Kernel-lanes",
    "Evidence-scope",
    "Authorship-status",
    "Assisted-by",
)
UPSTREAM_COMMITS = {
    "B02": (
        "19158c7332468bc28572bdca428e89c7954ee1b1",
        "Alex Deucher",
        "alexander.deucher@amd.com",
    ),
    "B03": (
        "f6e8dc9edf963dbc99085e54f6ced6da9daa6100",
        "Jani Nikula",
        "jani.nikula@intel.com",
    ),
}
HEX_40 = re.compile(r"^[0-9a-f]{40}$")


class HistoryError(Exception):
    """The reconstruction range violates its trusted control plan."""


def run(
    command: list[str],
    *,
    cwd: Path,
    input_bytes: bytes | None = None,
    timeout: int | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise HistoryError(f"{' '.join(command)} timed out") from exc
    if result.returncode:
        detail = (
            result.stdout.decode("utf-8", errors="replace")
            + result.stderr.decode("utf-8", errors="replace")
        ).strip()
        raise HistoryError(f"{' '.join(command)} exited {result.returncode}: {detail}")
    return result.stdout


def git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return run(["git", *arguments], cwd=repository, input_bytes=input_bytes)


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_control(control_root: Path) -> dict[str, object]:
    base = read_tsv(control_root / "docs/base-reconstruction-commit-plan.tsv")
    mechanism = read_tsv(control_root / "docs/reconstruction-commit-plan.tsv")
    base_assignments = read_tsv(
        control_root / "docs/base-reconstruction-effect-assignments.tsv"
    )
    mechanism_assignments = read_tsv(
        control_root / "docs/reconstruction-effect-assignments.tsv"
    )
    plans = {row["commit_id"]: row for row in base + mechanism}
    effects: dict[str, list[str]] = defaultdict(list)
    for row in base_assignments + mechanism_assignments:
        effects[row["commit_id"]].append(row["effect_atom"])
    return {
        "base": base,
        "mechanism": mechanism,
        "plans": plans,
        "effects": effects,
    }


def verify_oracle(control_root: Path, oracle_root: Path) -> None:
    inventory = read_tsv(control_root / "docs/reconstruction-input-inventory.tsv")
    repository = {row["source_repository"] for row in inventory}
    commits = {row["source_commit"] for row in inventory}
    expected_provenance = (
        f"source_repository={next(iter(repository))}\n"
        f"source_commit={next(iter(commits))}\n"
    )
    provenance = (oracle_root / "ORACLE_PROVENANCE").read_text(encoding="utf-8")
    if provenance != expected_provenance:
        raise HistoryError("downloaded oracle provenance differs")
    for row in inventory:
        path = oracle_root / Path(row["copied_path"]).name
        if not path.is_file():
            raise HistoryError(f"downloaded oracle file is missing: {path.name}")
        actual = sha256_file(path)
        if actual != row["sha256"]:
            raise HistoryError(f"downloaded oracle {path.name} has SHA-256 {actual}")


def parse_trailer_lines(text: str) -> dict[str, list[str]]:
    trailers: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        if ": " not in line:
            raise HistoryError(f"malformed trailer output: {line}")
        key, value = line.split(": ", 1)
        trailers[key].append(value)
    return trailers


def commit_trailers(repository: Path, commit: str) -> dict[str, list[str]]:
    message = git(repository, "show", "-s", "--format=%B", commit)
    parsed = git(
        repository,
        "interpret-trailers",
        "--parse",
        input_bytes=message,
    ).decode("utf-8")
    return parse_trailer_lines(parsed)


def changed_paths(repository: Path, commit: str) -> list[str]:
    parent = git(repository, "rev-parse", f"{commit}^").decode("utf-8").strip()
    return changed_paths_between(repository, parent, commit)


def changed_paths_between(
    repository: Path,
    before: str,
    after: str,
) -> list[str]:
    output = git(
        repository,
        "diff",
        "--name-only",
        "--no-renames",
        before,
        after,
    ).decode("utf-8")
    return [line for line in output.splitlines() if line]


def is_control_path(path: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in CONTROL_PATTERNS)


def is_reconstruction_range(
    commits: list[str],
    trailers_by_commit: list[dict[str, list[str]]],
) -> bool:
    marked = [
        bool(trailers.get("Reconstruction-id")) for trailers in trailers_by_commit
    ]
    if any(marked) and not all(marked):
        raise HistoryError("one range cannot mix reconstruction and post-tag commits")
    if not any(marked):
        return False
    for commit, trailers in zip(commits, trailers_by_commit, strict=True):
        if len(trailers["Reconstruction-id"]) != 1:
            raise HistoryError(
                f"{commit[:12]}: requires exactly one Reconstruction-id trailer"
            )
    return True


def generated_source_paths(paths: list[str]) -> list[str]:
    driver_prefix = "drivers/gpu/drm/radeon/"
    return [
        path
        for path in paths
        if path == f"{driver_prefix}mkregtable"
        or (path.startswith(driver_prefix) and path.endswith("_reg_safe.h"))
    ]


def tracked_generated_source(repository: Path, treeish: str) -> list[str]:
    output = git(
        repository,
        "ls-tree",
        "-r",
        "--name-only",
        treeish,
        "--",
        "drivers/gpu/drm/radeon",
    ).decode("utf-8")
    return generated_source_paths(output.splitlines())


def verify_post_tag_paths(commit: str, paths: list[str]) -> None:
    forbidden = [path for path in paths if is_control_path(path)]
    if forbidden:
        raise HistoryError(
            f"{commit[:12]}: post-tag source commit changes control files: "
            + ", ".join(forbidden)
        )
    generated = generated_source_paths(paths)
    if generated:
        raise HistoryError(
            f"{commit[:12]}: generated source is tracked: " + ", ".join(generated)
        )


def require_trusted_merge_parent(
    commit: str,
    parents: list[str],
    trusted_base: str,
) -> None:
    if len(parents) != 2:
        raise HistoryError(f"{commit[:12]}: post-tag source merge requires two parents")
    if parents.count(trusted_base) != 1:
        raise HistoryError(
            f"{commit[:12]}: post-tag source merge lacks the exact trusted base parent"
        )


def verify_post_tag_head(
    commit: str,
    parents: list[str],
    trusted_base: str,
) -> None:
    try:
        require_trusted_merge_parent(commit, parents, trusted_base)
    except HistoryError as exc:
        raise HistoryError(
            f"{commit[:12]}: post-tag source head is not the exact-base union merge"
        ) from exc


def verify_post_tag_commit(
    repository: Path,
    commit: str,
    trusted_base: str,
) -> None:
    commit_and_parents = (
        git(repository, "rev-list", "--parents", "-n", "1", commit)
        .decode("utf-8")
        .split()
    )
    parents = commit_and_parents[1:]
    generated = tracked_generated_source(repository, commit)
    if generated:
        raise HistoryError(
            f"{commit[:12]}: final source tree tracks generated output: "
            + ", ".join(generated)
        )
    if len(parents) == 1:
        verify_post_tag_paths(commit, changed_paths(repository, commit))
    else:
        require_trusted_merge_parent(commit, parents, trusted_base)
        try:
            validate_union_only_merge(
                repository,
                commit,
                parents,
                pathspec=None,
                authoritative_parent=trusted_base,
                authoritative_path=is_control_path,
            )
        except DeltaMapError as exc:
            raise HistoryError(f"{commit[:12]}: {exc}") from exc
        verify_post_tag_paths(
            commit,
            changed_paths_between(repository, trusted_base, commit),
        )
    for parent in parents:
        run(["git", "diff", "--check", parent, commit], cwd=repository)


def verify_source_delta_contract(repository: Path) -> None:
    try:
        validate_source_delta_baseline(repository)
        changed_commit_paths = changed_source_commit_paths(repository)
        validate_source_delta(read_map(repository), changed_commit_paths)
    except DeltaMapError as exc:
        raise HistoryError(f"source-delta contract: {exc}") from exc


def verify_commit_metadata(
    repository: Path,
    commit: str,
    plan: dict[str, str],
    effects: list[str],
) -> None:
    commit_id = plan["commit_id"]
    parents = git(repository, "rev-list", "--parents", "-n", "1", commit).split()
    if len(parents) != 2:
        raise HistoryError(f"{commit_id}: merge commits are forbidden")

    subject = git(repository, "show", "-s", "--format=%s", commit).decode().strip()
    if subject != plan["subject"]:
        raise HistoryError(f"{commit_id}: subject differs from the approved plan")

    trailers = commit_trailers(repository, commit)
    for key in REQUIRED_TRAILERS:
        count = len(trailers.get(key, []))
        if count != 1:
            raise HistoryError(f"{commit_id}: requires exactly one {key} trailer")
    if trailers["Reconstruction-id"][0] != commit_id:
        raise HistoryError(f"{commit_id}: Reconstruction-id trailer differs")
    if split_csv(trailers["Legacy-patches"][0]) != split_csv(plan["legacy_patches"]):
        raise HistoryError(f"{commit_id}: Legacy-patches trailer differs")
    if split_csv(trailers["Legacy-effects"][0]) != effects:
        raise HistoryError(f"{commit_id}: Legacy-effects trailer differs")
    if trailers["Future-profile"][0] != plan["future_profile"]:
        raise HistoryError(f"{commit_id}: Future-profile trailer differs")
    if trailers["Kernel-lanes"][0] != plan["kernel_lanes"]:
        raise HistoryError(f"{commit_id}: Kernel-lanes trailer differs")
    if not trailers["Evidence-scope"][0]:
        raise HistoryError(f"{commit_id}: Evidence-scope is empty")
    if trailers["Authorship-status"][0] not in {"original", "project", "unproven"}:
        raise HistoryError(f"{commit_id}: Authorship-status is invalid")
    if not trailers["Assisted-by"][0]:
        raise HistoryError(f"{commit_id}: Assisted-by is empty")
    if trailers.get("Co-authored-by"):
        raise HistoryError(f"{commit_id}: reconstruction commits carry no co-author")

    expected_authorship = "project"
    if commit_id in UPSTREAM_COMMITS:
        expected_authorship = "original"
    elif commit_id == "B10":
        expected_authorship = "unproven"
    if trailers["Authorship-status"][0] != expected_authorship:
        raise HistoryError(f"{commit_id}: Authorship-status differs from policy")

    if commit_id in UPSTREAM_COMMITS:
        origin, expected_name, expected_email = UPSTREAM_COMMITS[commit_id]
        if trailers.get("Upstream-origin") != [origin]:
            raise HistoryError(f"{commit_id}: Upstream-origin differs")
        author = (
            git(
                repository,
                "show",
                "-s",
                "--format=%an%x00%ae",
                commit,
            )
            .decode("utf-8")
            .strip()
            .split("\0")
        )
        if author != [expected_name, expected_email]:
            raise HistoryError(f"{commit_id}: original author identity differs")
    elif trailers.get("Upstream-origin"):
        raise HistoryError(f"{commit_id}: unexpected Upstream-origin trailer")


def verify_commit_content(
    repository: Path,
    control_root: Path,
    commit: str,
    plan: dict[str, str],
    compatibility_files: set[str],
) -> None:
    commit_id = plan["commit_id"]
    actual_tree = (
        git(
            repository,
            "rev-parse",
            f"{commit}:drivers/gpu/drm/radeon",
        )
        .decode("utf-8")
        .strip()
    )
    if actual_tree != plan["expected_driver_tree"]:
        raise HistoryError(
            f"{commit_id}: driver tree {actual_tree} != {plan['expected_driver_tree']}"
        )

    paths = changed_paths(repository, commit)
    forbidden = [path for path in paths if is_control_path(path)]
    if forbidden:
        raise HistoryError(
            f"{commit_id}: reconstruction commit changes control files: "
            + ", ".join(forbidden)
        )
    source_prefix = "drivers/gpu/drm/radeon/"
    source_changes = [
        path.removeprefix(source_prefix)
        for path in paths
        if path.startswith(source_prefix)
    ]
    outside_source = [path for path in paths if not path.startswith(source_prefix)]
    if outside_source:
        raise HistoryError(
            f"{commit_id}: reconstruction commit changes files outside Radeon source: "
            + ", ".join(outside_source)
        )
    if not source_changes:
        raise HistoryError(f"{commit_id}: commit changes no Radeon source")

    generated = [
        path
        for path in source_changes
        if path == "mkregtable" or path.endswith("_reg_safe.h")
    ]
    if generated:
        raise HistoryError(
            f"{commit_id}: generated source is tracked: {', '.join(generated)}"
        )

    compat_changes = compatibility_files.intersection(source_changes)
    pre_frontier = commit_id.startswith("B") and int(commit_id[1:]) <= 8
    if compat_changes and not pre_frontier and plan["kernel_lanes"] != "6.18,7.1":
        raise HistoryError(f"{commit_id}: compatibility change lacks both kernel lanes")

    parent = git(repository, "rev-parse", f"{commit}^").decode("utf-8").strip()
    run(
        ["git", "diff", "--check", parent, commit],
        cwd=repository,
    )


def range_commits(repository: Path, base: str, head: str) -> list[str]:
    try:
        git(repository, "merge-base", "--is-ancestor", base, head)
    except HistoryError as exc:
        raise HistoryError("base is not an ancestor of head") from exc
    output = git(
        repository,
        "rev-list",
        "--reverse",
        "--ancestry-path",
        f"{base}..{head}",
    ).decode("utf-8")
    commits = output.splitlines()
    if not commits:
        raise HistoryError("reconstruction range contains no commits")
    return commits


def phase_order(
    commit_ids: list[str],
    control: dict[str, object],
    require_complete: bool,
) -> None:
    if all(commit_id.startswith("B") for commit_id in commit_ids):
        expected = [row["commit_id"] for row in control["base"]]
    elif all(commit_id.startswith("M") for commit_id in commit_ids):
        expected = [row["commit_id"] for row in control["mechanism"]]
    else:
        raise HistoryError("one reconstruction range cannot mix B and M commits")
    if commit_ids != expected[: len(commit_ids)]:
        raise HistoryError("Reconstruction-id values are outside topological order")
    if require_complete and commit_ids != expected:
        raise HistoryError("ready range lacks the complete approved phase sequence")


def prepare(
    repository: Path,
    control_root: Path,
    oracle_root: Path,
    base: str,
    head: str,
    require_complete: bool,
) -> list[tuple[str, str]]:
    if git(repository, "rev-parse", "HEAD").decode("utf-8").strip() != head:
        raise HistoryError("subject checkout HEAD differs from --head")
    if git(control_root, "rev-parse", "HEAD").decode("utf-8").strip() != base:
        raise HistoryError("control checkout HEAD differs from --base")
    verify_oracle(control_root, oracle_root)
    control = load_control(control_root)
    plans = control["plans"]
    effects = control["effects"]
    assert isinstance(plans, dict)
    assert isinstance(effects, dict)
    compatibility_files = {
        line
        for line in (control_root / "policy/kernel-compat-files.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    }

    commits = range_commits(repository, base, head)
    trailers_by_commit = [commit_trailers(repository, commit) for commit in commits]
    if not is_reconstruction_range(commits, trailers_by_commit):
        for commit in commits:
            verify_post_tag_commit(repository, commit, base)
        head_and_parents = (
            git(repository, "rev-list", "--parents", "-n", "1", head)
            .decode("utf-8")
            .split()
        )
        verify_post_tag_head(head, head_and_parents[1:], base)
        verify_source_delta_contract(repository)
        print("post-tag source range: no reconstruction matrix")
        return []

    prepared: list[tuple[str, str]] = []
    commit_ids: list[str] = []
    for commit, trailers in zip(commits, trailers_by_commit, strict=True):
        values = trailers.get("Reconstruction-id", [])
        commit_id = values[0]
        if commit_id not in plans:
            raise HistoryError(f"{commit[:12]}: unknown Reconstruction-id {commit_id}")
        plan = plans[commit_id]
        verify_commit_metadata(repository, commit, plan, effects[commit_id])
        verify_commit_content(
            repository,
            control_root,
            commit,
            plan,
            compatibility_files,
        )
        prepared.append((commit_id, commit))
        commit_ids.append(commit_id)
    phase_order(commit_ids, control, require_complete)
    return prepared


def verify_worktree_manifest(
    worktree: Path,
    control_root: Path,
    plan: dict[str, str],
) -> None:
    driver = worktree / "drivers/gpu/drm/radeon"
    policy = load_policy(control_root)
    actual = ("\n".join(manifest(driver, policy)) + "\n").encode("utf-8")
    expected = (control_root / plan["expected_manifest"]).read_bytes()
    if actual != expected:
        raise HistoryError(
            f"{plan['commit_id']}: worktree manifest differs from expected prefix"
        )
    actual_hash = hashlib.sha256(actual).hexdigest()
    if actual_hash != plan["expected_manifest_sha256"]:
        raise HistoryError(f"{plan['commit_id']}: worktree manifest SHA-256 differs")


def registered_worktree(repository: Path, worktree: Path) -> bool:
    output = git(repository, "worktree", "list", "--porcelain").decode("utf-8")
    registered = {
        Path(line.removeprefix("worktree ")).resolve()
        for line in output.splitlines()
        if line.startswith("worktree ")
    }
    return worktree.resolve() in registered


def run_build(
    worktree: Path,
    control_root: Path,
    kernel_root: Path,
    log_path: Path,
    lock_path: Path,
    timeout_seconds: int,
) -> None:
    command = [
        "sh",
        str(control_root / "scripts/build_radeon_module.sh"),
        "--kernel-build-root",
        str(kernel_root),
    ]
    with lock_path.open("w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            result = subprocess.run(
                command,
                cwd=worktree,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            log_path.write_bytes(exc.stdout or b"")
            raise HistoryError(f"module build timed out against {kernel_root}") from exc
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    log_path.write_bytes(result.stdout)
    if result.returncode:
        raise HistoryError(
            f"module build failed against {kernel_root}; see {log_path.name}"
        )


def build_one(
    repository: Path,
    control_root: Path,
    oracle_root: Path,
    base: str,
    head: str,
    commit_id: str,
    root_6_18: Path,
    root_7_1: Path,
    log_root: Path,
    timeout_seconds: int,
) -> None:
    verify_kernel_root(
        root_6_18,
        control_root / "ci/kernel-build-roots/6.18.38-2-cachyos-lts.toml",
        control_root / "ci/kernel-build-roots/6.18.38-2-cachyos-lts.manifest.tsv",
        True,
    )
    verify_kernel_root(
        root_7_1,
        control_root / "ci/kernel-build-roots/7.1.4-1-cachyos.toml",
        control_root / "ci/kernel-build-roots/7.1.4-1-cachyos.manifest.tsv",
        True,
    )
    prepared = prepare(
        repository,
        control_root,
        oracle_root,
        base,
        head,
        require_complete=False,
    )
    matches = [
        (item_id, commit) for item_id, commit in prepared if item_id == commit_id
    ]
    if len(matches) != 1:
        raise HistoryError(f"range does not contain exactly one {commit_id}")
    commit = matches[0][1]
    control = load_control(control_root)
    plans = control["plans"]
    assert isinstance(plans, dict)
    plan = plans[commit_id]

    log_root.mkdir(parents=True, exist_ok=True)
    runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
    temporary = Path(tempfile.mkdtemp(prefix="reconstruct.", dir=runner_temp))
    worktree = temporary / "subject"
    added = False
    try:
        git(repository, "worktree", "add", "--detach", str(worktree), commit)
        added = True
        if not registered_worktree(repository, worktree):
            raise HistoryError("temporary worktree is not registered at the exact path")
        actual = (
            git(
                worktree,
                "rev-parse",
                "HEAD:drivers/gpu/drm/radeon",
            )
            .decode("utf-8")
            .strip()
        )
        if actual != plan["expected_driver_tree"]:
            raise HistoryError(f"{commit_id}: detached worktree tree differs")
        verify_worktree_manifest(worktree, control_root, plan)
        if commit_id in {"B14", "M24"}:
            legacy_count, target_count, compiler = verify_outputs(
                worktree / "drivers/gpu/drm/radeon",
                oracle_root / "legacy-payload-0.3-91-exact-context-manifest.tsv",
            )
            print(
                f"{commit_id}: {legacy_count} legacy generated outputs match; "
                f"{target_count} targets generate with {compiler}"
            )

        lock_path = Path.home() / ".cache/gororoba-ci/radeon-build.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lanes = split_csv(plan["kernel_lanes"])
        roots = {"6.18": root_6_18, "7.1": root_7_1}
        for lane in lanes:
            run_build(
                worktree,
                control_root,
                roots[lane],
                log_root / f"{commit_id}-{lane}.log",
                lock_path,
                timeout_seconds,
            )
    finally:
        if added:
            if not registered_worktree(repository, worktree):
                raise HistoryError(
                    "refusing to remove an unregistered temporary worktree"
                )
            git(repository, "worktree", "remove", "--force", str(worktree))
        if temporary.exists():
            shutil.rmtree(temporary)
    print(f"{commit_id}: exact prefix and {plan['kernel_lanes']} builds pass")


def append_matrix(path: Path, prepared: list[tuple[str, str]]) -> None:
    matrix = json.dumps([commit_id for commit_id, _ in prepared], separators=(",", ":"))
    with path.open("a", encoding="utf-8") as output:
        output.write(f"matrix={matrix}\n")


def self_test() -> int:
    union_rejections = 0
    try:
        parsed = parse_trailer_lines("Reconstruction-id: B01\nKernel-lanes: 6.18\n")
        if parsed["Reconstruction-id"] != ["B01"]:
            raise HistoryError("trailer parser lost Reconstruction-id")
        if not is_control_path("migration/input/oracle.tsv"):
            raise HistoryError("control path matcher missed migration input")
        if not is_control_path("scripts/check_source_delta_map.py"):
            raise HistoryError("control path matcher missed source history policy")
        if not is_control_path(".github/workflows/source-static.yml"):
            raise HistoryError("control path matcher missed workflow policy")
        if not is_control_path("scripts/manifest_source_tree.py"):
            raise HistoryError("control path matcher missed imported policy code")
        if is_control_path("drivers/gpu/drm/radeon/r300.c"):
            raise HistoryError("control path matcher rejected Radeon source")
        sample = {"base": [{"commit_id": "B01"}, {"commit_id": "B02"}]}
        phase_order(["B01"], sample, require_complete=False)
        try:
            phase_order(["B02"], sample, require_complete=False)
        except HistoryError:
            pass
        else:
            raise HistoryError("phase checker accepted an out-of-order prefix")
        if is_reconstruction_range(["a"], [{}]):
            raise HistoryError("range classifier rejected a post-tag commit")
        if not is_reconstruction_range(
            ["a"],
            [{"Reconstruction-id": ["B01"]}],
        ):
            raise HistoryError("range classifier missed a reconstruction commit")
        try:
            is_reconstruction_range(
                ["a", "b"],
                [{}, {"Reconstruction-id": ["B01"]}],
            )
        except HistoryError:
            pass
        else:
            raise HistoryError("range classifier accepted a mixed range")
        try:
            is_reconstruction_range(
                ["a"],
                [{"Reconstruction-id": ["B01", "B02"]}],
            )
        except HistoryError:
            pass
        else:
            raise HistoryError("range classifier accepted duplicate IDs")

        validate_union_path("base", "first", "base", "first", "first.c")
        validate_union_path("base", "base", "second", "second", "second.c")
        for entries in (
            ("base", "same", "same", "novel", "equal.c"),
            ("base", "first", "base", "base", "dropped-first.c"),
            ("base", "base", "second", "base", "dropped-second.c"),
            ("base", "first", "second", "first", "divergent.c"),
        ):
            try:
                validate_union_path(*entries)
            except DeltaMapError:
                union_rejections += 1
            else:
                raise HistoryError("union calibration accepted invalid source content")

        require_trusted_merge_parent("merge", ["feature", "base"], "base")
        verify_post_tag_head("head", ["feature", "base"], "base")
        for parents, trusted_base in (
            ([], "base"),
            (["feature"], "base"),
            (["first", "second"], "base"),
            (["base", "base"], "base"),
            (["first", "base", "second"], "base"),
        ):
            try:
                require_trusted_merge_parent("merge", parents, trusted_base)
            except HistoryError:
                union_rejections += 1
            else:
                raise HistoryError(
                    "union calibration accepted invalid parent authority"
                )
        try:
            verify_post_tag_head("head", ["linear-parent"], "base")
        except HistoryError:
            union_rejections += 1
        else:
            raise HistoryError("union calibration accepted a one-parent head")

        verify_post_tag_paths(
            "commit",
            ["drivers/gpu/drm/radeon/r300.c", "docs/result.md"],
        )
        generated_paths = generated_source_paths(
            [
                "drivers/gpu/drm/radeon/r300_reg_safe.h",
                "drivers/gpu/drm/radeon/mkregtable",
                "scripts/example_reg_safe.h",
            ]
        )
        if generated_paths != [
            "drivers/gpu/drm/radeon/r300_reg_safe.h",
            "drivers/gpu/drm/radeon/mkregtable",
        ]:
            raise HistoryError("generated source tree matcher differs")
        for path in (
            "scripts/check_source_delta_map.py",
            "drivers/gpu/drm/radeon/r300_reg_safe.h",
        ):
            try:
                verify_post_tag_paths("commit", [path])
            except HistoryError:
                union_rejections += 1
            else:
                raise HistoryError("union calibration accepted a forbidden path")
    except HistoryError as exc:
        print(f"reconstruction-history calibration: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "reconstruction-history calibration: trailers, range classes, "
        f"control paths, order, and {union_rejections} union rejections pass"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--control-root", type=Path)
    parser.add_argument("--oracle-root", type=Path)
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--reconstruction-id")
    parser.add_argument("--root-6-18", type=Path)
    parser.add_argument("--root-7-1", type=Path)
    parser.add_argument("--log-root", type=Path)
    parser.add_argument("--build-timeout-seconds", type=int, default=900)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    required = {
        "--repository": args.repository,
        "--control-root": args.control_root,
        "--oracle-root": args.oracle_root,
        "--base": args.base,
        "--head": args.head,
    }
    missing = [key for key, value in required.items() if value is None]
    if missing:
        parser.error("required arguments: " + ", ".join(missing))

    repository = args.repository.resolve()
    control_root = args.control_root.resolve()
    oracle_root = args.oracle_root.resolve()
    try:
        if args.prepare:
            prepared = prepare(
                repository,
                control_root,
                oracle_root,
                args.base,
                args.head,
                args.require_complete,
            )
            if args.github_output:
                append_matrix(args.github_output, prepared)
            print(
                "approved reconstruction order: "
                + " ".join(commit_id for commit_id, _ in prepared)
            )
        elif args.reconstruction_id:
            if not args.root_6_18 or not args.root_7_1 or not args.log_root:
                parser.error("--reconstruction-id requires both roots and --log-root")
            build_one(
                repository,
                control_root,
                oracle_root,
                args.base,
                args.head,
                args.reconstruction_id,
                args.root_6_18.resolve(),
                args.root_7_1.resolve(),
                args.log_root.resolve(),
                args.build_timeout_seconds,
            )
        else:
            parser.error("choose --prepare or --reconstruction-id")
    except (
        HistoryError,
        KeyError,
        KernelRootError,
        OutputError,
        OSError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        print(f"reconstruction history: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
