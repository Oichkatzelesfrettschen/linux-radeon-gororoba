#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Terascale Functionalists
"""Verify strict profiled-source attestations and calibrate their falsifiers.

The strict record binds an annotated SSH-signed tag to its peeled commit,
repository tree, Radeon subtree, feature policy tree and policy-file hash. It
also binds the external release allowlist, workflow head, clean-tree claims,
local guard commit, evidence classes, and tag-bound source-delta map. The
checker does not query GitHub and does not turn NOT RUN evidence into a pass.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


DRIVER_SUBTREE = "drivers/gpu/drm/radeon"
POLICY_TREE = "policy"
POLICY_FILE = "policy/build-features.toml"
MAP_FILE = "docs/base-delta-map.tsv"
AUTHORITY_LABEL = (
    "radeon-custom packaging/arch/radeon-unified-dkms/radeon-source-tag-allowed-signers"
)
AUTHORITY_RELATIVE_PATH = Path(
    "packaging/arch/radeon-unified-dkms/radeon-source-tag-allowed-signers"
)
TAG_NAME = re.compile(r"radeon-unified-0\.[0-9]+-profiled-source")
OBJECT_ID = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
DURABLE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
CHRONOLOGY_PREFIX = re.compile(
    r"(?:phase|wave|mission|sprint|step|batch|set|group)(?:-|$)"
)

MAP_HEADERS = (
    "# schema: gororoba-post-tag-source-delta-map-v1",
    "# baseline-tag: {tag}",
    "# baseline-tag-object: {tag_object}",
    "# baseline-commit: {commit}",
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

# Schema 2 keeps every claim explicit. The older schema 1 records remain
# readable by TOML but fail closed because these declarations are absent.
STRICT_FIELDS = {
    "schema",
    "tag_name",
    "tag_object",
    "peeled_commit",
    "repository_tree",
    "driver_subtree",
    "driver_tree",
    "feature_policy_tree",
    "feature_policy_sha256",
    "upstream_commit",
    "upstream_subtree",
    "signing_format",
    "signer_principal",
    "signer_fingerprint",
    "allowed_signers_sha256",
    "allowed_signers_path",
    "verification_command",
    "local_verification",
    "published_object_matches_local",
    "profile_workflow_run",
    "profile_workflow_head",
    "profile_workflow_clean_tree",
    "source_commit_6_18_build",
    "source_commit_7_1_build",
    "prod_profile",
    "all_dev_profile",
    "local_parked_guard_commit",
    "local_parked_guard_checker_command",
    "local_parked_guard_checker_result",
    "local_parked_guard_selftest_command",
    "local_parked_guard_selftest_result",
    "local_parked_guard_clean_tree",
    "kernel_6_18",
    "kernel_7_1",
    "package_artifacts",
    "package_signatures",
    "target_install",
    "hardware_operation",
    "source_delta_coverage",
    "source_delta_map_path",
    "source_delta_map_sha256",
    "source_delta_baseline_tag",
    "source_delta_baseline_tag_object",
    "source_delta_baseline_commit",
}
STRING_FIELDS = STRICT_FIELDS - {
    "schema",
    "published_object_matches_local",
    "profile_workflow_run",
    "profile_workflow_clean_tree",
    "local_parked_guard_clean_tree",
}
PASS_FIELDS = {
    "local_verification",
    "source_commit_6_18_build",
    "source_commit_7_1_build",
    "prod_profile",
    "all_dev_profile",
    "local_parked_guard_checker_result",
    "local_parked_guard_selftest_result",
}
NOT_RUN_FIELDS = {
    "package_artifacts",
    "package_signatures",
    "target_install",
    "hardware_operation",
}


class AttestationError(Exception):
    """The attestation does not reproduce the declared source identity."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AttestationError(message)


def parse_toml_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AttestationError(f"{label} is not ASCII") from exc
    try:
        value = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise AttestationError(f"{label} is malformed TOML: {exc}") from exc
    if not isinstance(value, dict):
        raise AttestationError(f"{label} must contain a TOML table")
    return value


def load_record(path: Path) -> dict[str, Any]:
    try:
        return parse_toml_bytes(path.read_bytes(), str(path))
    except FileNotFoundError as exc:
        raise AttestationError(f"missing attestation: {path}") from exc


def git_bytes(repository: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = (
            (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
        )
        raise AttestationError(
            f"git {' '.join(arguments)} failed: {detail or 'unknown error'}"
        )
    return result.stdout


def git_output(repository: Path, *arguments: str) -> str:
    raw = git_bytes(repository, *arguments)
    try:
        return raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise AttestationError(
            f"git {' '.join(arguments)} returned non-ASCII output"
        ) from exc


def exact_string(record: dict[str, Any], field: str) -> str:
    value = record[field]
    require(type(value) is str and value != "", f"{field} must be a nonempty string")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AttestationError(f"{field} is not ASCII") from exc
    return value


def check_schema(record: dict[str, Any]) -> None:
    missing = sorted(STRICT_FIELDS - set(record))
    extra = sorted(set(record) - STRICT_FIELDS)
    require(not missing, "attestation is missing strict fields: " + ", ".join(missing))
    require(not extra, "attestation has unknown fields: " + ", ".join(extra))
    require(
        type(record["schema"]) is int and record["schema"] == 2,
        "schema must be the strict integer 2",
    )
    for field in STRING_FIELDS:
        exact_string(record, field)
    require(
        type(record["published_object_matches_local"]) is bool,
        "published_object_matches_local must be a Boolean",
    )
    require(
        type(record["profile_workflow_run"]) is int
        and record["profile_workflow_run"] > 0,
        "profile_workflow_run must be a positive integer",
    )
    for field in ("profile_workflow_clean_tree", "local_parked_guard_clean_tree"):
        require(type(record[field]) is bool, f"{field} must be a Boolean")

    require(TAG_NAME.fullmatch(record["tag_name"]) is not None, "tag_name is invalid")
    for field in (
        "tag_object",
        "peeled_commit",
        "repository_tree",
        "driver_tree",
        "feature_policy_tree",
        "upstream_commit",
        "upstream_subtree",
        "local_parked_guard_commit",
        "profile_workflow_head",
        "source_delta_baseline_tag_object",
        "source_delta_baseline_commit",
    ):
        if record[field] != "NOT RUN":
            require(
                OBJECT_ID.fullmatch(record[field]) is not None,
                f"{field} must be a full lower-case object ID",
            )
    for field in ("feature_policy_sha256", "allowed_signers_sha256"):
        require(SHA256.fullmatch(record[field]) is not None, f"{field} is invalid")
    require(
        FINGERPRINT.fullmatch(record["signer_fingerprint"]) is not None,
        "signer_fingerprint is invalid",
    )
    require(record["signing_format"] == "ssh", "signing_format must be ssh")
    require(
        record["driver_subtree"] == DRIVER_SUBTREE,
        "driver_subtree must name the imported Radeon subtree",
    )
    require(
        record["allowed_signers_path"] == AUTHORITY_LABEL,
        "allowed_signers_path must name the external package authority",
    )
    require(
        record["verification_command"] == "git -c gpg.format=ssh -c "
        "gpg.ssh.allowedSignersFile=ALLOWED_SIGNERS verify-tag " + record["tag_name"],
        "verification_command is not the reproducible SSH command",
    )
    require(record["local_verification"] == "PASS", "local_verification must be PASS")
    require(
        record["published_object_matches_local"] is True,
        "published_object_matches_local must be true",
    )
    require(
        record["profile_workflow_head"] == record["peeled_commit"],
        "profile_workflow_head must equal the attested peeled commit",
    )
    for field in PASS_FIELDS:
        require(record[field] == "PASS", f"{field} must be PASS")
    for field in NOT_RUN_FIELDS:
        require(record[field] == "NOT RUN", f"{field} must be NOT RUN")
    require(
        record["local_parked_guard_commit"] == record["peeled_commit"],
        "local_parked_guard_commit must equal the attested peeled commit",
    )
    require(
        record["local_parked_guard_checker_command"]
        == "python3 scripts/check_parked_admission_guards.py",
        "local parked guard command is not the declared checker",
    )
    require(
        record["local_parked_guard_selftest_command"]
        == "python3 scripts/check_parked_admission_guards.py --selftest",
        "local parked guard self-test command is not the declared checker",
    )
    require(
        record["profile_workflow_clean_tree"] is True
        and record["local_parked_guard_clean_tree"] is True,
        "clean-tree declarations must be true",
    )
    require(
        record["source_delta_coverage"] in {"PASS", "NOT RUN"},
        "source_delta_coverage must be PASS or NOT RUN",
    )
    if record["source_delta_coverage"] == "PASS":
        require(
            record["source_delta_map_path"] == MAP_FILE,
            "source_delta_map_path must name docs/base-delta-map.tsv",
        )
        require(
            SHA256.fullmatch(record["source_delta_map_sha256"]) is not None,
            "source_delta_map_sha256 is invalid",
        )
        require(
            TAG_NAME.fullmatch(record["source_delta_baseline_tag"]) is not None,
            "source_delta_baseline_tag is invalid",
        )
    else:
        for field in (
            "source_delta_map_path",
            "source_delta_map_sha256",
            "source_delta_baseline_tag",
            "source_delta_baseline_tag_object",
            "source_delta_baseline_commit",
        ):
            require(record[field] == "NOT RUN", f"{field} must be NOT RUN")


def resolve_authority(repository: Path, explicit: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    environment_path = os.environ.get("RADEON_PROFILED_SOURCE_ALLOWED_SIGNERS")
    if environment_path:
        candidates.append(Path(environment_path))
    try:
        common = Path(git_output(repository, "rev-parse", "--git-common-dir"))
        if not common.is_absolute():
            common = (repository / common).resolve()
        candidates.append(
            common.parent.parent / "radeon-custom" / AUTHORITY_RELATIVE_PATH
        )
    except AttestationError:
        pass
    candidates.append(repository.parent / "radeon-custom" / AUTHORITY_RELATIVE_PATH)
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved.is_file():
            require(
                not resolved.is_relative_to(repository.resolve()),
                "allowed signers authority must remain outside the source repository",
            )
            return resolved
    hint = str(candidates[0]) if candidates else AUTHORITY_LABEL
    raise AttestationError(
        "external package allowlist is absent; pass --allowed-signers " + hint
    )


def authority_identity(
    authority: Path,
    expected_principal: str,
) -> tuple[str, str, str]:
    try:
        raw = authority.read_bytes()
        text = raw.decode("ascii")
    except FileNotFoundError as exc:
        raise AttestationError(
            f"allowed signers authority is absent: {authority}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise AttestationError("allowed signers authority is not ASCII") from exc
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    require(
        len(lines) == 1,
        "allowed signers authority must carry exactly one non-comment entry",
    )
    fields = lines[0].split()
    require(
        len(fields) == 3,
        "allowed signers authority entry must contain principal, key type, and key",
    )
    principal, key_type, key_value = fields
    require(principal == expected_principal, "SSH principal differs from authority")
    require(
        key_type == "ssh-ed25519",
        "allowed signers authority key type is not SSH Ed25519",
    )
    key_bytes = f"{key_type} {key_value}\n".encode("ascii")
    result = subprocess.run(
        ["ssh-keygen", "-lf", "-", "-E", "sha256"],
        input=key_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(
        result.returncode == 0,
        "ssh-keygen rejected the external allowed signer key",
    )
    output = result.stdout.decode("ascii", errors="replace").split()
    fingerprint = next(
        (field for field in output if field.startswith("SHA256:")),
        "",
    )
    require(
        FINGERPRINT.fullmatch(fingerprint) is not None,
        "ssh-keygen returned no valid SHA-256 fingerprint",
    )
    return hashlib.sha256(raw).hexdigest(), principal, fingerprint


def verify_tag_signature(
    repository: Path,
    tag_name: str,
    authority: Path,
    principal: str,
    fingerprint: str,
) -> None:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={authority}",
            "verify-tag",
            tag_name,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = result.stdout + result.stderr
    require(
        result.returncode == 0,
        "SSH tag signature verification failed: " + output.strip(),
    )
    require(principal in output, "SSH verification output omits the principal")
    require(fingerprint in output, "SSH verification output omits the fingerprint")


def validate_tree_identity(
    repository: Path,
    record: dict[str, Any],
) -> None:
    tag_name = record["tag_name"]
    tag_ref = f"refs/tags/{tag_name}"
    require(
        git_output(repository, "cat-file", "-t", tag_ref) == "tag",
        "tag reference is not an annotated tag",
    )
    actual_tag_object = git_output(
        repository, "rev-parse", "--verify", f"{tag_ref}^{{tag}}"
    )
    require(
        actual_tag_object == record["tag_object"],
        "tag object differs from the attestation",
    )
    require(
        git_output(repository, "cat-file", "-t", actual_tag_object) == "tag",
        "attested tag object is not a tag object",
    )
    actual_commit = git_output(
        repository, "rev-parse", "--verify", f"{tag_ref}^{{commit}}"
    )
    require(
        actual_commit == record["peeled_commit"],
        "peeled commit differs from the attestation",
    )
    require(
        git_output(repository, "cat-file", "-t", actual_commit) == "commit",
        "peeled object is not a commit",
    )
    actual_repository_tree = git_output(
        repository, "rev-parse", "--verify", f"{actual_commit}^{{tree}}"
    )
    require(
        actual_repository_tree == record["repository_tree"],
        "repository tree differs from the attestation",
    )
    actual_driver_tree = git_output(
        repository,
        "rev-parse",
        "--verify",
        f"{actual_commit}:{DRIVER_SUBTREE}",
    )
    require(
        actual_driver_tree == record["driver_tree"],
        "Radeon subtree differs from the attestation",
    )
    actual_policy_tree = git_output(
        repository, "rev-parse", "--verify", f"{actual_commit}:{POLICY_TREE}"
    )
    require(
        actual_policy_tree == record["feature_policy_tree"],
        "feature policy tree differs from the attestation",
    )
    policy_bytes = git_bytes(repository, "show", f"{actual_commit}:{POLICY_FILE}")
    parse_toml_bytes(policy_bytes, f"{POLICY_FILE} at {actual_commit}")
    require(
        hashlib.sha256(policy_bytes).hexdigest() == record["feature_policy_sha256"],
        "feature policy SHA-256 differs from the attestation",
    )

    upstream = parse_toml_bytes(
        git_bytes(repository, "show", f"{actual_commit}:UPSTREAM_BASE.toml"),
        f"UPSTREAM_BASE.toml at {actual_commit}",
    )
    require(upstream.get("schema") == 1, "tagged UPSTREAM_BASE.toml schema differs")
    require(
        upstream.get("commit") == record["upstream_commit"],
        "upstream commit differs from the tagged base declaration",
    )
    require(
        upstream.get("subtree_tree") == record["upstream_subtree"],
        "upstream subtree differs from the tagged base declaration",
    )


def parse_delta_map(
    raw: bytes,
    baseline_tag: str,
    baseline_tag_object: str,
    baseline_commit: str,
) -> list[dict[str, str]]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AttestationError("tag-bound source-delta map is not ASCII") from exc
    lines = text.splitlines()
    expected_headers = tuple(
        value.format(
            tag=baseline_tag,
            tag_object=baseline_tag_object,
            commit=baseline_commit,
        )
        for value in MAP_HEADERS
    )
    require(
        tuple(lines[: len(expected_headers)]) == expected_headers,
        "source-delta map provenance headers differ",
    )
    data_lines = [line for line in lines if line and not line.startswith("#")]
    require(bool(data_lines), "source-delta map has no rows")
    reader = csv.DictReader(data_lines, delimiter="\t")
    require(
        set(reader.fieldnames or ()) == MAP_FIELDS, "source-delta map schema differs"
    )
    rows: list[dict[str, str]] = []
    for row in reader:
        require(None not in row, "source-delta map carries extra columns")
        typed = {key: value for key, value in row.items() if key is not None}
        require(set(typed) == MAP_FIELDS, "source-delta map row schema differs")
        rows.append(typed)
    require(bool(rows), "source-delta map has no data rows")
    return rows


def changed_commit_paths(
    repository: Path,
    baseline_commit: str,
    target_commit: str,
) -> set[tuple[str, str]]:
    require(
        is_ancestor(repository, baseline_commit, target_commit),
        "source-delta baseline commit is not an ancestor of the tag",
    )
    commits = git_output(
        repository,
        "rev-list",
        "--full-history",
        "--reverse",
        f"{baseline_commit}..{target_commit}",
        "--",
        DRIVER_SUBTREE,
    ).splitlines()
    changed: set[tuple[str, str]] = set()
    for commit in commits:
        parents = git_output(
            repository, "rev-list", "--parents", "-n", "1", commit
        ).split()[1:]
        diff_mode = ["-c"] if len(parents) > 1 else []
        paths = git_output(
            repository,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            *diff_mode,
            commit,
            "--",
            DRIVER_SUBTREE,
        ).splitlines()
        changed.update((commit, path) for path in paths if path)
    return changed


def is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    detail = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
    raise AttestationError(
        "git merge-base --is-ancestor failed: " + (detail or "unknown error")
    )


def validate_delta_map(
    repository: Path,
    record: dict[str, Any],
    map_bytes: bytes | None,
) -> None:
    coverage = record["source_delta_coverage"]
    target_commit = record["peeled_commit"]
    if coverage == "NOT RUN":
        # The absence is valid only when the tag does not advance beyond the
        # fixed source-delta baseline. A later tag cannot hide an unclassified
        # Radeon path change behind NOT RUN.
        baseline = "radeon-unified-0.7-profiled-source"
        baseline_commit = git_output(
            repository, "rev-parse", "--verify", f"refs/tags/{baseline}^{{commit}}"
        )
        if not is_ancestor(repository, baseline_commit, target_commit):
            # A pre-baseline tag has no post-baseline source range. Keep the
            # relation explicit so an unrelated commit cannot use NOT RUN.
            require(
                is_ancestor(repository, target_commit, baseline_commit),
                "NOT RUN source-delta coverage has no baseline relation",
            )
            return
        changed = changed_commit_paths(repository, baseline_commit, target_commit)
        require(not changed, "NOT RUN source-delta coverage hides source changes")
        return

    require(map_bytes is not None, "source-delta map bytes are absent")
    require(
        hashlib.sha256(map_bytes).hexdigest() == record["source_delta_map_sha256"],
        "source-delta map SHA-256 differs from the tag-bound declaration",
    )
    baseline_tag = record["source_delta_baseline_tag"]
    baseline_tag_ref = f"refs/tags/{baseline_tag}"
    baseline_tag_object = git_output(
        repository, "rev-parse", "--verify", f"{baseline_tag_ref}^{{tag}}"
    )
    baseline_commit = git_output(
        repository, "rev-parse", "--verify", f"{baseline_tag_ref}^{{commit}}"
    )
    require(
        baseline_tag_object == record["source_delta_baseline_tag_object"],
        "source-delta baseline tag object differs from the declaration",
    )
    require(
        baseline_commit == record["source_delta_baseline_commit"],
        "source-delta baseline commit differs from the declaration",
    )
    rows = parse_delta_map(
        map_bytes,
        baseline_tag,
        baseline_tag_object,
        baseline_commit,
    )
    changed = changed_commit_paths(repository, baseline_commit, target_commit)
    require(bool(changed), "PASS source-delta coverage has no source changes")
    declared: set[tuple[str, str]] = set()
    keys: set[tuple[str, str, str, str]] = set()
    for row in rows:
        require(
            all(row.get(field) for field in MAP_FIELDS),
            "source-delta map carries an empty field",
        )
        require(
            DURABLE_ID.fullmatch(row["delta_id"]) is not None
            and CHRONOLOGY_PREFIX.match(row["delta_id"]) is None,
            "source-delta ID is not mechanism-named",
        )
        require(
            DURABLE_ID.fullmatch(row["mechanism"]) is not None
            and CHRONOLOGY_PREFIX.match(row["mechanism"]) is None,
            "source-delta mechanism is not durable",
        )
        require(
            OBJECT_ID.fullmatch(row["source_commit"]) is not None,
            "source-delta commit is not a full object ID",
        )
        require(
            row["classification"] in CLASSIFICATIONS,
            "source-delta classification is unknown",
        )
        require(
            row["evidence_class"] in EVIDENCE_CLASSES,
            "source-delta evidence class is unknown",
        )
        path = PurePosixPath(row["source_path"])
        require(
            path.as_posix() == row["source_path"]
            and not path.is_absolute()
            and ".." not in path.parts
            and path.is_relative_to(PurePosixPath(DRIVER_SUBTREE)),
            "source-delta path leaves the imported Radeon subtree",
        )
        pair = (row["source_commit"], row["source_path"])
        require(pair in changed, "source-delta row names no tag-bound source change")
        key = (
            row["delta_id"],
            row["source_commit"],
            row["source_path"],
            row["symbol_or_range"],
        )
        require(key not in keys, "source-delta row is duplicated")
        keys.add(key)
        declared.add(pair)
    require(
        declared == changed,
        "source-delta commit-path coverage differs from the tagged range",
    )


def validate_record(
    repository: Path,
    record: dict[str, Any],
    authority: Path,
    *,
    verify_signature: bool = True,
    map_bytes_override: bytes | None = None,
) -> None:
    check_schema(record)
    validate_tree_identity(repository, record)
    digest, principal, fingerprint = authority_identity(
        authority, record["signer_principal"]
    )
    require(
        digest == record["allowed_signers_sha256"],
        "external allowed-signers SHA-256 differs from the attestation",
    )
    require(principal == record["signer_principal"], "SSH principal differs")
    require(
        fingerprint == record["signer_fingerprint"],
        "SSH signer fingerprint differs",
    )
    if verify_signature:
        verify_tag_signature(
            repository,
            record["tag_name"],
            authority,
            principal,
            fingerprint,
        )
    map_bytes = map_bytes_override
    if map_bytes is None and record["source_delta_coverage"] == "PASS":
        map_bytes = git_bytes(
            repository,
            "show",
            f"{record['peeled_commit']}:{record['source_delta_map_path']}",
        )
    validate_delta_map(repository, record, map_bytes)


def record_paths(repository: Path, selected: list[Path] | None) -> list[Path]:
    if selected:
        return [path.resolve() for path in selected]
    directory = repository / "docs/profiled-source-attestations"
    paths = sorted(directory.glob("*.toml"))
    require(bool(paths), "no profiled-source attestation records exist")
    return paths


def validate_records(
    repository: Path,
    paths: list[Path],
    authority: Path,
) -> None:
    errors: list[str] = []
    workflow_runs: set[int] = set()
    tag_names: set[str] = set()
    for path in paths:
        try:
            record = load_record(path)
            validate_record(repository, record, authority)
            run = record["profile_workflow_run"]
            require(run not in workflow_runs, "profile workflow run is duplicated")
            workflow_runs.add(run)
            require(
                record["tag_name"] not in tag_names,
                "profiled-source tag name is duplicated",
            )
            tag_names.add(record["tag_name"])
        except (AttestationError, OSError, UnicodeError) as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise AttestationError("\n".join(errors))


def expect_failure(
    repository: Path,
    record: dict[str, Any],
    authority: Path,
    label: str,
    *,
    map_bytes_override: bytes | None = None,
) -> None:
    try:
        validate_record(
            repository,
            record,
            authority,
            verify_signature=False,
            map_bytes_override=map_bytes_override,
        )
    except AttestationError:
        print(f"  ok: {label}")
        return
    raise AttestationError(f"self-test accepted {label}")


def expect_parse_failure(raw: bytes, label: str) -> None:
    try:
        parse_toml_bytes(raw, label)
    except AttestationError:
        print(f"  ok: {label}")
        return
    raise AttestationError(f"self-test accepted {label}")


def map_metadata(raw: bytes) -> tuple[str, str, str]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise AttestationError("self-test map is not ASCII") from exc
    require(len(lines) >= 5, "self-test map has incomplete headers")
    values = tuple(line.split(": ", 1)[1] for line in lines[1:4])
    require(len(values) == 3, "self-test map metadata is malformed")
    return values[0], values[1], values[2]


def cryptographic_untrusted_fixture(
    repository: Path,
    record: dict[str, Any],
    authority: Path,
) -> None:
    with tempfile.TemporaryDirectory(prefix="profiled-source-attestation-") as temp:
        key_path = Path(temp) / "untrusted"
        result = subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "untrusted-profiled-source-self-test",
                "-f",
                str(key_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        require(result.returncode == 0, "self-test could not create an SSH key")
        public = (
            key_path.with_name(key_path.name + ".pub")
            .read_text(encoding="ascii")
            .split()
        )
        require(len(public) >= 3, "self-test public key is malformed")
        bad_authority = Path(temp) / "allowed-signers"
        bad_authority.write_text(
            f"{record['signer_principal']} {public[0]} {public[1]}\n",
            encoding="ascii",
        )
        digest, _principal, fingerprint = authority_identity(
            bad_authority, record["signer_principal"]
        )
        changed = copy.deepcopy(record)
        changed["allowed_signers_sha256"] = digest
        changed["signer_fingerprint"] = fingerprint
        try:
            validate_record(
                repository,
                changed,
                bad_authority,
                verify_signature=True,
            )
        except AttestationError as exc:
            print(f"  ok: cryptographic untrusted signer rejected ({exc})")
            return
        raise AttestationError("self-test accepted an untrusted SSH signer")


def self_test(repository: Path, authority: Path) -> int:
    source = repository / (
        "docs/profiled-source-attestations/radeon-unified-0.8-profiled-source.toml"
    )
    original = load_record(source)
    require(
        original.get("tag_name") == "radeon-unified-0.8-profiled-source",
        "self-test source tag differs",
    )
    record = copy.deepcopy(original)
    record["schema"] = 2
    map_bytes = git_bytes(
        repository,
        "show",
        f"{record['peeled_commit']}:{MAP_FILE}",
    )
    baseline_tag, baseline_tag_object, baseline_commit = map_metadata(map_bytes)
    record.update(
        {
            "profile_workflow_head": record["peeled_commit"],
            "profile_workflow_clean_tree": True,
            "local_parked_guard_clean_tree": True,
            "source_delta_coverage": "PASS",
            "source_delta_map_path": MAP_FILE,
            "source_delta_map_sha256": hashlib.sha256(map_bytes).hexdigest(),
            "source_delta_baseline_tag": baseline_tag,
            "source_delta_baseline_tag_object": baseline_tag_object,
            "source_delta_baseline_commit": baseline_commit,
        }
    )
    validate_record(repository, record, authority)
    print("  ok: real signed 0.8 tag and external authority verify")
    baseline_source = repository / (
        "docs/profiled-source-attestations/radeon-unified-0.7-profiled-source.toml"
    )
    baseline_record = copy.deepcopy(load_record(baseline_source))
    baseline_record.pop("parked_guard_checker")
    baseline_record.pop("parked_guard_checker_selftest")
    baseline_record.update(
        {
            "schema": 2,
            "profile_workflow_head": baseline_record["peeled_commit"],
            "profile_workflow_clean_tree": True,
            "local_parked_guard_commit": baseline_record["peeled_commit"],
            "local_parked_guard_checker_command": (
                "python3 scripts/check_parked_admission_guards.py"
            ),
            "local_parked_guard_checker_result": "PASS",
            "local_parked_guard_selftest_command": (
                "python3 scripts/check_parked_admission_guards.py --selftest"
            ),
            "local_parked_guard_selftest_result": "PASS",
            "local_parked_guard_clean_tree": True,
            "source_delta_coverage": "NOT RUN",
            "source_delta_map_path": "NOT RUN",
            "source_delta_map_sha256": "NOT RUN",
            "source_delta_baseline_tag": "NOT RUN",
            "source_delta_baseline_tag_object": "NOT RUN",
            "source_delta_baseline_commit": "NOT RUN",
        }
    )
    validate_record(repository, baseline_record, authority)
    print("  ok: pre-baseline signed tag proves explicit NOT RUN coverage")
    expect_parse_failure(b'schema = 2\nvalue = "\xff"\n', "non-ASCII record")
    expect_parse_failure(b"schema = [2\n", "malformed TOML record")

    mutations: list[tuple[str, str, Any]] = [
        ("schema drift", "schema", 1),
        ("unknown key", "unknown_field", "reject"),
        ("wrong workflow type", "profile_workflow_run", "31329206539"),
        ("tag object drift", "tag_object", "0" * 40),
        ("peeled commit drift", "peeled_commit", "1" * 40),
        ("repository tree drift", "repository_tree", "2" * 40),
        ("Radeon tree drift", "driver_tree", "3" * 40),
        ("policy tree drift", "feature_policy_tree", "4" * 40),
        ("policy hash drift", "feature_policy_sha256", "5" * 64),
        ("allowlist digest drift", "allowed_signers_sha256", "6" * 64),
        ("principal drift", "signer_principal", "untrusted@example.invalid"),
        ("fingerprint drift", "signer_fingerprint", "SHA256:" + "A" * 43),
        ("workflow head drift", "profile_workflow_head", "7" * 40),
        ("PASS evidence drift", "prod_profile", "NOT RUN"),
        ("NOT RUN evidence drift", "hardware_operation", "PASS"),
        ("local guard commit drift", "local_parked_guard_commit", "8" * 40),
        ("clean-tree declaration drift", "profile_workflow_clean_tree", False),
        ("map digest drift", "source_delta_map_sha256", "9" * 64),
        ("map baseline drift", "source_delta_baseline_commit", "a" * 40),
        ("map path drift", "source_delta_map_path", "docs/wrong.tsv"),
    ]
    for label, field, value in mutations:
        changed = copy.deepcopy(record)
        changed[field] = value
        expect_failure(repository, changed, authority, label)

    missing = copy.deepcopy(record)
    del missing["profile_workflow_head"]
    expect_failure(repository, missing, authority, "missing strict field")

    not_run_map = copy.deepcopy(record)
    for field in (
        "source_delta_coverage",
        "source_delta_map_path",
        "source_delta_map_sha256",
        "source_delta_baseline_tag",
        "source_delta_baseline_tag_object",
        "source_delta_baseline_commit",
    ):
        not_run_map[field] = "NOT RUN"
    expect_failure(
        repository,
        not_run_map,
        authority,
        "NOT RUN source-delta concealment",
    )

    tampered_map = map_bytes.replace(b"palm-mechanism", b"hardware-pass", 1)
    tampered_map_record = copy.deepcopy(record)
    tampered_map_record["source_delta_map_sha256"] = hashlib.sha256(
        tampered_map
    ).hexdigest()
    expect_failure(
        repository,
        tampered_map_record,
        authority,
        "tag-bound source-delta semantic tamper",
        map_bytes_override=tampered_map,
    )
    cryptographic_untrusted_fixture(repository, record, authority)
    print("profiled-source attestation calibration: strict identity drift fails closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--allowed-signers",
        type=Path,
        help="external radeon-custom package signer authority",
    )
    parser.add_argument(
        "--attestation",
        type=Path,
        action="append",
        help="strict TOML record; repeat to validate selected records",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve()
    try:
        authority = resolve_authority(repository, args.allowed_signers)
        if args.self_test:
            return self_test(repository, authority)
        paths = record_paths(repository, args.attestation)
        validate_records(repository, paths, authority)
    except (AttestationError, OSError, UnicodeError) as exc:
        print(f"profiled-source attestation: {exc}", file=sys.stderr)
        return 1
    print(
        f"profiled-source attestation: {len(paths)} strict records and signer identity verified"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
