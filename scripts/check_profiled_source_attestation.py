#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify strict profiled-source attestations and calibrate their falsifiers.

The strict record binds an annotated SSH-signed tag to its peeled commit,
repository tree, Radeon subtree, feature policy tree and policy-file hash. It
also binds the external release allowlist and tag-bound source-delta map. It
checks workflow, guard, clean-tree, and evidence-result declarations without
promoting them to independently verified execution evidence. The published
object match remains an explicit declaration because the checker does not query
GitHub. The checker does not turn NOT RUN evidence into a pass.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

if not __package__:
    # Direct script execution starts with scripts/ on sys.path; package
    # execution already resolves imports from the repository root.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.check_source_delta_map import (
    BASELINE_COMMIT as CANONICAL_BASELINE_COMMIT,
    BASELINE_TAG as CANONICAL_BASELINE_TAG,
    BASELINE_TAG_OBJECT as CANONICAL_BASELINE_TAG_OBJECT,
    DRIVER_ROOT as CANONICAL_DRIVER_ROOT,
    MAP_PATH as CANONICAL_MAP_PATH,
    DeltaMapError,
    git_output as canonical_git_output,
    parse_map as canonical_parse_map,
    source_history_commits as canonical_source_history_commits,
    tree_entry as canonical_tree_entry,
    validate as canonical_validate_map,
    validate_union_only_merge as canonical_validate_union_only_merge,
)


DRIVER_SUBTREE = CANONICAL_DRIVER_ROOT.as_posix()
POLICY_TREE = "policy"
POLICY_FILE = "policy/build-features.toml"
MAP_FILE = CANONICAL_MAP_PATH.as_posix()
BASELINE_TAG = CANONICAL_BASELINE_TAG
BASELINE_TAG_OBJECT = CANONICAL_BASELINE_TAG_OBJECT
BASELINE_COMMIT = CANONICAL_BASELINE_COMMIT
AUTHORITY_LABEL = (
    "radeon-custom packaging/arch/radeon-unified-dkms/radeon-source-tag-allowed-signers"
)
AUTHORITY_RELATIVE_PATH = Path(
    "packaging/arch/radeon-unified-dkms/radeon-source-tag-allowed-signers"
)
VERSION_COMPONENT = r"(?:0|[1-9][0-9]*)"
TAG_NAME = re.compile(
    rf"radeon-unified-0\.{VERSION_COMPONENT}"
    rf"(?:(?:-{VERSION_COMPONENT})|(?:\.{VERSION_COMPONENT}))?"
    r"-profiled-source"
)
OBJECT_ID = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")

# These fields are integrity-checked declarations. The checker does not
# verify the published object, workflow run, clean checkout, local guard
# execution, or profile results from these self-declared values.
DECLARATION_FIELDS = {
    "profile_workflow_run",
    "profile_workflow_head",
    "profile_workflow_clean_tree",
    "published_object_matches_local_declared",
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
}

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
    "published_object_matches_local_declared",
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
    "published_object_matches_local_declared",
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
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AttestationError(f"{label} is not UTF-8 text") from exc
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
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise AttestationError(
            f"git {' '.join(arguments)} returned output that is not UTF-8 text"
        ) from exc


def exact_string(record: dict[str, Any], field: str) -> str:
    value = record[field]
    if type(value) is not str or value == "":
        raise AttestationError(f"{field} must be a nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AttestationError(f"{field} is not UTF-8 text") from exc
    return value


def validate_tag_name(value: str, field: str = "tag_name") -> None:
    require(
        TAG_NAME.fullmatch(value) is not None,
        f"{field} does not match radeon-unified-0.<minor>(-<patch>|.<patch>)?-profiled-source",
    )


def check_schema(record: dict[str, Any]) -> None:
    missing = sorted(STRICT_FIELDS - set(record))
    extra = sorted(set(record) - STRICT_FIELDS)
    require(not missing, "attestation is missing strict fields: " + ", ".join(missing))
    require(not extra, "attestation has unknown fields: " + ", ".join(extra))
    require(
        DECLARATION_FIELDS <= set(record),
        "attestation is missing explicit declaration fields",
    )
    require(
        type(record["schema"]) is int and record["schema"] == 2,
        "schema must be the strict integer 2",
    )
    for field in STRING_FIELDS:
        exact_string(record, field)
    require(
        type(record["published_object_matches_local_declared"]) is bool,
        "published_object_matches_local_declared must be a Boolean",
    )
    require(
        type(record["profile_workflow_run"]) is int
        and record["profile_workflow_run"] > 0,
        "profile_workflow_run must be a positive integer",
    )
    for field in ("profile_workflow_clean_tree", "local_parked_guard_clean_tree"):
        require(type(record[field]) is bool, f"{field} must be a Boolean")

    validate_tag_name(record["tag_name"])
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
        record["published_object_matches_local_declared"] is True,
        "published_object_matches_local_declared must be true",
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
        validate_tag_name(
            record["source_delta_baseline_tag"],
            "source_delta_baseline_tag",
        )
        require(
            record["source_delta_baseline_tag"] == BASELINE_TAG,
            "source-delta baseline tag differs from canonical 0.7 identity",
        )
        require(
            record["source_delta_baseline_tag_object"] == BASELINE_TAG_OBJECT,
            "source-delta baseline tag object differs from canonical identity",
        )
        require(
            record["source_delta_baseline_commit"] == BASELINE_COMMIT,
            "source-delta baseline commit differs from canonical identity",
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


UPSTREAM_ROOT_FIELDS = {
    "schema",
    "repository",
    "tag",
    "tag_object",
    "commit",
    "path",
    "subtree_tree",
    "import_method",
    "import_script",
    "signature_verified",
    "target",
}
UPSTREAM_TARGET_FIELDS = {"tag", "commit", "subtree_tree"}


def strict_text_value(value: Any, field: str) -> str:
    if type(value) is not str or value == "":
        raise AttestationError(f"{field} must be a nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AttestationError(f"{field} is not UTF-8 text") from exc
    return value


def validate_upstream_declaration(
    repository: Path,
    commit: str,
    record: dict[str, Any],
) -> None:
    upstream = parse_toml_bytes(
        git_bytes(repository, "show", f"{commit}:UPSTREAM_BASE.toml"),
        f"UPSTREAM_BASE.toml at {commit}",
    )
    validate_upstream_data(repository, upstream, record)


def validate_upstream_data(
    repository: Path,
    upstream: dict[str, Any],
    record: dict[str, Any],
) -> None:
    require(
        set(upstream) == UPSTREAM_ROOT_FIELDS,
        "UPSTREAM_BASE.toml root schema differs",
    )
    require(
        type(upstream["schema"]) is int and upstream["schema"] == 1,
        "UPSTREAM_BASE.toml schema must be the integer 1",
    )
    for field in (
        "repository",
        "tag",
        "tag_object",
        "commit",
        "path",
        "subtree_tree",
        "import_method",
        "import_script",
    ):
        strict_text_value(upstream[field], f"UPSTREAM_BASE.toml {field}")
    require(
        type(upstream["signature_verified"]) is bool,
        "UPSTREAM_BASE.toml signature_verified must be a Boolean",
    )
    require(
        upstream["signature_verified"] is False,
        "UPSTREAM_BASE.toml signature proof must remain explicitly false",
    )
    require(
        OBJECT_ID.fullmatch(upstream["tag_object"]) is not None
        and OBJECT_ID.fullmatch(upstream["commit"]) is not None
        and OBJECT_ID.fullmatch(upstream["subtree_tree"]) is not None,
        "UPSTREAM_BASE.toml carries an invalid object identity",
    )
    # The upstream commit and annotated tag objects live in the external
    # kernel repository and are absent from the local object database.
    # Their local proof stops at strict object-ID syntax; the imported subtree
    # tree remains locally available for a Git object-type check.
    require_git_object_type(
        repository,
        upstream["subtree_tree"],
        "tree",
        "UPSTREAM_BASE.toml subtree_tree",
    )
    require(
        upstream["path"] == DRIVER_SUBTREE,
        "UPSTREAM_BASE.toml path differs from the Radeon subtree",
    )
    target = upstream["target"]
    require(
        type(target) is dict and set(target) == {"mainline"},
        "UPSTREAM_BASE.toml target schema differs",
    )
    mainline = target["mainline"]
    require(
        type(mainline) is dict and set(mainline) == UPSTREAM_TARGET_FIELDS,
        "UPSTREAM_BASE.toml mainline target schema differs",
    )
    for field in UPSTREAM_TARGET_FIELDS:
        strict_text_value(
            mainline[field], f"UPSTREAM_BASE.toml target.mainline {field}"
        )
    require(
        OBJECT_ID.fullmatch(mainline["commit"]) is not None
        and OBJECT_ID.fullmatch(mainline["subtree_tree"]) is not None,
        "UPSTREAM_BASE.toml mainline identity is invalid",
    )
    require(
        upstream["commit"] == record["upstream_commit"],
        "upstream commit differs from the tagged base declaration",
    )
    require(
        upstream["subtree_tree"] == record["upstream_subtree"],
        "upstream subtree differs from the tagged base declaration",
    )


def require_git_object_type(
    repository: Path,
    object_id: str,
    expected_type: str,
    field: str,
) -> None:
    actual_type = git_output(repository, "cat-file", "-t", object_id)
    require(
        actual_type == expected_type,
        f"{field} object type is {actual_type}, expected {expected_type}",
    )


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
        text = raw.decode("utf-8")
    except FileNotFoundError as exc:
        raise AttestationError(
            f"allowed signers authority is absent: {authority}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise AttestationError("allowed signers authority is not UTF-8 text") from exc
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
    key_bytes = f"{key_type} {key_value}\n".encode("utf-8")
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
    output = result.stdout.decode("utf-8", errors="replace").split()
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
    require_git_object_type(repository, actual_tag_object, "tag", "tag_object")
    actual_commit = git_output(
        repository, "rev-parse", "--verify", f"{tag_ref}^{{commit}}"
    )
    require(
        actual_commit == record["peeled_commit"],
        "peeled commit differs from the attestation",
    )
    require_git_object_type(repository, actual_commit, "commit", "peeled_commit")
    actual_repository_tree = git_output(
        repository, "rev-parse", "--verify", f"{actual_commit}^{{tree}}"
    )
    require(
        actual_repository_tree == record["repository_tree"],
        "repository tree differs from the attestation",
    )
    require_git_object_type(
        repository, actual_repository_tree, "tree", "repository_tree"
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
    require_git_object_type(repository, actual_driver_tree, "tree", "driver_tree")
    actual_policy_tree = git_output(
        repository, "rev-parse", "--verify", f"{actual_commit}:{POLICY_TREE}"
    )
    require(
        actual_policy_tree == record["feature_policy_tree"],
        "feature policy tree differs from the attestation",
    )
    require_git_object_type(
        repository, actual_policy_tree, "tree", "feature_policy_tree"
    )
    policy_bytes = git_bytes(repository, "show", f"{actual_commit}:{POLICY_FILE}")
    parse_toml_bytes(policy_bytes, f"{POLICY_FILE} at {actual_commit}")
    require(
        hashlib.sha256(policy_bytes).hexdigest() == record["feature_policy_sha256"],
        "feature policy SHA-256 differs from the attestation",
    )

    validate_upstream_declaration(repository, actual_commit, record)


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


def canonical_baseline_identity(repository: Path) -> None:
    baseline_ref = f"refs/tags/{BASELINE_TAG}"
    tag_object = git_output(
        repository, "rev-parse", "--verify", f"{baseline_ref}^{{tag}}"
    )
    commit = git_output(
        repository, "rev-parse", "--verify", f"{baseline_ref}^{{commit}}"
    )
    require(
        tag_object == BASELINE_TAG_OBJECT,
        "source-delta baseline tag object differs from canonical identity",
    )
    require(
        commit == BASELINE_COMMIT,
        "source-delta baseline commit differs from canonical identity",
    )
    require_git_object_type(repository, tag_object, "tag", "baseline tag object")
    require_git_object_type(repository, commit, "commit", "baseline commit")


def source_history_commits_at(repository: Path, target_commit: str) -> list[str]:
    canonical_arguments = (
        "rev-list",
        "--full-history",
        "--reverse",
        f"{BASELINE_COMMIT}..HEAD",
        "--",
        DRIVER_SUBTREE,
    )

    def target_reader(root: Path, *arguments: str) -> str:
        if arguments == canonical_arguments:
            arguments = (
                "rev-list",
                "--full-history",
                "--reverse",
                f"{BASELINE_COMMIT}..{target_commit}",
                "--",
                DRIVER_SUBTREE,
            )
        return canonical_git_output(root, *arguments)

    return canonical_source_history_commits(repository, target_reader)


def changed_source_commit_paths_at(
    repository: Path,
    target_commit: str,
) -> set[tuple[str, str]]:
    changed: set[tuple[str, str]] = set()
    for commit in source_history_commits_at(repository, target_commit):
        commit_and_parents = canonical_git_output(
            repository, "rev-list", "--parents", "-n", "1", commit
        ).split()
        parents = commit_and_parents[1:]
        if len(parents) > 1:
            try:
                canonical_validate_union_only_merge(
                    repository,
                    commit,
                    parents,
                    git_reader=canonical_git_output,
                    tree_reader=canonical_tree_entry,
                    pathspec=DRIVER_SUBTREE,
                )
            except DeltaMapError as exc:
                raise AttestationError(str(exc)) from exc
            continue
        require(
            len(parents) == 1,
            f"post-tag source commit has no parent: {commit}",
        )
        paths = canonical_git_output(
            repository,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "--no-renames",
            "-r",
            commit,
            "--",
            DRIVER_SUBTREE,
        )
        for source_path in paths.splitlines():
            if source_path:
                changed.add((commit, source_path))
    return changed


def validate_delta_map(
    repository: Path,
    record: dict[str, Any],
    map_bytes: bytes | None,
    *,
    ancestor_checker: Callable[[Path, str, str], bool] = is_ancestor,
) -> None:
    coverage = record["source_delta_coverage"]
    target_commit = record["peeled_commit"]
    if coverage == "NOT RUN":
        # The absence is valid only when the tag does not advance beyond the
        # fixed source-delta baseline. A later tag cannot hide an unclassified
        # Radeon path change behind NOT RUN.
        canonical_baseline_identity(repository)
        baseline_commit = BASELINE_COMMIT
        if not ancestor_checker(repository, baseline_commit, target_commit):
            # A pre-baseline tag has no post-baseline source range. Keep the
            # relation explicit so an unrelated commit cannot use NOT RUN.
            require(
                ancestor_checker(repository, target_commit, baseline_commit),
                "NOT RUN source-delta coverage has no baseline relation",
            )
            return
        changed = changed_source_commit_paths_at(repository, target_commit)
        require(not changed, "NOT RUN source-delta coverage hides source changes")
        return

    if map_bytes is None:
        raise AttestationError("source-delta map bytes are absent")
    canonical_baseline_identity(repository)
    require(
        ancestor_checker(repository, BASELINE_COMMIT, target_commit),
        "PASS source-delta target is not a descendant of canonical baseline",
    )
    require(
        hashlib.sha256(map_bytes).hexdigest() == record["source_delta_map_sha256"],
        "source-delta map SHA-256 differs from the tag-bound declaration",
    )
    require(
        record["source_delta_baseline_tag"] == BASELINE_TAG
        and record["source_delta_baseline_tag_object"] == BASELINE_TAG_OBJECT
        and record["source_delta_baseline_commit"] == BASELINE_COMMIT,
        "source-delta baseline declaration differs from canonical identity",
    )
    try:
        rows = canonical_parse_map(map_bytes.decode("utf-8"))
        changed = changed_source_commit_paths_at(repository, target_commit)
        canonical_validate_map(rows, changed)
    except (UnicodeDecodeError, DeltaMapError) as exc:
        raise AttestationError(f"tag-bound source-delta map differs: {exc}") from exc
    require(bool(changed), "PASS source-delta coverage has no source changes")


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


def record_paths(
    repository: Path,
    selected: list[Path] | None,
    *,
    all_strict: bool,
) -> list[Path]:
    if selected:
        require(not all_strict, "--attestation and --all-strict are mutually exclusive")
        return [path.resolve() for path in selected]
    require(
        all_strict,
        "select --attestation PATH or pass --all-strict; no default record scope exists",
    )
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


def expect_tag_failure(value: str, label: str) -> None:
    try:
        validate_tag_name(value, "self-test tag")
    except AttestationError:
        print(f"  ok: {label}")
        return
    raise AttestationError(f"self-test accepted {label}")


def expect_upstream_failure(
    repository: Path,
    upstream: dict[str, Any],
    record: dict[str, Any],
    label: str,
) -> None:
    try:
        validate_upstream_data(repository, upstream, record)
    except AttestationError:
        print(f"  ok: {label}")
        return
    raise AttestationError(f"self-test accepted {label}")


def expect_union_failure(repository: Path, label: str) -> None:
    source_path = DRIVER_SUBTREE + "/divergent.c"

    def merge_reader(_root: Path, *arguments: str) -> str:
        if arguments == ("merge-base", "--all", "first", "second"):
            return "base\n"
        if arguments[:4] == (
            "diff",
            "--name-only",
            "--no-renames",
            "base",
        ):
            require(
                len(arguments) == 7
                and arguments[4] in {"first", "second", "result"}
                and arguments[5:] == ("--", DRIVER_SUBTREE),
                "self-test source-scoped merge command differs",
            )
            return source_path + "\n"
        raise AttestationError("self-test source-scoped merge command differs")

    def merge_tree_reader(_root: Path, treeish: str, path: str) -> str:
        require(path == source_path, "self-test source-scoped merge path differs")
        entries = {
            "base": "base-entry",
            "first": "first-entry",
            "second": "second-entry",
            "result": "first-entry",
        }
        return entries[treeish]

    try:
        canonical_validate_union_only_merge(
            repository,
            "result",
            ["first", "second"],
            git_reader=merge_reader,
            tree_reader=merge_tree_reader,
            pathspec=DRIVER_SUBTREE,
        )
    except DeltaMapError:
        print(f"  ok: {label}")
        return
    raise AttestationError(f"self-test accepted {label}")


def calibrate_real_merge_history(repository: Path) -> None:
    ledger_merge = "2edbc15b74640472778362313c44b7da5e63736d"
    ledger_parents = canonical_git_output(
        repository, "rev-list", "--parents", "-n", "1", ledger_merge
    ).split()[1:]
    try:
        canonical_validate_union_only_merge(
            repository,
            ledger_merge,
            ledger_parents,
            git_reader=canonical_git_output,
            tree_reader=canonical_tree_entry,
            pathspec=None,
        )
    except DeltaMapError as exc:
        require(
            "docs/base-delta-map.tsv" in str(exc),
            "self-test documentation merge reports the wrong whole-tree path",
        )
    else:
        raise AttestationError(
            "self-test documentation merge unexpectedly passes whole-tree union"
        )
    try:
        canonical_validate_union_only_merge(
            repository,
            ledger_merge,
            ledger_parents,
            git_reader=canonical_git_output,
            tree_reader=canonical_tree_entry,
            pathspec=DRIVER_SUBTREE,
        )
    except DeltaMapError as exc:
        raise AttestationError(
            f"self-test source-scoped documentation merge rejected: {exc}"
        ) from exc
    print("  ok: documentation ledger divergence stays outside source attestation")

    ec5_target = "ec5b88802441720b0b972b1b2a92e53171094f31"
    history = source_history_commits_at(repository, ec5_target)
    require(
        bool(history) and history[-1] == ec5_target,
        "self-test ec5b888 target history is incomplete",
    )
    changed = changed_source_commit_paths_at(repository, ec5_target)
    require(
        (
            "285c87433b3fd7830806c9f47f4da5312a018cf5",
            DRIVER_SUBTREE + "/radeon_rs4xx_dev.c",
        )
        in changed,
        "self-test ec5b888 source history lost a driver path",
    )
    try:
        ec5_map = canonical_parse_map(
            git_bytes(repository, "show", f"{ec5_target}:{MAP_FILE}").decode("utf-8")
        )
        canonical_validate_map(ec5_map, changed)
    except (UnicodeDecodeError, DeltaMapError) as exc:
        raise AttestationError(f"self-test ec5b888 source map differs: {exc}") from exc
    print("  ok: ec5b888 source history and map validate through source-scoped unions")


def expect_parse_failure(raw: bytes, label: str) -> None:
    try:
        parse_toml_bytes(raw, label)
    except AttestationError:
        print(f"  ok: {label}")
        return
    raise AttestationError(f"self-test accepted {label}")


def map_metadata(raw: bytes) -> tuple[str, str, str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AttestationError("self-test map is not UTF-8 text") from exc
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
            .read_text(encoding="utf-8")
            .split()
        )
        require(len(public) >= 3, "self-test public key is malformed")
        bad_authority = Path(temp) / "allowed-signers"
        bad_authority.write_text(
            f"{record['signer_principal']} {public[0]} {public[1]}\n",
            encoding="utf-8",
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
    record["published_object_matches_local_declared"] = record.pop(
        "published_object_matches_local"
    )
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
    print(
        "  ok: real signed 0.8 source identity and map verify; "
        "published-object, workflow, and guard fields remain declarations"
    )
    target_history = source_history_commits_at(repository, record["peeled_commit"])
    require(
        "3840b3e01c98348242fa6c5e4307f5c43307f541" not in target_history,
        "self-test source history leaked commits after the attested tag",
    )
    print("  ok: source history stays bound to the attested target commit")
    separate_target = copy.deepcopy(record)
    separate_target["peeled_commit"] = "f" * 40

    def separate_root_checker(
        _repository: Path,
        ancestor: str,
        descendant: str,
    ) -> bool:
        require(
            ancestor == BASELINE_COMMIT and descendant == "f" * 40,
            "self-test target ancestry mutant differs",
        )
        return False

    try:
        validate_delta_map(
            repository,
            separate_target,
            map_bytes,
            ancestor_checker=separate_root_checker,
        )
    except AttestationError as exc:
        require(
            "not a descendant of canonical baseline" in str(exc),
            "self-test target ancestry mutant reports the wrong rejection",
        )
        print("  ok: separately rooted PASS target is rejected")
    else:
        raise AttestationError("self-test accepted a separately rooted PASS target")
    baseline_source = repository / (
        "docs/profiled-source-attestations/radeon-unified-0.7-profiled-source.toml"
    )
    baseline_record = copy.deepcopy(load_record(baseline_source))
    baseline_record.pop("parked_guard_checker")
    baseline_record.pop("parked_guard_checker_selftest")
    baseline_record.update(
        {
            "schema": 2,
            "published_object_matches_local_declared": baseline_record.pop(
                "published_object_matches_local"
            ),
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
    print("  ok: pre-baseline signed tag carries explicit NOT RUN declaration")
    for valid_tag in (
        "radeon-unified-0.5-profiled-source",
        "radeon-unified-0.5-2-profiled-source",
        "radeon-unified-0.8.1-profiled-source",
    ):
        validate_tag_name(valid_tag, "self-test valid tag")
    print("  ok: minor and optional patch tag grammar accepts known forms")
    for invalid_tag in (
        "radeon-unified-0.05-profiled-source",
        "radeon-unified-0.8.01-profiled-source",
        "radeon-unified-0.8.1.2-profiled-source",
        "radeon-unified-0.8-1-2-profiled-source",
        "radeon-unified-0.8.1-suffix-profiled-source",
    ):
        expect_tag_failure(invalid_tag, f"tag grammar rejects {invalid_tag}")

    upstream = parse_toml_bytes(
        git_bytes(
            repository,
            "show",
            f"{record['peeled_commit']}:UPSTREAM_BASE.toml",
        ),
        "self-test UPSTREAM_BASE.toml",
    )

    def remove_upstream_schema(value: dict[str, Any]) -> None:
        del value["schema"]

    def add_unknown_upstream_key(value: dict[str, Any]) -> None:
        value["unknown"] = True

    def change_upstream_schema_type(value: dict[str, Any]) -> None:
        value["schema"] = "1"

    def change_upstream_signature_type(value: dict[str, Any]) -> None:
        value["signature_verified"] = "false"

    def claim_unproven_upstream_signature(value: dict[str, Any]) -> None:
        value["signature_verified"] = True

    def remove_upstream_target_commit(value: dict[str, Any]) -> None:
        del value["target"]["mainline"]["commit"]

    upstream_mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("missing upstream key", remove_upstream_schema),
        ("unknown upstream key", add_unknown_upstream_key),
        ("wrong upstream schema type", change_upstream_schema_type),
        ("wrong upstream Boolean type", change_upstream_signature_type),
        ("unproven upstream signature declaration", claim_unproven_upstream_signature),
        ("missing upstream target key", remove_upstream_target_commit),
    ]
    for label, mutate in upstream_mutations:
        changed_upstream = copy.deepcopy(upstream)
        mutate(changed_upstream)
        expect_upstream_failure(repository, changed_upstream, record, label)

    require_git_object_type(
        repository,
        record["upstream_subtree"],
        "tree",
        "self-test upstream subtree",
    )
    for object_id, expected_type, label in (
        (record["peeled_commit"], "tree", "commit rejected as tree"),
        (record["repository_tree"], "commit", "tree rejected as commit"),
        (record["driver_tree"], "commit", "Radeon tree rejected as commit"),
        (record["feature_policy_tree"], "commit", "policy tree rejected as commit"),
    ):
        try:
            require_git_object_type(repository, object_id, expected_type, label)
        except AttestationError:
            print(f"  ok: {label}")
        else:
            raise AttestationError(f"self-test accepted {label}")

    selected_paths = record_paths(repository, [source], all_strict=False)
    require(
        selected_paths == [source.resolve()],
        "self-test explicit record selection differs",
    )
    all_paths = record_paths(repository, None, all_strict=True)
    require(
        any(path.name.startswith("radeon-unified-0.4") for path in all_paths),
        "self-test all-strict scope silently skipped legacy records",
    )
    try:
        record_paths(repository, None, all_strict=False)
    except AttestationError:
        print("  ok: default scope requires explicit selection or --all-strict")
    else:
        raise AttestationError("self-test silently selected a default record scope")

    expect_union_failure(repository, "divergent driver-source merge rejected")
    calibrate_real_merge_history(repository)
    expect_parse_failure(b'schema = 2\nvalue = "\xff"\n', "record that is not UTF-8 text")
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
        (
            "published object declaration drift",
            "published_object_matches_local_declared",
            False,
        ),
        ("legacy published object field", "published_object_matches_local", True),
        (
            "malformed target tag",
            "tag_name",
            "radeon-unified-0.8.1.2-profiled-source",
        ),
        (
            "malformed baseline tag",
            "source_delta_baseline_tag",
            "radeon-unified-0.8.1.2-profiled-source",
        ),
        ("PASS evidence drift", "prod_profile", "NOT RUN"),
        ("NOT RUN evidence drift", "hardware_operation", "PASS"),
        ("local guard commit drift", "local_parked_guard_commit", "8" * 40),
        ("clean-tree declaration drift", "profile_workflow_clean_tree", False),
        ("map digest drift", "source_delta_map_sha256", "9" * 64),
        (
            "arbitrary later baseline tag",
            "source_delta_baseline_tag",
            "radeon-unified-0.8.1-profiled-source",
        ),
        (
            "retagged baseline object",
            "source_delta_baseline_tag_object",
            record["tag_object"],
        ),
        ("map baseline drift", "source_delta_baseline_commit", "a" * 40),
        (
            "later baseline commit",
            "source_delta_baseline_commit",
            record["peeled_commit"],
        ),
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
    retagged_map = map_bytes.replace(
        b"# baseline-tag: radeon-unified-0.7-profiled-source",
        b"# baseline-tag: radeon-unified-0.8-profiled-source",
        1,
    )
    retagged_map_record = copy.deepcopy(record)
    retagged_map_record["source_delta_map_sha256"] = hashlib.sha256(
        retagged_map
    ).hexdigest()
    expect_failure(
        repository,
        retagged_map_record,
        authority,
        "retagged source-delta map baseline",
        map_bytes_override=retagged_map,
    )
    cryptographic_untrusted_fixture(repository, record, authority)
    print(
        "profiled-source attestation calibration: strict identity drift fails closed; "
        "published-object and execution fields remain declarations"
    )
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
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--attestation",
        type=Path,
        action="append",
        help="strict TOML record; repeat to validate selected records",
    )
    scope.add_argument(
        "--all-strict",
        action="store_true",
        help="validate every TOML record, including legacy schema-1 records",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve()
    try:
        authority = resolve_authority(repository, args.allowed_signers)
        if args.self_test:
            return self_test(repository, authority)
        paths = record_paths(
            repository,
            args.attestation,
            all_strict=args.all_strict,
        )
        validate_records(repository, paths, authority)
    except (AttestationError, OSError, UnicodeError) as exc:
        print(f"profiled-source attestation: {exc}", file=sys.stderr)
        return 1
    print(
        f"profiled-source attestation: {len(paths)} signed source identities, "
        "object trees, policy hashes, and source-delta maps verified; "
        "published-object, workflow, guard, and run-result fields checked as "
        "declarations only"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
