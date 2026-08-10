#!/usr/bin/env python3
"""Verify the source-equivalence tag, signer, and post-tag run identities."""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

RADEON_SUBTREE = "drivers/gpu/drm/radeon"
OBJECT_ID = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


class AttestationError(Exception):
    """The attestation does not reproduce the signed source identity."""


def load_attestation(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            data = tomllib.load(source)
    except FileNotFoundError as exc:
        raise AttestationError(f"missing attestation: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise AttestationError(f"malformed attestation: {exc}") from exc
    if data.get("schema") != 1:
        raise AttestationError("attestation must declare schema = 1")
    return data


def require_string(
    attestation: dict[str, Any],
    field: str,
    pattern: re.Pattern[str] | None = None,
) -> str:
    value = attestation.get(field)
    if not isinstance(value, str) or not value:
        raise AttestationError(f"attestation carries no {field}")
    if pattern and not pattern.fullmatch(value):
        raise AttestationError(f"attestation carries invalid {field}: {value}")
    return value


def git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AttestationError(f"git {' '.join(arguments)} failed: {detail}")
    return result


def git_output(repository: Path, *arguments: str) -> str:
    return git(repository, *arguments).stdout.strip()


def relative_file(repository: Path, value: str) -> Path:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise AttestationError(
            f"allowed_signers_file is not a normalized relative path: {value}"
        )
    resolved = repository / path
    if not resolved.is_file():
        raise AttestationError(f"allowed signers file is absent: {value}")
    return resolved


def public_key_identity(
    allowed_signers: Path,
    principal: str,
) -> tuple[str, str, str]:
    content = allowed_signers.read_bytes()
    try:
        lines = [
            line
            for line in content.decode("ascii").splitlines()
            if line and not line.startswith("#")
        ]
    except UnicodeDecodeError as exc:
        raise AttestationError("allowed signers file is not ASCII") from exc
    if len(lines) != 1:
        raise AttestationError("allowed signers file must carry exactly one entry")
    fields = lines[0].split()
    if len(fields) != 3:
        raise AttestationError(
            "allowed signers entry must contain principal, key type, and key"
        )
    if fields[0] != principal:
        raise AttestationError(f"allowed signers principal {fields[0]} != {principal}")
    key_bytes = f"{fields[1]} {fields[2]}\n".encode("ascii")
    result = subprocess.run(
        ["ssh-keygen", "-lf", "-", "-E", "sha256"],
        input=key_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise AttestationError(f"ssh-keygen rejected the public key: {detail}")
    output = result.stdout.decode("ascii").split()
    fingerprint = next(
        (field for field in output if field.startswith("SHA256:")),
        "",
    )
    if not fingerprint:
        raise AttestationError("ssh-keygen returned no SHA-256 fingerprint")
    return (
        hashlib.sha256(content).hexdigest(),
        hashlib.sha256(key_bytes).hexdigest(),
        fingerprint,
    )


def validate_attestation(
    repository: Path,
    attestation: dict[str, Any],
    *,
    verify_signature: bool = True,
) -> tuple[str, str, str]:
    tag_name = require_string(attestation, "tag_name")
    tag_object = require_string(attestation, "tag_object", OBJECT_ID)
    peeled_commit = require_string(attestation, "peeled_commit", OBJECT_ID)
    driver_tree = require_string(attestation, "driver_tree", OBJECT_ID)
    if attestation.get("signing_format") != "ssh":
        raise AttestationError("signing_format must be ssh")
    principal = require_string(attestation, "signer_principal")
    fingerprint = require_string(attestation, "signer_fingerprint", FINGERPRINT)
    public_key_sha256 = require_string(attestation, "public_key_sha256", SHA256)
    entry_sha256 = require_string(attestation, "allowed_signers_entry_sha256", SHA256)
    allowed_signers_name = require_string(attestation, "allowed_signers_file")
    allowed_signers = relative_file(repository, allowed_signers_name)

    if git_output(repository, "cat-file", "-t", tag_name) != "tag":
        raise AttestationError(f"{tag_name} is not an annotated tag")
    if git_output(repository, "rev-parse", tag_name) != tag_object:
        raise AttestationError("tag object differs from the attestation")
    if git_output(repository, "rev-parse", f"{tag_name}^{{}}") != peeled_commit:
        raise AttestationError("peeled commit differs from the attestation")
    actual_tree = git_output(
        repository,
        "rev-parse",
        f"{peeled_commit}:{RADEON_SUBTREE}",
    )
    if actual_tree != driver_tree:
        raise AttestationError("driver tree differs from the attestation")

    actual_entry_sha, actual_key_sha, actual_fingerprint = public_key_identity(
        allowed_signers, principal
    )
    if actual_entry_sha != entry_sha256:
        raise AttestationError("allowed signers entry SHA-256 differs")
    if actual_key_sha != public_key_sha256:
        raise AttestationError("public key SHA-256 differs")
    if actual_fingerprint != fingerprint:
        raise AttestationError("signer fingerprint differs")

    expected_command = (
        "git -c gpg.ssh.allowedSignersFile="
        f"{allowed_signers_name} verify-tag {tag_name}"
    )
    if attestation.get("local_verification_command") != expected_command:
        raise AttestationError("local verification command is not reproducible")

    source_run = attestation.get("equivalence_source_workflow_run")
    closure_run = attestation.get("closure_documentation_workflow_run")
    if (
        not isinstance(source_run, int)
        or source_run <= 0
        or not isinstance(closure_run, int)
        or closure_run <= 0
        or source_run == closure_run
    ):
        raise AttestationError(
            "equivalence and closure workflow runs must be distinct positive IDs"
        )

    if verify_signature:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "-c",
                f"gpg.ssh.allowedSignersFile={allowed_signers}",
                "verify-tag",
                tag_name,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = result.stdout + result.stderr
        if result.returncode:
            raise AttestationError(
                f"tag signature verification failed: {output.strip()}"
            )
        if principal not in output or fingerprint not in output:
            raise AttestationError(
                "tag verification output does not identify the attested signer"
            )
    return tag_object, peeled_commit, driver_tree


def expect_failure(
    repository: Path,
    attestation: dict[str, Any],
    label: str,
) -> None:
    try:
        validate_attestation(repository, attestation, verify_signature=False)
    except AttestationError:
        print(f"  ok: {label}")
        return
    raise AttestationError(f"self-test accepted {label}")


def self_test(repository: Path, attestation_path: Path) -> int:
    try:
        original = load_attestation(attestation_path)
        validate_attestation(repository, original)
        print("  ok: current tag and signer identity verify")

        mutations: tuple[tuple[str, str, object], ...] = (
            ("changed tag object", "tag_object", "0" * 40),
            ("changed peeled commit", "peeled_commit", "1" * 40),
            ("changed driver tree", "driver_tree", "2" * 40),
            ("changed signing format", "signing_format", "openpgp"),
            ("changed fingerprint", "signer_fingerprint", "SHA256:" + "A" * 43),
            ("changed public key hash", "public_key_sha256", "3" * 64),
            (
                "changed allowed signers hash",
                "allowed_signers_entry_sha256",
                "4" * 64,
            ),
            ("missing workflow run", "equivalence_source_workflow_run", 0),
        )
        for label, field, value in mutations:
            changed = copy.deepcopy(original)
            changed[field] = value
            expect_failure(repository, changed, label)

        same_runs = copy.deepcopy(original)
        same_runs["closure_documentation_workflow_run"] = same_runs[
            "equivalence_source_workflow_run"
        ]
        expect_failure(repository, same_runs, "conflated workflow runs")

        wrong_command = copy.deepcopy(original)
        wrong_command["local_verification_command"] = "git verify-tag HEAD"
        expect_failure(repository, wrong_command, "nonreproducible command")
    except (AttestationError, OSError, UnicodeDecodeError) as exc:
        print(
            f"source-equivalence attestation calibration: FAIL: {exc}", file=sys.stderr
        )
        return 1
    print("source-equivalence attestation calibration: identity drift fails closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    repository = args.repository.resolve()
    attestation_path = (
        args.attestation.resolve()
        if args.attestation
        else repository / "docs/source-equivalence-attestation.toml"
    )
    if args.self_test:
        return self_test(repository, attestation_path)

    try:
        tag_object, peeled_commit, driver_tree = validate_attestation(
            repository,
            load_attestation(attestation_path),
        )
    except (AttestationError, OSError, UnicodeDecodeError) as exc:
        print(f"source-equivalence attestation: {exc}", file=sys.stderr)
        return 1
    print(f"tag object: {tag_object}")
    print(f"peeled commit: {peeled_commit}")
    print(f"driver tree: {driver_tree}")
    print("source-equivalence attestation: signed identity verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
