#!/usr/bin/env python3
"""Verify protected jobs materialize and verify their own migration oracle."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


class WorkflowError(Exception):
    """The reconstruction workflow loses an oracle integrity boundary."""


PINNED_PACKAGING_REF = "210e2b06c0266e316f08eb0b2b3e9832884c43de"
ORACLE_ROOT = '"$RUNNER_TEMP/reconstruction-oracle"'
JOB_HEADER = re.compile(r"^  ([a-z][a-z0-9-]*):\n", re.MULTILINE)


def job_block(workflow: str, job_name: str) -> str:
    match = re.search(rf"^  {re.escape(job_name)}:\n", workflow, re.MULTILINE)
    if match is None:
        raise WorkflowError(f"workflow has no {job_name} job")
    next_header = JOB_HEADER.search(workflow, match.end())
    end = len(workflow) if next_header is None else next_header.start()
    return workflow[match.start() : end]


def require_once(text: str, token: str, context: str) -> None:
    count = text.count(token)
    if count != 1:
        raise WorkflowError(f"{context}: expected one {token!r}, found {count}")


def require_order(text: str, earlier: str, later: str, context: str) -> None:
    earlier_offset = text.find(earlier)
    later_offset = text.find(later)
    if earlier_offset < 0 or later_offset < 0 or earlier_offset >= later_offset:
        raise WorkflowError(f"{context}: {earlier!r} must precede {later!r}")


def check_materialization_job(workflow: str, job_name: str) -> None:
    block = job_block(workflow, job_name)
    context = f"{job_name} job"
    for token in (
        "Check out pinned packaging input",
        "repository: Oichkatzelesfrettschen/radeon-custom",
        f"ref: {PINNED_PACKAGING_REF}",
        "path: packaging",
        "ssh-key: ${{ secrets.RADEON_CUSTOM_READ_DEPLOY_KEY }}",
        "Materialize hash-verified migration input",
        "control/scripts/materialize_migration_input.py",
        f"--output {ORACLE_ROOT}",
        "Discard private-repository checkout\n        if: always()",
        'packaging_path="$GITHUB_WORKSPACE/packaging"',
        'rm -rf -- "$packaging_path"',
        f"--oracle-root {ORACLE_ROOT}",
    ):
        require_once(block, token, context)
    require_order(
        block,
        "Check out pinned packaging input",
        "Materialize hash-verified migration input",
        context,
    )
    require_order(
        block,
        "Materialize hash-verified migration input",
        "Discard private-repository checkout",
        context,
    )
    require_order(
        block,
        "Discard private-repository checkout",
        f"--oracle-root {ORACLE_ROOT}",
        context,
    )


def validate(workflow: str) -> None:
    if "trusted-oracle:" in workflow:
        raise WorkflowError("workflow retains the artifact-transfer trusted-oracle job")
    if "actions/download-artifact" in workflow:
        raise WorkflowError("workflow downloads a migration oracle from an interjob artifact")
    if "Upload sanitized migration input" in workflow:
        raise WorkflowError("workflow uploads a migration oracle for interjob transfer")
    if "reconstruction-oracle-${" in workflow:
        raise WorkflowError("workflow names an interjob reconstruction oracle artifact")

    plan = job_block(workflow, "history-plan")
    if "needs:" in plan:
        raise WorkflowError("history-plan must not depend on an oracle transport job")
    build = job_block(workflow, "history-build")
    require_once(build, "needs: history-plan", "history-build job")
    require_once(workflow, "Upload immutable commit logs", "workflow")
    check_materialization_job(workflow, "history-plan")
    check_materialization_job(workflow, "history-build")


def self_test(workflow: str) -> int:
    try:
        validate(workflow)
        mutations = (
            workflow.replace(
                "Materialize hash-verified migration input",
                "Materialize migration input",
                1,
            ),
            workflow.replace(
                f"ref: {PINNED_PACKAGING_REF}",
                "ref: unpinned-packaging-input",
                1,
            ),
            workflow.replace("needs: history-plan", "needs: trusted-oracle", 1),
            workflow.replace(
                "Upload immutable commit logs",
                "Upload sanitized migration input",
                1,
            ),
        )
        for mutation in mutations:
            try:
                validate(mutation)
            except WorkflowError:
                continue
            raise WorkflowError("workflow calibration accepted a lost oracle boundary")
    except WorkflowError as exc:
        print(f"reconstruction oracle workflow calibration: FAIL: {exc}", file=sys.stderr)
        return 1
    print("reconstruction oracle workflow calibration: exact jobs pass and drift fails closed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflow",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / ".github/workflows/reconstruction-history.yml",
    )
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    try:
        workflow = arguments.workflow.read_text(encoding="utf-8")
        if arguments.self_test:
            return self_test(workflow)
        validate(workflow)
    except (OSError, UnicodeDecodeError, WorkflowError) as exc:
        print(f"reconstruction oracle workflow: {exc}", file=sys.stderr)
        return 1
    print("reconstruction oracle workflow: protected jobs materialize independent inputs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
