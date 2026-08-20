#!/usr/bin/env python3
"""Verify fail closed containment for an RS480 CP microengine restore mismatch."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


class ContractError(Exception):
    """The CP microengine restore containment contract does not hold."""


def mask_comments_and_literals(source: str) -> str:
    """Replace comments and literals while preserving offsets and line endings."""
    masked = list(source)
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "*":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if current == "/" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if current == '"':
                masked[index] = " "
                index += 1
                state = "string"
                continue
            if current == "'":
                masked[index] = " "
                index += 1
                state = "character"
                continue
        elif state == "block-comment":
            if current == "*" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 2
                state = "code"
                continue
            if current != "\n":
                masked[index] = " "
        elif state == "line-comment":
            if current == "\n":
                state = "code"
            else:
                masked[index] = " "
        elif state in {"string", "character"}:
            delimiter = '"' if state == "string" else "'"
            if current == "\\":
                masked[index] = " "
                if index + 1 < len(source):
                    if source[index + 1] != "\n":
                        masked[index + 1] = " "
                    index += 2
                    continue
            if current == delimiter:
                masked[index] = " "
                state = "code"
            elif current != "\n":
                masked[index] = " "
        index += 1
    if state == "block-comment":
        raise ContractError("driver source ends inside a block comment")
    return "".join(masked)


def function_body(source: str, function_name: str) -> str:
    """Return one named C function through balanced brace matching."""
    masked = mask_comments_and_literals(source)
    signature = re.search(
        rf"\b{re.escape(function_name)}\s*\([^;]*?\)\s*\{{",
        masked,
        re.DOTALL,
    )
    if not signature:
        raise ContractError(f"missing function: {function_name}")
    opening_brace = masked.find("{", signature.start())
    depth = 0
    for position in range(opening_brace, len(masked)):
        if masked[position] == "{":
            depth += 1
        elif masked[position] == "}":
            depth -= 1
            if depth == 0:
                return masked[opening_brace + 1 : position]
    raise ContractError(f"unterminated function: {function_name}")


def require_pattern(body: str, pattern: str, description: str) -> re.Match[str]:
    match = re.search(pattern, body, re.DOTALL)
    if not match:
        raise ContractError(description)
    return match


def feature_block(policy: str, feature_id: str) -> str:
    """Return one TOML feature block by its exact identifier."""
    for block in re.split(r"(?=^\[\[feature\]\]$)", policy, flags=re.MULTILINE):
        if re.search(rf'^id = "{re.escape(feature_id)}"$', block, re.MULTILINE):
            return block
    raise ContractError(f"missing build feature: {feature_id}")


def verify_contract(
    driver_source: str, feature_policy: str, surface_audit: str
) -> None:
    """Verify source ordering and its two declared policy projections."""
    body = function_body(driver_source, "rs480_cp_me_ram_inject_one")
    queue_writes = list(re.finditer(r"WREG32\s*\(\s*RADEON_CP_CSQ_CNTL\s*,", body))
    if len(queue_writes) != 2:
        raise ContractError(
            "CP queue control must have one disable and one restore write"
        )

    queue_disable = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_CSQ_CNTL\s*,\s*"
        r"RADEON_CSQ_PRIDIS_INDDIS\s*\)",
        "CP queue disable write is absent",
    )
    restore_read = require_pattern(
        body,
        r"\*restored_l\s*=\s*RREG32\s*\(\s*RADEON_CP_ME_RAM_DATAL\s*\)",
        "restored microword readback is absent",
    )
    restore_mismatch = require_pattern(
        body,
        r"if\s*\(\s*\*restored_h\s*!=\s*orig_h\s*\|\|\s*"
        r"\*restored_l\s*!=\s*orig_l\s*\)\s*\{\s*"
        r"radeon_rs4xx_latch_parked_state\s*\(\s*rdev\s*\)\s*;\s*"
        r"return\s+-EIO\s*;\s*\}",
        "restore mismatch must latch the parked state and return -EIO",
    )
    queue_restore = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_CSQ_CNTL\s*,\s*csq\s*\)",
        "verified restore path does not restore CP queue control",
    )
    write_mismatch = require_pattern(
        body,
        r"if\s*\(\s*\*rb_h\s*!=\s*new_h\s*\|\|\s*"
        r"\*rb_l\s*!=\s*new_l\s*\)\s*return\s+-ENXIO\s*;",
        "bounded write mismatch contract is absent",
    )

    ordered_positions = (
        queue_disable.start(),
        restore_read.start(),
        restore_mismatch.start(),
        queue_restore.start(),
        write_mismatch.start(),
    )
    if ordered_positions != tuple(sorted(ordered_positions)):
        raise ContractError(
            "CP queue restoration must follow exact original microword validation"
        )
    if body.count("radeon_rs4xx_latch_parked_state(rdev);") != 1:
        raise ContractError("restore mismatch must have one parked state publication")
    if body.count("return -EIO;") != 1:
        raise ContractError("restore mismatch must have one exact -EIO return")

    cp_me_policy = feature_block(feature_policy, "cp-me-write")
    required_policy_phrases = (
        "restore mismatch keeps the command queue disabled",
        "publishes the parked state",
        "verified restore permits the original queue state",
        "restore mismatch parks the device before queue restoration",
    )
    for phrase in required_policy_phrases:
        if phrase not in cp_me_policy:
            raise ContractError(f"cp-me-write policy omits: {phrase}")

    audit_line = next(
        (
            line
            for line in surface_audit.splitlines()
            if line.startswith("| radeon_rs480_cp_me_ram_inject |")
        ),
        "",
    )
    if not audit_line:
        raise ContractError("development interface audit omits the CP injection node")
    for phrase in (
        "restore validation before queue reenable",
        "restore mismatch parks with the queue disabled",
    ):
        if phrase not in audit_line:
            raise ContractError(f"development interface audit omits: {phrase}")


def replace_once(subject: str, old: str, new: str, description: str) -> str:
    if subject.count(old) != 1:
        raise ContractError(f"selftest mutation anchor is not unique: {description}")
    return subject.replace(old, new, 1)


def selftest(repository: Path) -> int:
    driver_path = repository / "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c"
    policy_path = repository / "policy/build-features.toml"
    audit_path = repository / "docs/dev-interface-surface-audit.md"
    driver_source = driver_path.read_text(encoding="utf-8")
    feature_policy = policy_path.read_text(encoding="utf-8")
    surface_audit = audit_path.read_text(encoding="utf-8")

    try:
        verify_contract(driver_source, feature_policy, surface_audit)
        print("selftest known-good accepted: restore mismatch containment")

        mismatch_block = (
            "\tif (*restored_h != orig_h || *restored_l != orig_l) {\n"
            "\t\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\t\treturn -EIO;\n"
            "\t}\n"
        )
        queue_restore = "\tWREG32(RADEON_CP_CSQ_CNTL, csq);\n"
        protected_restore = mismatch_block + "\n" + queue_restore
        without_queue_restore = replace_once(
            driver_source,
            protected_restore,
            mismatch_block,
            "missing queue restore",
        )
        mutations = (
            (
                "queue restore precedes validation",
                replace_once(
                    driver_source,
                    protected_restore,
                    queue_restore + "\n" + mismatch_block,
                    "queue restore relocation",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "parked publication removed",
                replace_once(
                    driver_source,
                    "\t\tradeon_rs4xx_latch_parked_state(rdev);\n",
                    "",
                    "parked publication",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "restore failure errno changed",
                replace_once(
                    driver_source,
                    "\t\treturn -EIO;\n",
                    "\t\treturn -ENXIO;\n",
                    "restore mismatch errno",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "low microword half ignored",
                replace_once(
                    driver_source,
                    "*restored_h != orig_h || *restored_l != orig_l",
                    "*restored_h != orig_h",
                    "complete microword comparison",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "safe path queue restore removed",
                without_queue_restore,
                feature_policy,
                surface_audit,
            ),
            (
                "policy loses disabled queue state",
                driver_source,
                replace_once(
                    feature_policy,
                    "restore mismatch keeps the command queue disabled",
                    "restore mismatch reports an error",
                    "policy queue containment",
                ),
                surface_audit,
            ),
            (
                "surface audit loses parked disposition",
                driver_source,
                feature_policy,
                replace_once(
                    surface_audit,
                    "restore mismatch parks with the queue disabled",
                    "restore mismatch reports failure",
                    "surface parked disposition",
                ),
            ),
        )
        for description, mutated_source, mutated_policy, mutated_audit in mutations:
            try:
                verify_contract(mutated_source, mutated_policy, mutated_audit)
            except ContractError:
                print(f"selftest known-bad rejected: {description}")
            else:
                raise ContractError(f"selftest accepted: {description}")
    except (ContractError, OSError, UnicodeDecodeError) as error:
        print(
            f"RS480 CP ME restore containment selftest: FAIL: {error}", file=sys.stderr
        )
        return 1

    print(f"selftest: 1 good and {len(mutations)} bad fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()
    repository = arguments.repository.resolve()
    if arguments.selftest:
        return selftest(repository)
    try:
        verify_contract(
            (repository / "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c").read_text(
                encoding="utf-8"
            ),
            (repository / "policy/build-features.toml").read_text(encoding="utf-8"),
            (repository / "docs/dev-interface-surface-audit.md").read_text(
                encoding="utf-8"
            ),
        )
    except (ContractError, OSError, UnicodeDecodeError) as error:
        print(f"RS480 CP ME restore containment: FAIL: {error}", file=sys.stderr)
        return 1
    print("RS480 CP ME restore containment: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
