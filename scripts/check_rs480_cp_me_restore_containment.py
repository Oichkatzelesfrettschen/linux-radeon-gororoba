#!/usr/bin/env python3
"""Verify fail closed containment for an RS480 CP microengine restore mismatch."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

EXPECTED_BAD_COUNT = 33


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


def brace_depth_at(body: str, position: int) -> int:
    """Return the lexical brace depth before one masked source offset."""
    depth = 0
    for character in body[:position]:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth < 0:
                raise ContractError("function body closes before the checked statement")
    return depth


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

    original_capture = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_RADDR\s*,\s*addr\s*\)\s*;\s*"
        r"orig_h\s*=\s*RREG32\s*\(\s*RADEON_CP_ME_RAM_DATAH\s*\)\s*;\s*"
        r"orig_l\s*=\s*RREG32\s*\(\s*RADEON_CP_ME_RAM_DATAL\s*\)\s*;",
        "original microword capture is incomplete or reordered",
    )
    queue_capture_disable = require_pattern(
        body,
        r"csq\s*=\s*RREG32\s*\(\s*RADEON_CP_CSQ_CNTL\s*\)\s*;\s*"
        r"WREG32\s*\(\s*RADEON_CP_CSQ_CNTL\s*,\s*"
        r"RADEON_CSQ_PRIDIS_INDDIS\s*\)\s*;",
        "CP queue control capture must immediately precede the disable write",
    )
    injection_writes = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_ADDR\s*,\s*addr\s*\)\s*;\s*"
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_DATAH\s*,\s*new_h\s*\)\s*;\s*"
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_DATAL\s*,\s*new_l\s*\)\s*;",
        "modified microword writes are incomplete or reordered",
    )
    injection_readbacks = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_RADDR\s*,\s*addr\s*\)\s*;\s*"
        r"\*rb_h\s*=\s*RREG32\s*\(\s*RADEON_CP_ME_RAM_DATAH\s*\)\s*;\s*"
        r"\*rb_l\s*=\s*RREG32\s*\(\s*RADEON_CP_ME_RAM_DATAL\s*\)\s*;",
        "modified microword hardware readbacks are incomplete or reordered",
    )
    restore_writes = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_ADDR\s*,\s*addr\s*\)\s*;\s*"
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_DATAH\s*,\s*orig_h\s*\)\s*;\s*"
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_DATAL\s*,\s*orig_l\s*\)\s*;",
        "original microword restore writes are incomplete or reordered",
    )
    restore_readbacks = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_ME_RAM_RADDR\s*,\s*addr\s*\)\s*;\s*"
        r"\*restored_h\s*=\s*RREG32\s*\(\s*RADEON_CP_ME_RAM_DATAH\s*\)\s*;\s*"
        r"\*restored_l\s*=\s*RREG32\s*\(\s*RADEON_CP_ME_RAM_DATAL\s*\)\s*;",
        "restored microword hardware readbacks are incomplete or reordered",
    )
    restore_mismatch = require_pattern(
        body,
        r"if\s*\(\s*\*restored_h\s*!=\s*orig_h\s*\|\|\s*"
        r"\*restored_l\s*!=\s*orig_l\s*\)\s*\{\s*"
        r"radeon_rs4xx_latch_parked_publication\s*\(\s*rdev\s*\)\s*;\s*"
        r"return\s+-EIO\s*;\s*\}",
        "restore mismatch must request parked publication and return -EIO",
    )
    queue_restore = require_pattern(
        body,
        r"WREG32\s*\(\s*RADEON_CP_CSQ_CNTL\s*,\s*csq\s*\)\s*;",
        "verified restore path does not restore CP queue control",
    )
    write_mismatch = require_pattern(
        body,
        r"if\s*\(\s*\*rb_h\s*!=\s*new_h\s*\|\|\s*"
        r"\*rb_l\s*!=\s*new_l\s*\)\s*return\s+-ENXIO\s*;",
        "bounded write mismatch contract is absent",
    )
    successful_return = require_pattern(
        body,
        r"return\s+0\s*;",
        "verified write and restore path does not return success",
    )

    ordered_positions = (
        original_capture.start(),
        queue_capture_disable.start(),
        injection_writes.start(),
        injection_readbacks.start(),
        restore_writes.start(),
        restore_readbacks.start(),
        restore_mismatch.start(),
        queue_restore.start(),
        write_mismatch.start(),
        successful_return.start(),
    )
    if ordered_positions != tuple(sorted(ordered_positions)):
        raise ContractError(
            "CP queue restoration must follow exact original microword validation"
        )
    top_level_statements = (
        original_capture,
        queue_capture_disable,
        injection_writes,
        injection_readbacks,
        restore_writes,
        restore_readbacks,
        restore_mismatch,
        queue_restore,
        write_mismatch,
        successful_return,
    )
    if any(brace_depth_at(body, match.start()) != 0 for match in top_level_statements):
        raise ContractError("CP restore containment statements must remain top level")
    if body[original_capture.end() : queue_capture_disable.start()].strip():
        raise ContractError("original microword changes before queue disable")
    disabled_intervals = (
        (queue_capture_disable, injection_writes, "modified microword write"),
        (injection_writes, injection_readbacks, "modified microword readback"),
        (injection_readbacks, restore_writes, "original microword restore"),
        (restore_writes, restore_readbacks, "restored microword readback"),
        (restore_readbacks, restore_mismatch, "restore validation"),
        (restore_mismatch, queue_restore, "safe queue restoration"),
    )
    for preceding, following, operation in disabled_intervals:
        if body[preceding.end() : following.start()].strip():
            raise ContractError(
                f"control flow intervenes before {operation} while the queue is disabled"
            )
    if body[queue_restore.end() : write_mismatch.start()].strip():
        raise ContractError(
            "control flow intervenes before modified microword validation"
        )
    if body[write_mismatch.end() : successful_return.start()].strip():
        raise ContractError("control flow intervenes before the successful result")
    if body[successful_return.end() :].strip():
        raise ContractError("injection helper success is not the final statement")
    if body.count("radeon_rs4xx_latch_parked_publication(rdev);") != 1:
        raise ContractError("restore mismatch must have one parked publication request")
    if body.count("return -EIO;") != 1:
        raise ContractError("restore mismatch must have one exact -EIO return")
    if len(re.findall(r"\breturn\b", body)) != 3:
        raise ContractError("injection helper return denominator differs")

    handler = function_body(driver_source, "rs480_cp_me_ram_inject_write")
    idle_failure = require_pattern(
        handler,
        r"if\s*\(\s*ret\s*\)\s*\{[^{}]*return\s+ret\s*;\s*\}",
        "write handler idle failure cleanup is absent",
    )
    mutation_mark = require_pattern(
        handler,
        r"radeon_dev_mark_mutation\s*\(\s*rdev\s*,[^;]*\)\s*;",
        "write handler does not record the admitted mutation",
    )
    if idle_failure.start() >= mutation_mark.start():
        raise ContractError("idle failure cleanup does not precede the mutation marker")
    if handler[idle_failure.end() : mutation_mark.start()].strip():
        raise ContractError("mutation marker is conditional or reordered")
    if brace_depth_at(handler, mutation_mark.start()) != 0:
        raise ContractError("mutation marker must remain top level")
    injection_call = require_pattern(
        handler,
        r"ret\s*=\s*rs480_cp_me_ram_inject_one\s*\(\s*"
        r"rdev\s*,\s*addr\s*,\s*new_h\s*,\s*new_l\s*,\s*"
        r"&rb_h\s*,\s*&rb_l\s*,\s*&rs_h\s*,\s*&rs_l\s*\)\s*;",
        "write handler does not capture the injection result",
    )
    if mutation_mark.start() >= injection_call.start():
        raise ContractError("write handler mutation marker does not precede injection")
    if handler[mutation_mark.end() : injection_call.start()].strip():
        raise ContractError("injection helper call is conditional or reordered")
    if brace_depth_at(handler, injection_call.start()) != 0:
        raise ContractError("injection helper call must remain top level")
    normal_cleanup = require_pattern(
        handler[injection_call.end() :],
        r"snprintf\s*\(\s*ctx->result\s*,\s*"
        r"sizeof\s*\(\s*ctx->result\s*\)\s*,[^;]*\)\s*;\s*"
        r"mutex_unlock\s*\(\s*&ctx->lock\s*\)\s*;\s*"
        r"radeon_device_unlock_hardware\s*\(\s*rdev\s*\)\s*;",
        "write handler does not format the result and release both locks",
    )
    normal_cleanup_start = injection_call.end() + normal_cleanup.start()
    normal_cleanup_end = injection_call.end() + normal_cleanup.end()
    if handler[injection_call.end() : normal_cleanup_start].strip():
        raise ContractError("control flow intervenes before post-injection cleanup")
    if brace_depth_at(handler, normal_cleanup_start) != 0:
        raise ContractError("post-injection cleanup must remain top level")
    if re.search(
        r"(?:\(\s*)*\bret\b(?:\s*\))*\s*"
        r"(?:(?:<<|>>|[+\-*/%&^|])?=(?!=)|\+\+|--)|"
        r"(?:\+\+|--)\s*(?:\(\s*)*\bret\b(?:\s*\))*",
        handler[injection_call.end() :],
    ):
        raise ContractError("write handler overwrites the injection result")
    result_tail = require_pattern(
        handler[normal_cleanup_end:],
        r"if\s*\(\s*ret\s*==\s*-EIO\s*\)\s*"
        r"dev_err_ratelimited\s*\([^;]*\)\s*;\s*"
        r"else\s+if\s*\(\s*ret\s*==\s*-ENXIO\s*\)\s*"
        r"dev_warn_ratelimited\s*\([^;]*\)\s*;\s*"
        r"else\s*dev_info\s*\([^;]*\)\s*;\s*"
        r"return\s+ret\s*\?\s*ret\s*:\s*len\s*;",
        "write handler does not report and propagate the injection result",
    )
    result_tail_start = normal_cleanup_end + result_tail.start()
    result_tail_end = normal_cleanup_end + result_tail.end()
    if handler[normal_cleanup_end:result_tail_start].strip():
        raise ContractError("control flow intervenes before injection result handling")
    if handler[result_tail_end:].strip():
        raise ContractError(
            "write handler return propagation is not the final statement"
        )
    if len(re.findall(r"\brs480_cp_me_ram_inject_one\s*\(", handler)) != 1:
        raise ContractError(
            "write handler must invoke the injection helper exactly once"
        )
    if len(re.findall(r"\breturn\s+ret\s*\?\s*ret\s*:\s*len\s*;", handler)) != 1:
        raise ContractError(
            "write handler must propagate the injection result exactly once"
        )

    cp_me_policy = feature_block(feature_policy, "cp-me-write")
    required_policy_phrases = (
        "restore mismatch keeps the command queue disabled",
        "requests CPU-only parked publication",
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
        "restore mismatch requests parked publication with the queue disabled",
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
            "\t\tradeon_rs4xx_latch_parked_publication(rdev);\n"
            "\t\treturn -EIO;\n"
            "\t}\n"
        )
        original_capture_block = (
            "\tWREG32(RADEON_CP_ME_RAM_RADDR, addr);\n"
            "\torig_h = RREG32(RADEON_CP_ME_RAM_DATAH);\n"
            "\torig_l = RREG32(RADEON_CP_ME_RAM_DATAL);\n"
        )
        queue_capture_disable = (
            "\tcsq = RREG32(RADEON_CP_CSQ_CNTL);\n"
            "\tWREG32(RADEON_CP_CSQ_CNTL, RADEON_CSQ_PRIDIS_INDDIS);\n"
        )
        queue_disable = "\tWREG32(RADEON_CP_CSQ_CNTL, RADEON_CSQ_PRIDIS_INDDIS);\n"
        injection_write_block = (
            "\tWREG32(RADEON_CP_ME_RAM_ADDR, addr);\n"
            "\tWREG32(RADEON_CP_ME_RAM_DATAH, new_h);\n"
            "\tWREG32(RADEON_CP_ME_RAM_DATAL, new_l);\n"
        )
        injection_readback_block = (
            "\tWREG32(RADEON_CP_ME_RAM_RADDR, addr);\n"
            "\t*rb_h = RREG32(RADEON_CP_ME_RAM_DATAH);\n"
            "\t*rb_l = RREG32(RADEON_CP_ME_RAM_DATAL);\n"
        )
        restore_write_block = (
            "\tWREG32(RADEON_CP_ME_RAM_ADDR, addr);\n"
            "\tWREG32(RADEON_CP_ME_RAM_DATAH, orig_h);\n"
            "\tWREG32(RADEON_CP_ME_RAM_DATAL, orig_l);\n"
        )
        restore_readback_block = (
            "\tWREG32(RADEON_CP_ME_RAM_RADDR, addr);\n"
            "\t*restored_h = RREG32(RADEON_CP_ME_RAM_DATAH);\n"
            "\t*restored_l = RREG32(RADEON_CP_ME_RAM_DATAL);\n"
        )
        write_result_block = (
            "\tif (*rb_h != new_h || *rb_l != new_l)\n\t\treturn -ENXIO;\n\treturn 0;\n"
        )
        injection_call_block = (
            "\tret = rs480_cp_me_ram_inject_one(rdev, addr, new_h, new_l,\n"
            "\t\t\t\t\t &rb_h, &rb_l, &rs_h, &rs_l);\n"
        )
        mutation_mark_block = (
            '\tradeon_dev_mark_mutation(rdev, "RS4xx CP-ME RAM injection");\n'
        )
        normal_unlock_block = (
            "\tmutex_unlock(&ctx->lock);\n\tradeon_device_unlock_hardware(rdev);\n"
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
                    "\t\tradeon_rs4xx_latch_parked_publication(rdev);\n",
                    "",
                    "parked publication",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "parked publication downgraded to admission latch",
                replace_once(
                    driver_source,
                    "\t\tradeon_rs4xx_latch_parked_publication(rdev);\n",
                    "\t\tradeon_rs4xx_latch_parked_state(rdev);\n",
                    "parked publication request",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "original high half synthesized",
                replace_once(
                    driver_source,
                    original_capture_block,
                    original_capture_block.replace(
                        "orig_h = RREG32(RADEON_CP_ME_RAM_DATAH);",
                        "orig_h = new_h;",
                    ),
                    "original high-half capture",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "original low half synthesized",
                replace_once(
                    driver_source,
                    original_capture_block,
                    original_capture_block.replace(
                        "orig_l = RREG32(RADEON_CP_ME_RAM_DATAL);",
                        "orig_l = new_l;",
                    ),
                    "original low-half capture",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "captured microword overwritten before queue disable",
                replace_once(
                    driver_source,
                    original_capture_block,
                    original_capture_block + "\torig_h = new_h;\n\torig_l = new_l;\n",
                    "captured microword overwrite",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "original high-half restore omitted",
                replace_once(
                    driver_source,
                    restore_write_block,
                    restore_write_block.replace(
                        "\tWREG32(RADEON_CP_ME_RAM_DATAH, orig_h);\n", ""
                    ),
                    "original high-half restore",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "original low-half restore omitted",
                replace_once(
                    driver_source,
                    restore_write_block,
                    restore_write_block.replace(
                        "\tWREG32(RADEON_CP_ME_RAM_DATAL, orig_l);\n", ""
                    ),
                    "original low-half restore",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "restored high-half readback synthesized",
                replace_once(
                    driver_source,
                    restore_readback_block,
                    restore_readback_block.replace(
                        "*restored_h = RREG32(RADEON_CP_ME_RAM_DATAH);",
                        "*restored_h = orig_h;",
                    ),
                    "restored high-half readback",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "restored low-half readback synthesized",
                replace_once(
                    driver_source,
                    restore_readback_block,
                    restore_readback_block.replace(
                        "*restored_l = RREG32(RADEON_CP_ME_RAM_DATAL);",
                        "*restored_l = orig_l;",
                    ),
                    "restored low-half readback",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "queue control capture synthesized",
                replace_once(
                    driver_source,
                    queue_capture_disable,
                    queue_capture_disable.replace(
                        "csq = RREG32(RADEON_CP_CSQ_CNTL);",
                        "csq = 0;",
                    ),
                    "queue control capture",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "queue control capture follows disable",
                replace_once(
                    driver_source,
                    queue_capture_disable,
                    queue_disable + "\tcsq = RREG32(RADEON_CP_CSQ_CNTL);\n",
                    "late queue control capture",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "modified high-half write omitted",
                replace_once(
                    driver_source,
                    injection_write_block,
                    injection_write_block.replace(
                        "\tWREG32(RADEON_CP_ME_RAM_DATAH, new_h);\n", ""
                    ),
                    "modified high-half write",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "modified low-half write omitted",
                replace_once(
                    driver_source,
                    injection_write_block,
                    injection_write_block.replace(
                        "\tWREG32(RADEON_CP_ME_RAM_DATAL, new_l);\n", ""
                    ),
                    "modified low-half write",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "modified high-half readback synthesized",
                replace_once(
                    driver_source,
                    injection_readback_block,
                    injection_readback_block.replace(
                        "*rb_h = RREG32(RADEON_CP_ME_RAM_DATAH);",
                        "*rb_h = new_h;",
                    ),
                    "modified high-half readback",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "modified low-half readback synthesized",
                replace_once(
                    driver_source,
                    injection_readback_block,
                    injection_readback_block.replace(
                        "*rb_l = RREG32(RADEON_CP_ME_RAM_DATAL);",
                        "*rb_l = new_l;",
                    ),
                    "modified low-half readback",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "early return while command queue is disabled",
                replace_once(
                    driver_source,
                    queue_capture_disable,
                    queue_capture_disable + "\tif (new_h == 0)\n\t\treturn -EINVAL;\n",
                    "disabled queue early return",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "write handler reports unconditional success",
                replace_once(
                    driver_source,
                    "\treturn ret ? ret : len;\n",
                    "\treturn len;\n",
                    "write handler result propagation",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "write handler clears the injection failure",
                replace_once(
                    driver_source,
                    injection_call_block,
                    injection_call_block + "\tret = 0;\n",
                    "write handler result overwrite",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "write handler compound clears the injection failure",
                replace_once(
                    driver_source,
                    injection_call_block,
                    injection_call_block + "\tret &= 0;\n",
                    "write handler compound result overwrite",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "write handler parenthesized assignment clears the injection failure",
                replace_once(
                    driver_source,
                    "(ret != -EIO));\n",
                    "((ret) = 0, ret != -EIO));\n",
                    "write handler parenthesized result overwrite",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "write handler conditionally invokes the injection helper",
                replace_once(
                    driver_source,
                    injection_call_block,
                    "\tif (new_h)\n\t" + injection_call_block,
                    "conditional injection helper call",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "write handler conditionally records the mutation",
                replace_once(
                    driver_source,
                    mutation_mark_block,
                    "\tif (new_h)\n\t\tradeon_dev_mark_mutation("
                    'rdev, "RS4xx CP-ME RAM injection");\n',
                    "conditional mutation marker",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "write handler conditionally releases the context lock",
                replace_once(
                    driver_source,
                    normal_unlock_block,
                    "\tif (!ret)\n\t\tmutex_unlock(&ctx->lock);\n"
                    "\tradeon_device_unlock_hardware(rdev);\n",
                    "conditional post-injection unlock",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "injection helper adds an undeclared error return",
                replace_once(
                    driver_source,
                    "\tu32 orig_h, orig_l, csq;\n",
                    "\tu32 orig_h, orig_l, csq;\n\n\tif (!addr)\n\t\treturn -EINVAL;\n",
                    "undeclared injection helper return",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "verified write path loses success result",
                replace_once(
                    driver_source,
                    write_result_block,
                    write_result_block.replace("\treturn 0;\n", "\treturn -EINVAL;\n"),
                    "successful injection result",
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
                "restore validation becomes unreachable",
                replace_once(
                    driver_source,
                    mismatch_block,
                    "\tif (false) {\n" + mismatch_block + "\t}\n",
                    "unreachable restore validation",
                ),
                feature_policy,
                surface_audit,
            ),
            (
                "control flow bypasses restore validation",
                replace_once(
                    driver_source,
                    mismatch_block,
                    "\tgoto restore_queue;\n" + mismatch_block,
                    "restore validation bypass",
                ),
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
                    "restore mismatch requests parked publication with the queue disabled",
                    "restore mismatch reports failure",
                    "surface parked disposition",
                ),
            ),
        )
        if len(mutations) != EXPECTED_BAD_COUNT:
            raise ContractError("selftest mutation denominator differs")
        if len({mutation[0] for mutation in mutations}) != len(mutations):
            raise ContractError("selftest mutation labels repeat")
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
