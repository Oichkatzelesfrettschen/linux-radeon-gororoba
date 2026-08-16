#!/usr/bin/env python3
"""Prove the parked-device refusals still refuse, against known-bad mutations.

A parked device stays parked until reboot, and four call sites hold that
contract: radeon_gem_object_create refuses every buffer object allocation
funnelled through it, radeon_gem_prime_import_sg_table refuses the importer
that bypasses the funnel, radeon_gem_wait_idle_ioctl refuses before
mmio_hdp_flush reaches a wedged engine, and radeon_cs_ioctl refuses before
parser initialization. A fifth check holds the errno at the
dumb-create boundary: radeon_mode_dumb_create forwards the creator's result,
so the parked -EIO stays distinguishable from -ENOMEM exhaustion.

A compile test cannot see any of these break. Deleting a guard, moving it after
the allocation it was meant to precede, reading needs_reset instead of
gpu_parked, or returning 0 all compile clean and all silently readmit the
traffic the guard exists to stop. This checker encodes each of those as a
rejected mutation and runs its own fixtures with --selftest, so a green result
means the fixtures still discriminate rather than that the patterns stopped
matching anything.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import check_rs4xx_hardware_admission_contract as centralized_admission

SUBTREE = Path("drivers/gpu/drm/radeon")

# A guard is (file, enclosing function, the call it must precede). "precedes"
# is the load-bearing half: a check that runs after the allocation refuses
# nothing, and that is the mutation a reviewer is least likely to catch.
GUARDS = [
    {
        "id": "gem-create",
        "path": SUBTREE / "radeon_gem.c",
        "function": "radeon_gem_object_create",
        "precedes": "radeon_bo_create",
        "returns": "-EIO",
    },
    {
        "id": "prime-import",
        "path": SUBTREE / "radeon_prime.c",
        "function": "radeon_gem_prime_import_sg_table",
        "precedes": "radeon_bo_create",
        "returns": "ERR_PTR(-EIO)",
    },
    {
        "id": "wait-idle-flush",
        "path": SUBTREE / "radeon_gem.c",
        "function": "radeon_gem_wait_idle_ioctl",
        "precedes": "mmio_hdp_flush",
        "returns": "-EIO",
    },
    {
        "id": "command-submission",
        "path": SUBTREE / "radeon_cs.c",
        "function": "radeon_cs_ioctl",
        "precedes": "radeon_cs_parser_init",
        "returns": "-EIO",
    },
]

PARKED_GUARD = re.compile(r"\bif\s*\(\s*READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)\s*\)")
READ_LOCK = re.compile(r"\bdown_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;")
READ_UNLOCK = re.compile(r"\bup_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;")
DEVICE_UNLOCK = re.compile(r"\bradeon_device_unlock_hardware\s*\(\s*rdev\s*\)\s*;")
ACCESS_END = re.compile(r"\bradeon_rs4xx_hardware_access_end\s*\(\s*rdev\s*\)\s*;")
RESET_TRANSACTION = re.compile(
    r"\{\s*"
    r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
    r"r\s*=\s*radeon_gpu_reset\s*\(\s*rdev\s*\)\s*;\s*"
    r"if\s*\(\s*!\s*r\s*\)\s*"
    r"r\s*=\s*-EAGAIN\s*;\s*"
    r"return\s+r\s*;\s*"
    r"\}"
)
C_COMMENT_OR_LITERAL = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
    re.DOTALL,
)
C_LINE_SPLICE = re.compile(r"\\(?:\r\n|\n|\r)")
C_DIGRAPH_REPLACEMENTS = (
    ("%:%:", "##  "),
    ("<:", "[ "),
    (":>", "] "),
    ("<%", "{ "),
    ("%>", "} "),
    ("%:", "# "),
)
C_CONDITIONAL_DIRECTIVE = re.compile(
    r"(?m)^[ \t\v\f]*(?:#|%:)[ \t\v\f]*"
    r"(?P<kind>if|ifdef|ifndef|elif|else|endif)\b"
)
C_MACRO_OVERRIDE = re.compile(
    r"(?m)^[ \t\v\f]*(?:#|%:)[ \t\v\f]*(?:define|undef)"
    r"[ \t\v\f]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
C_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
PARKED_PROTECTED_MACROS = (
    "EAGAIN",
    "EBUSY",
    "EIO",
    "ERR_PTR",
    "READ_ONCE",
    "dma_resv_lock",
    "dma_resv_wait_timeout",
    "down_read",
    "drm_gem_object_put",
    "radeon_bo_create",
    "radeon_cs_parser_init",
    "radeon_device_lock_hardware",
    "radeon_device_unlock_hardware",
    "radeon_gpu_reset",
    "radeon_rs4xx_hardware_access_begin",
    "radeon_rs4xx_hardware_access_end",
    "up_read",
)
DUMB_CREATE_PROTECTED_MACROS = (
    "drm_gem_handle_create",
    "radeon_gem_object_create",
)


class GuardError(Exception):
    """A parked-device guard is absent, misplaced, or returns the wrong value."""


@dataclass(frozen=True)
class ControlledMatch:
    """One condition and the exact source interval that it controls."""

    condition: re.Match[str]
    statement_start: int
    statement_end: int


@dataclass(frozen=True)
class CommandSubmissionTopology:
    """Named lexical anchors in radeon_cs_ioctl."""

    function_open: int
    lock: re.Match[str]
    acceleration: ControlledMatch
    reset: ControlledMatch
    parser_zero: re.Match[str]
    parser_init: re.Match[str]
    parser_failure: ControlledMatch
    ib_fill: re.Match[str]
    relocation_stage: ControlledMatch
    relocations: re.Match[str]
    validation_failure: ControlledMatch
    trace: re.Match[str]
    ib_schedule: re.Match[str]
    ib_failure: ControlledMatch
    ib_vm_schedule: re.Match[str]
    ib_vm_failure: ControlledMatch
    fence_validation: ControlledMatch
    out_label: re.Match[str]
    final_unlock: re.Match[str]
    final_return: re.Match[str]


def strip_comments_and_literals(source: str) -> str:
    """Apply C line splicing, blank comments and literals, and map digraphs.

    Ordering is the whole check, and a comment naming radeon_bo_create sits
    above the guard that precedes the real call. Matching that prose would
    report the guard as following the allocation it actually precedes, so
    comments are blanked rather than deleted. C phase-2 line splices are
    deleted first because they can extend a line comment or form one token.
    C digraphs remain active tokens after preprocessing. They map to their
    single-character structural tokens with one trailing space so byte offsets
    stay stable. Every position comparison uses the resulting translation
    stream.
    """

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    code = C_COMMENT_OR_LITERAL.sub(blank, C_LINE_SPLICE.sub("", source))
    for digraph, replacement in C_DIGRAPH_REPLACEMENTS:
        code = code.replace(digraph, replacement)
    return code


def reject_enclosing_conditional(
    code: str,
    definition_offset: int,
    label: str,
) -> None:
    """Reject a function definition enclosed by conditional preprocessing."""
    conditional_stack: list[str] = []
    for directive in C_CONDITIONAL_DIRECTIVE.finditer(code, 0, definition_offset):
        kind = directive.group("kind")
        if kind in {"if", "ifdef", "ifndef"}:
            conditional_stack.append(kind)
        elif kind in {"elif", "else"}:
            if not conditional_stack:
                raise GuardError(f"{label} follows an unmatched #{kind}")
        elif conditional_stack:
            conditional_stack.pop()
        else:
            raise GuardError(f"{label} follows an unmatched #endif")
    if conditional_stack:
        raise GuardError(f"{label} is enclosed by conditional preprocessing")


def reject_local_macro_overrides(
    code: str,
    protected_names: tuple[str, ...],
    label: str,
) -> None:
    """Reject translation-unit overrides of protected source identifiers."""
    overridden = sorted(
        {
            match.group("name")
            for match in C_MACRO_OVERRIDE.finditer(code)
            if match.group("name") in protected_names
        }
    )
    if overridden:
        raise GuardError(f"{label} overrides protected macros: {overridden}")


def function_code(
    source: str,
    name: str,
    protected_macros: tuple[str, ...] = (),
) -> str:
    """Return one complete function with comments and literals blanked."""
    code = strip_comments_and_literals(source)
    reject_local_macro_overrides(code, protected_macros, f"function {name}")
    definition = re.search(
        rf"(?m)^[A-Za-z_][^\n]*\b{re.escape(name)}\s*\(",
        code,
    )
    if definition is None:
        raise GuardError(f"function {name} not found")
    reject_enclosing_conditional(code, definition.start(), f"function {name}")
    opening = code.find("{", definition.start())
    semicolon = code.find(";", definition.start())
    if opening < 0 or (semicolon >= 0 and semicolon < opening):
        raise GuardError(f"function {name} has no opening brace")
    depth = 0
    for offset in range(opening, len(code)):
        if code[offset] == "{":
            depth += 1
        elif code[offset] == "}":
            depth -= 1
            if depth == 0:
                function_text = code[definition.start() : offset + 1]
                protected_identifiers = tuple(
                    sorted(
                        set(protected_macros) | set(C_IDENTIFIER.findall(function_text))
                    )
                )
                reject_local_macro_overrides(
                    code,
                    protected_identifiers,
                    f"function {name}",
                )
                return function_text
            if depth < 0:
                break
    raise GuardError(f"function {name} has no closing brace")


def brace_depth(code: str, offset: int) -> int:
    """Return lexical brace depth at one byte offset in a function."""
    opening = code.find("{")
    if opening < 0 or offset < opening:
        raise GuardError("function body has no opening brace")
    depth = 0
    for token in code[opening:offset]:
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth < 0:
                raise GuardError("function body has invalid brace order")
    return depth


def direct_statement_depth(code: str, statement_start: int) -> int:
    """Return the brace depth owned directly by one controlled statement."""
    depth = brace_depth(code, statement_start)
    if code[statement_start] == "{":
        depth += 1
    return depth


def require_direct_statement(
    code: str,
    statement_start: int,
    match_start: int,
    label: str,
) -> None:
    """Require a match to begin one direct statement in a bounded scope."""
    expected_depth = direct_statement_depth(code, statement_start)
    if brace_depth(code, match_start) != expected_depth:
        raise GuardError(f"{label} is nested below its required statement scope")

    scan_start = statement_start + (code[statement_start] == "{")
    boundary = scan_start
    depth = brace_depth(code, scan_start)
    parenthesis_depth = 0
    bracket_depth = 0
    for offset in range(scan_start, match_start):
        token = code[offset]
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == expected_depth:
                boundary = offset + 1
        elif token == "(":
            parenthesis_depth += 1
        elif token == ")":
            parenthesis_depth -= 1
            if parenthesis_depth < 0:
                raise GuardError(f"{label} has invalid parenthesis order")
        elif token == "[":
            bracket_depth += 1
        elif token == "]":
            bracket_depth -= 1
            if bracket_depth < 0:
                raise GuardError(f"{label} has invalid bracket order")
        elif (
            token == ";"
            and depth == expected_depth
            and parenthesis_depth == 0
            and bracket_depth == 0
        ):
            boundary = offset + 1
    if code[boundary:match_start].strip():
        raise GuardError(f"{label} is controlled by an unbraced statement")


def reject_conditional_directives(code: str, label: str) -> None:
    """Reject conditional preprocessing inside one audited function."""
    if C_CONDITIONAL_DIRECTIVE.search(code) is not None:
        raise GuardError(f"{label} contains a conditional preprocessing directive")


def require_exact_statement_sequence(
    code: str,
    statement_start: int,
    statement_end: int,
    pattern: str,
    label: str,
) -> None:
    """Require one closed, target-specific statement sequence."""
    statement = code[statement_start:statement_end]
    if re.fullmatch(pattern, statement) is None:
        raise GuardError(f"{label} statement sequence differs")


def require_empty_source_interval(
    code: str,
    interval_start: int,
    interval_end: int,
    label: str,
) -> None:
    """Require one comment-stripped source interval to contain no tokens."""
    if interval_start > interval_end:
        raise GuardError(f"{label} interval has invalid order")
    if code[interval_start:interval_end].strip():
        raise GuardError(f"{label} contains an intervening source token")


def one_match_in_function(
    code: str,
    pattern: re.Pattern[str],
    label: str,
) -> re.Match[str]:
    """Return one lexical match across every brace depth in a function."""
    matches = list(pattern.finditer(code))
    if len(matches) != 1:
        raise GuardError(f"{label}: expected one match, found {len(matches)}")
    return matches[0]


def one_match_in_interval_at_depth(
    code: str,
    pattern: re.Pattern[str],
    interval_start: int,
    interval_end: int,
    depth: int,
    label: str,
) -> re.Match[str]:
    """Return one lexical match in a bounded interval and at one brace depth."""
    matches = [
        match
        for match in pattern.finditer(code, interval_start, interval_end)
        if brace_depth(code, match.start()) == depth
    ]
    if len(matches) != 1:
        raise GuardError(
            f"{label}: expected one match at depth {depth}, found {len(matches)}"
        )
    return matches[0]


def require_exact_match_offsets(
    code: str,
    pattern: re.Pattern[str],
    expected_offsets: list[int],
    label: str,
) -> None:
    """Require every match to belong to one explicitly admitted transaction."""
    actual_offsets = [match.start() for match in pattern.finditer(code)]
    if actual_offsets != sorted(expected_offsets):
        raise GuardError(
            f"{label} denominator differs: expected {len(expected_offsets)}, "
            f"found {len(actual_offsets)}"
        )


def require_call_denominator(
    code: str,
    identifier: str,
    expected_count: int,
    label: str,
) -> None:
    """Require an exact function-call identifier count at every brace depth."""
    pattern = re.compile(rf"\b{re.escape(identifier)}\s*\(")
    actual_count = len(list(pattern.finditer(code)))
    if actual_count != expected_count:
        raise GuardError(
            f"{label} denominator differs: expected {expected_count}, "
            f"found {actual_count}"
        )


def controlled_statement(code: str, condition_end: int) -> tuple[int, int]:
    """Return the byte interval controlled by one condition."""
    cursor = condition_end
    while cursor < len(code) and code[cursor].isspace():
        cursor += 1
    if cursor >= len(code):
        raise GuardError("guard has no controlled statement")
    if code[cursor] != "{":
        semicolon = code.find(";", cursor)
        if semicolon < 0:
            raise GuardError("guard statement has no terminator")
        return cursor, semicolon + 1
    depth = 0
    for offset in range(cursor, len(code)):
        if code[offset] == "{":
            depth += 1
        elif code[offset] == "}":
            depth -= 1
            if depth == 0:
                return cursor, offset + 1
            if depth < 0:
                break
    raise GuardError("guard block has no closing brace")


def controlled_match(code: str, condition: re.Match[str]) -> ControlledMatch:
    """Pair one condition with its controlled source interval."""
    statement_start, statement_end = controlled_statement(code, condition.end())
    return ControlledMatch(condition, statement_start, statement_end)


def prove_refusal_statement(
    code: str,
    guard_match: re.Match[str],
    expected_return: str,
    guard_id: str,
) -> tuple[int, int]:
    """Prove one direct return in the statement controlled by a guard."""
    statement_start, statement_end = controlled_statement(code, guard_match.end())
    statement = code[statement_start:statement_end]
    return_pattern = re.compile(rf"\breturn\s+{re.escape(expected_return)}\s*;")
    returns = list(return_pattern.finditer(statement))
    if len(returns) != 1:
        raise GuardError(
            f"{guard_id}: parked refusal does not return {expected_return} exactly once"
        )
    return_at = statement_start + returns[0].start()
    require_direct_statement(
        code,
        statement_start,
        return_at,
        f"{guard_id}: parked return",
    )
    if "EDEADLK" in statement or "needs_reset" in statement:
        raise GuardError(f"{guard_id}: parked refusal uses reset reentry state")
    return statement_start, statement_end


def reject_forward_goto_over_interval(
    code: str,
    interval_start: int,
    interval_end: int,
    label: str,
) -> None:
    """Reject a goto edge that enters after a required source interval."""
    label_positions = {
        match.group(1): match.start()
        for match in re.finditer(
            r"(?m)^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*:",
            code,
        )
    }
    for jump in re.finditer(r"\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", code):
        target = label_positions.get(jump.group(1))
        if target is None:
            raise GuardError(f"{label}: goto target {jump.group(1)} is absent")
        if jump.start() < interval_start and target >= interval_end:
            raise GuardError(f"{label}: goto {jump.group(1)} bypasses the refusal")


def one_match_at_depth(
    code: str,
    pattern: re.Pattern[str],
    depth: int,
    label: str,
) -> re.Match[str]:
    """Return one lexical match at an exact function brace depth."""
    matches = [
        match
        for match in pattern.finditer(code)
        if brace_depth(code, match.start()) == depth
    ]
    if len(matches) != 1:
        raise GuardError(
            f"{label}: expected one match at depth {depth}, found {len(matches)}"
        )
    return matches[0]


def require_lock_held_at_guard(
    code: str,
    lock_end: int,
    guard_start: int,
    label: str,
) -> None:
    """Reject any read unlock between acquisition and the parked latch read."""
    if READ_UNLOCK.search(code, lock_end, guard_start) is not None:
        raise GuardError(f"{label}: exclusive_lock is released before the parked test")


def require_refusal_unlock(
    code: str,
    statement_start: int,
    statement_end: int,
    expected_return: str,
    label: str,
) -> int:
    """Require the guarded refusal to unlock before its direct return."""
    statement = code[statement_start:statement_end]
    unlocks = list(READ_UNLOCK.finditer(statement))
    returns = list(
        re.finditer(rf"\breturn\s+{re.escape(expected_return)}\s*;", statement)
    )
    if (
        len(unlocks) != 1
        or len(returns) != 1
        or unlocks[0].start() > returns[0].start()
    ):
        raise GuardError(f"{label}: parked refusal does not unlock before returning")
    require_direct_statement(
        code,
        statement_start,
        statement_start + unlocks[0].start(),
        f"{label}: refusal unlock",
    )
    require_direct_statement(
        code,
        statement_start,
        statement_start + returns[0].start(),
        f"{label}: refusal return",
    )
    return statement_start + unlocks[0].start()


def check_legacy_guard(root: Path, guard: dict[str, str]) -> None:
    path = root / guard["path"]
    try:
        source = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise GuardError(f"{guard['id']}: missing source {path}") from exc

    body = function_code(source, guard["function"], PARKED_PROTECTED_MACROS)
    reject_conditional_directives(body, guard["id"])
    guard_matches = list(PARKED_GUARD.finditer(body))
    if len(guard_matches) != 1:
        raise GuardError(
            f"{guard['id']}: expected one unconditional parked guard in "
            f"{guard['function']}, found {len(guard_matches)}"
        )
    guard_match = guard_matches[0]
    function_open = body.find("{")
    require_direct_statement(
        body,
        function_open,
        guard_match.start(),
        f"{guard['id']}: parked guard",
    )
    if guard["id"] == "gem-create":
        require_exact_statement_sequence(
            body,
            function_open,
            guard_match.start(),
            r"\{\s*"
            r"struct\s+radeon_bo\s*\*\s*robj\s*;\s*"
            r"unsigned\s+long\s+max_size\s*;\s*"
            r"int\s+r\s*;\s*"
            r"\*\s*obj\s*=\s*NULL\s*;\s*",
            "gem-create entry-to-guard prefix",
        )

    call_matches = list(re.finditer(rf"\b{re.escape(guard['precedes'])}\s*\(", body))
    if not call_matches:
        raise GuardError(
            f"{guard['id']}: {guard['precedes']} call absent from {guard['function']}"
        )
    first_call = call_matches[0]
    if guard_match.start() > first_call.start():
        raise GuardError(
            f"{guard['id']}: the gpu_parked test follows {guard['precedes']}, "
            "so it refuses nothing"
        )

    statement_start, statement_end = prove_refusal_statement(
        body,
        guard_match,
        guard["returns"],
        guard["id"],
    )
    reject_forward_goto_over_interval(
        body,
        guard_match.start(),
        statement_end,
        guard["id"],
    )
    if guard["id"] == "gem-create":
        require_exact_statement_sequence(
            body,
            statement_start,
            statement_end,
            r"\s*return\s+-EIO\s*;\s*",
            "gem-create parked refusal",
        )

    # The create funnel refuses regardless of placement. A guard made
    # conditional on a VRAM request readmits the GTT traffic the measured
    # RS482 cell showed the fault path never terminates.
    if guard["id"] == "gem-create":
        if "DOMAIN_VRAM" in body[guard_match.start() : statement_end]:
            raise GuardError(
                f"{guard['id']}: the refusal is conditional on a VRAM request, "
                "so a GTT request is readmitted"
            )

    if guard["id"] == "prime-import":
        check_prime_import_lock(body, guard_match, statement_start, statement_end)
    elif guard["id"] == "wait-idle-flush":
        check_wait_idle_lock(body, guard_match, statement_start, statement_end)
    elif guard["id"] == "command-submission":
        check_command_submission_lock(body, guard_match, statement_start, statement_end)


def check_prime_import_lock(
    body: str,
    guard_match: re.Match[str],
    statement_start: int,
    statement_end: int,
) -> None:
    """Prove the exact PRIME reservation lock-through-result transaction."""

    function_open = body.find("{")
    reservation_declaration = one_match_in_function(
        body,
        re.compile(
            r"\bstruct\s+dma_resv\s*\*\s*resv\s*=\s*"
            r"attach->dmabuf->resv\s*;"
        ),
        "prime-import reservation declaration",
    )
    lock = one_match_in_function(body, READ_LOCK, "prime-import read lock")
    reservation = one_match_in_function(
        body,
        re.compile(r"\bdma_resv_lock\s*\(\s*resv\s*,\s*NULL\s*\)\s*;"),
        "prime-import reservation lock",
    )
    allocation = one_match_in_function(
        body,
        re.compile(
            r"\bret\s*=\s*radeon_bo_create\s*\(\s*rdev\s*,\s*"
            r"attach->dmabuf->size\s*,\s*PAGE_SIZE\s*,\s*false\s*,\s*"
            r"RADEON_GEM_DOMAIN_GTT\s*,\s*0\s*,\s*sg\s*,\s*resv\s*,\s*"
            r"&bo\s*\)\s*;"
        ),
        "prime-import allocation",
    )
    reservation_unlock = one_match_in_function(
        body,
        re.compile(r"\bdma_resv_unlock\s*\(\s*resv\s*\)\s*;"),
        "prime-import reservation unlock",
    )
    final_unlock = one_match_at_depth(
        body,
        READ_UNLOCK,
        1,
        "prime-import final read unlock",
    )
    result_guard = one_match_in_function(
        body,
        re.compile(r"\bif\s*\(\s*ret\s*\)"),
        "prime-import allocation result guard",
    )
    result_start, result_end = controlled_statement(body, result_guard.end())
    require_exact_statement_sequence(
        body,
        result_start,
        result_end,
        r"\s*return\s+ERR_PTR\s*\(\s*ret\s*\)\s*;\s*",
        "prime-import allocation failure",
    )

    for match, label in (
        (reservation_declaration, "prime-import reservation declaration"),
        (lock, "prime-import read lock"),
        (reservation, "prime-import reservation lock"),
        (allocation, "prime-import allocation"),
        (reservation_unlock, "prime-import reservation unlock"),
        (final_unlock, "prime-import final read unlock"),
        (result_guard, "prime-import allocation result guard"),
    ):
        if brace_depth(body, match.start()) != 1:
            raise GuardError(f"{label} is outside direct function scope")
        require_direct_statement(body, function_open, match.start(), label)
    if not (
        reservation_declaration.start()
        < lock.start()
        < guard_match.start()
        < statement_end
        <= reservation.start()
        < allocation.start()
        < reservation_unlock.start()
        < final_unlock.start()
        < result_guard.start()
    ):
        raise GuardError(
            "prime-import: reservation declaration, exclusive lock, parked "
            "refusal, reservation transaction, and result guard order differs"
        )

    require_empty_source_interval(
        body,
        lock.end(),
        guard_match.start(),
        "prime-import lock-to-guard",
    )
    require_empty_source_interval(
        body,
        statement_end,
        reservation.start(),
        "prime-import refusal-to-reservation",
    )
    require_empty_source_interval(
        body,
        reservation.end(),
        allocation.start(),
        "prime-import reservation-to-allocation",
    )
    require_empty_source_interval(
        body,
        allocation.end(),
        reservation_unlock.start(),
        "prime-import allocation-to-reservation-unlock",
    )
    require_empty_source_interval(
        body,
        reservation_unlock.end(),
        final_unlock.start(),
        "prime-import reservation-unlock-to-read-unlock",
    )
    require_empty_source_interval(
        body,
        final_unlock.end(),
        result_guard.start(),
        "prime-import read-unlock-to-result-guard",
    )
    require_exact_statement_sequence(
        body,
        function_open,
        lock.end(),
        r"\{\s*"
        r"struct\s+dma_resv\s*\*\s*resv\s*=\s*"
        r"attach->dmabuf->resv\s*;\s*"
        r"struct\s+radeon_device\s*\*\s*rdev\s*=\s*dev->dev_private\s*;\s*"
        r"struct\s+radeon_bo\s*\*\s*bo\s*;\s*"
        r"int\s+ret\s*;\s*"
        r"down_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*",
        "prime-import declaration and lock prefix",
    )

    parked_unlock_offset = require_refusal_unlock(
        body,
        statement_start,
        statement_end,
        "ERR_PTR(-EIO)",
        "prime-import",
    )
    require_exact_statement_sequence(
        body,
        statement_start,
        statement_end,
        r"\s*\{\s*"
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"return\s+ERR_PTR\s*\(\s*-EIO\s*\)\s*;\s*"
        r"\}\s*",
        "prime-import parked refusal",
    )
    require_exact_match_offsets(
        body,
        READ_UNLOCK,
        [parked_unlock_offset, final_unlock.start()],
        "prime-import read unlock",
    )
    transaction = body[lock.start() : result_end]
    if len(list(re.finditer(r"\breturn\b", transaction))) != 2:
        raise GuardError("prime-import transaction return denominator differs")
    if re.search(r"\bgoto\b", transaction) is not None:
        raise GuardError("prime-import transaction contains an unadmitted goto")


def check_wait_idle_lock(
    body: str,
    guard_match: re.Match[str],
    statement_start: int,
    statement_end: int,
) -> None:
    """Prove the bounded wait, parked refusal, VRAM flush, and result return."""

    function_open = body.find("{")
    wait = one_match_in_function(
        body,
        re.compile(
            r"\bret\s*=\s*dma_resv_wait_timeout\s*\(\s*"
            r"robj->tbo.base.resv\s*,\s*DMA_RESV_USAGE_READ\s*,\s*true\s*,\s*"
            r"30\s*\*\s*HZ\s*\)\s*;"
        ),
        "wait-idle-flush reservation wait",
    )
    require_exact_statement_sequence(
        body,
        function_open,
        wait.end(),
        r"\{\s*"
        r"struct\s+radeon_device\s*\*\s*rdev\s*=\s*dev->dev_private\s*;\s*"
        r"struct\s+drm_radeon_gem_wait_idle\s*\*\s*args\s*=\s*data\s*;\s*"
        r"struct\s+drm_gem_object\s*\*\s*gobj\s*;\s*"
        r"struct\s+radeon_bo\s*\*\s*robj\s*;\s*"
        r"int\s+r\s*=\s*0\s*;\s*"
        r"uint32_t\s+cur_placement\s*=\s*0\s*;\s*"
        r"long\s+ret\s*;\s*"
        r"gobj\s*=\s*drm_gem_object_lookup\s*\(\s*filp\s*,\s*"
        r"args->handle\s*\)\s*;\s*"
        r"if\s*\(\s*gobj\s*==\s*NULL\s*\)\s*\{\s*"
        r"return\s+-ENOENT\s*;\s*\}\s*"
        r"robj\s*=\s*gem_to_radeon_bo\s*\(\s*gobj\s*\)\s*;\s*"
        r"ret\s*=\s*dma_resv_wait_timeout\s*\(\s*"
        r"robj->tbo.base.resv\s*,\s*DMA_RESV_USAGE_READ\s*,\s*true\s*,\s*"
        r"30\s*\*\s*HZ\s*\)\s*;\s*",
        "wait-idle-flush entry-to-wait prefix",
    )
    lock = one_match_in_function(body, READ_LOCK, "wait-idle-flush read lock")
    placement = one_match_in_function(
        body,
        re.compile(
            r"\bcur_placement\s*=\s*READ_ONCE\s*\(\s*"
            r"robj->tbo.resource->mem_type\s*\)\s*;"
        ),
        "wait-idle-flush placement read",
    )
    flush_guard = one_match_in_function(
        body,
        re.compile(
            r"\bif\s*\(\s*rdev->asic->mmio_hdp_flush\s*&&\s*"
            r"radeon_mem_type_to_domain\s*\(\s*cur_placement\s*\)\s*==\s*"
            r"RADEON_GEM_DOMAIN_VRAM\s*\)"
        ),
        "wait-idle-flush VRAM predicate",
    )
    flush_start, flush_end = controlled_statement(body, flush_guard.end())
    flush = one_match_in_interval_at_depth(
        body,
        re.compile(r"\brobj->rdev->asic->mmio_hdp_flush\s*\(\s*rdev\s*\)\s*;"),
        flush_start,
        flush_end,
        direct_statement_depth(body, flush_start),
        "wait-idle-flush MMIO call",
    )
    require_exact_statement_sequence(
        body,
        flush_start,
        flush_end,
        r"\s*robj->rdev->asic->mmio_hdp_flush\s*\(\s*rdev\s*\)\s*;\s*",
        "wait-idle-flush MMIO call",
    )
    final_unlock = one_match_at_depth(
        body,
        READ_UNLOCK,
        1,
        "wait-idle-flush final read unlock",
    )
    for match, label in (
        (wait, "wait-idle-flush reservation wait"),
        (lock, "wait-idle-flush read lock"),
        (placement, "wait-idle-flush placement read"),
        (flush_guard, "wait-idle-flush VRAM predicate"),
        (final_unlock, "wait-idle-flush final read unlock"),
    ):
        if brace_depth(body, match.start()) != 1:
            raise GuardError(f"{label} is outside direct function scope")
        require_direct_statement(body, function_open, match.start(), label)
    require_direct_statement(
        body,
        flush_start,
        flush.start(),
        "wait-idle-flush MMIO call",
    )
    if not (
        wait.start()
        < lock.start()
        < guard_match.start()
        < statement_end
        < placement.start()
        < flush_guard.start()
        < flush.start()
        < final_unlock.start()
    ):
        raise GuardError(
            "wait-idle-flush: expected reservation wait, exclusive lock, "
            "parked guard, placement, flush, and unlock order"
        )
    require_exact_statement_sequence(
        body,
        wait.end(),
        lock.start(),
        r"\s*if\s*\(\s*ret\s*==\s*0\s*\)\s*"
        r"r\s*=\s*-EBUSY\s*;\s*"
        r"else\s+if\s*\(\s*ret\s*<\s*0\s*\)\s*"
        r"r\s*=\s*ret\s*;\s*",
        "wait-idle-flush wait result normalization",
    )
    require_empty_source_interval(
        body,
        lock.end(),
        guard_match.start(),
        "wait-idle-flush lock-to-guard",
    )
    require_empty_source_interval(
        body,
        statement_end,
        placement.start(),
        "wait-idle-flush refusal-to-placement",
    )
    require_empty_source_interval(
        body,
        placement.end(),
        flush_guard.start(),
        "wait-idle-flush placement-to-predicate",
    )
    require_empty_source_interval(
        body,
        flush_end,
        final_unlock.start(),
        "wait-idle-flush flush-to-unlock",
    )
    require_lock_held_at_guard(body, lock.end(), guard_match.start(), "wait-idle-flush")
    parked_unlock_offset = require_refusal_unlock(
        body,
        statement_start,
        statement_end,
        "-EIO",
        "wait-idle-flush",
    )
    require_exact_statement_sequence(
        body,
        statement_start,
        statement_end,
        r"\s*\{\s*"
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"drm_gem_object_put\s*\(\s*gobj\s*\)\s*;\s*"
        r"return\s+-EIO\s*;\s*"
        r"\}\s*",
        "wait-idle-flush parked refusal",
    )
    require_call_denominator(
        body,
        "dma_resv_wait_timeout",
        1,
        "wait-idle-flush reservation wait",
    )
    require_call_denominator(
        body,
        "mmio_hdp_flush",
        1,
        "wait-idle-flush MMIO call",
    )
    require_exact_match_offsets(
        body,
        READ_UNLOCK,
        [parked_unlock_offset, final_unlock.start()],
        "wait-idle-flush read unlock",
    )
    require_exact_statement_sequence(
        body,
        final_unlock.end(),
        len(body),
        r"\s*drm_gem_object_put\s*\(\s*gobj\s*\)\s*;\s*"
        r"r\s*=\s*radeon_gem_handle_lockup\s*\(\s*rdev\s*,\s*r\s*\)\s*;\s*"
        r"return\s+r\s*;\s*\}\s*",
        "wait-idle-flush post-unlock cleanup and result return",
    )
    interval_returns = list(
        re.compile(r"\breturn\b").finditer(
            body,
            wait.start(),
            final_unlock.end(),
        )
    )
    if len(interval_returns) != 1:
        raise GuardError("wait-idle-flush wait-to-unlock return denominator differs")
    if re.search(r"\bgoto\b", body[wait.start() : final_unlock.end()]) is not None:
        raise GuardError("wait-idle-flush wait-to-unlock interval contains goto")


def find_command_submission_topology(body: str) -> CommandSubmissionTopology:
    """Resolve every source anchor in the command-submission contract."""
    function_open = body.find("{")
    lock = one_match_in_function(body, READ_LOCK, "command-submission read lock")
    acceleration_condition = one_match_in_function(
        body,
        re.compile(r"\bif\s*\(\s*!\s*rdev->accel_working\s*\)"),
        "command-submission acceleration guard",
    )
    reset_condition = one_match_in_function(
        body,
        re.compile(r"\bif\s*\(\s*rdev->in_reset\s*\)"),
        "command-submission reset guard",
    )
    parser_zero = one_match_in_function(
        body,
        re.compile(
            r"\bmemset\s*\(\s*&parser\s*,\s*0\s*,\s*"
            r"sizeof\s*\(\s*(?:parser|struct\s+radeon_cs_parser)\s*\)\s*\)\s*;"
        ),
        "command-submission parser zeroing",
    )
    parser_init = one_match_in_function(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_parser_init\s*"
            r"\(\s*&parser\s*,\s*data\s*\)\s*;"
        ),
        "command-submission parser initialization",
    )
    ib_fill = one_match_in_function(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_fill\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        "command-submission IB fill call",
    )
    relocations = one_match_in_function(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_parser_relocs\s*"
            r"\(\s*&parser\s*\)\s*;"
        ),
        "command-submission relocation call",
    )
    trace = one_match_in_function(
        body,
        re.compile(r"\btrace_radeon_cs\s*\(\s*&parser\s*\)\s*;"),
        "command-submission trace call",
    )
    ib_schedule = one_match_in_function(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_chunk\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        "command-submission non-VM IB schedule call",
    )
    ib_vm_schedule = one_match_in_function(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_vm_chunk\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        "command-submission VM IB schedule call",
    )
    out_label = one_match_in_function(
        body,
        re.compile(r"(?m)^[ \t]*out\s*:"),
        "command-submission out label",
    )
    final_unlock = one_match_at_depth(
        body,
        READ_UNLOCK,
        1,
        "command-submission final read unlock",
    )

    parser_failure_condition = one_match_in_interval_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        parser_init.end(),
        ib_fill.start(),
        1,
        "command-submission parser initialization failure guard",
    )
    relocation_condition = one_match_in_interval_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*!\s*r\s*\)"),
        ib_fill.end(),
        trace.start(),
        1,
        "command-submission relocation result guard",
    )
    relocation_stage = controlled_match(body, relocation_condition)
    validation_failure_condition = one_match_in_interval_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        relocation_stage.statement_end,
        trace.start(),
        1,
        "command-submission validation failure guard",
    )
    ib_failure_condition = one_match_in_interval_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        ib_schedule.end(),
        ib_vm_schedule.start(),
        1,
        "command-submission non-VM result guard",
    )
    ib_vm_failure_condition = one_match_in_interval_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        ib_vm_schedule.end(),
        out_label.start(),
        1,
        "command-submission VM result guard",
    )
    ib_vm_failure = controlled_match(body, ib_vm_failure_condition)
    fence_condition = one_match_in_interval_at_depth(
        body,
        re.compile(
            r"\bif\s*\(\s*!\s*list_empty\s*\(\s*&parser\.validated\s*\)\s*"
            r"&&\s*!\s*parser\.ib\.fence\s*\)"
        ),
        ib_vm_failure.statement_end,
        out_label.start(),
        1,
        "command-submission validated-BO fence guard",
    )
    final_return = one_match_in_interval_at_depth(
        body,
        re.compile(r"\breturn\s+r\s*;"),
        out_label.end(),
        len(body),
        1,
        "command-submission final return",
    )
    return CommandSubmissionTopology(
        function_open=function_open,
        lock=lock,
        acceleration=controlled_match(body, acceleration_condition),
        reset=controlled_match(body, reset_condition),
        parser_zero=parser_zero,
        parser_init=parser_init,
        parser_failure=controlled_match(body, parser_failure_condition),
        ib_fill=ib_fill,
        relocation_stage=relocation_stage,
        relocations=relocations,
        validation_failure=controlled_match(body, validation_failure_condition),
        trace=trace,
        ib_schedule=ib_schedule,
        ib_failure=controlled_match(body, ib_failure_condition),
        ib_vm_schedule=ib_vm_schedule,
        ib_vm_failure=ib_vm_failure,
        fence_validation=controlled_match(body, fence_condition),
        out_label=out_label,
        final_unlock=final_unlock,
        final_return=final_return,
    )


def require_command_submission_denominators(
    body: str,
    topology: CommandSubmissionTopology,
    parked_statement_start: int,
    parked_statement_end: int,
    parked_unlock_offset: int,
    acceleration_unlock_offset: int,
    reset_unlock_offset: int,
) -> None:
    """Bind every CS call, unlock, return, and goto to one admitted stage."""
    parser_failure_unlock = one_match_in_interval_at_depth(
        body,
        READ_UNLOCK,
        topology.parser_failure.statement_start,
        topology.parser_failure.statement_end,
        direct_statement_depth(body, topology.parser_failure.statement_start),
        "command-submission parser failure unlock",
    )
    validation_failure_unlock = one_match_in_interval_at_depth(
        body,
        READ_UNLOCK,
        topology.validation_failure.statement_start,
        topology.validation_failure.statement_end,
        direct_statement_depth(body, topology.validation_failure.statement_start),
        "command-submission validation failure unlock",
    )
    require_exact_match_offsets(
        body,
        re.compile(r"\bmemset\s*\(\s*&parser\b"),
        [topology.parser_zero.start()],
        "command-submission parser zeroing",
    )
    for identifier, expected_count, label in (
        ("radeon_gpu_reset", 1, "reset call"),
        ("radeon_cs_parser_init", 1, "parser initialization"),
        ("radeon_cs_ib_fill", 1, "IB fill"),
        ("radeon_cs_parser_relocs", 1, "relocation"),
        ("trace_radeon_cs", 1, "trace"),
        ("radeon_cs_ib_chunk", 1, "non-VM schedule"),
        ("radeon_cs_ib_vm_chunk", 1, "VM schedule"),
        ("radeon_cs_parser_fini", 3, "parser finalization"),
        ("radeon_cs_handle_lockup", 3, "lockup translation"),
        ("radeon_ib_get", 0, "early IB allocation"),
    ):
        require_call_denominator(
            body,
            identifier,
            expected_count,
            f"command-submission {label}",
        )

    def one_token_offset(
        pattern: re.Pattern[str],
        interval_start: int,
        interval_end: int,
        label: str,
    ) -> int:
        matches = list(pattern.finditer(body, interval_start, interval_end))
        if len(matches) != 1:
            raise GuardError(f"{label}: expected one token, found {len(matches)}")
        return matches[0].start()

    return_pattern = re.compile(r"\breturn\b")
    goto_pattern = re.compile(r"\bgoto\b")
    return_offsets = [
        one_token_offset(
            return_pattern,
            parked_statement_start,
            parked_statement_end,
            "parked return",
        ),
        one_token_offset(
            return_pattern,
            topology.acceleration.statement_start,
            topology.acceleration.statement_end,
            "acceleration return",
        ),
        one_token_offset(
            return_pattern,
            topology.reset.statement_start,
            topology.reset.statement_end,
            "reset return",
        ),
        one_token_offset(
            return_pattern,
            topology.parser_failure.statement_start,
            topology.parser_failure.statement_end,
            "parser failure return",
        ),
        one_token_offset(
            return_pattern,
            topology.validation_failure.statement_start,
            topology.validation_failure.statement_end,
            "validation failure return",
        ),
        topology.final_return.start(),
    ]
    goto_offsets = [
        one_token_offset(
            goto_pattern,
            topology.ib_failure.statement_start,
            topology.ib_failure.statement_end,
            "non-VM failure goto",
        ),
        one_token_offset(
            goto_pattern,
            topology.ib_vm_failure.statement_start,
            topology.ib_vm_failure.statement_end,
            "VM failure goto",
        ),
    ]
    require_exact_match_offsets(
        body,
        READ_UNLOCK,
        [
            parked_unlock_offset,
            acceleration_unlock_offset,
            reset_unlock_offset,
            parser_failure_unlock.start(),
            validation_failure_unlock.start(),
            topology.final_unlock.start(),
        ],
        "command-submission read unlock",
    )
    require_exact_match_offsets(
        body,
        return_pattern,
        return_offsets,
        "command-submission return",
    )
    require_exact_match_offsets(
        body,
        goto_pattern,
        goto_offsets,
        "command-submission goto",
    )


def check_command_submission_lock(
    body: str,
    guard_match: re.Match[str],
    statement_start: int,
    statement_end: int,
) -> None:
    """Prove the complete CS refusal, validation, and scheduling topology."""

    topology = find_command_submission_topology(body)
    function_open = topology.function_open
    lock = topology.lock
    acceleration = topology.acceleration.condition
    reset = topology.reset.condition
    parser_zero = topology.parser_zero
    parser_init = topology.parser_init
    ib_fill = topology.ib_fill
    relocations = topology.relocations
    trace = topology.trace
    ib_schedule = topology.ib_schedule
    ib_vm_schedule = topology.ib_vm_schedule
    out_label = topology.out_label
    final_unlock = topology.final_unlock

    parser_failure = topology.parser_failure.condition
    parser_failure_start = topology.parser_failure.statement_start
    parser_failure_end = topology.parser_failure.statement_end
    relocation_guard = topology.relocation_stage.condition
    relocation_start = topology.relocation_stage.statement_start
    relocation_end = topology.relocation_stage.statement_end
    validation_failure = topology.validation_failure.condition
    validation_failure_start = topology.validation_failure.statement_start
    validation_failure_end = topology.validation_failure.statement_end
    ib_failure = topology.ib_failure.condition
    ib_failure_start = topology.ib_failure.statement_start
    ib_failure_end = topology.ib_failure.statement_end
    ib_vm_failure = topology.ib_vm_failure.condition
    ib_vm_failure_start = topology.ib_vm_failure.statement_start
    ib_vm_failure_end = topology.ib_vm_failure.statement_end
    fence_validation = topology.fence_validation.condition
    fence_validation_start = topology.fence_validation.statement_start
    fence_validation_end = topology.fence_validation.statement_end
    final_return = topology.final_return

    direct_matches = (
        (lock, "command-submission read lock"),
        (acceleration, "command-submission acceleration guard"),
        (reset, "command-submission reset guard"),
        (parser_zero, "command-submission parser zeroing"),
        (parser_init, "command-submission parser initialization"),
        (parser_failure, "command-submission parser initialization failure guard"),
        (ib_fill, "command-submission IB fill call"),
        (relocation_guard, "command-submission relocation result guard"),
        (validation_failure, "command-submission validation failure guard"),
        (trace, "command-submission trace call"),
        (ib_schedule, "command-submission non-VM IB schedule call"),
        (ib_failure, "command-submission non-VM result guard"),
        (ib_vm_schedule, "command-submission VM IB schedule call"),
        (ib_vm_failure, "command-submission VM result guard"),
        (fence_validation, "command-submission validated-BO fence guard"),
        (final_unlock, "command-submission final read unlock"),
        (final_return, "command-submission final return"),
    )
    for match, label in direct_matches:
        if brace_depth(body, match.start()) != 1:
            raise GuardError(f"{label} is outside direct function scope")
        require_direct_statement(body, function_open, match.start(), label)

    if not (
        lock.start()
        < guard_match.start()
        < statement_end
        <= acceleration.start()
        < reset.start()
        < parser_zero.start()
        < parser_init.start()
        < parser_failure.start()
        < ib_fill.start()
        < relocation_guard.start()
        < relocations.start()
        < validation_failure.start()
        < trace.start()
        < ib_schedule.start()
        < ib_failure.start()
        < ib_vm_schedule.start()
        < ib_vm_failure.start()
        < fence_validation.start()
        < out_label.start()
        < final_unlock.start()
        < final_return.start()
    ):
        raise GuardError(
            "command-submission: refusal, parser, validation, schedule, and "
            "cleanup order differs"
        )

    require_exact_statement_sequence(
        body,
        function_open,
        lock.end(),
        r"\{\s*"
        r"struct\s+radeon_device\s*\*\s*rdev\s*=\s*dev->dev_private\s*;\s*"
        r"struct\s+radeon_cs_parser\s+parser\s*;\s*"
        r"int\s+r\s*;\s*"
        r"down_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*",
        "command-submission declaration and lock prefix",
    )
    require_empty_source_interval(
        body,
        lock.end(),
        guard_match.start(),
        "command-submission lock-to-guard",
    )

    parked_unlock_offset = require_refusal_unlock(
        body,
        statement_start,
        statement_end,
        "-EIO",
        "command-submission",
    )
    require_exact_statement_sequence(
        body,
        statement_start,
        statement_end,
        r"\s*\{\s*"
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"(?:dev_err_once\s*\(\s*rdev->dev\s*,\s*\)\s*;\s*)?"
        r"return\s+-EIO\s*;\s*"
        r"\}\s*",
        "command-submission parked refusal",
    )
    acceleration_start, acceleration_end = controlled_statement(
        body,
        acceleration.end(),
    )
    acceleration_unlock_offset = require_refusal_unlock(
        body,
        acceleration_start,
        acceleration_end,
        "-EBUSY",
        "command-submission acceleration",
    )
    require_exact_statement_sequence(
        body,
        acceleration_start,
        acceleration_end,
        r"\s*\{\s*"
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"return\s+-EBUSY\s*;\s*"
        r"\}\s*",
        "command-submission acceleration refusal",
    )
    reset_start, reset_end = controlled_statement(body, reset.end())
    reset_statement = body[reset_start:reset_end]
    if RESET_TRANSACTION.fullmatch(reset_statement) is None:
        raise GuardError(
            "command-submission: reset path is not the direct unlock, reset, "
            "success translation, and return transaction"
        )
    reset_unlock = one_match_in_interval_at_depth(
        body,
        READ_UNLOCK,
        reset_start,
        reset_end,
        direct_statement_depth(body, reset_start),
        "command-submission reset unlock",
    )

    require_empty_source_interval(
        body,
        statement_end,
        acceleration.start(),
        "command-submission parked-to-acceleration",
    )
    require_empty_source_interval(
        body,
        acceleration_end,
        reset.start(),
        "command-submission acceleration-to-reset",
    )
    require_empty_source_interval(
        body,
        reset_end,
        parser_zero.start(),
        "command-submission reset-to-parser-zero",
    )
    require_exact_statement_sequence(
        body,
        parser_zero.start(),
        parser_init.end(),
        r"\s*memset\s*\(\s*&parser\s*,\s*0\s*,\s*"
        r"sizeof\s*\(\s*(?:parser|struct\s+radeon_cs_parser)\s*\)\s*\)\s*;\s*"
        r"parser\.filp\s*=\s*filp\s*;\s*"
        r"parser\.rdev\s*=\s*rdev\s*;\s*"
        r"parser\.dev\s*=\s*rdev->dev\s*;\s*"
        r"parser\.family\s*=\s*rdev->family\s*;\s*"
        r"r\s*=\s*radeon_cs_parser_init\s*\(\s*&parser\s*,\s*data\s*\)\s*;\s*",
        "command-submission parser initialization prefix",
    )
    require_empty_source_interval(
        body,
        parser_init.end(),
        parser_failure.start(),
        "command-submission parser-init-to-failure-guard",
    )
    require_exact_statement_sequence(
        body,
        parser_failure_start,
        parser_failure_end,
        r"\s*\{\s*DRM_ERROR\s*\(\s*\)\s*;\s*"
        r"radeon_cs_parser_fini\s*\(\s*&parser\s*,\s*r\s*\)\s*;\s*"
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"r\s*=\s*radeon_cs_handle_lockup\s*\(\s*rdev\s*,\s*r\s*\)\s*;\s*"
        r"return\s+r\s*;\s*\}\s*",
        "command-submission parser initialization failure",
    )
    require_empty_source_interval(
        body,
        parser_failure_end,
        ib_fill.start(),
        "command-submission parser-failure-to-IB-fill",
    )
    require_empty_source_interval(
        body,
        ib_fill.end(),
        relocation_guard.start(),
        "command-submission IB-fill-to-relocation-guard",
    )
    require_exact_statement_sequence(
        body,
        relocation_start,
        relocation_end,
        r"\s*\{\s*r\s*=\s*radeon_cs_parser_relocs\s*"
        r"\(\s*&parser\s*\)\s*;\s*"
        r"if\s*\(\s*r\s*&&\s*r\s*!=\s*-ERESTARTSYS\s*\)\s*"
        r"DRM_ERROR\s*\(\s*,\s*r\s*\)\s*;\s*\}\s*",
        "command-submission relocation success stage",
    )
    require_empty_source_interval(
        body,
        relocation_end,
        validation_failure.start(),
        "command-submission relocation-to-failure-guard",
    )
    require_exact_statement_sequence(
        body,
        validation_failure_start,
        validation_failure_end,
        r"\s*\{\s*radeon_cs_parser_fini\s*\(\s*&parser\s*,\s*r\s*\)\s*;\s*"
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"r\s*=\s*radeon_cs_handle_lockup\s*\(\s*rdev\s*,\s*r\s*\)\s*;\s*"
        r"return\s+r\s*;\s*\}\s*",
        "command-submission validation failure",
    )
    require_empty_source_interval(
        body,
        validation_failure_end,
        trace.start(),
        "command-submission validation-to-trace",
    )
    require_empty_source_interval(
        body,
        trace.end(),
        ib_schedule.start(),
        "command-submission trace-to-non-VM-stage",
    )
    require_empty_source_interval(
        body,
        ib_schedule.end(),
        ib_failure.start(),
        "command-submission non-VM-stage-to-result-guard",
    )
    require_exact_statement_sequence(
        body,
        ib_failure_start,
        ib_failure_end,
        r"\s*\{\s*goto\s+out\s*;\s*\}\s*",
        "command-submission non-VM failure edge",
    )
    require_empty_source_interval(
        body,
        ib_failure_end,
        ib_vm_schedule.start(),
        "command-submission non-VM-to-VM-stage",
    )
    require_empty_source_interval(
        body,
        ib_vm_schedule.end(),
        ib_vm_failure.start(),
        "command-submission VM-stage-to-result-guard",
    )
    require_exact_statement_sequence(
        body,
        ib_vm_failure_start,
        ib_vm_failure_end,
        r"\s*\{\s*goto\s+out\s*;\s*\}\s*",
        "command-submission VM failure edge",
    )
    require_empty_source_interval(
        body,
        ib_vm_failure_end,
        fence_validation.start(),
        "command-submission VM-failure-to-fence-guard",
    )
    require_exact_statement_sequence(
        body,
        fence_validation_start,
        fence_validation_end,
        r"\s*\{\s*DRM_ERROR\s*\(\s*\)\s*;\s*"
        r"r\s*=\s*-EINVAL\s*;\s*\}\s*",
        "command-submission validated-BO fence failure",
    )
    require_empty_source_interval(
        body,
        fence_validation_end,
        out_label.start(),
        "command-submission fence-failure-to-cleanup",
    )
    require_exact_statement_sequence(
        body,
        out_label.start(),
        final_return.end(),
        r"\s*out\s*:\s*"
        r"radeon_cs_parser_fini\s*\(\s*&parser\s*,\s*r\s*\)\s*;\s*"
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*"
        r"r\s*=\s*radeon_cs_handle_lockup\s*\(\s*rdev\s*,\s*r\s*\)\s*;\s*"
        r"return\s+r\s*;\s*",
        "command-submission final cleanup",
    )

    require_command_submission_denominators(
        body,
        topology,
        statement_start,
        statement_end,
        parked_unlock_offset,
        acceleration_unlock_offset,
        reset_unlock.start(),
    )


def check_legacy_dumb_create_propagation(root: Path) -> None:
    """Check that dumb-create returns the immediately preceding creator result."""
    path = root / SUBTREE / "radeon_gem.c"
    try:
        source = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise GuardError(f"dumb-create: missing source {path}") from exc

    body = function_code(
        source,
        "radeon_mode_dumb_create",
        DUMB_CREATE_PROTECTED_MACROS,
    )
    reject_conditional_directives(body, "dumb-create")
    function_open = body.find("{")
    lock = one_match_in_function(body, READ_LOCK, "dumb-create read lock")
    require_exact_statement_sequence(
        body,
        function_open,
        lock.end(),
        r"\{\s*"
        r"struct\s+radeon_device\s*\*\s*rdev\s*=\s*dev->dev_private\s*;\s*"
        r"struct\s+drm_gem_object\s*\*\s*gobj\s*;\s*"
        r"uint32_t\s+handle\s*;\s*"
        r"int\s+r\s*;\s*"
        r"args->pitch\s*=\s*radeon_align_pitch\s*\(\s*rdev\s*,\s*"
        r"args->width\s*,\s*DIV_ROUND_UP\s*\(\s*args->bpp\s*,\s*8\s*\)\s*,\s*"
        r"0\s*\)\s*;\s*"
        r"args->size\s*=\s*\(\s*u64\s*\)\s*args->pitch\s*\*\s*"
        r"args->height\s*;\s*"
        r"args->size\s*=\s*ALIGN\s*\(\s*args->size\s*,\s*PAGE_SIZE\s*\)\s*;\s*"
        r"down_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;\s*",
        "dumb-create entry-to-lock prefix",
    )
    creator = one_match_in_function(
        body,
        re.compile(
            r"\br\s*=\s*radeon_gem_object_create\s*\(\s*rdev\s*,\s*"
            r"args->size\s*,\s*0\s*,\s*RADEON_GEM_DOMAIN_VRAM\s*,\s*0\s*,\s*"
            r"false\s*,\s*&gobj\s*\)\s*;"
        ),
        "dumb-create creator assignment",
    )
    unlock = one_match_in_function(body, READ_UNLOCK, "dumb-create read unlock")
    result_guards = [
        match
        for match in re.finditer(r"\bif\s*\(\s*r\s*\)", body)
        if match.start() > creator.end()
    ]
    if not result_guards:
        raise GuardError(
            "dumb-create: the creator's result is never tested, so a failed "
            "create falls through to handle creation"
        )
    result_guard = result_guards[0]
    if not lock.start() < creator.start() < unlock.start() < result_guard.start():
        raise GuardError(
            "dumb-create: read lock, creator, read unlock, and result guard "
            "order differs"
        )
    for match, label in (
        (lock, "dumb-create read lock"),
        (creator, "dumb-create creator assignment"),
        (unlock, "dumb-create read unlock"),
        (result_guard, "dumb-create creator result guard"),
    ):
        if brace_depth(body, match.start()) != 1:
            raise GuardError(f"{label} is outside direct function scope")
        require_direct_statement(body, function_open, match.start(), label)
    require_empty_source_interval(
        body,
        lock.end(),
        creator.start(),
        "dumb-create lock-to-creator",
    )
    require_empty_source_interval(
        body,
        creator.end(),
        unlock.start(),
        "dumb-create creator-to-unlock",
    )
    require_empty_source_interval(
        body,
        unlock.end(),
        result_guard.start(),
        "dumb-create unlock-to-result-guard",
    )
    statement_start, statement_end = prove_refusal_statement(
        body,
        result_guard,
        "r",
        "dumb-create",
    )
    require_exact_statement_sequence(
        body,
        statement_start,
        statement_end,
        r"\s*return\s+r\s*;\s*",
        "dumb-create creator result refusal",
    )
    reject_forward_goto_over_interval(
        body,
        result_guard.start(),
        statement_end,
        "dumb-create",
    )
    require_call_denominator(
        body,
        "radeon_gem_object_create",
        1,
        "dumb-create creator assignment",
    )


def projected_direct_match(
    body: str,
    pattern: re.Pattern[str],
    label: str,
) -> re.Match[str]:
    """Return one direct function-scope match from a projected helper path."""

    match = one_match_in_function(body, pattern, label)
    function_open = body.find("{")
    if brace_depth(body, match.start()) != 1:
        raise GuardError(f"{label} is outside direct function scope")
    require_direct_statement(body, function_open, match.start(), label)
    return match


def projected_labeled_match(
    body: str,
    pattern: re.Pattern[str],
    label: str,
) -> re.Match[str]:
    """Return one function-scope match immediately following a C label."""

    match = one_match_in_function(body, pattern, label)
    if brace_depth(body, match.start()) != 1:
        raise GuardError(f"{label} is outside direct function scope")
    return match


def projected_condition(
    body: str,
    pattern: re.Pattern[str],
    interval_start: int,
    interval_end: int,
    label: str,
) -> ControlledMatch:
    """Return one direct function-scope condition in a bounded interval."""

    condition = one_match_in_interval_at_depth(
        body,
        pattern,
        interval_start,
        interval_end,
        1,
        label,
    )
    require_direct_statement(body, body.find("{"), condition.start(), label)
    return controlled_match(body, condition)


def require_projected_failure(
    body: str,
    assignment: re.Match[str],
    interval_end: int,
    result_name: str,
    statement_pattern: str,
    label: str,
) -> ControlledMatch:
    """Prove a helper result reaches one direct fail-closed return."""

    failure = projected_condition(
        body,
        re.compile(rf"\bif\s*\(\s*{re.escape(result_name)}\s*\)"),
        assignment.end(),
        interval_end,
        f"{label} result guard",
    )
    require_empty_source_interval(
        body,
        assignment.end(),
        failure.condition.start(),
        f"{label} assignment-to-result-guard",
    )
    require_exact_statement_sequence(
        body,
        failure.statement_start,
        failure.statement_end,
        statement_pattern,
        f"{label} failure",
    )
    return failure


def check_projected_gem_create(body: str) -> None:
    """Prove GEM creation holds reader admission across every BO retry."""

    begin = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_rs4xx_hardware_access_begin\s*"
            r"\(\s*rdev\s*\)\s*;"
        ),
        "gem-create access admission",
    )
    retry_label = one_match_in_function(
        body,
        re.compile(r"(?m)^[ \t]*retry\s*:"),
        "gem-create retry label",
    )
    allocation = projected_labeled_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_bo_create\s*\(\s*rdev\s*,\s*size\s*,\s*"
            r"alignment\s*,\s*kernel\s*,\s*initial_domain\s*,\s*flags\s*,\s*"
            r"NULL\s*,\s*NULL\s*,\s*&robj\s*\)\s*;"
        ),
        "gem-create BO allocation",
    )
    out_label = one_match_in_function(
        body,
        re.compile(r"(?m)^[ \t]*out\s*:"),
        "gem-create release label",
    )
    end = projected_labeled_match(body, ACCESS_END, "gem-create access release")
    final_return = one_match_in_interval_at_depth(
        body,
        re.compile(r"\breturn\s+r\s*;"),
        end.end(),
        len(body),
        1,
        "gem-create final return",
    )
    require_direct_statement(
        body,
        body.find("{"),
        final_return.start(),
        "gem-create final return",
    )
    failure = require_projected_failure(
        body,
        begin,
        retry_label.start(),
        "r",
        r"\s*return\s+r\s*;\s*",
        "gem-create access admission",
    )
    if not (
        begin.start()
        < failure.condition.start()
        < failure.statement_end
        <= retry_label.start()
        < allocation.start()
        < out_label.start()
        < end.start()
        < final_return.start()
    ):
        raise GuardError("gem-create projected admission order differs")
    require_empty_source_interval(
        body,
        failure.statement_end,
        retry_label.start(),
        "gem-create admission-to-retry",
    )
    require_empty_source_interval(
        body,
        retry_label.end(),
        allocation.start(),
        "gem-create retry-label-to-allocation",
    )
    require_empty_source_interval(
        body,
        out_label.end(),
        end.start(),
        "gem-create out-label-to-release",
    )
    if re.search(r"\breturn\b", body[retry_label.start() : end.start()]):
        raise GuardError("gem-create admitted retry region returns before release")
    gotos = tuple(
        match.group(1)
        for match in re.finditer(
            r"\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
            body[retry_label.start() : end.start()],
        )
    )
    if gotos != ("retry", "out"):
        raise GuardError(f"gem-create admitted goto denominator differs: {gotos}")
    for identifier, count, label in (
        ("radeon_rs4xx_hardware_access_begin", 1, "access admission"),
        ("radeon_rs4xx_hardware_access_end", 1, "access release"),
        ("radeon_bo_create", 1, "BO allocation"),
    ):
        require_call_denominator(body, identifier, count, f"gem-create {label}")


def check_projected_prime_import(body: str) -> None:
    """Prove PRIME import balances helper admission around one reservation."""

    admission = projected_direct_match(
        body,
        re.compile(
            r"\bret\s*=\s*radeon_device_lock_hardware\s*"
            r"\(\s*rdev\s*\)\s*;"
        ),
        "prime-import helper admission",
    )
    reservation = projected_direct_match(
        body,
        re.compile(r"\bdma_resv_lock\s*\(\s*resv\s*,\s*NULL\s*\)\s*;"),
        "prime-import reservation lock",
    )
    failure = require_projected_failure(
        body,
        admission,
        reservation.start(),
        "ret",
        r"\s*return\s+ERR_PTR\s*\(\s*ret\s*\)\s*;\s*",
        "prime-import helper admission",
    )
    allocation = projected_direct_match(
        body,
        re.compile(
            r"\bret\s*=\s*radeon_bo_create\s*\(\s*rdev\s*,\s*"
            r"attach->dmabuf->size\s*,\s*PAGE_SIZE\s*,\s*false\s*,\s*"
            r"RADEON_GEM_DOMAIN_GTT\s*,\s*0\s*,\s*sg\s*,\s*resv\s*,\s*"
            r"&bo\s*\)\s*;"
        ),
        "prime-import allocation",
    )
    reservation_unlock = projected_direct_match(
        body,
        re.compile(r"\bdma_resv_unlock\s*\(\s*resv\s*\)\s*;"),
        "prime-import reservation unlock",
    )
    release = projected_direct_match(
        body,
        DEVICE_UNLOCK,
        "prime-import helper release",
    )
    result = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*ret\s*\)"),
        release.end(),
        len(body),
        "prime-import allocation result guard",
    )
    require_exact_statement_sequence(
        body,
        result.statement_start,
        result.statement_end,
        r"\s*return\s+ERR_PTR\s*\(\s*ret\s*\)\s*;\s*",
        "prime-import allocation failure",
    )
    if not (
        admission.start()
        < failure.condition.start()
        < failure.statement_end
        <= reservation.start()
        < allocation.start()
        < reservation_unlock.start()
        < release.start()
        < result.condition.start()
    ):
        raise GuardError("prime-import projected transaction order differs")
    if re.search(r"\breturn\b", body[failure.statement_end : release.start()]):
        raise GuardError("prime-import admitted transaction returns before release")
    if re.search(r"\bgoto\b", body[admission.start() : release.end()]):
        raise GuardError("prime-import projected transaction contains goto")
    for identifier, count, label in (
        ("radeon_device_lock_hardware", 1, "helper admission"),
        ("radeon_device_unlock_hardware", 1, "helper release"),
        ("dma_resv_lock", 1, "reservation lock"),
        ("dma_resv_unlock", 1, "reservation unlock"),
        ("radeon_bo_create", 1, "allocation"),
    ):
        require_call_denominator(body, identifier, count, f"prime-import {label}")


def check_projected_wait_idle(body: str) -> None:
    """Prove wait normalization precedes one admitted MMIO flush region."""

    wait = projected_direct_match(
        body,
        re.compile(
            r"\bret\s*=\s*dma_resv_wait_timeout\s*\(\s*"
            r"robj->tbo.base.resv\s*,\s*DMA_RESV_USAGE_READ\s*,\s*true\s*,\s*"
            r"30\s*\*\s*HZ\s*\)\s*;"
        ),
        "wait-idle-flush reservation wait",
    )
    admission = projected_direct_match(
        body,
        re.compile(
            r"\bhardware_result\s*=\s*radeon_device_lock_hardware\s*"
            r"\(\s*rdev\s*\)\s*;"
        ),
        "wait-idle-flush helper admission",
    )
    wait_failure = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        wait.end(),
        admission.start(),
        "wait-idle-flush wait result guard",
    )
    require_exact_statement_sequence(
        body,
        wait.end(),
        wait_failure.statement_end,
        r"\s*if\s*\(\s*ret\s*==\s*0\s*\)\s*r\s*=\s*-EBUSY\s*;\s*"
        r"else\s+if\s*\(\s*ret\s*<\s*0\s*\)\s*r\s*=\s*ret\s*;\s*"
        r"if\s*\(\s*r\s*\)\s*\{\s*"
        r"drm_gem_object_put\s*\(\s*gobj\s*\)\s*;\s*"
        r"return\s+r\s*;\s*\}\s*",
        "wait-idle-flush wait result normalization",
    )
    placement = projected_direct_match(
        body,
        re.compile(
            r"\bcur_placement\s*=\s*READ_ONCE\s*\(\s*"
            r"robj->tbo.resource->mem_type\s*\)\s*;"
        ),
        "wait-idle-flush placement read",
    )
    admission_failure = require_projected_failure(
        body,
        admission,
        placement.start(),
        "hardware_result",
        r"\s*\{\s*drm_gem_object_put\s*\(\s*gobj\s*\)\s*;\s*"
        r"return\s+hardware_result\s*;\s*\}\s*",
        "wait-idle-flush helper admission",
    )
    flush_condition = one_match_in_function(
        body,
        re.compile(
            r"\bif\s*\(\s*rdev->asic->mmio_hdp_flush\s*&&\s*"
            r"radeon_mem_type_to_domain\s*\(\s*cur_placement\s*\)\s*==\s*"
            r"RADEON_GEM_DOMAIN_VRAM\s*\)"
        ),
        "wait-idle-flush VRAM predicate",
    )
    flush_start, flush_end = controlled_statement(body, flush_condition.end())
    flush = one_match_in_interval_at_depth(
        body,
        re.compile(r"\brobj->rdev->asic->mmio_hdp_flush\s*\(\s*rdev\s*\)\s*;"),
        flush_start,
        flush_end,
        direct_statement_depth(body, flush_start),
        "wait-idle-flush MMIO call",
    )
    release = projected_direct_match(
        body,
        DEVICE_UNLOCK,
        "wait-idle-flush helper release",
    )
    final_return = projected_direct_match(
        body,
        re.compile(r"\breturn\s+0\s*;"),
        "wait-idle-flush final return",
    )
    if not (
        wait.start()
        < wait_failure.condition.start()
        < wait_failure.statement_end
        <= admission.start()
        < admission_failure.condition.start()
        < admission_failure.statement_end
        <= placement.start()
        < flush_condition.start()
        < flush.start()
        < release.start()
        < final_return.start()
    ):
        raise GuardError("wait-idle-flush projected transaction order differs")
    if re.search(
        r"\breturn\b", body[admission_failure.statement_end : release.start()]
    ):
        raise GuardError("wait-idle-flush admitted region returns before release")
    if re.search(r"\bgoto\b", body[wait.start() : release.end()]):
        raise GuardError("wait-idle-flush projected transaction contains goto")
    require_exact_statement_sequence(
        body,
        release.end(),
        len(body),
        r"\s*drm_gem_object_put\s*\(\s*gobj\s*\)\s*;\s*"
        r"return\s+0\s*;\s*\}\s*",
        "wait-idle-flush post-release cleanup",
    )
    for identifier, count, label in (
        ("dma_resv_wait_timeout", 1, "reservation wait"),
        ("radeon_device_lock_hardware", 1, "helper admission"),
        ("radeon_device_unlock_hardware", 1, "helper release"),
        ("mmio_hdp_flush", 1, "MMIO flush"),
    ):
        require_call_denominator(body, identifier, count, f"wait-idle-flush {label}")


def check_projected_dumb_create(body: str) -> None:
    """Prove dumb-create balances helper admission and forwards both failures."""

    admission = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_device_lock_hardware\s*"
            r"\(\s*rdev\s*\)\s*;"
        ),
        "dumb-create helper admission",
    )
    creator = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_gem_object_create\s*\(\s*rdev\s*,\s*"
            r"args->size\s*,\s*0\s*,\s*RADEON_GEM_DOMAIN_VRAM\s*,\s*0\s*,\s*"
            r"false\s*,\s*&gobj\s*\)\s*;"
        ),
        "dumb-create creator assignment",
    )
    admission_failure = require_projected_failure(
        body,
        admission,
        creator.start(),
        "r",
        r"\s*return\s+r\s*;\s*",
        "dumb-create helper admission",
    )
    release = projected_direct_match(body, DEVICE_UNLOCK, "dumb-create helper release")
    handle = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*drm_gem_handle_create\s*\(\s*file_priv\s*,\s*"
            r"gobj\s*,\s*&handle\s*\)\s*;"
        ),
        "dumb-create handle creation",
    )
    result = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        release.end(),
        handle.start(),
        "dumb-create creator result guard",
    )
    require_exact_statement_sequence(
        body,
        result.statement_start,
        result.statement_end,
        r"\s*return\s+r\s*;\s*",
        "dumb-create creator failure",
    )
    if not (
        admission.start()
        < admission_failure.condition.start()
        < admission_failure.statement_end
        <= creator.start()
        < release.start()
        < result.condition.start()
        < result.statement_end
        <= handle.start()
    ):
        raise GuardError("dumb-create projected transaction order differs")
    if re.search(
        r"\breturn\b", body[admission_failure.statement_end : release.start()]
    ):
        raise GuardError("dumb-create admitted region returns before release")
    if re.search(r"\bgoto\b", body[admission.start() : release.end()]):
        raise GuardError("dumb-create projected transaction contains goto")
    for identifier, count, label in (
        ("radeon_device_lock_hardware", 1, "helper admission"),
        ("radeon_device_unlock_hardware", 1, "helper release"),
        ("radeon_gem_object_create", 1, "creator"),
        ("drm_gem_handle_create", 1, "handle creation"),
    ):
        require_call_denominator(body, identifier, count, f"dumb-create {label}")


def find_projected_command_submission_topology(
    body: str,
) -> CommandSubmissionTopology:
    """Resolve the helper-owned command-submission source anchors."""

    function_open = body.find("{")
    lock = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_device_lock_hardware\s*"
            r"\(\s*rdev\s*\)\s*;"
        ),
        "command-submission helper admission",
    )
    acceleration = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*!\s*rdev->accel_working\s*\)"),
        lock.end(),
        len(body),
        "command-submission acceleration guard",
    )
    reset = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*rdev->in_reset\s*\)"),
        acceleration.statement_end,
        len(body),
        "command-submission reset guard",
    )
    parser_zero = projected_direct_match(
        body,
        re.compile(
            r"\bmemset\s*\(\s*&parser\s*,\s*0\s*,\s*"
            r"sizeof\s*\(\s*(?:parser|struct\s+radeon_cs_parser)\s*\)\s*\)\s*;"
        ),
        "command-submission parser zeroing",
    )
    parser_init = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_parser_init\s*"
            r"\(\s*&parser\s*,\s*data\s*\)\s*;"
        ),
        "command-submission parser initialization",
    )
    ib_fill = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_fill\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        "command-submission IB fill call",
    )
    relocations = one_match_in_function(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_parser_relocs\s*"
            r"\(\s*&parser\s*\)\s*;"
        ),
        "command-submission relocation call",
    )
    trace = projected_direct_match(
        body,
        re.compile(r"\btrace_radeon_cs\s*\(\s*&parser\s*\)\s*;"),
        "command-submission trace call",
    )
    ib_schedule = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_chunk\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        "command-submission non-VM IB schedule call",
    )
    ib_vm_schedule = projected_direct_match(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_vm_chunk\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        "command-submission VM IB schedule call",
    )
    out_label = one_match_in_function(
        body,
        re.compile(r"(?m)^[ \t]*out\s*:"),
        "command-submission out label",
    )
    final_unlock = one_match_at_depth(
        body,
        DEVICE_UNLOCK,
        1,
        "command-submission final helper release",
    )
    parser_failure = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        parser_init.end(),
        ib_fill.start(),
        "command-submission parser initialization failure guard",
    )
    relocation = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*!\s*r\s*\)"),
        ib_fill.end(),
        trace.start(),
        "command-submission relocation result guard",
    )
    validation_failure = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        relocation.statement_end,
        trace.start(),
        "command-submission validation failure guard",
    )
    ib_failure = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        ib_schedule.end(),
        ib_vm_schedule.start(),
        "command-submission non-VM result guard",
    )
    ib_vm_failure = projected_condition(
        body,
        re.compile(r"\bif\s*\(\s*r\s*\)"),
        ib_vm_schedule.end(),
        out_label.start(),
        "command-submission VM result guard",
    )
    fence_validation = projected_condition(
        body,
        re.compile(
            r"\bif\s*\(\s*!\s*list_empty\s*\(\s*&parser\.validated\s*\)\s*"
            r"&&\s*!\s*parser\.ib\.fence\s*\)"
        ),
        ib_vm_failure.statement_end,
        out_label.start(),
        "command-submission validated-BO fence guard",
    )
    final_return = one_match_in_interval_at_depth(
        body,
        re.compile(r"\breturn\s+r\s*;"),
        out_label.end(),
        len(body),
        1,
        "command-submission final return",
    )
    return CommandSubmissionTopology(
        function_open=function_open,
        lock=lock,
        acceleration=acceleration,
        reset=reset,
        parser_zero=parser_zero,
        parser_init=parser_init,
        parser_failure=parser_failure,
        ib_fill=ib_fill,
        relocation_stage=relocation,
        relocations=relocations,
        validation_failure=validation_failure,
        trace=trace,
        ib_schedule=ib_schedule,
        ib_failure=ib_failure,
        ib_vm_schedule=ib_vm_schedule,
        ib_vm_failure=ib_vm_failure,
        fence_validation=fence_validation,
        out_label=out_label,
        final_unlock=final_unlock,
        final_return=final_return,
    )


def check_projected_command_submission(body: str) -> None:
    """Prove helper-owned CS admission, validation, scheduling, and cleanup."""

    topology = find_projected_command_submission_topology(body)
    parked_matches = list(PARKED_GUARD.finditer(body))
    if len(parked_matches) != 1:
        raise GuardError(
            "command-submission projected path requires one direct parked guard"
        )
    parked = parked_matches[0]
    if brace_depth(body, parked.start()) != 1:
        raise GuardError("command-submission parked guard is outside direct scope")
    require_direct_statement(
        body,
        topology.function_open,
        parked.start(),
        "command-submission parked guard",
    )
    admission_failure = require_projected_failure(
        body,
        topology.lock,
        parked.start(),
        "r",
        r"\s*return\s+r\s*;\s*",
        "command-submission helper admission",
    )
    require_exact_statement_sequence(
        body,
        topology.function_open,
        topology.lock.end(),
        r"\{\s*"
        r"struct\s+radeon_device\s*\*\s*rdev\s*=\s*dev->dev_private\s*;\s*"
        r"struct\s+radeon_cs_parser\s+parser\s*;\s*"
        r"int\s+r\s*;\s*"
        r"r\s*=\s*radeon_device_lock_hardware\s*\(\s*rdev\s*\)\s*;\s*",
        "command-submission declaration and helper-admission prefix",
    )
    require_empty_source_interval(
        body,
        admission_failure.statement_end,
        parked.start(),
        "command-submission admission-to-parked-guard",
    )
    parked_statement = controlled_match(body, parked)
    require_exact_statement_sequence(
        body,
        parked_statement.statement_start,
        parked_statement.statement_end,
        r"\s*\{\s*radeon_device_unlock_hardware\s*\(\s*rdev\s*\)\s*;\s*"
        r"(?:dev_err_once\s*\(\s*rdev->dev\s*,\s*\)\s*;\s*)?"
        r"return\s+-EIO\s*;\s*\}\s*",
        "command-submission parked refusal",
    )
    require_exact_statement_sequence(
        body,
        topology.acceleration.statement_start,
        topology.acceleration.statement_end,
        r"\s*\{\s*radeon_device_unlock_hardware\s*\(\s*rdev\s*\)\s*;\s*"
        r"return\s+-EBUSY\s*;\s*\}\s*",
        "command-submission acceleration refusal",
    )
    require_exact_statement_sequence(
        body,
        topology.reset.statement_start,
        topology.reset.statement_end,
        r"\s*\{\s*radeon_device_unlock_hardware\s*\(\s*rdev\s*\)\s*;\s*"
        r"r\s*=\s*radeon_gpu_reset\s*\(\s*rdev\s*\)\s*;\s*"
        r"if\s*\(\s*!\s*r\s*\)\s*r\s*=\s*-EAGAIN\s*;\s*"
        r"return\s+r\s*;\s*\}\s*",
        "command-submission reset transaction",
    )
    require_exact_statement_sequence(
        body,
        topology.parser_zero.start(),
        topology.parser_init.end(),
        r"\s*memset\s*\(\s*&parser\s*,\s*0\s*,\s*"
        r"sizeof\s*\(\s*(?:parser|struct\s+radeon_cs_parser)\s*\)\s*\)\s*;\s*"
        r"parser\.filp\s*=\s*filp\s*;\s*"
        r"parser\.rdev\s*=\s*rdev\s*;\s*"
        r"parser\.dev\s*=\s*rdev->dev\s*;\s*"
        r"parser\.family\s*=\s*rdev->family\s*;\s*"
        r"r\s*=\s*radeon_cs_parser_init\s*\(\s*&parser\s*,\s*data\s*\)\s*;\s*",
        "command-submission parser initialization prefix",
    )
    require_empty_source_interval(
        body,
        topology.parser_init.end(),
        topology.parser_failure.condition.start(),
        "command-submission parser-init-to-failure-guard",
    )
    cleanup_pattern = (
        r"radeon_cs_parser_release_reservations\s*\(\s*&parser\s*,\s*r\s*\)\s*;\s*"
        r"radeon_device_unlock_hardware\s*\(\s*rdev\s*\)\s*;\s*"
        r"radeon_cs_parser_release_storage\s*\(\s*&parser\s*\)\s*;\s*"
        r"r\s*=\s*radeon_cs_handle_lockup\s*\(\s*rdev\s*,\s*r\s*\)\s*;\s*"
        r"return\s+r\s*;"
    )
    require_exact_statement_sequence(
        body,
        topology.parser_failure.statement_start,
        topology.parser_failure.statement_end,
        r"\s*\{\s*DRM_ERROR\s*\(\s*\)\s*;\s*" + cleanup_pattern + r"\s*\}\s*",
        "command-submission parser initialization failure",
    )
    require_exact_statement_sequence(
        body,
        topology.relocation_stage.statement_start,
        topology.relocation_stage.statement_end,
        r"\s*\{\s*r\s*=\s*radeon_cs_parser_relocs\s*"
        r"\(\s*&parser\s*\)\s*;\s*"
        r"if\s*\(\s*r\s*&&\s*r\s*!=\s*-ERESTARTSYS\s*\)\s*"
        r"DRM_ERROR\s*\(\s*,\s*r\s*\)\s*;\s*\}\s*",
        "command-submission relocation success stage",
    )
    require_empty_source_interval(
        body,
        topology.relocation_stage.statement_end,
        topology.validation_failure.condition.start(),
        "command-submission relocation-to-failure-guard",
    )
    require_exact_statement_sequence(
        body,
        topology.validation_failure.statement_start,
        topology.validation_failure.statement_end,
        r"\s*\{\s*" + cleanup_pattern + r"\s*\}\s*",
        "command-submission validation failure",
    )
    for failure, label in (
        (topology.ib_failure, "non-VM"),
        (topology.ib_vm_failure, "VM"),
    ):
        require_exact_statement_sequence(
            body,
            failure.statement_start,
            failure.statement_end,
            r"\s*\{\s*goto\s+out\s*;\s*\}\s*",
            f"command-submission {label} failure edge",
        )
    require_exact_statement_sequence(
        body,
        topology.fence_validation.statement_start,
        topology.fence_validation.statement_end,
        r"\s*\{\s*DRM_ERROR\s*\(\s*\)\s*;\s*r\s*=\s*-EINVAL\s*;\s*\}\s*",
        "command-submission validated-BO fence failure",
    )
    require_exact_statement_sequence(
        body,
        topology.out_label.start(),
        topology.final_return.end(),
        r"\s*out\s*:\s*" + cleanup_pattern + r"\s*",
        "command-submission final cleanup",
    )
    if not (
        topology.lock.start()
        < admission_failure.condition.start()
        < admission_failure.statement_end
        <= parked.start()
        < parked_statement.statement_end
        <= topology.acceleration.condition.start()
        < topology.reset.condition.start()
        < topology.parser_zero.start()
        < topology.parser_init.start()
        < topology.parser_failure.condition.start()
        < topology.ib_fill.start()
        < topology.relocation_stage.condition.start()
        < topology.relocations.start()
        < topology.validation_failure.condition.start()
        < topology.trace.start()
        < topology.ib_schedule.start()
        < topology.ib_failure.condition.start()
        < topology.ib_vm_schedule.start()
        < topology.ib_vm_failure.condition.start()
        < topology.fence_validation.condition.start()
        < topology.out_label.start()
        < topology.final_unlock.start()
        < topology.final_return.start()
    ):
        raise GuardError("command-submission projected stage order differs")

    controlled_regions = (
        parked_statement,
        topology.acceleration,
        topology.reset,
        topology.parser_failure,
        topology.validation_failure,
    )
    unlock_offsets = []
    return_offsets = [
        one_match_in_interval_at_depth(
            body,
            re.compile(r"\breturn\s+r\s*;"),
            admission_failure.statement_start,
            admission_failure.statement_end,
            direct_statement_depth(body, admission_failure.statement_start),
            "command-submission admission failure return",
        ).start()
    ]
    for region, label in zip(
        controlled_regions,
        ("parked", "acceleration", "reset", "parser", "validation"),
        strict=True,
    ):
        unlock_offsets.append(
            one_match_in_interval_at_depth(
                body,
                DEVICE_UNLOCK,
                region.statement_start,
                region.statement_end,
                direct_statement_depth(body, region.statement_start),
                f"command-submission {label} helper release",
            ).start()
        )
        return_offsets.append(
            one_match_in_interval_at_depth(
                body,
                re.compile(r"\breturn\b"),
                region.statement_start,
                region.statement_end,
                direct_statement_depth(body, region.statement_start),
                f"command-submission {label} return",
            ).start()
        )
    unlock_offsets.append(topology.final_unlock.start())
    return_offsets.append(topology.final_return.start())
    require_exact_match_offsets(
        body,
        DEVICE_UNLOCK,
        unlock_offsets,
        "command-submission helper release",
    )
    require_exact_match_offsets(
        body,
        re.compile(r"\breturn\b"),
        return_offsets,
        "command-submission return",
    )
    goto_offsets = [
        one_match_in_interval_at_depth(
            body,
            re.compile(r"\bgoto\s+out\s*;"),
            region.statement_start,
            region.statement_end,
            direct_statement_depth(body, region.statement_start),
            f"command-submission {label} goto",
        ).start()
        for region, label in (
            (topology.ib_failure, "non-VM"),
            (topology.ib_vm_failure, "VM"),
        )
    ]
    require_exact_match_offsets(
        body,
        re.compile(r"\bgoto\b"),
        goto_offsets,
        "command-submission goto",
    )
    for identifier, count, label in (
        ("radeon_device_lock_hardware", 1, "helper admission"),
        ("radeon_device_unlock_hardware", 6, "helper release"),
        ("radeon_gpu_reset", 1, "reset"),
        ("radeon_cs_parser_init", 1, "parser initialization"),
        ("radeon_cs_ib_fill", 1, "IB fill"),
        ("radeon_cs_parser_relocs", 1, "relocation"),
        ("trace_radeon_cs", 1, "trace"),
        ("radeon_cs_ib_chunk", 1, "non-VM schedule"),
        ("radeon_cs_ib_vm_chunk", 1, "VM schedule"),
        ("radeon_cs_parser_release_reservations", 3, "reservation release"),
        ("radeon_cs_parser_release_storage", 3, "storage release"),
        ("radeon_cs_handle_lockup", 3, "lockup translation"),
        ("radeon_ib_get", 0, "early IB allocation"),
    ):
        require_call_denominator(
            body,
            identifier,
            count,
            f"command-submission {label}",
        )


def check_projected_guard(body: str, guard: dict[str, str]) -> None:
    """Dispatch one centralized-helper entrypoint proof."""

    if guard["id"] == "gem-create":
        check_projected_gem_create(body)
    elif guard["id"] == "prime-import":
        check_projected_prime_import(body)
    elif guard["id"] == "wait-idle-flush":
        check_projected_wait_idle(body)
    elif guard["id"] == "command-submission":
        check_projected_command_submission(body)
    else:
        raise GuardError(f"unsupported projected guard {guard['id']}")


def check_guard(
    root: Path,
    guard: dict[str, str],
    *,
    validate_helpers: bool = True,
) -> None:
    """Prove one legacy direct guard or centralized-helper projection."""

    path = root / guard["path"]
    try:
        source = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise GuardError(f"{guard['id']}: missing source {path}") from exc
    body = function_code(source, guard["function"], PARKED_PROTECTED_MACROS)
    projected = re.search(
        r"\b(?:radeon_device_lock_hardware|"
        r"radeon_rs4xx_hardware_access_begin)\s*\(",
        body,
    )
    if projected is None:
        check_legacy_guard(root, guard)
        return
    reject_conditional_directives(body, guard["id"])
    if validate_helpers:
        try:
            centralized_admission.check_contract(root)
        except centralized_admission.GuardError as exc:
            raise GuardError(f"centralized admission contract: {exc}") from exc
    check_projected_guard(body, guard)


def check_dumb_create_propagation(
    root: Path,
    *,
    validate_helpers: bool = True,
) -> None:
    """Prove the legacy direct lock or centralized helper at dumb-create."""

    path = root / SUBTREE / "radeon_gem.c"
    try:
        source = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise GuardError(f"dumb-create: missing source {path}") from exc
    body = function_code(
        source,
        "radeon_mode_dumb_create",
        DUMB_CREATE_PROTECTED_MACROS + PARKED_PROTECTED_MACROS,
    )
    if re.search(r"\bradeon_device_lock_hardware\s*\(", body) is None:
        check_legacy_dumb_create_propagation(root)
        return
    reject_conditional_directives(body, "dumb-create")
    if validate_helpers:
        try:
            centralized_admission.check_contract(root)
        except centralized_admission.GuardError as exc:
            raise GuardError(f"centralized admission contract: {exc}") from exc
    check_projected_dumb_create(body)


GEM_FIXTURE_OPEN = "int radeon_gem_object_create(struct radeon_device *rdev)\n{\n"
GEM_FIXTURE_PREFIX = (
    "int radeon_gem_object_create(struct radeon_device *rdev,\n"
    "\t\t\t     struct drm_gem_object **obj)\n"
    "{\n"
    "\tstruct radeon_bo *robj;\n"
    "\tunsigned long max_size;\n"
    "\tint r;\n\n"
    "\t*obj = NULL;\n"
)


def complete_gem_fixture(fixture: str) -> str:
    """Give every GEM fixture the exact audited entry prefix."""
    if GEM_FIXTURE_OPEN not in fixture:
        raise GuardError("GEM fixture has no recognized function opening")
    return fixture.replace(GEM_FIXTURE_OPEN, GEM_FIXTURE_PREFIX)


FIXTURE_GOOD = """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
"""

FIXTURES_BAD = {
    "infinite loop precedes the parked guard": FIXTURE_GOOD.replace(
        "\tif (READ_ONCE(rdev->gpu_parked))",
        "\tfor (;;)\n\t\t;\n\tif (READ_ONCE(rdev->gpu_parked))",
        1,
    ),
    "opaque terminator precedes the parked guard": FIXTURE_GOOD.replace(
        "\tif (READ_ONCE(rdev->gpu_parked))",
        "\tBUG();\n\tif (READ_ONCE(rdev->gpu_parked))",
        1,
    ),
    "declaration expression exits before the parked guard": FIXTURE_GOOD.replace(
        "\tif (READ_ONCE(rdev->gpu_parked))",
        "\tint prefix_result = ({ return 0; 0; });\n\tif (READ_ONCE(rdev->gpu_parked))",
        1,
    ),
    "disabled function precedes an active unguarded definition": (
        "#if 0\n"
        + FIXTURE_GOOD
        + "#else\n"
        + "int radeon_gem_object_create(struct radeon_device *rdev)\n"
        + "{\n"
        + "\tr = radeon_bo_create(rdev);\n"
        + "\treturn 0;\n"
        + "}\n"
        + "#endif\n"
    ),
    "translation unit overrides READ_ONCE": (
        "#undef READ_ONCE\n#define READ_ONCE(value) 0\n" + FIXTURE_GOOD
    ),
    "digraph conditional selects an active unguarded definition": (
        "%:if 0\n"
        + FIXTURE_GOOD
        + "%:else\n"
        + "int radeon_gem_object_create(struct radeon_device *rdev)\n"
        + "{\n"
        + "\tr = radeon_bo_create(rdev);\n"
        + "\treturn 0;\n"
        + "}\n"
        + "%:endif\n"
    ),
    "form-feed conditional selects an active unguarded definition": (
        "#\fif 0\n"
        + FIXTURE_GOOD
        + "#\felse\n"
        + "int radeon_gem_object_create(struct radeon_device *rdev)\n"
        + "{\n"
        + "\tr = radeon_bo_create(rdev);\n"
        + "\treturn 0;\n"
        + "}\n"
        + "#\fendif\n"
    ),
    "translation unit uses a digraph READ_ONCE override": (
        "%:undef READ_ONCE\n%:define READ_ONCE(value) 0\n" + FIXTURE_GOOD
    ),
    "translation unit redirects the gpu_parked member": (
        "#undef gpu_parked\n#define gpu_parked needs_reset\n" + FIXTURE_GOOD
    ),
    "continued line comment hides the guard": (
        "int radeon_gem_object_create(struct radeon_device *rdev)\n"
        "{\n"
        "\t// continued comment \\\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) \\\n"
        "\t\treturn -EIO;\n"
        "\tr = radeon_bo_create(rdev);\n"
        "\treturn 0;\n"
        "}\n"
    ),
    "guard polarity inverted": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (!READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard removed": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard after the allocation": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tr = radeon_bo_create(rdev);
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\treturn 0;
}
""",
    "success return precedes the parked guard": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\treturn 0;
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard reads needs_reset": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (READ_ONCE(rdev->gpu_parked) && rdev->needs_reset)
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard condition is always false": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (false && READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard is nested in an unreachable block": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (false) {
\t\tif (READ_ONCE(rdev->gpu_parked))
\t\t\treturn -EIO;
\t}
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard is controlled by an unbraced unreachable condition": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
	if (false)
		if (READ_ONCE(rdev->gpu_parked))
			return -EIO;
	r = radeon_bo_create(rdev);
	return 0;
}
""",
    "guard is disabled by a preprocessor conditional": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
#if 0
	if (READ_ONCE(rdev->gpu_parked))
		return -EIO;
#endif
	r = radeon_bo_create(rdev);
	return 0;
}
""",
    "guard is hidden by a null-boundary preprocessor conditional": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
#if 0
	;
	if (READ_ONCE(rdev->gpu_parked))
		return -EIO;
#endif
	;
	r = radeon_bo_create(rdev);
	return 0;
}
""",
    "forward goto bypasses the guard": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tgoto bypass_parked_refusal;
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
bypass_parked_refusal:
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard returns zero": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn 0;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard returns -EDEADLK": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EDEADLK;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "guard conditional on a VRAM request": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (READ_ONCE(rdev->gpu_parked) && initial_domain == RADEON_GEM_DOMAIN_VRAM)
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
""",
    "allocation call absent": """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\treturn 0;
}
""",
    "allocation name is not called": FIXTURE_GOOD.replace(
        "\tr = radeon_bo_create(rdev);",
        "\t(void)radeon_bo_create;\n\tr = -ENOMEM;",
        1,
    ),
}

DUMB_FIXTURE_GOOD = """
int radeon_mode_dumb_create(struct drm_file *file_priv,
\t\t\t    struct drm_device *dev,
\t\t\t    struct drm_mode_create_dumb *args)
{
\tstruct radeon_device *rdev = dev->dev_private;
\tstruct drm_gem_object *gobj;
\tuint32_t handle;
\tint r;

\targs->pitch = radeon_align_pitch(rdev, args->width,
\t\t\t\t\t DIV_ROUND_UP(args->bpp, 8), 0);
\targs->size = (u64)args->pitch * args->height;
\targs->size = ALIGN(args->size, PAGE_SIZE);

\tdown_read(&rdev->exclusive_lock);
\tr = radeon_gem_object_create(rdev, args->size, 0,
\t\t\t\t     RADEON_GEM_DOMAIN_VRAM, 0,
\t\t\t\t     false, &gobj);
\tup_read(&rdev->exclusive_lock);
\tif (r)
\t\treturn r;
\tr = drm_gem_handle_create(file_priv, gobj, &handle);
\treturn 0;
}
"""

DUMB_FIXTURES_BAD = {
    "success return precedes the read lock": DUMB_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\treturn 0;\n\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "conditional success return precedes the read lock": DUMB_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (rdev)\n\t\treturn 0;\n\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "infinite loop precedes the read lock": DUMB_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tfor (;;)\n\t\t;\n\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "opaque terminator precedes the read lock": DUMB_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tBUG();\n\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "declaration expression exits before the read lock": DUMB_FIXTURE_GOOD.replace(
        "\tint r;",
        "\tint r = ({ return 0; 0; });",
        1,
    ),
    "result guard controlled by an unbraced unreachable condition": (
        DUMB_FIXTURE_GOOD.replace(
            "\tif (r)\n\t\treturn r;",
            "\tif (false)\n\t\tif (r)\n\t\t\treturn r;",
            1,
        )
    ),
    "failure return nested in an unreachable block": DUMB_FIXTURE_GOOD.replace(
        "\tif (r)\n\t\treturn r;",
        "\tif (r) {\n\t\tif (false)\n\t\t\treturn r;\n\t}",
        1,
    ),
    "failure translated to -ENOMEM": DUMB_FIXTURE_GOOD.replace(
        "\t\treturn r;",
        "\t\treturn -ENOMEM;",
        1,
    ),
    "failure translated to another errno": DUMB_FIXTURE_GOOD.replace(
        "\t\treturn r;",
        "\t\treturn -EINVAL;",
        1,
    ),
    "failure answered with success": DUMB_FIXTURE_GOOD.replace(
        "\t\treturn r;",
        "\t\treturn 0;",
        1,
    ),
    "failure never tested": DUMB_FIXTURE_GOOD.replace(
        "\tif (r)\n\t\treturn r;\n",
        "",
        1,
    ),
    "creator result is clobbered before its guard": DUMB_FIXTURE_GOOD.replace(
        "\tup_read(&rdev->exclusive_lock);\n\tif (r)",
        "\tup_read(&rdev->exclusive_lock);\n\tr = 0;\n\tif (r)",
        1,
    ),
    "creator result is clobbered before the read unlock": DUMB_FIXTURE_GOOD.replace(
        "\tup_read(&rdev->exclusive_lock);",
        "\tr = 0;\n\tup_read(&rdev->exclusive_lock);",
        1,
    ),
    "complete transaction is inside an unreachable digraph block": (
        DUMB_FIXTURE_GOOD.replace(
            "\tdown_read(&rdev->exclusive_lock);",
            "\tif (false) <%\n\t\t;\n\tdown_read(&rdev->exclusive_lock);",
            1,
        ).replace(
            "\tif (r)\n\t\treturn r;",
            "\tif (r)\n\t\treturn r;\n\t%>",
            1,
        )
    ),
}

PRIME_FIXTURE_GOOD = """
struct drm_gem_object *radeon_gem_prime_import_sg_table(struct drm_device *dev)
{
\tstruct dma_resv *resv = attach->dmabuf->resv;
\tstruct radeon_device *rdev = dev->dev_private;
\tstruct radeon_bo *bo;
\tint ret;
\tdown_read(&rdev->exclusive_lock);
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn ERR_PTR(-EIO);
\t}
\tdma_resv_lock(resv, NULL);
\tret = radeon_bo_create(rdev, attach->dmabuf->size, PAGE_SIZE, false,
\t\t\t       RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo);
\tdma_resv_unlock(resv);
\tup_read(&rdev->exclusive_lock);
\tif (ret)
\t\treturn ERR_PTR(ret);
\treturn &bo->tbo.base;
}
"""

PRIME_FIXTURE_MUTATIONS = {
    "translation unit overrides up_read": (
        "struct drm_gem_object *radeon_gem_prime_import_sg_table",
        "#undef up_read\n"
        "#define up_read(lock) do { } while (0)\n"
        "struct drm_gem_object *radeon_gem_prime_import_sg_table",
    ),
    "guard polarity inverted": (
        "if (READ_ONCE(rdev->gpu_parked))",
        "if (!READ_ONCE(rdev->gpu_parked))",
    ),
    "guard condition is always false": (
        "if (READ_ONCE(rdev->gpu_parked))",
        "if (false && READ_ONCE(rdev->gpu_parked))",
    ),
    "read lock removed": (
        "\tdown_read(&rdev->exclusive_lock);",
        "\tremoved_down_read();",
    ),
    "read lock is controlled by an unreachable condition": (
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (false)\n\t\tdown_read(&rdev->exclusive_lock);",
    ),
    "guard unlock removed": (
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn ERR_PTR(-EIO);",
        "\t\treturn ERR_PTR(-EIO);",
    ),
    "guard unlock is nested in an unreachable block": (
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn ERR_PTR(-EIO);",
        (
            "\t\tif (false) {\n"
            "\t\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\t}\n"
            "\t\treturn ERR_PTR(-EIO);"
        ),
    ),
    "guard unlock is conditional without braces": (
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn ERR_PTR(-EIO);",
        (
            "\t\tif (false)\n"
            "\t\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\treturn ERR_PTR(-EIO);"
        ),
    ),
    "guard goto skips the unlock": (
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn ERR_PTR(-EIO);",
        (
            "\t\tgoto after_unlock;\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "after_unlock:\n"
            "\t\t;\n"
            "\t\treturn ERR_PTR(-EIO);"
        ),
    ),
    "guard loops before the unlock": (
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn ERR_PTR(-EIO);",
        (
            "\t\tfor (;;)\n"
            "\t\t\t;\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\treturn ERR_PTR(-EIO);"
        ),
    ),
    "guard unlock is disabled by preprocessing": (
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn ERR_PTR(-EIO);",
        (
            "\t\t;\n"
            "#if 0\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "#endif\n"
            "\t\t;\n"
            "\t\treturn ERR_PTR(-EIO);"
        ),
    ),
    "exclusive lock released before guard": (
        "\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked))",
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tup_read(&rdev->exclusive_lock);\n"
            "\tif (READ_ONCE(rdev->gpu_parked))"
        ),
    ),
    "nested read unlock precedes guard": (
        "\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked))",
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tif (false) {\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "\t}\n"
            "\tif (READ_ONCE(rdev->gpu_parked))"
        ),
    ),
    "parked errno changed": (
        "return ERR_PTR(-EIO);",
        "return ERR_PTR(-EBUSY);",
    ),
    "reservation lock moved before guard": (
        ("\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked))"),
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tdma_resv_lock(resv, NULL);\n"
            "\tif (READ_ONCE(rdev->gpu_parked))"
        ),
    ),
    "reservation lock is nested in an unreachable block": (
        "\tdma_resv_lock(resv, NULL);",
        "\tif (false) {\n\t\tdma_resv_lock(resv, NULL);\n\t}",
    ),
    "reservation lock is controlled by an unreachable condition": (
        "\tdma_resv_lock(resv, NULL);",
        "\tif (false)\n\t\tdma_resv_lock(resv, NULL);",
    ),
    "allocation is controlled by an unreachable condition": (
        "\tret = radeon_bo_create(rdev, attach->dmabuf->size, PAGE_SIZE, false,\n"
        "\t\t\t       RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo);",
        "\tif (false)\n"
        "\t\tret = radeon_bo_create(rdev, attach->dmabuf->size, PAGE_SIZE, false,\n"
        "\t\t\t\t       RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo);",
    ),
    "reservation unlock is controlled by an unreachable condition": (
        "\tdma_resv_unlock(resv);",
        "\tif (false)\n\t\tdma_resv_unlock(resv);",
    ),
    "final read unlock is controlled by an unreachable condition": (
        "\tup_read(&rdev->exclusive_lock);\n\tif (ret)",
        "\tif (false)\n\t\tup_read(&rdev->exclusive_lock);\n\tif (ret)",
    ),
    "reservation initializer is detached from the dma-buf": (
        "\tstruct dma_resv *resv = attach->dmabuf->resv;",
        "\tstruct dma_resv *resv = NULL;",
    ),
    "reservation is reassigned before the read lock": (
        "\tint ret;\n\tdown_read(&rdev->exclusive_lock);",
        "\tint ret;\n\tresv = NULL;\n\tdown_read(&rdev->exclusive_lock);",
    ),
    "success return follows the read lock": (
        "\tdown_read(&rdev->exclusive_lock);",
        "\tdown_read(&rdev->exclusive_lock);\n\treturn NULL;",
    ),
    "infinite loop follows the read lock": (
        "\tdown_read(&rdev->exclusive_lock);",
        "\tdown_read(&rdev->exclusive_lock);\n\tfor (;;)\n\t\t;",
    ),
    "success return follows the reservation lock": (
        "\tdma_resv_lock(resv, NULL);",
        "\tdma_resv_lock(resv, NULL);\n\treturn NULL;",
    ),
    "allocation uses a different reservation": (
        "RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo);",
        "RADEON_GEM_DOMAIN_GTT, 0, sg, NULL, &bo);",
    ),
    "reservation lock uses a different reservation": (
        "\tdma_resv_lock(resv, NULL);",
        "\tdma_resv_lock(NULL, NULL);",
    ),
    "reservation unlock uses a different reservation": (
        "\tdma_resv_unlock(resv);",
        "\tdma_resv_unlock(NULL);",
    ),
    "nested extra reservation unlock precedes allocation": (
        "\tdma_resv_lock(resv, NULL);",
        "\tdma_resv_lock(resv, NULL);\n\tif (false) {\n\t\tdma_resv_unlock(resv);\n\t}",
    ),
    "allocation result is clobbered before its guard": (
        "\tup_read(&rdev->exclusive_lock);\n\tif (ret)",
        "\tup_read(&rdev->exclusive_lock);\n\tret = 0;\n\tif (ret)",
    ),
    "allocation failure predicate is always false": (
        "\tif (ret)\n\t\treturn ERR_PTR(ret);",
        "\tif (false && ret)\n\t\treturn ERR_PTR(ret);",
    ),
    "complete transaction is inside an unreachable digraph block": (
        PRIME_FIXTURE_GOOD,
        PRIME_FIXTURE_GOOD.replace(
            "\tdown_read(&rdev->exclusive_lock);",
            "\tif (false) <%\n\t\t;\n\tdown_read(&rdev->exclusive_lock);",
            1,
        ).replace(
            "\tif (ret)\n\t\treturn ERR_PTR(ret);",
            "\tif (ret)\n\t\treturn ERR_PTR(ret);\n\t%>",
            1,
        ),
    ),
}

WAIT_FIXTURE_GOOD = """
int radeon_gem_wait_idle_ioctl(struct drm_device *dev, void *data,
\t\t\t      struct drm_file *filp)
{
\tstruct radeon_device *rdev = dev->dev_private;
\tstruct drm_radeon_gem_wait_idle *args = data;
\tstruct drm_gem_object *gobj;
\tstruct radeon_bo *robj;
\tint r = 0;
\tuint32_t cur_placement = 0;
\tlong ret;

\tgobj = drm_gem_object_lookup(filp, args->handle);
\tif (gobj == NULL) {
\t\treturn -ENOENT;
\t}
\trobj = gem_to_radeon_bo(gobj);

\tret = dma_resv_wait_timeout(robj->tbo.base.resv, DMA_RESV_USAGE_READ,
\t\t\t\t    true, 30 * HZ);
\tif (ret == 0)
\t\tr = -EBUSY;
\telse if (ret < 0)
\t\tr = ret;
\tdown_read(&rdev->exclusive_lock);
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\tdrm_gem_object_put(gobj);
\t\treturn -EIO;
\t}
\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);
\tif (rdev->asic->mmio_hdp_flush &&
\t    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)
\t\trobj->rdev->asic->mmio_hdp_flush(rdev);
\tup_read(&rdev->exclusive_lock);
\tdrm_gem_object_put(gobj);
\tr = radeon_gem_handle_lockup(rdev, r);
\treturn r;
}
"""

WAIT_FIXTURE_MUTATIONS = {
    "success result initializer is nonzero": (
        "\tint r = 0;",
        "\tint r = -EIO;",
    ),
    "success result is uninitialized": (
        "\tint r = 0;",
        "\tint r;",
    ),
    "success result is clobbered before the wait": (
        "\trobj = gem_to_radeon_bo(gobj);",
        "\trobj = gem_to_radeon_bo(gobj);\n\tr = -EIO;",
    ),
    "success return precedes the reservation wait": (
        "\tret = dma_resv_wait_timeout",
        "\treturn 0;\n\tret = dma_resv_wait_timeout",
    ),
    "infinite loop precedes the reservation wait": (
        "\tret = dma_resv_wait_timeout",
        "\tfor (;;)\n\t\t;\n\tret = dma_resv_wait_timeout",
    ),
    "declaration expression exits before the reservation wait": (
        "\tint r = 0;",
        "\tint r = ({ return 0; 0; });",
    ),
    "guard polarity inverted": (
        "if (READ_ONCE(rdev->gpu_parked))",
        "if (!READ_ONCE(rdev->gpu_parked))",
    ),
    "guard condition is always false": (
        "if (READ_ONCE(rdev->gpu_parked))",
        "if (false && READ_ONCE(rdev->gpu_parked))",
    ),
    "reservation wait moved under exclusive lock": (
        (
            "\tret = dma_resv_wait_timeout(robj->tbo.base.resv, "
            "DMA_RESV_USAGE_READ,\n"
            "\t\t\t\t    true, 30 * HZ);\n"
            "\tif (ret == 0)\n"
            "\t\tr = -EBUSY;\n"
            "\telse if (ret < 0)\n"
            "\t\tr = ret;\n"
            "\tdown_read(&rdev->exclusive_lock);"
        ),
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tret = dma_resv_wait_timeout(robj->tbo.base.resv, "
            "DMA_RESV_USAGE_READ,\n"
            "\t\t\t\t    true, 30 * HZ);\n"
            "\tif (ret == 0)\n"
            "\t\tr = -EBUSY;\n"
            "\telse if (ret < 0)\n"
            "\t\tr = ret;"
        ),
    ),
    "read lock is controlled by an unreachable condition": (
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (false)\n\t\tdown_read(&rdev->exclusive_lock);",
    ),
    "guard unlock removed": (
        ("\t\tup_read(&rdev->exclusive_lock);\n\t\tdrm_gem_object_put(gobj);"),
        "\t\tdrm_gem_object_put(gobj);",
    ),
    "guard unlock is nested in an unreachable block": (
        ("\t\tup_read(&rdev->exclusive_lock);\n\t\tdrm_gem_object_put(gobj);"),
        (
            "\t\tif (false) {\n"
            "\t\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\t}\n"
            "\t\tdrm_gem_object_put(gobj);"
        ),
    ),
    "guard unlock is conditional without braces": (
        ("\t\tup_read(&rdev->exclusive_lock);\n\t\tdrm_gem_object_put(gobj);"),
        (
            "\t\tif (false)\n"
            "\t\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\tdrm_gem_object_put(gobj);"
        ),
    ),
    "guard goto skips the unlock": (
        ("\t\tup_read(&rdev->exclusive_lock);\n\t\tdrm_gem_object_put(gobj);"),
        (
            "\t\tgoto after_unlock;\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "after_unlock:\n"
            "\t\t;\n"
            "\t\tdrm_gem_object_put(gobj);"
        ),
    ),
    "guard loops before the unlock": (
        ("\t\tup_read(&rdev->exclusive_lock);\n\t\tdrm_gem_object_put(gobj);"),
        (
            "\t\tfor (;;)\n"
            "\t\t\t;\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\tdrm_gem_object_put(gobj);"
        ),
    ),
    "exclusive lock released before guard": (
        "\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked))",
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tup_read(&rdev->exclusive_lock);\n"
            "\tif (READ_ONCE(rdev->gpu_parked))"
        ),
    ),
    "nested read unlock precedes guard": (
        "\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked))",
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tif (false) {\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "\t}\n"
            "\tif (READ_ONCE(rdev->gpu_parked))"
        ),
    ),
    "parked errno changed": ("\t\treturn -EIO;", "\t\treturn -EBUSY;"),
    "placement read is nested in an unreachable block": (
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
        (
            "\tif (false) {\n"
            "\t\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);\n"
            "\t}"
        ),
    ),
    "reservation wait is controlled by an unreachable condition": (
        "\tret = dma_resv_wait_timeout(robj->tbo.base.resv, "
        "DMA_RESV_USAGE_READ,\n"
        "\t\t\t\t    true, 30 * HZ);",
        "\tif (false)\n"
        "\t\tret = dma_resv_wait_timeout(robj->tbo.base.resv, "
        "DMA_RESV_USAGE_READ,\n"
        "\t\t\t\t\t    true, 30 * HZ);",
    ),
    "placement read is controlled by an unreachable condition": (
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
        "\tif (false)\n\t\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
    ),
    "final read unlock is controlled by an unreachable condition": (
        "\tup_read(&rdev->exclusive_lock);\n\tdrm_gem_object_put(gobj);",
        "\tif (false)\n\t\tup_read(&rdev->exclusive_lock);\n"
        "\tdrm_gem_object_put(gobj);",
    ),
    "success return follows the reservation wait": (
        "\t\t\t\t    true, 30 * HZ);",
        "\t\t\t\t    true, 30 * HZ);\n\treturn 0;",
    ),
    "success return follows the read lock": (
        "\tdown_read(&rdev->exclusive_lock);",
        "\tdown_read(&rdev->exclusive_lock);\n\treturn 0;",
    ),
    "success return follows the parked refusal": (
        "\t}\n\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
        "\t}\n\treturn 0;\n\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
    ),
    "flush predicate is always false": (
        "\tif (rdev->asic->mmio_hdp_flush &&\n"
        "\t    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)",
        "\tif (false && rdev->asic->mmio_hdp_flush &&\n"
        "\t    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)",
    ),
    "flush predicate is controlled by an unreachable condition": (
        "\tif (rdev->asic->mmio_hdp_flush &&",
        "\tif (false)\n\t\tif (rdev->asic->mmio_hdp_flush &&",
    ),
    "flush call uses a different device": (
        "\t\trobj->rdev->asic->mmio_hdp_flush(rdev);",
        "\t\trobj->rdev->asic->mmio_hdp_flush(NULL);",
    ),
    "nested extra flush precedes the predicate": (
        "\tif (rdev->asic->mmio_hdp_flush &&",
        "\tif (false) {\n"
        "\t\trobj->rdev->asic->mmio_hdp_flush(rdev);\n"
        "\t}\n"
        "\tif (rdev->asic->mmio_hdp_flush &&",
    ),
    "goto bypasses placement and flush": (
        "\t}\n"
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);\n"
        "\tif (rdev->asic->mmio_hdp_flush &&\n"
        "\t    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)\n"
        "\t\trobj->rdev->asic->mmio_hdp_flush(rdev);\n"
        "\tup_read(&rdev->exclusive_lock);",
        "\t}\n"
        "\tgoto after_flush;\n"
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);\n"
        "\tif (rdev->asic->mmio_hdp_flush &&\n"
        "\t    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)\n"
        "\t\trobj->rdev->asic->mmio_hdp_flush(rdev);\n"
        "after_flush:\n"
        "\tup_read(&rdev->exclusive_lock);",
    ),
    "complete transaction is inside an unreachable digraph block": (
        WAIT_FIXTURE_GOOD,
        WAIT_FIXTURE_GOOD.replace(
            "\tret = dma_resv_wait_timeout",
            "\tif (false) <%\n\t\t;\n\tret = dma_resv_wait_timeout",
            1,
        ).replace(
            "\treturn r;\n}",
            "\treturn r;\n\t%>\n}",
            1,
        ),
    ),
    "extra flush follows the final read unlock": (
        "\tup_read(&rdev->exclusive_lock);\n\tdrm_gem_object_put(gobj);",
        "\tup_read(&rdev->exclusive_lock);\n"
        "\trobj->rdev->asic->mmio_hdp_flush(rdev);\n"
        "\tdrm_gem_object_put(gobj);",
    ),
    "normalized wait result is replaced at final return": (
        "\tr = radeon_gem_handle_lockup(rdev, r);\n\treturn r;",
        "\tr = radeon_gem_handle_lockup(rdev, r);\n\treturn 0;",
    ),
}

# A comment naming the guarded call sits above the guard in the real source, so
# a matcher that reads prose as code reports the guard as following the call it
# precedes. This fixture is good and must stay accepted.
FIXTURE_GOOD_WITH_PROSE = """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\t/* The retry: path ORs GTT on only after radeon_bo_create fails for a
\t * VRAM-only request, so placement is decided below rather than here.
\t */
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
"""

FIXTURE_GOOD_WITH_COMMENT_TOKEN_LITERAL = """
int radeon_gem_object_create(struct radeon_device *rdev)
{
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tdev_info(rdev->dev, "//");
\tr = radeon_bo_create(rdev);
\treturn 0;
}
"""

FIXTURE_GOOD_WITH_DIGRAPH_LITERAL = FIXTURE_GOOD_WITH_COMMENT_TOKEN_LITERAL.replace(
    '"//"',
    '"<% %>"',
    1,
)

CS_FIXTURE_GOOD = """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tstruct radeon_device *rdev = dev->dev_private;
\tstruct radeon_cs_parser parser;
\tint r;

\tdown_read(&rdev->exclusive_lock);
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn -EIO;
\t}
\tif (!rdev->accel_working) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn -EBUSY;
\t}
\tif (rdev->in_reset) {
\t\tup_read(&rdev->exclusive_lock);
\t\tr = radeon_gpu_reset(rdev);
\t\tif (!r)
\t\t\tr = -EAGAIN;
\t\treturn r;
\t}
\tmemset(&parser, 0, sizeof(parser));
\tparser.filp = filp;
\tparser.rdev = rdev;
\tparser.dev = rdev->dev;
\tparser.family = rdev->family;
\tr = radeon_cs_parser_init(&parser, data);
\tif (r) {
\t\tDRM_ERROR("Failed to initialize parser !\\n");
\t\tradeon_cs_parser_fini(&parser, r);
\t\tup_read(&rdev->exclusive_lock);
\t\tr = radeon_cs_handle_lockup(rdev, r);
\t\treturn r;
\t}
\tr = radeon_cs_ib_fill(rdev, &parser);
\tif (!r) {
\t\tr = radeon_cs_parser_relocs(&parser);
\t\tif (r && r != -ERESTARTSYS)
\t\t\tDRM_ERROR("Failed to parse relocation %d!\\n", r);
\t}
\tif (r) {
\t\tradeon_cs_parser_fini(&parser, r);
\t\tup_read(&rdev->exclusive_lock);
\t\tr = radeon_cs_handle_lockup(rdev, r);
\t\treturn r;
\t}
\ttrace_radeon_cs(&parser);
\tr = radeon_cs_ib_chunk(rdev, &parser);
\tif (r) {
\t\tgoto out;
\t}
\tr = radeon_cs_ib_vm_chunk(rdev, &parser);
\tif (r) {
\t\tgoto out;
\t}
\tif (!list_empty(&parser.validated) && !parser.ib.fence) {
\t\tDRM_ERROR("Successful command submission has validated BOs but no fence !\\n");
\t\tr = -EINVAL;
\t}
out:
\tradeon_cs_parser_fini(&parser, r);
\tup_read(&rdev->exclusive_lock);
\tr = radeon_cs_handle_lockup(rdev, r);
\treturn r;
}
"""

CS_PARSER_FAILURE_FIXTURE = (
    "\tif (r) {\n"
    '\t\tDRM_ERROR("Failed to initialize parser !\\n");\n'
    "\t\tradeon_cs_parser_fini(&parser, r);\n"
    "\t\tup_read(&rdev->exclusive_lock);\n"
    "\t\tr = radeon_cs_handle_lockup(rdev, r);\n"
    "\t\treturn r;\n"
    "\t}\n"
)
CS_VALIDATION_FAILURE_FIXTURE = (
    "\tif (r) {\n"
    "\t\tradeon_cs_parser_fini(&parser, r);\n"
    "\t\tup_read(&rdev->exclusive_lock);\n"
    "\t\tr = radeon_cs_handle_lockup(rdev, r);\n"
    "\t\treturn r;\n"
    "\t}\n"
)
CS_NON_VM_STAGE_FIXTURE = (
    "\tr = radeon_cs_ib_chunk(rdev, &parser);\n\tif (r) {\n\t\tgoto out;\n\t}\n"
)
CS_VM_STAGE_FIXTURE = (
    "\tr = radeon_cs_ib_vm_chunk(rdev, &parser);\n\tif (r) {\n\t\tgoto out;\n\t}\n"
)
CS_FENCE_VALIDATION_FIXTURE = (
    "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {\n"
    '\t\tDRM_ERROR("Successful command submission has validated BOs but no '
    'fence !\\n");\n'
    "\t\tr = -EINVAL;\n"
    "\t}\n"
)

CS_FIXTURES_BAD = {
    "parked condition is always false": CS_FIXTURE_GOOD.replace(
        "if (READ_ONCE(rdev->gpu_parked))",
        "if (false && READ_ONCE(rdev->gpu_parked))",
        1,
    ),
    "parked guard is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tif (false) {\n\t\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ).replace(
        "\tif (!rdev->accel_working) {",
        "\t}\n\tif (!rdev->accel_working) {",
        1,
    ),
    "parser zeroing precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tmemset(&parser, 0, sizeof(parser));\n",
        "",
        1,
    ).replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tmemset(&parser, 0, sizeof(parser));\n\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "parser initialization precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tr = radeon_cs_parser_init(&parser, data);\n",
        "",
        1,
    ).replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tr = radeon_cs_parser_init(&parser, data);\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "acceleration refusal precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tif (!rdev->accel_working) {\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\treturn -EBUSY;\n"
        "\t}\n",
        "",
        1,
    ).replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tif (!rdev->accel_working) {\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\treturn -EBUSY;\n"
        "\t}\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "reset admission precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tif (rdev->in_reset) {\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\tr = radeon_gpu_reset(rdev);\n"
        "\t\tif (!r)\n"
        "\t\t\tr = -EAGAIN;\n"
        "\t\treturn r;\n"
        "\t}\n",
        "",
        1,
    ).replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tif (rdev->in_reset) {\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\tr = radeon_gpu_reset(rdev);\n"
        "\t\tif (!r)\n"
        "\t\t\tr = -EAGAIN;\n"
        "\t\treturn r;\n"
        "\t}\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "read lock is released before parked refusal": CS_FIXTURE_GOOD.replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tup_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "nested read unlock precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tdown_read(&rdev->exclusive_lock);\n"
        "\tif (false) {\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t}\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "read lock is controlled by an unreachable condition": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (false)\n\t\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "acceleration guard is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tif (!rdev->accel_working) {",
            "\tif (false)\n\t\tif (!rdev->accel_working) {",
            1,
        )
    ),
    "reset guard is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tif (rdev->in_reset) {",
            "\tif (false)\n\t\tif (rdev->in_reset) {",
            1,
        )
    ),
    "parser zeroing is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tmemset(&parser, 0, sizeof(parser));",
            "\tif (false)\n\t\tmemset(&parser, 0, sizeof(parser));",
            1,
        )
    ),
    "parser initialization is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tr = radeon_cs_parser_init(&parser, data);",
            "\tif (false)\n\t\tr = radeon_cs_parser_init(&parser, data);",
            1,
        )
    ),
    "parked refusal returns busy": CS_FIXTURE_GOOD.replace(
        "\t\treturn -EIO;",
        "\t\treturn -EBUSY;",
        1,
    ),
    "parked refusal retains read lock": CS_FIXTURE_GOOD.replace(
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EIO;",
        "\t\treturn -EIO;",
        1,
    ),
    "parked refusal unlock is nested in an unreachable block": (
        CS_FIXTURE_GOOD.replace(
            "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EIO;",
            "\t\tif (false) {\n"
            "\t\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\t}\n"
            "\t\treturn -EIO;",
            1,
        )
    ),
    "parked refusal unlock is conditional without braces": (
        CS_FIXTURE_GOOD.replace(
            "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EIO;",
            "\t\tif (false)\n\t\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EIO;",
            1,
        )
    ),
    "parked refusal goto skips the unlock": (
        CS_FIXTURE_GOOD.replace(
            "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EIO;",
            "\t\tgoto after_parked_unlock;\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "after_parked_unlock:\n"
            "\t\t;\n"
            "\t\treturn -EIO;",
            1,
        )
    ),
    "parked refusal loops before the unlock": (
        CS_FIXTURE_GOOD.replace(
            "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EIO;",
            "\t\tfor (;;)\n"
            "\t\t\t;\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\treturn -EIO;",
            1,
        )
    ),
    "parked refusal unlock is disabled by preprocessing": (
        CS_FIXTURE_GOOD.replace(
            "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EIO;",
            "\t\t;\n"
            "#if 0\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "#endif\n"
            "\t\t;\n"
            "\t\treturn -EIO;",
            1,
        )
    ),
    "acceleration refusal retains read lock": CS_FIXTURE_GOOD.replace(
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EBUSY;",
        "\t\treturn -EBUSY;",
        1,
    ),
    "acceleration return is nested in an unreachable block": (
        CS_FIXTURE_GOOD.replace(
            "\t\treturn -EBUSY;",
            "\t\tif (false) {\n\t\t\treturn -EBUSY;\n\t\t}",
            1,
        )
    ),
    "acceleration return is conditional without braces": (
        CS_FIXTURE_GOOD.replace(
            "\t\treturn -EBUSY;",
            "\t\tif (false)\n\t\t\treturn -EBUSY;",
            1,
        )
    ),
    "acceleration return follows an infinite loop": (
        CS_FIXTURE_GOOD.replace(
            "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn -EBUSY;",
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\tfor (;;)\n"
            "\t\t\t;\n"
            "\t\treturn -EBUSY;",
            1,
        )
    ),
    "acceleration return is disabled by preprocessing": (
        CS_FIXTURE_GOOD.replace(
            "\t\treturn -EBUSY;",
            "\t\t;\n#if 0\n\t\treturn -EBUSY;\n#endif\n\t\t;",
            1,
        )
    ),
    "reset begins before read unlock": CS_FIXTURE_GOOD.replace(
        "\t\tup_read(&rdev->exclusive_lock);\n\t\tr = radeon_gpu_reset(rdev);",
        "\t\tr = radeon_gpu_reset(rdev);\n\t\tup_read(&rdev->exclusive_lock);",
        1,
    ),
    "reset unlock is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\t\tup_read(&rdev->exclusive_lock);\n\t\tr = radeon_gpu_reset(rdev);",
        "\t\tif (false) {\n"
        "\t\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\t}\n"
        "\t\tr = radeon_gpu_reset(rdev);",
        1,
    ),
    "reset unlock is conditional without braces": CS_FIXTURE_GOOD.replace(
        "\tif (rdev->in_reset) {\n\t\tup_read(&rdev->exclusive_lock);",
        "\tif (rdev->in_reset) {\n"
        "\t\tif (false)\n"
        "\t\t\tup_read(&rdev->exclusive_lock);",
        1,
    ),
    "reset call is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\t\tr = radeon_gpu_reset(rdev);\n\t\tif (!r)",
        "\t\tif (false) {\n\t\t\tr = radeon_gpu_reset(rdev);\n\t\t}\n\t\tif (!r)",
        1,
    ),
    "reset return is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\t\treturn r;\n\t}",
        "\t\tif (false) {\n\t\t\treturn r;\n\t\t}\n\t}",
        1,
    ),
    "relocation validation precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tif (!r)\n\t\tr = radeon_cs_parser_relocs(&parser);\n",
        "",
        1,
    ).replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tif (!r)\n\t\tr = radeon_cs_parser_relocs(&parser);\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "IB fill call is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\tr = radeon_cs_ib_fill(rdev, &parser);",
        "\tif (false) {\n\t\tr = radeon_cs_ib_fill(rdev, &parser);\n\t}",
        1,
    ),
    "IB fill call is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tr = radeon_cs_ib_fill(rdev, &parser);",
            "\tif (false)\n\t\tr = radeon_cs_ib_fill(rdev, &parser);",
            1,
        )
    ),
    "relocation call is nested in an unreachable block": (
        CS_FIXTURE_GOOD.replace(
            "\t\tr = radeon_cs_parser_relocs(&parser);",
            "\t\tif (false) {\n\t\t\tr = radeon_cs_parser_relocs(&parser);\n\t\t}",
            1,
        )
    ),
    "relocation guard is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tif (!r) {",
            "\tif (false)\n\t\tif (!r) {",
            1,
        )
    ),
    "IB schedule call is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\tr = radeon_cs_ib_chunk(rdev, &parser);",
        "\tif (false) {\n\t\tr = radeon_cs_ib_chunk(rdev, &parser);\n\t}",
        1,
    ),
    "IB schedule call is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tr = radeon_cs_ib_chunk(rdev, &parser);",
            "\tif (false)\n\t\tr = radeon_cs_ib_chunk(rdev, &parser);",
            1,
        )
    ),
    "final unlock is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "out:\n"
            "\tradeon_cs_parser_fini(&parser, r);\n"
            "\tup_read(&rdev->exclusive_lock);",
            "out:\n"
            "\tradeon_cs_parser_fini(&parser, r);\n"
            "\tif (false)\n"
            "\t\tup_read(&rdev->exclusive_lock);",
            1,
        )
    ),
    "IB schedule precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tr = radeon_cs_ib_chunk(rdev, &parser);\n",
        "",
        1,
    ).replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        "\tr = radeon_cs_ib_chunk(rdev, &parser);\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "forward goto bypasses parked refusal": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);\n",
        "\tdown_read(&rdev->exclusive_lock);\n\tgoto bypass_parked_refusal;\n",
        1,
    ).replace(
        "\tif (!rdev->accel_working) {",
        "bypass_parked_refusal:\n\tif (!rdev->accel_working) {",
        1,
    ),
    "success return follows the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tdown_read(&rdev->exclusive_lock);\n\treturn 0;",
        1,
    ),
    "nested extra unlock follows admission": CS_FIXTURE_GOOD.replace(
        "\tmemset(&parser, 0, sizeof(parser));",
        "\tif (rdev->family == CHIP_RV100) {\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t}\n"
        "\tmemset(&parser, 0, sizeof(parser));",
        1,
    ),
    "parser initialization failure guard is deleted": CS_FIXTURE_GOOD.replace(
        CS_PARSER_FAILURE_FIXTURE,
        "",
        1,
    ),
    "validation failure guard is deleted": CS_FIXTURE_GOOD.replace(
        CS_VALIDATION_FAILURE_FIXTURE,
        "",
        1,
    ),
    "parser zeroing uses one member size": CS_FIXTURE_GOOD.replace(
        "sizeof(parser)",
        "sizeof(parser.rdev)",
        1,
    ),
    "nested IB fill precedes the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (false) {\n"
        "\t\tr = radeon_cs_ib_fill(rdev, &parser);\n"
        "\t}\n"
        "\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "nested non-VM schedule precedes the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (false) {\n"
        "\t\tr = radeon_cs_ib_chunk(rdev, &parser);\n"
        "\t}\n"
        "\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "error return follows the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tdown_read(&rdev->exclusive_lock);\n\treturn -EINVAL;",
        1,
    ),
    "nested return follows the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tdown_read(&rdev->exclusive_lock);\n\tif (false) {\n\t\treturn 0;\n\t}",
        1,
    ),
    "nested unlock is inside relocation success": CS_FIXTURE_GOOD.replace(
        "\tif (!r) {",
        "\tif (!r) {\n"
        "\t\tif (rdev->family == CHIP_RV100) {\n"
        "\t\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\t}",
        1,
    ),
    "nested unlock follows the non-VM stage": CS_FIXTURE_GOOD.replace(
        CS_NON_VM_STAGE_FIXTURE,
        CS_NON_VM_STAGE_FIXTURE
        + "\tif (rdev->family == CHIP_RV100) {\n"
        + "\t\tup_read(&rdev->exclusive_lock);\n"
        + "\t}\n",
        1,
    ),
    "parser initialization failure predicate is always false": (
        CS_FIXTURE_GOOD.replace(
            CS_PARSER_FAILURE_FIXTURE,
            CS_PARSER_FAILURE_FIXTURE.replace(
                "\tif (r) {",
                "\tif (false && r) {",
                1,
            ),
            1,
        )
    ),
    "validation failure predicate is always false": CS_FIXTURE_GOOD.replace(
        CS_VALIDATION_FAILURE_FIXTURE,
        CS_VALIDATION_FAILURE_FIXTURE.replace(
            "\tif (r) {",
            "\tif (false && r) {",
            1,
        ),
        1,
    ),
    "parser initialization result is clobbered": CS_FIXTURE_GOOD.replace(
        "\tr = radeon_cs_parser_init(&parser, data);\n",
        "\tr = radeon_cs_parser_init(&parser, data);\n\tr = 0;\n",
        1,
    ),
    "parser initialization error log clobbers result": CS_FIXTURE_GOOD.replace(
        'DRM_ERROR("Failed to initialize parser !\\n");',
        'DRM_ERROR("Failed to initialize parser: %d !\\n", r = 0);',
        1,
    ),
    "relocation error log clobbers result": CS_FIXTURE_GOOD.replace(
        'DRM_ERROR("Failed to parse relocation %d!\\n", r);',
        'DRM_ERROR("Failed to parse relocation %d!\\n", r = 0);',
        1,
    ),
    "relocation result is clobbered before failure handling": (
        CS_FIXTURE_GOOD.replace(
            CS_VALIDATION_FAILURE_FIXTURE,
            "\tr = 0;\n" + CS_VALIDATION_FAILURE_FIXTURE,
            1,
        )
    ),
    "non-VM result guard is deleted": CS_FIXTURE_GOOD.replace(
        CS_NON_VM_STAGE_FIXTURE,
        "\tr = radeon_cs_ib_chunk(rdev, &parser);\n",
        1,
    ),
    "non-VM result predicate is always false": CS_FIXTURE_GOOD.replace(
        CS_NON_VM_STAGE_FIXTURE,
        CS_NON_VM_STAGE_FIXTURE.replace(
            "\tif (r) {",
            "\tif (false && r) {",
            1,
        ),
        1,
    ),
    "VM result guard is deleted": CS_FIXTURE_GOOD.replace(
        CS_VM_STAGE_FIXTURE,
        "\tr = radeon_cs_ib_vm_chunk(rdev, &parser);\n",
        1,
    ),
    "VM result predicate is always false": CS_FIXTURE_GOOD.replace(
        CS_VM_STAGE_FIXTURE,
        CS_VM_STAGE_FIXTURE.replace(
            "\tif (r) {",
            "\tif (false && r) {",
            1,
        ),
        1,
    ),
    "VM stage is deleted": CS_FIXTURE_GOOD.replace(
        CS_VM_STAGE_FIXTURE,
        "",
        1,
    ),
    "parser zeroing uses pointer size": CS_FIXTURE_GOOD.replace(
        "sizeof(parser)",
        "sizeof(&parser)",
        1,
    ),
    "nested relocation precedes the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (false) {\n"
        "\t\tr = radeon_cs_parser_relocs(&parser);\n"
        "\t}\n"
        "\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "nested VM schedule precedes the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tif (false) {\n"
        "\t\tr = radeon_cs_ib_vm_chunk(rdev, &parser);\n"
        "\t}\n"
        "\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "parser member write precedes the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tparser.rdev = rdev;\n\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "complete transaction is inside an unreachable digraph block": (
        CS_FIXTURE_GOOD.replace(
            "\tdown_read(&rdev->exclusive_lock);",
            "\tif (false) <%\n\t\t;\n\tdown_read(&rdev->exclusive_lock);",
            1,
        ).replace(
            "\treturn r;\n}",
            "\treturn r;\n\t%>\n}",
            1,
        )
    ),
    "GPU reset precedes the read lock": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tradeon_gpu_reset(rdev);\n\tdown_read(&rdev->exclusive_lock);",
        1,
    ),
    "validated-BO fence guard is deleted": CS_FIXTURE_GOOD.replace(
        CS_FENCE_VALIDATION_FIXTURE,
        "",
        1,
    ),
    "extra GPU reset follows the VM stage": CS_FIXTURE_GOOD.replace(
        CS_FENCE_VALIDATION_FIXTURE,
        "\tr = radeon_gpu_reset(rdev);\n" + CS_FENCE_VALIDATION_FIXTURE,
        1,
    ),
}


PROJECTED_GEM_FIXTURE = """
int radeon_gem_object_create(struct radeon_device *rdev)
{
	int r;
	r = radeon_rs4xx_hardware_access_begin(rdev);
	if (r)
		return r;
retry:
	r = radeon_bo_create(rdev, size, alignment, kernel, initial_domain,
			     flags, NULL, NULL, &robj);
	if (r) {
		if (initial_domain == RADEON_GEM_DOMAIN_VRAM) {
			initial_domain |= RADEON_GEM_DOMAIN_GTT;
			goto retry;
		}
		goto out;
	}
out:
	radeon_rs4xx_hardware_access_end(rdev);
	return r;
}
"""

PROJECTED_GEM_MUTATIONS = {
    "access admission removed": PROJECTED_GEM_FIXTURE.replace(
        "\tr = radeon_rs4xx_hardware_access_begin(rdev);",
        "\tr = 0;",
        1,
    ),
    "access failure ignored": PROJECTED_GEM_FIXTURE.replace(
        "\tif (r)\n\t\treturn r;",
        "\tif (false && r)\n\t\treturn r;",
        1,
    ),
    "access failure returns success": PROJECTED_GEM_FIXTURE.replace(
        "\tif (r)\n\t\treturn r;",
        "\tif (r)\n\t\treturn 0;",
        1,
    ),
    "access release removed": PROJECTED_GEM_FIXTURE.replace(
        "\tradeon_rs4xx_hardware_access_end(rdev);",
        "",
        1,
    ),
    "admitted allocation returns before release": PROJECTED_GEM_FIXTURE.replace(
        "\tr = radeon_bo_create(rdev, size, alignment, kernel, initial_domain,",
        "\treturn 0;\n"
        "\tr = radeon_bo_create(rdev, size, alignment, kernel, initial_domain,",
        1,
    ),
    "unexpected admitted goto": PROJECTED_GEM_FIXTURE.replace(
        "\t\tgoto out;",
        "\t\tgoto retry;",
        1,
    ),
    "extra access admission": PROJECTED_GEM_FIXTURE.replace(
        "retry:\n",
        "retry:\n\tr = radeon_rs4xx_hardware_access_begin(rdev);\n",
        1,
    ),
}

PROJECTED_PRIME_FIXTURE = """
struct drm_gem_object *radeon_gem_prime_import_sg_table(struct drm_device *dev)
{
	struct dma_resv *resv = attach->dmabuf->resv;
	struct radeon_device *rdev = dev->dev_private;
	struct radeon_bo *bo;
	int ret;
	ret = radeon_device_lock_hardware(rdev);
	if (ret)
		return ERR_PTR(ret);
	dma_resv_lock(resv, NULL);
	ret = radeon_bo_create(rdev, attach->dmabuf->size, PAGE_SIZE, false,
			       RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo);
	dma_resv_unlock(resv);
	radeon_device_unlock_hardware(rdev);
	if (ret)
		return ERR_PTR(ret);
	return &bo->tbo.base;
}
"""

PROJECTED_PRIME_MUTATIONS = {
    "helper admission removed": PROJECTED_PRIME_FIXTURE.replace(
        "\tret = radeon_device_lock_hardware(rdev);",
        "\tret = 0;",
        1,
    ),
    "helper failure ignored": PROJECTED_PRIME_FIXTURE.replace(
        "\tif (ret)\n\t\treturn ERR_PTR(ret);",
        "\tif (false && ret)\n\t\treturn ERR_PTR(ret);",
        1,
    ),
    "reservation precedes admission": PROJECTED_PRIME_FIXTURE.replace(
        "\tret = radeon_device_lock_hardware(rdev);\n"
        "\tif (ret)\n"
        "\t\treturn ERR_PTR(ret);\n"
        "\tdma_resv_lock(resv, NULL);",
        "\tdma_resv_lock(resv, NULL);\n"
        "\tret = radeon_device_lock_hardware(rdev);\n"
        "\tif (ret)\n"
        "\t\treturn ERR_PTR(ret);",
        1,
    ),
    "helper release removed": PROJECTED_PRIME_FIXTURE.replace(
        "\tradeon_device_unlock_hardware(rdev);",
        "",
        1,
    ),
    "admitted allocation returns before release": PROJECTED_PRIME_FIXTURE.replace(
        "\tdma_resv_unlock(resv);",
        "\treturn NULL;\n\tdma_resv_unlock(resv);",
        1,
    ),
    "allocation uses another reservation": PROJECTED_PRIME_FIXTURE.replace(
        "RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo);",
        "RADEON_GEM_DOMAIN_GTT, 0, sg, NULL, &bo);",
        1,
    ),
}

PROJECTED_WAIT_FIXTURE = """
int radeon_gem_wait_idle_ioctl(struct drm_device *dev)
{
	struct radeon_device *rdev = dev->dev_private;
	int r = 0;
	int hardware_result;
	long ret;
	ret = dma_resv_wait_timeout(robj->tbo.base.resv, DMA_RESV_USAGE_READ,
				    true, 30 * HZ);
	if (ret == 0)
		r = -EBUSY;
	else if (ret < 0)
		r = ret;
	if (r) {
		drm_gem_object_put(gobj);
		return r;
	}
	hardware_result = radeon_device_lock_hardware(rdev);
	if (hardware_result) {
		drm_gem_object_put(gobj);
		return hardware_result;
	}
	cur_placement = READ_ONCE(robj->tbo.resource->mem_type);
	if (rdev->asic->mmio_hdp_flush &&
	    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)
		robj->rdev->asic->mmio_hdp_flush(rdev);
	radeon_device_unlock_hardware(rdev);
	drm_gem_object_put(gobj);
	return 0;
}
"""

PROJECTED_WAIT_MUTATIONS = {
    "wait failure discarded": PROJECTED_WAIT_FIXTURE.replace(
        "\tif (r) {\n\t\tdrm_gem_object_put(gobj);\n\t\treturn r;\n\t}\n",
        "",
        1,
    ),
    "helper admission removed": PROJECTED_WAIT_FIXTURE.replace(
        "\thardware_result = radeon_device_lock_hardware(rdev);",
        "\thardware_result = 0;",
        1,
    ),
    "helper failure returns success": PROJECTED_WAIT_FIXTURE.replace(
        "\t\treturn hardware_result;",
        "\t\treturn 0;",
        1,
    ),
    "placement read precedes admission": PROJECTED_WAIT_FIXTURE.replace(
        "\thardware_result = radeon_device_lock_hardware(rdev);\n"
        "\tif (hardware_result) {\n"
        "\t\tdrm_gem_object_put(gobj);\n"
        "\t\treturn hardware_result;\n"
        "\t}\n"
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);\n"
        "\thardware_result = radeon_device_lock_hardware(rdev);\n"
        "\tif (hardware_result) {\n"
        "\t\tdrm_gem_object_put(gobj);\n"
        "\t\treturn hardware_result;\n"
        "\t}",
        1,
    ),
    "helper release precedes flush": PROJECTED_WAIT_FIXTURE.replace(
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);\n"
        "\tif (rdev->asic->mmio_hdp_flush &&\n"
        "\t    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)\n"
        "\t\trobj->rdev->asic->mmio_hdp_flush(rdev);\n"
        "\tradeon_device_unlock_hardware(rdev);",
        "\tradeon_device_unlock_hardware(rdev);\n"
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);\n"
        "\tif (rdev->asic->mmio_hdp_flush &&\n"
        "\t    radeon_mem_type_to_domain(cur_placement) == RADEON_GEM_DOMAIN_VRAM)\n"
        "\t\trobj->rdev->asic->mmio_hdp_flush(rdev);",
        1,
    ),
    "flush uses another device": PROJECTED_WAIT_FIXTURE.replace(
        "robj->rdev->asic->mmio_hdp_flush(rdev);",
        "robj->rdev->asic->mmio_hdp_flush(robj->rdev);",
        1,
    ),
}

PROJECTED_DUMB_FIXTURE = """
int radeon_mode_dumb_create(struct drm_file *file_priv,
			    struct drm_device *dev,
			    struct drm_mode_create_dumb *args)
{
	struct radeon_device *rdev = dev->dev_private;
	struct drm_gem_object *gobj;
	uint32_t handle;
	int r;
	r = radeon_device_lock_hardware(rdev);
	if (r)
		return r;
	r = radeon_gem_object_create(rdev, args->size, 0,
				     RADEON_GEM_DOMAIN_VRAM, 0,
				     false, &gobj);
	radeon_device_unlock_hardware(rdev);
	if (r)
		return r;
	r = drm_gem_handle_create(file_priv, gobj, &handle);
	if (r)
		return r;
	return 0;
}
"""

PROJECTED_DUMB_MUTATIONS = {
    "helper admission removed": PROJECTED_DUMB_FIXTURE.replace(
        "\tr = radeon_device_lock_hardware(rdev);",
        "\tr = 0;",
        1,
    ),
    "helper failure translated": PROJECTED_DUMB_FIXTURE.replace(
        "\tif (r)\n\t\treturn r;",
        "\tif (r)\n\t\treturn -ENOMEM;",
        1,
    ),
    "creator precedes admission": PROJECTED_DUMB_FIXTURE.replace(
        "\tr = radeon_device_lock_hardware(rdev);\n"
        "\tif (r)\n"
        "\t\treturn r;\n"
        "\tr = radeon_gem_object_create(rdev, args->size, 0,\n"
        "\t\t\t\t     RADEON_GEM_DOMAIN_VRAM, 0,\n"
        "\t\t\t\t     false, &gobj);",
        "\tr = radeon_gem_object_create(rdev, args->size, 0,\n"
        "\t\t\t\t     RADEON_GEM_DOMAIN_VRAM, 0,\n"
        "\t\t\t\t     false, &gobj);\n"
        "\tr = radeon_device_lock_hardware(rdev);\n"
        "\tif (r)\n"
        "\t\treturn r;",
        1,
    ),
    "helper release removed": PROJECTED_DUMB_FIXTURE.replace(
        "\tradeon_device_unlock_hardware(rdev);",
        "",
        1,
    ),
    "creator failure translated": PROJECTED_DUMB_FIXTURE.replace(
        "\tradeon_device_unlock_hardware(rdev);\n\tif (r)\n\t\treturn r;",
        "\tradeon_device_unlock_hardware(rdev);\n\tif (r)\n\t\treturn -ENOMEM;",
        1,
    ),
}


def project_command_submission_fixture(source: str) -> str:
    """Project a direct-lock CS fixture through the centralized helper."""

    projected = source.replace(
        "\tdown_read(&rdev->exclusive_lock);",
        "\tr = radeon_device_lock_hardware(rdev);\n\tif (r)\n\t\treturn r;",
        1,
    )
    projected = projected.replace(
        "radeon_cs_parser_fini(&parser, r);",
        "radeon_cs_parser_release_reservations(&parser, r);",
    )
    projected = projected.replace(
        "up_read(&rdev->exclusive_lock);",
        "radeon_device_unlock_hardware(rdev);",
    )
    projected = projected.replace(
        "radeon_cs_parser_release_reservations(&parser, r);\n"
        "\t\tradeon_device_unlock_hardware(rdev);",
        "radeon_cs_parser_release_reservations(&parser, r);\n"
        "\t\tradeon_device_unlock_hardware(rdev);\n"
        "\t\tradeon_cs_parser_release_storage(&parser);",
    )
    projected = projected.replace(
        "radeon_cs_parser_release_reservations(&parser, r);\n"
        "\tradeon_device_unlock_hardware(rdev);",
        "radeon_cs_parser_release_reservations(&parser, r);\n"
        "\tradeon_device_unlock_hardware(rdev);\n"
        "\tradeon_cs_parser_release_storage(&parser);",
    )
    return projected


PROJECTED_CS_FIXTURE = project_command_submission_fixture(CS_FIXTURE_GOOD)
PROJECTED_CS_MUTATIONS = {
    "helper failure guard removed": PROJECTED_CS_FIXTURE.replace(
        "\tif (r)\n\t\treturn r;\n",
        "",
        1,
    ),
    "helper result clobbered": PROJECTED_CS_FIXTURE.replace(
        "\tr = radeon_device_lock_hardware(rdev);",
        "\tr = radeon_device_lock_hardware(rdev);\n\tr = 0;",
        1,
    ),
    "parked helper release removed": PROJECTED_CS_FIXTURE.replace(
        "\tif (READ_ONCE(rdev->gpu_parked)) {\n"
        "\t\tradeon_device_unlock_hardware(rdev);",
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "parser storage releases before admission": PROJECTED_CS_FIXTURE.replace(
        "\t\tradeon_device_unlock_hardware(rdev);\n"
        "\t\tradeon_cs_parser_release_storage(&parser);",
        "\t\tradeon_cs_parser_release_storage(&parser);\n"
        "\t\tradeon_device_unlock_hardware(rdev);",
        1,
    ),
    "raw read unlock reintroduced": PROJECTED_CS_FIXTURE.replace(
        "\tradeon_device_unlock_hardware(rdev);",
        "\tup_read(&rdev->exclusive_lock);",
        1,
    ),
}

MUTATION_EXPECTED_ERRORS = {
    "gem-create": {
        "allocation name is not called": "radeon_bo_create call absent",
        "success return precedes the parked guard": "entry-to-guard prefix",
        "infinite loop precedes the parked guard": "entry-to-guard prefix",
        "opaque terminator precedes the parked guard": "entry-to-guard prefix",
        "declaration expression exits before the parked guard": (
            "entry-to-guard prefix"
        ),
    },
    "dumb-create": {
        "success return precedes the read lock": "entry-to-lock prefix",
        "conditional success return precedes the read lock": "entry-to-lock prefix",
        "infinite loop precedes the read lock": "entry-to-lock prefix",
        "opaque terminator precedes the read lock": "entry-to-lock prefix",
        "declaration expression exits before the read lock": "entry-to-lock prefix",
        "creator result is clobbered before its guard": "unlock-to-result-guard",
        "creator result is clobbered before the read unlock": "creator-to-unlock",
        "complete transaction is inside an unreachable digraph block": (
            "entry-to-lock prefix"
        ),
    },
    "prime-import": {
        "success return follows the read lock": "lock-to-guard",
        "reservation is reassigned before the read lock": (
            "declaration and lock prefix statement sequence differs"
        ),
        "allocation uses a different reservation": "allocation: expected one match",
        "reservation lock uses a different reservation": (
            "reservation lock: expected one match"
        ),
        "reservation unlock uses a different reservation": (
            "reservation unlock: expected one match"
        ),
        "nested extra reservation unlock precedes allocation": (
            "reservation unlock: expected one match, found 2"
        ),
        "allocation result is clobbered before its guard": (
            "read-unlock-to-result-guard"
        ),
        "allocation failure predicate is always false": (
            "allocation result guard: expected one match"
        ),
        "complete transaction is inside an unreachable digraph block": (
            "parked guard is nested below its required statement scope"
        ),
    },
    "wait-idle-flush": {
        "success result initializer is nonzero": "entry-to-wait prefix",
        "success result is uninitialized": "entry-to-wait prefix",
        "success result is clobbered before the wait": "entry-to-wait prefix",
        "success return precedes the reservation wait": "entry-to-wait prefix",
        "infinite loop precedes the reservation wait": "entry-to-wait prefix",
        "declaration expression exits before the reservation wait": (
            "entry-to-wait prefix"
        ),
        "success return follows the read lock": "lock-to-guard",
        "flush predicate is always false": "VRAM predicate: expected one match",
        "flush predicate is controlled by an unreachable condition": (
            "VRAM predicate is controlled by an unbraced statement"
        ),
        "flush call uses a different device": "MMIO call: expected one match",
        "nested extra flush precedes the predicate": "placement-to-predicate",
        "goto bypasses placement and flush": (
            "final read unlock is controlled by an unbraced statement"
        ),
        "complete transaction is inside an unreachable digraph block": (
            "parked guard is nested below its required statement scope"
        ),
        "extra flush follows the final read unlock": "MMIO call denominator differs",
        "normalized wait result is replaced at final return": (
            "post-unlock cleanup and result return"
        ),
    },
    "command-submission": {
        "parser initialization error log clobbers result": (
            "parser initialization failure statement sequence differs"
        ),
        "relocation error log clobbers result": (
            "relocation success stage statement sequence differs"
        ),
        "success return follows the read lock": "lock-to-guard",
        "nested extra unlock follows admission": "reset-to-parser-zero",
        "parser initialization failure guard is deleted": (
            "parser initialization failure guard: expected one match"
        ),
        "validation failure guard is deleted": (
            "validation failure guard: expected one match"
        ),
        "parser zeroing uses one member size": "parser zeroing: expected one match",
        "nested IB fill precedes the read lock": "IB fill call: expected one match",
        "nested non-VM schedule precedes the read lock": (
            "non-VM IB schedule call: expected one match"
        ),
        "complete transaction is inside an unreachable digraph block": (
            "parked guard is nested below its required statement scope"
        ),
        "GPU reset precedes the read lock": (
            "declaration and lock prefix statement sequence differs"
        ),
        "validated-BO fence guard is deleted": (
            "validated-BO fence guard: expected one match"
        ),
        "extra GPU reset follows the VM stage": "VM-failure-to-fence-guard",
    },
}


def mutation_error_matches(contract: str, name: str, error: GuardError) -> bool:
    """Require selected mutations to reach their intended rejecting invariant."""
    expected = MUTATION_EXPECTED_ERRORS.get(contract, {}).get(name)
    return expected is None or expected in str(error)


def classify_gem_bad_fixture(
    tmp: Path,
    spec: dict[str, str],
    name: str,
    fixture: str,
) -> int:
    """Return zero only when one GEM fixture reaches its intended rejection."""
    (tmp / "radeon_gem.c").write_text(fixture, encoding="utf-8")
    try:
        check_guard(tmp, spec)
    except GuardError as error:
        if mutation_error_matches("gem-create", name, error):
            print(f"selftest known-bad rejected: {name}")
            return 0
        print(
            f"selftest known-bad MISDIRECTED: gem-create {name}: {error}",
            file=sys.stderr,
        )
        return 1
    print(f"selftest known-bad ACCEPTED: {name}", file=sys.stderr)
    return 1


def selftest(tmp: Path) -> int:
    """Run the fixtures. A checker earns trust by discriminating, not by passing."""
    spec = {
        "id": "gem-create",
        "path": Path("radeon_gem.c"),
        "function": "radeon_gem_object_create",
        "precedes": "radeon_bo_create",
        "returns": "-EIO",
    }
    failures = 0

    good = {
        "plain": FIXTURE_GOOD,
        "comment names the guarded call": FIXTURE_GOOD_WITH_PROSE,
        "comment token inside a string": FIXTURE_GOOD_WITH_COMMENT_TOKEN_LITERAL,
        "digraph tokens inside a string": FIXTURE_GOOD_WITH_DIGRAPH_LITERAL,
    }
    for name, fixture in good.items():
        fixture = complete_gem_fixture(fixture)
        (tmp / "radeon_gem.c").write_text(fixture, encoding="utf-8")
        try:
            check_guard(tmp, spec)
            print(f"selftest known-good accepted: {name}")
        except GuardError as exc:
            print(f"selftest known-good REJECTED: {name}: {exc}", file=sys.stderr)
            failures += 1

    for name, fixture in FIXTURES_BAD.items():
        fixture = complete_gem_fixture(fixture)
        failures += classify_gem_bad_fixture(tmp, spec, name, fixture)

    dumb_dir = tmp / SUBTREE
    dumb_dir.mkdir(parents=True, exist_ok=True)
    (dumb_dir / "radeon_gem.c").write_text(DUMB_FIXTURE_GOOD, encoding="utf-8")
    try:
        check_dumb_create_propagation(tmp)
        print("selftest known-good accepted: dumb-create forwards r")
    except GuardError as exc:
        print(f"selftest known-good REJECTED: dumb-create: {exc}", file=sys.stderr)
        failures += 1

    for name, fixture in DUMB_FIXTURES_BAD.items():
        (dumb_dir / "radeon_gem.c").write_text(fixture, encoding="utf-8")
        try:
            check_dumb_create_propagation(tmp)
        except GuardError as exc:
            if mutation_error_matches("dumb-create", name, exc):
                print(f"selftest known-bad rejected: dumb-create {name}")
            else:
                print(
                    f"selftest known-bad MISDIRECTED: dumb-create {name}: {exc}",
                    file=sys.stderr,
                )
                failures += 1
        else:
            print(f"selftest known-bad ACCEPTED: dumb-create {name}", file=sys.stderr)
            failures += 1

    locked_fixtures = (
        (
            next(item for item in GUARDS if item["id"] == "prime-import"),
            PRIME_FIXTURE_GOOD,
            PRIME_FIXTURE_MUTATIONS,
        ),
        (
            next(item for item in GUARDS if item["id"] == "wait-idle-flush"),
            WAIT_FIXTURE_GOOD,
            WAIT_FIXTURE_MUTATIONS,
        ),
    )
    for locked_spec, good_fixture, mutations in locked_fixtures:
        path = tmp / locked_spec["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(good_fixture, encoding="utf-8")
        try:
            check_guard(tmp, locked_spec)
            print(f"selftest known-good accepted: {locked_spec['id']} lock order")
        except GuardError as exc:
            print(
                f"selftest known-good REJECTED: {locked_spec['id']}: {exc}",
                file=sys.stderr,
            )
            failures += 1
        for name, (old, new) in mutations.items():
            if good_fixture.count(old) != 1:
                print(
                    f"selftest fixture error: {locked_spec['id']} {name}",
                    file=sys.stderr,
                )
                failures += 1
                continue
            path.write_text(good_fixture.replace(old, new, 1), encoding="utf-8")
            try:
                check_guard(tmp, locked_spec)
            except GuardError as exc:
                if mutation_error_matches(locked_spec["id"], name, exc):
                    print(f"selftest known-bad rejected: {locked_spec['id']} {name}")
                else:
                    print(
                        f"selftest known-bad MISDIRECTED: "
                        f"{locked_spec['id']} {name}: {exc}",
                        file=sys.stderr,
                    )
                    failures += 1
            else:
                print(
                    f"selftest known-bad ACCEPTED: {locked_spec['id']} {name}",
                    file=sys.stderr,
                )
                failures += 1

    cs_spec = {
        "id": "command-submission",
        "path": Path("radeon_cs.c"),
        "function": "radeon_cs_ioctl",
        "precedes": "radeon_cs_parser_init",
        "returns": "-EIO",
    }
    (tmp / "radeon_cs.c").write_text(CS_FIXTURE_GOOD, encoding="utf-8")
    try:
        check_guard(tmp, cs_spec)
        print("selftest known-good accepted: command submission refuses with -EIO")
    except GuardError as exc:
        print(
            f"selftest known-good REJECTED: command-submission: {exc}", file=sys.stderr
        )
        failures += 1

    for name, fixture in CS_FIXTURES_BAD.items():
        (tmp / "radeon_cs.c").write_text(fixture, encoding="utf-8")
        try:
            check_guard(tmp, cs_spec)
        except GuardError as exc:
            if mutation_error_matches("command-submission", name, exc):
                print(f"selftest known-bad rejected: command-submission {name}")
            else:
                print(
                    f"selftest known-bad MISDIRECTED: command-submission {name}: {exc}",
                    file=sys.stderr,
                )
                failures += 1
        else:
            print(
                f"selftest known-bad ACCEPTED: command-submission {name}",
                file=sys.stderr,
            )
            failures += 1

    projected_cases = (
        (
            "gem-create",
            "radeon_gem_object_create",
            PROJECTED_GEM_FIXTURE,
            PROJECTED_GEM_MUTATIONS,
            check_projected_gem_create,
        ),
        (
            "prime-import",
            "radeon_gem_prime_import_sg_table",
            PROJECTED_PRIME_FIXTURE,
            PROJECTED_PRIME_MUTATIONS,
            check_projected_prime_import,
        ),
        (
            "wait-idle-flush",
            "radeon_gem_wait_idle_ioctl",
            PROJECTED_WAIT_FIXTURE,
            PROJECTED_WAIT_MUTATIONS,
            check_projected_wait_idle,
        ),
        (
            "dumb-create",
            "radeon_mode_dumb_create",
            PROJECTED_DUMB_FIXTURE,
            PROJECTED_DUMB_MUTATIONS,
            check_projected_dumb_create,
        ),
        (
            "command-submission",
            "radeon_cs_ioctl",
            PROJECTED_CS_FIXTURE,
            PROJECTED_CS_MUTATIONS,
            check_projected_command_submission,
        ),
    )
    for label, function_name, good_fixture, mutations, checker in projected_cases:
        try:
            projected_body = function_code(
                good_fixture,
                function_name,
                PARKED_PROTECTED_MACROS,
            )
            reject_conditional_directives(projected_body, f"projected {label}")
            checker(projected_body)
            print(f"selftest known-good accepted: projected {label}")
        except GuardError as exc:
            print(
                f"selftest known-good REJECTED: projected {label}: {exc}",
                file=sys.stderr,
            )
            failures += 1
        for name, fixture in mutations.items():
            try:
                projected_body = function_code(
                    fixture,
                    function_name,
                    PARKED_PROTECTED_MACROS,
                )
                reject_conditional_directives(
                    projected_body,
                    f"projected {label} {name}",
                )
                checker(projected_body)
            except GuardError:
                print(f"selftest known-bad rejected: projected {label} {name}")
            else:
                print(
                    f"selftest known-bad ACCEPTED: projected {label} {name}",
                    file=sys.stderr,
                )
                failures += 1

    for name, fixture in CS_FIXTURES_BAD.items():
        try:
            projected_body = function_code(
                project_command_submission_fixture(fixture),
                "radeon_cs_ioctl",
                PARKED_PROTECTED_MACROS,
            )
            reject_conditional_directives(
                projected_body,
                f"projected command-submission legacy mutation {name}",
            )
            check_projected_command_submission(projected_body)
        except GuardError:
            print(f"selftest known-bad rejected: projected command-submission {name}")
        else:
            print(
                f"selftest known-bad ACCEPTED: projected command-submission {name}",
                file=sys.stderr,
            )
            failures += 1

    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    good_count = len(good) + 2 + len(locked_fixtures) + len(projected_cases)
    bad_count = (
        len(FIXTURES_BAD)
        + len(DUMB_FIXTURES_BAD)
        + len(CS_FIXTURES_BAD)
        + sum(len(mutations) for _, _, mutations in locked_fixtures)
        + sum(len(mutations) for _, _, _, mutations, _ in projected_cases)
        + len(CS_FIXTURES_BAD)
    )
    print(f"selftest: {good_count} good and {bad_count} bad fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="classify the built-in fixtures instead of the tree",
    )
    args = parser.parse_args()

    if args.selftest:
        import tempfile

        with tempfile.TemporaryDirectory() as name:
            return selftest(Path(name))

    failures = 0
    try:
        centralized_admission.check_contract(args.root)
    except centralized_admission.GuardError as exc:
        print(f"FAIL centralized admission contract: {exc}", file=sys.stderr)
        failures += 1
    else:
        print("ok centralized admission: reader and transaction helpers proven")
    for guard in GUARDS:
        try:
            check_guard(args.root, guard, validate_helpers=False)
        except GuardError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            failures += 1
        else:
            print(f"ok {guard['id']}: refuses before {guard['precedes']}")

    try:
        check_dumb_create_propagation(args.root, validate_helpers=False)
    except GuardError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        failures += 1
    else:
        print("ok dumb-create: forwards the creator's errno unchanged")

    if failures:
        print(f"parked admission guards: {failures} failure(s)", file=sys.stderr)
        return 1
    print(f"parked admission guards: {len(GUARDS) + 1} guards proven")
    return 0


if __name__ == "__main__":
    sys.exit(main())
