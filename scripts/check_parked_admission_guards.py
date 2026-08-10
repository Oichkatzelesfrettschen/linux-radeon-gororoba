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
from pathlib import Path

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

PARKED_GUARD = re.compile(
    r"\bif\s*\(\s*READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)\s*\)"
)
READ_LOCK = re.compile(r"\bdown_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;")
READ_UNLOCK = re.compile(r"\bup_read\s*\(\s*&rdev->exclusive_lock\s*\)\s*;")
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
    "radeon_gpu_reset",
    "up_read",
)
DUMB_CREATE_PROTECTED_MACROS = (
    "drm_gem_handle_create",
    "radeon_gem_object_create",
)


class GuardError(Exception):
    """A parked-device guard is absent, misplaced, or returns the wrong value."""


def strip_comments_and_literals(source: str) -> str:
    """Apply C line splicing, then blank comments and literals.

    Ordering is the whole check, and a comment naming radeon_bo_create sits
    above the guard that precedes the real call. Matching that prose would
    report the guard as following the allocation it actually precedes, so
    comments are blanked rather than deleted. C phase-2 line splices are
    deleted first because they can extend a line comment or form one token.
    Every position comparison uses the resulting translation stream.
    """

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return C_COMMENT_OR_LITERAL.sub(blank, C_LINE_SPLICE.sub("", source))


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
                        set(protected_macros)
                        | set(C_IDENTIFIER.findall(function_text))
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
        match for match in pattern.finditer(code) if brace_depth(code, match.start()) == depth
    ]
    if len(matches) != 1:
        raise GuardError(f"{label}: expected one match at depth {depth}, found {len(matches)}")
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
) -> None:
    """Require the guarded refusal to unlock before its direct return."""
    statement = code[statement_start:statement_end]
    unlocks = list(READ_UNLOCK.finditer(statement))
    returns = list(
        re.finditer(rf"\breturn\s+{re.escape(expected_return)}\s*;", statement)
    )
    if len(unlocks) != 1 or len(returns) != 1 or unlocks[0].start() > returns[0].start():
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


def check_guard(root: Path, guard: dict[str, str]) -> None:
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

    call_matches = list(re.finditer(rf"\b{re.escape(guard['precedes'])}\b", body))
    if not call_matches:
        raise GuardError(
            f"{guard['id']}: {guard['precedes']} absent from {guard['function']}"
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
    """Prove PRIME checks the latch before reservation and allocation locks."""

    function_open = body.find("{")
    lock = one_match_at_depth(body, READ_LOCK, 1, "prime-import read lock")
    require_direct_statement(
        body,
        function_open,
        lock.start(),
        "prime-import read lock",
    )
    reservation = one_match_at_depth(
        body,
        re.compile(r"\bdma_resv_lock\s*\("),
        1,
        "prime-import reservation lock",
    )
    allocation = one_match_at_depth(
        body,
        re.compile(r"\bret\s*=\s*radeon_bo_create\s*\("),
        1,
        "prime-import allocation",
    )
    reservation_unlock = one_match_at_depth(
        body,
        re.compile(r"\bdma_resv_unlock\s*\("),
        1,
        "prime-import reservation unlock",
    )
    final_unlock = one_match_at_depth(
        body,
        READ_UNLOCK,
        1,
        "prime-import final read unlock",
    )
    for match, label in (
        (reservation, "prime-import reservation lock"),
        (allocation, "prime-import allocation"),
        (reservation_unlock, "prime-import reservation unlock"),
        (final_unlock, "prime-import final read unlock"),
    ):
        require_direct_statement(body, function_open, match.start(), label)
    if not (
        lock.start()
        < guard_match.start()
        < reservation.start()
        < allocation.start()
        < reservation_unlock.start()
        < final_unlock.start()
    ):
        raise GuardError(
            "prime-import: expected exclusive lock, parked guard, dma_resv "
            "lock, allocation, dma_resv unlock, and exclusive unlock order"
        )
    require_lock_held_at_guard(
        body,
        lock.end(),
        guard_match.start(),
        "prime-import",
    )
    require_refusal_unlock(
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


def check_wait_idle_lock(
    body: str,
    guard_match: re.Match[str],
    statement_start: int,
    statement_end: int,
) -> None:
    """Prove WAIT leaves the bounded reservation wait outside the read lock."""

    function_open = body.find("{")
    wait = one_match_at_depth(
        body,
        re.compile(r"\bret\s*=\s*dma_resv_wait_timeout\s*\("),
        1,
        "wait-idle-flush reservation wait",
    )
    lock = one_match_at_depth(body, READ_LOCK, 1, "wait-idle-flush read lock")
    require_direct_statement(
        body,
        function_open,
        lock.start(),
        "wait-idle-flush read lock",
    )
    placement = one_match_at_depth(
        body,
        re.compile(r"\bcur_placement\s*=\s*READ_ONCE\s*\("),
        1,
        "wait-idle-flush placement read",
    )
    flush = one_match_at_depth(
        body,
        re.compile(r"\bmmio_hdp_flush\s*\("),
        1,
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
        (placement, "wait-idle-flush placement read"),
        (final_unlock, "wait-idle-flush final read unlock"),
    ):
        require_direct_statement(body, function_open, match.start(), label)
    if not (
        wait.start()
        < lock.start()
        < guard_match.start()
        < placement.start()
        < flush.start()
        < final_unlock.start()
    ):
        raise GuardError(
            "wait-idle-flush: expected reservation wait, exclusive lock, "
            "parked guard, placement, flush, and unlock order"
        )
    require_lock_held_at_guard(
        body,
        lock.end(),
        guard_match.start(),
        "wait-idle-flush",
    )
    require_refusal_unlock(
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


def check_command_submission_lock(
    body: str,
    guard_match: re.Match[str],
    statement_start: int,
    statement_end: int,
) -> None:
    """Prove CS lock, refusal, reset, parse, relocation, and schedule order."""

    lock = one_match_at_depth(body, READ_LOCK, 1, "command-submission read lock")
    acceleration = one_match_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*!\s*rdev->accel_working\s*\)"),
        1,
        "command-submission acceleration guard",
    )
    reset = one_match_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*rdev->in_reset\s*\)"),
        1,
        "command-submission reset guard",
    )
    parser_zero = one_match_at_depth(
        body,
        re.compile(r"\bmemset\s*\(\s*&parser\s*,\s*0\s*,"),
        1,
        "command-submission parser zeroing",
    )
    parser_init = one_match_at_depth(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_parser_init\s*"
            r"\(\s*&parser\s*,\s*data\s*\)\s*;"
        ),
        1,
        "command-submission parser initialization",
    )
    ib_fill = one_match_at_depth(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_fill\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        1,
        "command-submission IB fill call",
    )
    relocation_calls = list(
        re.finditer(
            r"\br\s*=\s*radeon_cs_parser_relocs\s*"
            r"\(\s*&parser\s*\)\s*;",
            body,
        )
    )
    if len(relocation_calls) != 1:
        raise GuardError(
            "command-submission relocation call: expected one direct call, "
            f"found {len(relocation_calls)}"
        )
    relocations = relocation_calls[0]
    relocation_guard = one_match_at_depth(
        body,
        re.compile(r"\bif\s*\(\s*!\s*r\s*\)"),
        1,
        "command-submission relocation result guard",
    )
    relocation_start, relocation_end = controlled_statement(
        body,
        relocation_guard.end(),
    )
    if not (
        relocation_start <= relocations.start()
        and relocations.end() <= relocation_end
    ):
        raise GuardError(
            "command-submission relocation call is outside its success guard"
        )
    ib_schedule = one_match_at_depth(
        body,
        re.compile(
            r"\br\s*=\s*radeon_cs_ib_chunk\s*"
            r"\(\s*rdev\s*,\s*&parser\s*\)\s*;"
        ),
        1,
        "command-submission IB schedule call",
    )
    final_unlock = one_match_at_depth(
        body,
        READ_UNLOCK,
        1,
        "command-submission final read unlock",
    )
    if not (
        lock.start()
        < guard_match.start()
        < acceleration.start()
        < reset.start()
        < parser_zero.start()
        < parser_init.start()
        < ib_fill.start()
        < relocations.start()
        < ib_schedule.start()
        < final_unlock.start()
    ):
        raise GuardError(
            "command-submission: lock, parked, acceleration, reset, parser, "
            "relocation, and schedule order differs"
        )
    require_lock_held_at_guard(
        body,
        lock.end(),
        guard_match.start(),
        "command-submission",
    )
    function_open = body.find("{")
    require_direct_statement(
        body,
        function_open,
        lock.start(),
        "command-submission read lock",
    )
    require_direct_statement(
        body,
        function_open,
        acceleration.start(),
        "command-submission acceleration guard",
    )
    require_direct_statement(
        body,
        function_open,
        reset.start(),
        "command-submission reset guard",
    )
    require_direct_statement(
        body,
        function_open,
        parser_zero.start(),
        "command-submission parser zeroing",
    )
    require_direct_statement(
        body,
        function_open,
        parser_init.start(),
        "command-submission parser initialization",
    )
    require_direct_statement(
        body,
        function_open,
        ib_fill.start(),
        "command-submission IB fill call",
    )
    require_direct_statement(
        body,
        function_open,
        relocation_guard.start(),
        "command-submission relocation result guard",
    )
    require_direct_statement(
        body,
        relocation_start,
        relocations.start(),
        "command-submission relocation call",
    )
    require_direct_statement(
        body,
        function_open,
        ib_schedule.start(),
        "command-submission IB schedule call",
    )
    require_direct_statement(
        body,
        function_open,
        final_unlock.start(),
        "command-submission final read unlock",
    )
    require_refusal_unlock(
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
    require_refusal_unlock(
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

    prefix = body[lock.end() : guard_match.start()]
    forbidden_before_parked = (
        "memset",
        "radeon_cs_parser_init",
        "radeon_cs_ib_fill",
        "radeon_cs_parser_relocs",
        "radeon_cs_ib_chunk",
        "radeon_ib_get",
    )
    if any(identifier in prefix for identifier in forbidden_before_parked):
        raise GuardError(
            "command-submission: parser or command work precedes the parked refusal"
        )


def check_dumb_create_propagation(root: Path) -> None:
    """The dumb-create wrapper forwards the creator's errno unchanged.

    radeon_mode_dumb_create funnels into radeon_gem_object_create, whose
    parked refusal is -EIO. A wrapper that translates every failure to
    -ENOMEM still refuses, and the measured RS482 park matrix showed exactly
    that: refusal before allocation with userspace receiving ENOMEM, so a
    caller cannot separate a parked device from memory exhaustion. The
    contract is `if (r) return r;` on the creator's result.
    """
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
    calls = list(
        re.finditer(r"\br\s*=\s*radeon_gem_object_create\s*\(", body)
    )
    if len(calls) != 1:
        raise GuardError(
            "dumb-create: expected one creator result assignment, "
            f"found {len(calls)}"
        )
    result_guards = [
        match
        for match in re.finditer(r"\bif\s*\(\s*r\s*\)", body)
        if match.start() > calls[0].end()
    ]
    if not result_guards:
        raise GuardError(
            "dumb-create: the creator's result is never tested, so a failed "
            "create falls through to handle creation"
        )
    result_guard = result_guards[0]
    require_direct_statement(
        body,
        body.find("{"),
        result_guard.start(),
        "dumb-create: creator result guard",
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
}

DUMB_FIXTURE_GOOD = """
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
\tr = radeon_gem_object_create(rdev, args->size, 0,
\t\t\t\t     RADEON_GEM_DOMAIN_VRAM, 0,
\t\t\t\t     false, &gobj);
\tif (r)
\t\treturn r;
\tr = drm_gem_handle_create(file_priv, gobj, &handle);
\treturn 0;
}
"""

DUMB_FIXTURES_BAD = {
    "result guard controlled by an unbraced unreachable condition": """
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
	r = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
	if (false)
		if (r)
			return r;
	return 0;
}
""",
    "failure return nested in an unreachable block": """
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
	r = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
	if (r) {
		if (false)
			return r;
	}
	return 0;
}
""",
    "failure translated to -ENOMEM": """
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
\tr = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
\tif (r)
\t\treturn -ENOMEM;
\treturn 0;
}
""",
    "failure translated to another errno": """
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
\tr = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
\tif (r)
\t\treturn -EINVAL;
\treturn 0;
}
""",
    "failure answered with success": """
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
\tr = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
\tif (r)
\t\treturn 0;
\treturn 0;
}
""",
    "failure never tested": """
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
\tr = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
\tr = drm_gem_handle_create(file_priv, gobj, &handle);
\treturn 0;
}
""",
}

PRIME_FIXTURE_GOOD = """
struct drm_gem_object *radeon_gem_prime_import_sg_table(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn ERR_PTR(-EIO);
\t}
\tdma_resv_lock(resv, NULL);
\tret = radeon_bo_create(rdev, size, align, false, domain, 0, sg, resv, &bo);
\tdma_resv_unlock(resv);
\tup_read(&rdev->exclusive_lock);
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
        "\tret = radeon_bo_create(rdev, size, align, false, domain, 0, sg, resv, &bo);",
        "\tif (false)\n"
        "\t\tret = radeon_bo_create(rdev, size, align, false, domain, 0, sg, resv, &bo);",
    ),
    "reservation unlock is controlled by an unreachable condition": (
        "\tdma_resv_unlock(resv);",
        "\tif (false)\n\t\tdma_resv_unlock(resv);",
    ),
    "final read unlock is controlled by an unreachable condition": (
        "\tup_read(&rdev->exclusive_lock);\n\treturn &bo->tbo.base;",
        "\tif (false)\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\treturn &bo->tbo.base;",
    ),
}

WAIT_FIXTURE_GOOD = """
int radeon_gem_wait_idle_ioctl(struct drm_device *dev)
{
\tret = dma_resv_wait_timeout(resv, usage, true, timeout);
\tdown_read(&rdev->exclusive_lock);
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\tdrm_gem_object_put(gobj);
\t\treturn -EIO;
\t}
\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);
\tif (rdev->asic->mmio_hdp_flush)
\t\trdev->asic->mmio_hdp_flush(rdev);
\tup_read(&rdev->exclusive_lock);
\treturn r;
}
"""

WAIT_FIXTURE_MUTATIONS = {
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
            "\tret = dma_resv_wait_timeout(resv, usage, true, timeout);\n"
            "\tdown_read(&rdev->exclusive_lock);"
        ),
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tret = dma_resv_wait_timeout(resv, usage, true, timeout);"
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
        "\tret = dma_resv_wait_timeout(resv, usage, true, timeout);",
        "\tif (false)\n"
        "\t\tret = dma_resv_wait_timeout(resv, usage, true, timeout);",
    ),
    "placement read is controlled by an unreachable condition": (
        "\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
        "\tif (false)\n"
        "\t\tcur_placement = READ_ONCE(robj->tbo.resource->mem_type);",
    ),
    "final read unlock is controlled by an unreachable condition": (
        "\tup_read(&rdev->exclusive_lock);\n\treturn r;",
        "\tif (false)\n"
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\treturn r;",
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
\tdev_info(rdev->dev, "//");
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tr = radeon_bo_create(rdev);
\treturn 0;
}
"""

CS_FIXTURE_GOOD = """
int radeon_cs_ioctl(struct drm_device *dev)
{
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
\tr = radeon_cs_parser_init(&parser, data);
\tr = radeon_cs_ib_fill(rdev, &parser);
\tif (!r)
\t\tr = radeon_cs_parser_relocs(&parser);
\tr = radeon_cs_ib_chunk(rdev, &parser);
\tup_read(&rdev->exclusive_lock);
\treturn r;
}
"""

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
        "\tmemset(&parser, 0, sizeof(parser));\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
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
        "\tup_read(&rdev->exclusive_lock);\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
        1,
    ),
    "nested read unlock precedes parked refusal": CS_FIXTURE_GOOD.replace(
        "\tdown_read(&rdev->exclusive_lock);\n"
        "\tif (READ_ONCE(rdev->gpu_parked)) {",
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
            "\tif (false)\n"
            "\t\tr = radeon_cs_parser_init(&parser, data);",
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
            "\t\tif (false)\n"
            "\t\t\tup_read(&rdev->exclusive_lock);\n"
            "\t\treturn -EIO;",
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
            "\t\tif (false) {\n"
            "\t\t\treturn -EBUSY;\n"
            "\t\t}",
            1,
        )
    ),
    "acceleration return is conditional without braces": (
        CS_FIXTURE_GOOD.replace(
            "\t\treturn -EBUSY;",
            "\t\tif (false)\n"
            "\t\t\treturn -EBUSY;",
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
            "\t\t;\n"
            "#if 0\n"
            "\t\treturn -EBUSY;\n"
            "#endif\n"
            "\t\t;",
            1,
        )
    ),
    "reset begins before read unlock": CS_FIXTURE_GOOD.replace(
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\tr = radeon_gpu_reset(rdev);",
        "\t\tr = radeon_gpu_reset(rdev);\n"
        "\t\tup_read(&rdev->exclusive_lock);",
        1,
    ),
    "reset unlock is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\tr = radeon_gpu_reset(rdev);",
        "\t\tif (false) {\n"
        "\t\t\tup_read(&rdev->exclusive_lock);\n"
        "\t\t}\n"
        "\t\tr = radeon_gpu_reset(rdev);",
        1,
    ),
    "reset unlock is conditional without braces": CS_FIXTURE_GOOD.replace(
        "\tif (rdev->in_reset) {\n"
        "\t\tup_read(&rdev->exclusive_lock);",
        "\tif (rdev->in_reset) {\n"
        "\t\tif (false)\n"
        "\t\t\tup_read(&rdev->exclusive_lock);",
        1,
    ),
    "reset call is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\t\tr = radeon_gpu_reset(rdev);\n"
        "\t\tif (!r)",
        "\t\tif (false) {\n"
        "\t\t\tr = radeon_gpu_reset(rdev);\n"
        "\t\t}\n"
        "\t\tif (!r)",
        1,
    ),
    "reset return is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\t\treturn r;\n"
        "\t}",
        "\t\tif (false) {\n"
        "\t\t\treturn r;\n"
        "\t\t}\n"
        "\t}",
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
        "\tif (false) {\n"
        "\t\tr = radeon_cs_ib_fill(rdev, &parser);\n"
        "\t}",
        1,
    ),
    "IB fill call is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tr = radeon_cs_ib_fill(rdev, &parser);",
            "\tif (false)\n"
            "\t\tr = radeon_cs_ib_fill(rdev, &parser);",
            1,
        )
    ),
    "relocation call is nested in an unreachable block": (
        CS_FIXTURE_GOOD.replace(
            "\tif (!r)\n"
            "\t\tr = radeon_cs_parser_relocs(&parser);",
            "\tif (!r) {\n"
            "\t\tif (false) {\n"
            "\t\t\tr = radeon_cs_parser_relocs(&parser);\n"
            "\t\t}\n"
            "\t}",
            1,
        )
    ),
    "relocation guard is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tif (!r)\n"
            "\t\tr = radeon_cs_parser_relocs(&parser);",
            "\tif (false)\n"
            "\t\tif (!r)\n"
            "\t\t\tr = radeon_cs_parser_relocs(&parser);",
            1,
        )
    ),
    "IB schedule call is nested in an unreachable block": CS_FIXTURE_GOOD.replace(
        "\tr = radeon_cs_ib_chunk(rdev, &parser);",
        "\tif (false) {\n"
        "\t\tr = radeon_cs_ib_chunk(rdev, &parser);\n"
        "\t}",
        1,
    ),
    "IB schedule call is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tr = radeon_cs_ib_chunk(rdev, &parser);",
            "\tif (false)\n"
            "\t\tr = radeon_cs_ib_chunk(rdev, &parser);",
            1,
        )
    ),
    "final unlock is controlled by an unreachable condition": (
        CS_FIXTURE_GOOD.replace(
            "\tup_read(&rdev->exclusive_lock);\n\treturn r;",
            "\tif (false)\n"
            "\t\tup_read(&rdev->exclusive_lock);\n"
            "\treturn r;",
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
        "\tdown_read(&rdev->exclusive_lock);\n"
        "\tgoto bypass_parked_refusal;\n",
        1,
    ).replace(
        "\tif (!rdev->accel_working) {",
        "bypass_parked_refusal:\n\tif (!rdev->accel_working) {",
        1,
    ),
}


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
    }
    for name, fixture in good.items():
        (tmp / "radeon_gem.c").write_text(fixture, encoding="utf-8")
        try:
            check_guard(tmp, spec)
            print(f"selftest known-good accepted: {name}")
        except GuardError as exc:
            print(f"selftest known-good REJECTED: {name}: {exc}", file=sys.stderr)
            failures += 1

    for name, fixture in FIXTURES_BAD.items():
        (tmp / "radeon_gem.c").write_text(fixture, encoding="utf-8")
        try:
            check_guard(tmp, spec)
        except GuardError:
            print(f"selftest known-bad rejected: {name}")
        else:
            print(f"selftest known-bad ACCEPTED: {name}", file=sys.stderr)
            failures += 1

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
        except GuardError:
            print(f"selftest known-bad rejected: dumb-create {name}")
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
        path.write_text(good_fixture, encoding="ascii")
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
            path.write_text(good_fixture.replace(old, new, 1), encoding="ascii")
            try:
                check_guard(tmp, locked_spec)
            except GuardError:
                print(f"selftest known-bad rejected: {locked_spec['id']} {name}")
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
        except GuardError:
            print(f"selftest known-bad rejected: command-submission {name}")
        else:
            print(
                f"selftest known-bad ACCEPTED: command-submission {name}",
                file=sys.stderr,
            )
            failures += 1

    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    good_count = len(good) + 2 + len(locked_fixtures)
    bad_count = (
        len(FIXTURES_BAD)
        + len(DUMB_FIXTURES_BAD)
        + len(CS_FIXTURES_BAD)
        + sum(len(mutations) for _, _, mutations in locked_fixtures)
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
    for guard in GUARDS:
        try:
            check_guard(args.root, guard)
        except GuardError as exc:
            print(f"FAIL {exc}", file=sys.stderr)
            failures += 1
        else:
            print(f"ok {guard['id']}: refuses before {guard['precedes']}")

    try:
        check_dumb_create_propagation(args.root)
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
