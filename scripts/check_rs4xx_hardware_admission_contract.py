#!/usr/bin/env python3
"""Prove the finite RS4xx hardware admission and terminal-state contract.

The transaction helpers are the admission roots for hardware work that can
reach the RS400 or RS480 aperture. The denominator is the direct call graph
in the Radeon subtree: twelve operational callers, two retry helpers, and the
three inline lock helpers. The BO constructor and destructor are roots because
they can allocate, bind, unbind, or retain TTM state after an outer entrypoint
has admitted its work. Every operational caller rejects a failed begin,
balances a successful begin with an end after its final hardware operation,
and keeps the hardware operation after admission. The parked latch remains a
terminal -EIO outcome at the central root. Five direct latch callers cover
teardown refusal, full parked-state publication, reset ring-restore failure,
RS400 initialization reset failure, and CP microengine restore failure. Four
teardown refusal callers cover BO destruction, TTM backend unbind, TTM
unpopulation, and GEM object release.
The refusal wrapper latches before it records pending publication, and the
publisher drains admitted transactions and readers before CPU-only cleanup.
The work item coalesces a running publisher, and terminal quiescence disables
the work item before its lifetime flag closes. The display modeset keeps its
terminal no-op behavior.

The checker is source static. It does not promote compile-verified source to
a hardware verdict. Its selftest mutates the root, rollback, terminal, and
caller fixtures so a green result demonstrates discrimination against the
known-bad mutations.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SUBTREE = Path("drivers/gpu/drm/radeon")

TRANSACTION_BEGIN = "radeon_rs4xx_hardware_transaction_begin"
TRANSACTION_WAIT_BEGIN = "radeon_rs4xx_hardware_transaction_wait_begin"
TRANSACTION_TRY_BEGIN = "radeon_rs4xx_hardware_transaction_try_begin"
TRANSACTION_END = "radeon_rs4xx_hardware_transaction_end"
READER_BEGIN = "radeon_rs4xx_hardware_reader_begin"
READER_END = "radeon_rs4xx_hardware_reader_end"
ACCESS_BEGIN = "radeon_rs4xx_hardware_access_begin"
ACCESS_END = "radeon_rs4xx_hardware_access_end"
ACCESS_WAIT_BEGIN = "radeon_rs4xx_hardware_access_wait_begin"
INTERNAL_ACCESS_BEGIN = "__radeon_rs4xx_hardware_access_begin"
INTERNAL_ACCESS_END = "__radeon_rs4xx_hardware_access_end"
LATCH_PARKED = "radeon_rs4xx_latch_parked_state"
PUBLISH_PARKED = "radeon_rs4xx_publish_parked_state"
QUEUE_PARKED = "radeon_rs4xx_queue_parked_publish"
PUBLISH_WORK = "radeon_rs4xx_parked_publish_work"
TERMINAL_QUIESCE = "radeon_rs4xx_terminal_quiesce"
REFUSAL_LATCH = "radeon_rs4xx_latch_teardown_refusal"


@dataclass(frozen=True)
class TransactionRoot:
    """One direct operational transaction admission root."""

    identifier: str
    path: Path
    function: str
    begin: str
    end_count: int
    side_effect: str
    failure_pattern: str


ROOTS = (
    TransactionRoot(
        "gem-fault",
        SUBTREE / "radeon_gem.c",
        "radeon_gem_fault",
        TRANSACTION_BEGIN,
        1,
        "ttm_bo_vm_fault_reserved",
        r"if \( radeon_rs4xx_hardware_transaction_begin \( rdev \) \) .*?"
        r"ret = VM_FAULT_SIGBUS ; goto unlock_resv ; \} hardware_transaction = true ;",
    ),
    TransactionRoot(
        "gem-vm-access",
        SUBTREE / "radeon_gem.c",
        "radeon_gem_vm_access",
        TRANSACTION_BEGIN,
        1,
        "ttm_bo_vm_access",
        r"ret = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( ret \) return ret ; .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    ),
    TransactionRoot(
        "gem-object-free",
        SUBTREE / "radeon_gem.c",
        "radeon_gem_object_free",
        TRANSACTION_WAIT_BEGIN,
        1,
        "ttm_bo_fini",
        r"ret = radeon_rs4xx_hardware_transaction_wait_begin \( rdev \) ; "
        r"if \( ret == - ESHUTDOWN \) ret = radeon_rs4xx_gart_teardown_wait "
        r"\( rdev \) ; else if \( ret == 0 \) hardware_transaction = true ; .*?"
        r"if \( ret \) \{.*?radeon_rs4xx_retain_bo \( robj \) .*?"
        r"radeon_rs4xx_latch_teardown_refusal \( rdev \) .*?"
        r"radeon_mn_unregister \( robj \) ; return ; \} .*?"
        r"radeon_mn_unregister \( robj \) ; .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    ),
    TransactionRoot(
        "prime-pin",
        SUBTREE / "radeon_prime.c",
        "radeon_gem_prime_pin",
        TRANSACTION_BEGIN,
        1,
        "radeon_bo_pin",
        r"ret = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( ret \) return ret ; .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    ),
    TransactionRoot(
        "prime-unpin",
        SUBTREE / "radeon_prime.c",
        "radeon_gem_prime_unpin",
        TRANSACTION_BEGIN,
        1,
        "radeon_bo_unpin",
        r"if \( radeon_rs4xx_hardware_transaction_begin \( rdev \) \) "
        r"return ; .*?radeon_bo_unpin .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    ),
    TransactionRoot(
        "cursor-set",
        SUBTREE / "radeon_cursor.c",
        "radeon_crtc_cursor_set2",
        TRANSACTION_BEGIN,
        2,
        "radeon_lock_cursor",
        r"ret = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( ret \) goto out_exec ; hardware_transaction = true ;.*?"
        r"ret = 0 ; radeon_rs4xx_hardware_transaction_end \( rdev \) ; "
        r"hardware_transaction = false ;.*?"
        r"out_exec :.*?if \( hardware_transaction \) "
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;.*?return ret ;",
    ),
    TransactionRoot(
        "modeset-config",
        SUBTREE / "radeon_display.c",
        "radeon_crtc_set_config",
        TRANSACTION_BEGIN,
        2,
        "drm_crtc_helper_set_config",
        r"ret = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( ret \) \{ .*? return ret ; \} .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    ),
    TransactionRoot(
        "fbdev-destroy",
        SUBTREE / "radeon_fbdev.c",
        "radeon_fbdev_destroy_pinned_object",
        TRANSACTION_BEGIN,
        1,
        "radeon_bo_unreserve",
        r"ret = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( ret \) \{ .*?drm_gem_object_put \( gobj \) ; return ; \} .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    ),
    TransactionRoot(
        "ttm-bo-move",
        SUBTREE / "radeon_ttm.c",
        "radeon_bo_move",
        TRANSACTION_BEGIN,
        1,
        "radeon_bo_move_notify",
        r"r = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( r \) return r ; .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ; return r ;",
    ),
    TransactionRoot(
        "ttm-tt-unpopulate",
        SUBTREE / "radeon_ttm.c",
        "radeon_ttm_tt_unpopulate",
        TRANSACTION_WAIT_BEGIN,
        1,
        "radeon_ttm_tt_unbind_status",
        r"r = radeon_rs4xx_hardware_transaction_wait_begin \( rdev \) ; "
        r"if \( r == - ESHUTDOWN \) r = radeon_rs4xx_gart_teardown_wait "
        r"\( rdev \) ; else if \( r == 0 \) hardware_transaction = true ; "
        r"if \( r \) \{ radeon_rs4xx_latch_teardown_refusal \( rdev \) ; "
        r"if \( gtt && gtt -> bound && radeon_rs4xx_hardware_target "
        r"\( rdev \) \) radeon_rs4xx_retain_ttm \( rdev , gtt \) ; "
        r"return ; \} r = radeon_ttm_tt_unbind_status \( bdev , ttm \) ; "
        r"if \( hardware_transaction \) radeon_rs4xx_hardware_transaction_end "
        r"\( rdev \) ;",
    ),
    TransactionRoot(
        "bo-create",
        SUBTREE / "radeon_object.c",
        "radeon_bo_create",
        TRANSACTION_BEGIN,
        1,
        "ttm_bo_init_validate",
        r"r = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( r \) return r ; .*?"
        r"ttm_bo_init_validate .*? & radeon_ttm_bo_destroy .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ; return r ;",
    ),
    TransactionRoot(
        "ttm-bo-destroy",
        SUBTREE / "radeon_object.c",
        "radeon_ttm_bo_destroy",
        TRANSACTION_WAIT_BEGIN,
        1,
        "drm_gem_object_release",
        r"r = radeon_rs4xx_hardware_transaction_wait_begin \( rdev \) ; .*?"
        r"r == - ESHUTDOWN .*? radeon_rs4xx_gart_teardown_wait \( rdev \) .*?"
        r"if \( r \) .*? radeon_rs4xx_retain_bo \( bo \) ; return ;",
    ),
)

# Compatibility for the CS contract checker. Its source guard query now
# projects the centralized lock helper rather than searching for an obsolete
# direct gpu_parked reader in radeon_cs_ioctl.
GUARDS = (
    {
        "id": "command-submission",
        "path": SUBTREE / "radeon_cs.c",
        "function": "radeon_cs_ioctl",
    },
)


@dataclass(frozen=True)
class CToken:
    value: str


@dataclass(frozen=True)
class SourceFunction:
    path: Path
    name: str
    body: tuple[CToken, ...]


class GuardError(Exception):
    """A transaction admission or terminal parked invariant is absent."""


_C_TOKEN = re.compile(
    r"(?P<block_comment>/\*.*?\*/)"
    r"|(?P<line_comment>//[^\n]*)"
    r'|(?P<string>"(?:\\.|[^"\\])*")'
    r"|(?P<character>'(?:\\.|[^'\\])*')"
    r"|(?P<identifier>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<number>0[xX][0-9A-Fa-f]+|[0-9]+)"
    r"|(?P<operator>->|<=|>=|==|!=|&&|\|\||<<|>>|\+\+|--|\+=|-=)"
    r"|(?P<punctuation>[^\s])",
    re.DOTALL,
)
_CONTROL_WORDS = {"if", "for", "while", "switch", "sizeof"}


def c_tokens(source: str) -> tuple[CToken, ...]:
    """Return C tokens while excluding comments and literals."""

    tokens = []
    for match in _C_TOKEN.finditer(source):
        if match.lastgroup in {"block_comment", "line_comment", "string", "character"}:
            continue
        tokens.append(CToken(match.group(0)))
    return tuple(tokens)


def source_paths(root: Path) -> tuple[Path, ...]:
    """Return every C and header file in the Radeon source subtree."""

    directory = root / SUBTREE
    paths = tuple(
        sorted(
            path.relative_to(root)
            for pattern in ("*.c", "*.h")
            for path in directory.glob(pattern)
        )
    )
    if not paths:
        raise GuardError(f"missing Radeon source subtree {directory}")
    return paths


def matching_token(
    tokens: tuple[CToken, ...], start: int, opening: str, closing: str
) -> int:
    """Return the matching closing token index."""

    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].value == opening:
            depth += 1
        elif tokens[index].value == closing:
            depth -= 1
            if depth == 0:
                return index
    raise GuardError(f"unbalanced {opening}{closing} token group")


def source_functions_in_path(root: Path, path: Path) -> tuple[SourceFunction, ...]:
    """Extract every function body from one declared source path."""

    source_path = root / path
    try:
        source = source_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise GuardError(f"missing source {source_path}") from exc
    tokens = c_tokens(source)
    result = []
    index = 0
    while index + 2 < len(tokens):
        name = tokens[index].value
        if (
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            or name in _CONTROL_WORDS
            or tokens[index + 1].value != "("
        ):
            index += 1
            continue
        try:
            close_paren = matching_token(tokens, index + 1, "(", ")")
        except GuardError:
            index += 1
            continue
        if close_paren + 1 >= len(tokens) or tokens[close_paren + 1].value != "{":
            index += 1
            continue
        close_brace = matching_token(tokens, close_paren + 1, "{", "}")
        result.append(
            SourceFunction(
                path,
                name,
                tokens[close_paren + 2 : close_brace],
            )
        )
        index = close_brace + 1
    return tuple(result)


def source_functions(root: Path) -> tuple[SourceFunction, ...]:
    """Extract all function bodies in the finite source surface."""

    return tuple(
        function
        for path in source_paths(root)
        for function in source_functions_in_path(root, path)
    )


def get_function(root: Path, path: Path, name: str) -> SourceFunction:
    """Return one source function from the finite source surface."""

    matches = [
        function
        for function in source_functions_in_path(root, path)
        if function.name == name
    ]
    if len(matches) != 1:
        raise GuardError(f"{path}:{name}: expected one function, found {len(matches)}")
    return matches[0]


def body_text(function: SourceFunction) -> str:
    return " ".join(token.value for token in function.body)


def call_positions(function: SourceFunction, name: str) -> list[int]:
    return [
        index
        for index, token in enumerate(function.body[:-1])
        if token.value == name and function.body[index + 1].value == "("
    ]


def token_position(function: SourceFunction, name: str) -> int:
    positions = call_positions(function, name)
    if not positions:
        raise GuardError(f"{function.path}:{function.name}: {name} is absent")
    return positions[0]


def require_pattern(label: str, text: str, pattern: str) -> None:
    if re.search(pattern, text) is None:
        raise GuardError(f"{label}: transaction failure is not fail closed")


def expected_call_sites() -> dict[tuple[Path, str, str], int]:
    """Return the exact direct transaction call denominator."""

    expected: dict[tuple[Path, str, str], int] = {}
    for root in ROOTS:
        expected[(root.path, root.function, root.begin)] = 1
        expected[(root.path, root.function, TRANSACTION_END)] = root.end_count

    helper_calls = {
        (
            SUBTREE / "radeon_device.c",
            "radeon_rs4xx_hardware_transaction_wait_begin",
            TRANSACTION_BEGIN,
        ): 1,
        (
            SUBTREE / "radeon_device.c",
            "radeon_rs4xx_hardware_transaction_try_begin",
            TRANSACTION_BEGIN,
        ): 1,
        (SUBTREE / "radeon.h", "radeon_device_lock_hardware", TRANSACTION_BEGIN): 1,
        (SUBTREE / "radeon.h", "radeon_device_lock_hardware", TRANSACTION_END): 1,
        (SUBTREE / "radeon.h", "radeon_device_unlock_hardware", TRANSACTION_END): 1,
        (
            SUBTREE / "radeon.h",
            "radeon_device_trylock_hardware",
            TRANSACTION_TRY_BEGIN,
        ): 1,
        (SUBTREE / "radeon.h", "radeon_device_trylock_hardware", TRANSACTION_END): 2,
    }
    for key, count in helper_calls.items():
        expected[key] = count
    return expected


def expected_latch_call_sites() -> dict[tuple[Path, str, str], int]:
    """Return the exact direct parked-latch call denominator."""

    return {
        (
            SUBTREE / "radeon_device.c",
            "radeon_rs4xx_latch_teardown_refusal",
            LATCH_PARKED,
        ): 1,
        (
            SUBTREE / "radeon_device.c",
            PUBLISH_PARKED,
            LATCH_PARKED,
        ): 1,
        (
            SUBTREE / "radeon_device.c",
            "radeon_gpu_reset_internal",
            LATCH_PARKED,
        ): 1,
        (
            SUBTREE / "radeon_rs4xx_dev.c",
            "rs480_cp_me_ram_inject_one",
            LATCH_PARKED,
        ): 1,
        (SUBTREE / "rs400.c", "rs400_init", LATCH_PARKED): 1,
    }


def expected_refusal_latch_call_sites() -> dict[tuple[Path, str, str], int]:
    """Return the exact teardown refusal wrapper caller denominator."""

    return {
        (SUBTREE / "radeon_gem.c", "radeon_gem_object_free", REFUSAL_LATCH): 1,
        (SUBTREE / "radeon_object.c", "radeon_ttm_bo_destroy", REFUSAL_LATCH): 1,
        (SUBTREE / "radeon_ttm.c", "radeon_ttm_backend_unbind", REFUSAL_LATCH): 1,
        (SUBTREE / "radeon_ttm.c", "radeon_ttm_tt_unpopulate", REFUSAL_LATCH): 1,
    }


def expected_reader_call_sites() -> dict[tuple[Path, str, str], int]:
    """Return the exact direct reader-core call denominator."""

    return {
        (
            SUBTREE / "radeon_device.c",
            INTERNAL_ACCESS_BEGIN,
            READER_BEGIN,
        ): 1,
        (SUBTREE / "radeon_device.c", ACCESS_WAIT_BEGIN, READER_BEGIN): 1,
        (SUBTREE / "radeon_device.c", INTERNAL_ACCESS_END, READER_END): 1,
    }


def check_call_denominator(root: Path) -> None:
    """Reject missing, extra, or multiply counted transaction call sites."""

    expected = expected_call_sites()
    actual: dict[tuple[Path, str, str], int] = {}
    for function in source_functions(root):
        for name in (
            TRANSACTION_BEGIN,
            TRANSACTION_WAIT_BEGIN,
            TRANSACTION_TRY_BEGIN,
            TRANSACTION_END,
        ):
            count = len(call_positions(function, name))
            if count:
                actual[(function.path, function.name, name)] = count
    if actual != expected:
        missing = sorted(set(expected) - set(actual), key=str)
        extra = sorted(set(actual) - set(expected), key=str)
        changed = sorted(
            key for key in set(expected) & set(actual) if expected[key] != actual[key]
        )
        details = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"extra {extra}")
        if changed:
            details.append(
                "counts " + str([(key, expected[key], actual[key]) for key in changed])
            )
        raise GuardError("transaction call denominator differs: " + "; ".join(details))


def check_latch_call_denominator(root: Path) -> None:
    """Reject missing, extra, or multiply counted direct parked-latch calls."""

    expected = expected_latch_call_sites()
    actual: dict[tuple[Path, str, str], int] = {}
    for function in source_functions(root):
        count = len(call_positions(function, LATCH_PARKED))
        if count:
            actual[(function.path, function.name, LATCH_PARKED)] = count
    if actual != expected:
        missing = sorted(set(expected) - set(actual), key=str)
        extra = sorted(set(actual) - set(expected), key=str)
        changed = sorted(
            key for key in set(expected) & set(actual) if expected[key] != actual[key]
        )
        details = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"extra {extra}")
        if changed:
            details.append(
                "counts " + str([(key, expected[key], actual[key]) for key in changed])
            )
        raise GuardError("parked-latch call denominator differs: " + "; ".join(details))


def check_refusal_latch_call_denominator(root: Path) -> None:
    """Reject missing, extra, or multiply counted refusal wrapper callers."""

    expected = expected_refusal_latch_call_sites()
    actual: dict[tuple[Path, str, str], int] = {}
    for function in source_functions(root):
        count = len(call_positions(function, REFUSAL_LATCH))
        if count:
            actual[(function.path, function.name, REFUSAL_LATCH)] = count
    if actual != expected:
        missing = sorted(set(expected) - set(actual), key=str)
        extra = sorted(set(actual) - set(expected), key=str)
        changed = sorted(
            key for key in set(expected) & set(actual) if expected[key] != actual[key]
        )
        details = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"extra {extra}")
        if changed:
            details.append(
                "counts " + str([(key, expected[key], actual[key]) for key in changed])
            )
        raise GuardError(
            "teardown refusal latch call denominator differs: " + "; ".join(details)
        )


def check_reader_call_denominator(root: Path) -> None:
    """Reject missing, extra, or multiply counted direct reader-core calls."""

    expected = expected_reader_call_sites()
    actual: dict[tuple[Path, str, str], int] = {}
    for function in source_functions(root):
        for name in (READER_BEGIN, READER_END):
            count = len(call_positions(function, name))
            if count:
                actual[(function.path, function.name, name)] = count
    if actual != expected:
        missing = sorted(set(expected) - set(actual), key=str)
        extra = sorted(set(actual) - set(expected), key=str)
        changed = sorted(
            key for key in set(expected) & set(actual) if expected[key] != actual[key]
        )
        details = []
        if missing:
            details.append(f"missing {missing}")
        if extra:
            details.append(f"extra {extra}")
        if changed:
            details.append(
                "counts " + str([(key, expected[key], actual[key]) for key in changed])
            )
        raise GuardError("reader-core call denominator differs: " + "; ".join(details))


def check_root(root: Path, spec: TransactionRoot) -> None:
    function = get_function(root, spec.path, spec.function)
    text = body_text(function)
    begins = call_positions(function, spec.begin)
    ends = call_positions(function, TRANSACTION_END)
    if len(begins) != 1:
        raise GuardError(
            f"{spec.identifier}: expected one {spec.begin} call, found {len(begins)}"
        )
    if len(ends) != spec.end_count:
        raise GuardError(
            f"{spec.identifier}: expected {spec.end_count} transaction end calls, "
            f"found {len(ends)}"
        )
    side_effect_positions = call_positions(function, spec.side_effect)
    if not side_effect_positions:
        raise GuardError(
            f"{spec.identifier}: final hardware operation {spec.side_effect} is absent"
        )
    side_effect = side_effect_positions[-1]
    if begins[0] > side_effect:
        raise GuardError(
            f"{spec.identifier}: transaction admission follows {spec.side_effect}"
        )
    if any(end <= side_effect for end in ends):
        raise GuardError(
            f"{spec.identifier}: transaction end precedes final "
            f"{spec.side_effect} operation"
        )
    require_pattern(spec.identifier, text, spec.failure_pattern)
    if spec.identifier == "modeset-config":
        require_pattern(
            "modeset transaction end branches",
            text,
            r"if \( active && ! rdev -> have_disp_power_ref \) \{.*?"
            r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;.*?return ret ; \}.*?"
            r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;.*?return ret ;",
        )


def check_bo_create(root: Path) -> None:
    """Keep constructor admission and the counted TTM lifetime adjacent."""

    function = get_function(root, SUBTREE / "radeon_object.c", "radeon_bo_create")
    text = body_text(function)
    begin = token_position(function, TRANSACTION_BEGIN)
    allocation = token_position(function, "kzalloc")
    validation = token_position(function, "ttm_bo_init_validate")
    end = token_position(function, TRANSACTION_END)
    if not begin < allocation < validation < end:
        raise GuardError(
            "bo-create: admission, allocation, validation, and transaction end order differs"
        )
    require_pattern(
        "bo-create live denominator",
        text,
        r"bo -> rs4xx_lifetime_counted = true ; "
        r"atomic_inc \( & rdev -> rs4xx_live_bos \) ;",
    )
    require_pattern(
        "bo-create destructor callback",
        text,
        r"ttm_bo_init_validate .*? & radeon_ttm_bo_destroy .*?\)",
    )


def check_bo_destroy(root: Path) -> None:
    """Keep delayed destruction, refusal retention, and final counting ordered."""

    function = get_function(root, SUBTREE / "radeon_object.c", "radeon_ttm_bo_destroy")
    text = body_text(function)
    wait_begin = token_position(function, TRANSACTION_WAIT_BEGIN)
    gart_wait = token_position(function, "radeon_rs4xx_gart_teardown_wait")
    release = token_position(function, "drm_gem_object_release")
    if not wait_begin < gart_wait < release:
        raise GuardError("ttm-bo-destroy: teardown wait does not precede final release")
    retained = text.find(
        "if ( READ_ONCE ( bo -> rs4xx_terminally_retained ) ) return ;"
    )
    if retained < 0 or retained > text.find("kfree ( bo )"):
        raise GuardError("ttm-bo-destroy: terminal retention does not precede free")
    require_pattern(
        "ttm-bo-destroy refusal retention",
        text,
        r"if \( r \) .*? radeon_rs4xx_latch_teardown_refusal \( rdev \) .*?"
        r"radeon_rs4xx_retain_bo \( bo \) ; return ;",
    )
    require_pattern(
        "ttm-bo-destroy live decrement wake",
        text,
        r"kfree \( bo \) ; .*?"
        r"atomic_dec_and_test \( & rdev -> rs4xx_live_bos \) .*?"
        r"wake_up_all \( & rdev -> rs4xx_hardware_wait \)",
    )


def check_bo_move(root: Path) -> None:
    """Keep fence wait and replacement-binding rollback before transaction end."""

    function = get_function(root, SUBTREE / "radeon_ttm.c", "radeon_bo_move")
    text = body_text(function)
    wait = token_position(function, "ttm_bo_wait_ctx")
    bind = token_position(function, "radeon_ttm_tt_bind")
    unbinds = call_positions(function, "radeon_ttm_tt_unbind_status")
    end = token_position(function, TRANSACTION_END)
    values = tuple(token.value for token in function.body)
    rollback_guard = next(
        (
            index
            for index in range(len(values) - 4)
            if values[index : index + 5] == ("if", "(", "r", "&&", "newly_bound")
        ),
        -1,
    )
    if wait > bind:
        raise GuardError("ttm-bo-move: reservation wait follows TT binding")
    if rollback_guard < 0 or len(unbinds) < 2:
        raise GuardError("ttm-bo-move: newly-bound rollback is absent")
    if not unbinds[-1] > rollback_guard:
        raise GuardError(
            "ttm-bo-move: rollback unbind does not follow the failure guard"
        )
    if not unbinds[-1] < end:
        raise GuardError("ttm-bo-move: rollback unbind follows transaction end")
    require_pattern(
        "ttm-bo-move newly-bound marker",
        text,
        r"newly_bound = radeon_rs4xx_hardware_target \( rdev \) && "
        r"! radeon_ttm_tt_is_bound \( bo -> bdev , bo -> ttm \) ; .*?"
        r"radeon_ttm_tt_bind \( bo -> bdev , bo -> ttm , new_mem \) ;",
    )
    require_pattern(
        "ttm-bo-move rollback result",
        text,
        r"rollback_result = radeon_ttm_tt_unbind_status \( bo -> bdev , bo -> ttm \) ; "
        r"if \( rollback_result \) r = rollback_result ;",
    )


def check_transaction_begin(root: Path) -> None:
    function = get_function(root, SUBTREE / "radeon_device.c", TRANSACTION_BEGIN)
    text = body_text(function)
    parked = "READ_ONCE ( rdev -> gpu_parked )"
    first_parked = text.find(parked)
    increment = text.find("atomic_inc ( & rdev -> rs4xx_hardware_transactions )")
    if first_parked < 0 or increment < 0 or first_parked > increment:
        raise GuardError("transaction-begin: parked refusal does not precede increment")
    require_pattern(
        "transaction-begin parked refusal",
        text,
        r"if \( READ_ONCE \( rdev -> gpu_parked \) \) return - EIO ;",
    )
    if text.count(parked) < 2:
        raise GuardError(
            "transaction-begin: post-increment parked revalidation is absent"
        )
    if "needs_reset" in text:
        raise GuardError(
            "transaction-begin: reset-progress state replaces terminal parking"
        )
    require_pattern(
        "transaction-begin state refusal",
        text,
        r"state != RADEON_RS4XX_HARDWARE_RUNNING .*?"
        r"radeon_rs4xx_hardware_state_errno \( state \)",
    )
    require_pattern(
        "transaction-begin closing refusal",
        text,
        r"state == RADEON_RS4XX_HARDWARE_RUNNING .*?"
        r"rs4xx_hardware_closing .*? return - EBUSY ;",
    )
    require_pattern(
        "transaction-begin post-increment parked revalidation",
        text,
        r"atomic_inc \( & rdev -> rs4xx_hardware_transactions \) ; "
        r"smp_mb__after_atomic \( \) ; "
        r"state = atomic_read \( & rdev -> rs4xx_hardware_state \) ; .*?"
        r"state == RADEON_RS4XX_HARDWARE_RUNNING && "
        r"! READ_ONCE \( rdev -> gpu_parked \) && .*?return 0 ;",
    )
    require_pattern(
        "transaction-begin rollback",
        text,
        r"smp_mb__after_atomic \( \) .*?"
        r"atomic_dec_and_test \( & rdev -> rs4xx_hardware_transactions \) .*?"
        r"radeon_rs4xx_hardware_state_errno \( state \)",
    )
    require_pattern(
        "transaction-begin rollback publication",
        text,
        r"if \( atomic_dec_and_test \( & rdev -> rs4xx_hardware_transactions \) \) "
        r"\{ wake_up_all \( & rdev -> rs4xx_hardware_wait \) ; "
        r"radeon_rs4xx_queue_parked_publish \( rdev \) ; \}",
    )
    post_increment_state = text.find(
        "state = atomic_read ( & rdev -> rs4xx_hardware_state )", increment
    )
    post_increment_success = text.find("return 0 ;", increment)
    if post_increment_state < 0 or post_increment_success < post_increment_state:
        raise GuardError("transaction-begin: success returns before validation")


def check_transaction_wait_begin(root: Path) -> None:
    function = get_function(root, SUBTREE / "radeon_device.c", TRANSACTION_WAIT_BEGIN)
    text = body_text(function)
    require_pattern(
        "transaction-wait-begin retry",
        text,
        r"for \( ; ; \) .*? radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( r != - EBUSY && r != - EHOSTDOWN \) return r ;",
    )
    require_pattern(
        "transaction-wait-begin disposition",
        text,
        r"wait_event \( rdev -> rs4xx_hardware_wait .*?"
        r"radeon_rs4xx_hardware_disposition_available \( rdev \)",
    )
    if call_positions(function, TRANSACTION_END):
        raise GuardError("transaction-wait-begin: retry helper ends no transaction")


def check_transaction_try_begin(root: Path) -> None:
    function = get_function(root, SUBTREE / "radeon_device.c", TRANSACTION_TRY_BEGIN)
    text = body_text(function)
    if text != "return radeon_rs4xx_hardware_transaction_begin ( rdev ) ;":
        raise GuardError("transaction-try-begin: try root diverges from begin root")


def check_transaction_end(root: Path) -> None:
    function = get_function(root, SUBTREE / "radeon_device.c", TRANSACTION_END)
    text = body_text(function)
    require_pattern(
        "transaction-end underflow",
        text,
        r"WARN_ON_ONCE \( atomic_read \( & rdev -> rs4xx_hardware_transactions \) <= 0 \)"
        r" \) return ;",
    )
    require_pattern(
        "transaction-end decrement",
        text,
        r"atomic_dec_and_test \( & rdev -> rs4xx_hardware_transactions \) .*?"
        r"wake_up_all \( & rdev -> rs4xx_hardware_wait \)",
    )
    require_pattern(
        "transaction-end publication",
        text,
        r"if \( atomic_dec_and_test \( & rdev -> rs4xx_hardware_transactions \) \) "
        r"\{ wake_up_all \( & rdev -> rs4xx_hardware_wait \) ; "
        r"radeon_rs4xx_queue_parked_publish \( rdev \) ; \}",
    )


def check_reader_begin(root: Path) -> None:
    """Prove reader admission, revalidation, and failed-admission rollback."""

    function = get_function(root, SUBTREE / "radeon_device.c", READER_BEGIN)
    text = body_text(function)
    markers = (
        "atomic_read_acquire ( & rdev -> rs4xx_hardware_state )",
        "READ_ONCE ( rdev -> gpu_parked )",
        "atomic_inc ( & rdev -> rs4xx_hardware_readers )",
        "smp_mb__after_atomic ( )",
        "atomic_read ( & rdev -> rs4xx_hardware_state )",
        "atomic_dec_and_test ( & rdev -> rs4xx_hardware_readers )",
        "wake_up_all ( & rdev -> rs4xx_hardware_wait )",
    )
    positions = tuple(text.find(marker) for marker in markers)
    if any(position < 0 for position in positions):
        raise GuardError("reader-begin: one or more admission operations are absent")
    if positions != tuple(sorted(positions)):
        raise GuardError("reader-begin: admission operations are out of order")
    require_pattern(
        "reader-begin parked refusal",
        text,
        r"if \( READ_ONCE \( rdev -> gpu_parked \) \) return - EIO ;",
    )
    require_pattern(
        "reader-begin state refusal",
        text,
        r"state != RADEON_RS4XX_HARDWARE_RUNNING && "
        r"! radeon_rs4xx_hardware_transition_owner_admitted \( rdev , state \) "
        r"\) return radeon_rs4xx_hardware_state_errno \( state \) ;",
    )
    require_pattern(
        "reader-begin post-increment validation",
        text,
        r"atomic_inc \( & rdev -> rs4xx_hardware_readers \) ; "
        r"smp_mb__after_atomic \( \) ; "
        r"state = atomic_read \( & rdev -> rs4xx_hardware_state \) ; "
        r"if \( \( likely \( state == RADEON_RS4XX_HARDWARE_RUNNING \) && "
        r"! READ_ONCE \( rdev -> gpu_parked \) \) \|\| "
        r"radeon_rs4xx_hardware_transition_owner_admitted \( rdev , state \) "
        r"\) return 0 ;",
    )
    require_pattern(
        "reader-begin rollback",
        text,
        r"atomic_dec_and_test \( & rdev -> rs4xx_hardware_readers \) .*?"
        r"wake_up_all \( & rdev -> rs4xx_hardware_wait \) ; "
        r"return radeon_rs4xx_hardware_state_errno \( state \) ;",
    )


def check_reader_end(root: Path) -> None:
    """Prove reader release rejects underflow and wakes the transition owner."""

    function = get_function(root, SUBTREE / "radeon_device.c", READER_END)
    text = body_text(function)
    require_pattern(
        "reader-end underflow",
        text,
        r"WARN_ON_ONCE \( atomic_read \( & rdev -> rs4xx_hardware_readers \) "
        r"<= 0 \) \) return ;",
    )
    require_pattern(
        "reader-end decrement",
        text,
        r"atomic_dec_and_test \( & rdev -> rs4xx_hardware_readers \) .*?"
        r"wake_up_all \( & rdev -> rs4xx_hardware_wait \)",
    )


def check_access_helpers(root: Path) -> None:
    """Prove public access wrappers preserve the reader-core result and balance."""

    internal_begin = get_function(
        root, SUBTREE / "radeon_device.c", INTERNAL_ACCESS_BEGIN
    )
    internal_end = get_function(root, SUBTREE / "radeon_device.c", INTERNAL_ACCESS_END)
    wait_begin = get_function(root, SUBTREE / "radeon_device.c", ACCESS_WAIT_BEGIN)
    public_begin = get_function(root, SUBTREE / "radeon.h", ACCESS_BEGIN)
    public_end = get_function(root, SUBTREE / "radeon.h", ACCESS_END)
    if body_text(internal_begin) != f"return {READER_BEGIN} ( rdev ) ;":
        raise GuardError("access-begin: internal wrapper changes the reader result")
    if body_text(internal_end) != f"{READER_END} ( rdev ) ;":
        raise GuardError("access-end: internal wrapper differs from reader release")
    if body_text(public_begin) != (
        "if ( ! radeon_rs4xx_hardware_target ( rdev ) ) return 0 ; "
        f"return {INTERNAL_ACCESS_BEGIN} ( rdev ) ;"
    ):
        raise GuardError("access-begin: public target projection differs")
    if body_text(public_end) != (
        f"if ( radeon_rs4xx_hardware_target ( rdev ) ) {INTERNAL_ACCESS_END} ( rdev ) ;"
    ):
        raise GuardError("access-end: public target projection differs")
    wait_text = body_text(wait_begin)
    require_pattern(
        "access-wait-begin retry",
        wait_text,
        r"for \( ; ; \) .*? radeon_rs4xx_hardware_reader_begin \( rdev \) ; "
        r"if \( r != - EBUSY && r != - EHOSTDOWN \) return r ;",
    )
    require_pattern(
        "access-wait-begin disposition",
        wait_text,
        r"wait_event \( rdev -> rs4xx_hardware_wait .*?"
        r"radeon_rs4xx_hardware_disposition_available \( rdev \)",
    )
    if call_positions(wait_begin, READER_END):
        raise GuardError("access-wait-begin: retry helper releases no reader")


def check_inline_lock_helpers(root: Path) -> None:
    lock = get_function(root, SUBTREE / "radeon.h", "radeon_device_lock_hardware")
    unlock = get_function(root, SUBTREE / "radeon.h", "radeon_device_unlock_hardware")
    trylock = get_function(root, SUBTREE / "radeon.h", "radeon_device_trylock_hardware")
    lock_text = body_text(lock)
    unlock_text = body_text(unlock)
    try_text = body_text(trylock)
    require_pattern(
        "lock helper failure",
        lock_text,
        r"r = radeon_rs4xx_hardware_transaction_begin \( rdev \) ; "
        r"if \( r \) return r ;",
    )
    require_pattern(
        "lock helper rollback",
        lock_text,
        r"if \( r \) up_read \( & rdev -> exclusive_lock \) ; "
        r"if \( r \) radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    )
    require_pattern(
        "unlock helper balance",
        unlock_text,
        r"if \( ! radeon_rs4xx_hardware_transition_owned \( rdev \) \) "
        r"up_read \( & rdev -> exclusive_lock \) ; "
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ;",
    )
    require_pattern(
        "trylock helper failure",
        try_text,
        r"r = radeon_rs4xx_hardware_transaction_try_begin \( rdev \) ; "
        r"if \( r \) return r ; .*?"
        r"! down_read_trylock \( & rdev -> exclusive_lock \) .*?"
        r"radeon_rs4xx_hardware_transaction_end \( rdev \) ; return - EBUSY ;",
    )
    if try_text.count(TRANSACTION_END) != 2:
        raise GuardError("trylock helper: failed paths do not end the transaction")


def check_terminal_parked_state(root: Path) -> None:
    begin = get_function(root, SUBTREE / "radeon_device.c", TRANSACTION_BEGIN)
    disposition = get_function(
        root, SUBTREE / "radeon_device.c", "radeon_rs4xx_hardware_disposition_available"
    )
    latch = get_function(root, SUBTREE / "radeon_device.c", LATCH_PARKED)
    publish = get_function(root, SUBTREE / "radeon_device.c", PUBLISH_PARKED)
    reset = get_function(root, SUBTREE / "radeon_device.c", "radeon_gpu_reset_internal")
    initialize = get_function(root, SUBTREE / "rs400.c", "rs400_init")
    if body_text(begin).find("READ_ONCE ( rdev -> gpu_parked )") < 0:
        raise GuardError(
            "terminal parked state: transaction root lacks gpu_parked refusal"
        )
    if "RADEON_RS4XX_HARDWARE_PARKED" not in body_text(disposition):
        raise GuardError("terminal parked state: parked disposition is unavailable")

    latch_text = body_text(latch)
    require_pattern(
        "terminal parked target scope",
        latch_text,
        r"if \( ! radeon_rs4xx_hardware_target \( rdev \) \) return ;",
    )
    latch_markers = (
        "spin_lock_irqsave ( & rdev -> rs4xx_hardware_state_lock , irqflags )",
        "WRITE_ONCE ( rdev -> gpu_parked , true )",
        "WRITE_ONCE ( rdev -> accel_working , false )",
        "WRITE_ONCE ( rdev -> needs_reset , false )",
        "WRITE_ONCE ( rdev -> ring [ ring_index ] . ready , false )",
        "atomic_set_release ( & rdev -> rs4xx_hardware_closing , 1 )",
        "radeon_rs4xx_publish_parked_hardware_state_locked ( rdev )",
        "spin_unlock_irqrestore ( & rdev -> rs4xx_hardware_state_lock , irqflags )",
        "smp_mb ( )",
        "wake_up_all ( & rdev -> rs4xx_hardware_wait )",
        "wake_up_all ( & rdev -> fence_queue )",
    )
    latch_positions = tuple(latch_text.find(marker) for marker in latch_markers)
    if any(position < 0 for position in latch_positions):
        raise GuardError(
            "terminal parked latch: one or more latch operations are absent"
        )
    if latch_positions != tuple(sorted(latch_positions)):
        raise GuardError("terminal parked latch: latch operations are out of order")
    require_pattern(
        "terminal parked writer barrier",
        latch_text,
        r"radeon_rs4xx_publish_parked_hardware_state_locked \( rdev \) ; "
        r"spin_unlock_irqrestore \( & rdev -> rs4xx_hardware_state_lock , "
        r"irqflags \) ; smp_mb \( \) ; wake_up_all "
        r"\( & rdev -> rs4xx_hardware_wait \) ;",
    )
    require_pattern(
        "terminal parked ring closure",
        latch_text,
        r"for \( ring_index = 0 ; ring_index < RADEON_NUM_RINGS ; "
        r"\+\+ ring_index \) WRITE_ONCE \( rdev -> ring \[ ring_index \] "
        r"\. ready , false \) ;",
    )
    require_pattern(
        "terminal parked fence wake",
        latch_text,
        r"if \( READ_ONCE \( rdev -> rs4xx_fence_work_initialized \) \) "
        r"wake_up_all \( & rdev -> fence_queue \) ;",
    )

    publish_text = body_text(publish)
    publisher_markers = (
        f"{LATCH_PARKED} ( rdev ) ;",
        "transition_owned = radeon_rs4xx_hardware_transition_owned ( rdev ) ;",
        "mutex_lock ( & rdev -> rs4xx_hardware_transition_lock ) ;",
        "mutex_lock ( & rdev -> rs4xx_parked_publish_lock ) ;",
        "wait_event ( rdev -> rs4xx_hardware_wait ,",
        "( void ) radeon_page_flip_quiesce ( rdev ) ;",
        "radeon_irq_kms_fini_hardwareless ( rdev ) ;",
        "cancel_delayed_work_sync ( & rdev -> pm . dynpm_idle_work ) ;",
        "radeon_fence_driver_force_completion_parked ( rdev ) ;",
        "( void ) radeon_page_flip_finalize_retained ( rdev , false ) ;",
        "mutex_unlock ( & rdev -> rs4xx_parked_publish_lock ) ;",
        "mutex_unlock ( & rdev -> rs4xx_hardware_transition_lock ) ;",
    )
    publisher_positions = tuple(
        publish_text.find(marker) for marker in publisher_markers
    )
    if any(position < 0 for position in publisher_positions):
        raise GuardError("terminal parked publisher: one or more operations are absent")
    if publisher_positions != tuple(sorted(publisher_positions)):
        raise GuardError("terminal parked publisher: drain and cleanup order differs")
    if (
        publish_text.count("mutex_lock ( & rdev -> rs4xx_hardware_transition_lock ) ;")
        != 1
    ):
        raise GuardError("terminal parked publisher: transition lock count differs")
    if publish_text.count("mutex_lock ( & rdev -> rs4xx_parked_publish_lock ) ;") != 1:
        raise GuardError("terminal parked publisher: publisher lock count differs")
    if (
        publish_text.count(
            "mutex_unlock ( & rdev -> rs4xx_hardware_transition_lock ) ;"
        )
        != 1
    ):
        raise GuardError("terminal parked publisher: transition unlock count differs")
    if (
        publish_text.count("mutex_unlock ( & rdev -> rs4xx_parked_publish_lock ) ;")
        != 1
    ):
        raise GuardError("terminal parked publisher: publisher unlock count differs")
    require_pattern(
        "terminal parked publisher ownership",
        publish_text,
        r"transition_owned = radeon_rs4xx_hardware_transition_owned \( rdev \) ; "
        r"if \( ! transition_owned \) mutex_lock "
        r"\( & rdev -> rs4xx_hardware_transition_lock \) ; .*?"
        r"if \( ! transition_owned \) mutex_unlock "
        r"\( & rdev -> rs4xx_hardware_transition_lock \) ;",
    )
    require_pattern(
        "terminal parked publisher drain",
        publish_text,
        r"wait_event \( rdev -> rs4xx_hardware_wait , "
        r"atomic_read \( & rdev -> rs4xx_hardware_transactions \) == 0 && "
        r"atomic_read \( & rdev -> rs4xx_hardware_readers \) == 0 \) ;",
    )
    require_pattern(
        "terminal parked publisher work gates",
        publish_text,
        r"if \( rdev -> rs4xx_pm_work_initialized \) "
        r"cancel_delayed_work_sync \( & rdev -> pm \. dynpm_idle_work \) ; "
        r"if \( rdev -> rs4xx_fence_work_initialized \) "
        r"radeon_fence_driver_force_completion_parked \( rdev \) ;",
    )

    require_pattern(
        "reset ring-restore parked latch",
        body_text(reset),
        r"restore_result = radeon_ring_restore .*?"
        r"if \( restore_result \) \{ kvfree \( ring_data \[ i \] \) ; "
        r"if \( rs4xx_reset \) \{ r = restore_result ; "
        r"radeon_rs4xx_latch_parked_state \( rdev \) ; "
        r"gpu_parked = true ; \}",
    )
    require_pattern(
        "RS400 initialization parked latch",
        body_text(initialize),
        r"r = radeon_asic_reset \( rdev \) ; if \( r \) \{ "
        r"radeon_rs4xx_latch_parked_state \( rdev \) ; .*?"
        r"radeon_rs4xx_hardware_transition_end \( rdev , "
        r"RADEON_RS4XX_HARDWARE_PARKED \) ; return r ; \} "
        r"radeon_rs4xx_hardware_transition_end \( rdev , "
        r"RADEON_RS4XX_HARDWARE_RUNNING \) ;",
    )
    require_pattern(
        "RS400 startup failure aborts device admission",
        body_text(initialize),
        r"rdev -> accel_working = true ; "
        r"r = rs400_startup \( rdev \) ; if \( r \) \{ .*?"
        r"rdev -> accel_working = false ; return r ; \} return 0 ;",
    )


def check_terminal_modeset(root: Path) -> None:
    function = get_function(
        root, SUBTREE / "radeon_display.c", "radeon_crtc_set_config"
    )
    text = body_text(function)
    require_pattern(
        "terminal modeset behavior",
        text,
        r"if \( rdev -> gpu_parked \) \{ .*? return 0 ; \} .*?"
        r"pm_runtime_get_sync .*?"
        r"radeon_rs4xx_hardware_transaction_begin",
    )


def check_async_publisher(root: Path) -> None:
    """Prove refusal publication, work coalescing, and work lifetime ordering."""

    queue = get_function(root, SUBTREE / "radeon_device.c", QUEUE_PARKED)
    refusal = get_function(root, SUBTREE / "radeon_device.c", REFUSAL_LATCH)
    worker = get_function(root, SUBTREE / "radeon_device.c", PUBLISH_WORK)
    terminal = get_function(root, SUBTREE / "radeon_device.c", TERMINAL_QUIESCE)
    initialize = get_function(root, SUBTREE / "radeon_device.c", "radeon_device_init")

    refusal_text = body_text(refusal)
    refusal_markers = (
        f"{LATCH_PARKED} ( rdev ) ;",
        "atomic_xchg ( & rdev -> rs4xx_parked_publish_pending , 1 ) ;",
        f"{QUEUE_PARKED} ( rdev ) ;",
    )
    refusal_positions = tuple(refusal_text.find(marker) for marker in refusal_markers)
    if any(position < 0 for position in refusal_positions):
        raise GuardError("teardown refusal: latch, pending state, or queue is absent")
    if refusal_positions != tuple(sorted(refusal_positions)):
        raise GuardError(
            "teardown refusal: latch, pending state, and queue order differs"
        )
    if refusal_text.count(f"{LATCH_PARKED} ( rdev ) ;") != 1:
        raise GuardError("teardown refusal: parked latch count differs")
    if refusal_text != (
        f"{LATCH_PARKED} ( rdev ) ; "
        "atomic_xchg ( & rdev -> rs4xx_parked_publish_pending , 1 ) ; "
        f"{QUEUE_PARKED} ( rdev ) ;"
    ):
        raise GuardError(
            "teardown refusal: callback performs work beyond publication request"
        )
    if PUBLISH_PARKED in refusal_text:
        raise GuardError("teardown refusal: callback invokes the blocking publisher")

    queue_text = body_text(queue)
    require_pattern(
        "parked publisher queue guard",
        queue_text,
        r"if \( ! radeon_rs4xx_hardware_target \( rdev \) \|\| "
        r"! READ_ONCE \( rdev -> rs4xx_parked_publish_work_initialized \) \|\| "
        r"! atomic_read \( & rdev -> rs4xx_parked_publish_pending \) \|\| "
        r"atomic_read \( & rdev -> rs4xx_parked_publish_running \) \|\| "
        r"atomic_read \( & rdev -> rs4xx_hardware_transactions \) != 0 \) "
        r"return ; queue_work \( system_unbound_wq , & rdev -> "
        r"rs4xx_parked_publish_work \) ;",
    )
    if len(call_positions(queue, "queue_work")) != 1:
        raise GuardError("parked publisher queue: queue_work count differs")

    worker_text = body_text(worker)
    worker_markers = (
        "if ( ! READ_ONCE ( rdev -> rs4xx_parked_publish_work_initialized ) ) "
        "{ atomic_set ( & rdev -> rs4xx_parked_publish_pending , 0 ) ; return ; }",
        "atomic_set ( & rdev -> rs4xx_parked_publish_running , 1 ) ;",
        f"{PUBLISH_PARKED} ( rdev ) ;",
        "atomic_xchg ( & rdev -> rs4xx_parked_publish_running , 0 ) ;",
        f"{QUEUE_PARKED} ( rdev ) ;",
    )
    worker_positions = tuple(worker_text.find(marker) for marker in worker_markers)
    if any(position < 0 for position in worker_positions):
        raise GuardError(
            "parked publisher work: coalescing or lifetime guard is absent"
        )
    pending_marker = "atomic_set ( & rdev -> rs4xx_parked_publish_pending , 0 ) ;"
    pending_positions = []
    search_start = 0
    while (position := worker_text.find(pending_marker, search_start)) >= 0:
        pending_positions.append(position)
        search_start = position + len(pending_marker)
    if len(pending_positions) != 2 or not (
        pending_positions[0]
        < worker_positions[1]
        < pending_positions[1]
        < worker_positions[2]
        < worker_positions[3]
        < worker_positions[4]
    ):
        raise GuardError(
            "parked publisher work: release does not preserve a later request"
        )
    if len(call_positions(worker, QUEUE_PARKED)) != 1:
        raise GuardError("parked publisher work: final queue count differs")

    terminal_text = body_text(terminal)
    require_pattern(
        "terminal parked publisher work lifetime",
        terminal_text,
        r"disable_work_sync \( & rdev -> rs4xx_parked_publish_work \) ; "
        r"WRITE_ONCE \( rdev -> rs4xx_parked_publish_work_initialized , false \) ; "
        r"atomic_set \( & rdev -> rs4xx_parked_publish_pending , 0 \) ; "
        r"atomic_set \( & rdev -> rs4xx_parked_publish_running , 0 \) ;",
    )
    if "cancel_work_sync" in terminal_text:
        raise GuardError(
            "terminal parked publisher work lifetime uses cancellation without disable"
        )

    initialize_text = body_text(initialize)
    require_pattern(
        "parked publisher work initialization",
        initialize_text,
        r"rdev -> rs4xx_parked_publish_work_initialized = false ; .*?"
        r"INIT_WORK \( & rdev -> rs4xx_parked_publish_work , "
        r"radeon_rs4xx_parked_publish_work \) ; .*?"
        r"rdev -> rs4xx_parked_publish_work_initialized = true ;",
    )


def check_command_submission_entry(root: Path) -> None:
    """Keep the old CS checker API as a centralized-helper projection."""

    function = get_function(root, SUBTREE / "radeon_cs.c", "radeon_cs_ioctl")
    text = body_text(function)
    require_pattern(
        "command-submission admission",
        text,
        r"radeon_device_lock_hardware \( rdev \) ; if \( r \) return r ; .*?"
        r"radeon_cs_parser_init",
    )
    require_pattern(
        "command-submission terminal parked refusal",
        text,
        r"if \( READ_ONCE \( rdev -> gpu_parked \) \) \{ .*?"
        r"radeon_device_unlock_hardware \( rdev \) ;.*?return - EIO ; \}.*?"
        r"radeon_cs_parser_init",
    )


def check_guard(root: Path, guard: dict[str, object]) -> None:
    """Compatibility entry point for the CS reservation contract checker."""

    if guard.get("id") != "command-submission":
        raise GuardError(f"unsupported parked guard {guard.get('id')}")
    check_command_submission_entry(root)


def check_contract(root: Path) -> None:
    """Run the complete finite transaction and terminal-state oracle."""

    check_call_denominator(root)
    check_latch_call_denominator(root)
    check_refusal_latch_call_denominator(root)
    check_reader_call_denominator(root)
    for spec in ROOTS:
        check_root(root, spec)
    check_bo_create(root)
    check_bo_destroy(root)
    check_bo_move(root)
    check_transaction_begin(root)
    check_transaction_wait_begin(root)
    check_transaction_try_begin(root)
    check_transaction_end(root)
    check_reader_begin(root)
    check_reader_end(root)
    check_access_helpers(root)
    check_inline_lock_helpers(root)
    check_terminal_parked_state(root)
    check_async_publisher(root)
    check_terminal_modeset(root)


FIXTURE_SOURCES = {
    SUBTREE / "radeon_rs4xx_dev.c": """
static int rs480_cp_me_ram_inject_one(struct radeon_device *rdev)
{
	radeon_rs4xx_latch_parked_state(rdev);
	return -EIO;
}
""",
    SUBTREE / "radeon_device.c": """
static int radeon_rs4xx_hardware_state_errno(int state)
{
\treturn -EIO;
}
static bool radeon_rs4xx_hardware_target(const struct radeon_device *rdev)
{
\treturn true;
}
static bool radeon_rs4xx_hardware_transition_owned(struct radeon_device *rdev)
{
\treturn false;
}
static bool radeon_rs4xx_hardware_transition_owner_admitted(
\tstruct radeon_device *rdev, int state)
{
\treturn state == RADEON_RS4XX_HARDWARE_RESETTING &&
\t\tradeon_rs4xx_hardware_transition_owned(rdev);
}
static bool radeon_rs4xx_hardware_disposition_available(
\tstruct radeon_device *rdev)
{
\tint state = atomic_read_acquire(&rdev->rs4xx_hardware_state);
\treturn state == RADEON_RS4XX_HARDWARE_RUNNING ||
\t\tstate == RADEON_RS4XX_HARDWARE_PARKED;
}
static int radeon_rs4xx_hardware_reader_begin(struct radeon_device *rdev)
{
	int state = atomic_read_acquire(&rdev->rs4xx_hardware_state);
	if (READ_ONCE(rdev->gpu_parked))
		return -EIO;
	if (state != RADEON_RS4XX_HARDWARE_RUNNING &&
	    !radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))
		return radeon_rs4xx_hardware_state_errno(state);
	atomic_inc(&rdev->rs4xx_hardware_readers);
	smp_mb__after_atomic();
	state = atomic_read(&rdev->rs4xx_hardware_state);
	if ((likely(state == RADEON_RS4XX_HARDWARE_RUNNING) &&
	     !READ_ONCE(rdev->gpu_parked)) ||
	    radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))
		return 0;
	if (atomic_dec_and_test(&rdev->rs4xx_hardware_readers))
		wake_up_all(&rdev->rs4xx_hardware_wait);
	return radeon_rs4xx_hardware_state_errno(state);
}
static void radeon_rs4xx_hardware_reader_end(struct radeon_device *rdev)
{
	if (WARN_ON_ONCE(atomic_read(&rdev->rs4xx_hardware_readers) <= 0))
		return;
	if (atomic_dec_and_test(&rdev->rs4xx_hardware_readers))
		wake_up_all(&rdev->rs4xx_hardware_wait);
}
int __radeon_rs4xx_hardware_access_begin(struct radeon_device *rdev)
{
	return radeon_rs4xx_hardware_reader_begin(rdev);
}
void __radeon_rs4xx_hardware_access_end(struct radeon_device *rdev)
{
	radeon_rs4xx_hardware_reader_end(rdev);
}
int radeon_rs4xx_hardware_access_wait_begin(struct radeon_device *rdev)
{
	int r;
	if (!radeon_rs4xx_hardware_target(rdev))
		return 0;
	for (;;) {
		r = radeon_rs4xx_hardware_reader_begin(rdev);
		if (r != -EBUSY && r != -EHOSTDOWN)
			return r;
		wait_event(rdev->rs4xx_hardware_wait,
			radeon_rs4xx_hardware_disposition_available(rdev));
	}
}
int radeon_rs4xx_hardware_transaction_begin(struct radeon_device *rdev)
{
\tint state;
\tif (!radeon_rs4xx_hardware_target(rdev))
\t\treturn 0;
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tstate = atomic_read_acquire(&rdev->rs4xx_hardware_state);
\tif (state != RADEON_RS4XX_HARDWARE_RUNNING &&
\t    !radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))
\t\treturn radeon_rs4xx_hardware_state_errno(state);
\tif (state == RADEON_RS4XX_HARDWARE_RUNNING &&
\t    atomic_read_acquire(&rdev->rs4xx_hardware_closing))
\t\treturn -EBUSY;
\tatomic_inc(&rdev->rs4xx_hardware_transactions);
\tsmp_mb__after_atomic();
\tstate = atomic_read(&rdev->rs4xx_hardware_state);
\tif (radeon_rs4xx_hardware_transition_owner_admitted(rdev, state) ||
\t    (state == RADEON_RS4XX_HARDWARE_RUNNING &&
\t     !READ_ONCE(rdev->gpu_parked) &&
\t     !atomic_read(&rdev->rs4xx_hardware_closing)))
\t\treturn 0;
\tif (atomic_dec_and_test(&rdev->rs4xx_hardware_transactions)) {
\t\twake_up_all(&rdev->rs4xx_hardware_wait);
\t\tradeon_rs4xx_queue_parked_publish(rdev);
\t}
\tif (state == RADEON_RS4XX_HARDWARE_RUNNING)
\t\treturn -EBUSY;
\treturn radeon_rs4xx_hardware_state_errno(state);
}
int radeon_rs4xx_hardware_transaction_wait_begin(struct radeon_device *rdev)
{
\tint r;
\tif (!radeon_rs4xx_hardware_target(rdev))
\t\treturn 0;
\tfor (;;) {
\t\tr = radeon_rs4xx_hardware_transaction_begin(rdev);
\t\tif (r != -EBUSY && r != -EHOSTDOWN)
\t\t\treturn r;
\t\twait_event(rdev->rs4xx_hardware_wait,
\t\t\tradeon_rs4xx_hardware_disposition_available(rdev));
\t}
}
int radeon_rs4xx_hardware_transaction_try_begin(struct radeon_device *rdev)
{
\treturn radeon_rs4xx_hardware_transaction_begin(rdev);
}
void radeon_rs4xx_hardware_transaction_end(struct radeon_device *rdev)
{
\tif (WARN_ON_ONCE(atomic_read(&rdev->rs4xx_hardware_transactions) <= 0))
\t\treturn;
\tif (atomic_dec_and_test(&rdev->rs4xx_hardware_transactions)) {
\t\twake_up_all(&rdev->rs4xx_hardware_wait);
\t\tradeon_rs4xx_queue_parked_publish(rdev);
\t}
}
void radeon_rs4xx_latch_parked_state(struct radeon_device *rdev)
{
\tunsigned long irqflags;
\tint ring_index;
\tif (!radeon_rs4xx_hardware_target(rdev))
\t\treturn;
\tspin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);
\tWRITE_ONCE(rdev->gpu_parked, true);
\tWRITE_ONCE(rdev->accel_working, false);
\tWRITE_ONCE(rdev->needs_reset, false);
\tfor (ring_index = 0; ring_index < RADEON_NUM_RINGS; ++ring_index)
\t\tWRITE_ONCE(rdev->ring[ring_index].ready, false);
\tatomic_set_release(&rdev->rs4xx_hardware_closing, 1);
\tradeon_rs4xx_publish_parked_hardware_state_locked(rdev);
\tspin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);
\tsmp_mb();
\twake_up_all(&rdev->rs4xx_hardware_wait);
\tif (READ_ONCE(rdev->rs4xx_fence_work_initialized))
\t\twake_up_all(&rdev->fence_queue);
}
void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)
{
\tradeon_rs4xx_latch_parked_state(rdev);
\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);
\tradeon_rs4xx_queue_parked_publish(rdev);
}
static void radeon_rs4xx_queue_parked_publish(struct radeon_device *rdev)
{
\tif (!radeon_rs4xx_hardware_target(rdev) ||
\t    !READ_ONCE(rdev->rs4xx_parked_publish_work_initialized) ||
\t    !atomic_read(&rdev->rs4xx_parked_publish_pending) ||
\t    atomic_read(&rdev->rs4xx_parked_publish_running) ||
\t    atomic_read(&rdev->rs4xx_hardware_transactions) != 0)
\t\treturn;
\tqueue_work(system_unbound_wq, &rdev->rs4xx_parked_publish_work);
}
void radeon_rs4xx_publish_parked_state(struct radeon_device *rdev)
{
\tbool transition_owned;
\tif (!radeon_rs4xx_hardware_target(rdev))
\t\treturn;
\tradeon_rs4xx_latch_parked_state(rdev);
\ttransition_owned = radeon_rs4xx_hardware_transition_owned(rdev);
\tif (!transition_owned)
\t\tmutex_lock(&rdev->rs4xx_hardware_transition_lock);
\tmutex_lock(&rdev->rs4xx_parked_publish_lock);
\twait_event(rdev->rs4xx_hardware_wait,
\t\t   atomic_read(&rdev->rs4xx_hardware_transactions) == 0 &&
\t\t   atomic_read(&rdev->rs4xx_hardware_readers) == 0);
\t(void)radeon_page_flip_quiesce(rdev);
\tradeon_irq_kms_fini_hardwareless(rdev);
\tif (rdev->rs4xx_pm_work_initialized)
\t\tcancel_delayed_work_sync(&rdev->pm.dynpm_idle_work);
\tif (rdev->rs4xx_fence_work_initialized)
\t\tradeon_fence_driver_force_completion_parked(rdev);
\t(void)radeon_page_flip_finalize_retained(rdev, false);
\tmutex_unlock(&rdev->rs4xx_parked_publish_lock);
\tif (!transition_owned)
\t\tmutex_unlock(&rdev->rs4xx_hardware_transition_lock);
}
static void radeon_rs4xx_parked_publish_work(struct work_struct *work_item)
{
\tstruct radeon_device *rdev = container_of(
\t\twork_item, struct radeon_device, rs4xx_parked_publish_work);

\tif (!READ_ONCE(rdev->rs4xx_parked_publish_work_initialized)) {
\t\tatomic_set(&rdev->rs4xx_parked_publish_pending, 0);
\t\treturn;
\t}
\tatomic_set(&rdev->rs4xx_parked_publish_running, 1);
\tatomic_set(&rdev->rs4xx_parked_publish_pending, 0);
\tradeon_rs4xx_publish_parked_state(rdev);
\tatomic_xchg(&rdev->rs4xx_parked_publish_running, 0);
\tradeon_rs4xx_queue_parked_publish(rdev);
}
void radeon_rs4xx_terminal_quiesce(struct radeon_device *rdev)
{
\tif (!radeon_rs4xx_hardware_target(rdev))
\t\treturn;
\tdisable_work_sync(&rdev->rs4xx_parked_publish_work);
\tWRITE_ONCE(rdev->rs4xx_parked_publish_work_initialized, false);
\tatomic_set(&rdev->rs4xx_parked_publish_pending, 0);
\tatomic_set(&rdev->rs4xx_parked_publish_running, 0);
}
int radeon_device_init(struct radeon_device *rdev)
{
\trdev->rs4xx_parked_publish_work_initialized = false;
\tatomic_set(&rdev->rs4xx_parked_publish_pending, 0);
\tatomic_set(&rdev->rs4xx_parked_publish_running, 0);
\tINIT_WORK(&rdev->rs4xx_parked_publish_work,
\t\t  radeon_rs4xx_parked_publish_work);
\trdev->rs4xx_parked_publish_work_initialized = true;
\treturn 0;
}
static int radeon_gpu_reset_internal(struct radeon_device *rdev)
{
\trestore_result = radeon_ring_restore(
\t\trdev, &rdev->ring[i], ring_sizes[i], ring_data[i]);
\tif (restore_result) {
\t\tkvfree(ring_data[i]);
\t\tif (rs4xx_reset) {
\t\t\tr = restore_result;
\t\t\tradeon_rs4xx_latch_parked_state(rdev);
\t\t\tgpu_parked = true;
\t\t}
\t}
\treturn r;
}
""",
    SUBTREE / "radeon.h": """
static inline int radeon_rs4xx_hardware_access_begin(struct radeon_device *rdev)
{
	if (!radeon_rs4xx_hardware_target(rdev))
		return 0;
	return __radeon_rs4xx_hardware_access_begin(rdev);
}
static inline void radeon_rs4xx_hardware_access_end(struct radeon_device *rdev)
{
	if (radeon_rs4xx_hardware_target(rdev))
		__radeon_rs4xx_hardware_access_end(rdev);
}
static inline int radeon_device_lock_hardware(struct radeon_device *rdev)
{
\tint r;
\tr = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (r)
\t\treturn r;
\tif (radeon_rs4xx_hardware_transition_owned(rdev))
\t\treturn 0;
\tdown_read(&rdev->exclusive_lock);
\tif (radeon_rs4xx_hardware_target(rdev))
\t\tr = 0;
\telse
\t\tr = radeon_dev_hardware_available(rdev);
\tif (r)
\t\tup_read(&rdev->exclusive_lock);
\tif (r)
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn r;
}
static inline void radeon_device_unlock_hardware(struct radeon_device *rdev)
{
\tif (!radeon_rs4xx_hardware_transition_owned(rdev))
\t\tup_read(&rdev->exclusive_lock);
\tradeon_rs4xx_hardware_transaction_end(rdev);
}
static inline int radeon_device_trylock_hardware(struct radeon_device *rdev)
{
\tint r;
\tr = radeon_rs4xx_hardware_transaction_try_begin(rdev);
\tif (r)
\t\treturn r;
\tif (radeon_rs4xx_hardware_transition_owned(rdev))
\t\treturn 0;
\tif (!down_read_trylock(&rdev->exclusive_lock)) {
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
\t\treturn -EBUSY;
\t}
\tif (radeon_rs4xx_hardware_target(rdev))
\t\treturn 0;
\tr = radeon_dev_hardware_available(rdev);
\tif (!r)
\t\treturn 0;
\tup_read(&rdev->exclusive_lock);
\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn r;
}
""",
    SUBTREE / "radeon_gem.c": """
int radeon_gem_create_ioctl(struct drm_device *dev)
{
\tint r;
\tr = radeon_device_lock_hardware(rdev);
\tif (r)
\t\treturn r;
\tr = radeon_gem_object_create(rdev, size, align, domain, flags, false, &gobj);
\tif (r) {
\t\tradeon_device_unlock_hardware(rdev);
\t\treturn r;
\t}
\tr = drm_gem_handle_create(filp, gobj, &handle);
\tradeon_device_unlock_hardware(rdev);
\treturn r;
}
int radeon_gem_userptr_ioctl(struct drm_device *dev)
{
\tint r;
\tr = radeon_device_lock_hardware(rdev);
\tif (r)
\t\treturn r;
\tr = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
\tif (r)
\t\tgoto handle_lockup;
\tr = radeon_ttm_tt_set_userptr(rdev, bo, addr, flags);
\tif (r)
\t\tgoto release_object;
\tr = radeon_mn_register(bo, addr);
\tif (r)
\t\tgoto release_object;
\tr = drm_gem_handle_create(filp, gobj, &handle);
\tradeon_device_unlock_hardware(rdev);
\treturn r;
release_object:
\tradeon_device_unlock_hardware(rdev);
\tdrm_gem_object_put(gobj);
\treturn r;
handle_lockup:
\tradeon_device_unlock_hardware(rdev);
\treturn r;
}
int radeon_gem_set_domain_ioctl(struct drm_device *dev)
{
\tint r;
\tr = radeon_device_lock_hardware(rdev);
\tif (r)
\t\treturn r;
\tgobj = drm_gem_object_lookup(filp, handle);
\tif (!gobj) {
\t\tradeon_device_unlock_hardware(rdev);
\t\treturn -ENOENT;
\t}
\tr = radeon_gem_set_domain(gobj, read_domains, write_domain);
\tradeon_device_unlock_hardware(rdev);
\treturn r;
}
int radeon_gem_wait_idle_ioctl(struct drm_device *dev)
{
\tint hardware_result;
\tret = dma_resv_wait_timeout(resv, usage, true, timeout);
\thardware_result = radeon_device_lock_hardware(rdev);
\tif (hardware_result)
\t\treturn hardware_result;
\tplacement = READ_ONCE(robj->tbo.resource->mem_type);
\tif (placement)
\t\trdev->asic->mmio_hdp_flush(rdev);
\tradeon_device_unlock_hardware(rdev);
\treturn 0;
}
int radeon_mode_dumb_create(struct drm_file *file_priv)
{
\tint r;
\tr = radeon_device_lock_hardware(rdev);
\tif (r)
\t\treturn r;
\tr = radeon_gem_object_create(rdev, size, 0, domain, 0, false, &gobj);
\tradeon_device_unlock_hardware(rdev);
\treturn r;
}
static vm_fault_t radeon_gem_fault(struct vm_fault *vmf)
{
\tbool hardware_transaction = false;
\tvm_fault_t ret;
\tret = ttm_bo_vm_reserve(bo, vmf);
\tif (ret)
\t\tgoto unlock_mclk;
\tif (radeon_rs4xx_hardware_transaction_begin(rdev)) {
\t\tret = VM_FAULT_SIGBUS;
\t\tgoto unlock_resv;
\t}
\thardware_transaction = true;
\tret = radeon_bo_fault_reserve_notify(bo);
\tif (ret)
\t\tgoto unlock_resv;
\tret = ttm_bo_vm_fault_reserved(vmf, prot, 1);
unlock_resv:
\tdma_resv_unlock(bo->base.resv);
unlock_transaction:
\tif (hardware_transaction)
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
unlock_mclk:
\treturn ret;
}
static int radeon_gem_vm_access(struct vm_area_struct *vma)
{
\tint ret;
\tret = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (ret)
\t\treturn ret;
\tret = ttm_bo_vm_access(vma, addr, buf, len, write);
\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn ret;
}
static void radeon_gem_object_free(struct drm_gem_object *gobj)
{
\tstruct radeon_bo *robj = gem_to_radeon_bo(gobj);
\tint ret;
\tret = radeon_rs4xx_hardware_transaction_wait_begin(rdev);
\tif (ret == -ESHUTDOWN)
\t\tret = radeon_rs4xx_gart_teardown_wait(rdev);
\telse if (ret == 0)
\t\thardware_transaction = true;
\tif (ret) {
\t\tradeon_rs4xx_retain_bo(robj);
\t\tradeon_rs4xx_latch_teardown_refusal(rdev);
\t\tradeon_mn_unregister(robj);
\t\treturn;
\t}
\tradeon_mn_unregister(robj);
\tttm_bo_fini(&robj->tbo);
\tif (hardware_transaction)
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
}
""",
    SUBTREE / "radeon_prime.c": """
struct drm_gem_object *radeon_gem_prime_import_sg_table(struct drm_device *dev)
{
\tint ret;
\tret = radeon_device_lock_hardware(rdev);
\tif (ret)
\t\treturn ERR_PTR(ret);
\tdma_resv_lock(resv, NULL);
\tret = radeon_bo_create(rdev, size, align, false, domain, 0, sg, resv, &bo);
\tdma_resv_unlock(resv);
\tradeon_device_unlock_hardware(rdev);
\treturn ERR_PTR(ret);
}
int radeon_gem_prime_pin(struct drm_gem_object *obj)
{
\tint ret;
\tret = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (ret)
\t\treturn ret;
\tret = radeon_bo_pin(bo, domain, NULL);
\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn ret;
}
void radeon_gem_prime_unpin(struct drm_gem_object *obj)
{
\tif (radeon_rs4xx_hardware_transaction_begin(rdev))
\t\treturn;
\tradeon_bo_unpin(bo);
\tradeon_rs4xx_hardware_transaction_end(rdev);
}
""",
    SUBTREE / "radeon_cursor.c": """
int radeon_crtc_cursor_set2(struct drm_crtc *crtc)
{
\tbool hardware_transaction = false;
\tint ret;
\tret = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (ret)
\t\tgoto out_exec;
\thardware_transaction = true;
\tret = radeon_bo_pin_restricted(new_rbo, domain, 0, &addr);
\tif (ret)
\t\tgoto out_unpin_new;
\tradeon_lock_cursor(crtc, true);
\tradeon_lock_cursor(crtc, false);
\tret = 0;
\tradeon_rs4xx_hardware_transaction_end(rdev);
\thardware_transaction = false;
\treturn 0;
out_unpin_new:
out_exec:
\tif (hardware_transaction)
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn ret;
}
""",
    SUBTREE / "radeon_display.c": """
static int radeon_crtc_set_config(struct drm_mode_set *set)
{
\tint ret;
\trdev = dev->dev_private;
\tif (rdev->gpu_parked) {
\t\tdev_err_once(rdev->dev, parked);
\t\treturn 0;
\t}
\tret = pm_runtime_get_sync(dev->dev);
\tret = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (ret) {
\t\tpm_runtime_put_autosuspend(dev->dev);
\t\treturn ret;
\t}
\tret = drm_crtc_helper_set_config(set, ctx);
\tif (active && !rdev->have_disp_power_ref) {
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
\t\treturn ret;
\t}
\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn ret;
}
""",
    SUBTREE / "radeon_fbdev.c": """
static int radeon_fbdev_create_pinned_object(struct drm_fb_helper *fb_helper)
{
\tint ret;
\tret = radeon_device_lock_hardware(rdev);
\tif (ret)
\t\treturn ret;
\tret = radeon_gem_object_create(rdev, size, 0, domain, 0, true, &gobj);
\tif (ret) {
\t\tradeon_device_unlock_hardware(rdev);
\t\treturn -ENOMEM;
\t}
\tret = radeon_bo_reserve(rbo, false);
\tif (ret)
\t\tgoto err_destroy;
\tret = radeon_bo_pin_restricted(rbo, domain, 0, NULL);
\tret = radeon_bo_kmap(rbo, NULL);
\tradeon_device_unlock_hardware(rdev);
\treturn ret;
err_destroy:
\tradeon_device_unlock_hardware(rdev);
\treturn ret;
}
static void radeon_fbdev_destroy_pinned_object(struct drm_gem_object *gobj)
{
\tint ret;
\tret = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (ret) {
\t\tdrm_gem_object_put(gobj);
\t\treturn;
\t}
\tret = radeon_bo_reserve(rbo, false);
\tradeon_bo_kunmap(rbo);
\tradeon_bo_unpin(rbo);
\tradeon_bo_unreserve(rbo);
\tradeon_rs4xx_hardware_transaction_end(rdev);
\tdrm_gem_object_put(gobj);
}
static int radeon_fbdev_fb_mmap(struct fb_info *info,
\t\t\t\tstruct vm_area_struct *vma)
{
\tstruct drm_fb_helper *fb_helper = info->par;
\tstruct radeon_device *rdev = fb_helper->dev->dev_private;

\tif (radeon_rs4xx_hardware_target(rdev))
\t\treturn -ENODEV;
\treturn fb_io_mmap(info, vma);
}
""",
    SUBTREE / "radeon_ttm.c": """
static int radeon_bo_move(struct ttm_buffer_object *bo)
{
\tint r;
\tint rollback_result;
\tbool newly_bound = false;
\tr = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (r)
\t\treturn r;
\tr = ttm_bo_wait_ctx(bo, ctx);
\tif (r)
\t\tgoto out_transaction;
\tif (new_mem->mem_type == TTM_PL_TT) {
\t\tnewly_bound = radeon_rs4xx_hardware_target(rdev) &&
\t\t\t!radeon_ttm_tt_is_bound(bo->bdev, bo->ttm);
\t\tr = radeon_ttm_tt_bind(bo->bdev, bo->ttm, new_mem);
\t\tif (r)
\t\t\tgoto out_transaction;
\t}
\tif (old_mem->mem_type == TTM_PL_TT &&
\t    new_mem->mem_type == TTM_PL_SYSTEM) {
\t\tr = radeon_ttm_tt_unbind_status(bo->bdev, bo->ttm);
\t\tif (r)
\t\t\tgoto out_transaction;
\t}
\tif (rdev->ring[0].ready)
\t\tr = radeon_move_blit(bo, evict, new_mem, old_mem);
\tif (r)
\t\tgoto out_transaction;
out:
\tr = 0;
\tradeon_bo_move_notify(bo);
out_transaction:
\tif (r && newly_bound) {
\t\trollback_result = radeon_ttm_tt_unbind_status(bo->bdev, bo->ttm);
\t\tif (rollback_result)
\t\t\tr = rollback_result;
\t}
\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn r;
}
static int radeon_ttm_backend_unbind(struct ttm_device *bdev,
\t\t\t\t     struct ttm_tt *ttm)
{
\tint r;

\tif (!gtt->bound)
\t\treturn 0;
\tr = radeon_gart_unbind(rdev, gtt->offset, ttm->num_pages);
\tif (r && radeon_rs4xx_hardware_target(rdev)) {
\t\tradeon_rs4xx_latch_teardown_refusal(rdev);
\t\treturn r;
\t}
\treturn 0;
}
static void radeon_ttm_tt_unpopulate(struct ttm_device *bdev,
\t\t\t\t\t struct ttm_tt *ttm)
{
\tbool hardware_transaction = false;
\tint r;

\tr = radeon_rs4xx_hardware_transaction_wait_begin(rdev);
\tif (r == -ESHUTDOWN)
\t\tr = radeon_rs4xx_gart_teardown_wait(rdev);
\telse if (r == 0)
\t\thardware_transaction = true;
\tif (r) {
\t\tradeon_rs4xx_latch_teardown_refusal(rdev);
\t\tif (gtt && gtt->bound &&
\t\t    radeon_rs4xx_hardware_target(rdev))
\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);
\t\treturn;
\t}
\tr = radeon_ttm_tt_unbind_status(bdev, ttm);
\tif (hardware_transaction)
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
\tif (r)
\t\treturn;
\tttm_pool_free(&rdev->mman.bdev.pool, ttm);
}
""",
    SUBTREE / "radeon_object.c": """
static void radeon_ttm_bo_destroy(struct ttm_buffer_object *tbo)
{
\tstruct radeon_bo *bo;
\tstruct radeon_device *rdev;
\tbool lifetime_counted;
\tbool teardown_complete = false;
\tint r = 0;

\tbo = container_of(tbo, struct radeon_bo, tbo);
\trdev = bo->rdev;
\tif (radeon_rs4xx_hardware_target(rdev)) {
\t\tif (READ_ONCE(bo->rs4xx_terminally_retained))
\t\t\treturn;
\t\tteardown_complete = radeon_rs4xx_gart_teardown_is_complete(rdev);
\t\tif (!teardown_complete) {
\t\t\tr = radeon_rs4xx_hardware_transaction_wait_begin(rdev);
\t\t\tif (r == -ESHUTDOWN) {
\t\t\t\tr = radeon_rs4xx_gart_teardown_wait(rdev);
\t\t\t\tteardown_complete = r == 0;
\t\t\t}
\t\t\tif (r) {
\t\t\t\tradeon_rs4xx_latch_teardown_refusal(rdev);
\t\t\t\tradeon_rs4xx_retain_bo(bo);
\t\t\t\treturn;
\t\t\t}
\t\t}
\t}
\tdrm_gem_object_release(&bo->tbo.base);
\tlifetime_counted = bo->rs4xx_lifetime_counted;
\tkfree(bo);
\tif (lifetime_counted &&
\t    atomic_dec_and_test(&rdev->rs4xx_live_bos))
\t\twake_up_all(&rdev->rs4xx_hardware_wait);
\tif (!teardown_complete)
\t\tradeon_rs4xx_hardware_transaction_end(rdev);
}

int radeon_bo_create(struct radeon_device *rdev,
\t\t\t     unsigned long size, int byte_align, bool kernel,
\t\t\t     u32 domain, u32 flags, struct sg_table *sg,
\t\t\t     struct dma_resv *resv,
\t\t\t     struct radeon_bo **bo_ptr)
{
\tstruct radeon_bo *bo;
\tint r;

\tr = radeon_rs4xx_hardware_transaction_begin(rdev);
\tif (r)
\t\treturn r;
\tbo = kzalloc(sizeof(*bo), GFP_KERNEL);
\tif (!bo) {
\t\tr = -ENOMEM;
\t\tgoto out_transaction;
\t}
\tbo->rs4xx_lifetime_counted = true;
\tatomic_inc(&rdev->rs4xx_live_bos);
\tr = ttm_bo_init_validate(&rdev->mman.bdev, &bo->tbo, type,
\t\t\t\t &bo->placement, page_align, !kernel, sg, resv,
\t\t\t\t &radeon_ttm_bo_destroy);
out_transaction:
\tradeon_rs4xx_hardware_transaction_end(rdev);
\treturn r;
}
""",
    SUBTREE / "radeon_cs.c": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tint r;
\tr = radeon_device_lock_hardware(rdev);
\tif (r)
\t\treturn r;
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tradeon_device_unlock_hardware(rdev);
\t\treturn -EIO;
\t}
\tif (!rdev->accel_working) {
\t\tradeon_device_unlock_hardware(rdev);
\t\treturn -EBUSY;
\t}
\tif (rdev->in_reset) {
\t\tradeon_device_unlock_hardware(rdev);
\t\treturn -EAGAIN;
\t}
\tr = radeon_cs_parser_init(&parser, data);
\tif (r) {
\t\tradeon_cs_parser_release_reservations(&parser, r);
\t\tradeon_device_unlock_hardware(rdev);
\t\tradeon_cs_parser_release_storage(&parser);
\t\treturn r;
\t}
\tr = radeon_cs_parser_relocs(&parser);
\tif (r) {
\t\tradeon_cs_parser_release_reservations(&parser, r);
\t\tradeon_device_unlock_hardware(rdev);
\t\tradeon_cs_parser_release_storage(&parser);
\t\treturn r;
\t}
\tradeon_cs_parser_release_reservations(&parser, r);
\tradeon_device_unlock_hardware(rdev);
\tradeon_cs_parser_release_storage(&parser);
\treturn r;
}
""",
    SUBTREE / "rs400.c": """
int rs400_init(struct radeon_device *rdev)
{
\tr = radeon_rs4xx_hardware_transition_begin(
\t\trdev, RADEON_RS4XX_HARDWARE_RUNNING,
\t\tRADEON_RS4XX_HARDWARE_RESETTING);
\tif (r)
\t\treturn r;
\tr = radeon_asic_reset(rdev);
\tif (r) {
\t\tradeon_rs4xx_latch_parked_state(rdev);
\t\tdev_err(rdev->dev, "reset failed");
\t\tradeon_rs4xx_hardware_transition_end(
\t\t\trdev, RADEON_RS4XX_HARDWARE_PARKED);
\t\treturn r;
\t}
\tradeon_rs4xx_hardware_transition_end(
\t\trdev, RADEON_RS4XX_HARDWARE_RUNNING);
\trdev->accel_working = true;
\tr = rs400_startup(rdev);
\tif (r) {
\t\trdev->accel_working = false;
\t\treturn r;
\t}
\treturn 0;
}
""",
}


def write_fixture_sources(root: Path) -> None:
    for path, source in FIXTURE_SOURCES.items():
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source, encoding="utf-8")


def selftest(root: Path) -> int:
    """Calibrate known-good and known-bad source mutations."""

    write_fixture_sources(root)
    try:
        check_contract(root)
        check_command_submission_entry(root)
    except GuardError as exc:
        print(f"selftest known-good REJECTED: {exc}", file=sys.stderr)
        return 1
    print("selftest known-good accepted: finite transaction contract")

    mutations = (
        (
            "transaction end precedes mapped access",
            SUBTREE / "radeon_gem.c",
            "\tret = ttm_bo_vm_access(vma, addr, buf, len, write);\n"
            "\tradeon_rs4xx_hardware_transaction_end(rdev);",
            "\tradeon_rs4xx_hardware_transaction_end(rdev);\n"
            "\tret = ttm_bo_vm_access(vma, addr, buf, len, write);",
        ),
        (
            "post-increment parked revalidation removed",
            SUBTREE / "radeon_device.c",
            "\t    (state == RADEON_RS4XX_HARDWARE_RUNNING &&\n"
            "\t     !READ_ONCE(rdev->gpu_parked) &&\n"
            "\t     !atomic_read(&rdev->rs4xx_hardware_closing)))",
            "\t    (state == RADEON_RS4XX_HARDWARE_RUNNING &&\n"
            "\t     !atomic_read(&rdev->rs4xx_hardware_closing)))",
        ),
        (
            "reader parked refusal returns success",
            SUBTREE / "radeon_device.c",
            "static int radeon_rs4xx_hardware_reader_begin(struct radeon_device *rdev)\n"
            "{\n"
            "\tint state = atomic_read_acquire(&rdev->rs4xx_hardware_state);\n"
            "\tif (READ_ONCE(rdev->gpu_parked))\n"
            "\t\treturn -EIO;",
            "static int radeon_rs4xx_hardware_reader_begin(struct radeon_device *rdev)\n"
            "{\n"
            "\tint state = atomic_read_acquire(&rdev->rs4xx_hardware_state);\n"
            "\tif (READ_ONCE(rdev->gpu_parked))\n"
            "\t\treturn 0;",
        ),
        (
            "reader post-increment barrier removed",
            SUBTREE / "radeon_device.c",
            "\tatomic_inc(&rdev->rs4xx_hardware_readers);\n"
            "\tsmp_mb__after_atomic();\n"
            "\tstate = atomic_read(&rdev->rs4xx_hardware_state);",
            "\tatomic_inc(&rdev->rs4xx_hardware_readers);\n"
            "\tstate = atomic_read(&rdev->rs4xx_hardware_state);",
        ),
        (
            "reader post-increment parked revalidation removed",
            SUBTREE / "radeon_device.c",
            "\tif ((likely(state == RADEON_RS4XX_HARDWARE_RUNNING) &&\n"
            "\t     !READ_ONCE(rdev->gpu_parked)) ||\n"
            "\t    radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))",
            "\tif (likely(state == RADEON_RS4XX_HARDWARE_RUNNING) ||\n"
            "\t    radeon_rs4xx_hardware_transition_owner_admitted(rdev, state))",
        ),
        (
            "reader failed-admission rollback removed",
            SUBTREE / "radeon_device.c",
            "\tif (atomic_dec_and_test(&rdev->rs4xx_hardware_readers))\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\treturn radeon_rs4xx_hardware_state_errno(state);\n"
            "}\n"
            "static void radeon_rs4xx_hardware_reader_end",
            "\treturn radeon_rs4xx_hardware_state_errno(state);\n"
            "}\n"
            "static void radeon_rs4xx_hardware_reader_end",
        ),
        (
            "reader release underflow check removed",
            SUBTREE / "radeon_device.c",
            "static void radeon_rs4xx_hardware_reader_end(struct radeon_device *rdev)\n"
            "{\n"
            "\tif (WARN_ON_ONCE(atomic_read(&rdev->rs4xx_hardware_readers) <= 0))\n"
            "\t\treturn;",
            "static void radeon_rs4xx_hardware_reader_end(struct radeon_device *rdev)\n"
            "{",
        ),
        (
            "internal access begin bypasses reader admission",
            SUBTREE / "radeon_device.c",
            "\treturn radeon_rs4xx_hardware_reader_begin(rdev);",
            "\treturn 0;",
        ),
        (
            "public access begin bypasses internal reader admission",
            SUBTREE / "radeon.h",
            "\treturn __radeon_rs4xx_hardware_access_begin(rdev);",
            "\treturn 0;",
        ),
        (
            "public access end omits reader release",
            SUBTREE / "radeon.h",
            "\t\t__radeon_rs4xx_hardware_access_end(rdev);",
            "\t\treturn;",
        ),
        (
            "access wait admits a transient error",
            SUBTREE / "radeon_device.c",
            "int radeon_rs4xx_hardware_access_wait_begin(struct radeon_device *rdev)\n"
            "{\n"
            "\tint r;\n"
            "\tif (!radeon_rs4xx_hardware_target(rdev))\n"
            "\t\treturn 0;\n"
            "\tfor (;;) {\n"
            "\t\tr = radeon_rs4xx_hardware_reader_begin(rdev);\n"
            "\t\tif (r != -EBUSY && r != -EHOSTDOWN)\n"
            "\t\t\treturn r;",
            "int radeon_rs4xx_hardware_access_wait_begin(struct radeon_device *rdev)\n"
            "{\n"
            "\tint r;\n"
            "\tif (!radeon_rs4xx_hardware_target(rdev))\n"
            "\t\treturn 0;\n"
            "\tfor (;;) {\n"
            "\t\tr = radeon_rs4xx_hardware_reader_begin(rdev);\n"
            "\t\tif (r)\n"
            "\t\t\treturn r;",
        ),
        (
            "unexpected direct reader-core caller",
            SUBTREE / "radeon_device.c",
            "int radeon_rs4xx_hardware_transaction_begin(struct radeon_device *rdev)",
            "static int extra_reader(struct radeon_device *rdev)\n"
            "{\n"
            "\treturn radeon_rs4xx_hardware_reader_begin(rdev);\n"
            "}\n"
            "int radeon_rs4xx_hardware_transaction_begin(struct radeon_device *rdev)",
        ),
        (
            "transaction end removed",
            SUBTREE / "radeon_gem.c",
            "\tradeon_rs4xx_hardware_transaction_end(rdev);\n\treturn ret;",
            "\treturn ret;",
        ),
        (
            "transaction failure returns success",
            SUBTREE / "radeon_gem.c",
            "\tif (ret)\n\t\treturn ret;\n\tret = ttm_bo_vm_access",
            "\tif (ret)\n\t\treturn 0;\n\tret = ttm_bo_vm_access",
        ),
        (
            "retained object count removed",
            SUBTREE / "radeon_gem.c",
            "\t\tradeon_rs4xx_retain_bo(robj);\n",
            "",
        ),
        (
            "parked refusal returns success",
            SUBTREE / "radeon_device.c",
            "int radeon_rs4xx_hardware_transaction_begin(struct radeon_device *rdev)\n"
            "{\n"
            "\tint state;\n"
            "\tif (!radeon_rs4xx_hardware_target(rdev))\n"
            "\t\treturn 0;\n"
            "\tif (READ_ONCE(rdev->gpu_parked))\n"
            "\t\treturn -EIO;",
            "int radeon_rs4xx_hardware_transaction_begin(struct radeon_device *rdev)\n"
            "{\n"
            "\tint state;\n"
            "\tif (!radeon_rs4xx_hardware_target(rdev))\n"
            "\t\treturn 0;\n"
            "\tif (READ_ONCE(rdev->gpu_parked))\n"
            "\t\treturn 0;",
        ),
        (
            "transaction rollback removed",
            SUBTREE / "radeon_device.c",
            "if (atomic_dec_and_test(&rdev->rs4xx_hardware_transactions)) {\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "\t}\n"
            "\tif (state == RADEON_RS4XX_HARDWARE_RUNNING)",
            "if (state == RADEON_RS4XX_HARDWARE_RUNNING)",
        ),
        (
            "lost queue after transaction rollback",
            SUBTREE / "radeon_device.c",
            "if (atomic_dec_and_test(&rdev->rs4xx_hardware_transactions)) {\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "\t}\n"
            "\tif (state == RADEON_RS4XX_HARDWARE_RUNNING)",
            "if (atomic_dec_and_test(&rdev->rs4xx_hardware_transactions)) {\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (state == RADEON_RS4XX_HARDWARE_RUNNING)",
        ),
        (
            "parked latch cleared",
            SUBTREE / "radeon_device.c",
            "WRITE_ONCE(rdev->gpu_parked, true);",
            "WRITE_ONCE(rdev->gpu_parked, false);",
        ),
        (
            "parked latch state lock removed",
            SUBTREE / "radeon_device.c",
            "\tspin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);\n",
            "",
        ),
        (
            "parked latch closing publication removed",
            SUBTREE / "radeon_device.c",
            "\tatomic_set_release(&rdev->rs4xx_hardware_closing, 1);\n",
            "",
        ),
        (
            "parked latch writer barrier removed",
            SUBTREE / "radeon_device.c",
            "\tspin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);\n"
            "\tsmp_mb();\n"
            "\twake_up_all(&rdev->rs4xx_hardware_wait);",
            "\tspin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);\n"
            "\twake_up_all(&rdev->rs4xx_hardware_wait);",
        ),
        (
            "teardown latch conditionalized",
            SUBTREE / "radeon_device.c",
            "void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)\n"
            "{\n"
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "}",
            "void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)\n"
            "{\n"
            "\tif (!READ_ONCE(rdev->gpu_parked))\n"
            "\t\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "}",
        ),
        (
            "teardown latch wrapper gains a blocking suffix",
            SUBTREE / "radeon_device.c",
            "void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)\n"
            "{\n"
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "}",
            "void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)\n"
            "{\n"
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "\t(void)radeon_page_flip_quiesce(rdev);\n"
            "}",
        ),
        (
            "pending publication precedes parked latch",
            SUBTREE / "radeon_device.c",
            "void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)\n"
            "{\n"
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "}",
            "void radeon_rs4xx_latch_teardown_refusal(struct radeon_device *rdev)\n"
            "{\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
            "}",
        ),
        (
            "parked publisher transaction drain removed",
            SUBTREE / "radeon_device.c",
            "\t\t   atomic_read(&rdev->rs4xx_hardware_transactions) == 0 &&\n",
            "",
        ),
        (
            "parked publisher reader drain removed",
            SUBTREE / "radeon_device.c",
            "\t\t   atomic_read(&rdev->rs4xx_hardware_readers) == 0);\n",
            "\t\t   true);\n",
        ),
        (
            "parked publisher cleanup precedes drain",
            SUBTREE / "radeon_device.c",
            "\twait_event(rdev->rs4xx_hardware_wait,\n"
            "\t\t   atomic_read(&rdev->rs4xx_hardware_transactions) == 0 &&\n"
            "\t\t   atomic_read(&rdev->rs4xx_hardware_readers) == 0);\n"
            "\t(void)radeon_page_flip_quiesce(rdev);",
            "\t(void)radeon_page_flip_quiesce(rdev);\n"
            "\twait_event(rdev->rs4xx_hardware_wait,\n"
            "\t\t   atomic_read(&rdev->rs4xx_hardware_transactions) == 0 &&\n"
            "\t\t   atomic_read(&rdev->rs4xx_hardware_readers) == 0);",
        ),
        (
            "parked publisher queues with active transaction",
            SUBTREE / "radeon_device.c",
            "\t    atomic_read(&rdev->rs4xx_hardware_transactions) != 0)\n",
            "",
        ),
        (
            "running publisher coalescing removed",
            SUBTREE / "radeon_device.c",
            "\t    atomic_read(&rdev->rs4xx_parked_publish_running) ||\n",
            "",
        ),
        (
            "refusal request loses ordered publication",
            SUBTREE / "radeon_device.c",
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n",
            "\tatomic_set(&rdev->rs4xx_parked_publish_pending, 1);\n",
        ),
        (
            "publisher release loses ordered publication",
            SUBTREE / "radeon_device.c",
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_running, 0);\n",
            "\tatomic_set(&rdev->rs4xx_parked_publish_running, 0);\n",
        ),
        (
            "publisher release drops final requeue",
            SUBTREE / "radeon_device.c",
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_running, 0);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n",
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_running, 0);\n",
        ),
        (
            "publisher clears a concurrent refusal",
            SUBTREE / "radeon_device.c",
            "\tradeon_rs4xx_publish_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_running, 0);\n",
            "\tradeon_rs4xx_publish_parked_state(rdev);\n"
            "\tatomic_set(&rdev->rs4xx_parked_publish_pending, 0);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_running, 0);\n",
        ),
        (
            "terminal publisher disable removed",
            SUBTREE / "radeon_device.c",
            "\tdisable_work_sync(&rdev->rs4xx_parked_publish_work);\n",
            "",
        ),
        (
            "terminal publisher work initialization removed",
            SUBTREE / "radeon_device.c",
            "\trdev->rs4xx_parked_publish_work_initialized = true;\n",
            "",
        ),
        (
            "unguarded TTM unpopulate",
            SUBTREE / "radeon_ttm.c",
            "\tr = radeon_rs4xx_hardware_transaction_wait_begin(rdev);\n"
            "\tif (r == -ESHUTDOWN)",
            "\tr = 0;\n\tif (r == -ESHUTDOWN)",
        ),
        (
            "TTM unpopulate drops terminal backing retention",
            SUBTREE / "radeon_ttm.c",
            (
                "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
                "\t\tif (gtt && gtt->bound &&\n"
                "\t\t    radeon_rs4xx_hardware_target(rdev))\n"
                "\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);\n"
            ),
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n",
        ),
        (
            "unexpected direct parked latch caller",
            SUBTREE / "radeon_device.c",
            "static int radeon_gpu_reset_internal(struct radeon_device *rdev)",
            "static void extra_latch(struct radeon_device *rdev)\n"
            "{\n"
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "}\n"
            "static int radeon_gpu_reset_internal(struct radeon_device *rdev)",
        ),
        (
            "unexpected teardown refusal latch caller",
            SUBTREE / "radeon_ttm.c",
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n\t\treturn r;",
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
            "\t\treturn r;",
        ),
        (
            "reset ring-restore parked latch removed",
            SUBTREE / "radeon_device.c",
            "\t\t\tr = restore_result;\n"
            "\t\t\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\t\t\tgpu_parked = true;",
            "\t\t\tr = restore_result;\n\t\t\tgpu_parked = true;",
        ),
        (
            "CP microengine restore parked latch removed",
            SUBTREE / "radeon_rs4xx_dev.c",
            "\tradeon_rs4xx_latch_parked_state(rdev);\n",
            "",
        ),
        (
            "RS400 initialization parked latch removed",
            SUBTREE / "rs400.c",
            "\tif (r) {\n"
            "\t\tradeon_rs4xx_latch_parked_state(rdev);\n"
            '\t\tdev_err(rdev->dev, "reset failed");',
            '\tif (r) {\n\t\tdev_err(rdev->dev, "reset failed");',
        ),
        (
            "RS400 startup failure returns success",
            SUBTREE / "rs400.c",
            "\tr = rs400_startup(rdev);\n"
            "\tif (r) {\n"
            "\t\trdev->accel_working = false;\n"
            "\t\treturn r;\n"
            "\t}",
            "\tr = rs400_startup(rdev);\n"
            "\tif (r) {\n"
            "\t\trdev->accel_working = false;\n"
            "\t\treturn 0;\n"
            "\t}",
        ),
        (
            "cursor cleanup end removed",
            SUBTREE / "radeon_cursor.c",
            "\tif (hardware_transaction)\n\t\tradeon_rs4xx_hardware_transaction_end(rdev);",
            "\tif (hardware_transaction)\n\t\treturn;",
        ),
        (
            "cursor success end removed",
            SUBTREE / "radeon_cursor.c",
            "\tret = 0;\n\tradeon_rs4xx_hardware_transaction_end(rdev);\n\thardware_transaction = false;",
            "\tret = 0;",
        ),
        (
            "cursor admission failure returns success",
            SUBTREE / "radeon_cursor.c",
            "\tif (ret)\n\t\tgoto out_exec;",
            "\tif (ret)\n\t\treturn 0;",
        ),
        (
            "unexpected unbalanced root caller",
            SUBTREE / "radeon_gem.c",
            "static vm_fault_t radeon_gem_fault",
            "static int extra_root(void) { radeon_rs4xx_hardware_transaction_begin(rdev); return 0; }\nstatic vm_fault_t radeon_gem_fault",
        ),
        (
            "terminal modeset refuses instead of no-op",
            SUBTREE / "radeon_display.c",
            "\t\treturn 0;",
            "\t\treturn -EIO;",
        ),
        (
            "BO constructor admission root omitted",
            SUBTREE / "radeon_object.c",
            "\tr = radeon_rs4xx_hardware_transaction_begin(rdev);\n"
            "\tif (r)\n"
            "\t\treturn r;\n"
            "\tbo = kzalloc",
            "\tif (r)\n\t\treturn r;\n\tbo = kzalloc",
        ),
        (
            "BO constructor admission follows allocation",
            SUBTREE / "radeon_object.c",
            "\tr = radeon_rs4xx_hardware_transaction_begin(rdev);\n"
            "\tif (r)\n"
            "\t\treturn r;\n"
            "\tbo = kzalloc(sizeof(*bo), GFP_KERNEL);",
            "\tbo = kzalloc(sizeof(*bo), GFP_KERNEL);\n"
            "\tr = radeon_rs4xx_hardware_transaction_begin(rdev);\n"
            "\tif (r)\n"
            "\t\treturn r;",
        ),
        (
            "BO destructor live decrement omitted",
            SUBTREE / "radeon_object.c",
            "atomic_dec_and_test(&rdev->rs4xx_live_bos)",
            "atomic_read(&rdev->rs4xx_live_bos)",
        ),
        (
            "BO destructor admission root omitted",
            SUBTREE / "radeon_object.c",
            "\t\t\tr = radeon_rs4xx_hardware_transaction_wait_begin(rdev);",
            "\t\t\tr = 0;",
        ),
        (
            "TT wait follows replacement bind",
            SUBTREE / "radeon_ttm.c",
            "\tr = ttm_bo_wait_ctx(bo, ctx);\n"
            "\tif (r)\n"
            "\t\tgoto out_transaction;\n"
            "\tif (new_mem->mem_type == TTM_PL_TT) {\n"
            "\t\tnewly_bound = radeon_rs4xx_hardware_target(rdev) &&\n"
            "\t\t\t!radeon_ttm_tt_is_bound(bo->bdev, bo->ttm);\n"
            "\t\tr = radeon_ttm_tt_bind(bo->bdev, bo->ttm, new_mem);\n"
            "\t\tif (r)\n"
            "\t\t\tgoto out_transaction;\n"
            "\t}",
            "\tif (new_mem->mem_type == TTM_PL_TT) {\n"
            "\t\tnewly_bound = radeon_rs4xx_hardware_target(rdev) &&\n"
            "\t\t\t!radeon_ttm_tt_is_bound(bo->bdev, bo->ttm);\n"
            "\t\tr = radeon_ttm_tt_bind(bo->bdev, bo->ttm, new_mem);\n"
            "\t\tif (r)\n"
            "\t\t\tgoto out_transaction;\n"
            "\t}\n"
            "\tr = ttm_bo_wait_ctx(bo, ctx);\n"
            "\tif (r)\n"
            "\t\tgoto out_transaction;",
        ),
        (
            "newly-bound rollback omitted",
            SUBTREE / "radeon_ttm.c",
            "\tif (r && newly_bound) {\n"
            "\t\trollback_result = radeon_ttm_tt_unbind_status(bo->bdev, bo->ttm);\n"
            "\t\tif (rollback_result)\n"
            "\t\t\tr = rollback_result;\n"
            "\t}\n",
            "",
        ),
    )
    failures = 0
    for label, path, old, new in mutations:
        write_fixture_sources(root)
        source_path = root / path
        source = source_path.read_text(encoding="utf-8")
        if source.count(old) != 1:
            print(f"selftest fixture error: {label}", file=sys.stderr)
            failures += 1
            continue
        source_path.write_text(source.replace(old, new, 1), encoding="utf-8")
        try:
            check_contract(root)
        except GuardError:
            print(f"selftest known-bad rejected: {label}")
        else:
            print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    print(f"selftest: 1 good and {len(mutations)} bad fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="classify built-in known-good and known-bad source fixtures",
    )
    args = parser.parse_args()
    if args.selftest:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            return selftest(Path(directory))
    try:
        check_contract(args.root)
    except GuardError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(
        "RS4xx hardware admission contract: "
        f"{len(ROOTS)} operational callers, "
        f"{len(expected_call_sites())} direct call-site shapes and "
        f"{sum(expected_call_sites().values())} direct call occurrences proven"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
