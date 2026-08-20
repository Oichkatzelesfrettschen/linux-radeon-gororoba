#!/usr/bin/env python3
"""Check the RS4xx lifecycle transition contract from source only.

The policy names every transition entry and every branch-specific terminal
edge.  The checker parses only the checked-in Radeon source and policy.  A
passing result proves source-static shape; it does not prove compilation,
installation, or hardware behavior.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import shutil
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

POLICY = Path("policy/rs4xx-hardware-transition-contract.tsv")
PCI_AUTHORITY = Path("policy/pci-runtime-resume-rollback-authority.toml")
UPSTREAM_BASE = Path("UPSTREAM_BASE.toml")
RADEON = Path("drivers/gpu/drm/radeon")
EXPECTED_PCI_AUTHORITY_SHA256 = (
    "8216c65513cb7a0dd2d6aa915d2ae1bc6521fddcdb959d8d1bbb80fcff7009b7"
)
POLICY_COLUMNS = (
    "mechanism",
    "edge_kind",
    "path",
    "function",
    "branch",
    "source_anchor",
    "target",
    "expected",
    "evidence_scope",
)
SOURCE_FILES = (
    UPSTREAM_BASE,
    PCI_AUTHORITY,
    RADEON / "radeon.h",
    RADEON / "radeon_device.c",
    RADEON / "radeon_rs4xx_dev.c",
    RADEON / "radeon_drv.c",
    RADEON / "radeon_kms.c",
    RADEON / "rs400.c",
    RADEON / "radeon_ib.c",
)
STATES = {
    "RADEON_RS4XX_HARDWARE_RUNNING",
    "RADEON_RS4XX_HARDWARE_RESETTING",
    "RADEON_RS4XX_HARDWARE_SUSPENDING",
    "RADEON_RS4XX_HARDWARE_SUSPENDED",
    "RADEON_RS4XX_HARDWARE_RESUMING",
    "RADEON_RS4XX_HARDWARE_SHUTTING_DOWN",
    "RADEON_RS4XX_HARDWARE_SHUTDOWN",
    "RADEON_RS4XX_HARDWARE_PARKED",
}
TERMINAL_CALL_RE = re.compile(
    r"\bradeon_rs4xx_hardware_transition_end\s*\(\s*rdev\s*,\s*"
    r"(?P<state>RADEON_RS4XX_HARDWARE_[A-Z_]+)\s*\)"
)


class ContractError(Exception):
    """The source or policy violates the RS4xx transition contract."""


@dataclass(frozen=True)
class FunctionSource:
    """One function body with source and comment-masked views."""

    path: Path
    name: str
    source: str
    body_start: int
    body_end: int
    masked_body: str

    @property
    def body(self) -> str:
        return self.source[self.body_start : self.body_end]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def read_utf8(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except FileNotFoundError as exc:
        raise ContractError(f"required file is absent: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ContractError(f"checked-in text is not UTF-8 text: {path}") from exc


def read_source(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ContractError(f"required source is absent: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ContractError(f"source is not valid UTF-8: {path}") from exc


def mask_noncode(source: str) -> str:
    """Blank comments and literals while preserving offsets and newlines."""

    result = list(source)
    index = 0
    state = "code"
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if current == "/" and following == "*":
                result[index] = result[index + 1] = " "
                index += 2
                state = "block"
                continue
            if current == "/" and following == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "line"
                continue
            if current == '"':
                result[index] = " "
                state = "string"
            elif current == "'":
                result[index] = " "
                state = "character"
        elif state == "block":
            if current == "*" and following == "/":
                result[index] = result[index + 1] = " "
                index += 2
                state = "code"
                continue
            if current != "\n":
                result[index] = " "
        elif state == "line":
            if current == "\n":
                state = "code"
            else:
                result[index] = " "
        else:
            if current == "\\" and following:
                result[index] = " "
                if following != "\n":
                    result[index + 1] = " "
                index += 2
                continue
            if (state == "string" and current == '"') or (
                state == "character" and current == "'"
            ):
                result[index] = " "
                state = "code"
            elif current != "\n":
                result[index] = " "
        index += 1
    require(state != "block", "unterminated block comment")
    return "".join(result)


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise ContractError(f"unterminated delimiter {left}{right}")


def locate_function(source: str, name: str) -> tuple[int, int]:
    """Return the body offsets for one C function definition."""

    masked = mask_noncode(source)
    for candidate in re.finditer(rf"\b{re.escape(name)}\s*\(", masked):
        opening_paren = masked.find("(", candidate.start(), candidate.end())
        closing_paren = matching_delimiter(masked, opening_paren, "(", ")")
        after = re.match(r"\s*\{", masked[closing_paren + 1 :])
        if after is None:
            continue
        opening_brace = closing_paren + 1 + after.end() - 1
        closing_brace = matching_delimiter(masked, opening_brace, "{", "}")
        return opening_brace + 1, closing_brace
    raise ContractError(f"function definition is absent: {name}")


def function_source(root: Path, path: Path, name: str) -> FunctionSource:
    source_path = root / path
    source = read_source(source_path)
    body_start, body_end = locate_function(source, name)
    body = source[body_start:body_end]
    return FunctionSource(path, name, source, body_start, body_end, mask_noncode(body))


def require_order(body: str, owner: str, expressions: tuple[str, ...]) -> None:
    offset = 0
    for expression in expressions:
        match = re.search(expression, body[offset:], re.MULTILINE | re.DOTALL)
        if not match:
            raise ContractError(f"{owner}: ordered contract misses {expression}")
        offset += match.end()


def require_order_from(
    body: str, owner: str, start: str, expressions: tuple[str, ...]
) -> None:
    match = re.search(start, body, re.MULTILINE | re.DOTALL)
    require(match is not None, f"{owner}: order anchor is absent: {start}")
    require_order(body[match.start() :], owner, expressions)


def call_matches(function: FunctionSource, target: str) -> list[re.Match[str]]:
    return list(
        re.finditer(
            rf"\b{re.escape(target)}\s*\(",
            function.masked_body,
            re.MULTILINE,
        )
    )


def load_policy(root: Path) -> list[dict[str, str]]:
    raw = read_utf8(root / POLICY)
    reader = csv.DictReader(raw.splitlines(), delimiter="\t")
    require(
        tuple(reader.fieldnames or ()) == POLICY_COLUMNS,
        "transition policy header differs",
    )
    rows = list(reader)
    require(rows, "transition policy is empty")
    identifiers: set[tuple[str, str, str, str, str]] = set()
    for row in rows:
        require(
            all(row.get(column, "").strip() for column in POLICY_COLUMNS),
            "transition policy contains an empty field",
        )
        identifier = (
            row["mechanism"],
            row["edge_kind"],
            row["path"],
            row["function"],
            row["branch"],
        )
        require(identifier not in identifiers, f"policy repeats {identifier}")
        identifiers.add(identifier)
        require(
            row["edge_kind"] in {"begin", "terminal", "route"},
            f"{identifier}: unsupported edge kind",
        )
        require(
            row["evidence_scope"] == "source-static",
            f"{identifier}: evidence scope is not source-static",
        )
        try:
            re.compile(row["source_anchor"], re.MULTILINE | re.DOTALL)
        except re.error as exc:
            raise ContractError(f"{identifier}: invalid source anchor") from exc
        if row["edge_kind"] == "terminal":
            require(
                row["target"] == "radeon_rs4xx_hardware_transition_end",
                f"{identifier}: terminal target differs",
            )
            require(row["expected"] in STATES, f"{identifier}: terminal state differs")
        elif row["edge_kind"] == "begin":
            require(
                row["target"]
                in {
                    "radeon_rs4xx_hardware_transition_begin",
                    "radeon_rs4xx_hardware_shutdown_begin",
                },
                f"{identifier}: begin target differs",
            )
        else:
            require(
                row["target"].startswith("radeon_rs4xx_")
                and row["target"].endswith(("_state", "_state_locked", "_shutdown"))
                or row["target"]
                in {
                    "radeon_rs4xx_latch_parked_state",
                    "radeon_rs4xx_publish_parked_state",
                    "radeon_rs4xx_finish_terminal_shutdown",
                },
                f"{identifier}: route target is not a Radeon transition helper",
            )
    return rows


def check_policy_edges(root: Path, rows: list[dict[str, str]]) -> None:
    """Check unique branch anchors and exact call denominators."""

    functions: dict[tuple[Path, str], FunctionSource] = {}
    grouped: dict[tuple[Path, str, str], list[dict[str, str]]] = {}
    anchored_positions: dict[tuple[Path, str, str], list[int]] = {}
    for row in rows:
        key = (Path(row["path"]), row["function"])
        function = functions.setdefault(key, function_source(root, *key))
        pattern = re.compile(row["source_anchor"], re.MULTILINE | re.DOTALL)
        matches = list(pattern.finditer(function.masked_body))
        identifier = f"{row['mechanism']}:{row['branch']}"
        require(
            len(matches) == 1,
            f"{identifier}: source anchor is not function-scoped unique",
        )
        match = matches[0]
        target_position = function.masked_body.rfind(
            row["target"], match.start(), match.end()
        )
        require(
            target_position >= 0,
            f"{identifier}: source anchor does not contain its target",
        )
        anchored_positions.setdefault((key[0], key[1], row["target"]), []).append(
            target_position
        )
        if row["edge_kind"] == "terminal":
            state_match = re.match(
                r"\s*(RADEON_RS4XX_HARDWARE_[A-Z_]+)\s*\)",
                function.masked_body[match.end() :],
            )
            require(state_match is not None, f"{identifier}: terminal state is absent")
            require(
                state_match.group(1) == row["expected"],
                f"{identifier}: terminal state differs",
            )
        elif row["edge_kind"] == "begin":
            require(
                re.search(rf"\b{re.escape(row['target'])}\b", match.group(0))
                is not None,
                f"{identifier}: begin call is absent from source anchor",
            )
            if row["expected"] != "NONE":
                require(
                    row["expected"] in match.group(0),
                    f"{identifier}: begin state is absent from source anchor",
                )
        else:
            require(
                re.search(rf"\b{re.escape(row['target'])}\b", match.group(0))
                is not None,
                f"{identifier}: route target is absent from source anchor",
            )
        grouped.setdefault((key[0], key[1], row["target"]), []).append(row)

    for (path, function_name, target), group in grouped.items():
        function = functions[(path, function_name)]
        actual = call_matches(function, target)
        positions = anchored_positions[(path, function_name, target)]
        require(
            len(actual) == len(group),
            f"{path}:{function_name}:{target}: policy call denominator differs",
        )
        require(
            len(set(positions)) == len(positions),
            f"{path}:{function_name}:{target}: policy anchors share one call",
        )
        require(
            set(positions) == {match.start() for match in actual},
            f"{path}:{function_name}:{target}: policy anchors omit a call",
        )

    terminal_groups = [
        (key, group)
        for key, group in grouped.items()
        if any(row["edge_kind"] == "terminal" for row in group)
    ]
    for (path, function_name, target), group in terminal_groups:
        function = functions[(path, function_name)]
        actual = TERMINAL_CALL_RE.findall(function.masked_body)
        expected = [row["expected"] for row in group]
        require(
            len(actual) == len(expected) and sorted(actual) == sorted(expected),
            f"{path}:{function_name}: terminal state denominator differs",
        )


def check_state_machine(root: Path) -> None:
    header = read_source(root / RADEON / "radeon.h")
    enum_match = re.search(
        r"enum radeon_rs4xx_hardware_state\s*\{(.*?)\};",
        mask_noncode(header),
        re.DOTALL,
    )
    require(enum_match is not None, "RS4xx hardware state enum is absent")
    enum_members = tuple(
        member.strip() for member in enum_match.group(1).split(",") if member.strip()
    )
    require(
        enum_members
        == (
            "RADEON_RS4XX_HARDWARE_RUNNING = 0",
            "RADEON_RS4XX_HARDWARE_RESETTING",
            "RADEON_RS4XX_HARDWARE_SUSPENDING",
            "RADEON_RS4XX_HARDWARE_SUSPENDED",
            "RADEON_RS4XX_HARDWARE_RESUMING",
            "RADEON_RS4XX_HARDWARE_SHUTTING_DOWN",
            "RADEON_RS4XX_HARDWARE_SHUTDOWN",
            "RADEON_RS4XX_HARDWARE_PARKED",
        ),
        "RS4xx hardware state denominator differs",
    )
    require(
        re.search(r"spinlock_t\s+rs4xx_hardware_state_lock\s*;", header) is not None,
        "RS4xx state spinlock declaration is absent",
    )

    initialization = function_source(
        root, RADEON / "radeon_device.c", "radeon_device_init"
    )
    require_order(
        initialization.masked_body,
        "hardware state initialization",
        (
            r"atomic_set\s*\(\s*&rdev->rs4xx_hardware_state\s*,\s*"
            r"RADEON_RS4XX_HARDWARE_RUNNING\s*\)",
            r"atomic_set\s*\(\s*&rdev->rs4xx_hardware_closing\s*,\s*0\s*\)",
            r"atomic_set\s*\(\s*&rdev->rs4xx_hardware_transactions\s*,\s*0\s*\)",
            r"atomic_set\s*\(\s*&rdev->rs4xx_hardware_readers\s*,\s*0\s*\)",
            r"init_waitqueue_head\s*\(\s*&rdev->rs4xx_hardware_wait\s*\)",
            r"spin_lock_init\s*\(\s*&rdev->rs4xx_hardware_state_lock\s*\)",
            r"mutex_init\s*\(\s*&rdev->rs4xx_hardware_transition_lock\s*\)",
        ),
    )

    transaction = function_source(
        root, RADEON / "radeon_device.c", "radeon_rs4xx_hardware_transaction_begin"
    )
    require_order(
        transaction.masked_body,
        "transaction admission ordering",
        (
            r"READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)",
            r"atomic_read_acquire\s*\(\s*&rdev->rs4xx_hardware_state\s*\)",
            r"atomic_read_acquire\s*\(\s*&rdev->rs4xx_hardware_closing\s*\)",
            r"atomic_inc\s*\(\s*&rdev->rs4xx_hardware_transactions\s*\)",
            r"smp_mb__after_atomic\s*\(\s*\)",
            r"state\s*=\s*atomic_read\s*\(\s*&rdev->rs4xx_hardware_state\s*\)",
            r"atomic_dec_and_test\s*\(\s*&rdev->rs4xx_hardware_transactions\s*\)",
            r"wake_up_all\s*\(\s*&rdev->rs4xx_hardware_wait\s*\)",
        ),
    )
    require(
        transaction.masked_body.count("READ_ONCE(rdev->gpu_parked)") >= 2,
        "transaction admission lacks post-increment PARKED revalidation",
    )

    reader = function_source(
        root, RADEON / "radeon_device.c", "radeon_rs4xx_hardware_reader_begin"
    )
    require_order(
        reader.masked_body,
        "reader admission ordering",
        (
            r"atomic_read_acquire\s*\(\s*&rdev->rs4xx_hardware_state\s*\)",
            r"READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)",
            r"atomic_inc\s*\(\s*&rdev->rs4xx_hardware_readers\s*\)",
            r"smp_mb__after_atomic\s*\(\s*\)",
            r"state\s*=\s*atomic_read\s*\(\s*&rdev->rs4xx_hardware_state\s*\)",
            r"atomic_dec_and_test\s*\(\s*&rdev->rs4xx_hardware_readers\s*\)",
            r"wake_up_all\s*\(\s*&rdev->rs4xx_hardware_wait\s*\)",
        ),
    )
    require(
        reader.masked_body.count("READ_ONCE(rdev->gpu_parked)") >= 2,
        "reader admission lacks post-increment PARKED revalidation",
    )

    transition_start = function_source(
        root,
        RADEON / "radeon_device.c",
        "radeon_rs4xx_hardware_transition_start_locked",
    )
    require_order(
        transition_start.masked_body,
        "transition transaction drain",
        (
            r"atomic_set\s*\(\s*&rdev->rs4xx_hardware_closing\s*,\s*1\s*\)",
            r"smp_mb\s*\(\s*\)",
            r"wait_event\s*\(\s*rdev->rs4xx_hardware_wait\s*,\s*"
            r"atomic_read\s*\(\s*&rdev->rs4xx_hardware_transactions\s*\)\s*==\s*0",
        ),
    )
    owner = re.search(
        r"WRITE_ONCE\s*\(\s*rdev->rs4xx_hardware_owner\s*,\s*current\s*\)",
        transition_start.masked_body,
    )
    require(owner is not None, "transition owner publication is absent")
    require_order(
        transition_start.masked_body[owner.start() :],
        "transition reader drain",
        (
            r"smp_wmb\s*\(\s*\)",
            r"spin_lock_irqsave\s*\(\s*&rdev->rs4xx_hardware_state_lock",
            r"atomic_set_release\s*\(\s*&rdev->rs4xx_hardware_state",
            r"spin_unlock_irqrestore\s*\(\s*&rdev->rs4xx_hardware_state_lock",
            r"smp_mb\s*\(\s*\)",
            r"wait_event\s*\(\s*rdev->rs4xx_hardware_wait\s*,\s*"
            r"atomic_read\s*\(\s*&rdev->rs4xx_hardware_readers\s*\)\s*==\s*0",
        ),
    )

    transition_end = function_source(
        root, RADEON / "radeon_device.c", "radeon_rs4xx_hardware_transition_end"
    )
    require_order(
        transition_end.masked_body,
        "transition terminal publication",
        (
            r"wait_event\s*\(\s*rdev->rs4xx_hardware_wait\s*,\s*"
            r"atomic_read\s*\(\s*&rdev->rs4xx_hardware_transactions\s*\)\s*==\s*0\s*&&\s*"
            r"atomic_read\s*\(\s*&rdev->rs4xx_hardware_readers\s*\)\s*==\s*0",
            r"WRITE_ONCE\s*\(\s*rdev->rs4xx_hardware_owner\s*,\s*NULL\s*\)",
            r"smp_wmb\s*\(\s*\)",
            r"spin_lock_irqsave\s*\(\s*&rdev->rs4xx_hardware_state_lock",
            r"state\s*=\s*atomic_read\s*\(\s*&rdev->rs4xx_hardware_state\s*\)",
            r"published_state\s*=\s*final_state",
            r"final_state\s*!\s*=\s*RADEON_RS4XX_HARDWARE_SHUTDOWN",
            r"state\s*==\s*RADEON_RS4XX_HARDWARE_PARKED",
            r"READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)",
            r"published_state\s*=\s*RADEON_RS4XX_HARDWARE_PARKED",
            r"atomic_set_release\s*\(\s*&rdev->rs4xx_hardware_state",
            r"atomic_set_release\s*\(\s*&rdev->rs4xx_hardware_closing",
            r"spin_unlock_irqrestore\s*\(\s*&rdev->rs4xx_hardware_state_lock",
        ),
    )

    parked_locked = function_source(
        root,
        RADEON / "radeon_device.c",
        "radeon_rs4xx_publish_parked_hardware_state_locked",
    )
    require_order(
        parked_locked.masked_body,
        "PARKED state dominance",
        (
            r"state\s*=\s*atomic_read\s*\(\s*&rdev->rs4xx_hardware_state\s*\)",
            r"state\s*!\s*=\s*RADEON_RS4XX_HARDWARE_PARKED",
            r"state\s*!\s*=\s*RADEON_RS4XX_HARDWARE_SHUTDOWN",
            r"atomic_set_release\s*\(\s*&rdev->rs4xx_hardware_state\s*,\s*"
            r"RADEON_RS4XX_HARDWARE_PARKED\s*\)",
        ),
    )

    latch = function_source(
        root, RADEON / "radeon_device.c", "radeon_rs4xx_latch_parked_state"
    )
    require_order(
        latch.masked_body,
        "parked latch ordering",
        (
            r"spin_lock_irqsave\s*\(\s*&rdev->rs4xx_hardware_state_lock",
            r"WRITE_ONCE\s*\(\s*rdev->gpu_parked\s*,\s*true\s*\)",
            r"WRITE_ONCE\s*\(\s*rdev->accel_working\s*,\s*false\s*\)",
            r"WRITE_ONCE\s*\(\s*rdev->needs_reset\s*,\s*false\s*\)",
            r"WRITE_ONCE\s*\(\s*rdev->ring\s*\[\s*ring_index\s*\]\.ready\s*,\s*false\s*\)",
            r"atomic_set_release\s*\(\s*&rdev->rs4xx_hardware_closing\s*,\s*1\s*\)",
            r"radeon_rs4xx_publish_parked_hardware_state_locked\s*\(\s*rdev\s*\)",
            r"spin_unlock_irqrestore\s*\(\s*&rdev->rs4xx_hardware_state_lock",
            r"smp_mb\s*\(\s*\)",
            r"wake_up_all\s*\(\s*&rdev->rs4xx_hardware_wait\s*\)",
        ),
    )
    require(
        re.search(
            r"if\s*\(\s*READ_ONCE\s*\(\s*rdev->rs4xx_fence_work_initialized\s*\)\s*\)\s*"
            r"wake_up_all\s*\(\s*&rdev->fence_queue\s*\)",
            latch.masked_body,
        )
        is not None,
        "parked latch fence wake is absent",
    )

    latch_wrapper = function_source(
        root, RADEON / "radeon_device.c", "radeon_rs4xx_latch_teardown_refusal"
    )
    wrapper = re.sub(r"\s+", " ", latch_wrapper.masked_body).strip()
    require(
        wrapper == "radeon_rs4xx_latch_parked_state(rdev); "
        "atomic_xchg(&rdev->rs4xx_parked_publish_pending, 1); "
        "radeon_rs4xx_queue_parked_publish(rdev);",
        "latch-only teardown refusal gained blocking cleanup",
    )

    publisher = function_source(
        root, RADEON / "radeon_device.c", "radeon_rs4xx_publish_parked_state"
    )
    require_order(
        publisher.masked_body,
        "full parked publisher ordering",
        (
            r"radeon_rs4xx_latch_parked_state\s*\(\s*rdev\s*\)",
            r"radeon_rs4xx_hardware_transition_owned\s*\(\s*rdev\s*\)",
            r"if\s*\(\s*!transition_owned\s*\)\s*mutex_lock\s*\(\s*&rdev->rs4xx_hardware_transition_lock\s*\)",
            r"wait_event\s*\(\s*rdev->rs4xx_hardware_wait\s*,\s*"
            r"atomic_read\s*\(\s*&rdev->rs4xx_hardware_transactions\s*\)\s*==\s*0\s*&&\s*"
            r"atomic_read\s*\(\s*&rdev->rs4xx_hardware_readers\s*\)\s*==\s*0",
            r"radeon_page_flip_quiesce\s*\(\s*rdev\s*\)",
            r"radeon_irq_kms_fini_hardwareless\s*\(\s*rdev\s*\)",
            r"cancel_delayed_work_sync\s*\(\s*&rdev->pm\.dynpm_idle_work\s*\)",
            r"radeon_fence_driver_force_completion_parked\s*\(\s*rdev\s*\)",
            r"radeon_page_flip_finalize_retained\s*\(\s*rdev\s*,\s*false\s*\)",
            r"if\s*\(\s*!transition_owned\s*\)\s*mutex_unlock\s*\(\s*&rdev->rs4xx_hardware_transition_lock\s*\)",
        ),
    )
    for forbidden in ("radeon_rs4xx_hardware_transition_end", "wait_event_timeout"):
        require(
            forbidden not in publisher.masked_body,
            f"full publisher contains {forbidden}",
        )


def check_ib_failure_propagation(root: Path) -> None:
    ib = function_source(root, RADEON / "radeon_ib.c", "radeon_ib_ring_tests")
    require_order(
        ib.masked_body,
        "RS4xx IB failure publication",
        (
            r"r\s*=\s*radeon_ib_test\s*\(\s*rdev\s*,\s*i\s*,\s*ring\s*\)",
            r"if\s*\(\s*radeon_rs4xx_hardware_target\s*\(\s*rdev\s*\)\s*\)\s*\{",
            r"radeon_rs4xx_publish_parked_state\s*\(\s*rdev\s*\)",
            r"DRM_ERROR\s*\(",
            r"return\s+r\s*;",
        ),
    )
    require(
        re.search(
            r"if\s*\(\s*radeon_rs4xx_hardware_target\s*\(\s*rdev\s*\)\s*\)\s*"
            r"\{\s*radeon_rs4xx_publish_parked_state\s*\(\s*rdev\s*\)\s*;\s*"
            r"DRM_ERROR\s*\([^;]*\)\s*;\s*return\s+r\s*;\s*\}",
            ib.masked_body,
            re.DOTALL,
        )
        is not None,
        "RS4xx IB failure branch differs from the centralized publisher route",
    )
    device_init = function_source(
        root, RADEON / "radeon_device.c", "radeon_device_init"
    )
    require_order(
        device_init.masked_body,
        "init IB failure propagation",
        (
            r"r\s*=\s*radeon_ib_ring_tests\s*\(\s*rdev\s*\)",
            r"if\s*\(\s*r\s*\)\s*\{",
            r"radeon_rs4xx_hardware_target\s*\(\s*rdev\s*\)",
            r"READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)",
            r"goto\s+failed\s*;",
        ),
    )
    resume = function_source(root, RADEON / "radeon_device.c", "radeon_resume_kms")
    require_order(
        resume.masked_body,
        "resume IB failure propagation",
        (
            r"r\s*=\s*radeon_ib_ring_tests\s*\(\s*rdev\s*\)",
            r"if\s*\(\s*r\s*\)\s*\{",
            r"if\s*\(\s*radeon_rs4xx_hardware_target\s*\(\s*rdev\s*\)\s*\)",
            r"goto\s+rs4xx_resume_parked\s*;",
        ),
    )
    require(
        re.search(
            r"r\s*=\s*radeon_ib_ring_tests\s*\(\s*rdev\s*\)\s*;\s*"
            r"if\s*\(\s*r\s*\)\s*\{\s*"
            r"if\s*\(\s*radeon_rs4xx_hardware_target\s*\(\s*rdev\s*\)\s*\)\s*"
            r"goto\s+rs4xx_resume_parked\s*;",
            resume.masked_body,
            re.DOTALL,
        )
        is not None,
        "resume IB failure route is not contiguous with the failure branch",
    )
    reset = function_source(
        root, RADEON / "radeon_device.c", "radeon_gpu_reset_internal"
    )
    require_order(
        reset.masked_body,
        "reset IB failure propagation",
        (
            r"r\s*=\s*radeon_ib_ring_tests\s*\(\s*rdev\s*\)",
            r"if\s*\(\s*rs4xx_reset\s*&&\s*READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)\s*\)",
            r"goto\s+rs4xx_reset_parked_after_downgrade\s*;",
        ),
    )
    require(
        re.search(
            r"r\s*=\s*radeon_ib_ring_tests\s*\(\s*rdev\s*\)\s*;\s*"
            r"if\s*\(\s*rs4xx_reset\s*&&\s*READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)\s*\)\s*"
            r"goto\s+rs4xx_reset_parked_after_downgrade\s*;",
            reset.masked_body,
            re.DOTALL,
        )
        is not None,
        "reset IB failure route is not contiguous with the failure branch",
    )


def check_runtime_pm_failure_restoration(root: Path) -> None:
    authority_raw = (root / PCI_AUTHORITY).read_bytes()
    try:
        authority_text = authority_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("PCI runtime rollback authority is not UTF-8 text") from exc
    require(
        hashlib.sha256(authority_raw).hexdigest() == EXPECTED_PCI_AUTHORITY_SHA256,
        "PCI runtime rollback authority identity differs",
    )
    authority = tomllib.loads(authority_text)
    upstream = tomllib.loads(read_utf8(root / UPSTREAM_BASE))
    observed_commits = {
        entry["kernel"]: entry["commit"] for entry in authority["authority"]
    }
    require(
        observed_commits
        == {
            "6.18": upstream["commit"],
            "7.1": upstream["target"]["mainline"]["commit"],
        },
        "PCI runtime rollback authority commit set differs",
    )
    for entry in authority["authority"]:
        files = entry.get("file", [])
        observed_paths = {file_entry["path"] for file_entry in files}
        require(
            len(files) == 2
            and observed_paths == {"drivers/pci/pci.c", "drivers/base/power/runtime.c"},
            f"PCI runtime rollback authority file set differs for {entry['kernel']}",
        )
        require(
            all(
                re.fullmatch(r"[0-9a-f]{64}", file_entry["sha256"]) is not None
                for file_entry in files
            ),
            f"PCI runtime rollback authority digest differs for {entry['kernel']}",
        )

    suspend_restore = function_source(
        root,
        RADEON / "radeon_drv.c",
        "radeon_runtime_pm_restore_suspend_failure",
    )
    require_order(
        suspend_restore.masked_body,
        "runtime suspend failure restoration",
        (
            r"radeon_rs4xx_terminal_ownership_retained\s*\(\s*rdev\s*\)",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_OFF",
            r"return\s*;",
            r"if\s*\(\s*!drm_dev->mode_config\.poll_enabled\s*\)",
            r"drm_kms_helper_poll_enable\s*\(\s*drm_dev\s*\)",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_ON",
        ),
    )

    low_power = function_source(
        root,
        RADEON / "radeon_drv.c",
        "radeon_runtime_pm_restore_low_power_state",
    )
    require_order(
        low_power.masked_body,
        "runtime PCI low-power policy",
        (
            r"if\s*\(\s*radeon_is_atpx_hybrid\s*\(\s*\)\s*\)",
            r"pci_set_power_state\s*\(\s*pdev\s*,\s*PCI_D3cold\s*\)",
            r"else\s+if\s*\(\s*!radeon_has_atpx_dgpu_power_cntl\s*\(\s*\)\s*\)",
            r"pci_set_power_state\s*\(\s*pdev\s*,\s*PCI_D3hot\s*\)",
        ),
    )

    resume_restore = function_source(
        root,
        RADEON / "radeon_drv.c",
        "radeon_runtime_pm_restore_resume_failure",
    )
    require_order(
        resume_restore.masked_body,
        "runtime resume failure restoration",
        (
            r"if\s*\(\s*drm_dev->mode_config\.poll_enabled\s*\)",
            r"drm_kms_helper_poll_disable\s*\(\s*drm_dev\s*\)",
            r"if\s*\(\s*radeon_rs4xx_terminal_ownership_retained\s*\(\s*rdev\s*\)\s*\)",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_OFF",
            r"return\s*;",
            r"pci_clear_master\s*\(\s*pdev\s*\)",
            r"if\s*\(\s*device_enabled\s*\)",
            r"pci_disable_device\s*\(\s*pdev\s*\)",
            r"pci_save_state\s*\(\s*pdev\s*\)",
            r"radeon_runtime_pm_restore_low_power_state\s*\(\s*pdev\s*\)",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_DYNAMIC_OFF",
        ),
    )
    require(
        "drm_kms_helper_poll_enable" not in resume_restore.masked_body,
        "runtime resume failure restoration enables polling",
    )
    resume_restore_shape = re.sub(r"\s+", " ", resume_restore.masked_body).strip()
    expected_resume_restore_shape = (
        "struct radeon_device *rdev = drm_dev->dev_private; "
        "if (drm_dev->mode_config.poll_enabled) "
        "drm_kms_helper_poll_disable(drm_dev); "
        "if (radeon_rs4xx_terminal_ownership_retained(rdev)) { "
        "drm_dev->switch_power_state = DRM_SWITCH_POWER_OFF; return; } "
        "pci_clear_master(pdev); "
        "if (device_enabled) pci_disable_device(pdev); "
        "pci_save_state(pdev); "
        "radeon_runtime_pm_restore_low_power_state(pdev); "
        "drm_dev->switch_power_state = DRM_SWITCH_POWER_DYNAMIC_OFF;"
    )
    require(
        resume_restore_shape == expected_resume_restore_shape,
        "runtime resume failure restoration direct shape differs",
    )
    for forbidden in (
        "radeon_resume(",
        "radeon_suspend(",
        "radeon_agp_resume(",
        "RREG32(",
        "WREG32(",
    ):
        require(
            forbidden not in resume_restore.masked_body,
            f"runtime resume failure restoration reaches GPU hardware: {forbidden}",
        )

    runtime_suspend = function_source(
        root, RADEON / "radeon_drv.c", "radeon_pmops_runtime_suspend"
    )
    require_order(
        runtime_suspend.masked_body,
        "runtime suspend failure route",
        (
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_CHANGING",
            r"drm_kms_helper_poll_disable\s*\(\s*drm_dev\s*\)",
            r"ret\s*=\s*radeon_suspend_kms\s*\(",
            r"if\s*\(\s*ret\s*\)\s*\{",
            r"radeon_runtime_pm_restore_suspend_failure\s*\(\s*drm_dev\s*\)",
            r"return\s+ret\s*;",
            r"pci_save_state\s*\(\s*pdev\s*\)",
            r"pci_disable_device\s*\(\s*pdev\s*\)",
            r"pci_ignore_hotplug\s*\(\s*pdev\s*\)",
            r"radeon_runtime_pm_restore_low_power_state\s*\(\s*pdev\s*\)",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_DYNAMIC_OFF",
        ),
    )

    runtime_resume = function_source(
        root, RADEON / "radeon_drv.c", "radeon_pmops_runtime_resume"
    )
    require(
        re.search(
            r"struct\s+radeon_device\s+\*rdev\s*=\s*"
            r"drm_dev->dev_private\s*;",
            runtime_resume.masked_body,
        )
        is not None,
        "runtime resume terminal retry gate lacks its Radeon device owner",
    )
    require_order(
        runtime_resume.masked_body,
        "runtime resume failure routes",
        (
            r"if\s*\(\s*!radeon_is_px\s*\(\s*drm_dev\s*\)\s*\)\s*return\s+-EINVAL\s*;",
            r"if\s*\(\s*radeon_rs4xx_terminal_ownership_retained\s*\(\s*rdev\s*\)\s*\)\s*\{",
            r"drm_kms_helper_poll_disable\s*\(\s*drm_dev\s*\)",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_OFF",
            r"return\s+-EIO\s*;",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_CHANGING",
            r"pci_restore_state\s*\(\s*pdev\s*\)",
            r"ret\s*=\s*pci_enable_device\s*\(\s*pdev\s*\)",
            r"if\s*\(\s*ret\s*\)\s*\{",
            r"radeon_runtime_pm_restore_resume_failure\s*\(\s*drm_dev\s*,\s*pdev\s*,\s*false\s*\)",
            r"return\s+ret\s*;",
            r"pci_set_master\s*\(\s*pdev\s*\)",
            r"ret\s*=\s*radeon_resume_kms\s*\(",
            r"if\s*\(\s*ret\s*\)\s*\{",
            r"radeon_runtime_pm_restore_resume_failure\s*\(\s*drm_dev\s*,\s*pdev\s*,\s*true\s*\)",
            r"return\s+ret\s*;",
            r"drm_kms_helper_poll_enable\s*\(\s*drm_dev\s*\)",
            r"drm_dev->switch_power_state\s*=\s*DRM_SWITCH_POWER_ON",
        ),
    )
    terminal_retry_position = runtime_resume.masked_body.find(
        "if (radeon_rs4xx_terminal_ownership_retained(rdev))"
    )
    require(
        terminal_retry_position >= 0, "runtime resume terminal retry gate is absent"
    )
    for pci_call in (
        "pci_set_power_state(",
        "pci_restore_state(",
        "pci_enable_device(",
        "pci_set_master(",
    ):
        call_position = runtime_resume.masked_body.find(pci_call)
        require(
            call_position > terminal_retry_position,
            f"runtime resume reaches PCI before terminal retry gate: {pci_call}",
        )


def check_rs400_startup_hardware_epoch(root: Path) -> None:
    startup = function_source(root, RADEON / "rs400.c", "rs400_startup")
    require_order(
        startup.masked_body,
        "RS400 startup hardware reader epoch",
        (
            r"r\s*=\s*radeon_rs4xx_hardware_access_begin\s*\(\s*rdev\s*\)",
            r"if\s*\(\s*r\s*\)\s*return\s+r\s*;",
            r"r100_set_common_regs\s*\(\s*rdev\s*\)",
            r"rs400_mc_program\s*\(\s*rdev\s*\)",
            r"r300_clock_startup\s*\(\s*rdev\s*\)",
            r"rs400_gpu_init\s*\(\s*rdev\s*\)",
            r"r100_enable_bm\s*\(\s*rdev\s*\)",
            r"rs400_gart_enable\s*\(\s*rdev\s*\)",
            r"radeon_wb_init\s*\(\s*rdev\s*\)",
            r"radeon_fence_driver_start_ring\s*\(",
            r"radeon_irq_kms_init\s*\(\s*rdev\s*\)",
            r"r100_irq_set\s*\(\s*rdev\s*\)",
            r"RREG32\s*\(\s*RADEON_HOST_PATH_CNTL\s*\)",
            r"r\s*=\s*r100_cp_init\s*\(",
            r"radeon_ib_pool_init\s*\(\s*rdev\s*\)",
            r"out_hardware\s*:",
            r"radeon_rs4xx_hardware_access_end\s*\(\s*rdev\s*\)",
            r"return\s+r\s*;",
        ),
    )
    require(
        startup.masked_body.count("radeon_rs4xx_hardware_access_begin(rdev)") == 1,
        "RS400 startup hardware reader begin denominator differs",
    )
    require(
        startup.masked_body.count("radeon_rs4xx_hardware_access_end(rdev)") == 1,
        "RS400 startup hardware reader end denominator differs",
    )
    require(
        len(re.findall(r"\breturn\b", startup.masked_body)) == 2,
        "RS400 startup has an error return outside the hardware reader release",
    )
    require(
        len(re.findall(r"\bgoto\s+out_hardware\s*;", startup.masked_body)) == 7,
        "RS400 startup error-release denominator differs",
    )


def check_system_resume_failure_restoration(root: Path) -> None:
    rollback = function_source(
        root,
        RADEON / "radeon_device.c",
        "radeon_rs4xx_system_resume_rollback",
    )
    require_order(
        rollback.masked_body,
        "system resume PCI rollback",
        (
            r"pci_clear_master\s*\(\s*pdev\s*\)",
            r"pci_save_state\s*\(\s*pdev\s*\)",
            r"pci_set_power_state\s*\(\s*pdev\s*,\s*PCI_D3hot\s*\)",
        ),
    )
    rollback_shape = re.sub(r"\s+", " ", rollback.masked_body).strip()
    require(
        rollback_shape
        == (
            "pci_clear_master(pdev); pci_save_state(pdev); "
            "pci_set_power_state(pdev, PCI_D3hot);"
        ),
        "system resume PCI rollback direct shape differs",
    )
    for forbidden in (
        "pci_disable_device(",
        "radeon_resume(",
        "radeon_suspend(",
        "RREG32(",
        "WREG32(",
    ):
        require(
            forbidden not in rollback.masked_body,
            f"system resume PCI rollback reaches a forbidden operation: {forbidden}",
        )

    resume = function_source(root, RADEON / "radeon_device.c", "radeon_resume_kms")
    require_order(
        resume.masked_body,
        "system resume PCI failure route",
        (
            r"if\s*\(\s*resume\s*\)\s*\{",
            r"pci_set_power_state\s*\(\s*pdev\s*,\s*PCI_D0\s*\)",
            r"pci_restore_state\s*\(\s*pdev\s*\)",
            r"r\s*=\s*pci_enable_device\s*\(\s*pdev\s*\)",
            r"if\s*\(\s*r\s*\)\s*\{",
            r"if\s*\(\s*radeon_rs4xx_hardware_target\s*\(\s*rdev\s*\)\s*\)\s*\{",
            r"radeon_rs4xx_system_resume_rollback\s*\(\s*pdev\s*\)",
            r"radeon_rs4xx_hardware_transition_end\s*\(\s*rdev\s*,\s*"
            r"RADEON_RS4XX_HARDWARE_SUSPENDED\s*\)",
            r"return\s+r\s*;",
            r"if\s*\(\s*radeon_rs4xx_hardware_target\s*\(\s*rdev\s*\)\s*\)",
            r"pci_set_master\s*\(\s*pdev\s*\)",
            r"radeon_agp_resume\s*\(\s*rdev\s*\)",
        ),
    )
    require(
        resume.masked_body.count("radeon_rs4xx_system_resume_rollback(pdev)") == 1,
        "system resume PCI rollback call denominator differs",
    )
    require(
        resume.masked_body.count("pci_set_master(pdev)") == 1,
        "system resume PCI master restoration denominator differs",
    )


def check_rs400_startup_failure_propagation(root: Path) -> None:
    initialize = function_source(root, RADEON / "rs400.c", "rs400_init")
    require_order_from(
        initialize.masked_body,
        "RS400 startup failure propagation",
        r"r\s*=\s*rs400_startup\s*\(\s*rdev\s*\)",
        (
            r"r\s*=\s*rs400_startup\s*\(\s*rdev\s*\)",
            r"if\s*\(\s*r\s*\)\s*\{",
            r"r100_cp_fini\s*\(\s*rdev\s*\)",
            r"radeon_wb_fini\s*\(\s*rdev\s*\)",
            r"radeon_ib_pool_fini\s*\(\s*rdev\s*\)",
            r"fini_r\s*=\s*rs400_gart_fini\s*\(\s*rdev\s*\)",
            r"if\s*\(\s*fini_r\s*\)\s*\{",
            r"rdev->accel_working\s*=\s*false",
            r"return\s+fini_r\s*;",
            r"radeon_irq_kms_fini\s*\(\s*rdev\s*\)",
            r"rdev->accel_working\s*=\s*false",
            r"return\s+r\s*;",
            r"return\s+0\s*;",
        ),
    )


def check_repository(root: Path) -> list[dict[str, str]]:
    rows = load_policy(root)
    check_policy_edges(root, rows)
    check_state_machine(root)
    check_ib_failure_propagation(root)
    check_runtime_pm_failure_restoration(root)
    check_rs400_startup_hardware_epoch(root)
    check_system_resume_failure_restoration(root)
    check_rs400_startup_failure_propagation(root)
    return rows


def copy_fixture(repository: Path, root: Path) -> None:
    (root / POLICY.parent).mkdir(parents=True, exist_ok=True)
    shutil.copy2(repository / POLICY, root / POLICY)
    for relative in SOURCE_FILES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repository / relative, destination)


def replace_in_function(
    root: Path, path: Path, function: str, old: str, new: str
) -> None:
    source_path = root / path
    source = read_source(source_path)
    body_start, body_end = locate_function(source, function)
    body = source[body_start:body_end]
    require(
        body.count(old) == 1,
        f"self-test function anchor is not unique: {path}:{function}:{old}",
    )
    position = body_start + body.index(old)
    updated = source[:position] + new + source[position + len(old) :]
    source_path.write_text(updated, encoding="utf-8")


def replace_policy_once(root: Path, old: str, new: str) -> None:
    path = root / POLICY
    source = read_utf8(path)
    require(source.count(old) == 1, f"self-test policy anchor is not unique: {old}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def replace_file_once(root: Path, path: Path, old: str, new: str) -> None:
    source_path = root / path
    source = read_utf8(source_path)
    require(
        source.count(old) == 1,
        f"self-test file anchor is not unique: {path}:{old}",
    )
    source_path.write_text(source.replace(old, new, 1), encoding="utf-8")


Mutation = tuple[str, Path | None, str | None, str, str]


def selftest(repository: Path) -> int:
    """Classify one known-good source copy and calibrated known-bad mutations."""

    mutations: tuple[Mutation, ...] = (
        (
            "PCI authority changes failed-enable ownership",
            PCI_AUTHORITY,
            None,
            "pci_enable_device_flags decrements enable_cnt when "
            "do_pci_enable_device fails",
            "pci_enable_device_flags retains enable_cnt when "
            "do_pci_enable_device fails",
        ),
        (
            "suspend parked edge changes terminal state",
            RADEON / "radeon_device.c",
            "radeon_suspend_kms",
            "rs4xx_suspend_parked:\n\tradeon_rs4xx_publish_parked_state(rdev);\n"
            "\tradeon_rs4xx_hardware_transition_end(\n"
            "\t\trdev, RADEON_RS4XX_HARDWARE_PARKED);",
            "rs4xx_suspend_parked:\n\tradeon_rs4xx_publish_parked_state(rdev);\n"
            "\tradeon_rs4xx_hardware_transition_end(\n"
            "\t\trdev, RADEON_RS4XX_HARDWARE_RUNNING);",
        ),
        (
            "resume PCI failure publishes the wrong state",
            RADEON / "radeon_device.c",
            "radeon_resume_kms",
            "\t\t\t\tradeon_rs4xx_system_resume_rollback(pdev);\n"
            "\t\t\t\tradeon_rs4xx_hardware_transition_end(\n"
            "\t\t\t\t\trdev, RADEON_RS4XX_HARDWARE_SUSPENDED);",
            "\t\t\t\tradeon_rs4xx_system_resume_rollback(pdev);\n"
            "\t\t\t\tradeon_rs4xx_hardware_transition_end(\n"
            "\t\t\t\t\trdev, RADEON_RS4XX_HARDWARE_RUNNING);",
        ),
        (
            "system resume PCI failure bypasses rollback",
            RADEON / "radeon_device.c",
            "radeon_resume_kms",
            "\t\t\t\tradeon_rs4xx_system_resume_rollback(pdev);\n",
            "",
        ),
        (
            "system resume rollback leaves bus mastering enabled",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_system_resume_rollback",
            "\tpci_clear_master(pdev);\n",
            "",
        ),
        (
            "system resume rollback drops the cleaned retry image",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_system_resume_rollback",
            "\tpci_save_state(pdev);\n",
            "",
        ),
        (
            "system resume rollback restores the wrong power state",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_system_resume_rollback",
            "\tpci_set_power_state(pdev, PCI_D3hot);\n",
            "\tpci_set_power_state(pdev, PCI_D0);\n",
        ),
        (
            "system resume retry omits bus master restoration",
            RADEON / "radeon_device.c",
            "radeon_resume_kms",
            "\t\t\tpci_set_master(pdev);\n",
            "",
        ),
        (
            "system resume PCI failure replaces the original error",
            RADEON / "radeon_device.c",
            "radeon_resume_kms",
            "\t\t\t\treturn r;\n\t\t\t}\n\t\t\treturn -1;",
            "\t\t\t\treturn -EIO;\n\t\t\t}\n\t\t\treturn -1;",
        ),
        (
            "reset loses the state spinlock",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_hardware_transition_end",
            "\tspin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);\n",
            "",
        ),
        (
            "transition end loses PARKED dominance",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_hardware_transition_end",
            "if (final_state != RADEON_RS4XX_HARDWARE_SHUTDOWN &&\n",
            "if (false &&\n",
        ),
        (
            "latch writer barrier removed",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_latch_parked_state",
            "\tsmp_mb();\n",
            "",
        ),
        (
            "teardown refusal gains full publisher cleanup",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_latch_teardown_refusal",
            "\tradeon_rs4xx_latch_parked_state(rdev);",
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\t(void)radeon_page_flip_quiesce(rdev);",
        ),
        (
            "full publisher stops draining readers",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_publish_parked_state",
            "atomic_read(&rdev->rs4xx_hardware_readers) == 0);",
            "true);",
        ),
        (
            "transaction revalidation omits PARKED",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_hardware_transaction_begin",
            "!READ_ONCE(rdev->gpu_parked) &&\n",
            "",
        ),
        (
            "reader revalidation loses its barrier",
            RADEON / "radeon_device.c",
            "radeon_rs4xx_hardware_reader_begin",
            "\tsmp_mb__after_atomic();\n",
            "",
        ),
        (
            "IB failure omits parked publication",
            RADEON / "radeon_ib.c",
            "radeon_ib_ring_tests",
            "\t\t\t\tradeon_rs4xx_publish_parked_state(rdev);\n",
            "",
        ),
        (
            "init IB failure bypasses failed cleanup",
            RADEON / "radeon_device.c",
            "radeon_device_init",
            "\t\tif (radeon_rs4xx_hardware_target(rdev) &&\n"
            "\t\t    READ_ONCE(rdev->gpu_parked))\n\t\t\tgoto failed;",
            "\t\tif (radeon_rs4xx_hardware_target(rdev) &&\n"
            "\t\t    READ_ONCE(rdev->gpu_parked))\n\t\t\treturn r;",
        ),
        (
            "resume IB failure bypasses parked branch",
            RADEON / "radeon_device.c",
            "radeon_resume_kms",
            "\t\tif (radeon_rs4xx_hardware_target(rdev))\n"
            "\t\t\tgoto rs4xx_resume_parked;",
            "\t\tif (radeon_rs4xx_hardware_target(rdev))\n"
            '\t\t\tDRM_ERROR("RS4xx IB failure");',
        ),
        (
            "reset IB failure bypasses parked branch",
            RADEON / "radeon_device.c",
            "radeon_gpu_reset_internal",
            "\t\tif (rs4xx_reset && READ_ONCE(rdev->gpu_parked))\n"
            "\t\t\tgoto rs4xx_reset_parked_after_downgrade;",
            "\t\tif (rs4xx_reset && READ_ONCE(rdev->gpu_parked))\n\t\t\treturn r;",
        ),
        (
            "terminal runtime suspend failure publishes ON",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_suspend_failure",
            ("\t\tdrm_dev->switch_power_state = DRM_SWITCH_POWER_OFF;\n\t\treturn;"),
            ("\t\tdrm_dev->switch_power_state = DRM_SWITCH_POWER_ON;\n\t\treturn;"),
        ),
        (
            "nonterminal runtime suspend failure leaves polling disabled",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_suspend_failure",
            (
                "\tif (!drm_dev->mode_config.poll_enabled)\n"
                "\t\tdrm_kms_helper_poll_enable(drm_dev);\n"
            ),
            "",
        ),
        (
            "runtime resume failure enables polling",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_resume_failure",
            "drm_kms_helper_poll_disable(drm_dev);",
            "drm_kms_helper_poll_enable(drm_dev);",
        ),
        (
            "runtime resume failure drops terminal PCI ownership",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_resume_failure",
            "\tif (radeon_rs4xx_terminal_ownership_retained(rdev)) {\n",
            "\tif (false) {\n",
        ),
        (
            "runtime resume rollback leaves bus mastering enabled",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_resume_failure",
            "\tpci_clear_master(pdev);\n",
            "",
        ),
        (
            "runtime resume rollback leaves the PCI device enabled",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_resume_failure",
            "\t\tpci_disable_device(pdev);\n",
            "",
        ),
        (
            "runtime resume rollback drops retry state",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_resume_failure",
            "\tpci_save_state(pdev);\n",
            "",
        ),
        (
            "nonterminal runtime resume failure suppresses retry",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_resume_failure",
            "\tdrm_dev->switch_power_state = DRM_SWITCH_POWER_DYNAMIC_OFF;\n",
            "\tdrm_dev->switch_power_state = DRM_SWITCH_POWER_OFF;\n",
        ),
        (
            "runtime PCI low-power policy drops D3cold",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_low_power_state",
            "\t\tpci_set_power_state(pdev, PCI_D3cold);\n",
            "\t\tpci_set_power_state(pdev, PCI_D0);\n",
        ),
        (
            "runtime PCI low-power policy drops D3hot",
            RADEON / "radeon_drv.c",
            "radeon_runtime_pm_restore_low_power_state",
            "\t\tpci_set_power_state(pdev, PCI_D3hot);\n",
            "\t\tpci_set_power_state(pdev, PCI_D0);\n",
        ),
        (
            "runtime suspend failure bypasses restoration",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_suspend",
            "\t\tradeon_runtime_pm_restore_suspend_failure(drm_dev);\n",
            "",
        ),
        (
            "terminal runtime resume retry loses its Radeon device owner",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            "\tstruct radeon_device *rdev = drm_dev->dev_private;\n",
            "",
        ),
        (
            "terminal runtime resume retry reaches PCI restore",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            (
                "\tif (radeon_rs4xx_terminal_ownership_retained(rdev)) {\n"
                "\t\tif (drm_dev->mode_config.poll_enabled)\n"
                "\t\t\tdrm_kms_helper_poll_disable(drm_dev);\n"
                "\t\tdrm_dev->switch_power_state = DRM_SWITCH_POWER_OFF;\n"
                "\t\treturn -EIO;\n"
                "\t}\n\n"
            ),
            "",
        ),
        (
            "terminal runtime resume retry reports success",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            "\t\treturn -EIO;\n",
            "\t\treturn 0;\n",
        ),
        (
            "terminal runtime resume retry gate follows PCI restore",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            "\tif (radeon_rs4xx_terminal_ownership_retained(rdev)) {\n",
            "\tpci_restore_state(pdev);\n"
            "\tif (radeon_rs4xx_terminal_ownership_retained(rdev)) {\n",
        ),
        (
            "PCI enable failure bypasses runtime resume restoration",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            (
                "\tret = pci_enable_device(pdev);\n"
                "\tif (ret) {\n"
                "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, false);\n"
                "\t\treturn ret;\n"
                "\t}"
            ),
            ("\tret = pci_enable_device(pdev);\n\tif (ret)\n\t\treturn ret;"),
        ),
        (
            "PCI enable failure claims successful enablement",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, false);\n",
            "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, true);\n",
        ),
        (
            "PCI enable failure replaces the original error",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            (
                "\tif (ret) {\n"
                "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, false);\n"
                "\t\treturn ret;\n"
                "\t}"
            ),
            (
                "\tif (ret) {\n"
                "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, false);\n"
                "\t\treturn -EIO;\n"
                "\t}"
            ),
        ),
        (
            "driver resume failure bypasses runtime restoration",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            (
                "\tret = radeon_resume_kms(drm_dev, false, false);\n"
                "\tif (ret) {\n"
                "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, true);\n"
                "\t\treturn ret;\n"
                "\t}"
            ),
            (
                "\tret = radeon_resume_kms(drm_dev, false, false);\n"
                "\tif (ret)\n"
                "\t\treturn ret;"
            ),
        ),
        (
            "driver resume failure omits enabled-device rollback",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, true);\n",
            "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, false);\n",
        ),
        (
            "driver resume failure replaces the original error",
            RADEON / "radeon_drv.c",
            "radeon_pmops_runtime_resume",
            (
                "\tif (ret) {\n"
                "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, true);\n"
                "\t\treturn ret;\n"
                "\t}"
            ),
            (
                "\tif (ret) {\n"
                "\t\tradeon_runtime_pm_restore_resume_failure(drm_dev, pdev, true);\n"
                "\t\treturn -EIO;\n"
                "\t}"
            ),
        ),
        (
            "RS400 startup drops hardware reader admission",
            RADEON / "rs400.c",
            "rs400_startup",
            "\tr = radeon_rs4xx_hardware_access_begin(rdev);",
            "\tr = 0;",
        ),
        (
            "RS400 startup releases the reader before MC programming",
            RADEON / "rs400.c",
            "rs400_startup",
            "\trs400_mc_program(rdev);",
            ("\tradeon_rs4xx_hardware_access_end(rdev);\n\trs400_mc_program(rdev);"),
        ),
        (
            "RS400 host-path read escapes the hardware reader epoch",
            RADEON / "rs400.c",
            "rs400_startup",
            (
                "\tr = r100_irq_set(rdev);\n"
                "\tif (r)\n"
                "\t\tgoto out_hardware;\n"
                "\trdev->config.r300.hdp_cntl = RREG32(RADEON_HOST_PATH_CNTL);"
            ),
            (
                "\tr = r100_irq_set(rdev);\n"
                "\tif (r)\n"
                "\t\tgoto out_hardware;\n"
                "\tradeon_rs4xx_hardware_access_end(rdev);\n"
                "\trdev->config.r300.hdp_cntl = RREG32(RADEON_HOST_PATH_CNTL);"
            ),
        ),
        (
            "RS400 startup suppresses the IRQ update error",
            RADEON / "rs400.c",
            "rs400_startup",
            "\tif (r)\n\t\tgoto out_hardware;\n"
            "\trdev->config.r300.hdp_cntl = RREG32(RADEON_HOST_PATH_CNTL);",
            "\tif (r)\n\t\tr = 0;\n"
            "\trdev->config.r300.hdp_cntl = RREG32(RADEON_HOST_PATH_CNTL);",
        ),
        (
            "RS400 initialization admits a degraded startup",
            RADEON / "rs400.c",
            "rs400_init",
            "\t\tradeon_irq_kms_fini(rdev);\n"
            "\t\trdev->accel_working = false;\n"
            "\t\treturn r;",
            "\t\tradeon_irq_kms_fini(rdev);\n"
            "\t\trdev->accel_working = false;\n"
            "\t\treturn 0;",
        ),
        (
            "policy loses one terminal branch row",
            None,
            None,
            "lifecycle_terminal_edge\tterminal\tdrivers/gpu/drm/radeon/rs400.c\trs400_init\treset-failure",
            "lifecycle_terminal_edge\tinvalid\tdrivers/gpu/drm/radeon/rs400.c\trs400_init\treset-failure",
        ),
    )

    checks = 0
    failures = 0
    with tempfile.TemporaryDirectory(prefix="rs4xx-transition-contract-") as directory:
        root = Path(directory)
        copy_fixture(repository, root)
        checks += 1
        try:
            check_repository(root)
        except ContractError as exc:
            print(f"  FAIL: known-good source copy: {exc}", file=sys.stderr)
            failures += 1
        else:
            print("  ok: known-good source copy")

    for label, path, function, old, new in mutations:
        checks += 1
        with tempfile.TemporaryDirectory(
            prefix="rs4xx-transition-mutation-"
        ) as directory:
            root = Path(directory)
            copy_fixture(repository, root)
            try:
                if path is None:
                    replace_policy_once(root, old, new)
                elif function is None:
                    replace_file_once(root, path, old, new)
                else:
                    replace_in_function(root, path, function, old, new)
            except (ContractError, OSError, ValueError) as exc:
                print(f"  FAIL: mutation setup: {label}: {exc}", file=sys.stderr)
                failures += 1
                continue
            try:
                check_repository(root)
            except ContractError:
                print(f"  ok: known-bad mutation rejected: {label}")
            else:
                print(f"  FAIL: known-bad mutation accepted: {label}", file=sys.stderr)
                failures += 1
    if failures:
        print(
            f"RS4xx hardware transition calibration: FAIL ({failures}/{checks})",
            file=sys.stderr,
        )
        return 1
    print(f"RS4xx hardware transition calibration: {checks} verdicts passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.selftest:
        return selftest(root)
    try:
        rows = check_repository(root)
    except ContractError as exc:
        print(f"RS4xx hardware transition contract: {exc}", file=sys.stderr)
        return 1
    print(
        "RS4xx hardware transition contract: PASS "
        f"(source-static, {len(rows)} policy rows, no hardware verdict)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
