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

GUARD_READ = re.compile(r"READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)")
POSITIVE_GUARD = re.compile(
    r"^\s*if\s*\(\s*READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)\s*\)\s*\{?\s*$"
)
FUNCTION_END = re.compile(r"^\}")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"//[^\n]*")


class GuardError(Exception):
    """A parked-device guard is absent, misplaced, or returns the wrong value."""


def strip_comments(source: str) -> str:
    """Blank comment bodies while preserving line numbering.

    Ordering is the whole check, and a comment naming radeon_bo_create sits
    above the guard that precedes the real call. Matching that prose would
    report the guard as following the allocation it actually precedes, so
    comments are blanked rather than deleted: deleting them would shift every
    later line and break the position comparison instead.
    """

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    return LINE_COMMENT.sub(blank, BLOCK_COMMENT.sub(blank, source))


def reject_forward_goto_over_interval(
    body: list[str],
    interval_start: int,
    interval_end: int,
    label: str,
) -> None:
    """Reject a goto edge that enters after a required source interval."""
    label_positions = {
        match.group(1): index
        for index, line in enumerate(body)
        if (match := re.match(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\s*:", line))
    }
    for index, line in enumerate(body):
        for jump in re.finditer(r"\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", line):
            target = label_positions.get(jump.group(1))
            if target is None:
                raise GuardError(f"{label}: goto target {jump.group(1)} is absent")
            if index < interval_start and target >= interval_end:
                raise GuardError(f"{label}: goto {jump.group(1)} bypasses the refusal")


def function_body(source: str, name: str) -> list[str]:
    """Return the lines of one function body, brace-to-brace.

    The opening line is matched on "name(" at column zero so a call to the
    function elsewhere cannot be mistaken for its definition.
    """
    lines = source.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(rf"^[A-Za-z_].*\b{re.escape(name)}\s*\(", line):
            start = index
            break
    if start is None:
        raise GuardError(f"function {name} not found")
    for index in range(start, len(lines)):
        if FUNCTION_END.match(lines[index]):
            return lines[start : index + 1]
    raise GuardError(f"function {name} has no closing brace")


def check_guard(root: Path, guard: dict[str, str]) -> None:
    path = root / guard["path"]
    try:
        source = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise GuardError(f"{guard['id']}: missing source {path}") from exc

    body = function_body(strip_comments(source), guard["function"])

    latch_reads = [i for i, line in enumerate(body) if GUARD_READ.search(line)]
    if not latch_reads:
        raise GuardError(
            f"{guard['id']}: no READ_ONCE(rdev->gpu_parked) in {guard['function']}"
        )
    guard_at = [i for i, line in enumerate(body) if POSITIVE_GUARD.match(line)]
    if len(guard_at) != 1 or guard_at != latch_reads:
        raise GuardError(
            f"{guard['id']}: the parked latch must appear once as the exact positive "
            "condition if (READ_ONCE(rdev->gpu_parked))"
        )

    call_at = [i for i, line in enumerate(body) if guard["precedes"] in line]
    if not call_at:
        raise GuardError(
            f"{guard['id']}: {guard['precedes']} absent from {guard['function']}"
        )

    if min(guard_at) > min(call_at):
        raise GuardError(
            f"{guard['id']}: the gpu_parked test follows {guard['precedes']}, "
            "so it refuses nothing"
        )
    reject_forward_goto_over_interval(
        body,
        min(guard_at),
        min(guard_at) + 1,
        guard["id"],
    )

    # The refusal value decides whether the caller reaches a reset re-entry:
    # radeon_gem_handle_lockup forwards every value except -EDEADLK, which it
    # turns into radeon_gpu_reset. A guard returning 0 admits outright.
    window = "\n".join(body[min(guard_at) : min(guard_at) + 6])
    if guard["returns"] not in window:
        raise GuardError(
            f"{guard['id']}: the refusal does not return {guard['returns']} "
            "within the guarded block"
        )
    if "EDEADLK" in window:
        raise GuardError(
            f"{guard['id']}: the refusal returns -EDEADLK, which drives "
            "radeon_gem_handle_lockup into a reset re-entry on a parked device"
        )
    if "needs_reset" in window:
        raise GuardError(
            f"{guard['id']}: the refusal reads needs_reset, which clears "
            "during reset, rather than gpu_parked, which latches"
        )

    # The create funnel refuses regardless of placement. A guard made
    # conditional on a VRAM request readmits the GTT traffic the measured
    # RS482 cell showed the fault path never terminates.
    if guard["id"] == "gem-create":
        guard_line = body[min(guard_at)]
        if "DOMAIN_VRAM" in guard_line or "DOMAIN_VRAM" in window.splitlines()[0]:
            raise GuardError(
                f"{guard['id']}: the refusal is conditional on a VRAM request, "
                "so a GTT request is readmitted"
            )

    if guard["id"] == "prime-import":
        check_prime_import_lock(body, min(guard_at))
    elif guard["id"] == "wait-idle-flush":
        check_wait_idle_lock(body, min(guard_at))
    elif guard["id"] == "command-submission":
        check_command_submission_lock(body, min(guard_at), min(call_at))


def line_index(body: list[str], pattern: str, start: int = 0) -> int:
    for index in range(start, len(body)):
        if re.search(pattern, body[index]):
            return index
    return -1


def require_guard_unlock(
    entry: str, body: list[str], guard_index: int, result_pattern: str
) -> None:
    """Require the guarded refusal to release the read lock before return."""

    unlock_at = line_index(
        body, r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)", guard_index
    )
    result_at = line_index(body, result_pattern, guard_index)
    if unlock_at < 0 or result_at < 0 or unlock_at > result_at:
        raise GuardError(
            f"{entry}: parked refusal does not release exclusive_lock before returning"
        )


def require_lock_held_at_guard(
    entry: str, body: list[str], lock_index: int, guard_index: int
) -> None:
    """Reject an exclusive-lock release between acquisition and latch read."""

    unlock_at = line_index(
        body,
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)",
        lock_index + 1,
    )
    if unlock_at >= 0 and unlock_at < guard_index:
        raise GuardError(
            f"{entry}: exclusive_lock is released before the parked latch test"
        )


def check_prime_import_lock(body: list[str], guard_index: int) -> None:
    """Prove PRIME checks the latch before reservation and allocation locks."""

    lock_at = line_index(body, r"down_read\s*\(\s*&rdev->exclusive_lock\s*\)")
    reservation_at = line_index(body, r"dma_resv_lock\s*\(")
    allocation_at = line_index(body, r"radeon_bo_create\s*\(")
    reservation_unlock_at = line_index(body, r"dma_resv_unlock\s*\(")
    final_unlock_at = line_index(
        body,
        r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)",
        reservation_unlock_at + 1,
    )
    if not (
        0
        <= lock_at
        < guard_index
        < reservation_at
        < allocation_at
        < reservation_unlock_at
        < final_unlock_at
    ):
        raise GuardError(
            "prime-import: expected exclusive lock, parked guard, dma_resv "
            "lock, allocation, dma_resv unlock, and exclusive unlock order"
        )
    require_lock_held_at_guard("prime-import", body, lock_at, guard_index)
    require_guard_unlock(
        "prime-import",
        body,
        guard_index,
        r"return\s+ERR_PTR\s*\(\s*-EIO\s*\)\s*;",
    )


def check_wait_idle_lock(body: list[str], guard_index: int) -> None:
    """Prove WAIT leaves the bounded reservation wait outside the read lock."""

    wait_at = line_index(body, r"dma_resv_wait_timeout\s*\(")
    lock_at = line_index(body, r"down_read\s*\(\s*&rdev->exclusive_lock\s*\)")
    placement_at = line_index(
        body, r"cur_placement\s*=\s*READ_ONCE\s*\(", guard_index + 1
    )
    flush_at = line_index(body, r"mmio_hdp_flush", placement_at + 1)
    final_unlock_at = line_index(
        body, r"up_read\s*\(\s*&rdev->exclusive_lock\s*\)", flush_at + 1
    )
    if not (
        0 <= wait_at < lock_at < guard_index < placement_at < flush_at < final_unlock_at
    ):
        raise GuardError(
            "wait-idle-flush: expected reservation wait, exclusive lock, "
            "parked guard, placement, flush, and unlock order"
        )
    require_lock_held_at_guard("wait-idle-flush", body, lock_at, guard_index)
    require_guard_unlock("wait-idle-flush", body, guard_index, r"return\s+-EIO\s*;")


def check_command_submission_lock(
    body: list[str], guard_index: int, parser_index: int
) -> None:
    """Prove the CS latch test is the first locked submission refusal."""

    lock_at = [
        index
        for index, line in enumerate(body)
        if re.search(r"down_read\s*\(\s*&rdev->exclusive_lock\s*\)", line)
    ]
    if not lock_at or min(lock_at) > guard_index:
        raise GuardError(
            "command-submission: exclusive_lock read acquisition does not "
            "precede the parked latch test"
        )

    require_lock_held_at_guard("command-submission", body, min(lock_at), guard_index)

    require_guard_unlock("command-submission", body, guard_index, r"return\s+-EIO\s*;")

    acceleration_at = [
        index
        for index, line in enumerate(body)
        if re.search(r"if\s*\(\s*!\s*rdev->accel_working\s*\)", line)
    ]
    if not acceleration_at or not (guard_index < min(acceleration_at) < parser_index):
        raise GuardError(
            "command-submission: gpu_parked -EIO must precede the separate "
            "accel_working refusal and parser initialization"
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

    body = function_body(strip_comments(source), "radeon_mode_dumb_create")

    call_at = [i for i, line in enumerate(body) if "radeon_gem_object_create" in line]
    if not call_at:
        raise GuardError(
            "dumb-create: radeon_gem_object_create absent from radeon_mode_dumb_create"
        )

    check = re.compile(r"if\s*\(\s*r\s*\)")
    for index in range(min(call_at) + 1, len(body)):
        if check.search(body[index]):
            window = "\n".join(body[index : index + 3])
            if re.search(r"return\s+r\s*;", window):
                return
            translated = re.search(r"return\s+(-\w+|0)\s*;", window)
            found = translated.group(1) if translated else "no return"
            raise GuardError(
                "dumb-create: the wrapper answers the creator's failure with "
                f"{found} rather than forwarding r, so the parked -EIO is "
                "masked at the ioctl boundary"
            )
    raise GuardError(
        "dumb-create: the creator's result is never tested, so a failed "
        "create falls through to handle creation"
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
    "guard polarity inverted": (
        "if (READ_ONCE(rdev->gpu_parked))",
        "if (!READ_ONCE(rdev->gpu_parked))",
    ),
    "read lock removed": (
        "\tdown_read(&rdev->exclusive_lock);",
        "\tremoved_down_read();",
    ),
    "guard unlock removed": (
        "\t\tup_read(&rdev->exclusive_lock);\n\t\treturn ERR_PTR(-EIO);",
        "\t\treturn ERR_PTR(-EIO);",
    ),
    "exclusive lock released before guard": (
        "\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked))",
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tup_read(&rdev->exclusive_lock);\n"
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
    "guard unlock removed": (
        ("\t\tup_read(&rdev->exclusive_lock);\n\t\tdrm_gem_object_put(gobj);"),
        "\t\tdrm_gem_object_put(gobj);",
    ),
    "exclusive lock released before guard": (
        "\tdown_read(&rdev->exclusive_lock);\n\tif (READ_ONCE(rdev->gpu_parked))",
        (
            "\tdown_read(&rdev->exclusive_lock);\n"
            "\tup_read(&rdev->exclusive_lock);\n"
            "\tif (READ_ONCE(rdev->gpu_parked))"
        ),
    ),
    "parked errno changed": ("\t\treturn -EIO;", "\t\treturn -EBUSY;"),
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
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
"""

CS_FIXTURES_BAD = {
    "parked guard polarity inverted": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tif (!READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn -EIO;
\t}
\tif (!rdev->accel_working)
\t\treturn -EBUSY;
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
""",
    "acceleration state substitutes for the parked latch": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tif (!rdev->accel_working)
\t\treturn -EBUSY;
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
""",
    "parked refusal follows parser initialization": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tr = radeon_cs_parser_init(&parser, data);
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\treturn r;
}
""",
    "parked refusal returns acceleration errno": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EBUSY;
\tif (!rdev->accel_working)
\t\treturn -EBUSY;
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
""",
    "exclusive read lock acquisition removed": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn -EIO;
\t}
\tif (!rdev->accel_working)
\t\treturn -EBUSY;
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
""",
    "exclusive read lock released before parked refusal": """
int radeon_cs_ioctl(struct drm_device *dev)
{
	down_read(&rdev->exclusive_lock);
	up_read(&rdev->exclusive_lock);
	if (READ_ONCE(rdev->gpu_parked)) {
		up_read(&rdev->exclusive_lock);
		return -EIO;
	}
	if (!rdev->accel_working)
		return -EBUSY;
	r = radeon_cs_parser_init(&parser, data);
	return r;
}
""",
    "parked refusal leaks the exclusive read lock": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tif (READ_ONCE(rdev->gpu_parked))
\t\treturn -EIO;
\tif (!rdev->accel_working)
\t\treturn -EBUSY;
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
""",
    "acceleration refusal precedes parked refusal": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tif (!rdev->accel_working)
\t\treturn -EBUSY;
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn -EIO;
\t}
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
""",
    "forward goto bypasses parked refusal": """
int radeon_cs_ioctl(struct drm_device *dev)
{
\tdown_read(&rdev->exclusive_lock);
\tgoto bypass_parked_refusal;
\tif (READ_ONCE(rdev->gpu_parked)) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn -EIO;
\t}
bypass_parked_refusal:
\tif (!rdev->accel_working) {
\t\tup_read(&rdev->exclusive_lock);
\t\treturn -EBUSY;
\t}
\tr = radeon_cs_parser_init(&parser, data);
\treturn r;
}
""",
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
