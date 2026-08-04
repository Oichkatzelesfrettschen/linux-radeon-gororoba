#!/usr/bin/env python3
"""Prove the parked-device refusals still refuse, against known-bad mutations.

A parked device stays parked until reboot, and three call sites hold that
contract: radeon_gem_object_create refuses every buffer object allocation
funnelled through it, radeon_gem_prime_import_sg_table refuses the importer
that bypasses the funnel, and radeon_gem_wait_idle_ioctl refuses before
mmio_hdp_flush reaches a wedged engine.

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
]

GUARD_READ = re.compile(r"READ_ONCE\s*\(\s*rdev->gpu_parked\s*\)")
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

    guard_at = [i for i, line in enumerate(body) if GUARD_READ.search(line)]
    if not guard_at:
        raise GuardError(
            f"{guard['id']}: no READ_ONCE(rdev->gpu_parked) in {guard['function']}"
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

    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    print(f"selftest: {len(good)} good and {len(FIXTURES_BAD)} bad fixtures classified")
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

    if failures:
        print(f"parked admission guards: {failures} failure(s)", file=sys.stderr)
        return 1
    print(f"parked admission guards: {len(GUARDS)} guards proven")
    return 0


if __name__ == "__main__":
    sys.exit(main())
