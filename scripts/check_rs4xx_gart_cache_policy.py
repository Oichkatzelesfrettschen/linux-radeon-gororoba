#!/usr/bin/env python3
"""Prove the RS4xx GART cache contract against calibrated source mutations.

The target path is a coupled policy, not one register bit. Non-PCIe Radeon
devices discard userspace UC and WC requests, TTM therefore chooses cached
pages, cached pages request the Radeon per-PTE SNOOP flag, and the RS400 PTE
encoder clears UNSNOOPED for that flag. At the same time, GART enable retains
the platform-wide REQ_TYPE_SNOOP_DIS setting. The GART page table itself is a
coherent DMA allocation whose RS4xx path calls `set_memory_uc`, then calls
`set_memory_wb` before release. The driver does not check either return value,
so this checker does not assert that either page-attribute transition succeeds.

This checker proves only those source relationships. It does not claim that a
per-PTE snoop request defeats the global disable, or that CPU and GPU payloads
are coherent on RS482. Those are target-silicon questions.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

SUBTREE = Path("drivers/gpu/drm/radeon")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT = re.compile(r"//[^\n]*")
C_LINE_SPLICE = re.compile(r"\\(?:\r\n|\n|\r)")
AGP_MODE_WRITE = re.compile(
    r"WREG32_MC\s*\(\s*RS480_AGP_MODE_CNTL\s*,",
)


class PolicyError(Exception):
    """A load-bearing RS4xx GART cache relationship is absent."""


def strip_comments(source: str) -> str:
    """Apply C phase-2 splicing, then blank comments for lexical checks."""

    def blank(match: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", match.group(0))

    logical_source = C_LINE_SPLICE.sub("", source)
    return LINE_COMMENT.sub(blank, BLOCK_COMMENT.sub(blank, logical_source))


def function_body(source: str, name: str) -> str:
    """Return one kernel-style function from its definition through column-zero }."""
    lines = source.splitlines()
    start = None
    for index, line in enumerate(lines):
        if re.match(rf"^[A-Za-z_].*\b{re.escape(name)}\s*\(", line):
            start = index
            break
    if start is None:
        raise PolicyError(f"function {name} not found")
    for index in range(start, len(lines)):
        if lines[index] == "}":
            return "\n".join(lines[start : index + 1])
    raise PolicyError(f"function {name} has no closing brace")


def read_function(root: Path, filename: str, name: str) -> str:
    path = root / SUBTREE / filename
    try:
        source = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PolicyError(f"missing source {path}") from exc
    return function_body(strip_comments(source), name)


def require(label: str, body: str, pattern: str) -> None:
    if re.search(pattern, body, re.DOTALL) is None:
        raise PolicyError(label)


def require_order(label: str, body: str, needles: tuple[str, ...]) -> None:
    cursor = 0
    for needle in needles:
        found = body.find(needle, cursor)
        if found < 0:
            raise PolicyError(f"{label}: missing or out of order: {needle}")
        cursor = found + len(needle)


def check_global_snoop_disable(root: Path) -> None:
    """Require one final RS480 AGP-mode write with global snooping disabled."""

    gart_enable = read_function(root, "rs400.c", "rs400_gart_enable")
    write_count = len(AGP_MODE_WRITE.findall(gart_enable))
    if write_count != 1:
        raise PolicyError(
            "RS4xx GART enable must contain exactly one RS480_AGP_MODE_CNTL "
            f"write, found {write_count}"
        )
    require(
        "RS4xx GART enable no longer retains the global snoop-disable setting",
        gart_enable,
        r"WREG32_MC\s*\(\s*RS480_AGP_MODE_CNTL\s*,\s*"
        r"\(\s*1\s*<<\s*RS480_REQ_TYPE_SNOOP_SHIFT\s*\)\s*\|\s*"
        r"RS480_REQ_TYPE_SNOOP_DIS\s*\)\s*;",
    )


def check_tree(root: Path) -> None:
    bo_create = read_function(root, "radeon_object.c", "radeon_bo_create")
    require(
        "non-PCIe BOs do not discard both GTT WC and UC flags",
        bo_create,
        r"if\s*\(\s*!\s*\(\s*rdev->flags\s*&\s*RADEON_IS_PCIE\s*\)\s*\)"
        r"\s*bo->flags\s*&=\s*~\s*\(\s*RADEON_GEM_GTT_WC\s*\|"
        r"\s*RADEON_GEM_GTT_UC\s*\)\s*;",
    )

    tt_create = read_function(root, "radeon_ttm.c", "radeon_ttm_tt_create")
    require(
        "TTM cache selection no longer maps UC, WC, and default to exact modes",
        tt_create,
        r"if\s*\(\s*rbo->flags\s*&\s*RADEON_GEM_GTT_UC\s*\)"
        r"\s*caching\s*=\s*ttm_uncached\s*;\s*else\s+if\s*\("
        r"\s*rbo->flags\s*&\s*RADEON_GEM_GTT_WC\s*\)"
        r"\s*caching\s*=\s*ttm_write_combined\s*;\s*else"
        r"\s*caching\s*=\s*ttm_cached\s*;",
    )

    backend_bind = read_function(root, "radeon_ttm.c", "radeon_ttm_backend_bind")
    require(
        "cached TTM pages no longer conditionally request per-PTE snoop",
        backend_bind,
        r"if\s*\(\s*ttm->caching\s*==\s*ttm_cached\s*\)\s*"
        r"flags\s*\|=\s*RADEON_GART_PAGE_SNOOP\s*;",
    )
    require_order(
        "cached TTM pages must request per-PTE snoop before GART bind",
        backend_bind,
        (
            "if (ttm->caching == ttm_cached)",
            "flags |= RADEON_GART_PAGE_SNOOP;",
            "radeon_gart_bind",
        ),
    )

    pte_encode = read_function(root, "rs400.c", "rs400_gart_get_page_entry")
    require(
        "RS400 PTE encoding no longer leaves UNSNOOPED clear for SNOOP requests",
        pte_encode,
        r"if\s*\(\s*!\s*\(\s*flags\s*&\s*RADEON_GART_PAGE_SNOOP\s*\)\s*\)"
        r"\s*entry\s*\|=\s*RS400_PTE_UNSNOOPED\s*;",
    )

    check_global_snoop_disable(root)

    table_alloc = read_function(root, "radeon_gart.c", "radeon_gart_table_ram_alloc")
    require(
        "RS400 and RS480 GART table paths no longer call set_memory_uc together",
        table_alloc,
        r"if\s*\(\s*rdev->family\s*==\s*CHIP_RS400\s*\|\|\s*"
        r"rdev->family\s*==\s*CHIP_RS480.*?\)\s*\{\s*"
        r"set_memory_uc\s*\(",
    )
    require_order(
        "GART table allocation must precede the RS4xx set_memory_uc call",
        table_alloc,
        ("dma_alloc_coherent", "CHIP_RS400", "CHIP_RS480", "set_memory_uc"),
    )

    table_free = read_function(root, "radeon_gart.c", "radeon_gart_table_ram_free")
    require(
        "RS400 and RS480 GART table paths no longer call set_memory_wb together",
        table_free,
        r"if\s*\(\s*rdev->family\s*==\s*CHIP_RS400\s*\|\|\s*"
        r"rdev->family\s*==\s*CHIP_RS480.*?\)\s*\{\s*"
        r"set_memory_wb\s*\(",
    )
    require_order(
        "The RS4xx set_memory_wb call must precede coherent DMA release",
        table_free,
        ("CHIP_RS400", "CHIP_RS480", "set_memory_wb", "dma_free_coherent"),
    )


FIXTURES = {
    "radeon_object.c": """
int radeon_bo_create(struct radeon_device *rdev)
{
\tbo->flags = flags;
\tif (!(rdev->flags & RADEON_IS_PCIE))
\t\tbo->flags &= ~(RADEON_GEM_GTT_WC | RADEON_GEM_GTT_UC);
\treturn 0;
}
""",
    "radeon_ttm.c": """
static int radeon_ttm_backend_bind(struct ttm_device *bdev)
{
\tif (ttm->caching == ttm_cached)
\t\tflags |= RADEON_GART_PAGE_SNOOP;
\tr = radeon_gart_bind(rdev, flags);
\treturn r;
}
static struct ttm_tt *radeon_ttm_tt_create(struct ttm_buffer_object *bo)
{
\tif (rbo->flags & RADEON_GEM_GTT_UC)
\t\tcaching = ttm_uncached;
\telse if (rbo->flags & RADEON_GEM_GTT_WC)
\t\tcaching = ttm_write_combined;
\telse
\t\tcaching = ttm_cached;
\treturn &gtt->ttm;
}
""",
    "rs400.c": """
int rs400_gart_enable(struct radeon_device *rdev)
{
\tWREG32_MC(RS480_AGP_MODE_CNTL,
\t\t  (1 << RS480_REQ_TYPE_SNOOP_SHIFT) | RS480_REQ_TYPE_SNOOP_DIS);
\treturn 0;
}
uint64_t rs400_gart_get_page_entry(uint64_t addr, uint32_t flags)
{
\tif (!(flags & RADEON_GART_PAGE_SNOOP))
\t\tentry |= RS400_PTE_UNSNOOPED;
\treturn entry;
}
""",
    "radeon_gart.c": """
int radeon_gart_table_ram_alloc(struct radeon_device *rdev)
{
\tptr = dma_alloc_coherent(dev, size, &addr, GFP_KERNEL);
\tif (rdev->family == CHIP_RS400 || rdev->family == CHIP_RS480) {
\t\tset_memory_uc((unsigned long)ptr, pages);
\t}
\treturn 0;
}
void radeon_gart_table_ram_free(struct radeon_device *rdev)
{
\tif (rdev->family == CHIP_RS400 || rdev->family == CHIP_RS480) {
\t\tset_memory_wb((unsigned long)rdev->gart.ptr, pages);
\t}
\tdma_free_coherent(dev, size, ptr, addr);
}
""",
}

MUTATIONS = {
    "phase-2 continued comment hides the non-PCIe guard": (
        "radeon_object.c",
        "\tif (!(rdev->flags & RADEON_IS_PCIE))",
        (
            "\t/\\\n/ hidden guard \\\n"
            "\tif (!(rdev->flags & RADEON_IS_PCIE))"
        ),
    ),
    "non-PCIe flag mask inverted": (
        "radeon_object.c",
        "if (!(rdev->flags & RADEON_IS_PCIE))",
        "if (rdev->flags & RADEON_IS_PCIE)",
    ),
    "default TTM cache changed to UC": (
        "radeon_ttm.c",
        "else\n\t\tcaching = ttm_cached;",
        "else\n\t\tcaching = ttm_uncached;",
    ),
    "cached bind drops per-PTE snoop": (
        "radeon_ttm.c",
        "flags |= RADEON_GART_PAGE_SNOOP;",
        "flags |= 0;",
    ),
    "cached bind makes per-PTE snoop unconditional": (
        "radeon_ttm.c",
        "if (ttm->caching == ttm_cached)\n\t\tflags |= RADEON_GART_PAGE_SNOOP;",
        ("if (ttm->caching == ttm_cached)\n\t\t;\n\tflags |= RADEON_GART_PAGE_SNOOP;"),
    ),
    "cached bind requests snoop after GART bind": (
        "radeon_ttm.c",
        (
            "if (ttm->caching == ttm_cached)\n"
            "\t\tflags |= RADEON_GART_PAGE_SNOOP;\n"
            "\tr = radeon_gart_bind"
        ),
        "r = radeon_gart_bind",
    ),
    "snoop request marks PTE unsnooped": (
        "rs400.c",
        "if (!(flags & RADEON_GART_PAGE_SNOOP))",
        "if (flags & RADEON_GART_PAGE_SNOOP)",
    ),
    "global snoop disable removed": (
        "rs400.c",
        " | RS480_REQ_TYPE_SNOOP_DIS",
        "",
    ),
    "later write re-enables global snooping": (
        "rs400.c",
        "\treturn 0;\n}\nuint64_t rs400_gart_get_page_entry",
        (
            "\tWREG32_MC(RS480_AGP_MODE_CNTL,\n"
            "\t\t  (1 << RS480_REQ_TYPE_SNOOP_SHIFT));\n"
            "\treturn 0;\n}\nuint64_t rs400_gart_get_page_entry"
        ),
    ),
    "page table loses coherent allocation": (
        "radeon_gart.c",
        "dma_alloc_coherent",
        "kmalloc",
    ),
    "page table CPU alias stays WB": (
        "radeon_gart.c",
        "set_memory_uc",
        "set_memory_wb",
    ),
    "RS480 page table alias leaves the UC cohort": (
        "radeon_gart.c",
        (
            "rdev->family == CHIP_RS400 || rdev->family == CHIP_RS480) {\n"
            "\t\tset_memory_uc"
        ),
        (
            "rdev->family == CHIP_RS400 || rdev->family == CHIP_RS690) {\n"
            "\t\tset_memory_uc"
        ),
    ),
    "page table CPU alias is not restored": (
        "radeon_gart.c",
        "set_memory_wb((unsigned long)rdev->gart.ptr",
        "set_memory_uc((unsigned long)rdev->gart.ptr",
    ),
}


def write_fixtures(root: Path) -> None:
    source_dir = root / SUBTREE
    source_dir.mkdir(parents=True, exist_ok=True)
    for filename, source in FIXTURES.items():
        (source_dir / filename).write_text(source, encoding="utf-8")


def selftest(root: Path) -> int:
    write_fixtures(root)
    try:
        check_tree(root)
    except PolicyError as exc:
        print(f"selftest known-good REJECTED: {exc}", file=sys.stderr)
        return 1
    print("selftest known-good accepted: coupled RS4xx cache policy")

    failures = 0
    for label, (filename, old, new) in MUTATIONS.items():
        write_fixtures(root)
        path = root / SUBTREE / filename
        source = path.read_text(encoding="utf-8")
        if source.count(old) != 1:
            print(f"selftest fixture error for {label}", file=sys.stderr)
            failures += 1
            continue
        path.write_text(source.replace(old, new, 1), encoding="utf-8")
        try:
            check_tree(root)
        except PolicyError:
            print(f"selftest known-bad rejected: {label}")
        else:
            print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    print(f"selftest: 1 good and {len(MUTATIONS)} bad fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="classify built-in known-good and known-bad fixtures",
    )
    args = parser.parse_args()

    if args.selftest:
        with tempfile.TemporaryDirectory() as directory:
            return selftest(Path(directory))

    try:
        check_tree(args.root)
    except PolicyError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print("RS4xx GART cache policy: 7 coupled source relationships proven")
    return 0


if __name__ == "__main__":
    sys.exit(main())
