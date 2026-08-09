#!/usr/bin/env python3
"""Prove the finite Radeon GART and BO lifecycle source contract.

The policy table separates source structure from runtime and silicon status.
This checker proves the finite row set, its dependency graph, the RS4xx cache
subcontract, and the source relations that make GART and userptr ownership
transactional. It does not promote an OPEN target row.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import shutil
import sys
import tempfile
from pathlib import Path

import check_rs4xx_gart_cache_policy as cache_policy

POLICY = Path("policy/rs4xx-gart-memory-path.tsv")
SUBTREE = Path("drivers/gpu/drm/radeon")
EXPECTED_POLICY_SHA256 = (
    "feb272afd22b5cddfaa4b5d25cfe067e7a8ca68d2918789e7fb08e0faac51a96"
)
HEADER = (
    "row_id",
    "owner",
    "source_file",
    "source_symbol",
    "device_scope",
    "depends_on",
    "source_status",
    "source_relation",
    "lock_or_order",
    "failure_contract",
    "runtime_status",
    "silicon_status",
    "external_repository",
    "external_commit",
    "external_artifact",
    "external_row_id",
    "completion_gate",
    "mesa_effect",
    "nonclaim",
)

EXPECTED_ROWS = {
    "GART_SOURCE_BUILD_REACHABILITY": ("proven", "NONE"),
    "RS400_ASIC_GART_CALLBACK_SELECTION": (
        "proven",
        "GART_SOURCE_BUILD_REACHABILITY",
    ),
    "GTT_APERTURE_SIZE_DERIVATION": (
        "proven",
        "RS400_ASIC_GART_CALLBACK_SELECTION",
    ),
    "GART_TABLE_DMA_COHERENT_ALLOCATION_API": (
        "proven",
        "GTT_APERTURE_SIZE_DERIVATION",
    ),
    "RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT": (
        "proven",
        "GART_TABLE_DMA_COHERENT_ALLOCATION_API",
    ),
    "NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION": (
        "proven",
        "GART_SOURCE_BUILD_REACHABILITY",
    ),
    "TTM_DEFAULT_CACHED_SELECTION": (
        "proven",
        "NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION",
    ),
    "USERPTR_TT_EXTERNAL_POPULATION": (
        "proven",
        "TTM_DEFAULT_CACHED_SELECTION",
    ),
    "USERPTR_PIN_DMA_MAP_TRANSACTION": (
        "repaired",
        "USERPTR_TT_EXTERNAL_POPULATION",
    ),
    "GART_BIND_RANGE_ADMISSION": (
        "repaired",
        "GTT_APERTURE_SIZE_DERIVATION",
    ),
    "CACHED_TTM_SNOOP_FLAG_PROPAGATION": (
        "proven",
        "TTM_DEFAULT_CACHED_SELECTION;USERPTR_PIN_DMA_MAP_TRANSACTION",
    ),
    "RS400_PTE_PERMISSION_AND_SNOOP_ENCODING": (
        "proven",
        "CACHED_TTM_SNOOP_FLAG_PROPAGATION;RS400_ASIC_GART_CALLBACK_SELECTION",
    ),
    "RS480_GLOBAL_REQUEST_SNOOP_DISABLE": (
        "proven",
        "RS400_ASIC_GART_CALLBACK_SELECTION",
    ),
    "GART_BIND_PTE_MB_TLB_PUBLICATION": (
        "proven",
        "GART_BIND_RANGE_ADMISSION;RS400_PTE_PERMISSION_AND_SNOOP_ENCODING",
    ),
    "GART_UNBIND_RANGE_ADMISSION": (
        "repaired",
        "GTT_APERTURE_SIZE_DERIVATION",
    ),
    "GART_UNBIND_SPARSE_CURSOR": (
        "repaired",
        "GART_UNBIND_RANGE_ADMISSION",
    ),
    "GART_UNBIND_PTE_MB_TLB_PUBLICATION": (
        "proven",
        "GART_UNBIND_SPARSE_CURSOR",
    ),
    "KERNEL_BO_MAP_RESERVATION_WAIT": (
        "proven",
        "GART_SOURCE_BUILD_REACHABILITY",
    ),
    "USER_MMAP_FAULT_RESERVATION": (
        "proven",
        "GART_SOURCE_BUILD_REACHABILITY",
    ),
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": (
        "proven",
        "GART_TABLE_DMA_COHERENT_ALLOCATION_API",
    ),
    "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT": (
        "proven",
        "RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT",
    ),
    "GART_COMMON_TEARDOWN": (
        "proven",
        "GART_UNBIND_PTE_MB_TLB_PUBLICATION;RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT",
    ),
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": (
        "open",
        "CACHED_TTM_SNOOP_FLAG_PROPAGATION;RS400_PTE_PERMISSION_AND_SNOOP_ENCODING;RS480_GLOBAL_REQUEST_SNOOP_DISABLE",
    ),
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": (
        "open",
        "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS;GART_BIND_PTE_MB_TLB_PUBLICATION",
    ),
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": (
        "open",
        "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS;GART_UNBIND_PTE_MB_TLB_PUBLICATION",
    ),
    "RS400_TLB_FLUSH_COMPLETION": (
        "open",
        "GART_BIND_PTE_MB_TLB_PUBLICATION;GART_UNBIND_PTE_MB_TLB_PUBLICATION",
    ),
    "GART_SUSPEND_READY_STATE": (
        "open",
        "RS400_ASIC_GART_CALLBACK_SELECTION",
    ),
    "GART_BACKEND_NOT_READY_UNBIND_STATE": (
        "open",
        "GART_COMMON_TEARDOWN",
    ),
    "GART_TTM_TEARDOWN_OWNERSHIP": (
        "open",
        "GART_COMMON_TEARDOWN;GART_BACKEND_NOT_READY_UNBIND_STATE",
    ),
}

EXPECTED_EXTERNAL = {
    "GTT_APERTURE_SIZE_DERIVATION": (
        "vostro1000-re",
        "0e5141a454c9453382059eea5d0062e79451de13",
        "uma-gart-cacheability-graph",
    ),
    "GART_TABLE_DMA_COHERENT_ALLOCATION_API": (
        "vostro1000-re",
        "0e5141a454c9453382059eea5d0062e79451de13",
        "gart-page-table-readonly-provenance",
    ),
    "NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "GTT_WC_NON_PCIE_UNREACHABLE",
    ),
    "CACHED_TTM_SNOOP_FLAG_PROPAGATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "RS400_PTE_PERMISSION_AND_SNOOP_ENCODING": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "RS480_GLOBAL_REQUEST_SNOOP_DISABLE": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "GLOBAL_GART_SNOOP_INVALID",
    ),
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": (
        "vostro1000-re",
        "0e5141a454c9453382059eea5d0062e79451de13",
        "gart-page-table-readonly-provenance",
    ),
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "CPU_GTT_GPU_PUBLICATION",
    ),
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "GPU_GTT_CPU_INVALIDATION",
    ),
}

SOURCE_FILES = (
    "drivers/gpu/drm/radeon/Makefile",
    "drivers/gpu/drm/radeon/radeon_asic.c",
    "drivers/gpu/drm/radeon/radeon_gart.c",
    "drivers/gpu/drm/radeon/radeon_gem.c",
    "drivers/gpu/drm/radeon/radeon_object.c",
    "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
    "drivers/gpu/drm/radeon/radeon_ttm.c",
    "drivers/gpu/drm/radeon/rs400.c",
)


class LifecycleError(Exception):
    """The finite GART lifecycle contract is incomplete or contradicted."""


def require(label: str, body: str, pattern: str) -> None:
    if re.search(pattern, body, re.DOTALL) is None:
        raise LifecycleError(label)


def require_order(label: str, body: str, needles: tuple[str, ...]) -> None:
    cursor = 0
    for needle in needles:
        found = body.find(needle, cursor)
        if found < 0:
            raise LifecycleError(f"{label}: missing or out of order: {needle}")
        cursor = found + len(needle)


def source(root: Path, filename: str) -> str:
    path = root / SUBTREE / filename
    try:
        return cache_policy.strip_comments(path.read_text(encoding="ascii"))
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        raise LifecycleError(f"cannot read ASCII source {path}") from exc


def function(root: Path, filename: str, name: str) -> str:
    try:
        return cache_policy.read_function(root, filename, name)
    except cache_policy.PolicyError as exc:
        raise LifecycleError(str(exc)) from exc


def initializer_body(source_text: str, name: str) -> str:
    match = re.search(rf"\b{re.escape(name)}\s*=\s*\{{", source_text)
    if match is None:
        raise LifecycleError(f"initializer {name} not found")
    start = source_text.find("{", match.start())
    depth = 0
    for index in range(start, len(source_text)):
        if source_text[index] == "{":
            depth += 1
        elif source_text[index] == "}":
            depth -= 1
            if depth == 0:
                return source_text[start : index + 1]
    raise LifecycleError(f"initializer {name} has no closing brace")


def read_policy(root: Path) -> dict[str, dict[str, str]]:
    path = root / POLICY
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise LifecycleError(f"missing policy table {path}") from exc
    if not raw.isascii() or b"\r" in raw:
        raise LifecycleError("policy table must be LF terminated ASCII")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_POLICY_SHA256:
        raise LifecycleError(f"policy bytes differ from exact contract: {digest}")
    text = raw.decode("ascii")
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    if tuple(reader.fieldnames or ()) != HEADER:
        raise LifecycleError("policy header differs from the 19 field schema")
    rows: dict[str, dict[str, str]] = {}
    for row in reader:
        row_id = row["row_id"]
        if not row_id or row_id in rows:
            raise LifecycleError(f"duplicate or empty row_id {row_id!r}")
        if any(not value for value in row.values()):
            raise LifecycleError(f"{row_id}: every field must be nonempty")
        rows[row_id] = row
    if set(rows) != set(EXPECTED_ROWS):
        missing = sorted(set(EXPECTED_ROWS) - set(rows))
        extra = sorted(set(rows) - set(EXPECTED_ROWS))
        raise LifecycleError(
            f"policy denominator differs: missing={missing} extra={extra}"
        )
    return rows


def check_dependencies(rows: dict[str, dict[str, str]]) -> None:
    graph: dict[str, list[str]] = {}
    for row_id, row in rows.items():
        expected_status, expected_dependencies = EXPECTED_ROWS[row_id]
        if row["source_status"] != expected_status:
            raise LifecycleError(
                f"{row_id}: source_status {row['source_status']} != {expected_status}"
            )
        if row["depends_on"] != expected_dependencies:
            raise LifecycleError(f"{row_id}: dependency edge differs")
        if row["source_status"] not in {"proven", "repaired", "open"}:
            raise LifecycleError(f"{row_id}: invalid source_status")
        if row["source_status"] == "open" and row["silicon_status"] == "proven":
            raise LifecycleError(f"{row_id}: an OPEN source row claims proven silicon")
        dependencies = (
            [] if row["depends_on"] == "NONE" else row["depends_on"].split(";")
        )
        unknown = sorted(set(dependencies) - set(rows))
        if unknown:
            raise LifecycleError(f"{row_id}: unknown dependencies {unknown}")
        graph[row_id] = dependencies

    active: set[str] = set()
    done: set[str] = set()

    def visit(row_id: str) -> None:
        if row_id in active:
            raise LifecycleError(f"dependency cycle reaches {row_id}")
        if row_id in done:
            return
        active.add(row_id)
        for dependency in graph[row_id]:
            visit(dependency)
        active.remove(row_id)
        done.add(row_id)

    for row_id in rows:
        visit(row_id)


def check_external(rows: dict[str, dict[str, str]]) -> None:
    for row_id, row in rows.items():
        expected = EXPECTED_EXTERNAL.get(row_id)
        fields = (
            row["external_repository"],
            row["external_commit"],
            row["external_row_id"],
        )
        if expected is None:
            if fields != ("NONE", "NONE", "NONE"):
                raise LifecycleError(f"{row_id}: unexpected external authority")
            if row["external_artifact"] != "NONE":
                raise LifecycleError(f"{row_id}: unexpected external artifact")
            continue
        if fields != expected:
            raise LifecycleError(f"{row_id}: external authority identity differs")
        if not re.fullmatch(r"[0-9a-f]{40}", row["external_commit"]):
            raise LifecycleError(f"{row_id}: external commit is not a full object ID")
        if row["external_artifact"] == "NONE":
            raise LifecycleError(f"{row_id}: external artifact is absent")


def check_build_and_callbacks(root: Path) -> None:
    makefile = (root / SUBTREE / "Makefile").read_text(encoding="ascii")
    for owner in (
        "radeon_asic.o",
        "radeon_fence.o",
        "radeon_ttm.o",
        "radeon_object.o",
        "radeon_gart.o",
        "radeon_gem.o",
        "radeon_cs.o",
        "radeon_ib.o",
        "radeon_sync.o",
        "rs400.o",
    ):
        if makefile.count(owner) != 1:
            raise LifecycleError(f"Kbuild owner count for {owner} is not one")

    asic = source(root, "radeon_asic.c")
    r300_ring = initializer_body(asic, "r300_gfx_ring")
    require(
        "r300 graphics ring callback set differs",
        r300_ring,
        r"\.ib_execute\s*=\s*&r100_ring_ib_execute"
        r".*?\.emit_fence\s*=\s*&r300_fence_ring_emit"
        r".*?\.cs_parse\s*=\s*&r300_cs_parse",
    )
    rs400 = initializer_body(asic, "rs400_asic")
    require(
        "RS400 ASIC GART callback set differs",
        rs400,
        r"\.gart\s*=\s*\{.*?\.tlb_flush\s*=\s*&rs400_gart_tlb_flush"
        r".*?\.get_page_entry\s*=\s*&rs400_gart_get_page_entry"
        r".*?\.set_page\s*=\s*&rs400_gart_set_page.*?\.ring\s*=\s*\{"
        r".*?\[RADEON_RING_TYPE_GFX_INDEX\]\s*=\s*&r300_gfx_ring",
    )
    require(
        "RS400 and RS480 no longer select rs400_asic together",
        function(root, "radeon_asic.c", "radeon_asic_init"),
        r"case\s+CHIP_RS400\s*:\s*case\s+CHIP_RS480\s*:\s*rdev->asic\s*=\s*&rs400_asic",
    )


def check_gart_source(root: Path) -> None:
    init = function(root, "radeon_gart.c", "radeon_gart_init")
    require_order(
        "GART size derivation and shadow allocation",
        init,
        (
            "num_cpu_pages = rdev->mc.gtt_size / PAGE_SIZE",
            "num_gpu_pages = rdev->mc.gtt_size / RADEON_GPU_PAGE_SIZE",
            "rdev->gart.pages = vcalloc",
            "rdev->gart.pages_entry = vmalloc_array",
        ),
    )

    range_valid = function(root, "radeon_gart.c", "radeon_gart_range_valid")
    require(
        "GART range validator accepts zero or negative page counts",
        range_valid,
        r"pages\s*<=\s*0",
    )
    require(
        "GART range validator lacks page alignment admission",
        range_valid,
        r"offset\s*&\s*~PAGE_MASK",
    )
    require_order(
        "GART range validator lacks overflow safe containment",
        range_valid,
        (
            "(unsigned int)pages > rdev->gart.num_cpu_pages",
            "start = offset >> PAGE_SHIFT",
            "start <= rdev->gart.num_cpu_pages - pages",
        ),
    )

    bind = function(root, "radeon_gart.c", "radeon_gart_bind")
    require_order(
        "GART bind admission must precede array access",
        bind,
        (
            "!dma_addr || !radeon_gart_range_valid",
            "rdev->gart.pages[p] =",
            "rdev->gart.pages_entry[t] = page_entry",
            "mb();",
            "radeon_gart_tlb_flush(rdev);",
        ),
    )

    unbind = function(root, "radeon_gart.c", "radeon_gart_unbind")
    require_order(
        "GART unbind admission and sparse cursor",
        unbind,
        (
            "!radeon_gart_range_valid",
            "t = p * (PAGE_SIZE / RADEON_GPU_PAGE_SIZE)",
            "if (rdev->gart.pages[p])",
            "rdev->gart.pages_entry[t] = rdev->dummy_page.entry",
            "mb();",
            "radeon_gart_tlb_flush(rdev);",
        ),
    )


def check_userptr_transaction(root: Path) -> None:
    pin = function(root, "radeon_ttm.c", "radeon_ttm_tt_pin_userptr")
    require_order(
        "userptr pin ownership sequence",
        pin,
        (
            "r = get_user_pages",
            "if (r < 0)",
            "if (!r)",
            "r = sg_alloc_table_from_pages",
            "if (r)",
            "goto release_pages;",
            "r = dma_map_sgtable",
            "goto release_sg;",
            "drm_prime_sg_to_dma_addr_array",
            "release_sg:",
            "sg_free_table(ttm->sg);",
            "memset(ttm->sg, 0, sizeof(*ttm->sg));",
            "release_pages:",
            "release_pages(ttm->pages, pinned);",
        ),
    )

    bind = function(root, "radeon_ttm.c", "radeon_ttm_backend_bind")
    require_order(
        "userptr bind must propagate and roll back ownership",
        bind,
        (
            "r = radeon_ttm_tt_pin_userptr",
            "if (r)",
            "return r;",
            "flags &= ~RADEON_GART_PAGE_WRITE;",
            "r = radeon_gart_bind",
            "if (r)",
            "radeon_ttm_tt_unpin_userptr",
            "return r;",
            "gtt->bound = true;",
        ),
    )

    unbind = function(root, "radeon_ttm.c", "radeon_ttm_backend_unbind")
    require_order(
        "userptr unbind must remove PTEs before releasing pages",
        unbind,
        (
            "if (!gtt->bound)",
            "radeon_gart_unbind",
            "gtt->bound = false;",
            "radeon_ttm_tt_unpin_userptr",
        ),
    )

    unpin = function(root, "radeon_ttm.c", "radeon_ttm_tt_unpin_userptr")
    require_order(
        "userptr unpin must retire DMA, pages, and SG ownership",
        unpin,
        (
            "dma_unmap_sgtable",
            "for_each_sgtable_page",
            "put_page",
            "sg_free_table(ttm->sg);",
            "memset(ttm->sg, 0, sizeof(*ttm->sg));",
        ),
    )


def check_cpu_access_and_snapshot(root: Path) -> None:
    kmap = function(root, "radeon_object.c", "radeon_bo_kmap")
    require_order(
        "kernel BO map must wait before using a map",
        kmap,
        (
            "dma_resv_wait_timeout",
            "if (r < 0)",
            "if (bo->kptr)",
            "ttm_bo_kmap",
        ),
    )
    fault = function(root, "radeon_gem.c", "radeon_gem_fault")
    if fault.find("bo->resource") < fault.find("ttm_bo_vm_reserve"):
        raise LifecycleError("userspace fault inspects placement before reserve")
    require_order(
        "userspace fault lock and reservation order",
        fault,
        (
            "down_read(&rdev->pm.mclk_lock)",
            "ttm_bo_vm_reserve",
            "bo->resource->mem_type",
            "ttm_bo_vm_fault_reserved",
            "dma_resv_unlock",
            "up_read(&rdev->pm.mclk_lock)",
        ),
    )
    reader = function(root, "radeon_rs4xx_dev.c", "rs400_debugfs_gart_page_table_show")
    require_order(
        "GART reader lifetime lock",
        reader,
        (
            "mutex_lock(&rs400_gart_page_table_lock)",
            "if (!rdev->gart.ready || !rdev->gart.ptr)",
            "table = rdev->gart.ptr",
            "READ_ONCE(table[index])",
            "mutex_unlock(&rs400_gart_page_table_lock)",
        ),
    )
    fini = function(root, "rs400.c", "rs400_gart_fini")
    require_order(
        "GART finalization shares the reader lifetime lock",
        fini,
        (
            "radeon_rs4xx_dev_gart_lock",
            "radeon_gart_fini",
            "radeon_gart_table_ram_free",
            "radeon_rs4xx_dev_gart_unlock",
        ),
    )


def check_open_source_boundaries(root: Path) -> None:
    tlb = function(root, "rs400.c", "rs400_gart_tlb_flush")
    require_order(
        "RS400 TLB issue and bounded poll structure",
        tlb,
        (
            "timeout = rdev->usec_timeout",
            "RS480_GART_CACHE_INVALIDATE",
            "timeout--;",
            "while (timeout > 0)",
        ),
    )
    disable = function(root, "rs400.c", "rs400_gart_disable")
    if "gart.ready" in disable:
        raise LifecycleError("suspend ready state row is no longer OPEN as recorded")
    suspend = function(root, "rs400.c", "rs400_suspend")
    if "rs400_gart_disable" not in suspend:
        raise LifecycleError("RS400 suspend no longer disables GART hardware")
    backend_unbind = function(root, "radeon_ttm.c", "radeon_ttm_backend_unbind")
    require_order(
        "backend not ready disposition changed without policy update",
        backend_unbind,
        ("radeon_gart_unbind", "gtt->bound = false;"),
    )
    ttm_fini = function(root, "radeon_ttm.c", "radeon_ttm_fini")
    if "radeon_gart_fini" not in ttm_fini:
        raise LifecycleError("TTM no longer participates in common GART teardown")


def sparse_unbind_model(present: tuple[bool, ...], entries_per_page: int) -> list[int]:
    cleared: list[int] = []
    for page_index, is_present in enumerate(present):
        cursor = page_index * entries_per_page
        if is_present:
            cleared.extend(range(cursor, cursor + entries_per_page))
    return cleared


def check_sparse_model() -> None:
    actual = sparse_unbind_model((False, True, False, True), 4)
    if actual != [4, 5, 6, 7, 12, 13, 14, 15]:
        raise LifecycleError(f"sparse unbind model differs: {actual}")


def check_tree(root: Path) -> None:
    rows = read_policy(root)
    check_dependencies(rows)
    check_external(rows)
    try:
        cache_policy.check_tree(root)
    except cache_policy.PolicyError as exc:
        raise LifecycleError(str(exc)) from exc
    check_build_and_callbacks(root)
    check_gart_source(root)
    check_userptr_transaction(root)
    check_cpu_access_and_snapshot(root)
    check_open_source_boundaries(root)
    check_sparse_model()


SOURCE_MUTATIONS = {
    "Kbuild drops synchronization owner": (
        "drivers/gpu/drm/radeon/Makefile",
        "\tradeon_sync.o radeon_audio.o",
        "\tradeon_audio.o",
    ),
    "RS400 drops TLB callback": (
        "drivers/gpu/drm/radeon/radeon_asic.c",
        (
            "\t.mc_wait_for_idle = &rs400_mc_wait_for_idle,\n"
            "\t.get_allowed_info_register = "
            "radeon_invalid_get_allowed_info_register,\n"
            "\t.gart = {\n\t\t.tlb_flush = &rs400_gart_tlb_flush,"
        ),
        (
            "\t.mc_wait_for_idle = &rs400_mc_wait_for_idle,\n"
            "\t.get_allowed_info_register = "
            "radeon_invalid_get_allowed_info_register,\n"
            "\t.gart = {\n\t\t.tlb_flush = NULL,"
        ),
    ),
    "range accepts zero pages": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "pages <= 0 || offset & ~PAGE_MASK",
        "pages < 0 || offset & ~PAGE_MASK",
    ),
    "bind skips DMA array admission": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "!dma_addr || !radeon_gart_range_valid",
        "!radeon_gart_range_valid",
    ),
    "sparse unbind retains stale cursor": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\t\tt = p * (PAGE_SIZE / RADEON_GPU_PAGE_SIZE);\n",
        "",
    ),
    "bind flush precedes memory barrier": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\t\tmb();\n\t\tradeon_gart_tlb_flush(rdev);\n\t}\n\treturn 0;",
        "\t\tradeon_gart_tlb_flush(rdev);\n\t\tmb();\n\t}\n\treturn 0;",
    ),
    "userptr pin can make zero progress": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\tif (!r) {\n\t\t\tr = -EFAULT;\n\t\t\tgoto release_pages;\n\t\t}\n",
        "",
    ),
    "DMA map failure frees SG container": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "release_sg:\n\tsg_free_table(ttm->sg);",
        "release_sg:\n\tkfree(ttm->sg);",
    ),
    "DMA map failure retains stale SG ownership": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "release_sg:\n\tsg_free_table(ttm->sg);\n\tmemset(ttm->sg, 0, sizeof(*ttm->sg));",
        "release_sg:\n\tsg_free_table(ttm->sg);",
    ),
    "userptr pin return is ignored": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\tr = radeon_ttm_tt_pin_userptr(bdev, ttm);\n\t\tif (r)\n\t\t\treturn r;",
        "\t\tradeon_ttm_tt_pin_userptr(bdev, ttm);",
    ),
    "bind failure retains userptr pin": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\tif (gtt->userptr)\n\t\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n\t\treturn r;",
        "\t\treturn r;",
    ),
    "userptr releases pages before PTEs": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tradeon_gart_unbind(rdev, gtt->offset, ttm->num_pages);\n\n\tgtt->bound = false;\n\tif (gtt->userptr)\n\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);",
        "\tif (gtt->userptr)\n\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n\tradeon_gart_unbind(rdev, gtt->offset, ttm->num_pages);\n\n\tgtt->bound = false;",
    ),
    "successful unpin retains stale SG ownership": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tsg_free_table(ttm->sg);\n\tmemset(ttm->sg, 0, sizeof(*ttm->sg));\n}\n\nstatic bool radeon_ttm_backend_is_bound",
        "\tsg_free_table(ttm->sg);\n}\n\nstatic bool radeon_ttm_backend_is_bound",
    ),
    "kernel map skips reservation wait": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\tr = dma_resv_wait_timeout(bo->tbo.base.resv, DMA_RESV_USAGE_KERNEL,\n\t\t\t\t  false, MAX_SCHEDULE_TIMEOUT);\n\tif (r < 0)\n\t\treturn r;",
        "\tr = 1;",
    ),
    "fault inspects placement before reserve": (
        "drivers/gpu/drm/radeon/radeon_gem.c",
        "\tret = ttm_bo_vm_reserve(bo, vmf);",
        "\t(void)READ_ONCE(bo->resource->mem_type);\n\tret = ttm_bo_vm_reserve(bo, vmf);",
    ),
    "reader drops lifetime lock": (
        "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
        "\tmutex_lock(&rs400_gart_page_table_lock);\n\tif (!rdev->gart.ready || !rdev->gart.ptr) {",
        "\tif (!rdev->gart.ready || !rdev->gart.ptr) {",
    ),
}

POLICY_MUTATIONS = {
    "repaired userptr row promoted to proven": (
        "USERPTR_PIN_DMA_MAP_TRANSACTION\t",
        "USERPTR_PIN_DMA_MAP_TRANSACTION\t",
        6,
        "proven",
    ),
    "open payload row promoted to proven": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        6,
        "proven",
    ),
    "external commit loses identity": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        13,
        "0" * 40,
    ),
    "sparse cursor loses range dependency": (
        "GART_UNBIND_SPARSE_CURSOR\t",
        "GART_UNBIND_SPARSE_CURSOR\t",
        5,
        "GTT_APERTURE_SIZE_DERIVATION",
    ),
    "payload nonclaim polarity is inverted": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        18,
        "The source proves CPU payload visibility.",
    ),
}


def copy_inputs(source_root: Path, destination: Path) -> None:
    for relative in (*SOURCE_FILES, str(POLICY)):
        source_path = source_root / relative
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination_path)


def mutate_policy(path: Path, row_prefix: str, field_index: int, value: str) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(row_prefix)]
    if len(matches) != 1:
        raise LifecycleError(
            f"selftest policy row match count for {row_prefix}: {matches}"
        )
    fields = lines[matches[0]].split("\t")
    fields[field_index] = value
    lines[matches[0]] = "\t".join(fields)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def selftest(root: Path) -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as directory:
        known_good = Path(directory) / "good"
        copy_inputs(root, known_good)
        try:
            check_tree(known_good)
        except LifecycleError as exc:
            print(f"selftest known-good REJECTED: {exc}", file=sys.stderr)
            return 1
        print("selftest known-good accepted: finite GART lifecycle")

        for label, (relative, old, new) in SOURCE_MUTATIONS.items():
            mutant = Path(directory) / re.sub(r"[^a-z0-9]+", "-", label.lower())
            copy_inputs(root, mutant)
            path = mutant / relative
            text = path.read_text(encoding="ascii")
            if text.count(old) != 1:
                print(f"selftest fixture error for {label}", file=sys.stderr)
                failures += 1
                continue
            path.write_text(text.replace(old, new, 1), encoding="ascii")
            try:
                check_tree(mutant)
            except LifecycleError:
                print(f"selftest known-bad rejected: {label}")
            else:
                print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
                failures += 1

        for label, (row_prefix, _, field_index, value) in POLICY_MUTATIONS.items():
            mutant = Path(directory) / re.sub(r"[^a-z0-9]+", "-", label.lower())
            copy_inputs(root, mutant)
            mutate_policy(mutant / POLICY, row_prefix, field_index, value)
            try:
                check_tree(mutant)
            except LifecycleError:
                print(f"selftest known-bad rejected: {label}")
            else:
                print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
                failures += 1

    if failures:
        print(f"selftest: {failures} fixture(s) misclassified", file=sys.stderr)
        return 1
    total_bad = len(SOURCE_MUTATIONS) + len(POLICY_MUTATIONS)
    print(f"selftest: 1 good and {total_bad} bad fixtures classified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest(args.root)
    try:
        check_tree(args.root)
    except LifecycleError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    rows = read_policy(args.root)
    counts = {status: 0 for status in ("proven", "repaired", "open")}
    for row in rows.values():
        counts[row["source_status"]] += 1
    print(
        "Radeon GART lifecycle: "
        f"{len(rows)} rows, {counts['proven']} proven, "
        f"{counts['repaired']} repaired, {counts['open']} open"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
