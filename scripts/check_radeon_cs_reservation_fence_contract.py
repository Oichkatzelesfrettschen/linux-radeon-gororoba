#!/usr/bin/env python3
"""Prove the finite Radeon CS, reservation, ring, and fence contract.

The checker binds the exact policy denominator to the source relationships
that establish admission, reservation ownership, dependency import, command
emission, and fence publication. OPEN rows stay source-visible and cannot be
promoted into payload-visibility or reset-semantics claims by prose drift.
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

import check_parked_admission_guards as parked_guards
import check_radeon_gart_lifecycle as lifecycle
import check_rs4xx_gart_cache_policy as cache_policy

POLICY = Path("policy/radeon-cs-reservation-fence-contract.tsv")
SUBTREE = Path("drivers/gpu/drm/radeon")
EXPECTED_POLICY_SHA256 = (
    "0542c3392b46196d679948a3c7150670f87afc645418d33e66c7226901cb54de"
)

EXPECTED_ROWS = {
    "RS482_ASIC_COMMAND_CALLBACK_BINDING": ("proven", "NONE"),
    "CS_PARKED_EARLY_REFUSAL": ("proven", "NONE"),
    "CS_RELOCATION_RECORD_GEOMETRY": ("repaired", "CS_PARKED_EARLY_REFUSAL"),
    "CS_SUCCESS_FENCE_INVARIANT": (
        "repaired",
        "CS_RELOCATION_RECORD_GEOMETRY",
    ),
    "CS_BO_RESERVATION_LOCKS": ("proven", "CS_SUCCESS_FENCE_INVARIANT"),
    "CS_RESERVATION_DEPENDENCY_IMPORT": (
        "proven",
        "CS_BO_RESERVATION_LOCKS",
    ),
    "CS_RING_DEPENDENCY_AND_IB_SCHEDULE": (
        "proven",
        "CS_RESERVATION_DEPENDENCY_IMPORT;RS482_ASIC_COMMAND_CALLBACK_BINDING",
    ),
    "R300_FENCE_COMMAND_SEQUENCE": (
        "proven",
        "RS482_ASIC_COMMAND_CALLBACK_BINDING;CS_RING_DEPENDENCY_AND_IB_SCHEDULE",
    ),
    "CS_RESERVATION_FENCE_PUBLICATION": (
        "proven",
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE",
    ),
    "CS_RELOCATION_ACCESS_DIRECTION": (
        "open",
        "CS_BO_RESERVATION_LOCKS;RS482_ASIC_COMMAND_CALLBACK_BINDING",
    ),
    "FENCE_FORCE_COMPLETION_PUBLICATION": (
        "open",
        "CS_RESERVATION_FENCE_PUBLICATION",
    ),
    "RS482_RESET_RING_REPLAY_SEMANTICS": (
        "open",
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE;FENCE_FORCE_COMPLETION_PUBLICATION",
    ),
    "CS_SUSPEND_FENCE_LOCK_CONTEXT": (
        "open",
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE",
    ),
    "RS482_CACHED_GTT_PAYLOAD_VISIBILITY": (
        "open",
        "R300_FENCE_COMMAND_SEQUENCE;CS_RESERVATION_FENCE_PUBLICATION",
    ),
}

EXPECTED_EXTERNAL = {
    "CS_PARKED_EARLY_REFUSAL": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "NONE",
    ),
    "RS482_RESET_RING_REPLAY_SEMANTICS": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "NONE",
    ),
    "RS482_CACHED_GTT_PAYLOAD_VISIBILITY": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "CPU_GTT_GPU_PUBLICATION;GPU_GTT_CPU_INVALIDATION",
    ),
}

SOURCE_FILES = (
    "drivers/gpu/drm/radeon/Makefile",
    "drivers/gpu/drm/radeon/radeon_asic.c",
    "drivers/gpu/drm/radeon/radeon_cs.c",
    "drivers/gpu/drm/radeon/radeon_device.c",
    "drivers/gpu/drm/radeon/radeon_fence.c",
    "drivers/gpu/drm/radeon/radeon_ib.c",
    "drivers/gpu/drm/radeon/radeon_object.c",
    "drivers/gpu/drm/radeon/radeon_ring.c",
    "drivers/gpu/drm/radeon/radeon_sync.c",
    "drivers/gpu/drm/radeon/r300.c",
)


class ContractError(Exception):
    """The finite CS and fence contract is incomplete or contradicted."""


def fail_if_present(label: str, body: str, needles: tuple[str, ...]) -> None:
    present = [needle for needle in needles if needle in body]
    if present:
        raise ContractError(f"{label}: unexpected source tokens {present}")


def read_policy(root: Path) -> dict[str, dict[str, str]]:
    path = root / POLICY
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ContractError(f"missing policy table {path}") from exc
    if not raw.isascii() or b"\r" in raw:
        raise ContractError("policy table must be LF terminated ASCII")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_POLICY_SHA256:
        raise ContractError(f"policy bytes differ from exact contract: {digest}")
    reader = csv.DictReader(raw.decode("ascii").splitlines(), delimiter="\t")
    if tuple(reader.fieldnames or ()) != lifecycle.HEADER:
        raise ContractError("policy header differs from the 19 field schema")
    rows: dict[str, dict[str, str]] = {}
    for row in reader:
        row_id = row["row_id"]
        if not row_id or row_id in rows:
            raise ContractError(f"duplicate or empty row_id {row_id!r}")
        if any(not value for value in row.values()):
            raise ContractError(f"{row_id}: every field must be nonempty")
        rows[row_id] = row
    if set(rows) != set(EXPECTED_ROWS):
        missing = sorted(set(EXPECTED_ROWS) - set(rows))
        extra = sorted(set(rows) - set(EXPECTED_ROWS))
        raise ContractError(
            f"policy denominator differs: missing={missing} extra={extra}"
        )
    return rows


def check_dependencies(rows: dict[str, dict[str, str]]) -> None:
    graph: dict[str, list[str]] = {}
    for row_id, row in rows.items():
        expected_status, expected_dependencies = EXPECTED_ROWS[row_id]
        if row["source_status"] != expected_status:
            raise ContractError(f"{row_id}: source status differs")
        if row["depends_on"] != expected_dependencies:
            raise ContractError(f"{row_id}: dependency edge differs")
        if row["source_status"] == "open" and row["silicon_status"] == "proven":
            raise ContractError(f"{row_id}: OPEN source row claims proven silicon")
        dependencies = (
            [] if row["depends_on"] == "NONE" else row["depends_on"].split(";")
        )
        unknown = sorted(set(dependencies) - set(rows))
        if unknown:
            raise ContractError(f"{row_id}: unknown dependencies {unknown}")
        graph[row_id] = dependencies

    active: set[str] = set()
    complete: set[str] = set()

    def visit(row_id: str) -> None:
        if row_id in active:
            raise ContractError(f"dependency cycle reaches {row_id}")
        if row_id in complete:
            return
        active.add(row_id)
        for dependency in graph[row_id]:
            visit(dependency)
        active.remove(row_id)
        complete.add(row_id)

    for row_id in rows:
        visit(row_id)


def check_external(rows: dict[str, dict[str, str]]) -> None:
    for row_id, row in rows.items():
        actual = (
            row["external_repository"],
            row["external_commit"],
            row["external_artifact"],
            row["external_row_id"],
        )
        expected = EXPECTED_EXTERNAL.get(row_id, ("NONE",) * 4)
        if actual != expected:
            raise ContractError(f"{row_id}: external authority identity differs")
        if expected[0] != "NONE" and not re.fullmatch(
            r"[0-9a-f]{40}", row["external_commit"]
        ):
            raise ContractError(f"{row_id}: external commit is not a full object ID")


def function(root: Path, filename: str, name: str) -> str:
    try:
        return lifecycle.function(root, filename, name)
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc


def source(root: Path, filename: str) -> str:
    path = root / SUBTREE / filename
    try:
        return cache_policy.strip_comments(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        raise ContractError(f"cannot read UTF-8 source {path}") from exc


def require(label: str, body: str, pattern: str) -> None:
    try:
        lifecycle.require(label, body, pattern)
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc


def require_order(label: str, body: str, needles: tuple[str, ...]) -> None:
    try:
        lifecycle.require_order(label, body, needles)
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc


def check_build_and_callbacks(root: Path) -> None:
    makefile = (root / SUBTREE / "Makefile").read_text(encoding="ascii")
    for owner in (
        "radeon_asic.o",
        "radeon_cs.o",
        "radeon_device.o",
        "radeon_fence.o",
        "radeon_ib.o",
        "radeon_object.o",
        "radeon_ring.o",
        "radeon_sync.o",
    ):
        if makefile.count(owner) != 1:
            raise ContractError(f"Kbuild owner count for {owner} is not one")
    if makefile.count("r100.o r300.o r420.o") != 1:
        raise ContractError("Kbuild link ownership for r300.o is not one")

    asic_source = source(root, "radeon_asic.c")
    try:
        ring = lifecycle.initializer_body(asic_source, "r300_gfx_ring")
        rs400 = lifecycle.initializer_body(asic_source, "rs400_asic")
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc
    require(
        "r300 graphics command callback set differs",
        ring,
        r"\.ib_execute\s*=\s*&r100_ring_ib_execute"
        r".*?\.emit_fence\s*=\s*&r300_fence_ring_emit"
        r".*?\.cs_parse\s*=\s*&r300_cs_parse",
    )
    require(
        "RS400 graphics ring selection differs",
        rs400,
        r"\.init\s*=\s*&rs400_init.*?\.ring\s*=\s*\{.*?"
        r"\[RADEON_RING_TYPE_GFX_INDEX\]\s*=\s*&r300_gfx_ring",
    )
    require(
        "RS400 and RS480 family selection differs",
        function(root, "radeon_asic.c", "radeon_asic_init"),
        r"case\s+CHIP_RS400\s*:\s*case\s+CHIP_RS480\s*:"
        r"\s*rdev->asic\s*=\s*&rs400_asic",
    )


def check_ioctl_and_relocation_admission(root: Path) -> None:
    command_guard = next(
        guard for guard in parked_guards.GUARDS if guard["id"] == "command-submission"
    )
    try:
        parked_guards.check_guard(root, command_guard)
    except parked_guards.GuardError as exc:
        raise ContractError(str(exc)) from exc

    ioctl = function(root, "radeon_cs.c", "radeon_cs_ioctl")
    require_order(
        "CS reader lock and parser lifetime",
        ioctl,
        (
            "down_read(&rdev->exclusive_lock)",
            "READ_ONCE(rdev->gpu_parked)",
            "radeon_cs_parser_init",
            "radeon_cs_parser_relocs",
            "radeon_cs_parser_fini",
            "up_read(&rdev->exclusive_lock)",
        ),
    )

    relocs = function(root, "radeon_cs.c", "radeon_cs_parser_relocs")
    require_order(
        "relocation chunk geometry admission",
        relocs,
        (
            "chunk = p->chunk_relocs",
            "chunk->length_dw % 4",
            "return -EINVAL;",
            "p->nrelocs = chunk->length_dw / 4",
            "drm_gem_object_lookup",
        ),
    )

    parser_init = function(root, "radeon_cs.c", "radeon_cs_parser_init")
    require_order(
        "relocation-only submission admission",
        parser_init,
        (
            "if (p->chunk_relocs && !p->chunk_ib)",
            '"relocs_without_ib"',
            "-EINVAL",
            "if (p->rdev)",
        ),
    )

    require_order(
        "validated submissions require a success fence before cleanup",
        ioctl,
        (
            "r = radeon_cs_ib_vm_chunk",
            "!list_empty(&parser.validated) && !parser.ib.fence",
            "r = -EINVAL;",
            "out:",
            "radeon_cs_parser_fini",
        ),
    )

    next_reloc = function(root, "radeon_cs.c", "radeon_cs_packet_next_reloc")
    require_order(
        "relocation record index admission",
        next_reloc,
        (
            "idx = radeon_get_ib_value",
            "idx >= relocs_chunk->length_dw",
            "idx % 4",
            "relocs_chunk->length_dw - idx < 4",
            "relocs_chunk->kdata[idx + 3]",
            "p->relocs[(idx / 4)]",
        ),
    )


def check_reservation_ownership(root: Path) -> None:
    relocs = function(root, "radeon_cs.c", "radeon_cs_parser_relocs")
    require_order(
        "relocation object and validation ownership",
        relocs,
        (
            "drm_gem_object_lookup",
            "p->relocs[i].robj = gem_to_radeon_bo",
            "p->relocs[i].shared = !r->write_domain",
            "radeon_cs_buckets_add",
            "radeon_cs_buckets_get_list",
            "radeon_bo_list_validate",
        ),
    )
    validate = function(root, "radeon_object.c", "radeon_bo_list_validate")
    require_order(
        "BO reservation before placement validation",
        validate,
        (
            "drm_exec_until_all_locked",
            "drm_exec_prepare_obj",
            "drm_exec_retry_on_contention",
            "ttm_bo_validate",
            "lobj->gpu_offset = radeon_bo_gpu_offset",
        ),
    )
    cs_sync = function(root, "radeon_cs.c", "radeon_cs_sync_rings")
    require_order(
        "reservation dependency collection",
        cs_sync,
        (
            "list_for_each_entry",
            "resv = reloc->robj->tbo.base.resv",
            "radeon_sync_resv",
            "if (r)",
            "return r;",
        ),
    )
    sync_resv = function(root, "radeon_sync.c", "radeon_sync_resv")
    require_order(
        "local and foreign reservation dependency split",
        sync_resv,
        (
            "dma_resv_for_each_fence",
            "dma_resv_usage_rw(!shared)",
            "fence = to_radeon_fence",
            "fence->rdev == rdev",
            "radeon_sync_fence",
            "dma_fence_wait",
        ),
    )


def check_ring_and_fence_publication(root: Path) -> None:
    schedule = function(root, "radeon_ib.c", "radeon_ib_schedule")
    require_order(
        "IB dependency, execute, fence, and commit order",
        schedule,
        (
            "radeon_ring_lock",
            "radeon_sync_rings",
            "radeon_ring_ib_execute(rdev, ib->ring, ib)",
            "radeon_fence_emit",
            "radeon_ring_unlock_commit",
        ),
    )
    commit = function(root, "radeon_ring.c", "radeon_ring_commit")
    if commit.count("radeon_ring_set_wptr") != 1:
        raise ContractError("ring commit must publish one hardware write pointer")
    require_order(
        "ring publication order",
        commit,
        (
            "hdp_flush(rdev, ring)",
            "while (ring->wptr & ring->align_mask)",
            "mb();",
            "mmio_hdp_flush(rdev)",
            "radeon_ring_set_wptr",
        ),
    )
    fence_emit = function(root, "r300.c", "r300_fence_ring_emit")
    require_order(
        "r300 cache, idle, sequence, and interrupt order",
        fence_emit,
        (
            "R300_RB3D_DSTCACHE_CTLSTAT",
            "R300_RB3D_DC_FLUSH",
            "R300_RB3D_ZCACHE_CTLSTAT",
            "R300_ZC_FLUSH",
            "RADEON_WAIT_3D_IDLECLEAN",
            "RADEON_HDP_READ_BUFFER_INVALIDATE",
            "scratch_reg",
            "fence->seq",
            "RADEON_SW_INT_FIRE",
        ),
    )
    parser_fini = function(root, "radeon_cs.c", "radeon_cs_parser_fini")
    if parser_fini.count("drm_exec_fini") != 1:
        raise ContractError("parser cleanup must release drm_exec exactly once")
    require_order(
        "reservation fence publication before unlock",
        parser_fini,
        (
            "if (!error)",
            "list_for_each_entry",
            "dma_resv_add_fence",
            "DMA_RESV_USAGE_READ",
            "DMA_RESV_USAGE_WRITE",
            "drm_exec_fini",
        ),
    )


def check_open_boundaries(root: Path) -> None:
    relocs = function(root, "radeon_cs.c", "radeon_cs_parser_relocs")
    require(
        "userspace relocation access declaration changed",
        relocs,
        r"\.shared\s*=\s*!r->write_domain",
    )
    parser = function(root, "r300.c", "r300_cs_parse")
    if "write_domain" in parser:
        raise ContractError(
            "r300 packet access now references write_domain; update the OPEN row"
        )

    force = function(root, "radeon_fence.c", "radeon_fence_driver_force_completion")
    require_order(
        "force completion source structure",
        force,
        ("radeon_fence_write", "cancel_delayed_work_sync"),
    )
    fail_if_present(
        "force completion OPEN boundary",
        force,
        ("last_seq", "dma_fence_signal", "wake_up"),
    )

    suspend = function(root, "radeon_device.c", "radeon_suspend_kms")
    require_order(
        "suspend fence wait structure",
        suspend,
        ("radeon_bo_evict_vram", "radeon_fence_wait_empty", "radeon_suspend"),
    )
    if "ring_lock" in suspend:
        raise ContractError(
            "suspend now carries a ring lock token; update the OPEN lock row"
        )

    reset = function(root, "radeon_device.c", "radeon_gpu_reset")
    require_order(
        "reset backup, reset, replay, and force-completion structure",
        reset,
        (
            "down_write(&rdev->exclusive_lock)",
            "radeon_ring_backup",
            "r = radeon_asic_reset",
            "if (!r && ring_data[i])",
            "radeon_ring_restore",
            "radeon_fence_driver_force_completion",
        ),
    )

    combined = "\n".join(source(root, Path(name).name) for name in SOURCE_FILES[1:])
    fail_if_present(
        "submit path payload cache maintenance boundary",
        combined.lower(),
        ("clflush", "dma_sync_", "begin_cpu_access", "end_cpu_access"),
    )


def check_tree(root: Path) -> None:
    rows = read_policy(root)
    check_dependencies(rows)
    check_external(rows)
    check_build_and_callbacks(root)
    check_ioctl_and_relocation_admission(root)
    check_reservation_ownership(root)
    check_ring_and_fence_publication(root)
    check_open_boundaries(root)


SOURCE_MUTATIONS = {
    "Kbuild drops CS owner": (
        "drivers/gpu/drm/radeon/Makefile",
        "\tradeon_cs.o radeon_bios.o",
        "\tradeon_bios.o",
    ),
    "RS400 drops its init callback": (
        "drivers/gpu/drm/radeon/radeon_asic.c",
        ("static struct radeon_asic rs400_asic = {\n\t.init = &rs400_init,"),
        ("static struct radeon_asic rs400_asic = {\n\t.init = &removed_rs400_init,"),
    ),
    "RS400 drops its graphics ring callback": (
        "drivers/gpu/drm/radeon/radeon_asic.c",
        (
            "static struct radeon_asic rs400_asic = {\n"
            "\t.init = &rs400_init,\n"
            "\t.fini = &rs400_fini,\n"
            "\t.suspend = &rs400_suspend,\n"
            "\t.resume = &rs400_resume,\n"
            "\t.vga_set_state = &r100_vga_set_state,\n"
            "\t.asic_reset = &r300_asic_reset,\n"
            "\t.mmio_hdp_flush = NULL,\n"
            "\t.gui_idle = &r100_gui_idle,\n"
            "\t.mc_wait_for_idle = &rs400_mc_wait_for_idle,\n"
            "\t.get_allowed_info_register = "
            "radeon_invalid_get_allowed_info_register,\n"
            "\t.gart = {\n"
            "\t\t.tlb_flush = &rs400_gart_tlb_flush,\n"
            "\t\t.get_page_entry = &rs400_gart_get_page_entry,\n"
            "\t\t.set_page = &rs400_gart_set_page,\n"
            "\t},\n\t.ring = {\n"
            "\t\t[RADEON_RING_TYPE_GFX_INDEX] = &r300_gfx_ring"
        ),
        (
            "static struct radeon_asic rs400_asic = {\n"
            "\t.init = &rs400_init,\n"
            "\t.fini = &rs400_fini,\n"
            "\t.suspend = &rs400_suspend,\n"
            "\t.resume = &rs400_resume,\n"
            "\t.vga_set_state = &r100_vga_set_state,\n"
            "\t.asic_reset = &r300_asic_reset,\n"
            "\t.mmio_hdp_flush = NULL,\n"
            "\t.gui_idle = &r100_gui_idle,\n"
            "\t.mc_wait_for_idle = &rs400_mc_wait_for_idle,\n"
            "\t.get_allowed_info_register = "
            "radeon_invalid_get_allowed_info_register,\n"
            "\t.gart = {\n"
            "\t\t.tlb_flush = &rs400_gart_tlb_flush,\n"
            "\t\t.get_page_entry = &rs400_gart_get_page_entry,\n"
            "\t\t.set_page = &rs400_gart_set_page,\n"
            "\t},\n\t.ring = {\n"
            "\t\t[RADEON_RING_TYPE_GFX_INDEX] = &rv515_gfx_ring"
        ),
    ),
    "parked CS condition is inverted": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "if (READ_ONCE(rdev->gpu_parked)) {",
        "if (!READ_ONCE(rdev->gpu_parked)) {",
    ),
    "relocation chunk accepts a partial record": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (chunk->length_dw % 4) {",
        "\tif (false) {",
    ),
    "relocation-only submission is admitted": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (p->chunk_relocs && !p->chunk_ib)\n",
        "\tif (false)\n",
    ),
    "validated submission lacks final fence admission": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {\n"
            '\t\tDRM_ERROR("Successful command submission has validated BOs but no fence !\\n");\n'
            "\t\tr = -EINVAL;\n\t}\n"
        ),
        "",
    ),
    "relocation index accepts unaligned records": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "idx >= relocs_chunk->length_dw || idx % 4 ||",
        "idx >= relocs_chunk->length_dw || false ||",
    ),
    "relocation index accepts truncated tails": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "relocs_chunk->length_dw - idx < 4) {",
        "false) {",
    ),
    "BO validation skips reservation preparation": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "drm_exec_prepare_obj",
        "reservation_prepare_removed",
    ),
    "CS drops reservation dependency import": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\t\tr = radeon_sync_resv(p->rdev, &p->ib.sync, resv, reloc->shared);",
        "\t\tr = 0;",
    ),
    "IB fence emits before execution": (
        "drivers/gpu/drm/radeon/radeon_ib.c",
        (
            "\tradeon_ring_ib_execute(rdev, ib->ring, ib);\n"
            "\tr = radeon_fence_emit(rdev, &ib->fence, ib->ring);"
        ),
        (
            "\tr = radeon_fence_emit(rdev, &ib->fence, ib->ring);\n"
            "\tradeon_ring_ib_execute(rdev, ib->ring, ib);"
        ),
    ),
    "ring publication drops memory barrier": (
        "drivers/gpu/drm/radeon/radeon_ring.c",
        "\tmb();\n",
        "",
    ),
    "r300 interrupt emits before sequence": (
        "drivers/gpu/drm/radeon/r300.c",
        (
            "\tradeon_ring_write(ring, fence->seq);\n"
            "\tradeon_ring_write(ring, PACKET0(RADEON_GEN_INT_STATUS, 0));\n"
            "\tradeon_ring_write(ring, RADEON_SW_INT_FIRE);"
        ),
        (
            "\tradeon_ring_write(ring, RADEON_SW_INT_FIRE);\n"
            "\tradeon_ring_write(ring, PACKET0(RADEON_GEN_INT_STATUS, 0));\n"
            "\tradeon_ring_write(ring, fence->seq);"
        ),
    ),
    "reservation unlock precedes fence publication": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (!error) {\n\t\tstruct radeon_bo_list *reloc;",
        "\tdrm_exec_fini(&parser->exec);\n\tif (!error) {\n\t\tstruct radeon_bo_list *reloc;",
    ),
    "force completion claims local waiter publication": (
        "drivers/gpu/drm/radeon/radeon_fence.c",
        "\t\tradeon_fence_write(rdev, rdev->fence_drv[ring].sync_seq[ring], ring);",
        "\t\trdev->fence_drv[ring].last_seq = rdev->fence_drv[ring].sync_seq[ring];\n\t\tradeon_fence_write(rdev, rdev->fence_drv[ring].sync_seq[ring], ring);",
    ),
}

POLICY_MUTATIONS = {
    "repaired relocation row promoted": (
        "CS_RELOCATION_RECORD_GEOMETRY\t",
        6,
        "proven",
    ),
    "OPEN payload row promoted": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        6,
        "proven",
    ),
    "payload nonclaim polarity inverted": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        18,
        "Reservations and fences prove payload visibility.",
    ),
    "external row identity changed": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        15,
        "CPU_GTT_GPU_PUBLICATION",
    ),
    "ring schedule loses dependency": (
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE\t",
        5,
        "RS482_ASIC_COMMAND_CALLBACK_BINDING",
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
        raise ContractError(
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
        except ContractError as exc:
            print(f"selftest known-good REJECTED: {exc}", file=sys.stderr)
            return 1
        print("selftest known-good accepted: finite CS and fence contract")

        for label, (relative, old, new) in SOURCE_MUTATIONS.items():
            mutant = Path(directory) / re.sub(r"[^a-z0-9]+", "-", label.lower())
            copy_inputs(root, mutant)
            path = mutant / relative
            text = path.read_text(encoding="utf-8")
            if text.count(old) != 1:
                print(f"selftest fixture error for {label}", file=sys.stderr)
                failures += 1
                continue
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
            try:
                check_tree(mutant)
            except ContractError:
                print(f"selftest known-bad rejected: {label}")
            else:
                print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
                failures += 1

        for label, (row_prefix, field_index, value) in POLICY_MUTATIONS.items():
            mutant = Path(directory) / re.sub(r"[^a-z0-9]+", "-", label.lower())
            copy_inputs(root, mutant)
            mutate_policy(mutant / POLICY, row_prefix, field_index, value)
            try:
                check_tree(mutant)
            except ContractError:
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
    except ContractError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    rows = read_policy(args.root)
    counts = {status: 0 for status in ("proven", "repaired", "open")}
    for row in rows.values():
        counts[row["source_status"]] += 1
    print(
        "Radeon CS reservation and fence contract: "
        f"{len(rows)} rows, {counts['proven']} proven, "
        f"{counts['repaired']} repaired, {counts['open']} open"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
