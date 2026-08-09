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
    "36e60bd6bde6347dd836bd9df40530210c34d83e2c7bea971245ff94c9604e1e"
)
CS_DIRECT_PREFIX_SHA256 = {
    "relocs": "bd4645062b4348cbecfb5a1353312a61f20f1e5909401bf2c9cac9717e652ead",
    "parser_init": "3e13e4a348a49a3343eb3ba83499f57f9af4d135603a2f755ab0eba1c8cd6488",
    "ioctl": "1ed23bf68d3eb2e5e9e640f556374c6d04a057aec4098698fa3311608d597291",
    "next_reloc": "bd02f061ab8376685f57aaaf9e108cc2ac1a67bbd90a27abb082442393caaa2e",
}
EXPECTED_POLICY_ROW_SHA256 = {
    "RS482_ASIC_COMMAND_CALLBACK_BINDING": "ff542ab28a631dd2625d5210b0e49483b35ba32b79532b6a73afaf3880bd7d8c",
    "CS_PARKED_EARLY_REFUSAL": "39966eb5ded5c02865dbdbf80a128c5a2bb04be08388cb38749c75281ce31364",
    "CS_RELOCATION_RECORD_GEOMETRY": "8b9a3b46b9eeb3d1f220231321dd11d651c48d353cc2214576c4b4889b57f8c0",
    "CS_BO_RESERVATION_LOCKS": "f1b5de72d7097b53d3fbf0aecb0fa5d85a0e186eaa5697d7d0e96831310d0626",
    "CS_RESERVATION_DEPENDENCY_IMPORT": "e3980ff208d5320c64504ae557b94a5360ec46c4274c15a6eda89116af9942a8",
    "CS_RING_DEPENDENCY_AND_IB_SCHEDULE": "911cf696a10ad7bc9973cc9ae29212bd84dac11129b51f1729e064e35c346eb1",
    "CS_SUCCESS_FENCE_INVARIANT": "e2ef42bf2a10ade2e90154b39c4454ce1a08cfbf32e0a48c509e7f2e5dd8a799",
    "R300_FENCE_COMMAND_SEQUENCE": "a2fdd6378417272101f92fd596d2f0bf1309db8e77e2d78d127515ad8eb77184",
    "CS_RESERVATION_FENCE_PUBLICATION": "cd0354edac2176635adb4533b6d7b2863d43a88978a93b0a6a39111c43821e0d",
    "CS_RELOCATION_ACCESS_DIRECTION": "00a7666480c9867108a10896c05ce67c3b2170ebfb55bea16b708606d30ee740",
    "FENCE_FORCE_COMPLETION_PUBLICATION": "cb392679622a03322f1e4c73ee62d0fbd7db6087744da82c8ebf5fab558fa36c",
    "RS482_RESET_RING_REPLAY_SEMANTICS": "908ab413a611c7c5dc78e3b6790e06d0408adee1a225e04a593e321fa30e0342",
    "CS_SUSPEND_FENCE_LOCK_CONTEXT": "632195d11b66ae70e39d2478c87f3d49f062da38e2f2241100198bf40d21bf10",
    "RS482_CACHED_GTT_PAYLOAD_VISIBILITY": "f439eef616546406773817bd358c12dc055499bc5ea567e595d53e99c87ea938",
}

EXPECTED_ROWS = {
    "RS482_ASIC_COMMAND_CALLBACK_BINDING": ("proven", "NONE"),
    "CS_PARKED_EARLY_REFUSAL": ("proven", "NONE"),
    "CS_RELOCATION_RECORD_GEOMETRY": ("repaired", "CS_PARKED_EARLY_REFUSAL"),
    "CS_BO_RESERVATION_LOCKS": ("proven", "CS_RELOCATION_RECORD_GEOMETRY"),
    "CS_RESERVATION_DEPENDENCY_IMPORT": (
        "proven",
        "CS_BO_RESERVATION_LOCKS",
    ),
    "CS_RING_DEPENDENCY_AND_IB_SCHEDULE": (
        "proven",
        "CS_RESERVATION_DEPENDENCY_IMPORT;RS482_ASIC_COMMAND_CALLBACK_BINDING",
    ),
    "CS_SUCCESS_FENCE_INVARIANT": (
        "repaired",
        "CS_BO_RESERVATION_LOCKS;CS_RING_DEPENDENCY_AND_IB_SCHEDULE",
    ),
    "R300_FENCE_COMMAND_SEQUENCE": (
        "proven",
        "RS482_ASIC_COMMAND_CALLBACK_BINDING;CS_RING_DEPENDENCY_AND_IB_SCHEDULE",
    ),
    "CS_RESERVATION_FENCE_PUBLICATION": (
        "proven",
        "CS_SUCCESS_FENCE_INVARIANT",
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
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE",
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
    "RS482_CACHED_GTT_PAYLOAD_VISIBILITY": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "CPU_GTT_GPU_PUBLICATION;GPU_GTT_CPU_INVALIDATION",
    ),
}

EXPECTED_NONCLAIMS = {
    "RS482_ASIC_COMMAND_CALLBACK_BINDING": "Source binding does not prove live callback execution.",
    "CS_PARKED_EARLY_REFUSAL": "The source guard does not prove target park or recovery behavior.",
    "CS_RELOCATION_RECORD_GEOMETRY": "Static admission does not prove every userspace producer emits correct domains.",
    "CS_BO_RESERVATION_LOCKS": "Reservation locks do not perform payload cache maintenance.",
    "CS_RESERVATION_DEPENDENCY_IMPORT": "Imported fences prove execution ordering, not cache visibility.",
    "CS_RING_DEPENDENCY_AND_IB_SCHEDULE": "A successful schedule means committed work, not completed work.",
    "CS_SUCCESS_FENCE_INVARIANT": "The last-ditch guard does not roll back or make safe work committed without a fence.",
    "R300_FENCE_COMMAND_SEQUENCE": "Emitted cache commands do not prove RS482 executed them or made payloads coherent.",
    "CS_RESERVATION_FENCE_PUBLICATION": "Fence publication does not prove fence completion or payload visibility.",
    "CS_RELOCATION_ACCESS_DIRECTION": "Parser address validation alone does not prove correct reservation usage.",
    "FENCE_FORCE_COMPLETION_PUBLICATION": "Writing the hardware sequence does not by itself prove generic dma_fence signaling.",
    "RS482_RESET_RING_REPLAY_SEMANTICS": "Source replay structure does not prove payload idempotence.",
    "CS_SUSPEND_FENCE_LOCK_CONTEXT": "A comment precondition does not prove the caller holds the lock.",
    "RS482_CACHED_GTT_PAYLOAD_VISIBILITY": "Reservations, fences, mb, and emitted GPU cache commands do not prove payload visibility.",
}

EXPECTED_EVIDENCE_STATUS = {
    "CS_PARKED_EARLY_REFUSAL": ("not-run", "unproved"),
    "RS482_RESET_RING_REPLAY_SEMANTICS": ("not-run", "unproved"),
    "RS482_CACHED_GTT_PAYLOAD_VISIBILITY": ("not-run", "peer-open"),
}

EXPECTED_COMPLETION_GATES = {
    "RS482_CACHED_GTT_PAYLOAD_VISIBILITY": (
        "Both exact target directions retain raw PTE bytes and decoded bits, "
        "raw global snoop control, BO and cache mapping, module and target "
        "identity, command stream, an observed completed fence, maintenance on "
        "and off arms, and producer and consumer digests. Arm outcomes retain "
        "the directional completion-gate interpretations rather than proving "
        "snoop attribution."
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


def read_policy(
    root: Path, expected_policy_sha256: str = EXPECTED_POLICY_SHA256
) -> dict[str, dict[str, str]]:
    path = root / POLICY
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ContractError(f"missing policy table {path}") from exc
    if not raw.isascii() or b"\r" in raw:
        raise ContractError("policy table must be LF terminated ASCII")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_policy_sha256:
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
    if tuple(rows) != tuple(EXPECTED_ROWS):
        raise ContractError("policy row order differs from the causal order")
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


def check_policy_claim_boundaries(rows: dict[str, dict[str, str]]) -> None:
    if set(EXPECTED_NONCLAIMS) != set(rows):
        raise ContractError("nonclaim binding denominator differs")
    for row_id, expected_nonclaim in EXPECTED_NONCLAIMS.items():
        if rows[row_id]["nonclaim"] != expected_nonclaim:
            raise ContractError(f"{row_id}: nonclaim identity differs")
    for row_id, expected_status in EXPECTED_EVIDENCE_STATUS.items():
        actual_status = (
            rows[row_id]["runtime_status"],
            rows[row_id]["silicon_status"],
        )
        if actual_status != expected_status:
            raise ContractError(f"{row_id}: runtime or silicon status differs")
    for row_id, expected_gate in EXPECTED_COMPLETION_GATES.items():
        if rows[row_id]["completion_gate"] != expected_gate:
            raise ContractError(f"{row_id}: completion gate identity differs")


def check_policy_row_identities(rows: dict[str, dict[str, str]]) -> None:
    """Bind all eighteen semantic fields after specific validators run."""

    if set(EXPECTED_POLICY_ROW_SHA256) != set(rows):
        raise ContractError("policy row identity denominator differs")
    for row_id, row in rows.items():
        if (
            lifecycle.policy_row_identity_sha256(row)
            != EXPECTED_POLICY_ROW_SHA256[row_id]
        ):
            raise ContractError(f"{row_id}: exact policy row identity differs")


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
    try:
        relocation_statements, relocation_guard_index = (
            lifecycle.require_exact_if_guard(
                "relocation chunk length admission guard differs",
                relocs,
                "chunk->length_dw % 4",
                "return -EINVAL;",
                7,
                (
                    'DRM_ERROR("Relocation chunk length %u is not a multiple '
                    'of 4 dwords\\n", chunk->length_dw);'
                    "return -EINVAL;"
                ),
            )
        )
        lifecycle.require_direct_statement_prefix_sha256(
            "relocation chunk admission dominance",
            relocation_statements,
            8,
            CS_DIRECT_PREFIX_SHA256["relocs"],
        )
        lifecycle.require_direct_statement(
            "relocation chunk length guard predecessor differs",
            relocation_statements,
            relocation_guard_index - 1,
            "chunk = p->chunk_relocs;",
        )
        lifecycle.require_direct_statement(
            "relocation chunk length guard successor differs",
            relocation_statements,
            relocation_guard_index + 1,
            "p->dma_reloc_idx = 0;",
        )
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc
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
    try:
        parser_statements, parser_guard_index = lifecycle.require_exact_if_guard(
            "relocation-only submission admission guard differs",
            parser_init,
            "p->chunk_relocs && !p->chunk_ib",
            (
                "return radeon_rs480_cs_parser_init_fail("
                'p, "relocs_without_ib", -EINVAL, p->nchunks, '
                "p->nchunks, 0, 0);"
            ),
            25,
            (
                "return radeon_rs480_cs_parser_init_fail("
                'p, "relocs_without_ib", -EINVAL, p->nchunks, '
                "p->nchunks, 0, 0);"
            ),
        )
        lifecycle.require_direct_statement_prefix_sha256(
            "relocation-only admission dominance",
            parser_statements,
            26,
            CS_DIRECT_PREFIX_SHA256["parser_init"],
        )
        lifecycle.require_direct_statement(
            "relocation-only guard predecessor differs",
            parser_statements,
            parser_guard_index - 1,
            "for (i = 0; i < p->nchunks; i++)",
            prefix=True,
        )
        lifecycle.require_direct_statement(
            "relocation-only guard successor differs",
            parser_statements,
            parser_guard_index + 1,
            "if (p->rdev)",
            prefix=True,
        )
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc
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

    try:
        fence_statements, fence_guard_index = lifecycle.require_exact_if_guard(
            "validated submission success fence guard differs",
            ioctl,
            "!list_empty(&parser.validated) && !parser.ib.fence",
            "r = -EINVAL;",
            22,
            (
                'DRM_ERROR("Successful command submission has validated BOs '
                'but no fence !\\n");'
                "r = -EINVAL;"
            ),
        )
        lifecycle.require_direct_statement_prefix_sha256(
            "validated submission fence dominance",
            fence_statements,
            23,
            CS_DIRECT_PREFIX_SHA256["ioctl"],
        )
        lifecycle.require_direct_statement(
            "validated submission fence call predecessor differs",
            fence_statements,
            fence_guard_index - 2,
            "r = radeon_cs_ib_vm_chunk(rdev, &parser);",
        )
        lifecycle.require_direct_statement(
            "validated submission fence branch predecessor differs",
            fence_statements,
            fence_guard_index - 1,
            "if (r) { goto out; }",
        )
        lifecycle.require_direct_statement(
            "validated submission fence guard successor differs",
            fence_statements,
            fence_guard_index + 1,
            "out: radeon_cs_parser_fini(&parser, r);",
        )
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc

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
    try:
        index_statements, index_guard_index = lifecycle.require_exact_if_guard(
            "relocation record index admission guard differs",
            next_reloc,
            (
                "idx >= relocs_chunk->length_dw || idx % 4 || "
                "relocs_chunk->length_dw - idx < 4"
            ),
            "return -EINVAL;",
            12,
            (
                'DRM_ERROR("Relocs at %d do not name one aligned 4-dword '
                'record in chunk %d !\\n", idx, relocs_chunk->length_dw);'
                "radeon_cs_dump_packet(p, &p3reloc);"
                "return -EINVAL;"
            ),
        )
        lifecycle.require_direct_statement_prefix_sha256(
            "relocation record index dominance",
            index_statements,
            13,
            CS_DIRECT_PREFIX_SHA256["next_reloc"],
        )
        lifecycle.require_direct_statement(
            "relocation record index guard predecessor differs",
            index_statements,
            index_guard_index - 1,
            "idx = radeon_get_ib_value(p, p3reloc.idx + 1);",
        )
        lifecycle.require_direct_statement(
            "relocation record index guard successor differs",
            index_statements,
            index_guard_index + 1,
            "if (nomm)",
            prefix=True,
        )
    except lifecycle.LifecycleError as exc:
        raise ContractError(str(exc)) from exc
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


def check_tree(
    root: Path, expected_policy_sha256: str = EXPECTED_POLICY_SHA256
) -> None:
    rows = read_policy(root, expected_policy_sha256)
    check_dependencies(rows)
    check_external(rows)
    check_policy_claim_boundaries(rows)
    check_policy_row_identities(rows)
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
    "relocation length guard is disabled": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (chunk->length_dw % 4) {",
        "\tif (false && (chunk->length_dw % 4)) {",
    ),
    "relocation length guard is negated": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (chunk->length_dw % 4) {",
        "\tif (!(chunk->length_dw % 4)) {",
    ),
    "relocation length guard is inside an outer disabled block": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tif (chunk->length_dw % 4) {\n"
            '\t\tDRM_ERROR("Relocation chunk length %u is not a multiple of 4 dwords\\n",\n'
            "\t\t\t  chunk->length_dw);\n"
            "\t\treturn -EINVAL;\n\t}"
        ),
        (
            "\tif (false) {\n"
            "\t\tif (chunk->length_dw % 4) {\n"
            '\t\t\tDRM_ERROR("Relocation chunk length %u is not a multiple of 4 dwords\\n",\n'
            "\t\t\t\t  chunk->length_dw);\n"
            "\t\t\treturn -EINVAL;\n\t\t}\n\t}"
        ),
    ),
    "relocation length guard is bypassed by a goto": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tchunk = p->chunk_relocs;\n"
            "\tif (chunk->length_dw % 4) {\n"
            '\t\tDRM_ERROR("Relocation chunk length %u is not a multiple of 4 dwords\\n",\n'
            "\t\t\t  chunk->length_dw);\n"
            "\t\treturn -EINVAL;\n"
            "\t}\n"
            "\tp->dma_reloc_idx = 0;"
        ),
        (
            "\tchunk = p->chunk_relocs;\n"
            "\tgoto relocation_guard_done;\n"
            "\tif (chunk->length_dw % 4) {\n"
            '\t\tDRM_ERROR("Relocation chunk length %u is not a multiple of 4 dwords\\n",\n'
            "\t\t\t  chunk->length_dw);\n"
            "\t\treturn -EINVAL;\n"
            "\t}\n"
            "relocation_guard_done:\n"
            "\tp->dma_reloc_idx = 0;"
        ),
    ),
    "relocation parser declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tbool need_mmap_lock = false;\n\tint r;\n\n",
        ("\tbool need_mmap_lock = false;\n\tint r = ({ return 0; 0; });\n\n"),
    ),
    "relocation-only submission is admitted": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (p->chunk_relocs && !p->chunk_ib)\n",
        "\tif (false)\n",
    ),
    "relocation-only guard is disabled": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "if (p->chunk_relocs && !p->chunk_ib)\n",
        "if (false && (p->chunk_relocs && !p->chunk_ib))\n",
    ),
    "relocation-only guard is negated": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "if (p->chunk_relocs && !p->chunk_ib)\n",
        "if (!(p->chunk_relocs && !p->chunk_ib))\n",
    ),
    "relocation-only guard is inside an outer disabled block": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tif (p->chunk_relocs && !p->chunk_ib)\n"
            "\t\treturn radeon_rs480_cs_parser_init_fail("
            'p, "relocs_without_ib",\n'
            "\t\t\t\t\t\t\t-EINVAL, p->nchunks,\n"
            "\t\t\t\t\t\t\tp->nchunks, 0, 0);"
        ),
        (
            "\tif (false) {\n"
            "\t\tif (p->chunk_relocs && !p->chunk_ib)\n"
            "\t\t\treturn radeon_rs480_cs_parser_init_fail("
            'p, "relocs_without_ib",\n'
            "\t\t\t\t\t\t\t\t-EINVAL, p->nchunks,\n"
            "\t\t\t\t\t\t\t\tp->nchunks, 0, 0);\n"
            "\t}"
        ),
    ),
    "relocation-only guard is bypassed by a goto": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tif (p->chunk_relocs && !p->chunk_ib)\n"
            "\t\treturn radeon_rs480_cs_parser_init_fail("
            'p, "relocs_without_ib",\n'
            "\t\t\t\t\t\t\t-EINVAL, p->nchunks,\n"
            "\t\t\t\t\t\t\tp->nchunks, 0, 0);\n\n"
            "\t/* these are KMS only */"
        ),
        (
            "\tgoto relocation_guard_done;\n"
            "\tif (p->chunk_relocs && !p->chunk_ib)\n"
            "\t\treturn radeon_rs480_cs_parser_init_fail("
            'p, "relocs_without_ib",\n'
            "\t\t\t\t\t\t\t-EINVAL, p->nchunks,\n"
            "\t\t\t\t\t\t\tp->nchunks, 0, 0);\n"
            "relocation_guard_done:\n\n"
            "\t/* these are KMS only */"
        ),
    ),
    "parser init declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tu32 ring = RADEON_CS_RING_GFX;\n\ts32 priority = 0;\n\n",
        ("\tu32 ring = RADEON_CS_RING_GFX;\n\ts32 priority = ({ return 0; 0; });\n\n"),
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
    "validated submission fence guard is disabled": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {",
        ("\tif (false && (!list_empty(&parser.validated) && !parser.ib.fence)) {"),
    ),
    "validated submission fence guard is negated": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {",
        "\tif (!(!list_empty(&parser.validated) && !parser.ib.fence)) {",
    ),
    "validated submission fence action is nested under false": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {\n"
            '\t\tDRM_ERROR("Successful command submission has validated BOs but no fence !\\n");\n'
            "\t\tr = -EINVAL;\n\t}"
        ),
        (
            "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {\n"
            "\t\tif (false) {\n"
            '\t\t\tDRM_ERROR("Successful command submission has validated BOs but no fence !\\n");\n'
            "\t\t\tr = -EINVAL;\n\t\t}\n\t}"
        ),
    ),
    "validated submission fence action is overridden later": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\t\tr = -EINVAL;\n\t}\nout:",
        "\t\tr = -EINVAL;\n\t\tr = 0;\n\t}\nout:",
    ),
    "validated submission fence action is bypassed inside the guard": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\t\tr = -EINVAL;\n\t}\nout:",
        "\t\tgoto out;\n\t\tr = -EINVAL;\n\t}\nout:",
    ),
    "validated submission fence guard is inside an outer disabled block": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {\n"
            '\t\tDRM_ERROR("Successful command submission has validated BOs but no fence !\\n");\n'
            "\t\tr = -EINVAL;\n\t}"
        ),
        (
            "\tif (false) {\n"
            "\t\tif (!list_empty(&parser.validated) && !parser.ib.fence) {\n"
            '\t\t\tDRM_ERROR("Successful command submission has validated BOs but no fence !\\n");\n'
            "\t\t\tr = -EINVAL;\n\t\t}\n\t}"
        ),
    ),
    "validated submission fence guard is bypassed by a goto": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tif (!list_empty(&parser.validated) && !parser.ib.fence) {",
        ("\tgoto out;\n\tif (!list_empty(&parser.validated) && !parser.ib.fence) {"),
    ),
    "CS ioctl declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tstruct radeon_cs_parser parser;\n\tint r;\n\n",
        ("\tstruct radeon_cs_parser parser;\n\tint r = ({ return 0; 0; });\n\n"),
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
    "relocation index guard is disabled": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "if (idx >= relocs_chunk->length_dw || idx % 4 ||\n"
            "\t    relocs_chunk->length_dw - idx < 4) {"
        ),
        (
            "if (false && (idx >= relocs_chunk->length_dw || idx % 4 ||\n"
            "\t    relocs_chunk->length_dw - idx < 4)) {"
        ),
    ),
    "relocation index guard is negated": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "if (idx >= relocs_chunk->length_dw || idx % 4 ||\n"
            "\t    relocs_chunk->length_dw - idx < 4) {"
        ),
        (
            "if (!(idx >= relocs_chunk->length_dw || idx % 4 ||\n"
            "\t      relocs_chunk->length_dw - idx < 4)) {"
        ),
    ),
    "relocation index guard is inside an outer disabled block": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tif (idx >= relocs_chunk->length_dw || idx % 4 ||\n"
            "\t    relocs_chunk->length_dw - idx < 4) {\n"
            '\t\tDRM_ERROR("Relocs at %d do not name one aligned 4-dword record in chunk %d !\\n",\n'
            "\t\t\t  idx, relocs_chunk->length_dw);\n"
            "\t\tradeon_cs_dump_packet(p, &p3reloc);\n"
            "\t\treturn -EINVAL;\n"
            "\t}"
        ),
        (
            "\tif (false) {\n"
            "\t\tif (idx >= relocs_chunk->length_dw || idx % 4 ||\n"
            "\t\t    relocs_chunk->length_dw - idx < 4) {\n"
            '\t\t\tDRM_ERROR("Relocs at %d do not name one aligned 4-dword record in chunk %d !\\n",\n'
            "\t\t\t\t  idx, relocs_chunk->length_dw);\n"
            "\t\t\tradeon_cs_dump_packet(p, &p3reloc);\n"
            "\t\t\treturn -EINVAL;\n"
            "\t\t}\n"
            "\t}"
        ),
    ),
    "relocation index guard is bypassed by an earlier return": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        (
            "\tidx = radeon_get_ib_value(p, p3reloc.idx + 1);\n"
            "\tif (idx >= relocs_chunk->length_dw || idx % 4 ||"
        ),
        (
            "\tidx = radeon_get_ib_value(p, p3reloc.idx + 1);\n"
            "\treturn 0;\n"
            "\tif (idx >= relocs_chunk->length_dw || idx % 4 ||"
        ),
    ),
    "packet relocation declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_cs.c",
        "\tunsigned idx;\n\tint r;\n\n",
        "\tunsigned idx;\n\tint r = ({ return 0; 0; });\n\n",
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

SOURCE_EXPECTED_ERRORS = {
    "relocation chunk accepts a partial record": (
        "relocation chunk length admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation length guard is disabled": (
        "relocation chunk length admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation length guard is negated": (
        "relocation chunk length admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation length guard is inside an outer disabled block": (
        "relocation chunk length admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation length guard is bypassed by a goto": (
        "relocation chunk length admission guard differs: direct statement index 8 != 7"
    ),
    "relocation parser declaration hides a statement-expression return": (
        "relocation chunk admission dominance: exact direct statement prefix differs"
    ),
    "relocation-only submission is admitted": (
        "relocation-only submission admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation-only guard is disabled": (
        "relocation-only submission admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation-only guard is negated": (
        "relocation-only submission admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation-only guard is inside an outer disabled block": (
        "relocation-only submission admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation-only guard is bypassed by a goto": (
        "relocation-only submission admission guard differs: "
        "direct statement index 26 != 25"
    ),
    "parser init declaration hides a statement-expression return": (
        "relocation-only admission dominance: exact direct statement prefix differs"
    ),
    "validated submission lacks final fence admission": (
        "validated submission success fence guard differs: "
        "exact condition match count is 0"
    ),
    "validated submission fence guard is disabled": (
        "validated submission success fence guard differs: "
        "exact condition match count is 0"
    ),
    "validated submission fence guard is negated": (
        "validated submission success fence guard differs: "
        "exact condition match count is 0"
    ),
    "validated submission fence action is nested under false": (
        "validated submission success fence guard differs: "
        "guarded action is not the final top-level statement"
    ),
    "validated submission fence action is overridden later": (
        "validated submission success fence guard differs: "
        "guarded action is not the final top-level statement"
    ),
    "validated submission fence action is bypassed inside the guard": (
        "validated submission success fence guard differs: exact guard body differs"
    ),
    "validated submission fence guard is inside an outer disabled block": (
        "validated submission success fence guard differs: "
        "exact condition match count is 0"
    ),
    "validated submission fence guard is bypassed by a goto": (
        "validated submission success fence guard differs: "
        "direct statement index 23 != 22"
    ),
    "CS ioctl declaration hides a statement-expression return": (
        "validated submission fence dominance: exact direct statement prefix differs"
    ),
    "relocation index accepts unaligned records": (
        "relocation record index admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation index accepts truncated tails": (
        "relocation record index admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation index guard is disabled": (
        "relocation record index admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation index guard is negated": (
        "relocation record index admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation index guard is inside an outer disabled block": (
        "relocation record index admission guard differs: "
        "exact condition match count is 0"
    ),
    "relocation index guard is bypassed by an earlier return": (
        "relocation record index admission guard differs: "
        "direct statement index 13 != 12"
    ),
    "packet relocation declaration hides a statement-expression return": (
        "relocation record index dominance: exact direct statement prefix differs"
    ),
}

POLICY_MUTATIONS = {
    "repaired relocation row promoted": (
        "CS_RELOCATION_RECORD_GEOMETRY\t",
        6,
        "proven",
        "CS_RELOCATION_RECORD_GEOMETRY: source status differs",
    ),
    "OPEN payload row promoted": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        6,
        "proven",
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY: source status differs",
    ),
    "payload source relation fabricates target proof": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        7,
        "Reservations and fence publication prove cached GTT payload visibility.",
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY: exact policy row identity differs",
    ),
    "parked current guard fabricates historical runtime observation": (
        "CS_PARKED_EARLY_REFUSAL\t",
        10,
        "peer-observation",
        "CS_PARKED_EARLY_REFUSAL: runtime or silicon status differs",
    ),
    "payload Mesa effect fabricates cache permission": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        17,
        "Mesa may rely on coherent cached GTT payloads without maintenance.",
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY: exact policy row identity differs",
    ),
    "payload nonclaim polarity inverted": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        18,
        "Reservations and fences prove payload visibility.",
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY: nonclaim identity differs",
    ),
    "payload completion gate drops observed fence completion": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        16,
        "Both target directions retain an emitted fence and both digests.",
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY: completion gate identity differs",
    ),
    "external row identity changed": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        15,
        "CPU_GTT_GPU_PUBLICATION",
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY: external authority identity differs",
    ),
    "external artifact identity changed": (
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY\t",
        14,
        "src/re/r300/corpora/incorrect.jsonl",
        "RS482_CACHED_GTT_PAYLOAD_VISIBILITY: external authority identity differs",
    ),
    "parked row gains external row authority": (
        "CS_PARKED_EARLY_REFUSAL\t",
        15,
        "CS_PARKED_EARLY_REFUSAL",
        "CS_PARKED_EARLY_REFUSAL: external authority identity differs",
    ),
    "parked row claims the historical bundle artifact": (
        "CS_PARKED_EARLY_REFUSAL\t",
        14,
        "src/re/r300/results/cachyos_vostro1000_rs482_parked_entry_contract_matrix_20260805T055406Z",
        "CS_PARKED_EARLY_REFUSAL: external authority identity differs",
    ),
    "reset replay claims an unmaterialized artifact": (
        "RS482_RESET_RING_REPLAY_SEMANTICS\t",
        12,
        "steinmarder-r300",
        "RS482_RESET_RING_REPLAY_SEMANTICS: external authority identity differs",
    ),
    "reset replay regains peer-open authority": (
        "RS482_RESET_RING_REPLAY_SEMANTICS\t",
        11,
        "peer-open",
        "RS482_RESET_RING_REPLAY_SEMANTICS: runtime or silicon status differs",
    ),
    "reset replay claims failed-reset sibling dependency": (
        "RS482_RESET_RING_REPLAY_SEMANTICS\t",
        5,
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE;FENCE_FORCE_COMPLETION_PUBLICATION",
        "RS482_RESET_RING_REPLAY_SEMANTICS: dependency edge differs",
    ),
    "ring schedule loses dependency": (
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE\t",
        5,
        "RS482_ASIC_COMMAND_CALLBACK_BINDING",
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE: dependency edge differs",
    ),
    "BO reservation depends on post-schedule success": (
        "CS_BO_RESERVATION_LOCKS\t",
        5,
        "CS_SUCCESS_FENCE_INVARIANT",
        "CS_BO_RESERVATION_LOCKS: dependency edge differs",
    ),
    "success fence loses schedule dependency": (
        "CS_SUCCESS_FENCE_INVARIANT\t",
        5,
        "CS_BO_RESERVATION_LOCKS",
        "CS_SUCCESS_FENCE_INVARIANT: dependency edge differs",
    ),
    "fence publication loses success dependency": (
        "CS_RESERVATION_FENCE_PUBLICATION\t",
        5,
        "CS_RING_DEPENDENCY_AND_IB_SCHEDULE",
        "CS_RESERVATION_FENCE_PUBLICATION: dependency edge differs",
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
            except ContractError as exc:
                expected_error = SOURCE_EXPECTED_ERRORS.get(label)
                if expected_error is not None and str(exc) != expected_error:
                    print(
                        f"selftest known-bad wrong error: {label}: {exc}",
                        file=sys.stderr,
                    )
                    failures += 1
                    continue
                suffix = f": {exc}" if expected_error is not None else ""
                print(f"selftest known-bad rejected: {label}{suffix}")
            else:
                print(f"selftest known-bad ACCEPTED: {label}", file=sys.stderr)
                failures += 1

        for label, (
            row_prefix,
            field_index,
            value,
            expected_error,
        ) in POLICY_MUTATIONS.items():
            mutant = Path(directory) / re.sub(r"[^a-z0-9]+", "-", label.lower())
            copy_inputs(root, mutant)
            mutate_policy(mutant / POLICY, row_prefix, field_index, value)
            mutant_digest = hashlib.sha256((mutant / POLICY).read_bytes()).hexdigest()
            try:
                check_tree(mutant, mutant_digest)
            except ContractError as exc:
                if str(exc) != expected_error:
                    print(
                        f"selftest known-bad wrong error: {label}: {exc}",
                        file=sys.stderr,
                    )
                    failures += 1
                    continue
                print(f"selftest known-bad rejected: {label}: {expected_error}")
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
