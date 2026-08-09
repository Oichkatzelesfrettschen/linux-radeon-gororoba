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
    "2ce391228b39edc16ee2dab788366db233989566e9b6b95a37e86d13839b9cc8"
)
GART_DIRECT_PREFIX_SHA256 = {
    "range": "892932bfd330e1d916f282e5822781f97ab1986420156fab8e096e1d65268480",
    "bind": "014e9a8795dd62f5edcf527968a3995faafbf8025aa76f50a09aab3293773da4",
    "unbind": "11eb49c3c9d7d0fe07137251c6bf23915a8788b85b8dad5269b28cf934405454",
}
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
EXPECTED_POLICY_ROW_SHA256 = {
    "GART_SOURCE_BUILD_REACHABILITY": "a8291cf87ea02150c3f311d017daa4f706ff47dd3c9f80f41567d0062817746c",
    "RS400_ASIC_GART_CALLBACK_SELECTION": "aa36363cc508f31487c9187c9bc82923829b8681b3adb663ee0c5d20d5f5f3d0",
    "GTT_APERTURE_SIZE_DERIVATION": "bac1358511e4dd4a634893c8009fb6bfdabddf5637ac1de6b96f6ad49c3e5ea3",
    "GART_TABLE_DMA_COHERENT_ALLOCATION_API": "fe5554c7d3c9043292a04380a3797dba87730f59014ecf89cba99660230f525a",
    "RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT": "ef1b574be4781316d9e96acd0a27087083b1da3122236a62a4d769119f1c22ec",
    "NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION": "231a9985b4ad855f583b1fdeceb4d8e0615a31ddb9095fd7af4a29f0a853890a",
    "TTM_DEFAULT_CACHED_SELECTION": "b54cd9f77cb7788f88646016d2f0c5b9e02d1a70678f3dff3a53f4a9598b5635",
    "USERPTR_TT_EXTERNAL_POPULATION": "63c97a7cbaf5d34a52bcf8011abf38c253ca3e780d6a3975a36ca0623fdf4e6d",
    "USERPTR_PIN_DMA_MAP_TRANSACTION": "0e99c37f9cb1513a83f68bb27079484a007f90af2f654948805dd1bccf9a5b8f",
    "GART_BIND_RANGE_ADMISSION": "2683117c17ea621ca172a45c2c201ad094061472cc11b0f81b15b16bd12ff6b3",
    "CACHED_TTM_SNOOP_FLAG_PROPAGATION": "c123e0a5d5308d4a809b052e8683014a9fe1f6a62f03eb5832007128a7b8bbf4",
    "RS400_PTE_PERMISSION_AND_SNOOP_ENCODING": "1436411df935ae759578308ae6dac371008f24b213c9e09318e004af3c834957",
    "RS480_GLOBAL_REQUEST_SNOOP_DISABLE": "f88f6ceafb3e72c04b9d7ab362f9da597a8ac359c46265c40316d407f01d8749",
    "GART_BIND_PTE_MB_TLB_PUBLICATION": "385882c4679db1391becb4d605691571c8ff8d8f9eef4c7add822947ca90fdea",
    "GART_UNBIND_RANGE_ADMISSION": "06bd449fe0f099c0f93760724c99665ebd697d48efc4a0573540876960996cae",
    "GART_UNBIND_SPARSE_CURSOR": "21c792aef097900553a9bed51ccff3ef8caed8a028ea71d710cd5a9d129327db",
    "GART_UNBIND_PTE_MB_TLB_PUBLICATION": "7f625005eea02702afae58278cef6e15ec1dcb7b510349b1f349c21c10944223",
    "KERNEL_BO_MAP_RESERVATION_WAIT": "6c6d705572d2b742f33214eb46a68bf14bd3ee2c89091277b5957f12cb8bbe85",
    "USER_MMAP_FAULT_RESERVATION": "7ad2fb7a1a775c21ca8c6c953cdc3fa30ba324aba381eec6a08a65a4111d6cbd",
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": "a2e488e9fcadbc320189ce3a92c671f5b602c5d8dda5d229bb975f548ce19957",
    "GART_COMMON_TEARDOWN": "14db30bd36fbb1e69e551a7f1da0f0bd371a06d176075653fc64814ff17f3fdb",
    "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT": "b0d5a1d660763582d833facff6f916aabe7546f0c88564893e1316dadffff5a3",
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": "482c662c714ee41905e0959857c0e73bc62adbe9a6ba278ef6ebc49bee941ab4",
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": "ae570a8117c818684f4ac85e448eea3a2835f31417bb6bee5949f2f413d415a3",
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": "57c8bf7fdc152519466ec2735497c3fc9d3e77ebde7b4eb8bc2838b454c30e27",
    "RS400_TLB_FLUSH_COMPLETION": "76af718d9768d10e3e3f6ac931ac6933b8a02bfa3129ebe34692442772a08c3b",
    "GART_SUSPEND_READY_STATE": "cde207fdd56b63e07f744028234a8c02dbba0e929c15d5db10fcb0483ff09651",
    "GART_BACKEND_NOT_READY_UNBIND_STATE": "5a7df63acc08b641a8a1b2567d36a9c56c5381bece3a51526889aac62f204b9f",
    "GART_TTM_TEARDOWN_OWNERSHIP": "c661cd8f528e66f54c5e14a3b3b7bd3ba6b413034e2b02052526834a207568f1",
}

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
    "GART_COMMON_TEARDOWN": (
        "proven",
        "GART_UNBIND_PTE_MB_TLB_PUBLICATION",
    ),
    "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT": (
        "proven",
        "RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT;GART_COMMON_TEARDOWN",
    ),
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": (
        "open",
        "CACHED_TTM_SNOOP_FLAG_PROPAGATION;RS400_PTE_PERMISSION_AND_SNOOP_ENCODING;RS480_GLOBAL_REQUEST_SNOOP_DISABLE",
    ),
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": (
        "open",
        "GART_BIND_PTE_MB_TLB_PUBLICATION",
    ),
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": (
        "open",
        "GART_BIND_PTE_MB_TLB_PUBLICATION",
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
        "GART_COMMON_TEARDOWN;RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT;GART_BACKEND_NOT_READY_UNBIND_STATE",
    ),
}

EXPECTED_EXTERNAL = {
    "GTT_APERTURE_SIZE_DERIVATION": (
        "vostro1000-re",
        "0e5141a454c9453382059eea5d0062e79451de13",
        "systems/dell-vostro-1000/platform-maximal-decomposition-frontier.tsv",
        "uma-gart-cacheability-graph",
    ),
    "GART_TABLE_DMA_COHERENT_ALLOCATION_API": (
        "vostro1000-re",
        "0e5141a454c9453382059eea5d0062e79451de13",
        "systems/dell-vostro-1000/platform-maximal-decomposition-frontier.tsv",
        "gart-page-table-readonly-provenance",
    ),
    "NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "GTT_WC_NON_PCIE_UNREACHABLE",
    ),
    "CACHED_TTM_SNOOP_FLAG_PROPAGATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "RS400_PTE_PERMISSION_AND_SNOOP_ENCODING": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "RS480_GLOBAL_REQUEST_SNOOP_DISABLE": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "GLOBAL_GART_SNOOP_INVALID",
    ),
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": (
        "vostro1000-re",
        "0e5141a454c9453382059eea5d0062e79451de13",
        "systems/dell-vostro-1000/platform-maximal-decomposition-frontier.tsv",
        "gart-page-table-readonly-provenance",
    ),
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "CPU_GTT_GPU_PUBLICATION",
    ),
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": (
        "steinmarder-r300",
        "dfd54caf26cc94f157cd231e0741cc16887ec595",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "GPU_GTT_CPU_INVALIDATION",
    ),
}

EXPECTED_NONCLAIMS = {
    "GART_SOURCE_BUILD_REACHABILITY": "Build reachability does not prove a live RS482 path.",
    "RS400_ASIC_GART_CALLBACK_SELECTION": "Source selection does not prove live PCI identity or callback execution.",
    "GTT_APERTURE_SIZE_DERIVATION": "The source formula does not establish one timeless aperture size.",
    "GART_TABLE_DMA_COHERENT_ALLOCATION_API": "dma_alloc_coherent is allocation API terminology, not a payload coherence verdict.",
    "RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT": "The call does not prove that the CPU alias became UC.",
    "NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION": "The source rule does not prove the effective CPU type of every mapping.",
    "TTM_DEFAULT_CACHED_SELECTION": "ttm_cached does not prove CPU to GPU coherence.",
    "USERPTR_TT_EXTERNAL_POPULATION": "Population alone does not establish a DMA mapping.",
    "USERPTR_PIN_DMA_MAP_TRANSACTION": "A correct lifetime does not prove payload visibility or make userptr a preferred Mesa ABI.",
    "GART_BIND_RANGE_ADMISSION": "Range validation does not validate payload bytes or cache state.",
    "CACHED_TTM_SNOOP_FLAG_PROPAGATION": "The request does not prove that the RS482 transaction is snooped.",
    "RS400_PTE_PERMISSION_AND_SNOOP_ENCODING": "Encoded bits do not prove global and per PTE precedence.",
    "RS480_GLOBAL_REQUEST_SNOOP_DISABLE": "Linux source does not independently prove the external silicon result.",
    "GART_BIND_PTE_MB_TLB_PUBLICATION": "mb and a dispatched flush do not prove payload publication or completed invalidation.",
    "GART_UNBIND_RANGE_ADMISSION": "The void return still does not communicate a not ready disposition to TTM.",
    "GART_UNBIND_SPARSE_CURSOR": "The repair does not prove a live TLB invalidation.",
    "GART_UNBIND_PTE_MB_TLB_PUBLICATION": "Source order does not prove that the GPU stopped using a stale translation.",
    "KERNEL_BO_MAP_RESERVATION_WAIT": "Fence retirement does not invalidate or flush payload cache lines.",
    "USER_MMAP_FAULT_RESERVATION": "A successful page fault does not prove a later GPU read sees CPU writes.",
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": "A bounded table dump does not characterize unobserved PTEs or payload visibility.",
    "GART_COMMON_TEARDOWN": "Common teardown does not prove every TTM callback observed one hardware enabled state.",
    "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT": "The call does not prove that the CPU alias returned to WB.",
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": "The encoded PTE and global register do not establish effective snooping.",
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": "A directional visibility result does not prove snoop attribution or general cache coherence.",
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": "A directional visibility result does not prove snoop attribution or general cache coherence.",
    "RS400_TLB_FLUSH_COMPLETION": "A returned void call does not prove TLB invalidation completed.",
    "GART_SUSPEND_READY_STATE": "gart.ready true does not always prove hardware translation is enabled.",
    "GART_BACKEND_NOT_READY_UNBIND_STATE": "The source does not prove bound changes only after hardware and shadow disposition.",
    "GART_TTM_TEARDOWN_OWNERSHIP": "A second idempotent call does not prove complete callback ordering.",
}

EXPECTED_COMPLETION_GATES = {
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": (
        "An admitted exact target CPU write and GPU read trial retains raw PTE "
        "bytes and decoded bits, raw global snoop control, BO and cache mapping, "
        "module and target identity, command stream, an observed completed fence, "
        "maintenance on and off arms, and both digests; it closes exact state "
        "visibility only. Maintenance off failing while maintenance on passes "
        "supports maintenance-required visibility only for the exact retained "
        "state. Both arms passing supports only that no maintenance effect was "
        "observed in the tested trials. Both arms failing leaves visibility open."
    ),
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": (
        "An admitted exact target GPU write and CPU read trial retains raw PTE "
        "bytes and decoded bits, raw global snoop control, BO and cache mapping, "
        "module and target identity, command stream, an observed completed fence, "
        "maintenance on and off arms, and both digests; it closes exact state "
        "visibility only. Maintenance off failing while maintenance on passes "
        "supports maintenance-required visibility only for the exact retained "
        "state. Both arms passing supports only that no maintenance effect was "
        "observed in the tested trials. Both arms failing leaves visibility open."
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


_C_TOKEN = re.compile(
    r"(?P<block_comment>/\*.*?\*/)"
    r"|(?P<line_comment>//[^\n]*)"
    r'|(?P<string>"(?:\\.|[^"\\])*")'
    r"|(?P<character>'(?:\\.|[^'\\])*')"
    r"|(?P<identifier>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<number>0[xX][0-9A-Fa-f]+|[0-9]+)"
    r"|(?P<operator>->|<=|>=|==|!=|&&|\|\||<<|>>|\+\+|--)"
    r"|(?P<punctuation>[^\s])",
    re.DOTALL,
)


def c_tokens(source_text: str) -> tuple[str, ...]:
    """Return C lexical tokens while ignoring formatting."""

    return tuple(
        match.group(0)
        for match in _C_TOKEN.finditer(source_text)
        if match.lastgroup not in {"block_comment", "line_comment"}
    )


def matching_token(
    tokens: tuple[str, ...], start: int, opening: str, closing: str
) -> int:
    """Return the closing token index for one balanced token group."""

    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == opening:
            depth += 1
        elif tokens[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    raise LifecycleError(f"unbalanced {opening}{closing} token group")


def if_statement_body(tokens: tuple[str, ...], condition_end: int) -> tuple[str, ...]:
    """Return the tokens governed by an if condition."""

    statement_start = condition_end + 1
    if statement_start >= len(tokens):
        raise LifecycleError("if condition has no statement")
    if tokens[statement_start] == "{":
        statement_end = matching_token(tokens, statement_start, "{", "}")
        return tokens[statement_start + 1 : statement_end]

    paren_depth = 0
    bracket_depth = 0
    for index in range(statement_start, len(tokens)):
        token = tokens[index]
        if token == "(":
            paren_depth += 1
        elif token == ")":
            paren_depth -= 1
        elif token == "[":
            bracket_depth += 1
        elif token == "]":
            bracket_depth -= 1
        elif token == ";" and paren_depth == 0 and bracket_depth == 0:
            return tokens[statement_start : index + 1]
    raise LifecycleError("if statement has no terminating semicolon")


def c_statement_end(tokens: tuple[str, ...], start: int) -> int:
    """Return the exclusive end of one C statement."""

    if start >= len(tokens):
        raise LifecycleError("C statement starts beyond the token stream")
    token = tokens[start]
    if start + 1 < len(tokens) and tokens[start + 1] == ":":
        return c_statement_end(tokens, start + 2)
    if token == "{":
        return matching_token(tokens, start, "{", "}") + 1
    if token == "if":
        if start + 1 >= len(tokens) or tokens[start + 1] != "(":
            raise LifecycleError("if statement has no condition")
        condition_end = matching_token(tokens, start + 1, "(", ")")
        controlled_end = c_statement_end(tokens, condition_end + 1)
        if controlled_end < len(tokens) and tokens[controlled_end] == "else":
            return c_statement_end(tokens, controlled_end + 1)
        return controlled_end
    if token in {"for", "while", "switch"}:
        if start + 1 >= len(tokens) or tokens[start + 1] != "(":
            raise LifecycleError(f"{token} statement has no condition")
        condition_end = matching_token(tokens, start + 1, "(", ")")
        return c_statement_end(tokens, condition_end + 1)
    if token == "do":
        controlled_end = c_statement_end(tokens, start + 1)
        if controlled_end >= len(tokens) or tokens[controlled_end] != "while":
            raise LifecycleError("do statement has no trailing while")
        condition_start = controlled_end + 1
        if condition_start >= len(tokens) or tokens[condition_start] != "(":
            raise LifecycleError("do while statement has no condition")
        condition_end = matching_token(tokens, condition_start, "(", ")")
        if condition_end + 1 >= len(tokens) or tokens[condition_end + 1] != ";":
            raise LifecycleError("do while statement has no terminating semicolon")
        return condition_end + 2

    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    for index in range(start, len(tokens)):
        current = tokens[index]
        if current == "(":
            paren_depth += 1
        elif current == ")":
            paren_depth -= 1
        elif current == "[":
            bracket_depth += 1
        elif current == "]":
            bracket_depth -= 1
        elif current == "{":
            brace_depth += 1
        elif current == "}":
            if brace_depth == 0:
                raise LifecycleError("C statement reaches its containing brace")
            brace_depth -= 1
        elif (
            current == ";"
            and paren_depth == 0
            and bracket_depth == 0
            and brace_depth == 0
        ):
            return index + 1
    raise LifecycleError("C statement has no terminating semicolon")


def direct_function_statements(
    tokens: tuple[str, ...],
) -> tuple[tuple[int, int], ...]:
    """Return spans for statements with no controlling ancestor."""

    try:
        body_start = tokens.index("{")
    except ValueError as exc:
        raise LifecycleError("function has no body") from exc
    body_end = matching_token(tokens, body_start, "{", "}")
    statements: list[tuple[int, int]] = []
    cursor = body_start + 1
    while cursor < body_end:
        statement_end = c_statement_end(tokens, cursor)
        statements.append((cursor, statement_end))
        cursor = statement_end
    if cursor != body_end:
        raise LifecycleError("function statement parsing crossed its body")
    return tuple(statements)


def require_direct_statement(
    label: str,
    statements: tuple[tuple[str, ...], ...],
    statement_index: int,
    expected: str,
    *,
    prefix: bool = False,
) -> None:
    """Require an exact direct statement or an exact prefix at one index."""

    if statement_index < 0 or statement_index >= len(statements):
        raise LifecycleError(f"{label}: direct statement index is absent")
    actual_tokens = statements[statement_index]
    expected_tokens = c_tokens(expected)
    matches = (
        actual_tokens[: len(expected_tokens)] == expected_tokens
        if prefix
        else actual_tokens == expected_tokens
    )
    if not matches:
        match_kind = "prefix" if prefix else "identity"
        raise LifecycleError(f"{label}: direct statement {match_kind} differs")


def direct_statement_prefix_sha256(
    statements: tuple[tuple[str, ...], ...], through_index: int
) -> str:
    """Return a length-framed digest of direct statements through one index."""

    if through_index < 0 or through_index >= len(statements):
        raise LifecycleError("direct statement prefix end is absent")
    digest = hashlib.sha256()
    for statement in statements[: through_index + 1]:
        digest.update(len(statement).to_bytes(4, "big"))
        for token in statement:
            token_bytes = token.encode("ascii")
            digest.update(len(token_bytes).to_bytes(4, "big"))
            digest.update(token_bytes)
    return digest.hexdigest()


def require_direct_statement_prefix_sha256(
    label: str,
    statements: tuple[tuple[str, ...], ...],
    through_index: int,
    expected_sha256: str,
) -> None:
    """Require an exact token digest for a direct function-body prefix."""

    actual_sha256 = direct_statement_prefix_sha256(statements, through_index)
    if actual_sha256 != expected_sha256:
        raise LifecycleError(f"{label}: exact direct statement prefix differs")


def require_exact_direct_statements(
    label: str, body: str, expected_statements: tuple[str, ...]
) -> None:
    """Require the exact ordered direct statement sequence of one function."""

    if re.search(r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b", body):
        raise LifecycleError(f"{label}: preprocessor conditional is not admitted")
    tokens = c_tokens(body)
    spans = direct_function_statements(tokens)
    actual = tuple(tokens[start:end] for start, end in spans)
    expected = tuple(c_tokens(statement) for statement in expected_statements)
    if len(actual) != len(expected):
        raise LifecycleError(
            f"{label}: direct statement count {len(actual)} != {len(expected)}"
        )
    for statement_index, (actual_statement, expected_statement) in enumerate(
        zip(actual, expected, strict=True)
    ):
        if actual_statement != expected_statement:
            raise LifecycleError(f"{label}: direct statement {statement_index} differs")


def has_final_top_level_statement(
    tokens: tuple[str, ...], expected: tuple[str, ...]
) -> bool:
    """Return whether the final top-level statement is the expected action."""

    statement_start = 0
    brace_depth = 0
    paren_depth = 0
    bracket_depth = 0
    for index, token in enumerate(tokens):
        if token == "{":
            brace_depth += 1
        elif token == "}":
            brace_depth -= 1
        elif token == "(":
            paren_depth += 1
        elif token == ")":
            paren_depth -= 1
        elif token == "[":
            bracket_depth += 1
        elif token == "]":
            bracket_depth -= 1
        elif (
            token == ";"
            and brace_depth == 0
            and paren_depth == 0
            and bracket_depth == 0
            and index + 1 < len(tokens)
        ):
            statement_start = index + 1
    return tokens[statement_start:] == expected


def require_exact_if_guard(
    label: str,
    body: str,
    condition: str,
    guarded_action: str,
    expected_statement_index: int,
    expected_guard_body: str | None = None,
) -> tuple[tuple[tuple[str, ...], ...], int]:
    """Require one exact direct if guard at its fixed function-body index."""

    if re.search(r"(?m)^\s*#\s*(?:if|ifdef|ifndef|elif|else|endif)\b", body):
        raise LifecycleError(f"{label}: preprocessor conditional is not admitted")
    tokens = c_tokens(body)
    direct_statement_spans = direct_function_statements(tokens)
    direct_statement_indexes = {
        statement_start: statement_index
        for statement_index, (statement_start, _) in enumerate(direct_statement_spans)
    }
    direct_statements = tuple(
        tokens[statement_start:statement_end]
        for statement_start, statement_end in direct_statement_spans
    )
    expected_condition = c_tokens(condition)
    expected_action = c_tokens(guarded_action)
    matching_guards: list[tuple[tuple[str, ...], int]] = []
    for index, token in enumerate(tokens[:-1]):
        if token != "if" or tokens[index + 1] != "(":
            continue
        condition_end = matching_token(tokens, index + 1, "(", ")")
        actual_condition = tokens[index + 2 : condition_end]
        if actual_condition == expected_condition and index in direct_statement_indexes:
            matching_guards.append(
                (
                    if_statement_body(tokens, condition_end),
                    direct_statement_indexes[index],
                )
            )

    if len(matching_guards) != 1:
        raise LifecycleError(
            f"{label}: exact condition match count is {len(matching_guards)}"
        )
    guard_body, statement_index = matching_guards[0]
    if not has_final_top_level_statement(guard_body, expected_action):
        raise LifecycleError(
            f"{label}: guarded action is not the final top-level statement"
        )
    if expected_guard_body is not None and guard_body != c_tokens(expected_guard_body):
        raise LifecycleError(f"{label}: exact guard body differs")
    if statement_index != expected_statement_index:
        raise LifecycleError(
            f"{label}: direct statement index {statement_index} != "
            f"{expected_statement_index}"
        )
    return direct_statements, statement_index


def check_direct_statement_parser_calibration() -> None:
    """Calibrate direct statement count, order, and guard location."""

    calibration = (
        "static int guard_calibration(int value) {"
        "int result;"
        "if (value) return -EINVAL;"
        "return 0;"
        "}"
    )
    statements, guard_index = require_exact_if_guard(
        "direct statement parser calibration guard differs",
        calibration,
        "value",
        "return -EINVAL;",
        1,
        "return -EINVAL;",
    )
    expected_statements = tuple(
        c_tokens(statement)
        for statement in (
            "int result;",
            "if (value) return -EINVAL;",
            "return 0;",
        )
    )
    if statements != expected_statements or guard_index != 1:
        raise LifecycleError("direct statement parser calibration sequence differs")


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


def read_policy(
    root: Path, expected_policy_sha256: str = EXPECTED_POLICY_SHA256
) -> dict[str, dict[str, str]]:
    path = root / POLICY
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise LifecycleError(f"missing policy table {path}") from exc
    if not raw.isascii() or b"\r" in raw:
        raise LifecycleError("policy table must be LF terminated ASCII")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_policy_sha256:
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
    if tuple(rows) != tuple(EXPECTED_ROWS):
        raise LifecycleError("policy row order differs from the causal order")
    return rows


def policy_row_identity_sha256(row: dict[str, str]) -> str:
    """Return the exact length-framed identity of every field after row_id."""

    digest = hashlib.sha256()
    for field in HEADER[1:]:
        value = row[field].encode("ascii")
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()


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
            row["external_artifact"],
            row["external_row_id"],
        )
        if expected is None:
            if fields != ("NONE", "NONE", "NONE", "NONE"):
                raise LifecycleError(f"{row_id}: unexpected external authority")
            continue
        if fields != expected:
            raise LifecycleError(f"{row_id}: external authority identity differs")
        if not re.fullmatch(r"[0-9a-f]{40}", row["external_commit"]):
            raise LifecycleError(f"{row_id}: external commit is not a full object ID")


def check_nonclaims(rows: dict[str, dict[str, str]]) -> None:
    if set(EXPECTED_NONCLAIMS) != set(rows):
        raise LifecycleError("nonclaim binding denominator differs")
    for row_id, expected_nonclaim in EXPECTED_NONCLAIMS.items():
        if rows[row_id]["nonclaim"] != expected_nonclaim:
            raise LifecycleError(f"{row_id}: nonclaim identity differs")


def check_completion_gates(rows: dict[str, dict[str, str]]) -> None:
    for row_id, expected_gate in EXPECTED_COMPLETION_GATES.items():
        if rows[row_id]["completion_gate"] != expected_gate:
            raise LifecycleError(f"{row_id}: completion gate identity differs")


def check_policy_row_identities(rows: dict[str, dict[str, str]]) -> None:
    """Bind all eighteen semantic fields after specific validators run."""

    if set(EXPECTED_POLICY_ROW_SHA256) != set(rows):
        raise LifecycleError("policy row identity denominator differs")
    for row_id, row in rows.items():
        if policy_row_identity_sha256(row) != EXPECTED_POLICY_ROW_SHA256[row_id]:
            raise LifecycleError(f"{row_id}: exact policy row identity differs")


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
    range_statements, range_guard_index = require_exact_if_guard(
        "GART page count and alignment admission guard differs",
        range_valid,
        "pages <= 0 || offset & ~PAGE_MASK",
        "return false;",
        1,
        "return false;",
    )
    require_direct_statement_prefix_sha256(
        "GART range admission dominance",
        range_statements,
        4,
        GART_DIRECT_PREFIX_SHA256["range"],
    )
    require_direct_statement(
        "GART range guard predecessor differs",
        range_statements,
        range_guard_index - 1,
        "unsigned int start;",
    )
    require_direct_statement(
        "GART range guard successor differs",
        range_statements,
        range_guard_index + 1,
        "if ((unsigned int)pages > rdev->gart.num_cpu_pages) return false;",
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
    bind_statements, bind_guard_index = require_exact_if_guard(
        "GART bind DMA and range admission guard differs",
        bind,
        "!dma_addr || !radeon_gart_range_valid(rdev, offset, pages)",
        "return -EINVAL;",
        4,
        (
            'WARN(1, "invalid GART bind range offset %u pages %d\\n", '
            "offset, pages);"
            "return -EINVAL;"
        ),
    )
    require_direct_statement_prefix_sha256(
        "GART bind admission dominance",
        bind_statements,
        6,
        GART_DIRECT_PREFIX_SHA256["bind"],
    )
    require_direct_statement(
        "GART bind guard predecessor differs",
        bind_statements,
        bind_guard_index - 1,
        (
            "if (!rdev->gart.ready) {"
            'WARN(1, "trying to bind memory to uninitialized GART !\\n");'
            "return -EINVAL;"
            "}"
        ),
    )
    require_direct_statement(
        "GART bind guard successor differs",
        bind_statements,
        bind_guard_index + 1,
        "t = offset / RADEON_GPU_PAGE_SIZE;",
    )
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
    unbind_statements, unbind_guard_index = require_exact_if_guard(
        "GART unbind range admission guard differs",
        unbind,
        "!radeon_gart_range_valid(rdev, offset, pages)",
        "return;",
        3,
        (
            'WARN(1, "invalid GART unbind range offset %u pages %d\\n", '
            "offset, pages);"
            "return;"
        ),
    )
    require_direct_statement_prefix_sha256(
        "GART unbind admission dominance",
        unbind_statements,
        5,
        GART_DIRECT_PREFIX_SHA256["unbind"],
    )
    require_direct_statement(
        "GART unbind guard predecessor differs",
        unbind_statements,
        unbind_guard_index - 1,
        (
            "if (!rdev->gart.ready) {"
            'WARN(1, "trying to unbind memory from uninitialized GART !\\n");'
            "return;"
            "}"
        ),
    )
    require_direct_statement(
        "GART unbind guard successor differs",
        unbind_statements,
        unbind_guard_index + 1,
        "t = offset / RADEON_GPU_PAGE_SIZE;",
    )
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
    require_exact_direct_statements(
        "GART finalization direct teardown sequence",
        fini,
        (
            "radeon_rs4xx_dev_gart_lock();",
            "radeon_gart_fini(rdev);",
            "rs400_gart_disable(rdev);",
            "radeon_gart_table_ram_free(rdev);",
            "radeon_rs4xx_dev_gart_unlock();",
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


def check_tree(
    root: Path, expected_policy_sha256: str = EXPECTED_POLICY_SHA256
) -> None:
    rows = read_policy(root, expected_policy_sha256)
    check_dependencies(rows)
    check_external(rows)
    check_nonclaims(rows)
    check_completion_gates(rows)
    check_policy_row_identities(rows)
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
    "range page guard is disabled": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;",
        ("if (false && (pages <= 0 || offset & ~PAGE_MASK))\n\t\treturn false;"),
    ),
    "range page guard is negated": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;",
        "if (!(pages <= 0 || offset & ~PAGE_MASK))\n\t\treturn false;",
    ),
    "range page guard survives only in a comment": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;",
        (
            "/* if (pages <= 0 || offset & ~PAGE_MASK)\n"
            " *     return false; */\n"
            "\tif (false)\n\t\treturn false;"
        ),
    ),
    "range page guard is inside an inactive preprocessor branch": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;",
        ("#if 0\n\tif (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;\n#endif"),
    ),
    "range page guard action is nested under false": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;",
        (
            "if (pages <= 0 || offset & ~PAGE_MASK) {\n"
            "\t\tif (false)\n\t\t\treturn false;\n\t}"
        ),
    ),
    "range page guard is inside an outer disabled block": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;",
        (
            "if (false) {\n"
            "\t\tif (pages <= 0 || offset & ~PAGE_MASK)\n"
            "\t\t\treturn false;\n\t}"
        ),
    ),
    "range page guard is inside an outer disabled statement": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (pages <= 0 || offset & ~PAGE_MASK)\n\t\treturn false;",
        ("if (false)\n\t\tif (pages <= 0 || offset & ~PAGE_MASK)\n\t\t\treturn false;"),
    ),
    "range page guard is bypassed by an earlier return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        ("\tunsigned int start;\n\n\tif (pages <= 0 || offset & ~PAGE_MASK)"),
        (
            "\tunsigned int start;\n\n"
            "\treturn true;\n"
            "\tif (pages <= 0 || offset & ~PAGE_MASK)"
        ),
    ),
    "range declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tunsigned int start;\n\n",
        "\tunsigned int start = ({ return true; 0; });\n\n",
    ),
    "bind skips DMA array admission": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "!dma_addr || !radeon_gart_range_valid",
        "!radeon_gart_range_valid",
    ),
    "bind DMA and range guard is disabled": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (!dma_addr || !radeon_gart_range_valid(rdev, offset, pages)) {",
        (
            "if (false && "
            "(!dma_addr || !radeon_gart_range_valid(rdev, offset, pages))) {"
        ),
    ),
    "bind DMA and range guard is negated": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (!dma_addr || !radeon_gart_range_valid(rdev, offset, pages)) {",
        "if (!(!dma_addr || !radeon_gart_range_valid(rdev, offset, pages))) {",
    ),
    "bind DMA and range guard is inside an outer disabled block": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        (
            "\tif (!dma_addr || !radeon_gart_range_valid(rdev, offset, pages)) {\n"
            '\t\tWARN(1, "invalid GART bind range offset %u pages %d\\n",\n'
            "\t\t     offset, pages);\n"
            "\t\treturn -EINVAL;\n"
            "\t}"
        ),
        (
            "\tif (false) {\n"
            "\t\tif (!dma_addr || "
            "!radeon_gart_range_valid(rdev, offset, pages)) {\n"
            '\t\t\tWARN(1, "invalid GART bind range offset %u pages %d\\n",\n'
            "\t\t\t     offset, pages);\n"
            "\t\t\treturn -EINVAL;\n"
            "\t\t}\n"
            "\t}"
        ),
    ),
    "bind DMA and range guard is bypassed by an earlier return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tif (!dma_addr || !radeon_gart_range_valid(rdev, offset, pages)) {",
        (
            "\treturn 0;\n"
            "\tif (!dma_addr || !radeon_gart_range_valid(rdev, offset, pages)) {"
        ),
    ),
    "bind declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tuint64_t page_base, page_entry;\n\tint i, j;\n",
        ("\tuint64_t page_base, page_entry;\n\tint i = ({ return 0; 0; }), j;\n"),
    ),
    "unbind range guard is disabled": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (!radeon_gart_range_valid(rdev, offset, pages)) {",
        "if (false && !radeon_gart_range_valid(rdev, offset, pages)) {",
    ),
    "unbind range guard is negated": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "if (!radeon_gart_range_valid(rdev, offset, pages)) {",
        "if (radeon_gart_range_valid(rdev, offset, pages)) {",
    ),
    "unbind range guard is inside an outer disabled block": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        (
            "\tif (!radeon_gart_range_valid(rdev, offset, pages)) {\n"
            '\t\tWARN(1, "invalid GART unbind range offset %u pages %d\\n",\n'
            "\t\t     offset, pages);\n"
            "\t\treturn;\n"
            "\t}"
        ),
        (
            "\tif (false) {\n"
            "\t\tif (!radeon_gart_range_valid(rdev, offset, pages)) {\n"
            '\t\t\tWARN(1, "invalid GART unbind range offset %u pages %d\\n",\n'
            "\t\t\t     offset, pages);\n"
            "\t\t\treturn;\n"
            "\t\t}\n"
            "\t}"
        ),
    ),
    "unbind range guard is bypassed by an earlier return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tif (!radeon_gart_range_valid(rdev, offset, pages)) {",
        ("\treturn;\n\tif (!radeon_gart_range_valid(rdev, offset, pages)) {"),
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
    "RS400 finalization hardware disable is conditionally disabled": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tradeon_gart_fini(rdev);\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        (
            "\tradeon_gart_fini(rdev);\n"
            "\tif (false)\n"
            "\t\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
    ),
    "unbind declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tunsigned int t, p;\n\tint i, j;\n\n",
        ("\tunsigned int t, p;\n\tint i = ({ return; 0; }), j;\n\n"),
    ),
    "RS400 finalization hardware disable is nested in a scope": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tradeon_gart_fini(rdev);\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        (
            "\tradeon_gart_fini(rdev);\n"
            "\t{\n"
            "\t\trs400_gart_disable(rdev);\n"
            "\t}\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
    ),
    "RS400 finalization drops hardware disable": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tradeon_gart_fini(rdev);\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        "\tradeon_gart_fini(rdev);\n\tradeon_gart_table_ram_free(rdev);",
    ),
    "RS400 finalization releases table before hardware disable": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tradeon_gart_fini(rdev);\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        (
            "\tradeon_gart_fini(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);\n"
            "\trs400_gart_disable(rdev);"
        ),
    ),
}

SOURCE_EXPECTED_ERRORS = {
    "range accepts zero pages": (
        "GART page count and alignment admission guard differs: "
        "exact condition match count is 0"
    ),
    "range page guard is disabled": (
        "GART page count and alignment admission guard differs: "
        "exact condition match count is 0"
    ),
    "range page guard is negated": (
        "GART page count and alignment admission guard differs: "
        "exact condition match count is 0"
    ),
    "range page guard survives only in a comment": (
        "GART page count and alignment admission guard differs: "
        "exact condition match count is 0"
    ),
    "range page guard is inside an inactive preprocessor branch": (
        "GART page count and alignment admission guard differs: "
        "preprocessor conditional is not admitted"
    ),
    "range page guard action is nested under false": (
        "GART page count and alignment admission guard differs: "
        "guarded action is not the final top-level statement"
    ),
    "range page guard is inside an outer disabled block": (
        "GART page count and alignment admission guard differs: "
        "exact condition match count is 0"
    ),
    "range page guard is inside an outer disabled statement": (
        "GART page count and alignment admission guard differs: "
        "exact condition match count is 0"
    ),
    "range page guard is bypassed by an earlier return": (
        "GART page count and alignment admission guard differs: "
        "direct statement index 2 != 1"
    ),
    "range declaration hides a statement-expression return": (
        "GART range admission dominance: exact direct statement prefix differs"
    ),
    "bind skips DMA array admission": (
        "GART bind DMA and range admission guard differs: "
        "exact condition match count is 0"
    ),
    "bind DMA and range guard is disabled": (
        "GART bind DMA and range admission guard differs: "
        "exact condition match count is 0"
    ),
    "bind DMA and range guard is negated": (
        "GART bind DMA and range admission guard differs: "
        "exact condition match count is 0"
    ),
    "bind DMA and range guard is inside an outer disabled block": (
        "GART bind DMA and range admission guard differs: "
        "exact condition match count is 0"
    ),
    "bind DMA and range guard is bypassed by an earlier return": (
        "GART bind DMA and range admission guard differs: direct statement index 5 != 4"
    ),
    "bind declaration hides a statement-expression return": (
        "GART bind admission dominance: exact direct statement prefix differs"
    ),
    "unbind range guard is disabled": (
        "GART unbind range admission guard differs: exact condition match count is 0"
    ),
    "unbind range guard is negated": (
        "GART unbind range admission guard differs: exact condition match count is 0"
    ),
    "unbind range guard is inside an outer disabled block": (
        "GART unbind range admission guard differs: exact condition match count is 0"
    ),
    "unbind range guard is bypassed by an earlier return": (
        "GART unbind range admission guard differs: direct statement index 4 != 3"
    ),
    "unbind declaration hides a statement-expression return": (
        "GART unbind admission dominance: exact direct statement prefix differs"
    ),
    "RS400 finalization hardware disable is conditionally disabled": (
        "GART finalization direct teardown sequence: direct statement 2 differs"
    ),
    "RS400 finalization hardware disable is nested in a scope": (
        "GART finalization direct teardown sequence: direct statement 2 differs"
    ),
    "RS400 finalization drops hardware disable": (
        "GART finalization direct teardown sequence: direct statement count 4 != 5"
    ),
    "RS400 finalization releases table before hardware disable": (
        "GART finalization direct teardown sequence: direct statement 2 differs"
    ),
}

POLICY_MUTATIONS = {
    "repaired userptr row promoted to proven": (
        "USERPTR_PIN_DMA_MAP_TRANSACTION\t",
        6,
        "proven",
        "USERPTR_PIN_DMA_MAP_TRANSACTION: source_status proven != repaired",
    ),
    "open payload row promoted to proven": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        6,
        "proven",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: source_status proven != open",
    ),
    "payload source relation fabricates target proof": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        7,
        "Target execution proves coherent CPU to GPU payload publication.",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: exact policy row identity differs",
    ),
    "payload runtime fabricates target observation": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        10,
        "peer-observation",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: exact policy row identity differs",
    ),
    "payload Mesa effect fabricates cache permission": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        17,
        "Mesa may omit CPU cache maintenance for cached GTT payloads.",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: exact policy row identity differs",
    ),
    "external commit loses identity": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        13,
        "0" * 40,
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: external authority identity differs",
    ),
    "external artifact identity changed": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        14,
        "src/re/r300/corpora/incorrect.jsonl",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: external authority identity differs",
    ),
    "external row identity changed": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        15,
        "GPU_GTT_CPU_INVALIDATION",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: external authority identity differs",
    ),
    "sparse cursor loses range dependency": (
        "GART_UNBIND_SPARSE_CURSOR\t",
        5,
        "GTT_APERTURE_SIZE_DERIVATION",
        "GART_UNBIND_SPARSE_CURSOR: dependency edge differs",
    ),
    "CPU payload direction claims snoop semantics as a prerequisite": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        5,
        "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS;GART_BIND_PTE_MB_TLB_PUBLICATION",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: dependency edge differs",
    ),
    "GPU payload direction claims unbind as a prerequisite": (
        "GPU_GTT_CPU_PAYLOAD_INVALIDATION\t",
        5,
        "GART_UNBIND_PTE_MB_TLB_PUBLICATION",
        "GPU_GTT_CPU_PAYLOAD_INVALIDATION: dependency edge differs",
    ),
    "common teardown claims WB as a prerequisite": (
        "GART_COMMON_TEARDOWN\t",
        5,
        "GART_UNBIND_PTE_MB_TLB_PUBLICATION;RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT",
        "GART_COMMON_TEARDOWN: dependency edge differs",
    ),
    "WB restore loses common teardown dependency": (
        "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT\t",
        5,
        "RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT",
        "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT: dependency edge differs",
    ),
    "TTM teardown loses table release owner": (
        "GART_TTM_TEARDOWN_OWNERSHIP\t",
        5,
        "GART_COMMON_TEARDOWN;GART_BACKEND_NOT_READY_UNBIND_STATE",
        "GART_TTM_TEARDOWN_OWNERSHIP: dependency edge differs",
    ),
    "payload nonclaim polarity is inverted": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        18,
        "The source proves CPU payload visibility.",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: nonclaim identity differs",
    ),
    "CPU payload arm interpretation promotes both-pass snooping": (
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION\t",
        16,
        "Both maintenance arms passing proves coherent snooping.",
        "CPU_GTT_GPU_PAYLOAD_PUBLICATION: completion gate identity differs",
    ),
    "GPU payload arm interpretation promotes both-fail closure": (
        "GPU_GTT_CPU_PAYLOAD_INVALIDATION\t",
        16,
        "Both maintenance arms failing closes visibility as unsupported.",
        "GPU_GTT_CPU_PAYLOAD_INVALIDATION: completion gate identity differs",
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
    try:
        check_direct_statement_parser_calibration()
    except LifecycleError as exc:
        print(f"selftest parser calibration REJECTED: {exc}", file=sys.stderr)
        return 1
    print("selftest parser calibration accepted: 3 direct statements")
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
            except LifecycleError as exc:
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
            except LifecycleError as exc:
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
