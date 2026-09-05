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
import tomllib
from pathlib import Path

import check_rs4xx_gart_cache_policy as cache_policy

POLICY = Path("policy/rs4xx-gart-memory-path.tsv")
TTM_AUTHORITY = Path("policy/rs4xx-ttm-retention-authority.toml")
UPSTREAM_BASE = Path("UPSTREAM_BASE.toml")
SUBTREE = Path("drivers/gpu/drm/radeon")
EXPECTED_POLICY_SHA256 = (
    "62f117eef7de9e84e2d80871f70d0d976f907a9198ece8e9275cd95978e2762e"
)
EXPECTED_TTM_AUTHORITY_SHA256 = (
    "d49d884ec32024abaa044ec3abb4015244b00975d681e077cc39214a0c78096a"
)
GART_DIRECT_PREFIX_SHA256 = {
    "range": "892932bfd330e1d916f282e5822781f97ab1986420156fab8e096e1d65268480",
    "bind": "014e9a8795dd62f5edcf527968a3995faafbf8025aa76f50a09aab3293773da4",
    "unbind": "64d023defc1d5864f949266af510b052a78233b91c664d05e12676a4e2ff17cd",
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
    "GART_SOURCE_BUILD_REACHABILITY": "8f4e40754231c1fd36f342d288b78248197f044aa75dfab5d5432864a45a331c",
    "RS400_ASIC_GART_CALLBACK_SELECTION": "aa36363cc508f31487c9187c9bc82923829b8681b3adb663ee0c5d20d5f5f3d0",
    "GTT_APERTURE_SIZE_DERIVATION": "bac1358511e4dd4a634893c8009fb6bfdabddf5637ac1de6b96f6ad49c3e5ea3",
    "GART_TABLE_DMA_COHERENT_ALLOCATION_API": "fe5554c7d3c9043292a04380a3797dba87730f59014ecf89cba99660230f525a",
    "RS4XX_GART_TABLE_UC_ALIAS_ATTEMPT": "ef1b574be4781316d9e96acd0a27087083b1da3122236a62a4d769119f1c22ec",
    "NON_PCIE_GTT_ATTRIBUTE_NORMALIZATION": "932dd0b7050ac2fa81ef22a7f421a91aaf0503a341408130594eb4e3eabb13c4",
    "TTM_DEFAULT_CACHED_SELECTION": "b54cd9f77cb7788f88646016d2f0c5b9e02d1a70678f3dff3a53f4a9598b5635",
    "USERPTR_TT_EXTERNAL_POPULATION": "63c97a7cbaf5d34a52bcf8011abf38c253ca3e780d6a3975a36ca0623fdf4e6d",
    "USERPTR_PIN_DMA_MAP_TRANSACTION": "0e99c37f9cb1513a83f68bb27079484a007f90af2f654948805dd1bccf9a5b8f",
    "GART_BIND_RANGE_ADMISSION": "bde7bd2be8ef66f200b086e262f5a6c4a5eaa984e6265e21a10a1510c9c95c71",
    "CACHED_TTM_SNOOP_FLAG_PROPAGATION": "21147c41c720175f939f0101f51880589f656939a6ed3923afcaa8e690754213",
    "RS400_PTE_PERMISSION_AND_SNOOP_ENCODING": "03a4de4d7c3136d5eacfb78dce5dfe87757950ad57d3e336321971e6a023510c",
    "RS480_GLOBAL_REQUEST_SNOOP_DISABLE": "25d60d2f09abe76b55c1d097563475ddbee42c042c9722201d1e4f62c3a477be",
    "GART_BIND_PTE_MB_TLB_PUBLICATION": "cc874dc497df5749a650ce93afa7bc0f3ff9cac00147b7d8380301eaa44ca208",
    "GART_UNBIND_RANGE_ADMISSION": "c86bb9b169f8fe169590f01f2d9d51c6991cee11b667f595b56850571635bdb4",
    "GART_UNBIND_SPARSE_CURSOR": "db51218105bf8cb9128e6042275265a65ce9e4e3e4d2243b63577e229dbe91ac",
    "GART_UNBIND_PTE_MB_TLB_PUBLICATION": "6b61643eb9cea5c4b7590847a0aabcffc0beddb75d66d59155783a25a6f2f5a9",
    "KERNEL_BO_MAP_RESERVATION_WAIT": "6c6d705572d2b742f33214eb46a68bf14bd3ee2c89091277b5957f12cb8bbe85",
    "USER_MMAP_FAULT_RESERVATION": "69193af651a78aeee402203d87c11a6efd11f4c6a4ce5e18884a8b3f53050310",
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": "d0b36062b23a39d607e3a1d097ba6690c935c6583f9da5aff3d43ff607fae9dd",
    "GART_COMMON_TEARDOWN": "4881e60041c9b8028b7d249a0c5a67db5d16717b965d72c14b00baf04b3809d6",
    "RS4XX_GART_TEARDOWN_ERROR_PROPAGATION": "35d7a10d7e1cdbbf9333098d7d6ca7a649ca48b75ca872311ed9a3337af686c1",
    "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT": "b0d5a1d660763582d833facff6f916aabe7546f0c88564893e1316dadffff5a3",
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": "e3e77b176af743d4a96484d6a4225c76568c83beb7a1561d8593cf825ffa4610",
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": "1a20db8baa0e1454be1ac09df445bc10ce6e26475032739b7edd41ba4e6bfb3a",
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": "467c50fdfa11df670c8103fe9dd93b31a8851cab73d4d67a2ffc8cc2011d4c3c",
    "RS400_TLB_FLUSH_COMPLETION": "b9eee72d3c55fc4ec3f1f906cec7fe66bb8229091c34ad78e190de68ee4e86da",
    "GART_SUSPEND_READY_STATE": "f4509dd49e51a48da562535699ef30e8b7e34defc20aaab597ea5a91ee82ecb1",
    "GART_BACKEND_NOT_READY_UNBIND_STATE": "98b9d15e6ae748e974e10870215875f4cefa2b51900931c3cd8789413353e11b",
    "GART_TTM_TEARDOWN_OWNERSHIP": "a2cd8581b5b686c2e33da216d0b95c5a3b1a8601755c4ff0e90064fde62dea92",
    "RS4XX_GART_COMPLETION_RELEASE": "88f4f8ea72bb94b99fb14a9057cd54f1c54616f7a8e9e465c4bfe35945babe50",
    "TTM_BO_MOVE_BIND_ROLLBACK": "6fbae494e28a79fc94419b2c0d53f54ceffe1bd67243650b81475de2ece494d7",
    "RS4XX_BO_LIFETIME_ACCOUNTING": "03acb9ce00fdf4a410f22ae8ccbb9d7cb57c43ea43b33a69b52502ec76396ac5",
    "RS4XX_BO_TRANSACTION_ROOTS": "7565a641fa7f281aeed18a445253271aae5023cd0c01263899073ce51d2b8315",
    "RS4XX_TTM_FINI_LIVE_DENOMINATOR": "a0973fc564a7a530f5072fe8cb7dd2f776174a92d9a83ccf490b0e21fd9ee496",
}

# A runtime status names what a target run produced. "not-run" carries no
# target execution, "awaiting-target-run" names a row whose verifier exists and
# whose run is pending, and "peer-observation" carries an external repository's
# retained observation. A value outside this set would let a row claim target
# execution the repository holds no artifact for.
RUNTIME_STATUS_VOCABULARY = frozenset(
    {"not-run", "awaiting-target-run", "peer-observation"}
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
        "repaired",
        "GART_SOURCE_BUILD_REACHABILITY",
    ),
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": (
        "repaired",
        "GART_TABLE_DMA_COHERENT_ALLOCATION_API;GART_BIND_PTE_MB_TLB_PUBLICATION;GART_UNBIND_PTE_MB_TLB_PUBLICATION",
    ),
    "GART_COMMON_TEARDOWN": (
        "repaired",
        "GART_UNBIND_PTE_MB_TLB_PUBLICATION",
    ),
    "RS4XX_GART_TEARDOWN_ERROR_PROPAGATION": (
        "repaired",
        "GART_COMMON_TEARDOWN",
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
        "repaired",
        "GART_BIND_PTE_MB_TLB_PUBLICATION;GART_UNBIND_PTE_MB_TLB_PUBLICATION",
    ),
    "GART_SUSPEND_READY_STATE": (
        "repaired",
        "RS400_ASIC_GART_CALLBACK_SELECTION",
    ),
    "GART_BACKEND_NOT_READY_UNBIND_STATE": (
        "repaired",
        "GART_COMMON_TEARDOWN",
    ),
    "GART_TTM_TEARDOWN_OWNERSHIP": (
        "repaired",
        "GART_COMMON_TEARDOWN;RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT;GART_BACKEND_NOT_READY_UNBIND_STATE;RS4XX_GART_TEARDOWN_ERROR_PROPAGATION",
    ),
    "RS4XX_GART_COMPLETION_RELEASE": (
        "repaired",
        "GART_COMMON_TEARDOWN",
    ),
    "TTM_BO_MOVE_BIND_ROLLBACK": (
        "repaired",
        "USERPTR_PIN_DMA_MAP_TRANSACTION;GART_BACKEND_NOT_READY_UNBIND_STATE",
    ),
    "RS4XX_BO_LIFETIME_ACCOUNTING": (
        "repaired",
        "TTM_BO_MOVE_BIND_ROLLBACK",
    ),
    "RS4XX_BO_TRANSACTION_ROOTS": (
        "repaired",
        "RS4XX_BO_LIFETIME_ACCOUNTING",
    ),
    "RS4XX_TTM_FINI_LIVE_DENOMINATOR": (
        "repaired",
        "GART_TTM_TEARDOWN_OWNERSHIP;RS4XX_BO_LIFETIME_ACCOUNTING;RS4XX_BO_TRANSACTION_ROOTS;RS4XX_GART_TEARDOWN_ERROR_PROPAGATION",
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
        "746675620eb49d3b7186da01f137773a5128d41b",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "GTT_WC_NON_PCIE_UNREACHABLE",
    ),
    "CACHED_TTM_SNOOP_FLAG_PROPAGATION": (
        "steinmarder-r300",
        "746675620eb49d3b7186da01f137773a5128d41b",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "RS400_PTE_PERMISSION_AND_SNOOP_ENCODING": (
        "steinmarder-r300",
        "746675620eb49d3b7186da01f137773a5128d41b",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "RS480_GLOBAL_REQUEST_SNOOP_DISABLE": (
        "steinmarder-r300",
        "746675620eb49d3b7186da01f137773a5128d41b",
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
        "746675620eb49d3b7186da01f137773a5128d41b",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "PER_PTE_GART_SNOOP_UNKNOWN",
    ),
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": (
        "steinmarder-r300",
        "746675620eb49d3b7186da01f137773a5128d41b",
        "src/re/r300/corpora/rs482_k8_memory_path_frontier_v1/frontier.jsonl",
        "CPU_GTT_GPU_PUBLICATION",
    ),
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": (
        "steinmarder-r300",
        "746675620eb49d3b7186da01f137773a5128d41b",
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
    "GART_UNBIND_RANGE_ADMISSION": "An integer disposition does not prove completed hardware invalidation.",
    "GART_UNBIND_SPARSE_CURSOR": "The repair does not prove a live TLB invalidation.",
    "GART_UNBIND_PTE_MB_TLB_PUBLICATION": "Source order does not prove that the GPU stopped using a stale translation.",
    "KERNEL_BO_MAP_RESERVATION_WAIT": "Fence retirement does not invalidate or flush payload cache lines.",
    "USER_MMAP_FAULT_RESERVATION": "A successful page fault does not prove a later GPU read sees CPU writes.",
    "GART_TABLE_READER_SNAPSHOT_BOUNDARY": "A bounded table dump does not characterize unobserved PTEs or payload visibility.",
    "GART_COMMON_TEARDOWN": "Successful common teardown does not prove target TLB completion.",
    "RS4XX_GART_TEARDOWN_ERROR_PROPAGATION": "Exact source propagation does not prove target teardown failure or recovery.",
    "RS4XX_GART_TABLE_WB_RESTORE_ATTEMPT": "The call does not prove that the CPU alias returned to WB.",
    "EFFECTIVE_PER_PTE_SNOOP_SEMANTICS": "The encoded PTE and global register do not establish effective snooping.",
    "CPU_GTT_GPU_PAYLOAD_PUBLICATION": "A directional visibility result does not prove snoop attribution or general cache coherence.",
    "GPU_GTT_CPU_PAYLOAD_INVALIDATION": "A directional visibility result does not prove snoop attribution or general cache coherence.",
    "RS400_TLB_FLUSH_COMPLETION": "A completed poll proves the invalidate bit cleared, not that every stale translation was dropped.",
    "GART_SUSPEND_READY_STATE": "gart.ready alone does not prove hardware translation is enabled.",
    "GART_BACKEND_NOT_READY_UNBIND_STATE": "A software completion disposition does not prove completed hardware invalidation.",
    "GART_TTM_TEARDOWN_OWNERSHIP": "Terminal retention proves source lifetime safety, not target recovery or reclaimed memory.",
    "RS4XX_GART_COMPLETION_RELEASE": "The release store does not prove target TLB completion.",
    "TTM_BO_MOVE_BIND_ROLLBACK": "Source rollback does not prove target payload visibility or TTM implementation identity.",
    "RS4XX_BO_LIFETIME_ACCOUNTING": "The counter proves source ownership accounting, not that TTM drains an external fence.",
    "RS4XX_BO_TRANSACTION_ROOTS": "Transaction admission does not prove a live target teardown.",
    "RS4XX_TTM_FINI_LIVE_DENOMINATOR": "The live denominator does not prove a fence will ever retire.",
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
    str(UPSTREAM_BASE),
    str(TTM_AUTHORITY),
    "drivers/gpu/drm/radeon/Makefile",
    "drivers/gpu/drm/radeon/radeon.h",
    "drivers/gpu/drm/radeon/radeon_asic.c",
    "drivers/gpu/drm/radeon/radeon_device.c",
    "drivers/gpu/drm/radeon/radeon_gart.c",
    "drivers/gpu/drm/radeon/radeon_gem.c",
    "drivers/gpu/drm/radeon/radeon_kms.c",
    "drivers/gpu/drm/radeon/radeon_object.c",
    "drivers/gpu/drm/radeon/radeon_prime.c",
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
            token_bytes = token.encode("utf-8")
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
        return cache_policy.strip_comments(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, UnicodeDecodeError) as exc:
        raise LifecycleError(f"cannot read UTF-8 source {path}") from exc


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
        raise LifecycleError("policy table must be LF terminated text")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_policy_sha256:
        raise LifecycleError(f"policy bytes differ from exact contract: {digest}")
    text = raw.decode("utf-8")
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
        value = row[field].encode("utf-8")
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
        if row["runtime_status"] not in RUNTIME_STATUS_VOCABULARY:
            raise LifecycleError(f"{row_id}: invalid runtime_status")
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


def check_ttm_authority(root: Path) -> None:
    authority_raw = (root / TTM_AUTHORITY).read_bytes()
    try:
        authority_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LifecycleError("TTM authority is not UTF-8 text") from exc
    if hashlib.sha256(authority_raw).hexdigest() != EXPECTED_TTM_AUTHORITY_SHA256:
        raise LifecycleError("TTM authority identity differs")

    authority = tomllib.loads(authority_raw.decode("utf-8"))
    upstream = tomllib.loads((root / UPSTREAM_BASE).read_text(encoding="utf-8"))
    expected_commits = {
        "6.18": upstream["commit"],
        "7.1": upstream["target"]["mainline"]["commit"],
    }
    observed_commits = {
        entry["kernel"]: entry["commit"] for entry in authority["authority"]
    }
    if observed_commits != expected_commits:
        raise LifecycleError("TTM authority commit set differs from upstream lanes")

    expected_paths = {
        "drivers/gpu/drm/ttm/ttm_tt.c",
        "drivers/gpu/drm/ttm/ttm_agp_backend.c",
        "drivers/gpu/drm/ttm/ttm_bo.c",
        "drivers/gpu/drm/ttm/ttm_resource.c",
        "drivers/gpu/drm/drm_gem.c",
        "drivers/gpu/drm/drm_prime.c",
        "include/drm/ttm/ttm_device.h",
        "include/drm/ttm/ttm_tt.h",
        "include/drm/drm_prime.h",
    }
    for entry in authority["authority"]:
        files = entry.get("file", [])
        observed_paths = {file_entry["path"] for file_entry in files}
        if observed_paths != expected_paths or len(files) != len(expected_paths):
            raise LifecycleError(
                f"TTM authority file denominator differs for {entry['kernel']}"
            )
        if any(
            re.fullmatch(r"[0-9a-f]{64}", file_entry["sha256"]) is None
            for file_entry in files
        ):
            raise LifecycleError(f"TTM authority digest differs for {entry['kernel']}")


def check_build_and_callbacks(root: Path) -> None:
    makefile = (root / SUBTREE / "Makefile").read_text(encoding="utf-8")
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
            "if (rdev->gart.pages)",
            "smp_store_release(&rdev->rs4xx_gart_teardown_complete, false)",
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

    bind = function(root, "radeon_gart.c", "radeon_gart_bind_locked")
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

    bind_root = function(root, "radeon_gart.c", "radeon_gart_bind")
    require_exact_direct_statements(
        "GART bind hardware admission and table serialization",
        bind_root,
        (
            "int r;",
            "r = radeon_rs4xx_hardware_access_begin(rdev);",
            "if (r) return r;",
            "mutex_lock(&rdev->gart.lock);",
            "r = radeon_gart_bind_locked(rdev, offset, pages, pagelist, dma_addr, flags);",
            "mutex_unlock(&rdev->gart.lock);",
            "radeon_rs4xx_hardware_access_end(rdev);",
            "return r;",
        ),
    )

    unbind = function(root, "radeon_gart.c", "radeon_gart_unbind_locked")
    unbind_statements, unbind_guard_index = require_exact_if_guard(
        "GART unbind range admission guard differs",
        unbind,
        "!radeon_gart_range_valid(rdev, offset, pages)",
        "return -EINVAL;",
        3,
        (
            'WARN(1, "invalid GART unbind range offset %u pages %d\\n", '
            "offset, pages);"
            "return -EINVAL;"
        ),
    )

    unbind_root = function(root, "radeon_gart.c", "radeon_gart_unbind")
    require_exact_direct_statements(
        "GART unbind wait admission and table serialization",
        unbind_root,
        (
            "int r;",
            "r = radeon_rs4xx_hardware_access_wait_begin(rdev);",
            "if (r) return r;",
            "mutex_lock(&rdev->gart.lock);",
            "r = radeon_gart_unbind_locked(rdev, offset, pages);",
            "mutex_unlock(&rdev->gart.lock);",
            "radeon_rs4xx_hardware_access_end(rdev);",
            "return r;",
        ),
    )

    fini = function(root, "radeon_gart.c", "radeon_gart_fini")
    require_exact_direct_statements(
        "GART finalization admission retention and table serialization",
        fini,
        (
            "int r;",
            "r = radeon_rs4xx_hardware_access_begin(rdev);",
            "if (r) return r;",
            "mutex_lock(&rdev->gart.lock);",
            "if (rdev->gart.ready) {"
            "r = radeon_gart_unbind_locked(rdev, 0, rdev->gart.num_cpu_pages);"
            "if (r) goto out_unlock;"
            "}",
            "rdev->gart.ready = false;",
            "vfree(rdev->gart.pages);",
            "vfree(rdev->gart.pages_entry);",
            "rdev->gart.pages = NULL;",
            "rdev->gart.pages_entry = NULL;",
            "radeon_dummy_page_fini(rdev);",
            "r = 0;",
            "out_unlock: mutex_unlock(&rdev->gart.lock);",
            "radeon_rs4xx_hardware_access_end(rdev);",
            "return r;",
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
            "if (radeon_rs4xx_hardware_target(rdev) && "
            "radeon_rs4xx_gart_teardown_is_complete(rdev)) return 0;"
            'WARN(1, "trying to unbind memory from uninitialized GART !\\n");'
            "return -EINVAL;"
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


def check_ttm_population_contract(root: Path) -> None:
    target = function(root, "radeon.h", "radeon_rs4xx_hardware_target")
    require_exact_direct_statements(
        "RS4xx terminal TTM scope is the internal-GART IGP path",
        target,
        (
            "return rdev && (rdev->flags & RADEON_IS_IGP) && "
            "(rdev->family == CHIP_RS400 || rdev->family == CHIP_RS480);",
        ),
    )
    device_init = function(root, "radeon_device.c", "radeon_device_init")
    require_order(
        "RS4xx IGP initialization removes the AGP backend before driver bring-up",
        device_init,
        (
            "if ((rdev->family >= CHIP_RS400) &&",
            "(rdev->flags & RADEON_IS_IGP))",
            "rdev->flags &= ~RADEON_IS_AGP",
            "r = radeon_init(rdev)",
        ),
    )

    prime_import = function(root, "radeon_prime.c", "radeon_gem_prime_import_sg_table")
    require_order(
        "PRIME import transfers the exact SG table into Radeon BO creation",
        prime_import,
        (
            "ret = radeon_device_lock_hardware(rdev)",
            "dma_resv_lock(resv, NULL)",
            "ret = radeon_bo_create",
            "RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo",
            "dma_resv_unlock(resv)",
            "radeon_device_unlock_hardware(rdev)",
        ),
    )

    bo_create = function(root, "radeon_object.c", "radeon_bo_create")
    require_order(
        "AGP imported SG admission closes before TTM BO construction",
        bo_create,
        (
            "r = radeon_rs4xx_hardware_transaction_begin(rdev)",
            "if (r)",
            "if (sg && (rdev->flags & RADEON_IS_AGP))",
            "r = -EOPNOTSUPP",
            "goto out_transaction",
            "size = ALIGN(size, PAGE_SIZE)",
            "bo = kzalloc",
            "drm_gem_private_object_init",
            "ttm_bo_init_validate",
            "out_transaction:",
            "radeon_rs4xx_hardware_transaction_end(rdev)",
        ),
    )

    create = function(root, "radeon_ttm.c", "radeon_ttm_tt_create")
    require_order(
        "TTM creation separates AGP and Radeon GART translation storage",
        create,
        (
            "if (rdev->flags & RADEON_IS_AGP)",
            "return ttm_agp_tt_create",
            "gtt = kzalloc",
            "INIT_LIST_HEAD(&gtt->rs4xx_retained_node)",
            "ttm_sg_tt_init",
        ),
    )

    populate = function(root, "radeon_ttm.c", "radeon_ttm_tt_populate")
    require_order(
        "TTM population refuses external SG without Radeon GART storage",
        populate,
        (
            "bool slave = !!(ttm->page_flags & TTM_TT_FLAG_EXTERNAL)",
            "if (gtt && gtt->userptr)",
            "ttm->page_flags |= TTM_TT_FLAG_EXTERNAL",
            "gtt->rs4xx_ttm_pages_accounted = true",
            "if (slave && ttm->sg)",
            "if (!gtt)",
            "return -EOPNOTSUPP",
            "return drm_prime_sg_to_dma_addr_array",
            "r = ttm_pool_alloc",
            "gtt->rs4xx_ttm_pages_accounted = true",
            "return r",
        ),
    )
    if "drm_prime_sg_to_page_array" in populate:
        raise LifecycleError("TTM population uses deprecated SG page conversion")
    if populate.count("drm_prime_sg_to_dma_addr_array") != 1:
        raise LifecycleError("TTM population DMA conversion call count differs")

    retain = function(root, "radeon_ttm.c", "radeon_rs4xx_retain_ttm")
    require_order(
        "terminal TTM ownership transfers before generic accounting retires",
        retain,
        (
            "retained_bo_count = radeon_rs4xx_retain_bo(gtt->rs4xx_owner)",
            "mutex_lock(&rdev->rs4xx_retained_ttm_lock)",
            "if (list_empty(&gtt->rs4xx_retained_node))",
            "list_add_tail(&gtt->rs4xx_retained_node",
            "atomic_inc_return",
            "if (gtt->rs4xx_ttm_pages_accounted)",
            "atomic_long_add_return",
            "gtt->ttm.num_pages",
            "&rdev->rs4xx_retained_ttm_accounted_pages",
            "gtt->rs4xx_ttm_pages_accounted = false",
            "gtt->ttm.page_flags &= ~TTM_TT_FLAG_EXTERNAL",
            "mutex_unlock(&rdev->rs4xx_retained_ttm_lock)",
            "accounted pages=%ld",
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
            "radeon_rs4xx_gart_teardown_is_complete(rdev)",
            "gtt->bound = false;",
            "radeon_ttm_tt_unpin_userptr",
            "return 0;",
            "r = radeon_gart_unbind",
            "if (r && radeon_rs4xx_hardware_target(rdev))",
            "radeon_rs4xx_latch_teardown_refusal(rdev);",
            "return r;",
            "gtt->bound = false;",
            "radeon_ttm_tt_unpin_userptr",
            "return 0;",
        ),
    )
    unbind_tokens = c_tokens(unbind)
    unbind_spans = direct_function_statements(unbind_tokens)
    unbind_statements = tuple(unbind_tokens[start:end] for start, end in unbind_spans)
    require_direct_statement(
        "TTM completed-GART unbind disposition differs",
        unbind_statements,
        4,
        (
            "if (radeon_rs4xx_hardware_target(rdev) && "
            "radeon_rs4xx_gart_teardown_is_complete(rdev)) {"
            "gtt->bound = false;"
            "if (gtt->userptr) radeon_ttm_tt_unpin_userptr(bdev, ttm);"
            "return 0;"
            "}"
        ),
    )
    require_direct_statement(
        "TTM unbind failure retention guard differs",
        unbind_statements,
        7,
        (
            "if (r && radeon_rs4xx_hardware_target(rdev)) {"
            "radeon_rs4xx_latch_teardown_refusal(rdev);"
            "if (r == -EINVAL)"
            "dev_err_once(rdev->dev, "
            '"RS4xx GART unbind invariant failure retains binding\\n");'
            "else "
            "dev_err_once(rdev->dev, "
            '"RS4xx teardown refusal retains GART binding: %d\\n", r);'
            "return r;"
            "}"
        ),
    )

    unpopulate = function(root, "radeon_ttm.c", "radeon_ttm_tt_unpopulate")
    require_order(
        "TTM unpopulate owns admission through the unbind disposition",
        unpopulate,
        (
            "if (gtt && !gtt->bound)",
            "radeon_ttm_tt_unpin_userptr",
            "kfree(ttm->sg)",
            "ttm->sg = NULL",
            "ttm->page_flags &= ~TTM_TT_FLAG_EXTERNAL",
            "ttm_pool_free",
            "r = radeon_rs4xx_hardware_transaction_wait_begin(rdev)",
            "if (r == -ESHUTDOWN)",
            "r = radeon_rs4xx_gart_teardown_wait(rdev)",
            "else if (r == 0)",
            "hardware_transaction = true",
            "if (r)",
            "radeon_rs4xx_latch_teardown_refusal(rdev)",
            "return;",
            "r = radeon_ttm_tt_unbind_status(bdev, ttm)",
            "if (hardware_transaction)",
            "radeon_rs4xx_hardware_transaction_end(rdev)",
            "if (r)",
            "return;",
            "kfree(ttm->sg)",
            "ttm_pool_free",
        ),
    )
    require_exact_if_guard(
        "TTM unbound CPU cleanup guard differs",
        unpopulate,
        "gtt && !gtt->bound",
        "return;",
        5,
        (
            "if (gtt->userptr) {"
            "radeon_ttm_tt_unpin_userptr(bdev, ttm);"
            "kfree(ttm->sg);"
            "ttm->sg = NULL;"
            "ttm->page_flags &= ~TTM_TT_FLAG_EXTERNAL;"
            "gtt->rs4xx_ttm_pages_accounted = false;"
            "return;"
            "}"
            "if (slave) return;"
            "ttm_pool_free(&rdev->mman.bdev.pool, ttm);"
            "gtt->rs4xx_ttm_pages_accounted = false;"
            "return;"
        ),
    )
    require_exact_direct_statements(
        "TTM unpopulate admission and retention sequence",
        unpopulate,
        (
            "struct radeon_device *rdev = radeon_get_rdev(bdev);",
            "struct radeon_ttm_tt *gtt = radeon_ttm_tt_to_gtt(rdev, ttm);",
            "bool slave = !!(ttm->page_flags & TTM_TT_FLAG_EXTERNAL);",
            "bool hardware_transaction = false;",
            "int r;",
            "if (gtt && !gtt->bound) {"
            "if (gtt->userptr) {"
            "radeon_ttm_tt_unpin_userptr(bdev, ttm);"
            "kfree(ttm->sg);"
            "ttm->sg = NULL;"
            "ttm->page_flags &= ~TTM_TT_FLAG_EXTERNAL;"
            "gtt->rs4xx_ttm_pages_accounted = false;"
            "return;"
            "}"
            "if (slave) return;"
            "ttm_pool_free(&rdev->mman.bdev.pool, ttm);"
            "gtt->rs4xx_ttm_pages_accounted = false;"
            "return;"
            "}",
            "r = radeon_rs4xx_hardware_transaction_wait_begin(rdev);",
            "if (r == -ESHUTDOWN) "
            "r = radeon_rs4xx_gart_teardown_wait(rdev); "
            "else if (r == 0) hardware_transaction = true;",
            "if (r) {"
            "radeon_rs4xx_latch_teardown_refusal(rdev);"
            "if (gtt && gtt->bound && radeon_rs4xx_hardware_target(rdev)) "
            "radeon_rs4xx_retain_ttm(rdev, gtt);"
            "return;"
            "}",
            "r = radeon_ttm_tt_unbind_status(bdev, ttm);",
            "if (hardware_transaction) radeon_rs4xx_hardware_transaction_end(rdev);",
            "if (r) {"
            "if (gtt && gtt->bound && radeon_rs4xx_hardware_target(rdev)) "
            "radeon_rs4xx_retain_ttm(rdev, gtt);"
            "return;"
            "}",
            "if (gtt && gtt->userptr) {"
            "kfree(ttm->sg);"
            "ttm->sg = NULL;"
            "ttm->page_flags &= ~TTM_TT_FLAG_EXTERNAL;"
            "gtt->rs4xx_ttm_pages_accounted = false;"
            "return;"
            "}",
            "if (slave) return;",
            "ttm_pool_free(&rdev->mman.bdev.pool, ttm);",
            "if (gtt) gtt->rs4xx_ttm_pages_accounted = false;",
        ),
    )
    destroy = function(root, "radeon_ttm.c", "radeon_ttm_tt_destroy")
    require_order(
        "TTM destroy transfers a bound translation table to device ownership",
        destroy,
        (
            "if (gtt && gtt->bound && radeon_rs4xx_hardware_target(rdev))",
            "radeon_rs4xx_retain_ttm(rdev, gtt)",
            "return;",
            "radeon_ttm_backend_destroy",
        ),
    )
    destroy_tokens = c_tokens(destroy)
    destroy_spans = direct_function_statements(destroy_tokens)
    destroy_statements = tuple(
        destroy_tokens[start:end] for start, end in destroy_spans
    )
    require_direct_statement(
        "TTM destroy bound-table retention guard differs",
        destroy_statements,
        2,
        (
            "if (gtt && gtt->bound && radeon_rs4xx_hardware_target(rdev)) {"
            "radeon_rs4xx_retain_ttm(rdev, gtt);"
            "return;"
            "}"
        ),
    )
    create = function(root, "radeon_ttm.c", "radeon_ttm_tt_create")
    require_order(
        "TTM retained-list node initialization",
        create,
        (
            "gtt = kzalloc",
            "if (gtt == NULL)",
            "INIT_LIST_HEAD(&gtt->rs4xx_retained_node)",
            "ttm_sg_tt_init",
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
    if fault.find("radeon_bo_fault_reserve_notify") < fault.find("ttm_bo_vm_reserve"):
        raise LifecycleError("userspace fault inspects placement before reserve")
    require_order(
        "userspace fault lock and reservation order",
        fault,
        (
            "down_read(&rdev->pm.mclk_lock)",
            "ttm_bo_vm_reserve",
            "radeon_rs4xx_hardware_transaction_begin",
            "radeon_bo_fault_reserve_notify",
            "ttm_bo_vm_fault_reserved",
            "dma_resv_unlock",
            "radeon_rs4xx_hardware_transaction_end",
            "up_read(&rdev->pm.mclk_lock)",
        ),
    )
    fault_tokens = c_tokens(fault)
    fault_spans = direct_function_statements(fault_tokens)
    fault_statements = tuple(fault_tokens[start:end] for start, end in fault_spans)
    require_direct_statement(
        "userspace fault hardware transaction guard differs",
        fault_statements,
        7,
        (
            "if (radeon_rs4xx_hardware_transaction_begin(rdev)) {"
            'dev_err_once(rdev->dev, "RS4xx hardware unavailable: SIGBUS on '
            'GEM fault\\n");'
            "ret = VM_FAULT_SIGBUS;"
            "goto unlock_resv;"
            "}"
        ),
    )
    reader = function(root, "radeon_rs4xx_dev.c", "rs400_debugfs_gart_page_table_show")
    require_exact_if_guard(
        "GART reader hardware admission guard differs",
        reader,
        "radeon_device_lock_hardware(rdev)",
        "return 0;",
        9,
        (
            'seq_puts(m, "metadata\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\thardware-unavailable\\n");'
            "return 0;"
        ),
    )
    require_order(
        "GART reader lifetime lock",
        reader,
        (
            "radeon_device_lock_hardware(rdev)",
            "mutex_lock(&rdev->gart.lock)",
            "if (!rdev->gart.ready || !rdev->gart.ptr)",
            "table = rdev->gart.ptr",
            "READ_ONCE(table[index])",
            "mutex_unlock(&rdev->gart.lock)",
            "radeon_device_unlock_hardware(rdev)",
        ),
    )
    fini = function(root, "rs400.c", "rs400_gart_fini")
    require_exact_direct_statements(
        "GART finalization direct teardown sequence",
        fini,
        (
            "int r;",
            "r = radeon_gart_fini(rdev);",
            "if (r && radeon_rs4xx_hardware_target(rdev)) {"
            "WRITE_ONCE(rdev->rs4xx_gart_fini_error, r);"
            "wake_up_all(&rdev->rs4xx_hardware_wait);"
            "}",
            "if (r) return r;",
            "rs400_gart_disable(rdev);",
            "radeon_gart_table_ram_free(rdev);",
            "if (radeon_rs4xx_hardware_target(rdev)) {"
            "WRITE_ONCE(rdev->rs4xx_gart_fini_error, 0);"
            "smp_store_release(&rdev->rs4xx_gart_teardown_complete, true);"
            "wake_up_all(&rdev->rs4xx_hardware_wait);"
            "}",
            "return 0;",
        ),
    )


def check_bo_ttm_lifecycle(root: Path) -> None:
    move = function(root, "radeon_ttm.c", "radeon_bo_move")
    wait_position = move.find("r = ttm_bo_wait_ctx(bo, ctx);")
    bind_position = move.find("r = radeon_ttm_tt_bind(bo->bdev, bo->ttm, new_mem);")
    if wait_position < 0 or bind_position < 0 or wait_position > bind_position:
        raise LifecycleError("TTM move binds before reservation wait")
    initial_branch_start = move.find("if (!old_mem ||", bind_position)
    initial_branch_end = move.find(
        "if (old_mem->mem_type == TTM_PL_TT &&", initial_branch_start
    )
    if initial_branch_start < 0:
        raise LifecycleError("TTM move initial ownership branch is absent")
    if initial_branch_end < 0:
        raise LifecycleError("TTM move initial ownership branches are absent")
    initial_move = move[initial_branch_start:initial_branch_end]
    if "goto out_transaction" in initial_move:
        raise LifecycleError("TTM initial SG move escapes without a bound rollback")
    rollback_position = move.find("if (r && newly_bound)", bind_position)
    if rollback_position < 0 or "return " in move[bind_position:rollback_position]:
        raise LifecycleError("TTM move returns after bind without rollback")
    require_order(
        "TTM move records and rolls back a new binding",
        move,
        (
            "newly_bound = radeon_rs4xx_hardware_target(rdev)",
            "!radeon_ttm_tt_is_bound(bo->bdev, bo->ttm)",
            "r = radeon_ttm_tt_bind",
            "if (!old_mem ||",
            "ttm_bo_move_null(bo, new_mem);",
            "if (r && newly_bound)",
            "rollback_result = radeon_ttm_tt_unbind_status",
            "if (rollback_result)",
            "r = rollback_result",
            "radeon_rs4xx_hardware_transaction_end(rdev)",
        ),
    )
    if move.count("if (r && newly_bound)") != 1:
        raise LifecycleError("TTM move has no unique new-binding rollback")

    create = function(root, "radeon_object.c", "radeon_bo_create")
    require_order(
        "BO lifetime count precedes TTM ownership transfer",
        create,
        (
            "r = radeon_rs4xx_hardware_transaction_begin(rdev)",
            "bo = kzalloc",
            "bo->rs4xx_lifetime_counted = false",
            "bo->rs4xx_lifetime_counted = true",
            "atomic_inc(&rdev->rs4xx_live_bos)",
            "ttm_bo_init_validate",
            "*bo_ptr = bo",
            "out_transaction:",
            "radeon_rs4xx_hardware_transaction_end(rdev)",
        ),
    )
    if create.count("atomic_inc(&rdev->rs4xx_live_bos)") != 1:
        raise LifecycleError("BO lifetime count increment is not unique")

    destroy = function(root, "radeon_object.c", "radeon_ttm_bo_destroy")
    require_order(
        "BO destruction retains refused imported ownership",
        destroy,
        (
            "if (READ_ONCE(bo->rs4xx_terminally_retained))",
            "radeon_rs4xx_hardware_transaction_wait_begin",
            "radeon_rs4xx_latch_teardown_refusal",
            "radeon_rs4xx_retain_bo(bo)",
            "return;",
            "drm_prime_gem_destroy",
            "drm_gem_object_release",
            "lifetime_counted = bo->rs4xx_lifetime_counted",
            "kfree(bo)",
            "atomic_dec_and_test(&rdev->rs4xx_live_bos)",
            "wake_up_all(&rdev->rs4xx_hardware_wait)",
            "radeon_rs4xx_hardware_transaction_end(rdev)",
        ),
    )
    if "if (lifetime_counted &&" not in destroy:
        raise LifecycleError("BO lifetime decrement is not conditional on ownership")
    if destroy.count("atomic_dec_and_test(&rdev->rs4xx_live_bos)") != 1:
        raise LifecycleError("BO lifetime count decrement is not unique")

    gem_free = function(root, "radeon_gem.c", "radeon_gem_object_free")
    require_order(
        "GEM destruction keeps the transaction root across TTM release",
        gem_free,
        (
            "ret = radeon_rs4xx_hardware_transaction_wait_begin(rdev)",
            "if (ret == -ESHUTDOWN)",
            "ret = radeon_rs4xx_gart_teardown_wait(rdev)",
            "hardware_transaction = true",
            "radeon_rs4xx_retain_bo(robj)",
            "return;",
            "radeon_mn_unregister(robj)",
            "ttm_bo_",
            "if (hardware_transaction)",
            "radeon_rs4xx_hardware_transaction_end(rdev)",
        ),
    )

    gem_info = function(root, "radeon_gem.c", "radeon_debugfs_gem_info_show")
    require_order(
        "GEM debugfs classifies retained and detached BOs before placement",
        gem_info,
        (
            "if (READ_ONCE(rbo->rs4xx_terminally_retained))",
            'placement = "RETAINED"',
            "else if (!rbo->tbo.resource)",
            'placement = "DETACHED"',
            "radeon_mem_type_to_domain(",
            "rbo->tbo.resource->mem_type",
        ),
    )
    retained_guard_position = gem_info.find(
        "if (READ_ONCE(rbo->rs4xx_terminally_retained))"
    )
    null_guard_position = gem_info.find("else if (!rbo->tbo.resource)")
    resource_read_position = gem_info.find("rbo->tbo.resource->mem_type")
    if not (
        0 <= retained_guard_position < null_guard_position < resource_read_position
        and gem_info.count("rbo->tbo.resource->mem_type") == 1
    ):
        raise LifecycleError("GEM debugfs dereferences placement before BO disposition")

    ttm_fini = function(root, "radeon_ttm.c", "radeon_ttm_fini")
    if "drain_workqueue" in ttm_fini or "flush_workqueue" in ttm_fini:
        raise LifecycleError("TTM finalization pre-drains external-fence work")
    require_order(
        "TTM finalization vetoes live and retained ownership",
        ttm_fini,
        (
            "live_bos = atomic_read_acquire(&rdev->rs4xx_live_bos)",
            "retained_bos = atomic_read(&rdev->rs4xx_retained_gem_objects)",
            "retained_tables = atomic_read(&rdev->rs4xx_retained_ttm_tables)",
            "retained_accounted_pages = atomic_long_read(",
            "&rdev->rs4xx_retained_ttm_accounted_pages)",
            "transactions = atomic_read(&rdev->rs4xx_hardware_transactions)",
            "readers = atomic_read(&rdev->rs4xx_hardware_readers)",
            "if (live_bos != 0 || retained_bos != 0 || retained_tables != 0 ||",
            "retained_accounted_pages != 0",
            "transactions != 0 || readers != 0)",
            "WRITE_ONCE(rdev->rs4xx_ttm_fini_error, r)",
            "wake_up_all(&rdev->rs4xx_hardware_wait)",
            "return r;",
            "ttm_range_man_fini",
            "ttm_device_fini",
        ),
    )


def check_terminal_ownership(root: Path) -> None:
    header = source(root, "radeon.h")
    for field in (
        "rs4xx_hardware_transactions",
        "rs4xx_hardware_readers",
        "rs4xx_live_bos",
        "rs4xx_retained_gem_objects",
        "rs4xx_retained_ttm_tables",
        "rs4xx_retained_ttm_accounted_pages",
        "rs4xx_hardware_wait",
        "rs4xx_retained_bos_list",
        "rs4xx_retained_ttm_lock",
        "rs4xx_retained_ttm_tables_list",
        "rs4xx_gart_fini_error",
        "rs4xx_ttm_fini_error",
        "rs4xx_gart_teardown_complete",
    ):
        if field not in header:
            raise LifecycleError(f"terminal ownership field is absent: {field}")

    initialization = function(root, "radeon_device.c", "radeon_device_init")
    require_order(
        "terminal ownership initialization",
        initialization,
        (
            "atomic_set(&rdev->rs4xx_hardware_transactions, 0)",
            "atomic_set(&rdev->rs4xx_hardware_readers, 0)",
            "atomic_set(&rdev->rs4xx_live_bos, 0)",
            "atomic_set(&rdev->rs4xx_retained_gem_objects, 0)",
            "atomic_set(&rdev->rs4xx_retained_ttm_tables, 0)",
            "atomic_long_set(&rdev->rs4xx_retained_ttm_accounted_pages, 0)",
            "init_waitqueue_head(&rdev->rs4xx_hardware_wait)",
            "mutex_init(&rdev->rs4xx_retained_ttm_lock)",
            "INIT_LIST_HEAD(&rdev->rs4xx_retained_bos_list)",
            "INIT_LIST_HEAD(&rdev->rs4xx_retained_ttm_tables_list)",
            "WRITE_ONCE(rdev->rs4xx_gart_fini_error, 0)",
            "WRITE_ONCE(rdev->rs4xx_ttm_fini_error, 0)",
            "WRITE_ONCE(rdev->rs4xx_gart_teardown_complete, false)",
        ),
    )
    retained = function(root, "radeon.h", "radeon_rs4xx_terminal_ownership_retained")
    require_order(
        "terminal retention helper covers every retained owner",
        retained,
        (
            "radeon_rs4xx_hardware_target(rdev)",
            "READ_ONCE(rdev->gpu_parked)",
            "READ_ONCE(rdev->rs4xx_gart_fini_error)",
            "READ_ONCE(rdev->rs4xx_ttm_fini_error)",
            "atomic_read(&rdev->rs4xx_retained_gem_objects)",
            "atomic_read(&rdev->rs4xx_retained_ttm_tables)",
            "atomic_long_read(",
            "&rdev->rs4xx_retained_ttm_accounted_pages)",
        ),
    )
    terminal_error = function(root, "radeon.h", "radeon_rs4xx_terminal_ownership_error")
    require_order(
        "terminal error helper propagates every retained owner",
        terminal_error,
        (
            "READ_ONCE(rdev->rs4xx_gart_fini_error)",
            "READ_ONCE(rdev->rs4xx_ttm_fini_error)",
            "READ_ONCE(rdev->gpu_parked)",
            "atomic_read(&rdev->rs4xx_retained_gem_objects)",
            "atomic_read(&rdev->rs4xx_retained_ttm_tables)",
            "atomic_long_read(&rdev->rs4xx_retained_ttm_accounted_pages)",
            "return -EBUSY",
        ),
    )
    teardown_wrapper = function(
        root, "radeon_device.c", "radeon_rs4xx_latch_teardown_refusal"
    )
    require_exact_direct_statements(
        "TTM failure routes through the nonblocking publication latch",
        teardown_wrapper,
        ("radeon_rs4xx_latch_parked_publication(rdev);",),
    )
    publication_latch = function(
        root, "radeon_device.c", "radeon_rs4xx_latch_parked_publication"
    )
    require_exact_direct_statements(
        "parked publication latch queues deferred cleanup",
        publication_latch,
        (
            "radeon_rs4xx_latch_parked_state(rdev);",
            "atomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);",
            "radeon_rs4xx_queue_parked_publish(rdev);",
        ),
    )
    parked_latch = function(root, "radeon_device.c", "radeon_rs4xx_latch_parked_state")
    require_exact_direct_statements(
        "TTM failure closes hardware admission under the state lock",
        parked_latch,
        (
            "unsigned long irqflags;",
            "int ring_index;",
            "if (!radeon_rs4xx_hardware_target(rdev)) return;",
            "spin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags);",
            "WRITE_ONCE(rdev->gpu_parked, true);",
            "WRITE_ONCE(rdev->accel_working, false);",
            "WRITE_ONCE(rdev->needs_reset, false);",
            "for (ring_index = 0; ring_index < RADEON_NUM_RINGS; "
            "++ring_index) WRITE_ONCE(rdev->ring[ring_index].ready, false);",
            "atomic_set_release(&rdev->rs4xx_hardware_closing, 1);",
            "radeon_rs4xx_publish_parked_hardware_state_locked(rdev);",
            "spin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);",
            "smp_mb();",
            "wake_up_all(&rdev->rs4xx_hardware_wait);",
            "if (READ_ONCE(rdev->rs4xx_fence_work_initialized)) "
            "wake_up_all(&rdev->fence_queue);",
        ),
    )
    require_order(
        "TTM failure closes RS4xx hardware admission",
        parked_latch,
        (
            "if (!radeon_rs4xx_hardware_target(rdev))",
            "spin_lock_irqsave(&rdev->rs4xx_hardware_state_lock, irqflags)",
            "WRITE_ONCE(rdev->gpu_parked, true)",
            "WRITE_ONCE(rdev->accel_working, false)",
            "WRITE_ONCE(rdev->needs_reset, false)",
            "WRITE_ONCE(rdev->ring[ring_index].ready, false)",
            "atomic_set_release(&rdev->rs4xx_hardware_closing, 1)",
            "radeon_rs4xx_publish_parked_hardware_state_locked(rdev)",
            "spin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags)",
            "wake_up_all(&rdev->rs4xx_hardware_wait)",
        ),
    )

    gem_free = function(root, "radeon_gem.c", "radeon_gem_object_free")
    require_order(
        "terminal GEM object retains its driver ownership anchor",
        gem_free,
        (
            "ret = radeon_rs4xx_hardware_transaction_wait_begin(rdev)",
            "if (ret)",
            "radeon_rs4xx_retain_bo(robj)",
            "radeon_rs4xx_latch_teardown_refusal(rdev)",
            "radeon_mn_unregister(robj)",
            "return;",
            "ttm_bo_",
            "radeon_rs4xx_hardware_transaction_end(rdev)",
        ),
    )

    rs400_fini = function(root, "rs400.c", "rs400_fini")
    require_exact_direct_statements(
        "RS400 finalization direct ownership sequence",
        rs400_fini,
        (
            "int r;",
            "if (radeon_rs4xx_terminal_ownership_retained(rdev)) return;",
            "radeon_pm_fini(rdev);",
            "r100_cp_fini(rdev);",
            "radeon_wb_fini(rdev);",
            "radeon_ib_pool_fini(rdev);",
            "r = rs400_gart_fini(rdev);",
            "if (r) return;",
            "if (radeon_rs4xx_terminal_ownership_retained(rdev)) return;",
            "radeon_gem_fini(rdev);",
            "if (radeon_rs4xx_terminal_ownership_retained(rdev)) return;",
            "radeon_irq_kms_fini(rdev);",
            "radeon_fence_driver_fini(rdev);",
            "r = radeon_bo_fini(rdev);",
            "if (r) return;",
            "radeon_atombios_fini(rdev);",
            "radeon_bios_fini(rdev);",
        ),
    )
    require_order(
        "RS400 finalization stops before GEM deletion after GART refusal",
        rs400_fini,
        (
            "if (radeon_rs4xx_terminal_ownership_retained(rdev))",
            "return;",
            "r = rs400_gart_fini(rdev)",
            "if (r)",
            "return;",
            "radeon_gem_fini(rdev)",
            "radeon_bo_fini(rdev)",
        ),
    )
    device_fini = function(root, "radeon_device.c", "radeon_device_fini")
    require_exact_direct_statements(
        "device finalization direct propagation sequence",
        device_fini,
        (
            "int r;",
            "r = radeon_rs4xx_terminal_ownership_error(rdev);",
            "if (r) return r;",
            'DRM_INFO("radeon: finishing device.\\n");',
            "WRITE_ONCE(rdev->shutdown, true);",
            "radeon_rs480_panic_unregister(rdev);",
            "r = radeon_bo_evict_vram(rdev);",
            "if (r && radeon_rs4xx_hardware_target(rdev)) return r;",
            "r = radeon_rs4xx_terminal_ownership_error(rdev);",
            "if (r) return r;",
            "radeon_audio_component_fini(rdev);",
            "radeon_fini(rdev);",
            "r = radeon_rs4xx_terminal_ownership_error(rdev);",
            "if (r) return r;",
            "radeon_device_fini_external_interfaces(rdev);",
            "if (rdev->rio_mem) pci_iounmap(rdev->pdev, rdev->rio_mem);",
            "rdev->rio_mem = NULL;",
            "iounmap(rdev->rmmio);",
            "rdev->rmmio = NULL;",
            "if (rdev->family >= CHIP_BONAIRE) radeon_doorbell_fini(rdev);",
            "return 0;",
        ),
    )
    require_order(
        "device finalization propagates the RS4xx GART refusal before teardown",
        device_fini,
        (
            "radeon_rs4xx_terminal_ownership_error(rdev)",
            "if (r)",
            "return r;",
            "r = radeon_bo_evict_vram(rdev)",
            "if (r && radeon_rs4xx_hardware_target(rdev))",
            "return r;",
            "radeon_rs4xx_terminal_ownership_error(rdev)",
            "if (r)",
            "return r;",
            "radeon_fini(rdev)",
            "radeon_rs4xx_terminal_ownership_error(rdev)",
            "if (r)",
            "return r;",
            "radeon_device_fini_external_interfaces(rdev)",
            "pci_iounmap",
            "iounmap(rdev->rmmio)",
        ),
    )
    agp_retry = function(root, "radeon_device.c", "radeon_device_init")
    require_order(
        "AGP retry stops after a latched RS4xx GART refusal",
        agp_retry,
        (
            "radeon_fini(rdev)",
            "READ_ONCE(rdev->rs4xx_gart_fini_error)",
            "if (r)",
            "goto failed;",
            "radeon_agp_disable(rdev)",
            "r = radeon_init(rdev)",
        ),
    )
    rs400_init = function(root, "rs400.c", "rs400_init")
    require_order(
        "RS400 startup cleanup returns its GART refusal",
        rs400_init,
        (
            "r = rs400_startup(rdev)",
            "if (r)",
            "fini_r = rs400_gart_fini(rdev)",
            "if (fini_r)",
            "rdev->accel_working = false",
            "return fini_r;",
            "radeon_irq_kms_fini(rdev)",
        ),
    )
    unload = function(root, "radeon_kms.c", "radeon_driver_unload_kms")
    require_order(
        "unload converts GART teardown refusal to terminal retention",
        unload,
        (
            "r = radeon_device_fini(rdev)",
            "if (r && rs4xx_transition)",
            "radeon_rs4xx_finish_terminal_shutdown",
            "mutex_unlock(&rdev->rs4xx_unload_lock)",
            "return;",
            "radeon_rs4xx_hardware_transition_end",
        ),
    )


def check_open_source_boundaries(root: Path) -> None:
    tlb = function(root, "rs400.c", "rs400_gart_tlb_invalidate")
    require_order(
        "RS400 TLB issue and bounded poll structure",
        tlb,
        (
            "timeout = rdev->usec_timeout",
            "int r = -ETIMEDOUT;",
            "RS480_GART_CACHE_INVALIDATE",
            "r = 0;",
            "timeout--;",
            "while (timeout > 0)",
            "return r;",
        ),
    )
    flush = function(root, "rs400.c", "rs400_gart_tlb_flush")
    require_order(
        "RS400 TLB flush callback disposition",
        flush,
        (
            "rs400_gart_tlb_invalidate(rdev)",
            "r == -ETIMEDOUT",
            "atomic_inc(&rdev->rs4xx_gart_tlb_flush_timeouts)",
            "dev_warn_once",
        ),
    )
    enable = function(root, "rs400.c", "rs400_gart_enable")
    require_order(
        "RS400 GART enable publishes ready only after a completed invalidation",
        enable,
        (
            "RS480_GART_EN | size_reg",
            "r = rs400_gart_tlb_invalidate(rdev);",
            "if (r) {",
            "WREG32_MC(RS480_AGP_ADDRESS_SPACE_SIZE, 0);",
            "return r;",
            "rdev->gart.ready = true;",
        ),
    )
    disable = function(root, "rs400.c", "rs400_gart_disable")
    if "gart.ready" in disable:
        raise LifecycleError("suspend ready state row is no longer OPEN as recorded")
    suspend = function(root, "rs400.c", "rs400_suspend")
    if "rs400_gart_disable" not in suspend:
        raise LifecycleError("RS400 suspend no longer disables GART hardware")
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
    check_ttm_authority(root)
    check_build_and_callbacks(root)
    check_gart_source(root)
    check_ttm_population_contract(root)
    check_userptr_transaction(root)
    check_cpu_access_and_snapshot(root)
    check_bo_ttm_lifecycle(root)
    check_terminal_ownership(root)
    check_open_source_boundaries(root)
    check_sparse_model()


SOURCE_MUTATIONS = {
    "TTM authority changes its generic BO cleanup contract": (
        "policy/rs4xx-ttm-retention-authority.toml",
        'bo_release_successor = "invoke the driver destroy callback after generic cleanup"',
        'bo_release_successor = "skip the driver destroy callback"',
    ),
    "RS4xx terminal target admits a non-IGP backend": (
        "drivers/gpu/drm/radeon/radeon.h",
        (
            "return rdev && (rdev->flags & RADEON_IS_IGP) &&\n"
            "\t       (rdev->family == CHIP_RS400 || "
            "rdev->family == CHIP_RS480);"
        ),
        ("return rdev && (rdev->family == CHIP_RS400 || rdev->family == CHIP_RS480);"),
    ),
    "RS4xx IGP initialization retains the AGP backend": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        "\t\trdev->flags &= ~RADEON_IS_AGP;\n",
        "\t\trdev->flags |= RADEON_IS_AGP;\n",
    ),
    "PRIME import omits its SG ownership input": (
        "drivers/gpu/drm/radeon/radeon_prime.c",
        "RADEON_GEM_DOMAIN_GTT, 0, sg, resv, &bo);",
        "RADEON_GEM_DOMAIN_GTT, 0, NULL, resv, &bo);",
    ),
    "AGP imported SG admission is removed": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\tif (sg && (rdev->flags & RADEON_IS_AGP)) {\n",
        "\tif (false && sg && (rdev->flags & RADEON_IS_AGP)) {\n",
    ),
    "AGP imported SG admission is inverted": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\tif (sg && (rdev->flags & RADEON_IS_AGP)) {\n",
        "\tif (sg && !(rdev->flags & RADEON_IS_AGP)) {\n",
    ),
    "AGP imported SG admission follows BO allocation": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        (
            "\tif (sg && (rdev->flags & RADEON_IS_AGP)) {\n"
            "\t\tr = -EOPNOTSUPP;\n"
            "\t\tgoto out_transaction;\n"
            "\t}\n\n"
            "\tsize = ALIGN(size, PAGE_SIZE);"
        ),
        (
            "\tsize = ALIGN(size, PAGE_SIZE);\n\n"
            "\tif (sg && (rdev->flags & RADEON_IS_AGP)) {\n"
            "\t\tr = -EOPNOTSUPP;\n"
            "\t\tgoto out_transaction;\n"
            "\t}"
        ),
    ),
    "external SG population drops the defensive AGP refusal": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\tif (!gtt)\n\t\t\treturn -EOPNOTSUPP;\n",
        "\t\tif (!gtt)\n\t\t\treturn 0;\n",
    ),
    "external SG population inverts the defensive AGP refusal": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\tif (!gtt)\n\t\t\treturn -EOPNOTSUPP;\n",
        "\t\tif (gtt)\n\t\t\treturn -EOPNOTSUPP;\n",
    ),
    "external SG population restores deprecated page conversion": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\t\treturn -EOPNOTSUPP;",
        (
            "\t\t\treturn drm_prime_sg_to_page_array(ttm->sg, ttm->pages,\n"
            "\t\t\t\t\t\t  ttm->num_pages);"
        ),
    ),
    "Radeon imported SG population ignores conversion failure": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\t\treturn drm_prime_sg_to_dma_addr_array(ttm->sg,\n"
            "\t\t\t\t\t\t      gtt->ttm.dma_address,\n"
            "\t\t\t\t\t\t      ttm->num_pages);"
        ),
        (
            "\t\t(void)drm_prime_sg_to_dma_addr_array(ttm->sg,\n"
            "\t\t\t\t\t\t      gtt->ttm.dma_address,\n"
            "\t\t\t\t\t\t      ttm->num_pages);\n"
            "\t\treturn 0;"
        ),
    ),
    "terminal TTM retention drops the outer BO owner": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tretained_bo_count = radeon_rs4xx_retain_bo(gtt->rs4xx_owner);\n",
        "\tretained_bo_count = 0;\n",
    ),
    "terminal TTM retention drops transferred page accounting": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\t\t\tretained_page_count = atomic_long_add_return(\n"
            "\t\t\t\tgtt->ttm.num_pages,\n"
            "\t\t\t\t&rdev->rs4xx_retained_ttm_accounted_pages);"
        ),
        (
            "\t\t\tretained_page_count = atomic_long_read(\n"
            "\t\t\t\t&rdev->rs4xx_retained_ttm_accounted_pages);"
        ),
    ),
    "terminal TTM retention leaves accounting transferable twice": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\t\t\tgtt->rs4xx_ttm_pages_accounted = false;\n"
            "\t\t\t/* TTM clears its population accounting after this void\n"
        ),
        "\t\t\t/* TTM clears its population accounting after this void\n",
    ),
    "terminal userptr retention hides pages from generic retirement": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\t\tgtt->ttm.page_flags &= ~TTM_TT_FLAG_EXTERNAL;\n",
        "\t\t\tgtt->ttm.page_flags |= TTM_TT_FLAG_EXTERNAL;\n",
    ),
    "admission refusal drops terminal TTM retention": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
            "\t\tif (gtt && gtt->bound &&\n"
            "\t\t    radeon_rs4xx_hardware_target(rdev))\n"
            "\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);\n"
        ),
        "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n",
    ),
    "unbind refusal drops terminal TTM retention": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (r) {\n"
            "\t\tif (gtt && gtt->bound &&\n"
            "\t\t    radeon_rs4xx_hardware_target(rdev))\n"
            "\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);\n"
            "\t\treturn;\n"
            "\t}\n\n"
            "\tif (gtt && gtt->userptr) {"
        ),
        ("\tif (r)\n\t\treturn;\n\n\tif (gtt && gtt->userptr) {"),
    ),
    "TTM finalization drops retained page observation": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\t\tretained_accounted_pages = atomic_long_read(\n"
            "\t\t\t&rdev->rs4xx_retained_ttm_accounted_pages);\n"
        ),
        "\t\tretained_accounted_pages = 0;\n",
    ),
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
    "bind wrapper bypasses hardware admission": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        (
            "\tr = radeon_rs4xx_hardware_access_begin(rdev);\n"
            "\tif (r)\n\t\treturn r;\n"
            "\tmutex_lock(&rdev->gart.lock);\n"
            "\tr = radeon_gart_bind_locked"
        ),
        (
            "\tr = 0;\n"
            "\tif (r)\n\t\treturn r;\n"
            "\tmutex_lock(&rdev->gart.lock);\n"
            "\tr = radeon_gart_bind_locked"
        ),
    ),
    "bind wrapper drops table serialization": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        (
            "\tmutex_lock(&rdev->gart.lock);\n"
            "\tr = radeon_gart_bind_locked(rdev, offset, pages, pagelist, dma_addr,\n"
            "\t\t\t\t   flags);"
        ),
        (
            "\tr = radeon_gart_bind_locked(rdev, offset, pages, pagelist, dma_addr,\n"
            "\t\t\t\t   flags);"
        ),
    ),
    "unbind wrapper uses nonwaiting admission": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tr = radeon_rs4xx_hardware_access_wait_begin(rdev);",
        "\tr = radeon_rs4xx_hardware_access_begin(rdev);",
    ),
    "unbind wrapper drops hardware access release": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        (
            "\tr = radeon_gart_unbind_locked(rdev, offset, pages);\n"
            "\tmutex_unlock(&rdev->gart.lock);\n"
            "\tradeon_rs4xx_hardware_access_end(rdev);\n"
            "\treturn r;"
        ),
        (
            "\tr = radeon_gart_unbind_locked(rdev, offset, pages);\n"
            "\tmutex_unlock(&rdev->gart.lock);\n"
            "\treturn r;"
        ),
    ),
    "common finalization frees storage after unbind failure": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        (
            "\tif (rdev->gart.ready) {\n"
            "\t\t/* unbind pages */\n"
            "\t\tr = radeon_gart_unbind_locked(rdev, 0,\n"
            "\t\t\t\t\t      rdev->gart.num_cpu_pages);\n"
            "\t\tif (r)\n\t\t\tgoto out_unlock;\n"
            "\t}"
        ),
        (
            "\tif (rdev->gart.ready) {\n"
            "\t\t/* unbind pages */\n"
            "\t\tr = radeon_gart_unbind_locked(rdev, 0,\n"
            "\t\t\t\t\t      rdev->gart.num_cpu_pages);\n"
            "\t}"
        ),
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
            "\t\treturn -EINVAL;\n"
            "\t}"
        ),
        (
            "\tif (false) {\n"
            "\t\tif (!radeon_gart_range_valid(rdev, offset, pages)) {\n"
            '\t\t\tWARN(1, "invalid GART unbind range offset %u pages %d\\n",\n'
            "\t\t\t     offset, pages);\n"
            "\t\t\treturn -EINVAL;\n"
            "\t\t}\n"
            "\t}"
        ),
    ),
    "unbind range guard is bypassed by an earlier return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tif (!radeon_gart_range_valid(rdev, offset, pages)) {",
        ("\treturn 0;\n\tif (!radeon_gart_range_valid(rdev, offset, pages)) {"),
    ),
    "sparse unbind retains stale cursor": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\t\tt = p * (PAGE_SIZE / RADEON_GPU_PAGE_SIZE);\n",
        "",
    ),
    "bind flush precedes memory barrier": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        (
            "\t\tmb();\n\t\tradeon_gart_tlb_flush(rdev);\n\t}\n"
            "\treturn 0;\n}\n\nint radeon_gart_bind"
        ),
        (
            "\t\tradeon_gart_tlb_flush(rdev);\n\t\tmb();\n\t}\n"
            "\treturn 0;\n}\n\nint radeon_gart_bind"
        ),
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
        (
            "\tr = radeon_gart_unbind(rdev, gtt->offset, ttm->num_pages);\n"
            "\tif (r == -ESHUTDOWN && radeon_rs4xx_hardware_target(rdev))\n"
            "\t\tr = radeon_rs4xx_gart_teardown_wait(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
            "\t\tif (r == -EINVAL)\n"
            "\t\t\tdev_err_once(\n"
            "\t\t\t\trdev->dev,\n"
            '\t\t\t\t"RS4xx GART unbind invariant failure retains binding\\n");\n'
            "\t\telse\n"
            "\t\t\tdev_err_once(\n"
            "\t\t\t\trdev->dev,\n"
            '\t\t\t\t"RS4xx teardown refusal retains GART binding: %d\\n",\n'
            "\t\t\t\tr);\n"
            "\t\treturn r;\n\t}\n\n"
            "\tgtt->bound = false;\n\tif (gtt->userptr)\n"
            "\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n"
            "\treturn 0;"
        ),
        (
            "\tif (gtt->userptr)\n"
            "\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n"
            "\tr = radeon_gart_unbind(rdev, gtt->offset, ttm->num_pages);\n"
            "\tif (r == -ESHUTDOWN && radeon_rs4xx_hardware_target(rdev))\n"
            "\t\tr = radeon_rs4xx_gart_teardown_wait(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
            "\t\tif (r == -EINVAL)\n"
            "\t\t\tdev_err_once(\n"
            "\t\t\t\trdev->dev,\n"
            '\t\t\t\t"RS4xx GART unbind invariant failure retains binding\\n");\n'
            "\t\telse\n"
            "\t\t\tdev_err_once(\n"
            "\t\t\t\trdev->dev,\n"
            '\t\t\t\t"RS4xx teardown refusal retains GART binding: %d\\n",\n'
            "\t\t\t\tr);\n"
            "\t\treturn r;\n\t}\n\n\tgtt->bound = false;"
        ),
    ),
    "TTM backend clears bound state after RS4xx unbind refusal": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tif (r && radeon_rs4xx_hardware_target(rdev)) {",
        "\tif (false && r && radeon_rs4xx_hardware_target(rdev)) {",
    ),
    "TTM unpopulate bypasses wait-capable admission": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tr = radeon_rs4xx_hardware_transaction_wait_begin(rdev);\n",
        "\tr = 0;\n",
    ),
    "TTM unpopulate ignores completed GART shutdown": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (r == -ESHUTDOWN)\n"
            "\t\tr = radeon_rs4xx_gart_teardown_wait(rdev);\n"
            "\telse if (r == 0)\n"
            "\t\thardware_transaction = true;\n"
        ),
        ("\tif (r == 0)\n\t\thardware_transaction = true;\n"),
    ),
    "TTM unpopulate forgets admitted transaction ownership": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\telse if (r == 0)\n\t\thardware_transaction = true;\n",
        "\telse if (r == 0)\n\t\thardware_transaction = false;\n",
    ),
    "TTM unpopulate omits refusal latch": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (r) {\n"
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
            "\t\tif (gtt && gtt->bound &&\n"
            "\t\t    radeon_rs4xx_hardware_target(rdev))\n"
            "\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);\n"
            "\t\treturn;\n"
            "\t}\n"
        ),
        (
            "\tif (r) {\n"
            "\t\tif (gtt && gtt->bound &&\n"
            "\t\t    radeon_rs4xx_hardware_target(rdev))\n"
            "\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);\n"
            "\t\treturn;\n"
            "\t}\n"
        ),
    ),
    "TTM unpopulate releases admission before unbind": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tr = radeon_ttm_tt_unbind_status(bdev, ttm);\n"
            "\tif (hardware_transaction)\n"
            "\t\tradeon_rs4xx_hardware_transaction_end(rdev);\n"
        ),
        (
            "\tif (hardware_transaction)\n"
            "\t\tradeon_rs4xx_hardware_transaction_end(rdev);\n"
            "\tr = radeon_ttm_tt_unbind_status(bdev, ttm);\n"
        ),
    ),
    "TTM unpopulate leaks admitted transaction ownership": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (hardware_transaction)\n"
            "\t\tradeon_rs4xx_hardware_transaction_end(rdev);\n"
        ),
        "",
    ),
    "TTM unpopulate releases storage after unbind refusal": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (r) {\n"
            "\t\tif (gtt && gtt->bound &&\n"
            "\t\t    radeon_rs4xx_hardware_target(rdev))\n"
            "\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);\n"
            "\t\treturn;\n"
            "\t}\n\n"
            "\tif (gtt && gtt->userptr) {\n"
        ),
        (
            "\tif (false && r) {\n"
            "\t\tif (gtt && gtt->bound &&\n"
            "\t\t    radeon_rs4xx_hardware_target(rdev))\n"
            "\t\t\tradeon_rs4xx_retain_ttm(rdev, gtt);\n"
            "\t\treturn;\n"
            "\t}\n\n"
            "\tif (gtt && gtt->userptr) {\n"
        ),
    ),
    "TTM unbound populated cleanup enters hardware admission": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tif (gtt && !gtt->bound) {",
        "\tif (false && gtt && !gtt->bound) {",
    ),
    "TTM unbound userptr cleanup skips page release": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (gtt && !gtt->bound) {\n"
            "\t\tif (gtt->userptr) {\n"
            "\t\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n"
        ),
        ("\tif (gtt && !gtt->bound) {\n\t\tif (gtt->userptr) {\n"),
    ),
    "TTM unbound userptr cleanup releases pages twice": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (gtt && !gtt->bound) {\n"
            "\t\tif (gtt->userptr) {\n"
            "\t\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n"
        ),
        (
            "\tif (gtt && !gtt->bound) {\n"
            "\t\tif (gtt->userptr) {\n"
            "\t\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n"
            "\t\t\tradeon_ttm_tt_unpin_userptr(bdev, ttm);\n"
        ),
    ),
    "TTM destroy releases a bound translation table": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tif (gtt && gtt->bound && radeon_rs4xx_hardware_target(rdev)) {",
        ("\tif (false && gtt && gtt->bound && radeon_rs4xx_hardware_target(rdev)) {"),
    ),
    "TTM bound refusal drops retained translation table": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\t\tlist_add_tail(&gtt->rs4xx_retained_node,\n"
            "\t\t\t      &rdev->rs4xx_retained_ttm_tables_list);\n"
        ),
        "",
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
        (
            "\t(void)radeon_bo_fault_reserve_notify(bo);\n"
            "\tret = ttm_bo_vm_reserve(bo, vmf);"
        ),
    ),
    "fault bypasses hardware transaction admission": (
        "drivers/gpu/drm/radeon/radeon_gem.c",
        "\tif (radeon_rs4xx_hardware_transaction_begin(rdev)) {",
        "\tif (false && radeon_rs4xx_hardware_transaction_begin(rdev)) {",
    ),
    "reader drops lifetime lock": (
        "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
        "\tmutex_lock(&rdev->gart.lock);\n\tif (!rdev->gart.ready || !rdev->gart.ptr) {",
        "\tif (!rdev->gart.ready || !rdev->gart.ptr) {",
    ),
    "reader bypasses hardware transaction admission": (
        "drivers/gpu/drm/radeon/radeon_rs4xx_dev.c",
        '\tif (radeon_device_lock_hardware(rdev)) {\n\t\tseq_puts(m, "metadata',
        '\tif (false && radeon_device_lock_hardware(rdev)) {\n\t\tseq_puts(m, "metadata',
    ),
    "TTM move drops reservation wait before bind": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tr = ttm_bo_wait_ctx(bo, ctx);\n",
        "\t/* reservation wait removed */\n",
    ),
    "TTM move drops newly bound rollback": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tif (r && newly_bound) {",
        "\tif (false && r && newly_bound) {",
    ),
    "TTM initial move escapes after bind": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (!old_mem || (old_mem->mem_type == TTM_PL_SYSTEM &&\n"
            "\t\t\t bo->ttm == NULL)) {\n"
            "\t\tttm_bo_move_null(bo, new_mem);\n"
            "\t\tgoto out;\n"
            "\t}\n"
        ),
        (
            "\tif (!old_mem || (old_mem->mem_type == TTM_PL_SYSTEM &&\n"
            "\t\t\t bo->ttm == NULL)) {\n"
            "\t\tttm_bo_move_null(bo, new_mem);\n"
            "\t\tgoto out_transaction;\n"
            "\t}\n"
        ),
    ),
    "BO creation drops provisional lifetime count": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\t\tbo->rs4xx_lifetime_counted = true;\n",
        "",
    ),
    "BO destruction drops final lifetime decrement": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\tif (lifetime_counted &&\n\t    atomic_dec_and_test(&rdev->rs4xx_live_bos))",
        "\tif (false && lifetime_counted &&\n\t    atomic_dec_and_test(&rdev->rs4xx_live_bos))",
    ),
    "BO destruction drops final lifetime wake": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n",
        "",
    ),
    "BO creation bypasses transaction root": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\tr = radeon_rs4xx_hardware_transaction_begin(rdev);\n",
        "\tr = 0;\n",
    ),
    "GEM destruction bypasses transaction root": (
        "drivers/gpu/drm/radeon/radeon_gem.c",
        "\t\tret = radeon_rs4xx_hardware_transaction_wait_begin(rdev);",
        "\t\tret = 0;",
    ),
    "GEM debugfs disables retained and detached guards": (
        "drivers/gpu/drm/radeon/radeon_gem.c",
        (
            "\t\tif (READ_ONCE(rbo->rs4xx_terminally_retained)) {\n"
            '\t\t\tplacement = "RETAINED";\n'
            "\t\t} else if (!rbo->tbo.resource) {"
        ),
        (
            "\t\tif (false && READ_ONCE(rbo->rs4xx_terminally_retained)) {\n"
            '\t\t\tplacement = "RETAINED";\n'
            "\t\t} else if (false && !rbo->tbo.resource) {"
        ),
    ),
    "GEM debugfs reads placement before retained disposition": (
        "drivers/gpu/drm/radeon/radeon_gem.c",
        "\t\tif (READ_ONCE(rbo->rs4xx_terminally_retained)) {\n",
        (
            "\t\tdomain = radeon_mem_type_to_domain(\n"
            "\t\t\trbo->tbo.resource->mem_type);\n"
            "\t\tif (READ_ONCE(rbo->rs4xx_terminally_retained)) {\n"
        ),
    ),
    "TTM BO destruction bypasses transaction root": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\t\t\tr = radeon_rs4xx_hardware_transaction_wait_begin(rdev);",
        "\t\t\tr = 0;",
    ),
    "TTM finalization pre-drains external-fence work": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tif (!rdev->mman.initialized)\n\t\treturn 0;\n",
        "\tdrain_workqueue(rdev->mman.bdev.wq);\n\tif (!rdev->mman.initialized)\n\t\treturn 0;\n",
    ),
    "TTM finalization omits live BO veto": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (live_bos != 0 || retained_bos != 0 || retained_tables != 0 ||\n"
            "\t    retained_accounted_pages != 0 || transactions != 0 || readers != 0) {"
        ),
        (
            "\tif (retained_bos != 0 || retained_tables != 0 ||\n"
            "\t    retained_accounted_pages != 0 || transactions != 0 || readers != 0) {"
        ),
    ),
    "TTM finalization omits retained BO veto": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tif (live_bos != 0 || retained_bos != 0 || retained_tables != 0 ||\n",
        "\tif (live_bos != 0 || retained_tables != 0 ||\n",
    ),
    "TTM finalization omits retained page veto": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t    retained_accounted_pages != 0 || transactions != 0 || readers != 0) {",
        "\t    transactions != 0 || readers != 0) {",
    ),
    "TTM finalization omits transaction veto": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t    retained_accounted_pages != 0 || transactions != 0 || readers != 0) {",
        "\t    retained_accounted_pages != 0 || readers != 0) {",
    ),
    "TTM finalization omits reader veto": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t    retained_accounted_pages != 0 || transactions != 0 || readers != 0) {",
        "\t    retained_accounted_pages != 0 || transactions != 0) {",
    ),
    "TTM finalization drops result propagation": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\t\tWRITE_ONCE(rdev->rs4xx_ttm_fini_error, r);\n",
        "",
    ),
    "BO destruction releases imported attachment on refusal": (
        "drivers/gpu/drm/radeon/radeon_object.c",
        "\t\tdrm_prime_gem_destroy(&bo->tbo.base, bo->tbo.sg);\n",
        "",
    ),
    "RS400 publishes completion before aperture disable": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tif (r)\n\t\treturn r;\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);\n"
            "\tif (radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, 0);\n"
            "\t\t/* The release publishes aperture disable and table storage removal. */\n"
            "\t\tsmp_store_release(&rdev->rs4xx_gart_teardown_complete, true);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
        ),
        (
            "\tif (r)\n\t\treturn r;\n"
            "\tif (radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, 0);\n"
            "\t\t/* The release publishes aperture disable and table storage removal. */\n"
            "\t\tsmp_store_release(&rdev->rs4xx_gart_teardown_complete, true);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);\n"
        ),
    ),
    "RS400 finalization ignores common teardown refusal": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\trs400_gart_disable(rdev);"
        ),
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\trs400_gart_disable(rdev);"
        ),
    ),
    "RS400 finalization hardware disable is conditionally disabled": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\tif (false)\n"
            "\t\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
    ),
    "unbind declaration hides a statement-expression return": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "\tunsigned int t, p;\n\tint i, j;\n\n",
        ("\tunsigned int t, p;\n\tint i = ({ return 0; 0; }), j;\n\n"),
    ),
    "RS400 finalization hardware disable is nested in a scope": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\t{\n"
            "\t\trs400_gart_disable(rdev);\n"
            "\t}\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
    ),
    "RS400 finalization drops hardware disable": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
    ),
    "RS400 finalization releases table before hardware disable": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\trs400_gart_disable(rdev);\n"
            "\tradeon_gart_table_ram_free(rdev);"
        ),
        (
            "\tr = radeon_gart_fini(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
            "\tif (r)\n\t\treturn r;\n"
            "\tradeon_gart_table_ram_free(rdev);\n"
            "\trs400_gart_disable(rdev);"
        ),
    ),
    "GART initialization retains stale teardown completion": (
        "drivers/gpu/drm/radeon/radeon_gart.c",
        "smp_store_release(&rdev->rs4xx_gart_teardown_complete, false);",
        "smp_store_release(&rdev->rs4xx_gart_teardown_complete, true);",
    ),
    "common finalization drops teardown completion publication": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tif (radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, 0);\n"
            "\t\t/* The release publishes aperture disable and table storage removal. */\n"
            "\t\tsmp_store_release(&rdev->rs4xx_gart_teardown_complete, true);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
        ),
        "",
    ),
    "completed global teardown still reaches hardware unbind": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (radeon_rs4xx_hardware_target(rdev) &&\n"
            "\t    radeon_rs4xx_gart_teardown_is_complete(rdev)) {"
        ),
        (
            "\tif (false && radeon_rs4xx_hardware_target(rdev) &&\n"
            "\t    radeon_rs4xx_gart_teardown_is_complete(rdev)) {"
        ),
    ),
    "unbind failure leaves later hardware admission open": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n"
        ),
        "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n",
    ),
    "TTM create leaves retention node uninitialized": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        "\tINIT_LIST_HEAD(&gtt->rs4xx_retained_node);\n",
        "",
    ),
    "TTM retention drops its device list owner": (
        "drivers/gpu/drm/radeon/radeon_ttm.c",
        (
            "\t\tlist_add_tail(&gtt->rs4xx_retained_node,\n"
            "\t\t\t      &rdev->rs4xx_retained_ttm_tables_list);\n"
        ),
        "",
    ),
    "GEM retention leaves later hardware admission open": (
        "drivers/gpu/drm/radeon/radeon_gem.c",
        "\t\t\tradeon_rs4xx_latch_teardown_refusal(rdev);\n",
        "",
    ),
    "hardware fault latch keeps GPU admission open": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tWRITE_ONCE(rdev->gpu_parked, true);\n"
            "\tWRITE_ONCE(rdev->accel_working, false);\n"
        ),
        (
            "\tWRITE_ONCE(rdev->gpu_parked, false);\n"
            "\tWRITE_ONCE(rdev->accel_working, false);\n"
        ),
    ),
    "parked publication latch loses its pending request": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
        ),
        (
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
        ),
    ),
    "parked publication latch loses its queue request": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
        ),
        (
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
        ),
    ),
    "parked publication latch gains blocking cleanup": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
        ),
        (
            "\tradeon_rs4xx_latch_parked_state(rdev);\n"
            "\t(void)radeon_page_flip_quiesce(rdev);\n"
            "\tatomic_xchg(&rdev->rs4xx_parked_publish_pending, 1);\n"
            "\tradeon_rs4xx_queue_parked_publish(rdev);\n"
        ),
    ),
    "teardown refusal bypasses parked publication": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        "\tradeon_rs4xx_latch_parked_publication(rdev);",
        "\tradeon_rs4xx_latch_parked_state(rdev);",
    ),
    "parked publication escapes the state lock": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tatomic_set_release(&rdev->rs4xx_hardware_closing, 1);\n"
            "\tradeon_rs4xx_publish_parked_hardware_state_locked(rdev);\n"
            "\tspin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);\n"
        ),
        (
            "\tatomic_set_release(&rdev->rs4xx_hardware_closing, 1);\n"
            "\tspin_unlock_irqrestore(&rdev->rs4xx_hardware_state_lock, irqflags);\n"
            "\tradeon_rs4xx_publish_parked_hardware_state_locked(rdev);\n"
        ),
    ),
    "retained TTM denominator lacks initialization": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        "\tatomic_set(&rdev->rs4xx_retained_ttm_tables, 0);\n",
        "",
    ),
    "RS400 finalizer drops its result latch": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tif (r && radeon_rs4xx_hardware_target(rdev)) {\n"
            "\t\tWRITE_ONCE(rdev->rs4xx_gart_fini_error, r);\n"
            "\t\twake_up_all(&rdev->rs4xx_hardware_wait);\n"
            "\t}\n"
        ),
        "",
    ),
    "RS400 finalization enters cleanup with a prior GART refusal": (
        "drivers/gpu/drm/radeon/rs400.c",
        ("\tif (radeon_rs4xx_terminal_ownership_retained(rdev))\n\t\treturn;\n\n"),
        "",
    ),
    "RS400 GEM deletion precedes global GART disposition": (
        "drivers/gpu/drm/radeon/rs400.c",
        (
            "\tr = rs400_gart_fini(rdev);\n"
            "\tif (r)\n"
            "\t\treturn;\n"
            "\tif (radeon_rs4xx_terminal_ownership_retained(rdev))\n"
            "\t\treturn;\n"
            "\tradeon_gem_fini(rdev);\n"
        ),
        (
            "\tradeon_gem_fini(rdev);\n"
            "\tr = rs400_gart_fini(rdev);\n"
            "\tif (r)\n"
            "\t\treturn;\n"
            "\tif (radeon_rs4xx_terminal_ownership_retained(rdev))\n"
            "\t\treturn;\n"
        ),
    ),
    "device finalization ignores a preexisting GART refusal": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tr = radeon_rs4xx_terminal_ownership_error(rdev);\n"
            "\tif (r)\n"
            "\t\treturn r;\n\n"
            "\tDRM_INFO"
        ),
        "\tDRM_INFO",
    ),
    "device finalization ignores VRAM eviction refusal": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tradeon_rs480_panic_unregister(rdev);\n"
            "\t/* evict vram memory */\n"
            "\tr = radeon_bo_evict_vram(rdev);\n"
            "\tif (r && radeon_rs4xx_hardware_target(rdev))\n"
            "\t\treturn r;\n"
            "\tr = radeon_rs4xx_terminal_ownership_error(rdev);\n"
            "\tif (r)\n"
            "\t\treturn r;\n"
            "\tradeon_audio_component_fini(rdev);\n"
        ),
        (
            "\tradeon_rs480_panic_unregister(rdev);\n"
            "\t/* evict vram memory */\n"
            "\tradeon_bo_evict_vram(rdev);\n"
            "\tradeon_audio_component_fini(rdev);\n"
        ),
    ),
    "device finalization ignores a new GART refusal": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\tradeon_fini(rdev);\n"
            "\tr = radeon_rs4xx_terminal_ownership_error(rdev);\n"
            "\tif (r)\n"
            "\t\treturn r;\n"
        ),
        "\tradeon_fini(rdev);\n",
    ),
    "AGP retry continues after a GART refusal": (
        "drivers/gpu/drm/radeon/radeon_device.c",
        (
            "\t\tradeon_fini(rdev);\n"
            "\t\tr = READ_ONCE(rdev->rs4xx_gart_fini_error);\n"
            "\t\tif (r)\n"
            "\t\t\tgoto failed;\n"
            "\t\tradeon_agp_disable(rdev);\n"
        ),
        ("\t\tradeon_fini(rdev);\n\t\tradeon_agp_disable(rdev);\n"),
    ),
    "RS400 startup cleanup hides its GART refusal": (
        "drivers/gpu/drm/radeon/rs400.c",
        "\t\t\treturn fini_r;\n",
        "\t\t\treturn 0;\n",
    ),
    "unload ignores the device finalization result": (
        "drivers/gpu/drm/radeon/radeon_kms.c",
        "\tr = radeon_device_fini(rdev);\n",
        "\tradeon_device_fini(rdev);\n",
    ),
    "unload disables terminal retention after a GART refusal": (
        "drivers/gpu/drm/radeon/radeon_kms.c",
        ("\tr = radeon_device_fini(rdev);\n\tif (r && rs4xx_transition) {\n"),
        ("\tr = radeon_device_fini(rdev);\n\tif (false && r && rs4xx_transition) {\n"),
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
        "GART finalization direct teardown sequence: direct statement 4 differs"
    ),
    "RS400 finalization hardware disable is nested in a scope": (
        "GART finalization direct teardown sequence: direct statement 4 differs"
    ),
    "RS400 finalization drops hardware disable": (
        "GART finalization direct teardown sequence: direct statement count 7 != 8"
    ),
    "RS400 finalization releases table before hardware disable": (
        "GART finalization direct teardown sequence: direct statement 4 differs"
    ),
}

POLICY_MUTATIONS = {
    "repaired userptr row promoted to proven": (
        "USERPTR_PIN_DMA_MAP_TRANSACTION\t",
        6,
        "proven",
        "USERPTR_PIN_DMA_MAP_TRANSACTION: source_status proven != repaired",
    ),
    "repaired userspace fault row promoted to proven": (
        "USER_MMAP_FAULT_RESERVATION\t",
        6,
        "proven",
        "USER_MMAP_FAULT_RESERVATION: source_status proven != repaired",
    ),
    "repaired GART reader row promoted to proven": (
        "GART_TABLE_READER_SNAPSHOT_BOUNDARY\t",
        6,
        "proven",
        "GART_TABLE_READER_SNAPSHOT_BOUNDARY: source_status proven != repaired",
    ),
    "repaired common teardown row promoted to proven": (
        "GART_COMMON_TEARDOWN\t",
        6,
        "proven",
        "GART_COMMON_TEARDOWN: source_status proven != repaired",
    ),
    "repaired GART error propagation row reopened": (
        "RS4XX_GART_TEARDOWN_ERROR_PROPAGATION\t",
        6,
        "open",
        "RS4XX_GART_TEARDOWN_ERROR_PROPAGATION: source_status open != repaired",
    ),
    "repaired suspend row reopened": (
        "GART_SUSPEND_READY_STATE\t",
        6,
        "open",
        "GART_SUSPEND_READY_STATE: source_status open != repaired",
    ),
    "repaired backend unbind row reopened": (
        "GART_BACKEND_NOT_READY_UNBIND_STATE\t",
        6,
        "open",
        "GART_BACKEND_NOT_READY_UNBIND_STATE: source_status open != repaired",
    ),
    "repaired TTM teardown row reopened": (
        "GART_TTM_TEARDOWN_OWNERSHIP\t",
        6,
        "open",
        "GART_TTM_TEARDOWN_OWNERSHIP: source_status open != repaired",
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
    "TLB flush runtime status leaves the declared vocabulary": (
        "RS400_TLB_FLUSH_COMPLETION\t",
        10,
        "hardware-pass",
        "RS400_TLB_FLUSH_COMPLETION: invalid runtime_status",
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
    "GART error propagation loses common teardown dependency": (
        "RS4XX_GART_TEARDOWN_ERROR_PROPAGATION\t",
        5,
        "GART_UNBIND_PTE_MB_TLB_PUBLICATION",
        "RS4XX_GART_TEARDOWN_ERROR_PROPAGATION: dependency edge differs",
    ),
    "TTM teardown loses table release owner": (
        "GART_TTM_TEARDOWN_OWNERSHIP\t",
        5,
        "GART_COMMON_TEARDOWN;GART_BACKEND_NOT_READY_UNBIND_STATE;RS4XX_GART_TEARDOWN_ERROR_PROPAGATION",
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
    lines = path.read_text(encoding="utf-8").splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(row_prefix)]
    if len(matches) != 1:
        raise LifecycleError(
            f"selftest policy row match count for {row_prefix}: {matches}"
        )
    fields = lines[matches[0]].split("\t")
    fields[field_index] = value
    lines[matches[0]] = "\t".join(fields)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
            text = path.read_text(encoding="utf-8")
            if text.count(old) != 1:
                print(f"selftest fixture error for {label}", file=sys.stderr)
                failures += 1
                continue
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
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
