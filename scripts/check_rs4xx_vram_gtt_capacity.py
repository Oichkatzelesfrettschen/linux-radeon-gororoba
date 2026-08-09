#!/usr/bin/env python3
"""Prove the finite RS482 VRAM and GTT capacity source contract."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import math
import re
import sys
from pathlib import Path

from check_radeon_gart_lifecycle import c_tokens, function

POLICY = Path("policy/rs4xx-vram-gtt-capacity-contract.tsv")
MATRIX = Path("policy/rs482-gtt-capacity-matrix.tsv")
EXCLUSIONS = Path("policy/rs482-gtt-capacity-exclusions.tsv")
SUBTREE = Path("drivers/gpu/drm/radeon")

POLICY_HEADER = (
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
    "measurement_surface",
    "optimization_effect",
    "runtime_status",
    "silicon_status",
    "nonclaim",
)
MATRIX_HEADER = (
    "config_id",
    "gtt_mib",
    "vram_mib",
    "size_code_hex",
    "enabled_value_hex",
    "cpu_pages_4k",
    "gpu_pages_4k",
    "hardware_table_bytes",
    "cpu_page_pointer_bytes_x86_64",
    "pte_shadow_bytes",
    "static_metadata_bytes",
    "auto_default_rs482",
    "model_scope",
    "effective_capacity_status",
    "source_status",
    "nonclaim",
)
EXCLUSION_HEADER = (
    "selector",
    "source_disposition",
    "denominator_disposition",
    "reason",
    "reactivation_condition",
)

EXPECTED_ROWS = {
    "RS482_GTT_PARAMETER_ADMISSION": ("proven", "NONE"),
    "RS482_GTT_SIZE_REGISTER_ENCODING": (
        "proven",
        "RS482_GTT_PARAMETER_ADMISSION",
    ),
    "RS482_GTT_ADDRESS_PLACEMENT": (
        "proven",
        "RS482_GTT_SIZE_REGISTER_ENCODING",
    ),
    "RS482_GART_METADATA_CAPACITY": (
        "proven",
        "RS482_GTT_SIZE_REGISTER_ENCODING",
    ),
    "RS482_VRAM_CARVEOUT_ACCOUNTING": ("proven", "NONE"),
    "RADEON_VRAMLIMIT_TEST_BOUNDARY": (
        "proven",
        "RS482_VRAM_CARVEOUT_ACCOUNTING",
    ),
    "RADEON_TTM_MANAGER_CAPACITY": (
        "proven",
        "RS482_GART_METADATA_CAPACITY;RS482_VRAM_CARVEOUT_ACCOUNTING",
    ),
    "RADEON_BO_DOMAIN_PLACEMENT_ORDER": (
        "proven",
        "RADEON_TTM_MANAGER_CAPACITY",
    ),
    "RADEON_VRAM_RELOCATION_THRESHOLD": (
        "proven",
        "RADEON_BO_DOMAIN_PLACEMENT_ORDER",
    ),
    "RADEON_SINGLE_BO_GTT_CEILING": (
        "proven",
        "RADEON_TTM_MANAGER_CAPACITY",
    ),
    "RADEON_PINNED_CAPACITY_ACCOUNTING": (
        "proven",
        "RADEON_TTM_MANAGER_CAPACITY",
    ),
    "RADEON_CAPACITY_USAGE_AND_MOVE_COUNTERS": (
        "proven",
        "RADEON_TTM_MANAGER_CAPACITY;RADEON_VRAM_RELOCATION_THRESHOLD;RADEON_PINNED_CAPACITY_ACCOUNTING",
    ),
    "RADEON_FRAGMENTATION_AND_PLACEMENT_DEBUGFS": (
        "proven",
        "RADEON_TTM_MANAGER_CAPACITY;RADEON_BO_DOMAIN_PLACEMENT_ORDER",
    ),
    "RS482_CAPACITY_OPTIMUM": (
        "open",
        "RS482_GTT_ADDRESS_PLACEMENT;RS482_GART_METADATA_CAPACITY;RADEON_VRAM_RELOCATION_THRESHOLD;RADEON_SINGLE_BO_GTT_CEILING;RADEON_CAPACITY_USAGE_AND_MOVE_COUNTERS;RADEON_FRAGMENTATION_AND_PLACEMENT_DEBUGFS",
    ),
}

EXPECTED_POLICY_ROW_SHA256 = {
    "RS482_GTT_PARAMETER_ADMISSION": "44bb9d04370f32f7fdab5c33c3c4827c38fd88d267ea862183181412de11baa9",
    "RS482_GTT_SIZE_REGISTER_ENCODING": "f99e7ebd03d94da771b97d4711c27923022e9c3ec0179ee4c1b1be96c9d181a2",
    "RS482_GTT_ADDRESS_PLACEMENT": "6d46ffc6d5e6c208319b36d30f76ace0b6730da2d6c301da8ca2cd8960c47aba",
    "RS482_GART_METADATA_CAPACITY": "6d5e1b5048dcc636dbe1757b73bfbd7811e6bdc12453647cf85b14adaab83402",
    "RS482_VRAM_CARVEOUT_ACCOUNTING": "9f41fe42c2c7c53140bbce4b24077f41484f45151a9251271a4595e2610f8bd9",
    "RADEON_VRAMLIMIT_TEST_BOUNDARY": "aea5c9c151ac8ebb3ed59856a8acffd4f49d28b0f299598602a94264ab7bc6ab",
    "RADEON_TTM_MANAGER_CAPACITY": "8dc1e686175636c921c8c0d8ca5ea079752760f2b66cce8f1f28ca7773fb9cea",
    "RADEON_BO_DOMAIN_PLACEMENT_ORDER": "657a9e64615767e0254374811e566df348b7cfdb81639935caa0426f0be71c20",
    "RADEON_VRAM_RELOCATION_THRESHOLD": "ba4bd84e9a1329e160d592b1c1c78fd27e19fcb0a6746dfe3926055ed7eaf400",
    "RADEON_SINGLE_BO_GTT_CEILING": "a645a5242abf8c476cb4edf9553f75904f9f385de1f7d7f9acdc45ec64c742d1",
    "RADEON_PINNED_CAPACITY_ACCOUNTING": "9cf1efacfd711de4768082431deea53356573264f750c41ffabc3cfd658b6e1b",
    "RADEON_CAPACITY_USAGE_AND_MOVE_COUNTERS": "9c036a0268ca817b148053bcd7ed4d3f40b139f4b4f7b95825401deb37b5b605",
    "RADEON_FRAGMENTATION_AND_PLACEMENT_DEBUGFS": "3bd8c58c62b276f2eed3a5f78805d8a8047245d5ee47b15c1678a694201f1230",
    "RS482_CAPACITY_OPTIMUM": "8d21e52e33be126df2ded1edfca87831f9de0dd71e59f37220cf636fd210b0e8",
}

EXPECTED_FUNCTION_SHA256 = {
    (
        "radeon_device.c",
        "radeon_gart_size_auto",
    ): "c7a740ca8f7d5551fe6e6828949950cb82694e7d6fbb4ac94583a319f90ae75e",
    (
        "radeon_device.c",
        "radeon_check_arguments",
    ): "b674226cd846143a77e78d3a92564862625e1b205992210c4bcb1a82ee6c3141",
    (
        "radeon_device.c",
        "radeon_device_init",
    ): "fb7e859a1d8502aba6877591350c29c1ef6420316d6b73429e6f5c4145955632",
    (
        "radeon_device.c",
        "radeon_vram_location",
    ): "eb6b6a4ed8e8228e7cc60f6be53bfbb0cdcc28c4845dfc483a56db39a6520364",
    (
        "radeon_device.c",
        "radeon_gtt_location",
    ): "414a14f3d3313ceadba193ae868c9d7bfaee2e9da69d729fa4f3a9ca4cad3f96",
    (
        "rs400.c",
        "rs400_gart_adjust_size",
    ): "03a49a956c1c470c22b96a72ddd381f54865a3c5ef8a2ebdccf2f323efff45b6",
    (
        "rs400.c",
        "rs400_gart_init",
    ): "3096d46cd531c0cfad4b720ff828a5c195f785fc822528cf9bfa04c8e0586c7c",
    (
        "rs400.c",
        "rs400_gart_enable",
    ): "f97178ed96047ce6b23560a5a43b27f00bb3a2bbbe0816f655e58cefb611fe69",
    (
        "rs400.c",
        "rs400_mc_init",
    ): "f6e2a10061197814dffc5f5457beb458588d4512026de713658ef0005062b845",
    (
        "radeon_gart.c",
        "radeon_gart_init",
    ): "3efae848cc1b40c5236e1ca226c824e89c67d47af310607e01024d5f18c926e6",
    (
        "r100.c",
        "r100_vram_init_sizes",
    ): "e6dbe5f04722595d7e0ba7ff675d70ddc51443539a4702de9c11aacf19e40405",
    (
        "radeon_ttm.c",
        "radeon_ttm_init_vram",
    ): "48219b49f90159e65b6b89b3e4f0da9e1470f8bae6d21e930c47f55f17eb2694",
    (
        "radeon_ttm.c",
        "radeon_ttm_init_gtt",
    ): "df42cf8a9529bacfd5c0c183039660e63fa1e5e7bb2076f63ee375872a892cf5",
    (
        "radeon_ttm.c",
        "radeon_ttm_set_active_vram_size",
    ): "a26f3bb32cc7a1049345d8f3db0f0e68a22a90386d8e396486e3d2ef7c7c9c32",
    (
        "radeon_ttm.c",
        "radeon_ttm_init",
    ): "3ebb3aa30d5c295bdf94e6006411955c9b1d2d0d0ab98916786ef5d2714c56bd",
    (
        "radeon_ttm.c",
        "radeon_ttm_debugfs_init",
    ): "93221ca4be1de9a8c1a07572c10dc47f86365d46d752e5b754e6c642de6437de",
    (
        "radeon_object.c",
        "radeon_ttm_placement_from_domain",
    ): "22bf293354a70e67e8ac423acb0e499a7f2683a8998bced9abf721b46f10af9b",
    (
        "radeon_object.c",
        "radeon_bo_get_threshold_for_moves",
    ): "42450c55eb8bf425a71197cced2a6d214812934b48d7d737742d6539436717ae",
    (
        "radeon_object.c",
        "radeon_bo_list_validate",
    ): "46b510c720046b1222276c53427b40e442989cabc44b96a21d530139aef5eca5",
    (
        "radeon_object.c",
        "radeon_bo_pin_restricted",
    ): "1e1eec1738827219863d0fc73addb08f03bcf0c0b68b3ea6997def1821d9fb00",
    (
        "radeon_object.c",
        "radeon_bo_unpin",
    ): "f1714a34bffc347910f0d997ea4b36e411b8129cdad4df5134512e78deafa880",
    (
        "radeon_gem.c",
        "radeon_gem_object_create",
    ): "e9290b1846cb58447116400e5aa40baf27dc95691249eb87c10bc7b5e6181989",
    (
        "radeon_gem.c",
        "radeon_gem_info_ioctl",
    ): "99d784c93792e20a74d890c10decd3f5bed1de3c48e3b0e589df68d0449676b9",
    (
        "radeon_gem.c",
        "radeon_debugfs_gem_info_show",
    ): "5e4f70df5ace40929431124da928dba0da2bc25e6794e995a61c47eff439553e",
    (
        "radeon_kms.c",
        "radeon_info_ioctl",
    ): "a78028871b0a4c9eb3dc1587453e0735a54f02fe4d86efbebb6bb4eaedca3815",
}

EXPECTED_EXCLUSION_SELECTORS = {
    "32MiB",
    "64MiB",
    "2048MiB",
    "non-power-of-two",
    "raw-radeon-vram-gtt-debugfs",
    "vramlimit-below-firmware-carveout",
}
EXPECTED_EXCLUSION_ROW_SHA256 = {
    "32MiB": "9e2fff751144a8a4c8a59e1a71650e7de720fcbf97ca3ec9c7b835db7a766d68",
    "64MiB": "514fc9c9908c60209d469726ee6a185adb794dd0426d323c537e3fbb0e51dc3f",
    "2048MiB": "7cd62ba7247a886966f86f4ec28f718bd45a49ff8a2908596eb62fe96a784489",
    "non-power-of-two": "2ead101fa9a432cba51170187b7ea10ff5bb13da5ab9b9d94d1a98fa270066c9",
    "vramlimit-below-firmware-carveout": "69f2238612c908885fbaa4d7d9b550345458ff9214ab5e9af28fd6d71ba8bf7f",
    "raw-radeon-vram-gtt-debugfs": "32b6d663f38b298c99f753414aa444084c93bdf55b91a2b29581f17a155f459b",
}
EXPECTED_GART_PARAMETER_DECLARATION_SHA256 = (
    "7e5fb41f28b918202ae34503233b75e062aef2c6d79d50bbc067b7c52a8e5841"
)
EXPECTED_MATRIX_NONCLAIMS = {
    128: "The 128 MiB aperture is not proved sufficient for a workload.",
    256: "The 256 MiB aperture is not proved sufficient for a workload.",
    512: "The RS482 source default is not a measured optimum.",
    1024: "The 1024 MiB aperture is not proved usable or optimal on one target event.",
}


class CapacityError(Exception):
    """The finite source or configuration contract is contradicted."""


def read_tsv(path: Path, header: tuple[str, ...]) -> list[dict[str, str]]:
    try:
        path.read_text(encoding="ascii")
        with path.open(newline="", encoding="ascii") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if tuple(reader.fieldnames or ()) != header:
                raise CapacityError(f"{path}: unexpected schema")
            rows = list(reader)
    except (OSError, UnicodeDecodeError) as error:
        raise CapacityError(f"cannot read ASCII TSV {path}: {error}") from error
    if not rows:
        raise CapacityError(f"{path}: empty denominator")
    if any(any(not row[field].strip() for field in header) for row in rows):
        raise CapacityError(f"{path}: incomplete row")
    return rows


def framed_row_sha256(row: dict[str, str], fields: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for field in fields:
        value = row[field].encode("ascii")
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()


def row_sha256(row: dict[str, str]) -> str:
    return framed_row_sha256(row, POLICY_HEADER[1:])


def validate_graph(rows: dict[str, dict[str, str]]) -> None:
    visited: set[str] = set()
    active: set[str] = set()

    def visit(row_id: str) -> None:
        if row_id in active:
            raise CapacityError(f"dependency cycle at {row_id}")
        if row_id in visited:
            return
        active.add(row_id)
        dependencies = rows[row_id]["depends_on"].split(";")
        for dependency in dependencies:
            if dependency == "NONE":
                continue
            if dependency not in rows:
                raise CapacityError(f"{row_id}: unknown dependency {dependency}")
            visit(dependency)
        active.remove(row_id)
        visited.add(row_id)

    for row_id in rows:
        visit(row_id)


def validate_policy_rows(policy_rows: list[dict[str, str]]) -> None:
    rows = {row["row_id"]: row for row in policy_rows}
    if len(rows) != len(policy_rows):
        raise CapacityError("capacity policy row IDs are not unique")
    if set(rows) != set(EXPECTED_ROWS):
        missing = sorted(set(EXPECTED_ROWS) - set(rows))
        extra = sorted(set(rows) - set(EXPECTED_ROWS))
        raise CapacityError(
            f"capacity policy denominator differs: missing={missing} extra={extra}"
        )
    for row_id, (status, dependencies) in EXPECTED_ROWS.items():
        row = rows[row_id]
        if row["source_status"] != status:
            raise CapacityError(f"{row_id}: source status differs")
        if row["depends_on"] != dependencies:
            raise CapacityError(f"{row_id}: dependencies differ")
        if row["runtime_status"] != "not-run":
            raise CapacityError(f"{row_id}: runtime status exceeds source authority")
        if row["silicon_status"] != "unproved":
            raise CapacityError(f"{row_id}: silicon status exceeds source authority")
        if row_sha256(row) != EXPECTED_POLICY_ROW_SHA256[row_id]:
            raise CapacityError(f"{row_id}: exact policy row identity differs")
    validate_graph(rows)


def matrix_expected(gtt_mib: int) -> dict[str, str]:
    gtt_bytes = gtt_mib << 20
    pages = gtt_bytes // 4096
    size_code = int(math.log2(gtt_mib // 32)) << 1
    table_bytes = pages * 4
    pointer_bytes = pages * 8
    shadow_bytes = pages * 8
    return {
        "config_id": f"RS482_GTT_{gtt_mib}",
        "gtt_mib": str(gtt_mib),
        "vram_mib": "128",
        "size_code_hex": f"0x{size_code:08x}",
        "enabled_value_hex": f"0x{size_code | 1:08x}",
        "cpu_pages_4k": str(pages),
        "gpu_pages_4k": str(pages),
        "hardware_table_bytes": str(table_bytes),
        "cpu_page_pointer_bytes_x86_64": str(pointer_bytes),
        "pte_shadow_bytes": str(shadow_bytes),
        "static_metadata_bytes": str(table_bytes + pointer_bytes + shadow_bytes),
        "auto_default_rs482": "yes" if gtt_mib == 512 else "no",
        "model_scope": "nominal-selector-before-address-fit",
        "effective_capacity_status": "target-placement-not-run",
        "source_status": "source-model-only",
        "nonclaim": EXPECTED_MATRIX_NONCLAIMS[gtt_mib],
    }


def validate_matrix_rows(matrix_rows: list[dict[str, str]]) -> None:
    rows: dict[int, dict[str, str]] = {}
    for row in matrix_rows:
        try:
            gtt_mib = int(row["gtt_mib"])
        except ValueError as error:
            raise CapacityError("matrix GTT size is not an integer") from error
        if gtt_mib in rows:
            raise CapacityError(f"matrix duplicates {gtt_mib} MiB")
        rows[gtt_mib] = row
    if set(rows) != {128, 256, 512, 1024}:
        raise CapacityError("matrix is not the exact four-state denominator")
    for gtt_mib, row in rows.items():
        expected = matrix_expected(gtt_mib)
        if row != expected:
            differing = [
                field for field in MATRIX_HEADER if row[field] != expected[field]
            ]
            raise CapacityError(f"{gtt_mib} MiB matrix fields differ: {differing}")


def validate_exclusion_rows(rows: list[dict[str, str]]) -> None:
    selectors = [row["selector"] for row in rows]
    if len(selectors) != len(set(selectors)):
        raise CapacityError("capacity exclusions contain duplicate selectors")
    if set(selectors) != EXPECTED_EXCLUSION_SELECTORS:
        raise CapacityError("capacity exclusion denominator differs")
    for row in rows:
        selector = row["selector"]
        digest = framed_row_sha256(row, EXCLUSION_HEADER)
        if digest != EXPECTED_EXCLUSION_ROW_SHA256[selector]:
            raise CapacityError(f"{selector}: exact exclusion row identity differs")


def validate_gart_parameter_declaration(source: str) -> None:
    patterns = (
        r"(?m)^int\s+radeon_gart_size\s*=.*$",
        r"(?m)^MODULE_PARM_DESC\(gartsize,.*$",
        r"(?m)^module_param_named\(gartsize,.*$",
    )
    lines: list[str] = []
    for pattern in patterns:
        matches = re.findall(pattern, source)
        if len(matches) != 1:
            raise CapacityError("radeon_drv.c: gartsize declaration is not unique")
        lines.append(matches[0])
    digest = hashlib.sha256("\n".join(lines).encode("ascii")).hexdigest()
    if digest != EXPECTED_GART_PARAMETER_DECLARATION_SHA256:
        raise CapacityError("radeon_drv.c: exact gartsize declaration identity differs")


def function_token_sha256(body: str) -> str:
    return hashlib.sha256("\0".join(c_tokens(body)).encode("ascii")).hexdigest()


def validate_function_body(
    filename: str, symbol: str, body: str, expected_sha256: str
) -> None:
    if function_token_sha256(body) != expected_sha256:
        raise CapacityError(
            f"{filename}:{symbol}: exact function token identity differs"
        )


def validate_source(root: Path) -> None:
    for (filename, symbol), expected_sha256 in EXPECTED_FUNCTION_SHA256.items():
        body = function(root, filename, symbol)
        validate_function_body(filename, symbol, body, expected_sha256)

    driver_source = (root / SUBTREE / "radeon_drv.c").read_text(encoding="ascii")
    validate_gart_parameter_declaration(driver_source)

    header = (root / SUBTREE / "r500_reg.h").read_text(encoding="ascii")
    expected_macros = {
        "RS480_GART_EN": "(1 << 0)",
        "RS480_VA_SIZE_32MB": "(0 << 1)",
        "RS480_VA_SIZE_64MB": "(1 << 1)",
        "RS480_VA_SIZE_128MB": "(2 << 1)",
        "RS480_VA_SIZE_256MB": "(3 << 1)",
        "RS480_VA_SIZE_512MB": "(4 << 1)",
        "RS480_VA_SIZE_1GB": "(5 << 1)",
        "RS480_VA_SIZE_2GB": "(6 << 1)",
    }
    for name, value in expected_macros.items():
        pattern = rf"(?m)^#\s*define\s+{name}\s+{re.escape(value)}\s*$"
        if re.search(pattern, header) is None:
            raise CapacityError(f"r500_reg.h: {name} encoding differs")


def check_tree(root: Path) -> None:
    policy_rows = read_tsv(root / POLICY, POLICY_HEADER)
    matrix_rows = read_tsv(root / MATRIX, MATRIX_HEADER)
    exclusion_rows = read_tsv(root / EXCLUSIONS, EXCLUSION_HEADER)
    validate_policy_rows(policy_rows)
    validate_matrix_rows(matrix_rows)
    validate_exclusion_rows(exclusion_rows)
    validate_source(root)


def selftest(root: Path) -> None:
    policy_rows = read_tsv(root / POLICY, POLICY_HEADER)
    matrix_rows = read_tsv(root / MATRIX, MATRIX_HEADER)
    exclusion_rows = read_tsv(root / EXCLUSIONS, EXCLUSION_HEADER)
    validate_policy_rows(policy_rows)
    validate_matrix_rows(matrix_rows)
    validate_exclusion_rows(exclusion_rows)
    validate_source(root)

    mutations: list[tuple[str, callable]] = []

    missing_policy = copy.deepcopy(policy_rows[:-1])
    mutations.append(
        ("missing-policy-row", lambda: validate_policy_rows(missing_policy))
    )

    promoted_runtime = copy.deepcopy(policy_rows)
    promoted_runtime[0]["runtime_status"] = "hardware-pass"
    mutations.append(
        ("runtime-promotion", lambda: validate_policy_rows(promoted_runtime))
    )

    reversed_nonclaim = copy.deepcopy(policy_rows)
    reversed_nonclaim[-1]["nonclaim"] = "The largest aperture is automatically optimal."
    mutations.append(
        ("optimum-promotion", lambda: validate_policy_rows(reversed_nonclaim))
    )

    cyclic_policy = copy.deepcopy(policy_rows)
    next(
        row for row in cyclic_policy if row["row_id"] == "RS482_GTT_PARAMETER_ADMISSION"
    )["depends_on"] = "RS482_CAPACITY_OPTIMUM"
    mutations.append(("dependency-cycle", lambda: validate_policy_rows(cyclic_policy)))

    missing_matrix = copy.deepcopy(matrix_rows[:-1])
    mutations.append(
        ("missing-matrix-state", lambda: validate_matrix_rows(missing_matrix))
    )

    wrong_metadata = copy.deepcopy(matrix_rows)
    wrong_metadata[2]["static_metadata_bytes"] = "0"
    mutations.append(
        ("wrong-metadata-cost", lambda: validate_matrix_rows(wrong_metadata))
    )

    wrong_vram = copy.deepcopy(matrix_rows)
    wrong_vram[0]["vram_mib"] = "256"
    mutations.append(("wrong-fixed-vram", lambda: validate_matrix_rows(wrong_vram)))

    promoted_effective_capacity = copy.deepcopy(matrix_rows)
    promoted_effective_capacity[0]["effective_capacity_status"] = "runtime-proven"
    mutations.append(
        (
            "promoted-effective-capacity",
            lambda: validate_matrix_rows(promoted_effective_capacity),
        )
    )

    false_default = copy.deepcopy(matrix_rows)
    false_default[0]["auto_default_rs482"] = "yes"
    mutations.append(("multiple-defaults", lambda: validate_matrix_rows(false_default)))

    missing_exclusion = copy.deepcopy(exclusion_rows[:-1])
    mutations.append(
        (
            "missing-exclusion",
            lambda: validate_exclusion_rows(missing_exclusion),
        )
    )

    exclusion_content_mutations = (
        ("source_disposition", "unsupported"),
        ("denominator_disposition", "included"),
        ("reason", "The excluded selector is optimal."),
        ("reactivation_condition", "No evidence is required."),
    )
    for field, replacement in exclusion_content_mutations:
        changed_exclusion = copy.deepcopy(exclusion_rows)
        changed_exclusion[0][field] = replacement
        mutations.append(
            (
                f"changed-exclusion-{field}",
                lambda rows=changed_exclusion: validate_exclusion_rows(rows),
            )
        )

    driver_source = (root / SUBTREE / "radeon_drv.c").read_text(encoding="ascii")
    changed_declaration = driver_source.replace(
        "int radeon_gart_size = -1; /* auto */",
        "int radeon_gart_size = 1024;",
        1,
    )
    mutations.append(
        (
            "changed-module-default",
            lambda: validate_gart_parameter_declaration(changed_declaration),
        )
    )

    device_init_body = function(root, "radeon_device.c", "radeon_device_init")
    changed_device_init = device_init_body.replace(
        "radeon_check_arguments(rdev);",
        "",
        1,
    )
    mutations.append(
        (
            "removed-argument-validation-call",
            lambda: validate_function_body(
                "radeon_device.c",
                "radeon_device_init",
                changed_device_init,
                EXPECTED_FUNCTION_SHA256[("radeon_device.c", "radeon_device_init")],
            ),
        )
    )

    source_body = function(root, "radeon_device.c", "radeon_gart_size_auto")
    mutated_body = source_body.replace("return 512;", "return 1024;", 1)
    mutations.append(
        (
            "changed-auto-default",
            lambda: validate_function_body(
                "radeon_device.c",
                "radeon_gart_size_auto",
                mutated_body,
                EXPECTED_FUNCTION_SHA256[("radeon_device.c", "radeon_gart_size_auto")],
            ),
        )
    )

    failures = 0
    for name, mutation in mutations:
        try:
            mutation()
        except CapacityError:
            failures += 1
        else:
            raise CapacityError(f"selftest accepted known-bad mutation: {name}")
    print(f"capacity contract selftest: 1 good, {failures} bad")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    try:
        if args.selftest:
            selftest(root)
        else:
            check_tree(root)
            print(
                "RS482 capacity contract: 14 rows, 4 configurations, "
                "6 exclusions, 25 source functions, 1 module declaration"
            )
    except CapacityError as error:
        print(f"capacity contract failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
