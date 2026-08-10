#!/usr/bin/env python3
"""Prove the finite RS482 VRAM and GTT capacity source contract."""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from check_all_dev_interfaces import (
    C_CONDITIONAL_DIRECTIVE,
    C_IDENTIFIER,
    InterfaceError,
    conditional_stack_at,
    function_body,
    require_no_local_macro_overrides,
    strip_comments,
    strip_comments_and_literals,
)
from check_radeon_gart_lifecycle import c_tokens

POLICY = Path("policy/rs4xx-vram-gtt-capacity-contract.tsv")
MATRIX = Path("policy/rs482-gtt-capacity-matrix.tsv")
EXCLUSIONS = Path("policy/rs482-gtt-capacity-exclusions.tsv")
COEFFICIENTS = Path("policy/rs482-vram-gtt-capacity-coefficients.tsv")
SUBTREE = Path("drivers/gpu/drm/radeon")
MAX_TSV_BYTES = 256 * 1024
MAX_TSV_ROWS = 64
MAX_TSV_LINE_BYTES = 16 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024

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
    "rs482_first_probe_auto_default",
    "trial_request_form",
    "model_scope",
    "effective_capacity_status",
    "source_status",
    "nonclaim",
)
EXCLUSION_HEADER = (
    "input_class",
    "source_disposition",
    "denominator_disposition",
    "reason",
    "reactivation_condition",
)
COEFFICIENT_HEADER = (
    "coefficient_id",
    "contract_row",
    "source_file",
    "source_symbol",
    "output_quantity",
    "input_quantity",
    "coefficient_numerator",
    "coefficient_denominator",
    "addend_bytes",
    "evaluation_inputs",
    "derived_value",
    "derived_unit",
    "valid_domain",
    "source_status",
    "nonclaim",
)

EXPECTED_ROWS = {
    "RADEON_GTT_MODULE_GLOBAL_REQUEST_STATE": ("proven", "NONE"),
    "RS482_GTT_PARAMETER_ADMISSION": (
        "proven",
        "RADEON_GTT_MODULE_GLOBAL_REQUEST_STATE",
    ),
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
        "RS482_GTT_ADDRESS_PLACEMENT",
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
        "RADEON_GTT_MODULE_GLOBAL_REQUEST_STATE;RS482_GTT_ADDRESS_PLACEMENT;RS482_GART_METADATA_CAPACITY;RADEON_VRAM_RELOCATION_THRESHOLD;RADEON_SINGLE_BO_GTT_CEILING;RADEON_CAPACITY_USAGE_AND_MOVE_COUNTERS;RADEON_FRAGMENTATION_AND_PLACEMENT_DEBUGFS",
    ),
}
EXPECTED_POLICY_ORDER = tuple(EXPECTED_ROWS)

EXPECTED_POLICY_ROW_SHA256 = {
    "RADEON_GTT_MODULE_GLOBAL_REQUEST_STATE": "64eefa74267a13a97db088e18a068e215cf3e08bf6e62ab78fdd0ebe6cd7984b",
    "RS482_GTT_PARAMETER_ADMISSION": "13dbfe7e638fefac9d95ec62ee22b80c380fdc91a55d99b8e2dd1705ccd434ab",
    "RS482_GTT_SIZE_REGISTER_ENCODING": "ff20d9414a2dad6ac2966e140c413a1022fe4c650a5c2341961ff5f480a168bf",
    "RS482_GTT_ADDRESS_PLACEMENT": "e28efe9efd8ba2246bfc3e9a1f3aca255934dfed3ccbc5c5e9a4693f7c98d039",
    "RS482_GART_METADATA_CAPACITY": "63dd92ef30c2eb3099b79289cdbf207bb06ed2615608963a7361b0a7a5eab159",
    "RS482_VRAM_CARVEOUT_ACCOUNTING": "7e8fc4bc90ed69f3556c86f50b32a9a9c5b7311fcb5080beae39bb4fa56b344a",
    "RADEON_VRAMLIMIT_TEST_BOUNDARY": "dc6a585355fd19ee6ffea687c9e9c87e28d9fd387dec02ea2253153a883aa0f8",
    "RADEON_TTM_MANAGER_CAPACITY": "e55734981324c50f7aedb184fc6fcb1753bc254f0c5c660ce054014dd4531310",
    "RADEON_BO_DOMAIN_PLACEMENT_ORDER": "657a9e64615767e0254374811e566df348b7cfdb81639935caa0426f0be71c20",
    "RADEON_VRAM_RELOCATION_THRESHOLD": "bc60b9ca97ab2cf87366605f63bbe87b4be7ea332420f1eda82efca1d5b7b5aa",
    "RADEON_SINGLE_BO_GTT_CEILING": "39b7ea33d63e48c662daf4b8ffa939184f1bdf93703e300c343325468aeea065",
    "RADEON_PINNED_CAPACITY_ACCOUNTING": "790bcd2bd9d456bad44489953a5cbc0193632f933f053c12486eae52cb583767",
    "RADEON_CAPACITY_USAGE_AND_MOVE_COUNTERS": "93e3dbfa36827703d10a8a0695429ffdf16708faf569ba8ace111318c7035aef",
    "RADEON_FRAGMENTATION_AND_PLACEMENT_DEBUGFS": "da4c776ebcdbf9cf32e754b33ab4a375116fba80945f34cf0349158ce8251c6d",
    "RS482_CAPACITY_OPTIMUM": "b4967c8835f9bd98f41e370bc264e5182708fd9769297805310ef303e525915f",
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
    (
        "rs400.c",
        "rs400_init",
    ): "3c7083e4e68795a93a88589f20784b55c7b255c02e8f547593af79ac85c54b67",
    (
        "rs400.c",
        "rs400_startup",
    ): "0a9421306e437ea32ec59efe779d07e590b5ef8f4a99dccbac60faa0ca21724f",
    (
        "rs400.c",
        "rs400_gart_fini",
    ): "7b686ffb63018dab43638b8a70bb750bf48732a6106651de2e80d7e9e589c73f",
    (
        "radeon_object.c",
        "radeon_bo_init",
    ): "13b48446ce0d02309c2d245cc172a233b38421ae050090819e14b403408d5c9b",
    (
        "radeon_gart.c",
        "radeon_gart_table_ram_alloc",
    ): "1983f199056dc53e62f60ea7a201f4796452292047aabe7b3bc177295b4d7df1",
    (
        "radeon_gart.c",
        "radeon_gart_table_ram_free",
    ): "bc818a3433a2cc63d0cfbb5d263321fdcbf385935c6abb355ef00db5ec0096df",
    (
        "radeon_gem.c",
        "radeon_gem_debugfs_init",
    ): "758acf54e8d009ca23239d05dc4a6d40fa1c43bdd9ce646887fcc9d9494fde43",
    (
        "radeon_ttm.c",
        "radeon_ttm_vram_open",
    ): "efccb8ac5616f8d89e66979a83ef240c08d2da994f94878648ba7466a83728e3",
    (
        "radeon_ttm.c",
        "radeon_ttm_vram_read",
    ): "d0bda720be584bcb1d846f53580a3ee3f958f75635434d1b3464b9d76b23be9f",
    (
        "radeon_ttm.c",
        "radeon_ttm_gtt_open",
    ): "ff663060720bf8081d90a7245ddf579ec72c18e7366112a6144897f9e3c515ad",
    (
        "radeon_ttm.c",
        "radeon_ttm_gtt_read",
    ): "0983c4f0b9a4de47c03f315ffa3863d02fe3fe9e83ab48a961b27107b9dde0d4",
}
EXPECTED_DEBUGFS_CONDITIONAL_FUNCTIONS = {
    ("radeon_gem.c", "radeon_debugfs_gem_info_show"),
    ("radeon_ttm.c", "radeon_ttm_vram_open"),
    ("radeon_ttm.c", "radeon_ttm_vram_read"),
    ("radeon_ttm.c", "radeon_ttm_gtt_open"),
    ("radeon_ttm.c", "radeon_ttm_gtt_read"),
}

EXPECTED_EXCLUSION_ORDER = (
    "auto-minus-one",
    "below-32MiB",
    "non-power-of-two-at-or-above-32MiB",
    "32MiB",
    "64MiB",
    "2048MiB",
    "power-of-two-above-2048MiB",
    "post-probe-gartsize-write",
    "vramlimit-below-firmware-carveout",
    "raw-radeon-vram-gtt-debugfs",
)
EXPECTED_EXCLUSION_ROW_SHA256 = {
    "auto-minus-one": "ec495dc46b74bf05044e6af5dbbd1fcf8f487464b3ec83868aa30aa357000696",
    "below-32MiB": "db3472fcb31b9b30b8c4a0c73b6ce5f08258cf8e23570d14c2ff0af89d121e4e",
    "non-power-of-two-at-or-above-32MiB": "acb8c2563497acde57a0b5b7e08f8405746446d3160d79a0b7e9217f7148b723",
    "32MiB": "9e2fff751144a8a4c8a59e1a71650e7de720fcbf97ca3ec9c7b835db7a766d68",
    "64MiB": "514fc9c9908c60209d469726ee6a185adb794dd0426d323c537e3fbb0e51dc3f",
    "2048MiB": "7cd62ba7247a886966f86f4ec28f718bd45a49ff8a2908596eb62fe96a784489",
    "power-of-two-above-2048MiB": "b019b3bffcd5484499ae0ad99a06b533ef65e6d08380a938c8fd8deba2f824a3",
    "post-probe-gartsize-write": "b38b43b9886925f25f288227668d4866e5b8488a1682518a0079d0f762731904",
    "vramlimit-below-firmware-carveout": "30589553b5facd26f520a55532ef92342aeb21bf6f0336dc80d3494350197178",
    "raw-radeon-vram-gtt-debugfs": "fdce6825c6ac4b97e979379eee6bca0058fc1202ac6dd1d1c7273051be88d86d",
}
EXPECTED_GART_PARAMETER_DECLARATION_SHA256 = (
    "1a635a55c515857d37bdada24a462c370c39145c46002ea61c5aae61fea644c5"
)
EXPECTED_MATRIX_NONCLAIMS = {
    128: "The 128 MiB aperture is not proved sufficient for a workload.",
    256: "The 256 MiB aperture is not proved sufficient for a workload.",
    512: "The RS482 first-probe source default is not a measured optimum.",
    1024: "The 1024 MiB aperture is not proved usable or optimal on one target event.",
}
EXPECTED_COEFFICIENT_ORDER = (
    "RS400_HARDWARE_PTE_BYTES_PER_GPU_PAGE",
    "RADEON_CPU_PAGE_POINTER_BYTES_PER_CPU_PAGE",
    "RADEON_PTE_SHADOW_BYTES_PER_GPU_PAGE",
    "RS482_STATIC_METADATA_BYTES_PER_GTT_MIB",
    "RADEON_MOVE_THRESHOLD_EMPTY_VRAM_INTERCEPT",
    "RADEON_MOVE_THRESHOLD_USAGE_SLOPE",
    "RADEON_MOVE_THRESHOLD_FLOOR",
    "RS482_MOVE_THRESHOLD_128_MIB_KNEE",
    "RADEON_SINGLE_BO_EFFECTIVE_GTT_TERM",
    "RADEON_SINGLE_BO_PINNED_DEBIT",
)


class CapacityError(Exception):
    """The finite source or configuration contract is contradicted."""


def read_bounded_file(path: Path, maximum_size: int) -> bytes:
    """Read one stable regular file through a no-follow descriptor."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= getattr(os, "O_NOCTTY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CapacityError(f"cannot open regular input {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CapacityError(f"{path}: input is not a regular file")
        if before.st_size > maximum_size:
            raise CapacityError(f"{path}: input exceeds {maximum_size} bytes")
        chunks: list[bytes] = []
        remaining = maximum_size + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > maximum_size:
            raise CapacityError(f"{path}: input grew beyond {maximum_size} bytes")
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise CapacityError(f"{path}: input changed while being read")
        if len(content) != before.st_size:
            raise CapacityError(f"{path}: input length differs from descriptor size")
        return content
    except OSError as error:
        raise CapacityError(f"cannot read regular input {path}: {error}") from error
    finally:
        os.close(descriptor)


def read_tsv(path: Path, header: tuple[str, ...]) -> list[dict[str, str]]:
    data = read_bounded_file(path, MAX_TSV_BYTES)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise CapacityError(f"{path}: TSV is not ASCII") from error
    if not data.endswith(b"\n") or b"\r" in data:
        raise CapacityError(f"{path}: TSV must use canonical LF termination")
    lines = text[:-1].split("\n")
    if any(not line for line in lines):
        raise CapacityError(f"{path}: TSV contains an empty physical row")
    if any(len(line.encode("ascii")) > MAX_TSV_LINE_BYTES for line in lines):
        raise CapacityError(f"{path}: TSV line exceeds the byte ceiling")
    fields = tuple(lines[0].split("\t"))
    if fields != header or len(fields) != len(set(fields)):
        raise CapacityError(f"{path}: unexpected or duplicate schema columns")
    if not 1 <= len(lines) - 1 <= MAX_TSV_ROWS:
        raise CapacityError(f"{path}: TSV row count exceeds the finite bound")
    rows: list[dict[str, str]] = []
    for line_number, line in enumerate(lines[1:], 2):
        values = line.split("\t")
        if len(values) != len(header):
            raise CapacityError(f"{path}:{line_number}: TSV field count differs")
        if any(not value.strip() for value in values):
            raise CapacityError(f"{path}:{line_number}: incomplete row")
        rows.append(dict(zip(header, values, strict=True)))
    canonical = (
        "\t".join(header)
        + "\n"
        + "\n".join("\t".join(row[field] for field in header) for row in rows)
        + "\n"
    ).encode("ascii")
    if data != canonical:
        raise CapacityError(f"{path}: TSV serialization is not canonical")
    if not rows:
        raise CapacityError(f"{path}: empty denominator")
    return rows


def read_ascii_source(path: Path) -> str:
    data = read_bounded_file(path, MAX_SOURCE_BYTES)
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as error:
        raise CapacityError(f"{path}: source is not ASCII") from error

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
    row_order = tuple(row["row_id"] for row in policy_rows)
    if row_order != EXPECTED_POLICY_ORDER:
        raise CapacityError("capacity policy row order differs")
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
    size_code = ((gtt_mib // 32).bit_length() - 1) << 1
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
        "rs482_first_probe_auto_default": "yes" if gtt_mib == 512 else "no",
        "trial_request_form": "explicit-module-load-gartsize",
        "model_scope": "nominal-selector-before-target-address-fit",
        "effective_capacity_status": "target-interval-and-boot-not-run",
        "source_status": "source-model-only",
        "nonclaim": EXPECTED_MATRIX_NONCLAIMS[gtt_mib],
    }


def validate_matrix_rows(matrix_rows: list[dict[str, str]]) -> None:
    expected_order = (128, 256, 512, 1024)
    rows: dict[int, dict[str, str]] = {}
    for row in matrix_rows:
        try:
            gtt_mib = int(row["gtt_mib"])
        except ValueError as error:
            raise CapacityError("matrix GTT size is not an integer") from error
        if gtt_mib in rows:
            raise CapacityError(f"matrix duplicates {gtt_mib} MiB")
        rows[gtt_mib] = row
    if tuple(int(row["gtt_mib"]) for row in matrix_rows) != expected_order:
        raise CapacityError("matrix row order differs")
    if set(rows) != set(expected_order):
        raise CapacityError("matrix is not the exact four-state denominator")
    for gtt_mib, row in rows.items():
        expected = matrix_expected(gtt_mib)
        if row != expected:
            differing = [
                field for field in MATRIX_HEADER if row[field] != expected[field]
            ]
            raise CapacityError(f"{gtt_mib} MiB matrix fields differ: {differing}")


def validate_exclusion_rows(rows: list[dict[str, str]]) -> None:
    input_classes = [row["input_class"] for row in rows]
    if len(input_classes) != len(set(input_classes)):
        raise CapacityError("capacity exclusions contain duplicate input classes")
    if tuple(input_classes) != EXPECTED_EXCLUSION_ORDER:
        raise CapacityError("capacity exclusion denominator differs")
    for row in rows:
        input_class = row["input_class"]
        digest = framed_row_sha256(row, EXCLUSION_HEADER)
        if digest != EXPECTED_EXCLUSION_ROW_SHA256[input_class]:
            raise CapacityError(
                f"{input_class}: exact exclusion row identity differs"
            )


def coefficient_row(
    coefficient_id: str,
    contract_row: str,
    source_file: str,
    source_symbol: str,
    output_quantity: str,
    input_quantity: str,
    numerator: int,
    denominator: int,
    addend_bytes: int,
    evaluation_inputs: str,
    derived_value: int,
    valid_domain: str,
    nonclaim: str,
) -> dict[str, str]:
    return {
        "coefficient_id": coefficient_id,
        "contract_row": contract_row,
        "source_file": source_file,
        "source_symbol": source_symbol,
        "output_quantity": output_quantity,
        "input_quantity": input_quantity,
        "coefficient_numerator": str(numerator),
        "coefficient_denominator": str(denominator),
        "addend_bytes": str(addend_bytes),
        "evaluation_inputs": evaluation_inputs,
        "derived_value": str(derived_value),
        "derived_unit": "bytes",
        "valid_domain": valid_domain,
        "source_status": "source-model-only",
        "nonclaim": nonclaim,
    }


def expected_coefficient_rows() -> dict[str, dict[str, str]]:
    floor_bytes = 1024 * 1024
    vram_bytes = 128 * 1024 * 1024
    return {
        "RS400_HARDWARE_PTE_BYTES_PER_GPU_PAGE": coefficient_row(
            "RS400_HARDWARE_PTE_BYTES_PER_GPU_PAGE",
            "RS482_GART_METADATA_CAPACITY",
            "drivers/gpu/drm/radeon/rs400.c",
            "rs400_gart_init",
            "hardware_table_bytes",
            "gpu_pages",
            4,
            1,
            0,
            "gpu_pages=32768",
            32768 * 4,
            "RS400 or RS480 with 4 KiB GPU pages",
            "The coefficient excludes coherent-allocation metadata and alignment overhead.",
        ),
        "RADEON_CPU_PAGE_POINTER_BYTES_PER_CPU_PAGE": coefficient_row(
            "RADEON_CPU_PAGE_POINTER_BYTES_PER_CPU_PAGE",
            "RS482_GART_METADATA_CAPACITY",
            "drivers/gpu/drm/radeon/radeon_gart.c",
            "radeon_gart_init",
            "cpu_page_pointer_bytes",
            "cpu_pages",
            8,
            1,
            0,
            "cpu_pages=32768",
            32768 * 8,
            "x86_64 with PAGE_SIZE=4096 and pointer size 8",
            "The coefficient changes with CPU page size or pointer width.",
        ),
        "RADEON_PTE_SHADOW_BYTES_PER_GPU_PAGE": coefficient_row(
            "RADEON_PTE_SHADOW_BYTES_PER_GPU_PAGE",
            "RS482_GART_METADATA_CAPACITY",
            "drivers/gpu/drm/radeon/radeon_gart.c",
            "radeon_gart_init",
            "pte_shadow_bytes",
            "gpu_pages",
            8,
            1,
            0,
            "gpu_pages=32768",
            32768 * 8,
            "RADEON_GPU_PAGE_SIZE=4096 and u64 size 8",
            "The coefficient excludes virtual-allocation metadata and host page tables.",
        ),
        "RS482_STATIC_METADATA_BYTES_PER_GTT_MIB": coefficient_row(
            "RS482_STATIC_METADATA_BYTES_PER_GTT_MIB",
            "RS482_GART_METADATA_CAPACITY",
            "drivers/gpu/drm/radeon/radeon_gart.c;drivers/gpu/drm/radeon/rs400.c",
            "radeon_gart_init;rs400_gart_init",
            "static_metadata_bytes",
            "gtt_mib",
            5120,
            1,
            0,
            "gtt_mib=128",
            128 * 5120,
            "x86_64 with 4 KiB CPU and GPU pages",
            "The combined slope excludes the dummy page, allocator metadata, and payload backing.",
        ),
        "RADEON_MOVE_THRESHOLD_EMPTY_VRAM_INTERCEPT": coefficient_row(
            "RADEON_MOVE_THRESHOLD_EMPTY_VRAM_INTERCEPT",
            "RADEON_VRAM_RELOCATION_THRESHOLD",
            "drivers/gpu/drm/radeon/radeon_object.c",
            "radeon_bo_get_threshold_for_moves",
            "raw_movement_threshold_bytes",
            "real_vram_bytes",
            1,
            4,
            0,
            f"real_vram_bytes={vram_bytes};vram_usage_bytes=0",
            vram_bytes // 4,
            "zero VRAM usage",
            "The intercept does not include the one MiB floor comparison.",
        ),
        "RADEON_MOVE_THRESHOLD_USAGE_SLOPE": coefficient_row(
            "RADEON_MOVE_THRESHOLD_USAGE_SLOPE",
            "RADEON_VRAM_RELOCATION_THRESHOLD",
            "drivers/gpu/drm/radeon/radeon_object.c",
            "radeon_bo_get_threshold_for_moves",
            "raw_movement_threshold_bytes",
            "vram_usage_bytes",
            -1,
            2,
            0,
            "vram_usage_bytes=2",
            -1,
            "zero through one-half real VRAM usage",
            "The term is one component of the piecewise threshold rather than a complete verdict.",
        ),
        "RADEON_MOVE_THRESHOLD_FLOOR": coefficient_row(
            "RADEON_MOVE_THRESHOLD_FLOOR",
            "RADEON_VRAM_RELOCATION_THRESHOLD",
            "drivers/gpu/drm/radeon/radeon_object.c",
            "radeon_bo_get_threshold_for_moves",
            "movement_threshold_floor_bytes",
            "floor_bytes",
            1,
            1,
            0,
            f"floor_bytes={floor_bytes}",
            floor_bytes,
            "all VRAM usage",
            "The floor is a threshold and does not cap the size of the next moved BO.",
        ),
        "RS482_MOVE_THRESHOLD_128_MIB_KNEE": coefficient_row(
            "RS482_MOVE_THRESHOLD_128_MIB_KNEE",
            "RADEON_VRAM_RELOCATION_THRESHOLD",
            "drivers/gpu/drm/radeon/radeon_object.c",
            "radeon_bo_get_threshold_for_moves",
            "vram_usage_knee_bytes",
            "real_vram_bytes",
            1,
            2,
            -2 * floor_bytes,
            f"real_vram_bytes={vram_bytes};floor_bytes={floor_bytes}",
            vram_bytes // 2 - 2 * floor_bytes,
            "even real_vram_bytes at least twice the floor",
            "The 62 MiB knee is a source derivation rather than a measured pressure optimum.",
        ),
        "RADEON_SINGLE_BO_EFFECTIVE_GTT_TERM": coefficient_row(
            "RADEON_SINGLE_BO_EFFECTIVE_GTT_TERM",
            "RADEON_SINGLE_BO_GTT_CEILING",
            "drivers/gpu/drm/radeon/radeon_gem.c",
            "radeon_gem_object_create",
            "max_bo_size_bytes",
            "effective_gtt_bytes",
            1,
            1,
            0,
            f"effective_gtt_bytes={vram_bytes}",
            vram_bytes,
            "effective_gtt_bytes at least gart_pin_size",
            "The positive term does not prove a free allocator extent of that size.",
        ),
        "RADEON_SINGLE_BO_PINNED_DEBIT": coefficient_row(
            "RADEON_SINGLE_BO_PINNED_DEBIT",
            "RADEON_SINGLE_BO_GTT_CEILING",
            "drivers/gpu/drm/radeon/radeon_gem.c",
            "radeon_gem_object_create",
            "max_bo_size_bytes",
            "gart_pin_size",
            -1,
            1,
            0,
            f"gart_pin_size={floor_bytes}",
            -floor_bytes,
            "effective_gtt_bytes at least gart_pin_size",
            "The debit does not identify which pinned objects consume the counter.",
        ),
    }


def validate_coefficient_rows(rows: list[dict[str, str]]) -> None:
    row_order = tuple(row["coefficient_id"] for row in rows)
    if row_order != EXPECTED_COEFFICIENT_ORDER:
        raise CapacityError("capacity coefficient denominator or order differs")
    expected_rows = expected_coefficient_rows()
    for row in rows:
        coefficient_id = row["coefficient_id"]
        if row != expected_rows[coefficient_id]:
            differing = [
                field
                for field in COEFFICIENT_HEADER
                if row[field] != expected_rows[coefficient_id][field]
            ]
            raise CapacityError(
                f"{coefficient_id}: coefficient fields differ: {differing}"
            )


REGISTER_DEFINE = re.compile(
    r"(?m)^[ \t\v\f]*(?:#|%:)[ \t\v\f]*define[ \t\v\f]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t\v\f]+"
    r"(?P<value>[^\r\n]+?)\s*$"
)
REGISTER_DEFINE_NAME = re.compile(
    r"(?m)^[ \t\v\f]*(?:#|%:)[ \t\v\f]*define[ \t\v\f]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
REGISTER_UNDEF = re.compile(
    r"(?m)^[ \t\v\f]*(?:#|%:)[ \t\v\f]*undef[ \t\v\f]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
EXPECTED_REGISTER_MACROS = {
    "RS480_GART_EN": "(1 << 0)",
    "RS480_VA_SIZE_32MB": "(0 << 1)",
    "RS480_VA_SIZE_64MB": "(1 << 1)",
    "RS480_VA_SIZE_128MB": "(2 << 1)",
    "RS480_VA_SIZE_256MB": "(3 << 1)",
    "RS480_VA_SIZE_512MB": "(4 << 1)",
    "RS480_VA_SIZE_1GB": "(5 << 1)",
    "RS480_VA_SIZE_2GB": "(6 << 1)",
}


def validate_gart_parameter_declaration(source: str) -> None:
    comment_free = strip_comments(source)
    literal_mask = strip_comments_and_literals(source)
    patterns = (
        r"(?m)^int\s+radeon_gart_size\s*=.*$",
        r"(?m)^MODULE_PARM_DESC\(gartsize,.*$",
        r"(?m)^module_param_named\(gartsize,.*$",
    )
    lines: list[str] = []
    for pattern in patterns:
        matches = list(re.finditer(pattern, comment_free))
        if len(matches) != 1:
            raise CapacityError("radeon_drv.c: gartsize declaration is not unique")
        match = matches[0]
        try:
            stack = conditional_stack_at(
                literal_mask,
                match.start(),
                "radeon_drv.c gartsize declaration",
            )
        except InterfaceError as error:
            raise CapacityError(str(error)) from error
        if stack:
            raise CapacityError("radeon_drv.c: gartsize declaration is conditional")
        lines.append(match.group(0).rstrip())
    declaration_identifiers = tuple(
        sorted(
            set(
                C_IDENTIFIER.findall(
                    strip_comments_and_literals("\n".join(lines))
                )
            )
        )
    )
    try:
        require_no_local_macro_overrides(
            source,
            declaration_identifiers,
            "radeon_drv.c gartsize declaration",
        )
    except InterfaceError as error:
        raise CapacityError(str(error)) from error
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


def capacity_function_body(filename: str, symbol: str, source: str) -> str:
    options: dict[str, object] = {"protect_identifiers": True}
    if (filename, symbol) in EXPECTED_DEBUGFS_CONDITIONAL_FUNCTIONS:
        options["expected_enclosing_condition"] = "defined(CONFIG_DEBUG_FS)"
    else:
        options["require_unconditional"] = True
    try:
        return function_body(source, symbol, **options)
    except InterfaceError as error:
        raise CapacityError(f"{filename}:{symbol}: {error}") from error


def validate_function_source(
    filename: str,
    symbol: str,
    source: str,
    expected_sha256: str,
) -> None:
    body = capacity_function_body(filename, symbol, source)
    validate_function_body(filename, symbol, body, expected_sha256)


def validate_register_macros(source: str) -> None:
    code = strip_comments_and_literals(source)
    undefined_names = {
        match.group("name")
        for match in REGISTER_UNDEF.finditer(code)
        if match.group("name") in EXPECTED_REGISTER_MACROS
    }
    if undefined_names:
        raise CapacityError(
            f"r500_reg.h: protected encodings are undefined: {sorted(undefined_names)}"
        )
    for name, expected_value in EXPECTED_REGISTER_MACROS.items():
        all_definitions = [
            match
            for match in REGISTER_DEFINE_NAME.finditer(code)
            if match.group("name") == name
        ]
        if len(all_definitions) != 1:
            raise CapacityError(f"r500_reg.h: {name} definition is not unique")
        definitions = [
            match
            for match in REGISTER_DEFINE.finditer(code)
            if match.group("name") == name
        ]
        if len(definitions) != 1:
            raise CapacityError(f"r500_reg.h: {name} definition is not unique")
        definition = definitions[0]
        try:
            stack = conditional_stack_at(
                code,
                definition.start(),
                f"r500_reg.h {name}",
            )
        except InterfaceError as error:
            raise CapacityError(str(error)) from error
        if stack != [("ifndef", "__R500_REG_H__", "initial")]:
            raise CapacityError(f"r500_reg.h: {name} conditional scope differs")
        value = re.sub(r"[ \t\v\f]+", " ", definition.group("value").strip())
        if value != expected_value:
            raise CapacityError(f"r500_reg.h: {name} encoding differs")


def validate_capacity_ioctl_bindings(source: str) -> None:
    code = strip_comments_and_literals(source)
    definition = re.search(
        r"(?m)^static const struct drm_ioctl_desc "
        r"radeon_ioctls_kms\[\]\s*=\s*\{",
        code,
    )
    if definition is None:
        raise CapacityError("radeon_drv.c: radeon_ioctls_kms is absent")
    try:
        stack = conditional_stack_at(
            code,
            definition.start(),
            "radeon_drv.c radeon_ioctls_kms",
        )
    except InterfaceError as error:
        raise CapacityError(f"radeon_drv.c: {error}") from error
    if stack:
        raise CapacityError("radeon_drv.c: radeon_ioctls_kms is conditional")
    opening = code.find("{", definition.start())
    depth = 0
    closing = -1
    for offset in range(opening, len(code)):
        if code[offset] == "{":
            depth += 1
        elif code[offset] == "}":
            depth -= 1
            if depth == 0:
                closing = offset + 1
                break
    if closing < 0:
        raise CapacityError("radeon_drv.c: radeon_ioctls_kms has no closing brace")
    body = code[definition.start():closing]
    if C_CONDITIONAL_DIRECTIVE.search(strip_comments_and_literals(body)):
        raise CapacityError(
            "radeon_drv.c: capacity ioctl table contains a conditional directive"
        )
    protected_names = tuple(sorted(set(C_IDENTIFIER.findall(body))))
    try:
        require_no_local_macro_overrides(
            source,
            protected_names,
            "radeon_drv.c radeon_ioctls_kms",
        )
    except InterfaceError as error:
        raise CapacityError(f"radeon_drv.c: {error}") from error
    expected_bindings = (
        (
            "RADEON_GEM_INFO",
            "radeon_gem_info_ioctl",
        ),
        (
            "RADEON_INFO",
            "radeon_info_ioctl",
        ),
    )
    for command, callback in expected_bindings:
        command_pattern = re.compile(
            rf"\bDRM_IOCTL_DEF_DRV\(\s*{command}\b"
        )
        if len(command_pattern.findall(body)) != 1:
            raise CapacityError(
                f"radeon_drv.c: {command} command denominator differs"
            )
        pattern = re.compile(
            rf"\bDRM_IOCTL_DEF_DRV\(\s*{command}\s*,\s*"
            rf"{callback}\s*,"
        )
        if len(pattern.findall(body)) != 1:
            raise CapacityError(
                f"radeon_drv.c: {command} callback binding differs"
            )


def validate_source(root: Path) -> None:
    source_cache: dict[str, str] = {}
    for filename, _symbol in EXPECTED_FUNCTION_SHA256:
        if filename not in source_cache:
            path = root / SUBTREE / filename
            source_cache[filename] = read_ascii_source(path)
    for (filename, symbol), expected_sha256 in EXPECTED_FUNCTION_SHA256.items():
        validate_function_source(
            filename,
            symbol,
            source_cache[filename],
            expected_sha256,
        )

    driver_source = source_cache["radeon_device.c"]
    if "radeon_check_arguments(rdev);" not in capacity_function_body(
        "radeon_device.c",
        "radeon_device_init",
        driver_source,
    ):
        raise CapacityError(
            "radeon_device.c: device init no longer calls argument validation"
        )

    radeon_drv_source = read_ascii_source(root / SUBTREE / "radeon_drv.c")
    validate_gart_parameter_declaration(radeon_drv_source)
    validate_capacity_ioctl_bindings(radeon_drv_source)

    header = read_ascii_source(root / SUBTREE / "r500_reg.h")
    validate_register_macros(header)

def check_tree(root: Path) -> None:
    policy_rows = read_tsv(root / POLICY, POLICY_HEADER)
    matrix_rows = read_tsv(root / MATRIX, MATRIX_HEADER)
    exclusion_rows = read_tsv(root / EXCLUSIONS, EXCLUSION_HEADER)
    coefficient_rows = read_tsv(root / COEFFICIENTS, COEFFICIENT_HEADER)
    validate_policy_rows(policy_rows)
    validate_matrix_rows(matrix_rows)
    validate_exclusion_rows(exclusion_rows)
    validate_coefficient_rows(coefficient_rows)
    validate_source(root)


def replace_once(source: str, old: str, new: str, label: str) -> str:
    if source.count(old) != 1:
        raise CapacityError(f"selftest fixture is not unique: {label}")
    return source.replace(old, new, 1)


def raw_function_text(source: str, name: str) -> str:
    lines = source.splitlines(keepends=True)
    start = None
    for index, line in enumerate(lines):
        if re.match(rf"^[A-Za-z_].*\b{re.escape(name)}\s*\(", line):
            start = index
            break
    if start is None:
        raise CapacityError(f"selftest function is absent: {name}")
    for index in range(start, len(lines)):
        if lines[index].rstrip("\r\n") == "}":
            return "".join(lines[start : index + 1]).rstrip("\r\n")
    raise CapacityError(f"selftest function has no closing brace: {name}")


def selftest(root: Path) -> None:
    policy_rows = read_tsv(root / POLICY, POLICY_HEADER)
    matrix_rows = read_tsv(root / MATRIX, MATRIX_HEADER)
    exclusion_rows = read_tsv(root / EXCLUSIONS, EXCLUSION_HEADER)
    coefficient_rows = read_tsv(root / COEFFICIENTS, COEFFICIENT_HEADER)
    validate_policy_rows(policy_rows)
    validate_matrix_rows(matrix_rows)
    validate_exclusion_rows(exclusion_rows)
    validate_coefficient_rows(coefficient_rows)
    validate_source(root)

    mutations: list[tuple[str, Callable[[], None]]] = []

    missing_policy = copy.deepcopy(policy_rows[:-1])
    mutations.append(
        ("missing-policy-row", lambda: validate_policy_rows(missing_policy))
    )
    reordered_policy = copy.deepcopy(policy_rows)
    reordered_policy[0], reordered_policy[1] = (
        reordered_policy[1],
        reordered_policy[0],
    )
    mutations.append(
        ("reordered-policy-rows", lambda: validate_policy_rows(reordered_policy))
    )
    promoted_runtime = copy.deepcopy(policy_rows)
    promoted_runtime[0]["runtime_status"] = "hardware-pass"
    mutations.append(
        ("runtime-promotion", lambda: validate_policy_rows(promoted_runtime))
    )
    reversed_nonclaim = copy.deepcopy(policy_rows)
    reversed_nonclaim[-1]["nonclaim"] = (
        "The largest aperture is automatically optimal."
    )
    mutations.append(
        ("optimum-promotion", lambda: validate_policy_rows(reversed_nonclaim))
    )
    cyclic_policy = copy.deepcopy(policy_rows)
    next(
        row
        for row in cyclic_policy
        if row["row_id"] == "RADEON_GTT_MODULE_GLOBAL_REQUEST_STATE"
    )["depends_on"] = "RS482_CAPACITY_OPTIMUM"
    mutations.append(
        ("dependency-cycle", lambda: validate_policy_rows(cyclic_policy))
    )

    missing_matrix = copy.deepcopy(matrix_rows[:-1])
    mutations.append(
        ("missing-matrix-state", lambda: validate_matrix_rows(missing_matrix))
    )
    reordered_matrix = list(reversed(copy.deepcopy(matrix_rows)))
    mutations.append(
        ("reordered-matrix-rows", lambda: validate_matrix_rows(reordered_matrix))
    )
    wrong_metadata = copy.deepcopy(matrix_rows)
    wrong_metadata[2]["static_metadata_bytes"] = "0"
    mutations.append(
        ("wrong-metadata-cost", lambda: validate_matrix_rows(wrong_metadata))
    )
    wrong_vram = copy.deepcopy(matrix_rows)
    wrong_vram[0]["vram_mib"] = "256"
    mutations.append(
        ("wrong-fixed-vram", lambda: validate_matrix_rows(wrong_vram))
    )
    promoted_effective_capacity = copy.deepcopy(matrix_rows)
    promoted_effective_capacity[0]["effective_capacity_status"] = "runtime-proven"
    mutations.append(
        (
            "promoted-effective-capacity",
            lambda: validate_matrix_rows(promoted_effective_capacity),
        )
    )
    false_default = copy.deepcopy(matrix_rows)
    false_default[0]["rs482_first_probe_auto_default"] = "yes"
    mutations.append(
        ("multiple-defaults", lambda: validate_matrix_rows(false_default))
    )

    missing_exclusion = copy.deepcopy(exclusion_rows[:-1])
    mutations.append(
        ("missing-exclusion", lambda: validate_exclusion_rows(missing_exclusion))
    )
    reordered_exclusions = list(reversed(copy.deepcopy(exclusion_rows)))
    mutations.append(
        (
            "reordered-exclusion-rows",
            lambda: validate_exclusion_rows(reordered_exclusions),
        )
    )
    exclusion_content_mutations = (
        ("source_disposition", "unsupported"),
        ("denominator_disposition", "included"),
        ("reason", "The excluded input is optimal."),
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

    missing_coefficient = copy.deepcopy(coefficient_rows[:-1])
    mutations.append(
        (
            "missing-coefficient",
            lambda: validate_coefficient_rows(missing_coefficient),
        )
    )
    reordered_coefficients = list(reversed(copy.deepcopy(coefficient_rows)))
    mutations.append(
        (
            "reordered-coefficients",
            lambda: validate_coefficient_rows(reordered_coefficients),
        )
    )
    wrong_slope = copy.deepcopy(coefficient_rows)
    wrong_slope[5]["coefficient_numerator"] = "1"
    mutations.append(
        ("wrong-movement-slope", lambda: validate_coefficient_rows(wrong_slope))
    )
    wrong_knee = copy.deepcopy(coefficient_rows)
    wrong_knee[7]["derived_value"] = str(64 * 1024 * 1024)
    mutations.append(
        ("wrong-movement-knee", lambda: validate_coefficient_rows(wrong_knee))
    )

    driver_source = read_ascii_source(root / SUBTREE / "radeon_drv.c")
    changed_declaration = replace_once(
        driver_source,
        "int radeon_gart_size = -1; /* auto */",
        "int radeon_gart_size = 1024;",
        "changed module default",
    )
    mutations.append(
        (
            "changed-module-default",
            lambda: validate_gart_parameter_declaration(changed_declaration),
        )
    )
    overridden_module_parameter = replace_once(
        driver_source,
        "int radeon_gart_size = -1; /* auto */",
        "#undef module_param_named\n"
        "#define module_param_named(...)\n"
        "int radeon_gart_size = -1; /* auto */",
        "overridden module parameter declaration",
    )
    mutations.append(
        (
            "overridden-module-parameter-declaration",
            lambda: validate_gart_parameter_declaration(
                overridden_module_parameter
            ),
        )
    )

    device_source = read_ascii_source(root / SUBTREE / "radeon_device.c")
    changed_device_init = replace_once(
        device_source,
        "radeon_check_arguments(rdev);",
        "",
        "removed argument validation call",
    )
    mutations.append(
        (
            "removed-argument-validation-call",
            lambda: validate_function_source(
                "radeon_device.c",
                "radeon_device_init",
                changed_device_init,
                EXPECTED_FUNCTION_SHA256[
                    ("radeon_device.c", "radeon_device_init")
                ],
            ),
        )
    )
    good_check_arguments = raw_function_text(
        device_source,
        "radeon_check_arguments",
    )
    overridden_power_check = replace_once(
        device_source,
        good_check_arguments,
        "#undef is_power_of_2\n"
        "#define is_power_of_2(value) true\n"
        + good_check_arguments,
        "overridden power-of-two check",
    )
    mutations.append(
        (
            "overridden-function-identifier",
            lambda: validate_function_source(
                "radeon_device.c",
                "radeon_check_arguments",
                overridden_power_check,
                EXPECTED_FUNCTION_SHA256[
                    ("radeon_device.c", "radeon_check_arguments")
                ],
            ),
        )
    )
    changed_auto_default = replace_once(
        device_source,
        "return 512;",
        "return 1024;",
        "changed auto default",
    )
    mutations.append(
        (
            "changed-auto-default",
            lambda: validate_function_source(
                "radeon_device.c",
                "radeon_gart_size_auto",
                changed_auto_default,
                EXPECTED_FUNCTION_SHA256[
                    ("radeon_device.c", "radeon_gart_size_auto")
                ],
            ),
        )
    )

    good_auto_body = raw_function_text(
        device_source,
        "radeon_gart_size_auto",
    )
    bad_auto_body = replace_once(
        good_auto_body,
        "return 512;",
        "return 1024;",
        "inactive good active bad function",
    )
    conditional_auto_twin = replace_once(
        device_source,
        good_auto_body,
        "#if 0\n"
        + good_auto_body
        + "\n#else\n"
        + bad_auto_body
        + "\n#endif",
        "inactive good active bad function",
    )
    mutations.append(
        (
            "inactive-good-active-bad-function",
            lambda: validate_function_source(
                "radeon_device.c",
                "radeon_gart_size_auto",
                conditional_auto_twin,
                EXPECTED_FUNCTION_SHA256[
                    ("radeon_device.c", "radeon_gart_size_auto")
                ],
            ),
        )
    )

    register_source = read_ascii_source(root / SUBTREE / "r500_reg.h")
    macro_match = re.search(
        r"(?m)^#\s*define\s+RS480_VA_SIZE_512MB\s+\(4 << 1\)\s*$",
        register_source,
    )
    if macro_match is None:
        raise CapacityError("selftest fixture is absent: RS480 512 MiB macro")
    good_macro = macro_match.group(0)
    conditional_macro_twin = replace_once(
        register_source,
        good_macro,
        "#if 0\n"
        + good_macro
        + "\n#else\n"
        + good_macro.replace("(4 << 1)", "(5 << 1)")
        + "\n#endif",
        "inactive good active bad register macro",
    )
    mutations.append(
        (
            "inactive-good-active-bad-register-macro",
            lambda: validate_register_macros(conditional_macro_twin),
        )
    )
    function_like_macro = replace_once(
        register_source,
        good_macro,
        good_macro + "\n#define RS480_VA_SIZE_512MB(value) (value)",
        "function-like register macro redefinition",
    )
    mutations.append(
        (
            "function-like-register-macro-redefinition",
            lambda: validate_register_macros(function_like_macro),
        )
    )
    undefined_macro = replace_once(
        register_source,
        good_macro,
        good_macro + "\n#undef RS480_VA_SIZE_512MB",
        "undefined register macro",
    )
    mutations.append(
        (
            "undefined-register-macro",
            lambda: validate_register_macros(undefined_macro),
        )
    )
    ioctl_match = re.search(
        r"(?m)^\s*DRM_IOCTL_DEF_DRV\(RADEON_GEM_INFO,\s*"
        r"radeon_gem_info_ioctl,.*$",
        driver_source,
    )
    if ioctl_match is None:
        raise CapacityError("selftest fixture is absent: GEM_INFO binding")
    good_ioctl = ioctl_match.group(0)
    duplicate_ioctl_binding = replace_once(
        driver_source,
        good_ioctl,
        good_ioctl
        + "\n"
        + good_ioctl.replace("radeon_gem_info_ioctl", "drm_invalid_op"),
        "duplicate capacity ioctl binding",
    )
    mutations.append(
        (
            "duplicate-capacity-ioctl-binding",
            lambda: validate_capacity_ioctl_bindings(duplicate_ioctl_binding),
        )
    )
    conditional_ioctl_twin = replace_once(
        driver_source,
        good_ioctl,
        "#if 0\n"
        + good_ioctl
        + "\n#else\n"
        + good_ioctl.replace("radeon_gem_info_ioctl", "drm_invalid_op")
        + "\n#endif",
        "inactive good active bad ioctl binding",
    )
    mutations.append(
        (
            "inactive-good-active-bad-ioctl-binding",
            lambda: validate_capacity_ioctl_bindings(conditional_ioctl_twin),
        )
    )

    with tempfile.TemporaryDirectory(
        prefix="radeon-capacity-selftest-"
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        matrix_bytes = read_bounded_file(root / MATRIX, MAX_TSV_BYTES)
        parser_mutations = {
            "crlf-tsv": matrix_bytes.replace(b"\n", b"\r\n"),
            "missing-final-lf": matrix_bytes[:-1],
            "extra-empty-row": matrix_bytes + b"\n",
            "quoted-key-alias": matrix_bytes.replace(
                b"RS482_GTT_128\t",
                b'"RS482_GTT_128"\t',
                1,
            ),
            "duplicate-header-name": matrix_bytes.replace(
                b"config_id\tgtt_mib",
                b"config_id\tconfig_id",
                1,
            ),
            "oversized-tsv": b"x" * (MAX_TSV_BYTES + 1),
        }
        for name, data in parser_mutations.items():
            path = temporary_root / f"{name}.tsv"
            path.write_bytes(data)
            mutations.append(
                (
                    name,
                    lambda candidate=path: validate_matrix_rows(
                        read_tsv(candidate, MATRIX_HEADER)
                    ),
                )
            )
        fifo_path = temporary_root / "fifo.tsv"
        os.mkfifo(fifo_path)
        mutations.append(
            (
                "fifo-input",
                lambda: validate_matrix_rows(
                    read_tsv(fifo_path, MATRIX_HEADER)
                ),
            )
        )
        symlink_path = temporary_root / "symlink.tsv"
        symlink_path.symlink_to((root / MATRIX).resolve())
        mutations.append(
            (
                "symlink-input",
                lambda: validate_matrix_rows(
                    read_tsv(symlink_path, MATRIX_HEADER)
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
                raise CapacityError(
                    f"selftest accepted known-bad mutation: {name}"
                )

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
                "RS482 capacity contract: 15 rows, 4 configurations, "
                "10 exclusions, 10 coefficients, 36 source functions, "
                "1 module declaration, 2 ioctl bindings, 8 register encodings"
            )
    except CapacityError as error:
        print(f"capacity contract failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
